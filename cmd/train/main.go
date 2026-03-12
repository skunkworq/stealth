// train orchestrates the full ML training loop for the stealth platform.
// It connects the data generation, Python DQN training, and validation
// benchmarking steps into a single automated pipeline.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/skunkworq/stealth/brws/ml"
	"github.com/skunkworq/stealth/brws/ml/datagen"
)

var version = "0.1.0"

func main() {
	rootCmd := &cobra.Command{
		Use:     "train",
		Short:   "ML training orchestration for the stealth browser platform",
		Version: version,
		Long: `train orchestrates the full ML training loop:

  1. Baseline benchmark - measure current detection rates
  2. Data generation   - generate training episodes via fast evaluation
  3. Export            - export to CSV for Python training
  4. Python training   - run DQN training with shield_sword
  5. Validation        - measure improvement with trained policy
  6. Report            - compare baseline vs trained performance

Examples:
  train run --lab-url http://localhost:8080 --episodes 500
  train benchmark --episodes 100
  train discover --output signatures/`,
	}

	rootCmd.AddCommand(runCmd())
	rootCmd.AddCommand(benchmarkCmd())
	rootCmd.AddCommand(discoverCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// ---------- run subcommand ----------

func runCmd() *cobra.Command {
	var (
		labURL       string
		episodes     int
		benchmarkEps int
		dbPath       string
		modelDir     string
		startLab     bool
	)

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Full end-to-end training loop",
		Long: `Execute the complete training pipeline:
  Phase 1: Baseline benchmark (random configs)
  Phase 2: Generate training data
  Phase 3: Export to CSV
  Phase 4: Python DQN training
  Phase 5: Validation benchmark (policy-driven)
  Phase 6: Improvement report`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTrainLoop(labURL, episodes, benchmarkEps, dbPath, modelDir, startLab)
		},
	}

	cmd.Flags().StringVar(&labURL, "lab-url", "http://localhost:8080", "Lab server URL")
	cmd.Flags().IntVar(&episodes, "episodes", 500, "Number of training episodes")
	cmd.Flags().IntVar(&benchmarkEps, "benchmark-episodes", 100, "Number of benchmark episodes")
	cmd.Flags().StringVar(&dbPath, "db", "data/training.db", "SQLite database path")
	cmd.Flags().StringVar(&modelDir, "model-dir", "models/", "Model output directory")
	cmd.Flags().BoolVar(&startLab, "start-lab", false, "Auto-start lab server in background")

	return cmd
}

type benchmarkResult struct {
	Episodes    int
	AvgBotScore float64
	SuccessRate float64
	AvgReward   float64
}

func runTrainLoop(labURL string, episodes, benchmarkEps int, dbPath, modelDir string, startLab bool) error {
	labURL = strings.TrimRight(labURL, "/")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		fmt.Println("\nInterrupted. Cleaning up...")
		cancel()
	}()

	// Optionally start the lab server
	var labProc *exec.Cmd
	if startLab {
		fmt.Println("Starting lab server in background...")
		labProc = exec.CommandContext(ctx, "build/labd", "--http-port", "8080", "--https-port", "8443")
		labProc.Stdout = os.Stdout
		labProc.Stderr = os.Stderr
		if err := labProc.Start(); err != nil {
			return fmt.Errorf("start lab server: %w", err)
		}
		defer func() {
			if labProc.Process != nil {
				_ = labProc.Process.Kill()
			}
		}()
		// Wait for lab to be ready
		fmt.Print("Waiting for lab server...")
		for i := 0; i < 30; i++ {
			resp, err := http.Get(labURL + "/health")
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == 200 {
					fmt.Println(" ready!")
					break
				}
			}
			time.Sleep(time.Second)
			fmt.Print(".")
		}
		fmt.Println()
	}

	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║              ML Training Pipeline                            ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Printf("  Lab URL:            %s\n", labURL)
	fmt.Printf("  Training Episodes:  %d\n", episodes)
	fmt.Printf("  Benchmark Episodes: %d\n", benchmarkEps)
	fmt.Printf("  Database:           %s\n", dbPath)
	fmt.Printf("  Model Dir:          %s\n", modelDir)
	fmt.Println()

	// Phase 1: Baseline Benchmark
	fmt.Println("━━━ Phase 1: Baseline Benchmark ━━━")
	baseline, err := runBenchmark(ctx, labURL, benchmarkEps, "")
	if err != nil {
		return fmt.Errorf("baseline benchmark: %w", err)
	}
	fmt.Printf("  Avg Bot Score:  %.4f\n", baseline.AvgBotScore)
	fmt.Printf("  Success Rate:   %.1f%%\n", baseline.SuccessRate*100)
	fmt.Printf("  Avg Reward:     %.4f\n", baseline.AvgReward)
	fmt.Println()

	// Phase 2: Generate Training Data
	fmt.Println("━━━ Phase 2: Generate Training Data ━━━")
	if err := generateData(ctx, labURL, episodes, dbPath); err != nil {
		return fmt.Errorf("data generation: %w", err)
	}
	fmt.Println()

	// Phase 3: Export to CSV
	fmt.Println("━━━ Phase 3: Export Training Data ━━━")
	outputDir := filepath.Join(filepath.Dir(dbPath), "training")
	if err := exportData(dbPath, outputDir); err != nil {
		return fmt.Errorf("data export: %w", err)
	}
	fmt.Println()

	// Phase 4: Python Training
	fmt.Println("━━━ Phase 4: Python DQN Training ━━━")
	if err := runPythonTraining(ctx, labURL, episodes, modelDir); err != nil {
		fmt.Printf("  Warning: Python training failed: %v\n", err)
		fmt.Println("  Continuing with validation using existing model (if available)...")
	}
	fmt.Println()

	// Phase 5: Validation Benchmark
	fmt.Println("━━━ Phase 5: Validation Benchmark ━━━")
	weightsPath := filepath.Join(modelDir, "shield_sword_weights.json")
	validation, err := runBenchmark(ctx, labURL, benchmarkEps, weightsPath)
	if err != nil {
		return fmt.Errorf("validation benchmark: %w", err)
	}
	fmt.Printf("  Avg Bot Score:  %.4f\n", validation.AvgBotScore)
	fmt.Printf("  Success Rate:   %.1f%%\n", validation.SuccessRate*100)
	fmt.Printf("  Avg Reward:     %.4f\n", validation.AvgReward)
	fmt.Println()

	// Phase 6: Report
	fmt.Println("━━━ Phase 6: Training Report ━━━")
	botDelta := baseline.AvgBotScore - validation.AvgBotScore
	successDelta := validation.SuccessRate - baseline.SuccessRate
	rewardDelta := validation.AvgReward - baseline.AvgReward
	fmt.Println()
	fmt.Println("  ┌─────────────────────────┬──────────┬──────────┬──────────┐")
	fmt.Println("  │ Metric                  │ Baseline │ Trained  │ Delta    │")
	fmt.Println("  ├─────────────────────────┼──────────┼──────────┼──────────┤")
	fmt.Printf("  │ Avg Bot Score            │ %8.4f │ %8.4f │ %+7.4f  │\n", baseline.AvgBotScore, validation.AvgBotScore, -botDelta)
	fmt.Printf("  │ Success Rate             │ %7.1f%% │ %7.1f%% │ %+6.1f%%  │\n", baseline.SuccessRate*100, validation.SuccessRate*100, successDelta*100)
	fmt.Printf("  │ Avg Reward               │ %8.4f │ %8.4f │ %+7.4f  │\n", baseline.AvgReward, validation.AvgReward, rewardDelta)
	fmt.Println("  └─────────────────────────┴──────────┴──────────┴──────────┘")
	fmt.Println()

	if botDelta > 0 {
		fmt.Printf("  Bot score improved by %.4f (lower is better for the sword)\n", botDelta)
	} else {
		fmt.Printf("  Bot score worsened by %.4f\n", -botDelta)
	}

	// Save report
	report := map[string]interface{}{
		"timestamp":   time.Now().Format(time.RFC3339),
		"episodes":    episodes,
		"benchmark":   benchmarkEps,
		"baseline":    baseline,
		"validation":  validation,
		"improvement": map[string]float64{"bot_score": botDelta, "success_rate": successDelta, "reward": rewardDelta},
	}
	reportPath := filepath.Join(modelDir, "training_report.json")
	if err := os.MkdirAll(modelDir, 0o755); err == nil {
		if f, err := os.Create(reportPath); err == nil {
			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			_ = enc.Encode(report)
			f.Close()
			fmt.Printf("\n  Report saved to %s\n", reportPath)
		}
	}

	return nil
}

// runBenchmark evaluates N episodes with random (or policy-driven) configs.
func runBenchmark(ctx context.Context, labURL string, episodes int, weightsPath string) (*benchmarkResult, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	webrtcModes := []string{"disabled", "fake", "real"}

	var policyLoader *ml.PolicyLoader
	if weightsPath != "" {
		var err error
		policyLoader, err = ml.NewPolicyLoader(weightsPath)
		if err != nil {
			fmt.Printf("  Warning: could not load policy from %s: %v\n", weightsPath, err)
		}
	}

	var totalBotScore, totalReward float64
	var successes int

	for i := 0; i < episodes; i++ {
		select {
		case <-ctx.Done():
			break
		default:
		}

		config := randomConfig(webrtcModes)

		// If we have a policy, use it to modify the config
		if policyLoader != nil {
			stateVec := make([]float64, 18)
			for j := 0; j < 11; j++ {
				stateVec[j] = 1.0 // Assume all detections active initially
			}
			actionIdx, _ := policyLoader.SelectAction(stateVec)
			applyActionToSnapshot(&config, actionIdx)
		}

		reqBody := struct {
			StealthConfig datagen.StealthConfigSnapshot `json:"stealth_config"`
			EngineName    string                        `json:"engine_name"`
			FastMode      bool                          `json:"fast_mode"`
		}{
			StealthConfig: config,
			EngineName:    "chromium",
			FastMode:      true,
		}
		bodyBytes, _ := json.Marshal(reqBody)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, labURL+"/api/ml/evaluate", bytes.NewReader(bodyBytes))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		var evalResp struct {
			BotScore float64 `json:"bot_score"`
			IsBot    bool    `json:"is_bot"`
			Success  bool    `json:"success"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&evalResp)
		resp.Body.Close()

		totalBotScore += evalResp.BotScore
		reward := 1.0 - evalResp.BotScore
		if evalResp.BotScore < 0.35 {
			successes++
			reward += 0.25
		}
		totalReward += reward

		if (i+1)%25 == 0 {
			fmt.Printf("  [%d/%d] avg_bot_score=%.4f\n", i+1, episodes, totalBotScore/float64(i+1))
		}
	}

	n := float64(episodes)
	return &benchmarkResult{
		Episodes:    episodes,
		AvgBotScore: totalBotScore / n,
		SuccessRate: float64(successes) / n,
		AvgReward:   totalReward / n,
	}, nil
}

func generateData(ctx context.Context, labURL string, episodes int, dbPath string) error {
	if dir := filepath.Dir(dbPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create db directory: %w", err)
		}
	}

	collector, err := datagen.NewCollector(dbPath)
	if err != nil {
		return fmt.Errorf("open collector: %w", err)
	}
	defer collector.Close()

	client := &http.Client{Timeout: 30 * time.Second}
	webrtcModes := []string{"disabled", "fake", "real"}
	engineNames := []string{"chromium", "firefox", "native", "webkit"}
	sessionID := uuid.New().String()
	generated := 0

	fmt.Printf("  Generating %d episodes...\n", episodes)

	for i := 0; i < episodes; i++ {
		select {
		case <-ctx.Done():
			fmt.Printf("  Interrupted after %d episodes.\n", generated)
			return nil
		default:
		}

		engineName := engineNames[rand.Intn(len(engineNames))]
		config := randomConfig(webrtcModes)

		reqBody := struct {
			StealthConfig datagen.StealthConfigSnapshot `json:"stealth_config"`
			EngineName    string                        `json:"engine_name"`
			FastMode      bool                          `json:"fast_mode"`
		}{
			StealthConfig: config,
			EngineName:    engineName,
			FastMode:      true,
		}
		bodyBytes, _ := json.Marshal(reqBody)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, labURL+"/api/ml/evaluate", bytes.NewReader(bodyBytes))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		var evalResp struct {
			BotScore  float64  `json:"bot_score"`
			Anomalies []string `json:"anomalies"`
			Success   bool     `json:"success"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&evalResp)
		resp.Body.Close()

		ep := &datagen.TrainingEpisode{
			EpisodeID:     uuid.New().String(),
			Timestamp:     time.Now(),
			SessionID:     sessionID,
			TargetURL:     labURL + "/api/ml/evaluate",
			EngineName:    engineName,
			StealthConfig: config,
			BotScore:      evalResp.BotScore,
			Reward:        1.0 - evalResp.BotScore,
			ModelVersion:  "v0.1.0",
		}

		if err := collector.RecordEpisode(ctx, ep); err != nil {
			continue
		}
		generated++

		if generated%50 == 0 {
			fmt.Printf("  [%d/%d] generated (bot_score=%.3f)\n", generated, episodes, ep.BotScore)
		}
	}

	fmt.Printf("  Done. %d episodes recorded to %s\n", generated, dbPath)
	return nil
}

func exportData(dbPath, outputDir string) error {
	collector, err := datagen.NewCollector(dbPath)
	if err != nil {
		return fmt.Errorf("open collector: %w", err)
	}
	defer collector.Close()

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	dataFile := filepath.Join(outputDir, "training.csv")
	f, err := os.Create(dataFile)
	if err != nil {
		return fmt.Errorf("create csv file: %w", err)
	}
	defer f.Close()

	n, err := collector.ExportCSV(f, datagen.EpisodeFilters{})
	if err != nil {
		return fmt.Errorf("export csv: %w", err)
	}
	fmt.Printf("  Exported %d episodes to %s\n", n, dataFile)

	manifest, err := collector.ExportManifest(datagen.EpisodeFilters{})
	if err != nil {
		return fmt.Errorf("generate manifest: %w", err)
	}

	manifestPath := filepath.Join(outputDir, "manifest.json")
	mf, err := os.Create(manifestPath)
	if err != nil {
		return fmt.Errorf("create manifest file: %w", err)
	}
	defer mf.Close()

	enc := json.NewEncoder(mf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(manifest); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	fmt.Printf("  Wrote manifest to %s\n", manifestPath)

	return nil
}

func runPythonTraining(ctx context.Context, labURL string, episodes int, modelDir string) error {
	if err := os.MkdirAll(modelDir, 0o755); err != nil {
		return fmt.Errorf("create model directory: %w", err)
	}

	scriptPath := "brws/ml/train_shield_sword.py"
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		return fmt.Errorf("training script not found: %s", scriptPath)
	}

	cmd := exec.CommandContext(ctx, "python3", scriptPath,
		"--lab-url", labURL+"/api/ml/evaluate",
		"--episodes", fmt.Sprintf("%d", episodes),
		"--model-dir", modelDir,
	)
	cmd.Env = append(os.Environ(), "LAB_URL="+labURL+"/api/ml/evaluate")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Printf("  Running: python3 %s --episodes %d\n", scriptPath, episodes)
	return cmd.Run()
}

// ---------- benchmark subcommand ----------

func benchmarkCmd() *cobra.Command {
	var (
		labURL      string
		episodes    int
		weightsPath string
	)

	cmd := &cobra.Command{
		Use:   "benchmark",
		Short: "Run N episodes with random or policy-driven configs",
		Long:  `Evaluate stealth configs against the detection engine and report avg bot_score and success rate.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, os.Interrupt)
			go func() {
				<-sigCh
				cancel()
			}()

			result, err := runBenchmark(ctx, strings.TrimRight(labURL, "/"), episodes, weightsPath)
			if err != nil {
				return err
			}

			fmt.Println()
			fmt.Println("Benchmark Results:")
			fmt.Printf("  Episodes:     %d\n", result.Episodes)
			fmt.Printf("  Avg Bot Score: %.4f\n", result.AvgBotScore)
			fmt.Printf("  Success Rate:  %.1f%%\n", result.SuccessRate*100)
			fmt.Printf("  Avg Reward:    %.4f\n", result.AvgReward)
			return nil
		},
	}

	cmd.Flags().StringVar(&labURL, "lab-url", "http://localhost:8080", "Lab server URL")
	cmd.Flags().IntVar(&episodes, "episodes", 100, "Number of episodes")
	cmd.Flags().StringVar(&weightsPath, "weights", "", "Path to DQN weights JSON (omit for random)")

	return cmd
}

// ---------- discover subcommand ----------

func discoverCmd() *cobra.Command {
	var (
		labURL    string
		outputDir string
		headless  bool
	)

	cmd := &cobra.Command{
		Use:   "discover",
		Short: "Launch real Chrome to capture baseline fingerprints",
		Long: `Launch real Chrome through the MITM proxy to capture browser fingerprints
and save them as baseline signature JSONs.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			labURL = strings.TrimRight(labURL, "/")

			fmt.Println("Fingerprint Discovery")
			fmt.Printf("  Lab URL: %s\n", labURL)
			fmt.Printf("  Output:  %s\n", outputDir)
			fmt.Println()

			// Start proxy and capture
			client := &http.Client{Timeout: 30 * time.Second}

			// Launch Chrome via the lab API
			launchReq := struct {
				URL      string `json:"url"`
				Headless bool   `json:"headless"`
			}{
				URL:      labURL + "/capture",
				Headless: headless,
			}
			bodyBytes, _ := json.Marshal(launchReq)

			req, _ := http.NewRequest(http.MethodPost, labURL+"/api/chrome/launch", bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			if err != nil {
				return fmt.Errorf("launch Chrome: %w", err)
			}
			resp.Body.Close()

			fmt.Println("  Chrome launched. Waiting for fingerprint capture...")
			time.Sleep(5 * time.Second)

			// Fetch captured fingerprints
			if err := os.MkdirAll(outputDir, 0o755); err != nil {
				return fmt.Errorf("create output directory: %w", err)
			}

			fpResp, err := http.Get(labURL + "/api/captures?limit=5")
			if err != nil {
				return fmt.Errorf("fetch captures: %w", err)
			}
			defer fpResp.Body.Close()

			outPath := filepath.Join(outputDir, fmt.Sprintf("discovery_%s.json", time.Now().Format("20060102_150405")))
			f, err := os.Create(outPath)
			if err != nil {
				return fmt.Errorf("create output file: %w", err)
			}
			defer f.Close()

			var captures json.RawMessage
			_ = json.NewDecoder(fpResp.Body).Decode(&captures)

			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			_ = enc.Encode(captures)

			fmt.Printf("  Fingerprints saved to %s\n", outPath)

			// Stop Chrome
			stopReq, _ := http.NewRequest(http.MethodPost, labURL+"/api/chrome/stop", nil)
			stopResp, err := client.Do(stopReq)
			if err == nil {
				stopResp.Body.Close()
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&labURL, "lab-url", "http://localhost:8080", "Lab server URL")
	cmd.Flags().StringVar(&outputDir, "output", "signatures/", "Output directory for fingerprint JSONs")
	cmd.Flags().BoolVar(&headless, "headless", false, "Run Chrome headless")

	return cmd
}

// ---------- helpers ----------

func randomConfig(webrtcModes []string) datagen.StealthConfigSnapshot {
	return datagen.StealthConfigSnapshot{
		RemoveWebDriver: rand.Intn(2) == 1,
		CanvasNoise:     rand.Intn(2) == 1,
		WebGLSpoof:      rand.Intn(2) == 1,
		ClientHints:     rand.Intn(2) == 1,
		FakeScreen:      rand.Intn(2) == 1,
		FakeTimezone:    rand.Intn(2) == 1,
		RandomUA:        rand.Intn(2) == 1,
		HardwareSync:    rand.Intn(2) == 1,
		NetworkSync:     rand.Intn(2) == 1,
		PluginsSync:     rand.Intn(2) == 1,
		GeometrySync:    rand.Intn(2) == 1,
		VideoSync:       rand.Intn(2) == 1,
		PermissionsSync: rand.Intn(2) == 1,
		TimezoneSync:    rand.Intn(2) == 1,
		WebRTCMode:      webrtcModes[rand.Intn(len(webrtcModes))],
		CanvasNoiseStr:  rand.Float64() * 0.1,
	}
}

func applyActionToSnapshot(cfg *datagen.StealthConfigSnapshot, actionIdx int) {
	switch actionIdx {
	case 0:
		cfg.RemoveWebDriver = true
	case 1:
		cfg.CanvasNoise = true
	case 2:
		cfg.ClientHints = true
	case 3:
		cfg.RandomUA = true
	case 4:
		cfg.WebGLSpoof = true
	case 5:
		cfg.HardwareSync = true
	case 6:
		cfg.NetworkSync = true
	case 7:
		cfg.PluginsSync = true
	case 8:
		cfg.GeometrySync = true
	case 9:
		cfg.VideoSync = true
	case 10:
		cfg.PermissionsSync = true
	case 11:
		cfg.TimezoneSync = true
	}
}
