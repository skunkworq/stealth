// ml_datagen generates, exports, and inspects ML training data for the stealth
// browser platform. It connects to a running lab server to evaluate randomized
// stealth configurations and stores the resulting episodes in a local SQLite
// database for downstream model training.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/skunkworq/stealth/brws/fingerprint/train/datagen"
)

var (
	dbPath  string
	version = "0.1.0"
)

func main() {
	rootCmd := &cobra.Command{
		Use:     "ml_datagen",
		Short:   "ML training data generator for the stealth browser platform",
		Version: version,
		Long: `ml_datagen generates, exports, and inspects ML training data.

It connects to a running lab server, evaluates randomized stealth configurations,
and stores structured training episodes in a local SQLite database. The collected
data can then be exported as CSV or JSONL for downstream model training.

Examples:
  # Generate 500 training episodes
  ml_datagen generate --episodes 500 --db data/training.db --lab-url http://localhost:8080

  # Export as CSV
  ml_datagen export --db data/training.db --format csv --output data/training/

  # View collection statistics
  ml_datagen stats --db data/training.db`,
	}

	rootCmd.PersistentFlags().StringVar(&dbPath, "db", "data/training.db", "Path to the SQLite training database")

	rootCmd.AddCommand(generateCmd())
	rootCmd.AddCommand(exportCmd())
	rootCmd.AddCommand(statsCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// ---------- generate subcommand ----------

func generateCmd() *cobra.Command {
	var (
		episodes int
		labURL   string
	)

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate training episodes by evaluating randomized stealth configs",
		Long: `Connect to the lab API and generate training episodes. For each episode a
randomized stealth configuration is sent to the lab's ML evaluation endpoint.
The response (bot score, anomalies, captcha info) is recorded as a structured
TrainingEpisode in the local SQLite database.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGenerate(episodes, labURL)
		},
	}

	cmd.Flags().IntVar(&episodes, "episodes", 500, "Number of episodes to generate")
	cmd.Flags().StringVar(&labURL, "lab-url", "http://localhost:8080", "Lab server URL")

	return cmd
}

// evaluateRequest is the payload sent to the lab evaluation endpoint.
type evaluateRequest struct {
	StealthConfig datagen.StealthConfigSnapshot `json:"stealth_config"`
	EngineName    string                        `json:"engine_name"`
	FastMode      bool                          `json:"fast_mode"`
}

// evaluateResponse is the expected response from the lab evaluation endpoint.
type evaluateResponse struct {
	BotScore  float64 `json:"bot_score"`
	Anomalies struct {
		WebdriverExposed    bool `json:"webdriver_exposed"`
		CanvasDetected      bool `json:"canvas_detected"`
		ClientHintsIssues   bool `json:"client_hints_issues"`
		IsomorphicIssues    bool `json:"isomorphic_issues"`
		HardwareMismatch    bool `json:"hardware_mismatch"`
		NetworkMismatch     bool `json:"network_mismatch"`
		PluginsDetected     bool `json:"plugins_detected"`
		GeometryMismatch    bool `json:"geometry_mismatch"`
		VideoDetected       bool `json:"video_detected"`
		PermissionsMismatch bool `json:"permissions_mismatch"`
		TimezoneMismatch    bool `json:"timezone_mismatch"`
	} `json:"anomalies"`
	Captcha *struct {
		Presented   bool    `json:"presented"`
		Solved      bool    `json:"solved"`
		Type        string  `json:"type"`
		Difficulty  float64 `json:"difficulty"`
		SolveTimeMs int64   `json:"solve_time_ms"`
	} `json:"captcha,omitempty"`
	Outcome struct {
		StatusCode int    `json:"status_code"`
		Blocked    bool   `json:"blocked"`
		Challenged bool   `json:"challenged"`
		Success    bool   `json:"success"`
		Error      string `json:"error,omitempty"`
	} `json:"outcome"`
}

func runGenerate(episodes int, labURL string) error {
	// Ensure the database directory exists.
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle Ctrl+C for clean shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		fmt.Println("\nShutting down gracefully...")
		cancel()
	}()

	labURL = strings.TrimRight(labURL, "/")
	client := &http.Client{Timeout: 30 * time.Second}
	engineNames := []string{"chromium", "firefox", "native", "webkit"}
	webrtcModes := []string{"disabled", "fake", "real"}

	fmt.Printf("Generating %d training episodes (lab: %s, db: %s)\n", episodes, labURL, dbPath)
	fmt.Println(strings.Repeat("-", 60))

	sessionID := uuid.New().String()
	generated := 0

	for i := 0; i < episodes; i++ {
		// Check for cancellation.
		select {
		case <-ctx.Done():
			fmt.Printf("\nInterrupted after %d episodes.\n", generated)
			return nil
		default:
		}

		engineName := engineNames[rand.Intn(len(engineNames))]
		config := randomStealthConfig(webrtcModes)

		reqBody := evaluateRequest{
			StealthConfig: config,
			EngineName:    engineName,
			FastMode:      true,
		}
		bodyBytes, _ := json.Marshal(reqBody)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, labURL+"/api/ml/evaluate", bytes.NewReader(bodyBytes))
		if err != nil {
			return fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			// On context cancellation, exit cleanly.
			if ctx.Err() != nil {
				fmt.Printf("\nInterrupted after %d episodes.\n", generated)
				return nil
			}
			fmt.Fprintf(os.Stderr, "  [%d] request error: %v\n", i+1, err)
			continue
		}

		var evalResp evaluateResponse
		if err := json.NewDecoder(resp.Body).Decode(&evalResp); err != nil {
			resp.Body.Close()
			fmt.Fprintf(os.Stderr, "  [%d] decode error: %v\n", i+1, err)
			continue
		}
		resp.Body.Close()

		ep := buildEpisode(sessionID, engineName, config, &evalResp, labURL)

		if err := collector.RecordEpisode(ctx, ep); err != nil {
			if ctx.Err() != nil {
				fmt.Printf("\nInterrupted after %d episodes.\n", generated)
				return nil
			}
			fmt.Fprintf(os.Stderr, "  [%d] record error: %v\n", i+1, err)
			continue
		}

		generated++

		// Progress every 10 episodes.
		if generated%10 == 0 {
			fmt.Printf("  [%d/%d] generated (bot_score=%.3f, engine=%s)\n",
				generated, episodes, ep.BotScore, ep.EngineName)
		}
	}

	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("Done. %d episodes recorded to %s\n", generated, dbPath)

	return nil
}

func randomStealthConfig(webrtcModes []string) datagen.StealthConfigSnapshot {
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

func buildEpisode(sessionID, engineName string, config datagen.StealthConfigSnapshot, resp *evaluateResponse, labURL string) *datagen.TrainingEpisode {
	ep := &datagen.TrainingEpisode{
		EpisodeID:     uuid.New().String(),
		Timestamp:     time.Now(),
		SessionID:     sessionID,
		TargetURL:     labURL + "/api/ml/evaluate",
		EngineName:    engineName,
		StealthConfig: config,
		Detection: datagen.DetectionSnapshot{
			WebdriverExposed:    resp.Anomalies.WebdriverExposed,
			CanvasDetected:      resp.Anomalies.CanvasDetected,
			ClientHintsIssues:   resp.Anomalies.ClientHintsIssues,
			IsomorphicIssues:    resp.Anomalies.IsomorphicIssues,
			HardwareMismatch:    resp.Anomalies.HardwareMismatch,
			NetworkMismatch:     resp.Anomalies.NetworkMismatch,
			PluginsDetected:     resp.Anomalies.PluginsDetected,
			GeometryMismatch:    resp.Anomalies.GeometryMismatch,
			VideoDetected:       resp.Anomalies.VideoDetected,
			PermissionsMismatch: resp.Anomalies.PermissionsMismatch,
			TimezoneMismatch:    resp.Anomalies.TimezoneMismatch,
			OverallScore:        resp.BotScore,
		},
		FSMState: datagen.FSMSnapshot{
			CurrentState: "evaluate",
		},
		Outcome: datagen.RequestOutcome{
			StatusCode:   resp.Outcome.StatusCode,
			Blocked:      resp.Outcome.Blocked,
			Challenged:   resp.Outcome.Challenged,
			Success:      resp.Outcome.Success,
			ErrorMessage: resp.Outcome.Error,
		},
		BotScore:     resp.BotScore,
		Reward:       computeReward(resp),
		ModelVersion: "v0.1.0",
	}

	if resp.Captcha != nil {
		ep.Captcha = &datagen.CaptchaSnapshot{
			Presented:   resp.Captcha.Presented,
			Solved:      resp.Captcha.Solved,
			Type:        resp.Captcha.Type,
			Difficulty:  resp.Captcha.Difficulty,
			SolveTimeMs: resp.Captcha.SolveTimeMs,
		}
	}

	return ep
}

// computeReward derives a scalar reward signal from the evaluation response.
// Lower bot scores and successful outcomes yield higher rewards.
func computeReward(resp *evaluateResponse) float64 {
	reward := 1.0 - resp.BotScore
	if resp.Outcome.Blocked {
		reward -= 0.5
	}
	if resp.Outcome.Challenged {
		reward -= 0.25
	}
	if resp.Outcome.Success {
		reward += 0.25
	}
	// Clamp to [-1, 1].
	if reward > 1.0 {
		reward = 1.0
	}
	if reward < -1.0 {
		reward = -1.0
	}
	return reward
}

// ---------- export subcommand ----------

func exportCmd() *cobra.Command {
	var (
		format    string
		outputDir string
	)

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export training data to CSV or JSONL",
		Long: `Read episodes from the SQLite database and export them in the specified
format. A manifest.json sidecar is always written alongside the data file.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runExport(format, outputDir)
		},
	}

	cmd.Flags().StringVar(&format, "format", "csv", "Export format (csv, jsonl)")
	cmd.Flags().StringVar(&outputDir, "output", "data/training/", "Output directory")

	return cmd
}

func runExport(format, outputDir string) error {
	collector, err := datagen.NewCollector(dbPath)
	if err != nil {
		return fmt.Errorf("open collector: %w", err)
	}
	defer collector.Close()

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	filters := datagen.EpisodeFilters{}

	// Export data file.
	var dataFile string
	switch strings.ToLower(format) {
	case "csv":
		dataFile = filepath.Join(outputDir, "training.csv")
		f, err := os.Create(dataFile)
		if err != nil {
			return fmt.Errorf("create csv file: %w", err)
		}
		defer f.Close()

		n, err := collector.ExportCSV(f, filters)
		if err != nil {
			return fmt.Errorf("export csv: %w", err)
		}
		fmt.Printf("Exported %d episodes to %s\n", n, dataFile)

	case "jsonl":
		dataFile = filepath.Join(outputDir, "training.jsonl")
		f, err := os.Create(dataFile)
		if err != nil {
			return fmt.Errorf("create jsonl file: %w", err)
		}
		defer f.Close()

		n, err := collector.ExportJSONL(f, filters)
		if err != nil {
			return fmt.Errorf("export jsonl: %w", err)
		}
		fmt.Printf("Exported %d episodes to %s\n", n, dataFile)

	default:
		return fmt.Errorf("unsupported format: %s (use csv or jsonl)", format)
	}

	// Write manifest sidecar.
	manifest, err := collector.ExportManifest(filters)
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
	fmt.Printf("Wrote manifest to %s\n", manifestPath)

	return nil
}

// ---------- stats subcommand ----------

func statsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stats",
		Short: "Display collection statistics",
		Long:  `Open the SQLite database and print a formatted summary of the collected training data.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStats()
		},
	}
}

func runStats() error {
	collector, err := datagen.NewCollector(dbPath)
	if err != nil {
		return fmt.Errorf("open collector: %w", err)
	}
	defer collector.Close()

	stats, err := collector.Stats()
	if err != nil {
		return fmt.Errorf("get stats: %w", err)
	}

	fmt.Println("ML Training Data Statistics")
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("  Database:         %s\n", dbPath)
	fmt.Printf("  Total Episodes:   %d\n", stats.TotalEpisodes)
	fmt.Printf("  Avg Bot Score:    %.4f\n", stats.AvgBotScore)
	fmt.Printf("  Avg Reward:       %.4f\n", stats.AvgReward)
	fmt.Println()

	if stats.DateRange[0] != "" {
		fmt.Println("  Date Range:")
		fmt.Printf("    From: %s\n", stats.DateRange[0])
		fmt.Printf("    To:   %s\n", stats.DateRange[1])
		fmt.Println()
	}

	if len(stats.ByEngine) > 0 {
		fmt.Println("  Episodes by Engine:")
		for engine, count := range stats.ByEngine {
			pct := 0.0
			if stats.TotalEpisodes > 0 {
				pct = float64(count) / float64(stats.TotalEpisodes) * 100
			}
			fmt.Printf("    %-15s %5d  (%.1f%%)\n", engine, count, pct)
		}
		fmt.Println()
	}

	if len(stats.ByOutcome) > 0 {
		fmt.Println("  Episodes by Outcome:")
		for outcome, count := range stats.ByOutcome {
			pct := 0.0
			if stats.TotalEpisodes > 0 {
				pct = float64(count) / float64(stats.TotalEpisodes) * 100
			}
			fmt.Printf("    %-15s %5d  (%.1f%%)\n", outcome, count, pct)
		}
		fmt.Println()
	}

	fmt.Println(strings.Repeat("=", 50))

	return nil
}
