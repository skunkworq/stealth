package datagen

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestEndToEndPipeline validates the complete ML data flow:
// collect episodes → query with filters → export CSV → export JSONL → generate manifest
func TestEndToEndPipeline(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "pipeline.db")

	c, err := NewCollector(dbPath)
	if err != nil {
		t.Fatalf("NewCollector: %v", err)
	}
	defer c.Close()

	ctx := context.Background()

	// Phase 1: Ingest diverse episodes
	engines := []string{"chromium-stealth", "firefox-stealth", "native-go"}
	outcomes := []struct {
		code       int
		success    bool
		blocked    bool
		challenged bool
	}{
		{200, true, false, false},
		{403, false, true, false},
		{503, false, false, true},
	}

	for i := 0; i < 30; i++ {
		engine := engines[i%3]
		outcome := outcomes[i%3]
		ep := &TrainingEpisode{
			EpisodeID:  fmt.Sprintf("ep-%03d", i),
			Timestamp:  time.Now().Add(-time.Duration(30-i) * time.Minute),
			SessionID:  fmt.Sprintf("sess-%03d", i/5),
			TargetURL:  "https://example.com/page",
			EngineName: engine,
			StealthConfig: StealthConfigSnapshot{
				RemoveWebDriver: true,
				CanvasNoise:     i%2 == 0,
				WebGLSpoof:      i%3 == 0,
				ClientHints:     true,
				HardwareSync:    true,
			},
			Detection: DetectionSnapshot{
				WebdriverExposed: i%5 == 0,
				CanvasDetected:   i%4 == 0,
				OverallScore:     float64(i) / 30.0,
			},
			FSMState: FSMSnapshot{
				CurrentState:    "complete",
				TransitionCount: i + 1,
			},
			Outcome: RequestOutcome{
				StatusCode: outcome.code,
				Success:    outcome.success,
				Blocked:    outcome.blocked,
				Challenged: outcome.challenged,
			},
			BotScore:     float64(i) * 0.03,
			Reward:       float64(100 - i*3),
			ModelVersion: "v2.0-test",
		}

		// Add captcha data to some episodes
		if i%3 == 2 {
			ep.Captcha = &CaptchaSnapshot{
				Presented:   true,
				Solved:      i%6 != 0,
				Type:        "turnstile",
				Difficulty:  float64(i%20) * 0.05, // Keep in [0,1] range
				SolveTimeMs: int64(500 + i*100),
			}
		}

		// Add behavioral data to most episodes
		if i%2 == 0 {
			ep.Behavioral = &BehavioralSnapshot{
				MouseVelocity:  float64(200 + i*30),
				TypingSpeed:    float64(50 + i*5),
				Straightness:   0.3 + float64(i)*0.02,
				EventIntervals: float64(50 + i*2),
				TotalEvents:    100 + i*10,
				Clicks:         5 + i,
			}
		}

		if err := c.RecordEpisode(ctx, ep); err != nil {
			t.Fatalf("RecordEpisode[%d]: %v", i, err)
		}
	}

	// Phase 2: Query with various filters
	t.Run("QueryAll", func(t *testing.T) {
		eps, err := c.Query(EpisodeFilters{Limit: 100})
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(eps) != 30 {
			t.Errorf("expected 30 episodes, got %d", len(eps))
		}
	})

	t.Run("QueryByEngine", func(t *testing.T) {
		eps, err := c.Query(EpisodeFilters{EngineName: "chromium-stealth", Limit: 100})
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(eps) != 10 {
			t.Errorf("expected 10 chromium episodes, got %d", len(eps))
		}
		for _, ep := range eps {
			if ep.EngineName != "chromium-stealth" {
				t.Errorf("got wrong engine: %s", ep.EngineName)
			}
		}
	})

	t.Run("QueryByBotScore", func(t *testing.T) {
		eps, err := c.Query(EpisodeFilters{MinBotScore: 0.5, Limit: 100})
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		for _, ep := range eps {
			if ep.BotScore < 0.5 {
				t.Errorf("got episode with bot_score %.2f, expected >= 0.5", ep.BotScore)
			}
		}
	})

	t.Run("QueryWithPagination", func(t *testing.T) {
		page1, err := c.Query(EpisodeFilters{Limit: 10, Offset: 0})
		if err != nil {
			t.Fatalf("Query page 1: %v", err)
		}
		page2, err := c.Query(EpisodeFilters{Limit: 10, Offset: 10})
		if err != nil {
			t.Fatalf("Query page 2: %v", err)
		}

		if len(page1) != 10 || len(page2) != 10 {
			t.Errorf("expected 10 per page, got %d and %d", len(page1), len(page2))
		}
		if page1[0].EpisodeID == page2[0].EpisodeID {
			t.Error("pages should not overlap")
		}
	})

	// Phase 3: Export CSV and validate
	t.Run("ExportCSV", func(t *testing.T) {
		var buf bytes.Buffer
		count, err := c.ExportCSV(&buf, EpisodeFilters{Limit: 100})
		if err != nil {
			t.Fatalf("ExportCSV: %v", err)
		}
		if count != 30 {
			t.Errorf("expected 30 rows, got %d", count)
		}

		// Parse CSV and validate structure
		r := csv.NewReader(&buf)
		header, err := r.Read()
		if err != nil {
			t.Fatalf("read header: %v", err)
		}
		if len(header) != 23 {
			t.Errorf("expected 23 columns, got %d", len(header))
		}
		if header[0] != "episode_id" {
			t.Errorf("expected first column 'episode_id', got %q", header[0])
		}
		if header[5] != "f0" {
			t.Errorf("expected column 5 to be 'f0', got %q", header[5])
		}

		// Count data rows
		rowCount := 0
		for {
			_, err := r.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("read row: %v", err)
			}
			rowCount++
		}
		if rowCount != 30 {
			t.Errorf("expected 30 data rows, got %d", rowCount)
		}
	})

	// Phase 4: Export JSONL and validate
	t.Run("ExportJSONL", func(t *testing.T) {
		var buf bytes.Buffer
		count, err := c.ExportJSONL(&buf, EpisodeFilters{Limit: 100})
		if err != nil {
			t.Fatalf("ExportJSONL: %v", err)
		}
		if count != 30 {
			t.Errorf("expected 30 lines, got %d", count)
		}

		// Validate each line is valid JSON
		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		if len(lines) != 30 {
			t.Errorf("expected 30 lines, got %d", len(lines))
		}
		for i, line := range lines {
			var ep TrainingEpisode
			if err := json.Unmarshal([]byte(line), &ep); err != nil {
				t.Errorf("line %d: invalid JSON: %v", i, err)
			}
			if ep.EpisodeID == "" {
				t.Errorf("line %d: empty episode ID", i)
			}
		}
	})

	// Phase 5: Generate manifest and validate
	t.Run("ExportManifest", func(t *testing.T) {
		manifest, err := c.ExportManifest(EpisodeFilters{Limit: 100})
		if err != nil {
			t.Fatalf("ExportManifest: %v", err)
		}
		if manifest.RowCount != 30 {
			t.Errorf("manifest row count: expected 30, got %d", manifest.RowCount)
		}
		if manifest.FeatureDimension != 18 {
			t.Errorf("feature dimension: expected 18, got %d", manifest.FeatureDimension)
		}
		if len(manifest.Columns) != 23 {
			t.Errorf("columns: expected 23, got %d", len(manifest.Columns))
		}

		// Verify label distribution sums to 30
		total := manifest.LabelDistribution["success"] +
			manifest.LabelDistribution["blocked"] +
			manifest.LabelDistribution["challenged"]
		if total != 30 {
			t.Errorf("label distribution sum: expected 30, got %d", total)
		}

		// Verify manifest serializes to valid JSON
		manifestJSON, err := json.Marshal(manifest)
		if err != nil {
			t.Fatalf("marshal manifest: %v", err)
		}
		var decoded Manifest
		if err := json.Unmarshal(manifestJSON, &decoded); err != nil {
			t.Fatalf("unmarshal manifest: %v", err)
		}
		if decoded.RowCount != 30 {
			t.Error("manifest roundtrip failed")
		}
	})

	// Phase 6: Stats validation
	t.Run("Stats", func(t *testing.T) {
		stats, err := c.Stats()
		if err != nil {
			t.Fatalf("Stats: %v", err)
		}
		if stats.TotalEpisodes != 30 {
			t.Errorf("total: expected 30, got %d", stats.TotalEpisodes)
		}
		if len(stats.ByEngine) != 3 {
			t.Errorf("expected 3 engines, got %d", len(stats.ByEngine))
		}
		for _, name := range engines {
			if count, ok := stats.ByEngine[name]; !ok || count != 10 {
				t.Errorf("engine %s: expected 10, got %d (ok=%v)", name, count, ok)
			}
		}
	})

	// Phase 7: Feature vector consistency check
	t.Run("FeatureVectorConsistency", func(t *testing.T) {
		eps, err := c.Query(EpisodeFilters{Limit: 100})
		if err != nil {
			t.Fatalf("Query: %v", err)
		}

		for _, ep := range eps {
			vec := ToFeatureVector(&ep)
			if len(vec) != 18 {
				t.Errorf("ep %s: expected 18 dims, got %d", ep.EpisodeID, len(vec))
			}

			// All values should be in [0, 1]
			for j, v := range vec {
				if v < 0 || v > 1 {
					t.Errorf("ep %s dim %d: value %f out of [0,1] range", ep.EpisodeID, j, v)
				}
			}
		}
	})

	// Phase 8: Verify file export works
	t.Run("FileExport", func(t *testing.T) {
		csvPath := filepath.Join(dir, "export.csv")
		jsonlPath := filepath.Join(dir, "export.jsonl")
		manifestPath := filepath.Join(dir, "manifest.json")

		// CSV
		csvFile, _ := os.Create(csvPath)
		c.ExportCSV(csvFile, EpisodeFilters{Limit: 100})
		csvFile.Close()

		csvInfo, _ := os.Stat(csvPath)
		if csvInfo.Size() == 0 {
			t.Error("CSV file is empty")
		}

		// JSONL
		jsonlFile, _ := os.Create(jsonlPath)
		c.ExportJSONL(jsonlFile, EpisodeFilters{Limit: 100})
		jsonlFile.Close()

		jsonlInfo, _ := os.Stat(jsonlPath)
		if jsonlInfo.Size() == 0 {
			t.Error("JSONL file is empty")
		}

		// Manifest
		manifest, _ := c.ExportManifest(EpisodeFilters{Limit: 100})
		manifestData, _ := json.MarshalIndent(manifest, "", "  ")
		os.WriteFile(manifestPath, manifestData, 0o644)

		manifestInfo, _ := os.Stat(manifestPath)
		if manifestInfo.Size() == 0 {
			t.Error("Manifest file is empty")
		}
	})
}

// TestFeatureVectorBoundaryConditions tests edge cases for feature extraction
func TestFeatureVectorBoundaryConditions(t *testing.T) {
	t.Run("NilCaptchaAndBehavioral", func(t *testing.T) {
		ep := &TrainingEpisode{
			Detection: DetectionSnapshot{},
		}
		vec := ToFeatureVector(ep)
		if len(vec) != 18 {
			t.Fatalf("expected 18 dims, got %d", len(vec))
		}
		// CAPTCHA and behavioral dims should be 0
		for i := 11; i <= 17; i++ {
			if vec[i] != 0 {
				t.Errorf("dim %d should be 0 with nil snapshots, got %f", i, vec[i])
			}
		}
	})

	t.Run("MaxValues", func(t *testing.T) {
		ep := &TrainingEpisode{
			Detection: DetectionSnapshot{
				WebdriverExposed:    true,
				CanvasDetected:      true,
				ClientHintsIssues:   true,
				IsomorphicIssues:    true,
				HardwareMismatch:    true,
				NetworkMismatch:     true,
				PluginsDetected:     true,
				GeometryMismatch:    true,
				VideoDetected:       true,
				PermissionsMismatch: true,
				TimezoneMismatch:    true,
			},
			Captcha: &CaptchaSnapshot{
				Presented:   true,
				Solved:      true,
				Difficulty:  1.0,
				SolveTimeMs: 60000, // Well above 30s max
			},
			Behavioral: &BehavioralSnapshot{
				MouseVelocity: 5000, // Well above 2000 max
				TypingSpeed:   1000, // Well above 500 max
				Straightness:  1.0,
			},
		}
		vec := ToFeatureVector(ep)

		// All detection dims should be 1.0
		for i := 0; i <= 10; i++ {
			if vec[i] != 1.0 {
				t.Errorf("dim %d: expected 1.0, got %f", i, vec[i])
			}
		}

		// Clamped values should be at 1.0
		if vec[14] != 1.0 {
			t.Errorf("mouse_velocity should clamp to 1.0, got %f", vec[14])
		}
		if vec[15] != 1.0 {
			t.Errorf("typing_speed should clamp to 1.0, got %f", vec[15])
		}
		if vec[17] != 1.0 {
			t.Errorf("solve_time should clamp to 1.0, got %f", vec[17])
		}
	})

	t.Run("AllDetectionsFalse", func(t *testing.T) {
		ep := &TrainingEpisode{
			Detection: DetectionSnapshot{},
		}
		vec := ToFeatureVector(ep)
		for i := 0; i <= 10; i++ {
			if vec[i] != 0.0 {
				t.Errorf("dim %d: expected 0.0, got %f", i, vec[i])
			}
		}
	})
}
