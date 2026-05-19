package training

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCollectorCRUD(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	c, err := NewCollector(dbPath)
	if err != nil {
		t.Fatalf("NewCollector: %v", err)
	}
	defer c.Close()

	// Create episode
	ep := &TrainingEpisode{
		EpisodeID:  "ep-001",
		Timestamp:  time.Now(),
		SessionID:  "sess-001",
		TargetURL:  "https://example.com",
		EngineName: "chromium-stealth",
		StealthConfig: StealthConfigSnapshot{
			RemoveWebDriver: true,
			CanvasNoise:     true,
		},
		Detection: DetectionSnapshot{
			WebdriverExposed: false,
			CanvasDetected:   false,
			OverallScore:     0.15,
		},
		FSMState: FSMSnapshot{
			CurrentState: "complete",
		},
		Outcome: RequestOutcome{
			StatusCode: 200,
			Success:    true,
		},
		BotScore:     0.15,
		Reward:       100.0,
		ModelVersion: "v1.0",
	}

	ctx := context.Background()
	if err := c.RecordEpisode(ctx, ep); err != nil {
		t.Fatalf("RecordEpisode: %v", err)
	}

	// Query
	episodes, err := c.Query(EpisodeFilters{Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(episodes) != 1 {
		t.Fatalf("expected 1 episode, got %d", len(episodes))
	}
	if episodes[0].EpisodeID != "ep-001" {
		t.Errorf("expected ep-001, got %s", episodes[0].EpisodeID)
	}

	// Stats
	stats, err := c.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.TotalEpisodes != 1 {
		t.Errorf("expected 1 total, got %d", stats.TotalEpisodes)
	}
}

func TestFeatureVector(t *testing.T) {
	ep := &TrainingEpisode{
		Detection: DetectionSnapshot{
			WebdriverExposed: true,
			CanvasDetected:   true,
		},
		Captcha: &CaptchaSnapshot{
			Presented:   true,
			Solved:      true,
			Difficulty:  0.8,
			SolveTimeMs: 5000,
		},
		Behavioral: &BehavioralSnapshot{
			MouseVelocity: 500,
			TypingSpeed:   100,
			Straightness:  0.7,
		},
	}

	vec := ToFeatureVector(ep)
	if len(vec) != 18 {
		t.Fatalf("expected 18 dims, got %d", len(vec))
	}

	// webdriver_exposed = 1.0
	if vec[0] != 1.0 {
		t.Errorf("vec[0] webdriver: expected 1.0, got %f", vec[0])
	}
	// canvas_detected = 1.0
	if vec[1] != 1.0 {
		t.Errorf("vec[1] canvas: expected 1.0, got %f", vec[1])
	}
	// captcha_presented = 1.0
	if vec[11] != 1.0 {
		t.Errorf("vec[11] captcha_presented: expected 1.0, got %f", vec[11])
	}
	// mouse_velocity normalized (500/2000 = 0.25)
	if vec[14] < 0.24 || vec[14] > 0.26 {
		t.Errorf("vec[14] mouse_velocity: expected ~0.25, got %f", vec[14])
	}
	// straightness = 0.7
	if vec[16] != 0.7 {
		t.Errorf("vec[16] straightness: expected 0.7, got %f", vec[16])
	}
}

func TestExportCSV(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	c, err := NewCollector(dbPath)
	if err != nil {
		t.Fatalf("NewCollector: %v", err)
	}
	defer c.Close()

	ctx := context.Background()
	for i := 0; i < 5; i++ {
		ep := &TrainingEpisode{
			EpisodeID:     fmt.Sprintf("ep-%03d", i),
			Timestamp:     time.Now(),
			SessionID:     "sess-001",
			TargetURL:     "https://example.com",
			EngineName:    "chromium-stealth",
			StealthConfig: StealthConfigSnapshot{},
			Detection:     DetectionSnapshot{},
			FSMState:      FSMSnapshot{},
			Outcome:       RequestOutcome{Success: true, StatusCode: 200},
			BotScore:      float64(i) * 0.2,
			Reward:        float64(100 - i*20),
			ModelVersion:  "v1.0",
		}
		if err := c.RecordEpisode(ctx, ep); err != nil {
			t.Fatalf("RecordEpisode: %v", err)
		}
	}

	// Export CSV
	f, err := os.Create(filepath.Join(dir, "export.csv"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer f.Close()

	count, err := c.ExportCSV(f, EpisodeFilters{})
	if err != nil {
		t.Fatalf("ExportCSV: %v", err)
	}
	if count != 5 {
		t.Errorf("expected 5 rows, got %d", count)
	}
}
