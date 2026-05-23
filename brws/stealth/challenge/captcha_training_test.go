package challenge

import (
	"encoding/json"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// CaptchaTracer tests
// ---------------------------------------------------------------------------

func TestNewCaptchaTracer(t *testing.T) {
	ct := NewCaptchaTracer()
	if ct == nil {
		t.Fatal("NewCaptchaTracer() returned nil")
	}
	if ct.traces == nil {
		t.Error("expected non-nil traces map")
	}
}

func TestCaptchaTracer_CreateTrace(t *testing.T) {
	ct := NewCaptchaTracer()
	trace := ct.CreateTrace("chg-001", "sess-abc", "text")

	if trace == nil {
		t.Fatal("CreateTrace() returned nil")
	}
	if trace.ChallengeID != "chg-001" {
		t.Errorf("ChallengeID: want %q, got %q", "chg-001", trace.ChallengeID)
	}
	if trace.SessionID != "sess-abc" {
		t.Errorf("SessionID: want %q, got %q", "sess-abc", trace.SessionID)
	}
	if trace.Type != "text" {
		t.Errorf("Type: want %q, got %q", "text", trace.Type)
	}
	if trace.Events == nil {
		t.Error("Events should be initialized (not nil)")
	}
	if trace.Metrics == nil {
		t.Error("Metrics should be initialized (not nil)")
	}
	if trace.CreatedAt.IsZero() {
		t.Error("CreatedAt should not be zero")
	}
}

func TestCaptchaTracer_GetTrace_Exists(t *testing.T) {
	ct := NewCaptchaTracer()
	ct.CreateTrace("chg-001", "sess-abc", "text")

	trace, ok := ct.GetTrace("chg-001")
	if !ok {
		t.Fatal("GetTrace should find a trace that was created")
	}
	if trace == nil {
		t.Fatal("GetTrace returned nil trace")
	}
	if trace.ChallengeID != "chg-001" {
		t.Errorf("ChallengeID: want %q, got %q", "chg-001", trace.ChallengeID)
	}
}

func TestCaptchaTracer_GetTrace_NotFound(t *testing.T) {
	ct := NewCaptchaTracer()

	_, ok := ct.GetTrace("nonexistent")
	if ok {
		t.Error("GetTrace should return false for non-existent challenge")
	}
}

func TestCaptchaTracer_AddEvent_UpdatesMetrics(t *testing.T) {
	ct := NewCaptchaTracer()
	ct.CreateTrace("chg-001", "sess-abc", "text")

	baseTime := time.Now().UnixMilli()
	events := []CaptchaEvent{
		{Type: "mousemove", Timestamp: baseTime + 100, ElapsedMs: 100, X: 10, Y: 20},
		{Type: "mousemove", Timestamp: baseTime + 200, ElapsedMs: 200, X: 50, Y: 60},
		{Type: "keydown", Timestamp: baseTime + 300, ElapsedMs: 300, Key: "a"},
		{Type: "scroll", Timestamp: baseTime + 400, ElapsedMs: 400, Delta: 50},
		{Type: "click", Timestamp: baseTime + 500, ElapsedMs: 500, X: 100, Y: 200},
	}

	for _, ev := range events {
		ct.AddEvent("chg-001", ev)
	}

	trace, _ := ct.GetTrace("chg-001")
	if trace.Metrics.TotalEvents != 5 {
		t.Errorf("TotalEvents: want 5, got %d", trace.Metrics.TotalEvents)
	}
	if trace.Metrics.MouseMovements != 2 {
		t.Errorf("MouseMovements: want 2, got %d", trace.Metrics.MouseMovements)
	}
	if trace.Metrics.Keystrokes != 1 {
		t.Errorf("Keystrokes: want 1, got %d", trace.Metrics.Keystrokes)
	}
	if trace.Metrics.ScrollEvents != 1 {
		t.Errorf("ScrollEvents: want 1, got %d", trace.Metrics.ScrollEvents)
	}
	if trace.Metrics.Clicks != 1 {
		t.Errorf("Clicks: want 1, got %d", trace.Metrics.Clicks)
	}
}

func TestCaptchaTracer_AddEvent_NoOpForUnknownChallenge(t *testing.T) {
	ct := NewCaptchaTracer()

	// Should not panic for unknown challenge ID
	ct.AddEvent("nonexistent", CaptchaEvent{Type: "click", Timestamp: 1000})
}

func TestCaptchaTracer_CalculateBotScore_FewEvents(t *testing.T) {
	ct := NewCaptchaTracer()
	ct.CreateTrace("chg-001", "sess-abc", "text")

	// Only 2 events → TotalEvents < 5 → +0.4 score at minimum
	ct.AddEvent("chg-001", CaptchaEvent{Type: "click", Timestamp: 1000, X: 10, Y: 20})
	ct.AddEvent("chg-001", CaptchaEvent{Type: "click", Timestamp: 2000, X: 15, Y: 25})

	trace, _ := ct.GetTrace("chg-001")
	score := ct.CalculateBotScore(trace)
	if score < 0.4 {
		t.Errorf("expected score >= 0.4 for few events, got %f", score)
	}
	if score > 1.0 {
		t.Errorf("score should be capped at 1.0, got %f", score)
	}
}

func TestCaptchaTracer_CalculateBotScore_Range(t *testing.T) {
	ct := NewCaptchaTracer()
	ct.CreateTrace("chg-001", "sess-abc", "text")

	trace, _ := ct.GetTrace("chg-001")
	score := ct.CalculateBotScore(trace)
	if score < 0 || score > 1 {
		t.Errorf("bot score should be in [0,1], got %f", score)
	}
}

func TestCaptchaTracer_CreateDetectionTrace_Nil(t *testing.T) {
	ct := NewCaptchaTracer()
	dt := ct.CreateDetectionTrace(nil)
	if dt != nil {
		t.Errorf("expected nil DetectionTrace for nil DetectionResult, got %+v", dt)
	}
}

// ---------------------------------------------------------------------------
// CaptchaTrainingData tests
// ---------------------------------------------------------------------------

func TestNewCaptchaTrainingData(t *testing.T) {
	td := NewCaptchaTrainingData()
	if td == nil {
		t.Fatal("NewCaptchaTrainingData() returned nil")
	}
	if td.Size() != 0 {
		t.Errorf("new training data should have size 0, got %d", td.Size())
	}
}

func TestCaptchaTrainingData_RecordSample(t *testing.T) {
	td := NewCaptchaTrainingData()

	sample := TrainingSample{
		ID:            "s-001",
		Timestamp:     time.Now(),
		ChallengeType: ChallengeCloudflare,
		Label:         "human",
		Features:      []float64{1.0, 2.0, 3.0},
	}

	td.RecordSample(sample)

	if td.Size() != 1 {
		t.Errorf("expected size 1 after one RecordSample, got %d", td.Size())
	}
}

func TestCaptchaTrainingData_RecordMultipleSamples(t *testing.T) {
	td := NewCaptchaTrainingData()

	for i := 0; i < 5; i++ {
		td.RecordSample(TrainingSample{
			Label:    "bot",
			Features: []float64{float64(i)},
		})
	}

	if td.Size() != 5 {
		t.Errorf("expected size 5, got %d", td.Size())
	}
}

func TestCaptchaTrainingData_GetLabels(t *testing.T) {
	td := NewCaptchaTrainingData()

	td.RecordSample(TrainingSample{Label: "human", Features: []float64{1}})
	td.RecordSample(TrainingSample{Label: "bot", Features: []float64{2}})

	labels := td.GetLabels()
	if len(labels) != 2 {
		t.Errorf("expected 2 labels, got %d", len(labels))
	}
	if labels[0] != "human" {
		t.Errorf("labels[0]: want %q, got %q", "human", labels[0])
	}
	if labels[1] != "bot" {
		t.Errorf("labels[1]: want %q, got %q", "bot", labels[1])
	}
}

func TestCaptchaTrainingData_GetFeatures(t *testing.T) {
	td := NewCaptchaTrainingData()

	td.RecordSample(TrainingSample{Label: "human", Features: []float64{1.1, 2.2}})
	td.RecordSample(TrainingSample{Label: "bot", Features: []float64{3.3, 4.4}})

	features := td.GetFeatures()
	if len(features) != 2 {
		t.Errorf("expected 2 feature rows, got %d", len(features))
	}
}

func TestCaptchaTrainingData_GetStats(t *testing.T) {
	td := NewCaptchaTrainingData()

	td.RecordSample(TrainingSample{Label: "human", ChallengeType: ChallengeCloudflare, Features: []float64{1}})
	td.RecordSample(TrainingSample{Label: "human", ChallengeType: ChallengeCloudflare, Features: []float64{2}})
	td.RecordSample(TrainingSample{Label: "bot", ChallengeType: ChallengeRecaptchaV2, Features: []float64{3}})

	stats := td.GetStats()
	if stats.TotalSamples != 3 {
		t.Errorf("TotalSamples: want 3, got %d", stats.TotalSamples)
	}
	if stats.ByLabel["human"] != 2 {
		t.Errorf("ByLabel[human]: want 2, got %d", stats.ByLabel["human"])
	}
	if stats.ByLabel["bot"] != 1 {
		t.Errorf("ByLabel[bot]: want 1, got %d", stats.ByLabel["bot"])
	}
	if stats.ByType[string(ChallengeCloudflare)] != 2 {
		t.Errorf("ByType[%s]: want 2, got %d", ChallengeCloudflare, stats.ByType[string(ChallengeCloudflare)])
	}
}

func TestCaptchaTrainingData_ExportJSON(t *testing.T) {
	td := NewCaptchaTrainingData()

	td.RecordSample(TrainingSample{
		ID:    "s-001",
		Label: "human",
	})

	data, err := td.ExportJSON()
	if err != nil {
		t.Fatalf("ExportJSON() failed: %v", err)
	}
	if len(data) == 0 {
		t.Error("ExportJSON() returned empty bytes")
	}

	var samples []TrainingSample
	if err := json.Unmarshal(data, &samples); err != nil {
		t.Fatalf("ExportJSON() output is not valid JSON: %v", err)
	}
	if len(samples) != 1 {
		t.Errorf("expected 1 sample in JSON, got %d", len(samples))
	}
}

func TestCaptchaTrainingData_ExportForML(t *testing.T) {
	td := NewCaptchaTrainingData()

	td.RecordSample(TrainingSample{Label: "human", Features: []float64{1, 2, 3}})
	td.RecordSample(TrainingSample{Label: "bot", Features: []float64{4, 5, 6}})

	data, err := td.ExportForML()
	if err != nil {
		t.Fatalf("ExportForML() failed: %v", err)
	}

	var out struct {
		Features [][]float64 `json:"features"`
		Labels   []string    `json:"labels"`
		Metadata struct {
			TotalSamples int `json:"total_samples"`
			HumanSamples int `json:"human_samples"`
			BotSamples   int `json:"bot_samples"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("ExportForML() output is not valid JSON: %v", err)
	}
	if out.Metadata.TotalSamples != 2 {
		t.Errorf("TotalSamples: want 2, got %d", out.Metadata.TotalSamples)
	}
	if out.Metadata.HumanSamples != 1 {
		t.Errorf("HumanSamples: want 1, got %d", out.Metadata.HumanSamples)
	}
	if out.Metadata.BotSamples != 1 {
		t.Errorf("BotSamples: want 1, got %d", out.Metadata.BotSamples)
	}
}

func TestCaptchaTrainingData_ExportCSV(t *testing.T) {
	td := NewCaptchaTrainingData()

	td.RecordSample(TrainingSample{
		ID:        "s-001",
		Label:     "human",
		SessionID: "sess-1",
	})

	data, err := td.ExportCSV()
	if err != nil {
		t.Fatalf("ExportCSV() failed: %v", err)
	}
	csv := string(data)
	if csv == "" {
		t.Error("ExportCSV() returned empty string")
	}
	// Must include the header
	if len(csv) < 10 {
		t.Errorf("CSV output too short: %q", csv)
	}
}

func TestCaptchaTrainingData_GetSamplesFiltered_NoFilter(t *testing.T) {
	td := NewCaptchaTrainingData()

	for i := 0; i < 5; i++ {
		td.RecordSample(TrainingSample{Label: "human", Features: []float64{float64(i)}})
	}

	samples, total := td.GetSamplesFiltered("", "", 10, 0)
	if total != 5 {
		t.Errorf("total: want 5, got %d", total)
	}
	if len(samples) != 5 {
		t.Errorf("samples: want 5, got %d", len(samples))
	}
}

func TestCaptchaTrainingData_GetSamplesFiltered_Pagination(t *testing.T) {
	td := NewCaptchaTrainingData()

	for i := 0; i < 10; i++ {
		td.RecordSample(TrainingSample{Label: "human", Features: []float64{float64(i)}})
	}

	samples, total := td.GetSamplesFiltered("", "", 3, 5)
	if total != 10 {
		t.Errorf("total: want 10, got %d", total)
	}
	if len(samples) != 3 {
		t.Errorf("samples (limit=3, offset=5): want 3, got %d", len(samples))
	}
}

func TestCaptchaTrainingData_GetSamplesFiltered_OffsetPastEnd(t *testing.T) {
	td := NewCaptchaTrainingData()

	td.RecordSample(TrainingSample{Label: "human", Features: []float64{1}})

	samples, total := td.GetSamplesFiltered("", "", 10, 999)
	if total != 1 {
		t.Errorf("total: want 1, got %d", total)
	}
	if len(samples) != 0 {
		t.Errorf("samples past end: want 0, got %d", len(samples))
	}
}

func TestCaptchaTrainingData_GetSamplesFiltered_LabelFilter(t *testing.T) {
	td := NewCaptchaTrainingData()

	td.RecordSample(TrainingSample{Label: "human", Features: []float64{1}})
	td.RecordSample(TrainingSample{Label: "bot", Features: []float64{2}})
	td.RecordSample(TrainingSample{Label: "human", Features: []float64{3}})

	samples, total := td.GetSamplesFiltered("", "human", 10, 0)
	if total != 2 {
		t.Errorf("total (label=human): want 2, got %d", total)
	}
	if len(samples) != 2 {
		t.Errorf("samples (label=human): want 2, got %d", len(samples))
	}
}

func TestCaptchaTrainingData_RecordEvent(t *testing.T) {
	td := NewCaptchaTrainingData()

	ev := &CaptchaEvent{Type: "click", Timestamp: 1000, X: 10, Y: 20}
	// Recording an event for a challenge that doesn't exist yet should create a new sample
	td.RecordEvent("chg-001", ev, &ChallengeMetrics{})

	if td.Size() != 1 {
		t.Errorf("expected size 1 after RecordEvent for new challenge, got %d", td.Size())
	}

	// Recording another event for the same challenge should NOT create a duplicate sample
	ev2 := &CaptchaEvent{Type: "keydown", Timestamp: 1500, Key: "a"}
	td.RecordEvent("chg-001", ev2, &ChallengeMetrics{})

	if td.Size() != 1 {
		t.Errorf("expected size to remain 1 after second event for same challenge, got %d", td.Size())
	}
}

// ---------------------------------------------------------------------------
// TrainingSample type-safety tests
// ---------------------------------------------------------------------------

func TestTrainingSample_ChallengeTypeField(t *testing.T) {
	// Verify that ChallengeType is the correct type (not a raw string)
	s := TrainingSample{
		ChallengeType: ChallengeCloudflare,
	}
	if s.ChallengeType != ChallengeCloudflare {
		t.Errorf("ChallengeType field: want %q, got %q", ChallengeCloudflare, s.ChallengeType)
	}
}

func TestTrainingSample_JSONRoundTrip(t *testing.T) {
	original := TrainingSample{
		ID:            "test-001",
		ChallengeType: ChallengeRecaptchaV2,
		IsBot:         true,
		BotScore:      0.85,
		Solved:        false,
		Label:         "bot",
		Features:      []float64{1.0, 2.0, 3.0},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var restored TrainingSample
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if restored.ID != original.ID {
		t.Errorf("ID: want %q, got %q", original.ID, restored.ID)
	}
	if restored.ChallengeType != original.ChallengeType {
		t.Errorf("ChallengeType: want %q, got %q", original.ChallengeType, restored.ChallengeType)
	}
	if restored.BotScore != original.BotScore {
		t.Errorf("BotScore: want %f, got %f", original.BotScore, restored.BotScore)
	}
	if restored.Label != original.Label {
		t.Errorf("Label: want %q, got %q", original.Label, restored.Label)
	}
}

// ---------------------------------------------------------------------------
// GetGlobalTracer tests
// ---------------------------------------------------------------------------

func TestGetGlobalTracer_ReturnsSameInstance(t *testing.T) {
	t1 := GetGlobalTracer()
	t2 := GetGlobalTracer()

	if t1 != t2 {
		t.Error("GetGlobalTracer should return the same singleton instance on each call")
	}
	if t1 == nil {
		t.Error("GetGlobalTracer should not return nil")
	}
}

// ---------------------------------------------------------------------------
// extractFeaturesFromMetrics tests
// ---------------------------------------------------------------------------

func TestExtractFeaturesFromMetrics_Nil(t *testing.T) {
	features := extractFeaturesFromMetrics(nil)
	if len(features) != 11 {
		t.Errorf("nil metrics: expected 11 features, got %d", len(features))
	}
	for i, f := range features {
		if f != 0 {
			t.Errorf("nil metrics: feature[%d] should be 0, got %f", i, f)
		}
	}
}

func TestExtractFeaturesFromMetrics_NonNil(t *testing.T) {
	m := &TraceMetrics{
		TotalEvents:    20,
		MouseMovements: 10,
		Keystrokes:     5,
		ScrollEvents:   3,
		Clicks:         2,
		MouseVelocity:  150.5,
		TypingSpeed:    4.2,
		EventIntervals: 120.0,
		Straightness:   0.75,
		Pauses:         3,
		LongPauses:     1,
	}

	features := extractFeaturesFromMetrics(m)
	if len(features) != 11 {
		t.Errorf("expected 11 features, got %d", len(features))
	}
	if features[0] != 20 {
		t.Errorf("features[0] (TotalEvents): want 20, got %f", features[0])
	}
	if features[5] != 150.5 {
		t.Errorf("features[5] (MouseVelocity): want 150.5, got %f", features[5])
	}
	if features[8] != 0.75 {
		t.Errorf("features[8] (Straightness): want 0.75, got %f", features[8])
	}
}
