package cloudflare

import (
	"testing"
	"time"

	coredetection "github.com/skunkworq/stealth/brws/core/detection"
	captchatraining "github.com/skunkworq/stealth/brws/research/captcha/training"
)

// ---------------------------------------------------------------------------
// Helper: build a minimal DetectionResult for use in tests.
// ---------------------------------------------------------------------------

func newDetectionResult(score float64) *coredetection.DetectionResult {
	return &coredetection.DetectionResult{
		Timestamp:  time.Now(),
		IsBot:      score >= 0.7,
		Confidence: score,
		Score:      score,
		Indicators: []coredetection.Indicator{},
	}
}

// ---------------------------------------------------------------------------
// Constructor tests
// ---------------------------------------------------------------------------

func TestNewCaptchaShield_DefaultConfig(t *testing.T) {
	shield := NewCaptchaShield(nil, nil, nil)
	if shield == nil {
		t.Fatal("NewCaptchaShield(nil, nil, nil) returned nil")
	}
	if shield.config == nil {
		t.Error("shield.config should not be nil")
	}
	if shield.service == nil {
		t.Error("shield.service should not be nil")
	}
	if shield.tracer == nil {
		t.Error("shield.tracer should not be nil")
	}
	if shield.trainingData == nil {
		t.Error("shield.trainingData should not be nil")
	}
	if shield.activeChallenges == nil {
		t.Error("shield.activeChallenges should not be nil")
	}
}

func TestNewCaptchaShield_CustomConfig(t *testing.T) {
	cfg := &CaptchaShieldConfig{
		Threshold:          0.5,
		CaptchaTypes:       []string{"text"},
		AutoGenDifficulty:  false,
		RecordTrainingData: false,
		RetentionDays:      7,
		MaxChallenges:      50,
	}

	shield := NewCaptchaShield(cfg, nil, nil)
	if shield == nil {
		t.Fatal("NewCaptchaShield with config returned nil")
	}
	if shield.config.Threshold != 0.5 {
		t.Errorf("Threshold: want 0.5, got %f", shield.config.Threshold)
	}
	if shield.config.MaxChallenges != 50 {
		t.Errorf("MaxChallenges: want 50, got %d", shield.config.MaxChallenges)
	}
}

func TestNewCaptchaShield_CustomTracer(t *testing.T) {
	tracer := captchatraining.NewCaptchaTracer()
	shield := NewCaptchaShield(nil, nil, tracer)
	if shield == nil {
		t.Fatal("NewCaptchaShield with tracer returned nil")
	}
	if shield.tracer != tracer {
		t.Error("shield.tracer should be the provided tracer")
	}
}

// ---------------------------------------------------------------------------
// DefaultCaptchaShieldConfig tests
// ---------------------------------------------------------------------------

func TestDefaultCaptchaShieldConfig(t *testing.T) {
	cfg := DefaultCaptchaShieldConfig

	if cfg.Threshold <= 0 || cfg.Threshold > 1 {
		t.Errorf("default Threshold should be in (0,1], got %f", cfg.Threshold)
	}
	if len(cfg.CaptchaTypes) == 0 {
		t.Error("default CaptchaTypes should not be empty")
	}
	if cfg.MaxChallenges <= 0 {
		t.Error("default MaxChallenges should be > 0")
	}
}

// ---------------------------------------------------------------------------
// ShouldPresentCaptcha tests
// ---------------------------------------------------------------------------

func TestShouldPresentCaptcha_Nil(t *testing.T) {
	shield := NewCaptchaShield(nil, nil, nil)
	if shield.ShouldPresentCaptcha(nil) {
		t.Error("ShouldPresentCaptcha(nil) should return false")
	}
}

func TestShouldPresentCaptcha_HighScore(t *testing.T) {
	shield := NewCaptchaShield(nil, nil, nil)
	dr := newDetectionResult(0.9) // above default threshold 0.7

	if !shield.ShouldPresentCaptcha(dr) {
		t.Error("ShouldPresentCaptcha should return true for score 0.9 (above 0.7 threshold)")
	}
}

func TestShouldPresentCaptcha_LowScore(t *testing.T) {
	shield := NewCaptchaShield(nil, nil, nil)
	dr := newDetectionResult(0.1) // well below threshold

	if shield.ShouldPresentCaptcha(dr) {
		t.Error("ShouldPresentCaptcha should return false for score 0.1")
	}
}

func TestShouldPresentCaptcha_HighSeverityIndicator(t *testing.T) {
	shield := NewCaptchaShield(nil, nil, nil)
	dr := &coredetection.DetectionResult{
		Score:      0.3, // below threshold
		Confidence: 0.3,
		Indicators: []coredetection.Indicator{
			{Severity: 0.9}, // but one very high-severity indicator
		},
	}
	if !shield.ShouldPresentCaptcha(dr) {
		t.Error("ShouldPresentCaptcha should return true when an indicator has severity >= 0.8")
	}
}

// ---------------------------------------------------------------------------
// CreateChallenge tests
// ---------------------------------------------------------------------------

func TestCreateChallenge_TextType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CreateChallenge test in short mode")
	}

	shield := NewCaptchaShield(nil, nil, nil)

	ch, err := shield.CreateChallenge("sess-001", nil, "text")
	if err != nil {
		t.Fatalf("CreateChallenge(text) failed: %v", err)
	}
	if ch == nil {
		t.Fatal("CreateChallenge returned nil challenge")
	}
	if ch.ID == "" {
		t.Error("challenge ID should not be empty")
	}
	if ch.SessionID != "sess-001" {
		t.Errorf("SessionID: want %q, got %q", "sess-001", ch.SessionID)
	}
	if ch.Type != "text" {
		t.Errorf("Type: want %q, got %q", "text", ch.Type)
	}
	if ch.Metrics == nil {
		t.Error("challenge Metrics should not be nil")
	}
	if ch.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should not be zero")
	}
	if ch.ExpiresAt.Before(time.Now()) {
		t.Error("ExpiresAt should be in the future")
	}
}

func TestCreateChallenge_CloudflareTypes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CreateChallenge test in short mode")
	}

	shield := NewCaptchaShield(nil, nil, nil)

	cloudflareTypes := []string{"cloudflare_js", "cloudflare_managed", "cloudflare_turnstile"}
	for _, ct := range cloudflareTypes {
		t.Run(ct, func(t *testing.T) {
			ch, err := shield.CreateChallenge("sess-cf", nil, ct)
			if err != nil {
				t.Fatalf("CreateChallenge(%s) failed: %v", ct, err)
			}
			if ch == nil {
				t.Fatal("CreateChallenge returned nil")
			}
			if ch.Type != ct {
				t.Errorf("Type: want %q, got %q", ct, ch.Type)
			}
			if ch.Challenge == nil {
				t.Errorf("Challenge data should not be nil for %s", ct)
			}
			if ct, ok := ch.Challenge["challenge_type"]; !ok || ct == "" {
				t.Errorf("challenge_type key missing or empty in Challenge map for %s", ch.Type)
			}
		})
	}
}

func TestCreateChallenge_UnknownTypeDefaultsToText(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CreateChallenge test in short mode")
	}

	shield := NewCaptchaShield(nil, nil, nil)

	ch, err := shield.CreateChallenge("sess-002", nil, "unknown_type_xyz")
	if err != nil {
		t.Fatalf("CreateChallenge(unknown) failed: %v", err)
	}
	if ch == nil {
		t.Fatal("CreateChallenge returned nil for unknown type")
	}
	// Should have fallen through to the default (text) captcha
	if ch.CaptchaID == "" {
		t.Error("CaptchaID should not be empty even for unknown type")
	}
}

func TestCreateChallenge_BehavioralType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CreateChallenge test in short mode")
	}

	shield := NewCaptchaShield(nil, nil, nil)

	ch, err := shield.CreateChallenge("sess-beh", nil, "behavioral")
	if err != nil {
		t.Fatalf("CreateChallenge(behavioral) failed: %v", err)
	}
	if ch == nil {
		t.Fatal("CreateChallenge returned nil")
	}
	if v, ok := ch.Challenge["required_events"]; !ok {
		t.Error("behavioral challenge should have required_events key")
	} else if v.(int) <= 0 {
		t.Error("required_events should be > 0")
	}
}

// ---------------------------------------------------------------------------
// GetChallenge tests
// ---------------------------------------------------------------------------

func TestGetChallenge_NotFound(t *testing.T) {
	shield := NewCaptchaShield(nil, nil, nil)

	_, ok := shield.GetChallenge("nonexistent")
	if ok {
		t.Error("GetChallenge should return false for non-existent challenge")
	}
}

func TestGetChallenge_Found(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping GetChallenge test in short mode")
	}

	shield := NewCaptchaShield(nil, nil, nil)

	ch, err := shield.CreateChallenge("sess-001", nil, "text")
	if err != nil {
		t.Fatalf("CreateChallenge failed: %v", err)
	}

	got, ok := shield.GetChallenge(ch.ID)
	if !ok {
		t.Fatalf("GetChallenge should find the created challenge %q", ch.ID)
	}
	if got.ID != ch.ID {
		t.Errorf("ID mismatch: want %q, got %q", ch.ID, got.ID)
	}
}

// ---------------------------------------------------------------------------
// GetActiveChallenges tests
// ---------------------------------------------------------------------------

func TestGetActiveChallenges_Empty(t *testing.T) {
	shield := NewCaptchaShield(nil, nil, nil)

	challenges := shield.GetActiveChallenges()
	if challenges == nil {
		t.Error("GetActiveChallenges should return non-nil slice")
	}
	if len(challenges) != 0 {
		t.Errorf("expected 0 challenges, got %d", len(challenges))
	}
}

func TestGetActiveChallenges_AfterCreate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping GetActiveChallenges test in short mode")
	}

	shield := NewCaptchaShield(nil, nil, nil)

	_, err := shield.CreateChallenge("sess-001", nil, "text")
	if err != nil {
		t.Fatalf("CreateChallenge failed: %v", err)
	}
	_, err = shield.CreateChallenge("sess-002", nil, "text")
	if err != nil {
		t.Fatalf("second CreateChallenge failed: %v", err)
	}

	challenges := shield.GetActiveChallenges()
	if len(challenges) != 2 {
		t.Errorf("expected 2 active challenges, got %d", len(challenges))
	}
}

// ---------------------------------------------------------------------------
// ValidateChallenge tests
// ---------------------------------------------------------------------------

func TestValidateChallenge_NotFound(t *testing.T) {
	shield := NewCaptchaShield(nil, nil, nil)

	valid, metrics := shield.ValidateChallenge("nonexistent", "solution")
	if valid {
		t.Error("ValidateChallenge should return false for unknown challenge")
	}
	if metrics != nil {
		t.Error("ValidateChallenge should return nil metrics for unknown challenge")
	}
}

func TestValidateChallenge_CorrectSolution(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping ValidateChallenge test in short mode")
	}

	shield := NewCaptchaShield(nil, nil, nil)

	ch, err := shield.CreateChallenge("sess-001", nil, "text")
	if err != nil {
		t.Fatalf("CreateChallenge failed: %v", err)
	}

	// Extract the correct text solution from the challenge data
	expectedText, ok := ch.Challenge["text"].(string)
	if !ok || expectedText == "" {
		t.Skip("challenge does not have a text solution; skipping validation")
	}

	valid, metrics := shield.ValidateChallenge(ch.ID, expectedText)
	if !valid {
		t.Error("ValidateChallenge should return true for the correct solution")
	}
	if metrics == nil {
		t.Error("metrics should not be nil after validation")
	}
	if metrics.AttemptCount != 1 {
		t.Errorf("AttemptCount: want 1, got %d", metrics.AttemptCount)
	}
}

func TestValidateChallenge_WrongSolution(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping ValidateChallenge test in short mode")
	}

	shield := NewCaptchaShield(nil, nil, nil)

	ch, err := shield.CreateChallenge("sess-001", nil, "text")
	if err != nil {
		t.Fatalf("CreateChallenge failed: %v", err)
	}

	valid, metrics := shield.ValidateChallenge(ch.ID, "DEFINITELY_WRONG_ANSWER")
	if valid {
		t.Error("ValidateChallenge should return false for wrong solution")
	}
	if metrics == nil {
		t.Error("metrics should not be nil even for wrong solution")
	}
	if metrics.WrongAttempts != 1 {
		t.Errorf("WrongAttempts: want 1, got %d", metrics.WrongAttempts)
	}
}

// ---------------------------------------------------------------------------
// RecordEvent tests
// ---------------------------------------------------------------------------

func TestRecordEvent_UnknownChallenge(t *testing.T) {
	shield := NewCaptchaShield(nil, nil, nil)

	err := shield.RecordEvent("nonexistent", CaptchaEvent{Type: "click", Timestamp: 1000})
	if err == nil {
		t.Error("RecordEvent should return an error for unknown challenge ID")
	}
}

func TestRecordEvent_KnownChallenge(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping RecordEvent test in short mode")
	}

	shield := NewCaptchaShield(nil, nil, nil)

	ch, err := shield.CreateChallenge("sess-001", nil, "text")
	if err != nil {
		t.Fatalf("CreateChallenge failed: %v", err)
	}

	ev := CaptchaEvent{Type: "click", ElapsedMs: 500}
	if err := shield.RecordEvent(ch.ID, ev); err != nil {
		t.Fatalf("RecordEvent failed: %v", err)
	}

	got, _ := shield.GetChallenge(ch.ID)
	if got.Metrics.EventCount != 1 {
		t.Errorf("EventCount: want 1, got %d", got.Metrics.EventCount)
	}
}

// ---------------------------------------------------------------------------
// GetTrainingData tests
// ---------------------------------------------------------------------------

func TestGetTrainingData_NotNil(t *testing.T) {
	shield := NewCaptchaShield(nil, nil, nil)
	td := shield.GetTrainingData()
	if td == nil {
		t.Error("GetTrainingData() should return non-nil CaptchaTrainingData")
	}
}

// ---------------------------------------------------------------------------
// GetStatistics tests
// ---------------------------------------------------------------------------

func TestGetStatistics_Empty(t *testing.T) {
	shield := NewCaptchaShield(nil, nil, nil)
	stats := shield.GetStatistics()
	if stats == nil {
		t.Fatal("GetStatistics() returned nil")
	}
	if stats.TotalChallenges != 0 {
		t.Errorf("empty shield: TotalChallenges should be 0, got %d", stats.TotalChallenges)
	}
	if stats.ByType == nil {
		t.Error("ByType map should not be nil")
	}
}

// ---------------------------------------------------------------------------
// CaptchaShieldMiddleware tests
// ---------------------------------------------------------------------------

func TestNewCaptchaShieldMiddleware(t *testing.T) {
	shield := NewCaptchaShield(nil, nil, nil)
	mw := NewCaptchaShieldMiddleware(shield, nil)
	if mw == nil {
		t.Fatal("NewCaptchaShieldMiddleware returned nil")
	}
	if mw.config == nil {
		t.Error("middleware config should not be nil")
	}
}

func TestMiddleware_HandleDetection_LowScore(t *testing.T) {
	shield := NewCaptchaShield(nil, nil, nil)
	mw := NewCaptchaShieldMiddleware(shield, nil)

	dr := newDetectionResult(0.1)
	ch, needsCaptcha := mw.HandleDetection("sess-001", dr)
	if needsCaptcha {
		t.Error("HandleDetection should not need captcha for low-score detection")
	}
	if ch != nil {
		t.Error("HandleDetection should return nil challenge for low-score detection")
	}
}

func TestMiddleware_HandleDetection_HighScore(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping HandleDetection high-score test in short mode")
	}

	shield := NewCaptchaShield(nil, nil, nil)
	mw := NewCaptchaShieldMiddleware(shield, nil)

	dr := newDetectionResult(0.95)
	ch, needsCaptcha := mw.HandleDetection("sess-001", dr)
	if !needsCaptcha {
		t.Error("HandleDetection should need captcha for score 0.95")
	}
	if ch == nil {
		t.Error("HandleDetection should return a challenge for high-score detection")
	}
}

// ---------------------------------------------------------------------------
// Type alias tests — verify the aliases are the same as challenge package types
// ---------------------------------------------------------------------------

func TestTypeAliases(t *testing.T) {
	// CaptchaEvent alias
	var ev CaptchaEvent
	ev.Type = "click"
	ev.Timestamp = 1000
	ev.ElapsedMs = 500
	ev.X = 10.5
	ev.Y = 20.3
	if ev.Type != "click" {
		t.Errorf("CaptchaEvent.Type: want %q, got %q", "click", ev.Type)
	}

	// ChallengeMetrics alias
	var m ChallengeMetrics
	m.EventCount = 5
	m.AttemptCount = 1
	if m.EventCount != 5 {
		t.Errorf("ChallengeMetrics.EventCount: want 5, got %d", m.EventCount)
	}

	// TraceMetrics alias
	var tm TraceMetrics
	tm.TotalEvents = 10
	if tm.TotalEvents != 10 {
		t.Errorf("TraceMetrics.TotalEvents: want 10, got %d", tm.TotalEvents)
	}

	// CaptchaChallenge alias
	var c CaptchaChallenge
	c.ID = "test-123"
	c.Type = "text"
	if c.ID != "test-123" {
		t.Errorf("CaptchaChallenge.ID: want %q, got %q", "test-123", c.ID)
	}
}
