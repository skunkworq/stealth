package challenge

import (
	"math/rand"
	"testing"
)

func stableRNG(seed int64) func() float64 {
	r := rand.New(rand.NewSource(seed))
	return r.Float64
}

// --- Rotate Challenge Tests ---

func TestRotateSolver_PassesValidator(t *testing.T) {
	cfg := turnstileRotateConfig(270)
	rng := stableRNG(42)

	result := SolveRotateChallenge(RotateSolveParams{
		TargetAngleDeg:    cfg.TargetAngleDeg,
		DialRadiusPx:      cfg.DialRadiusPx,
		RequiredOvershoot: cfg.RequiredOvershootDeg,
	}, rng)

	passed, signals := ValidateRotateProof(cfg, result.Proof)
	t.Logf("Rotate proof: angle=%d° events=%d overshoot=%d° duration=%dms velocity=%.0f°/s",
		result.Proof.FinalAngleDeg, result.Proof.RotationEventCount,
		result.Proof.OvershootDeg, result.Proof.RotationDurationMs,
		result.Proof.AngularVelocityAvg)
	for _, s := range signals {
		t.Logf("  signal: %s (%.2f) %s", s.Name, s.Weight, s.Detail)
	}

	if !passed {
		t.Error("solver-generated rotate proof should pass validation")
	}
}

func TestRotateSolver_MultipleSeeds(t *testing.T) {
	cfg := turnstileRotateConfig(270)

	for seed := int64(0); seed < 20; seed++ {
		rng := stableRNG(seed)
		result := SolveRotateChallenge(RotateSolveParams{
			TargetAngleDeg:    cfg.TargetAngleDeg,
			DialRadiusPx:      cfg.DialRadiusPx,
			RequiredOvershoot: cfg.RequiredOvershootDeg,
		}, rng)

		passed, signals := ValidateRotateProof(cfg, result.Proof)
		if !passed {
			t.Errorf("seed=%d: solver failed validation", seed)
			for _, s := range signals {
				t.Logf("  signal: %s (%.2f) %s", s.Name, s.Weight, s.Detail)
			}
		}
	}
}

func TestRotateValidator_RejectsBotFastRotation(t *testing.T) {
	cfg := turnstileRotateConfig(270)

	// Bot-like: correct angle but superhuman speed and insufficient events
	proof := TurnstileInteractionProof{
		Type:               turnstileInteractionRotate,
		Completed:          true,
		FinalAngleDeg:      270,
		RotationEventCount: 3, // way too few
		OvershootDeg:       0, // no overshoot
		RotationDurationMs: 50,
		AngularVelocityAvg: 5400, // 5400°/s = superhuman
	}

	passed, signals := ValidateRotateProof(cfg, proof)
	if passed {
		t.Error("bot-fast rotation should be rejected")
	}
	t.Logf("Rejected with %d signals", len(signals))
	for _, s := range signals {
		t.Logf("  %s (%.2f) %s", s.Name, s.Weight, s.Detail)
	}
}

func TestRotateValidator_RejectsWrongAngle(t *testing.T) {
	cfg := turnstileRotateConfig(270)

	proof := TurnstileInteractionProof{
		Type:               turnstileInteractionRotate,
		Completed:          true,
		FinalAngleDeg:      90, // 180° off
		RotationEventCount: 15,
		OvershootDeg:       10,
		RotationDurationMs: 1200,
		AngularVelocityAvg: 225,
	}

	passed, _ := ValidateRotateProof(cfg, proof)
	if passed {
		t.Error("wrong angle should be rejected")
	}
}

func TestRotateValidator_RejectsWrongType(t *testing.T) {
	cfg := turnstileRotateConfig(270)

	proof := TurnstileInteractionProof{
		Type: turnstileInteractionCheckbox,
	}

	passed, signals := ValidateRotateProof(cfg, proof)
	if passed {
		t.Error("wrong type should be rejected")
	}
	if len(signals) == 0 || signals[0].Name != "wrong_interaction_type" {
		t.Error("expected wrong_interaction_type signal")
	}
}

// --- Slide Puzzle Tests ---

func TestSlideSolver_PassesValidator(t *testing.T) {
	cfg := turnstileSlidePuzzleConfig(180)
	rng := stableRNG(42)

	result := SolveSlidePuzzle(SlidePuzzleSolveParams{
		TargetXPx:    cfg.TargetSlideXPx,
		TrackWidthPx: cfg.SlideTrackWidthPx,
	}, rng)

	passed, signals := ValidateSlidePuzzleProof(cfg, result.Proof)
	t.Logf("Slide proof: x=%dpx events=%d yVar=%.1f duration=%dms overshoot=%dpx",
		result.Proof.FinalSlideXPx, result.Proof.SlideEventCount,
		result.Proof.SlideYVariancePx, result.Proof.SlideDurationMs,
		result.Proof.SlideOvershootPx)
	for _, s := range signals {
		t.Logf("  signal: %s (%.2f) %s", s.Name, s.Weight, s.Detail)
	}

	if !passed {
		t.Error("solver-generated slide proof should pass validation")
	}
}

func TestSlideSolver_MultipleSeeds(t *testing.T) {
	cfg := turnstileSlidePuzzleConfig(180)

	for seed := int64(0); seed < 20; seed++ {
		rng := stableRNG(seed)
		result := SolveSlidePuzzle(SlidePuzzleSolveParams{
			TargetXPx:    cfg.TargetSlideXPx,
			TrackWidthPx: cfg.SlideTrackWidthPx,
		}, rng)

		passed, signals := ValidateSlidePuzzleProof(cfg, result.Proof)
		if !passed {
			t.Errorf("seed=%d: solver failed validation", seed)
			for _, s := range signals {
				t.Logf("  signal: %s (%.2f) %s", s.Name, s.Weight, s.Detail)
			}
		}
	}
}

func TestSlideValidator_RejectsBotStraightLine(t *testing.T) {
	cfg := turnstileSlidePuzzleConfig(180)

	// Bot-like: perfect X but zero Y wobble, too fast, too few events
	proof := TurnstileInteractionProof{
		Type:             turnstileInteractionSlidePuzzle,
		Completed:        true,
		FinalSlideXPx:    180,
		SlideEventCount:  4,   // too few
		SlideYVariancePx: 0.0, // perfectly straight
		SlideDurationMs:  100, // too fast
	}

	passed, signals := ValidateSlidePuzzleProof(cfg, proof)
	if passed {
		t.Error("bot straight-line slide should be rejected")
	}
	t.Logf("Rejected with %d signals", len(signals))
	for _, s := range signals {
		t.Logf("  %s (%.2f) %s", s.Name, s.Weight, s.Detail)
	}
}

func TestSlideValidator_RejectsWrongPosition(t *testing.T) {
	cfg := turnstileSlidePuzzleConfig(180)

	proof := TurnstileInteractionProof{
		Type:             turnstileInteractionSlidePuzzle,
		Completed:        true,
		FinalSlideXPx:    50, // way off
		SlideEventCount:  15,
		SlideYVariancePx: 5.0,
		SlideDurationMs:  800,
	}

	passed, _ := ValidateSlidePuzzleProof(cfg, proof)
	if passed {
		t.Error("wrong position should be rejected")
	}
}

func TestSlideValidator_RejectsWrongType(t *testing.T) {
	cfg := turnstileSlidePuzzleConfig(180)

	proof := TurnstileInteractionProof{
		Type: turnstileInteractionRotate,
	}

	passed, signals := ValidateSlidePuzzleProof(cfg, proof)
	if passed {
		t.Error("wrong type should be rejected")
	}
	if len(signals) == 0 || signals[0].Name != "wrong_interaction_type" {
		t.Error("expected wrong_interaction_type signal")
	}
}

// --- Risk Escalation ---

func TestRiskEscalation_RotateAtExtreme(t *testing.T) {
	cfg := turnstileWidgetConfigForRisk("test-session", 0.96)
	if cfg.Interaction.Type != turnstileInteractionRotate {
		t.Errorf("extreme risk (0.96) should produce rotate challenge, got %s", cfg.Interaction.Type)
	}
	if cfg.RiskLevel != "extreme" {
		t.Errorf("expected risk_level=extreme, got %s", cfg.RiskLevel)
	}
}

func TestRiskEscalation_PrecisionAtCritical(t *testing.T) {
	cfg := turnstileWidgetConfigForRisk("test-session", 0.91)
	if cfg.Interaction.Type != turnstileInteractionPrecision {
		t.Errorf("critical risk (0.91) should produce precision challenge, got %s", cfg.Interaction.Type)
	}
}

func TestRiskEscalation_CheckboxAtLow(t *testing.T) {
	cfg := turnstileWidgetConfigForRisk("test-session", 0.2)
	if cfg.Interaction.Type != turnstileInteractionCheckbox {
		t.Errorf("low risk (0.2) should produce checkbox challenge, got %s", cfg.Interaction.Type)
	}
}

// --- Helper Tests ---

func TestAngleDifference(t *testing.T) {
	cases := []struct{ a, b, want int }{
		{0, 0, 0},
		{90, 90, 0},
		{10, 350, 20},
		{350, 10, 20},
		{180, 0, 180},
		{270, 90, 180},
		{1, 359, 2},
	}
	for _, c := range cases {
		got := angleDifference(c.a, c.b)
		if got != c.want {
			t.Errorf("angleDifference(%d, %d) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCalculateVariance(t *testing.T) {
	// Known values: [2, 4, 4, 4, 5, 5, 7, 9] → stddev ≈ 2.0
	vals := []float64{2, 4, 4, 4, 5, 5, 7, 9}
	v := calculateVariance(vals)
	if v < 1.9 || v > 2.2 {
		t.Errorf("calculateVariance = %.3f, expected ~2.0", v)
	}

	// Empty/single should return 0
	if calculateVariance(nil) != 0 {
		t.Error("nil should return 0")
	}
	if calculateVariance([]float64{5}) != 0 {
		t.Error("single value should return 0")
	}
}
