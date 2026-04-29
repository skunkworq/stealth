package challenge

import (
	"math/rand"
	"testing"
)

func labRNG(seed int64) func() float64 {
	r := rand.New(rand.NewSource(seed))
	return r.Float64
}

// --- reCAPTCHA v2 Tests ---

func TestReCaptchaV2_SolverPassesValidator(t *testing.T) {
	ch := DefaultReCaptchaV2Lab("traffic lights", []int{0, 1, 3, 4})
	rng := labRNG(42)

	proof := SolveReCaptchaV2Grid(ch, 100, 100, rng)
	passed, signals := ValidateReCaptchaV2Proof(ch, proof)

	t.Logf("v2 proof: selected=%v order=%v duration=%dms",
		proof.SelectedCells, proof.SelectionOrder, proof.TotalDurationMs)
	for _, s := range signals {
		t.Logf("  signal: %s (%.2f) %s", s.Name, s.Weight, s.Detail)
	}

	if !passed {
		t.Error("solver should pass v2 validation")
	}
}

func TestReCaptchaV2_SolverMultipleSeeds(t *testing.T) {
	ch := DefaultReCaptchaV2Lab("crosswalks", []int{2, 5, 8})

	for seed := int64(0); seed < 15; seed++ {
		proof := SolveReCaptchaV2Grid(ch, 50, 50, labRNG(seed))
		passed, signals := ValidateReCaptchaV2Proof(ch, proof)
		if !passed {
			t.Errorf("seed=%d: solver failed", seed)
			for _, s := range signals {
				t.Logf("  %s (%.2f) %s", s.Name, s.Weight, s.Detail)
			}
		}
	}
}

func TestReCaptchaV2_RejectsWrongSelection(t *testing.T) {
	ch := DefaultReCaptchaV2Lab("bicycles", []int{1, 4, 7})
	proof := ReCaptchaV2LabProof{
		SelectedCells:    []int{0, 2, 6}, // wrong cells
		SelectionTimesMs: []int64{500, 800, 1100},
		TotalDurationMs:  1200,
	}

	passed, _ := ValidateReCaptchaV2Proof(ch, proof)
	if passed {
		t.Error("wrong selection should be rejected")
	}
}

func TestReCaptchaV2_RejectsBotTiming(t *testing.T) {
	ch := DefaultReCaptchaV2Lab("buses", []int{3, 6})
	proof := ReCaptchaV2LabProof{
		SelectedCells:    []int{3, 6},
		SelectionOrder:   []int{3, 6},
		SelectionTimesMs: []int64{50, 100}, // 50ms between clicks = bot
		TotalDurationMs:  100,
		ClickEvents: []CaptchaEvent{
			{Type: "click", X: 65, Y: 65}, // exactly centered in 130px cell
			{Type: "click", X: 65, Y: 65},
			{Type: "click", X: 65, Y: 65},
		},
	}

	passed, signals := ValidateReCaptchaV2Proof(ch, proof)
	if passed {
		t.Error("bot timing should be rejected")
	}

	hasSignal := false
	for _, s := range signals {
		if s.Name == "selections_too_fast" || s.Name == "solve_too_fast" {
			hasSignal = true
		}
	}
	if !hasSignal {
		t.Error("expected timing signal")
	}
}

// --- reCAPTCHA v3 Tests ---

func TestReCaptchaV3_HumanLikeEventsScore(t *testing.T) {
	session := DefaultReCaptchaV3Lab("login")
	rng := labRNG(42)

	// Generate human-like events
	var events []CaptchaEvent
	baseMs := int64(0)
	for range 30 {
		baseMs += int64(100 + rng()*300)
		events = append(events, CaptchaEvent{
			Type: "mousemove", ElapsedMs: baseMs,
			X: 200 + rng()*600, Y: 100 + rng()*400,
		})
	}
	// Add a pause
	baseMs += 700
	events = append(events, CaptchaEvent{
		Type: "mousemove", ElapsedMs: baseMs, X: 500, Y: 300,
	})
	// Scroll
	baseMs += 200
	events = append(events, CaptchaEvent{Type: "scroll", ElapsedMs: baseMs, Delta: 120})
	// Click
	baseMs += 300
	events = append(events, CaptchaEvent{Type: "click", ElapsedMs: baseMs, X: 400, Y: 350})

	proof := ReCaptchaV3LabProof{
		Events:     events,
		DurationMs: baseMs,
		Action:     "login",
	}

	score, signals := ScoreReCaptchaV3(session, proof)
	t.Logf("v3 score: %.3f (%d signals)", score, len(signals))
	for _, s := range signals {
		t.Logf("  %s (%.2f) %s", s.Name, s.Weight, s.Detail)
	}

	if score < session.MinScore {
		t.Errorf("human-like events scored %.3f, below threshold %.1f", score, session.MinScore)
	}
}

func TestReCaptchaV3_BotEventsScore(t *testing.T) {
	session := DefaultReCaptchaV3Lab("submit")

	// Bot: constant-interval linear movement, no pauses
	var events []CaptchaEvent
	for i := range 20 {
		events = append(events, CaptchaEvent{
			Type: "mousemove", ElapsedMs: int64(i * 50), // exactly 50ms intervals
			X: float64(100 + i*30), Y: 200, // perfectly straight line
		})
	}

	proof := ReCaptchaV3LabProof{
		Events:     events,
		DurationMs: 950,
		Action:     "submit",
	}

	score, signals := ScoreReCaptchaV3(session, proof)
	t.Logf("bot v3 score: %.3f (%d signals)", score, len(signals))

	if score >= session.MinScore {
		t.Errorf("bot events scored %.3f, should be below %.1f", score, session.MinScore)
	}

	// Should flag linear path and uniform timing
	foundLinear := false
	foundUniform := false
	for _, s := range signals {
		if s.Name == "linear_mouse_path" {
			foundLinear = true
		}
		if s.Name == "uniform_event_timing" {
			foundUniform = true
		}
	}
	if !foundLinear {
		t.Error("expected linear_mouse_path signal")
	}
	if !foundUniform {
		t.Error("expected uniform_event_timing signal")
	}
}

// --- Cloudflare Challenge Tests ---

func TestCloudflareJS_SolverPasses(t *testing.T) {
	ch := DefaultCloudflareJSChallenge()
	rng := labRNG(42)

	proof := SolveCloudflareJSChallenge(ch, rng)
	passed, signals := ValidateCloudflareProof(ch, proof)

	t.Logf("JS challenge: compute=%dms callbacks=%v duration=%dms",
		proof.JSComputeActualMs, proof.CallbackOrder, proof.TotalDurationMs)

	if !passed {
		t.Error("JS challenge solver should pass")
		for _, s := range signals {
			t.Logf("  %s (%.2f) %s", s.Name, s.Weight, s.Detail)
		}
	}
}

func TestCloudflareJS_RejectsFastCompute(t *testing.T) {
	ch := DefaultCloudflareJSChallenge()
	proof := CloudflareLabProof{
		Type:              CFChallengeJS,
		JSComputeActualMs: 100,                                               // way too fast for 3000ms challenge
		CallbackOrder:     []string{"challenge_start", "challenge_complete"}, // also wrong callback order
		TotalDurationMs:   200,
	}

	passed, signals := ValidateCloudflareProof(ch, proof)
	if passed {
		t.Error("fast JS compute should be rejected")
	}

	found := false
	for _, s := range signals {
		if s.Name == "js_compute_too_fast" {
			found = true
		}
	}
	if !found {
		t.Error("expected js_compute_too_fast signal")
	}
}

func TestCloudflareManaged_SolverPasses(t *testing.T) {
	ch := DefaultCloudflareManagedChallenge("test-session", 0.3) // low risk = checkbox
	rng := labRNG(42)

	proof := SolveCloudflareManagedChallenge(ch, rng)
	passed, signals := ValidateCloudflareProof(ch, proof)

	t.Logf("Managed challenge: callbacks=%v interaction=%s duration=%dms",
		proof.CallbackOrder, proof.InteractionProof.Type, proof.TotalDurationMs)

	if !passed {
		t.Error("managed challenge solver should pass")
		for _, s := range signals {
			t.Logf("  %s (%.2f) %s", s.Name, s.Weight, s.Detail)
		}
	}
}

func TestCloudflareManaged_RotateAtHighRisk(t *testing.T) {
	ch := DefaultCloudflareManagedChallenge("test-session", 0.96) // extreme = rotate
	rng := labRNG(42)

	proof := SolveCloudflareManagedChallenge(ch, rng)
	passed, signals := ValidateCloudflareProof(ch, proof)

	if proof.InteractionProof.Type != turnstileInteractionRotate {
		t.Errorf("expected rotate interaction, got %s", proof.InteractionProof.Type)
	}

	t.Logf("High-risk managed: passed=%v signals=%d", passed, len(signals))
	if !passed {
		t.Error("high-risk managed solver should pass")
		for _, s := range signals {
			t.Logf("  %s (%.2f) %s", s.Name, s.Weight, s.Detail)
		}
	}
}

func TestCloudflareTurnstile_RejectsCallbackViolation(t *testing.T) {
	ch := DefaultCloudflareTurnstile("test", 0.2)
	proof := CloudflareLabProof{
		Type:          CFChallengeTurnstile,
		CallbackOrder: []string{"success", "before-interactive"}, // wrong order
		WidgetTelemetry: &WidgetTelemetry{
			CallbackState: TurnstileCallbackState{Success: true},
		},
		Token:           "fake-token",
		TotalDurationMs: 1000,
	}

	passed, signals := ValidateCloudflareProof(ch, proof)

	hasViolation := false
	for _, s := range signals {
		if s.Name == "turnstile_callback_violation" || s.Name == "missing_before_interactive" {
			hasViolation = true
		}
	}
	if !hasViolation {
		t.Error("expected callback violation signal")
	}
	_ = passed // may or may not fail depending on total weight
}

func TestCallbackOrderValid(t *testing.T) {
	cases := []struct {
		expected []string
		actual   []string
		want     bool
	}{
		{[]string{"a", "b", "c"}, []string{"a", "b", "c"}, true},
		{[]string{"a", "c"}, []string{"a", "b", "c"}, true},  // extras allowed
		{[]string{"a", "b"}, []string{"b", "a"}, false},      // wrong order
		{[]string{}, []string{"a", "b"}, true},               // no expectations
		{[]string{"a", "b", "c"}, []string{"a", "b"}, false}, // missing c
	}
	for _, c := range cases {
		got := callbackOrderValid(c.expected, c.actual)
		if got != c.want {
			t.Errorf("callbackOrderValid(%v, %v) = %v, want %v", c.expected, c.actual, got, c.want)
		}
	}
}
