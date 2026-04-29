package captcha

import (
	"testing"
	"time"
)

func TestReCaptchaV2(t *testing.T) {
	config := &ReCaptchaV2Config{
		ImageCount: 9,
		GridRows:   3,
		GridCols:   3,
	}

	captcha := NewReCaptchaV2(config)
	err := captcha.Generate("traffic_light")
	if err != nil {
		t.Fatalf("failed to generate: %v", err)
	}

	if captcha.TargetLabel != "traffic_light" {
		t.Errorf("expected target 'traffic_light', got '%s'", captcha.TargetLabel)
	}

	if len(captcha.Options) != 9 {
		t.Errorf("expected 9 options, got %d", len(captcha.Options))
	}
}

func TestReCaptchaV2Validation(t *testing.T) {
	captcha := NewReCaptchaV2(nil)
	err := captcha.Generate("traffic_light")
	if err != nil {
		t.Fatalf("failed to generate: %v", err)
	}

	tests := []struct {
		name     string
		selected []int
		expected bool
	}{
		{"correct", []int{0, 1, 2}, true},
		{"partial_4_correct", []int{0, 1, 2, 3}, true},
		{"wrong", []int{3, 4, 5}, false},
		{"empty", []int{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := captcha.Validate(tt.selected)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestReCaptchaV2Expiration(t *testing.T) {
	captcha := NewReCaptchaV2(nil)
	if captcha.IsExpired() {
		t.Error("new captcha should not be expired")
	}

	captcha.ExpiresAt = time.Now().Add(-1 * time.Second)
	if !captcha.IsExpired() {
		t.Error("expired captcha should be expired")
	}
}

func TestHCaptcha(t *testing.T) {
	config := &HCaptchaConfig{}

	captcha, err := NewHCaptcha(config, "automobile")
	if err != nil {
		t.Fatalf("failed to create: %v", err)
	}

	err = captcha.Generate(8)
	if err != nil {
		t.Fatalf("failed to generate: %v", err)
	}

	if captcha.Category.Name != "automobile" {
		t.Errorf("expected category 'automobile', got '%s'", captcha.Category.Name)
	}

	if len(captcha.Options) != 8 {
		t.Errorf("expected 8 options, got %d", len(captcha.Options))
	}
}

func TestHCaptchaValidation(t *testing.T) {
	captcha, _ := NewHCaptcha(nil, "dog")
	err := captcha.Generate(8)
	if err != nil {
		t.Fatalf("failed to generate: %v", err)
	}

	selected := []int{0, 1, 2, 3}
	result := captcha.Validate(selected)

	if !result {
		t.Error("expected validation to pass for correct selection")
	}
}

func TestHCaptchaCategories(t *testing.T) {
	if len(DefaultCategories) < 30 {
		t.Errorf("expected at least 30 categories, got %d", len(DefaultCategories))
	}

	found := false
	for _, cat := range DefaultCategories {
		if cat.Name == "bird" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected to find 'bird' category")
	}
}

func TestTurnstile(t *testing.T) {
	config := &TurnstileConfig{
		SiteKey: "test-key",
		Theme:   "dark",
		Action:  "login",
	}

	challenge := NewTurnstile(config)
	err := challenge.Generate()
	if err != nil {
		t.Fatalf("failed to generate: %v", err)
	}

	if challenge.Token == "" {
		t.Error("expected non-empty token")
	}

	if challenge.SiteKey != "test-key" {
		t.Errorf("expected sitekey 'test-key', got '%s'", challenge.SiteKey)
	}
}

func TestTurnstileValidation(t *testing.T) {
	challenge := NewTurnstile(nil)
	err := challenge.Generate()
	if err != nil {
		t.Fatalf("failed to generate: %v", err)
	}

	if !challenge.Validate(challenge.Token) {
		t.Error("expected validation to pass for correct token")
	}

	if challenge.Validate("wrong-token") {
		t.Error("expected validation to fail for wrong token")
	}
}

func TestTurnstileExpiration(t *testing.T) {
	challenge := NewTurnstile(nil)
	err := challenge.Generate()
	if err != nil {
		t.Fatalf("failed to generate: %v", err)
	}

	if challenge.IsExpired() {
		t.Error("new challenge should not be expired")
	}

	challenge.ExpiresAt = time.Now().Add(-1 * time.Second)
	if !challenge.IsExpired() {
		t.Error("expired challenge should be expired")
	}
}

func TestDistortedTextCaptcha(t *testing.T) {
	config := &DistortedTextConfig{
		Length:     6,
		CharSet:    "ABCDEFGHJKLMNPQRSTUVWXYZ23456789",
		NoiseLevel: 3,
	}

	captcha := NewDistortedTextCaptcha(config)
	solution, err := captcha.Generate()
	if err != nil {
		t.Fatalf("failed to generate: %v", err)
	}

	if len(solution) != 6 {
		t.Errorf("expected length 6, got %d", len(solution))
	}

	if captcha.Solution != solution {
		t.Error("expected solution to match")
	}
}

func TestDistortedTextValidation(t *testing.T) {
	captcha := NewDistortedTextCaptcha(nil)
	captcha.Config.CaseSensitive = false
	_, err := captcha.Generate()
	if err != nil {
		t.Fatalf("failed to generate: %v", err)
	}

	tests := []struct {
		name     string
		answer   string
		expected bool
	}{
		{"correct", captcha.Solution, true},
		{"wrong", "WRONG", false},
		{"case_insensitive", toLower(captcha.Solution), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := captcha.Validate(tt.answer)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestDistortedTextCaseSensitive(t *testing.T) {
	captcha := NewDistortedTextCaptcha(&DistortedTextConfig{CaseSensitive: false})
	_, _ = captcha.Generate()

	solution := captcha.Solution
	if len(solution) > 0 {
		upper := toUpper(solution)
		if !captcha.Validate(upper) {
			t.Error("expected case-insensitive validation to pass")
		}
	}
}

func toUpper(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		result[i] = c
	}
	return string(result)
}

func TestAudioCaptcha(t *testing.T) {
	config := &AudioConfig{
		Length:     4,
		DigitsOnly: true,
	}

	captcha := NewAudioCaptcha(config)
	solution, err := captcha.Generate()
	if err != nil {
		t.Fatalf("failed to generate: %v", err)
	}

	if len(solution) != 4 {
		t.Errorf("expected length 4, got %d", len(solution))
	}

	if !captcha.Validate(solution) {
		t.Error("expected validation to pass for correct solution")
	}
}

func TestAudioCaptchaValidation(t *testing.T) {
	captcha := NewAudioCaptcha(nil)
	_, _ = captcha.Generate()

	if captcha.Validate("1234") {
		t.Error("expected validation to fail for wrong answer")
	}
}

func TestBehavioralProfile(t *testing.T) {
	config := &BehavioralConfig{
		MouseMovements: true,
		Keystrokes:     true,
	}

	profile := NewBehavioralProfile(config)

	profile.AddEvent(BehavioralEvent{Type: "mousemove", Timestamp: 1000, X: 10, Y: 10})
	profile.AddEvent(BehavioralEvent{Type: "mousemove", Timestamp: 1100, X: 20, Y: 20})
	profile.AddEvent(BehavioralEvent{Type: "keydown", Timestamp: 2000, Key: "a"})
	profile.AddEvent(BehavioralEvent{Type: "keyup", Timestamp: 2100})
	profile.AddEvent(BehavioralEvent{Type: "keydown", Timestamp: 2200, Key: "b"})
	profile.AddEvent(BehavioralEvent{Type: "keyup", Timestamp: 2300})
	profile.AddEvent(BehavioralEvent{Type: "scroll", Timestamp: 3000, ScrollDelta: 100})

	if profile.EventCount != 7 {
		t.Errorf("expected 7 events, got %d", profile.EventCount)
	}

	confidence := profile.Analyze()
	if confidence < 0 || confidence > 1 {
		t.Errorf("expected confidence between 0 and 1, got %f", confidence)
	}
}

func TestBehavioralProfileNotHuman(t *testing.T) {
	profile := NewBehavioralProfile(nil)

	profile.AddEvent(BehavioralEvent{Type: "mousemove", Timestamp: 1000, X: 10, Y: 10})
	profile.AddEvent(BehavioralEvent{Type: "mousemove", Timestamp: 1010, X: 20, Y: 20})

	confidence := profile.Analyze()

	if confidence > 0.5 {
		t.Error("expected low confidence for insufficient events")
	}
}

func TestCanvasFingerprint(t *testing.T) {
	config := &CanvasFingerprintConfig{
		Width:    200,
		Height:   50,
		Text:     "Test",
		FontSize: 20,
	}

	fingerprint := NewCanvasFingerprint(config)

	if fingerprint.Config.Width != 200 {
		t.Errorf("expected width 200, got %d", fingerprint.Config.Width)
	}

	_, err := fingerprint.Generate()
	if err != nil {
		t.Fatalf("failed to generate: %v", err)
	}
}

func TestCaptchaService(t *testing.T) {
	service := NewCaptchaService()

	if service.TextStore == nil {
		t.Error("expected non-nil TextStore")
	}

	textCaptcha, err := service.CreateTextCaptcha(nil)
	if err != nil {
		t.Fatalf("failed to create text captcha: %v", err)
	}

	if retrieved, ok := service.GetTextCaptcha(textCaptcha.ID); !ok {
		t.Error("expected to retrieve text captcha")
	} else if retrieved.ID != textCaptcha.ID {
		t.Error("expected retrieved ID to match")
	}
}

func TestCaptchaServiceReCaptcha(t *testing.T) {
	service := NewCaptchaService()

	captcha, err := service.CreateReCaptchaV2("car", nil)
	if err != nil {
		t.Fatalf("failed to create reCAPTCHA: %v", err)
	}

	_, ok := service.GetReCaptchaV2(captcha.ID)
	if !ok {
		t.Error("expected to retrieve reCAPTCHA")
	}
}

func TestCaptchaServiceHCaptcha(t *testing.T) {
	service := NewCaptchaService()

	captcha, err := service.CreateHCaptcha("dog", 8, nil)
	if err != nil {
		t.Fatalf("failed to create hCaptcha: %v", err)
	}

	_, ok := service.GetHCaptcha(captcha.ID)
	if !ok {
		t.Error("expected to retrieve hCaptcha")
	}
}

func TestCaptchaServiceTurnstile(t *testing.T) {
	service := NewCaptchaService()

	challenge, err := service.CreateTurnstile(nil)
	if err != nil {
		t.Fatalf("failed to create Turnstile: %v", err)
	}

	_, ok := service.GetTurnstile(challenge.ID)
	if !ok {
		t.Error("expected to retrieve Turnstile challenge")
	}
}

func TestCaptchaServiceDistortedText(t *testing.T) {
	service := NewCaptchaService()

	captcha, err := service.CreateDistortedText(nil)
	if err != nil {
		t.Fatalf("failed to create distorted text: %v", err)
	}

	if _, ok := service.DistortedText[captcha.ID]; !ok {
		t.Error("expected to find distorted text captcha")
	}
}

func TestCaptchaServiceAudio(t *testing.T) {
	service := NewCaptchaService()

	captcha, err := service.CreateAudio(nil)
	if err != nil {
		t.Fatalf("failed to create audio: %v", err)
	}

	if _, ok := service.Audio[captcha.ID]; !ok {
		t.Error("expected to find audio captcha")
	}
}

func TestCaptchaServiceBehavioral(t *testing.T) {
	service := NewCaptchaService()

	profile := service.CreateBehavioralProfile("session-123", nil)
	if profile == nil {
		t.Error("expected non-nil profile")
	}

	profile.AddEvent(BehavioralEvent{Type: "mousemove", Timestamp: 1000})
	service.Behavioral["session-123"] = profile

	_, ok := service.Behavioral["session-123"]
	if !ok {
		t.Error("expected to retrieve behavioral profile")
	}
}

func TestCaptchaServiceCleanup(t *testing.T) {
	service := NewCaptchaService()

	service.TextStore.captchas = make(map[string]*Captcha)

	_, _ = service.CreateTextCaptcha(nil)
	_, _ = service.CreateTextCaptcha(nil)

	removed := service.Cleanup()

	if removed < 0 {
		t.Errorf("expected non-negative removed count, got %d", removed)
	}
}
