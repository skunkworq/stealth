package captcha_test

import (
	"testing"

	"github.com/skunkworq/stealth/brws/stealth/captcha"
)

func TestDefaultReCaptchaV2Config(t *testing.T) {
	cfg := captcha.DefaultReCaptchaV2Config
	if cfg.Theme == "" {
		t.Error("Theme should not be empty")
	}
	if cfg.ImageCount <= 0 {
		t.Error("ImageCount should be positive")
	}
	if cfg.GridRows <= 0 {
		t.Error("GridRows should be positive")
	}
	if cfg.GridCols <= 0 {
		t.Error("GridCols should be positive")
	}
}

func TestNewReCaptchaV2_defaultConfig(t *testing.T) {
	rc := captcha.NewReCaptchaV2(nil)
	if rc == nil {
		t.Fatal("NewReCaptchaV2(nil) returned nil")
	}
	// ExpiresAt should be in the future
	if rc.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should be set")
	}
}

func TestNewReCaptchaV2_customConfig(t *testing.T) {
	cfg := &captcha.ReCaptchaV2Config{
		Theme:         "dark",
		Size:          "compact",
		TabIndex:      1,
		SiteKey:       "test-site-key",
		ChallengeType: "image",
		ImageCount:    9,
		GridRows:      3,
		GridCols:      3,
		Instructions:  "Select traffic lights",
	}
	rc := captcha.NewReCaptchaV2(cfg)
	if rc == nil {
		t.Fatal("NewReCaptchaV2 returned nil")
	}
}

func TestReCaptchaV2_IsExpired_fresh(t *testing.T) {
	rc := captcha.NewReCaptchaV2(nil)
	// Fresh challenge should not be expired
	if rc.IsExpired() {
		t.Error("fresh ReCaptchaV2 should not be expired immediately")
	}
}

func TestReCaptchaV2_Validate_noOptions(t *testing.T) {
	rc := captcha.NewReCaptchaV2(nil)
	if err := rc.Generate("traffic lights"); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	// Empty selection should not be valid if there are targets
	result := rc.Validate(nil)
	_ = result // just check it doesn't panic
}

func TestReCaptchaV2_Generate(t *testing.T) {
	rc := captcha.NewReCaptchaV2(nil)
	if err := rc.Generate("traffic lights"); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	if len(rc.Options) == 0 {
		t.Error("Generate should populate Options")
	}
}

func TestDefaultHCaptchaConfig(t *testing.T) {
	cfg := captcha.DefaultHCaptchaConfig
	if cfg.Theme == "" {
		t.Error("Theme should not be empty")
	}
}

func TestNewHCaptcha_defaultCategory(t *testing.T) {
	hc, err := captcha.NewHCaptcha(nil, "vehicles")
	if err != nil {
		t.Fatalf("NewHCaptcha error: %v", err)
	}
	if hc == nil {
		t.Fatal("NewHCaptcha returned nil")
	}
}

func TestNewHCaptcha_invalidCategory_fallsBack(t *testing.T) {
	// NewHCaptcha falls back to the first default category when name not found
	hc, err := captcha.NewHCaptcha(nil, "nonexistent-category-xyz")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hc == nil {
		t.Fatal("NewHCaptcha returned nil for unknown category")
	}
	// Category is set to the first default
	if hc.Category.Name == "" {
		t.Error("Category.Name should not be empty")
	}
}

func TestHCaptcha_IsExpired_fresh(t *testing.T) {
	hc, err := captcha.NewHCaptcha(nil, "vehicles")
	if err != nil {
		t.Fatalf("NewHCaptcha error: %v", err)
	}
	if hc.IsExpired() {
		t.Error("fresh HCaptcha should not be expired")
	}
}

func TestHCaptcha_Generate(t *testing.T) {
	hc, err := captcha.NewHCaptcha(nil, "vehicles")
	if err != nil {
		t.Fatalf("NewHCaptcha error: %v", err)
	}
	if err := hc.Generate(9); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	if len(hc.Options) == 0 {
		t.Error("Generate should populate Options")
	}
}

func TestHCaptcha_Validate_noSelection(t *testing.T) {
	hc, err := captcha.NewHCaptcha(nil, "vehicles")
	if err != nil {
		t.Fatalf("NewHCaptcha error: %v", err)
	}
	if err := hc.Generate(9); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	result := hc.Validate(nil)
	_ = result // should not panic
}

func TestDefaultTurnstileConfig(t *testing.T) {
	cfg := captcha.DefaultTurnstileConfig
	if cfg.Theme == "" {
		t.Error("Theme should not be empty")
	}
}

func TestNewTurnstile(t *testing.T) {
	tc := captcha.NewTurnstile(nil)
	if tc == nil {
		t.Fatal("NewTurnstile returned nil")
	}
}

func TestTurnstile_Generate(t *testing.T) {
	tc := captcha.NewTurnstile(nil)
	if err := tc.Generate(); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	if tc.Token == "" {
		t.Error("token should be set after Generate()")
	}
}

func TestTurnstile_IsExpired_fresh(t *testing.T) {
	tc := captcha.NewTurnstile(nil)
	_ = tc.Generate()
	if tc.IsExpired() {
		t.Error("fresh Turnstile should not be expired immediately")
	}
}

func TestTurnstile_Validate(t *testing.T) {
	tc := captcha.NewTurnstile(nil)
	_ = tc.Generate()
	// Validate with the correct token should succeed
	if !tc.Validate(tc.Token) {
		t.Error("Validate with correct token should return true")
	}
}

func TestTurnstile_Validate_wrongToken(t *testing.T) {
	tc := captcha.NewTurnstile(nil)
	_ = tc.Generate()
	if tc.Validate("wrong-token-xyz") {
		t.Error("Validate with wrong token should return false")
	}
}

func TestDefaultCategories_notEmpty(t *testing.T) {
	if len(captcha.DefaultCategories) == 0 {
		t.Error("DefaultCategories should not be empty")
	}
	for _, cat := range captcha.DefaultCategories {
		if cat.Name == "" {
			t.Error("category Name should not be empty")
		}
	}
}
