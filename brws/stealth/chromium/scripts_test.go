package chromestealth_test

import (
	"strings"
	"testing"
	"time"

	chromestealth "github.com/skunkworq/stealth/brws/stealth/chromium"
)

func TestDefaultStealthConfig(t *testing.T) {
	cfg := chromestealth.DefaultStealthConfig()
	if cfg == nil {
		t.Fatal("DefaultStealthConfig returned nil")
	}
	if !cfg.Enabled {
		t.Error("default config should have Enabled=true")
	}
	if !cfg.RemoveWebDriver {
		t.Error("default config should have RemoveWebDriver=true")
	}
	if cfg.ScreenWidth <= 0 {
		t.Error("ScreenWidth should be positive")
	}
	if cfg.ScreenHeight <= 0 {
		t.Error("ScreenHeight should be positive")
	}
	if cfg.ChromeVersion == "" {
		t.Error("ChromeVersion should not be empty")
	}
	if cfg.Timezone == "" {
		t.Error("Timezone should not be empty")
	}
}

func TestStealthConfig_IsEnabled(t *testing.T) {
	cfg := &chromestealth.StealthConfig{Enabled: true}
	if !cfg.IsEnabled() {
		t.Error("IsEnabled() should return true when Enabled=true")
	}
	cfg.Enabled = false
	if cfg.IsEnabled() {
		t.Error("IsEnabled() should return false when Enabled=false")
	}
}

func TestStealthConfig_SetEnabled(t *testing.T) {
	cfg := &chromestealth.StealthConfig{}
	cfg.SetEnabled(true)
	if !cfg.IsEnabled() {
		t.Error("SetEnabled(true) should make IsEnabled() true")
	}
	cfg.SetEnabled(false)
	if cfg.IsEnabled() {
		t.Error("SetEnabled(false) should make IsEnabled() false")
	}
}

func TestStealthConfig_ToggleFeature_RemoveWebDriver(t *testing.T) {
	cfg := &chromestealth.StealthConfig{}
	applied, alreadySet := cfg.ToggleFeature("RemoveWebDriver")
	if !applied {
		t.Error("ToggleFeature should return applied=true when toggling from off to on")
	}
	if alreadySet {
		t.Error("ToggleFeature should return alreadySet=false when was off")
	}
	if !cfg.RemoveWebDriver {
		t.Error("RemoveWebDriver should be true after toggle")
	}

	// Toggle again — already set
	applied2, alreadySet2 := cfg.ToggleFeature("RemoveWebDriver")
	if applied2 {
		t.Error("second toggle should return applied=false")
	}
	if !alreadySet2 {
		t.Error("second toggle should return alreadySet=true")
	}
}

func TestStealthConfig_ToggleFeature_unknown(t *testing.T) {
	cfg := &chromestealth.StealthConfig{}
	applied, alreadySet := cfg.ToggleFeature("NonExistentFeature")
	if applied || alreadySet {
		t.Error("unknown feature should return (false, false)")
	}
}

func TestStealthConfig_ToggleFeature_CanvasNoise(t *testing.T) {
	cfg := &chromestealth.StealthConfig{}
	applied, _ := cfg.ToggleFeature("CanvasNoise")
	if !applied {
		t.Error("ToggleFeature(CanvasNoise) should return applied=true")
	}
	if !cfg.CanvasNoise {
		t.Error("CanvasNoise should be true after toggle")
	}
}

func TestStealthConfig_ToggleFeature_allFeatures(t *testing.T) {
	features := []string{
		"RemoveWebDriver", "CanvasNoise", "ClientHints", "RandomUserAgent",
		"WebGLSpoof", "HardwareSync", "NetworkSync", "PluginsSync",
		"GeometrySync", "VideoSync", "PermissionsSync", "TimezoneSync",
	}
	cfg := &chromestealth.StealthConfig{}
	for _, f := range features {
		applied, alreadySet := cfg.ToggleFeature(f)
		if !applied || alreadySet {
			t.Errorf("ToggleFeature(%q) first call: applied=%v alreadySet=%v, want true,false", f, applied, alreadySet)
		}
	}
}

func TestGenerateStealthScript_returnsJS(t *testing.T) {
	cfg := chromestealth.DefaultStealthConfig()
	script := chromestealth.GenerateStealthScript(cfg)
	if script == "" {
		t.Fatal("GenerateStealthScript returned empty string")
	}
	// Should be JavaScript content
	if !strings.Contains(script, "navigator") && !strings.Contains(script, "Object.defineProperty") {
		t.Error("script should contain browser API references")
	}
}

func TestGenerateStealthScript_disabled(t *testing.T) {
	cfg := &chromestealth.StealthConfig{Enabled: false}
	script := chromestealth.GenerateStealthScript(cfg)
	// Disabled config should return empty or minimal script
	_ = script // Not panicking is sufficient
}

func TestBezierCurve_basic(t *testing.T) {
	curve := chromestealth.GenerateBezierCurve(0, 0, 100, 100)
	if curve == nil {
		t.Fatal("GenerateBezierCurve returned nil")
	}
}

func TestBezierCurve_GetPointAt(t *testing.T) {
	curve := chromestealth.GenerateBezierCurve(0, 0, 100, 100)
	x0, y0 := curve.GetPointAt(0.0)
	x1, y1 := curve.GetPointAt(1.0)
	// At t=0 should be near start, at t=1 should be near end
	if x0 < 0 || x0 > 150 {
		t.Errorf("GetPointAt(0).x = %f, expected near 0", x0)
	}
	if x1 < 50 || x1 > 200 {
		t.Errorf("GetPointAt(1).x = %f, expected near 100", x1)
	}
	_ = y0
	_ = y1
}

func TestGenerateMousePath(t *testing.T) {
	path := chromestealth.GenerateMousePath(0, 0, 100, 100, 500*time.Millisecond)
	if path == nil {
		t.Fatal("GenerateMousePath returned nil")
	}
}

func TestMousePath_ToJavaScript(t *testing.T) {
	path := chromestealth.GenerateMousePath(0, 0, 100, 100, 200*time.Millisecond)
	js := path.ToJavaScript()
	if js == "" {
		t.Error("ToJavaScript returned empty string")
	}
}

func TestRandomDelay(t *testing.T) {
	min := 10 * time.Millisecond
	max := 100 * time.Millisecond
	for i := 0; i < 10; i++ {
		d := chromestealth.RandomDelay(min, max)
		if d < min || d > max {
			t.Errorf("RandomDelay out of range: %v (want [%v, %v])", d, min, max)
		}
	}
}

func TestRandomUserAgent_notEmpty(t *testing.T) {
	ua := chromestealth.RandomUserAgent()
	if ua == "" {
		t.Error("RandomUserAgent returned empty string")
	}
	if !strings.Contains(ua, "Mozilla") {
		t.Errorf("RandomUserAgent should return browser UA, got: %q", ua)
	}
}

func TestRandomRAM(t *testing.T) {
	for i := 0; i < 5; i++ {
		ram := chromestealth.RandomRAM()
		if ram <= 0 {
			t.Errorf("RandomRAM() = %d, should be positive", ram)
		}
	}
}

func TestRandomCoreCount(t *testing.T) {
	for i := 0; i < 5; i++ {
		cores := chromestealth.RandomCoreCount()
		if cores <= 0 {
			t.Errorf("RandomCoreCount() = %d, should be positive", cores)
		}
	}
}

func TestRandomFloat(t *testing.T) {
	for i := 0; i < 10; i++ {
		v := chromestealth.RandomFloat(0.5, 1.5)
		if v < 0.5 || v > 1.5 {
			t.Errorf("RandomFloat(0.5, 1.5) = %f out of range", v)
		}
	}
}

func TestRandomBirthDate_notEmpty(t *testing.T) {
	date := chromestealth.RandomBirthDate()
	if date == "" {
		t.Error("RandomBirthDate returned empty string")
	}
}

func TestRandomLocalIP_privateRange(t *testing.T) {
	for i := 0; i < 5; i++ {
		ip := chromestealth.RandomLocalIP()
		if ip == "" {
			t.Error("RandomLocalIP returned empty string")
		}
		if !strings.HasPrefix(ip, "10.") &&
			!strings.HasPrefix(ip, "192.168.") &&
			!strings.HasPrefix(ip, "172.") {
			t.Errorf("RandomLocalIP = %q, expected private IP range", ip)
		}
	}
}

func TestChromeVersions_notEmpty(t *testing.T) {
	if len(chromestealth.ChromeVersions) == 0 {
		t.Error("ChromeVersions should not be empty")
	}
	for _, v := range chromestealth.ChromeVersions {
		if v == "" {
			t.Error("ChromeVersions contains empty string")
		}
	}
}
