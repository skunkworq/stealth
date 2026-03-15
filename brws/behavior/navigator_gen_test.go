package behavior

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/constants"
)

func chromeWindowsNavProfile() NavigatorProfile {
	bp := ChromeWindowsProfile()
	return NavigatorProfileFromBrowserProfile(bp)
}

func chromeMacOSNavProfile() NavigatorProfile {
	bp := ChromeMacOSProfile()
	return NavigatorProfileFromBrowserProfile(bp)
}

func chromeLinuxNavProfile() NavigatorProfile {
	bp := ChromeLinuxProfile()
	return NavigatorProfileFromBrowserProfile(bp)
}

func firefoxWindowsNavProfile() NavigatorProfile {
	bp := FirefoxWindowsProfile()
	return NavigatorProfileFromBrowserProfile(bp)
}

func TestNavigatorData_WindowsChrome(t *testing.T) {
	nav := GenerateNavigatorData(chromeWindowsNavProfile(), 123)

	if nav.Platform != "Win32" {
		t.Errorf("expected platform Win32, got %s", nav.Platform)
	}
	if nav.HardwareConcurrency < 8 {
		t.Errorf("expected hardwareConcurrency >= 8, got %d", nav.HardwareConcurrency)
	}
	if nav.MediaQueryPointer != "fine" {
		t.Errorf("expected pointer fine, got %s", nav.MediaQueryPointer)
	}
	if nav.MediaQueryAnyPointer != "fine" {
		t.Errorf("expected any-pointer fine, got %s", nav.MediaQueryAnyPointer)
	}
	if nav.MaxTouchPoints != 0 {
		t.Errorf("expected maxTouchPoints 0, got %d", nav.MaxTouchPoints)
	}
	if nav.FontPlatform != "windows" {
		t.Errorf("expected font_platform windows, got %s", nav.FontPlatform)
	}
	if nav.UserAgentData == nil {
		t.Fatal("expected userAgentData to be set for Chrome")
	}
	if nav.ScreenColorDepth != 24 {
		t.Errorf("expected colorDepth 24, got %d", nav.ScreenColorDepth)
	}
}

func TestNavigatorData_MacOSChrome(t *testing.T) {
	nav := GenerateNavigatorData(chromeMacOSNavProfile(), 456)

	if nav.Platform != "MacIntel" {
		t.Errorf("expected platform MacIntel, got %s", nav.Platform)
	}
	// For macOS with DPR >= 2.0, screen width must be >= 1920
	if nav.PixelRatio >= 2.0 && nav.ScreenOuterWidth < 1920 {
		t.Errorf("macOS DPR=%.1f but screen width=%d (must be >= 1920)", nav.PixelRatio, nav.ScreenOuterWidth)
	}
	if nav.FontPlatform != "macos" {
		t.Errorf("expected font_platform macos, got %s", nav.FontPlatform)
	}
	if nav.HardwareConcurrency < 8 {
		t.Errorf("expected hardwareConcurrency >= 8 for macOS/Apple Silicon, got %d", nav.HardwareConcurrency)
	}
}

func TestNavigatorData_LanguageConsistency(t *testing.T) {
	profile := chromeWindowsNavProfile()
	profile.AcceptLanguage = "en-US,en;q=0.9"
	nav := GenerateNavigatorData(profile, 789)

	// language must match languages[0]
	if nav.Language != nav.Languages[0] {
		t.Errorf("language (%s) != languages[0] (%s)", nav.Language, nav.Languages[0])
	}

	// intlLocale must match language
	if nav.IntlLocale != nav.Language {
		t.Errorf("intlLocale (%s) != language (%s)", nav.IntlLocale, nav.Language)
	}

	// Primary language must appear in AcceptLanguage
	primaryShort := strings.Split(nav.Language, "-")[0]
	if !strings.Contains(strings.ToLower(profile.AcceptLanguage), strings.ToLower(primaryShort)) {
		t.Errorf("primary language %s not found in Accept-Language %s", primaryShort, profile.AcceptLanguage)
	}
}

func TestNavigatorData_UADataMatchesSecCHUA(t *testing.T) {
	profile := chromeWindowsNavProfile()
	nav := GenerateNavigatorData(profile, 111)

	if nav.UserAgentData == nil {
		t.Fatal("expected userAgentData to be set")
	}

	secCHUA := profile.SecCHUA
	for _, brand := range nav.UserAgentData.Brands {
		expected := fmt.Sprintf(`"%s";v="%s"`, brand.Brand, brand.Version)
		if !strings.Contains(secCHUA, expected) {
			t.Errorf("brand %s v%s not found in SecCHUA: %s", brand.Brand, brand.Version, secCHUA)
		}
	}
}

func TestNavigatorData_ErrorStackV8Format(t *testing.T) {
	nav := GenerateNavigatorData(chromeWindowsNavProfile(), 222)

	if !strings.HasPrefix(nav.ErrorStack, "Error") {
		t.Errorf("V8 stack should start with 'Error', got: %s", nav.ErrorStack[:min(50, len(nav.ErrorStack))])
	}
	if !strings.Contains(nav.ErrorStack, "\n    at ") {
		t.Errorf("V8 stack should contain '\\n    at ', got: %s", nav.ErrorStack)
	}
	if !strings.Contains(nav.ErrorStack, ".js") {
		t.Errorf("V8 stack should contain .js filenames, got: %s", nav.ErrorStack)
	}
	if !strings.Contains(nav.ErrorStack, "async") {
		t.Errorf("V8 stack should contain async frames, got: %s", nav.ErrorStack)
	}
}

func TestNavigatorData_ErrorStackSpiderMonkey(t *testing.T) {
	nav := GenerateNavigatorData(firefoxWindowsNavProfile(), 333)

	if strings.HasPrefix(nav.ErrorStack, "Error") {
		t.Errorf("SpiderMonkey stack should NOT start with 'Error', got: %s", nav.ErrorStack[:min(50, len(nav.ErrorStack))])
	}
	if !strings.Contains(nav.ErrorStack, "@") {
		t.Errorf("SpiderMonkey stack should contain '@', got: %s", nav.ErrorStack)
	}
	if !strings.Contains(nav.ErrorStack, ".js") {
		t.Errorf("SpiderMonkey stack should contain .js filenames, got: %s", nav.ErrorStack)
	}
}

func TestNavigatorData_ScreenDPRCoherent(t *testing.T) {
	// Test multiple seeds to ensure DPR/screen width coherence
	for _, seed := range []int64{1, 42, 100, 999, 12345} {
		for _, platform := range []string{"windows", "macos", "linux"} {
			var profile NavigatorProfile
			switch platform {
			case "windows":
				profile = chromeWindowsNavProfile()
			case "macos":
				profile = chromeMacOSNavProfile()
			case "linux":
				profile = chromeLinuxNavProfile()
			}

			nav := GenerateNavigatorData(profile, seed)

			// DPR >= 2.0 only valid on screens >= 1920px
			if nav.PixelRatio >= 2.0 && nav.ScreenOuterWidth < 1920 {
				t.Errorf("[%s seed=%d] DPR=%.1f but screen width=%d (must be >= 1920)",
					platform, seed, nav.PixelRatio, nav.ScreenOuterWidth)
			}
		}
	}
}

func TestNavigatorData_FontPlatformMatches(t *testing.T) {
	tests := []struct {
		name         string
		profile      NavigatorProfile
		wantPlatform string
		wantFont     string
	}{
		{"Windows", chromeWindowsNavProfile(), "Win32", "windows"},
		{"macOS", chromeMacOSNavProfile(), "MacIntel", "macos"},
		{"Linux", chromeLinuxNavProfile(), "Linux x86_64", "linux"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nav := GenerateNavigatorData(tt.profile, 42)
			if nav.Platform != tt.wantPlatform {
				t.Errorf("platform = %s, want %s", nav.Platform, tt.wantPlatform)
			}
			if nav.FontPlatform != tt.wantFont {
				t.Errorf("font_platform = %s, want %s", nav.FontPlatform, tt.wantFont)
			}
		})
	}
}

func TestNavigatorData_TouchPointerCoherent(t *testing.T) {
	for _, platform := range []string{"windows", "macos", "linux"} {
		var profile NavigatorProfile
		switch platform {
		case "windows":
			profile = chromeWindowsNavProfile()
		case "macos":
			profile = chromeMacOSNavProfile()
		case "linux":
			profile = chromeLinuxNavProfile()
		}

		nav := GenerateNavigatorData(profile, 42)

		// Desktop: touchPoints=0, pointer=fine
		if nav.MaxTouchPoints != 0 {
			t.Errorf("[%s] maxTouchPoints = %d, want 0", platform, nav.MaxTouchPoints)
		}
		if nav.MediaQueryPointer != "fine" {
			t.Errorf("[%s] pointer = %s, want fine", platform, nav.MediaQueryPointer)
		}
		if nav.MediaQueryAnyPointer != "fine" {
			t.Errorf("[%s] any-pointer = %s, want fine", platform, nav.MediaQueryAnyPointer)
		}
	}
}

func TestNavigatorData_PassesIsomorphicAnalyzer(t *testing.T) {
	// Generate navigator data for Chrome/Windows
	bp := ChromeWindowsProfile()
	profile := NavigatorProfileFromBrowserProfile(bp)
	nav := GenerateNavigatorData(profile, 42)

	// Build HTTP request with all required headers
	req, _ := http.NewRequest("GET", "https://example.com/page", nil)

	// Set standard HTTP headers
	req.Header.Set("User-Agent", bp.UserAgent)
	req.Header.Set("Accept", bp.Accept)
	req.Header.Set("Accept-Language", bp.AcceptLanguage)
	req.Header.Set("Accept-Encoding", bp.AcceptEncoding)
	req.Header.Set("Sec-Ch-Ua", bp.SecChUa)
	req.Header.Set("Sec-Ch-Ua-Platform", bp.SecChUaPlatform)
	req.Header.Set("Sec-Ch-Ua-Mobile", bp.SecChUaMobile)
	req.Header.Set("Sec-Fetch-Dest", bp.SecFetchDest)
	req.Header.Set("Sec-Fetch-Mode", bp.SecFetchMode)
	req.Header.Set("Sec-Fetch-Site", bp.SecFetchSite)
	req.Header.Set("Sec-Fetch-User", bp.SecFetchUser)

	// Navigator data header
	navJSON, err := json.Marshal(nav)
	if err != nil {
		t.Fatalf("failed to marshal navigator data: %v", err)
	}
	req.Header.Set(constants.HeaderNavigatorData, string(navJSON))

	// Canvas fingerprint header (minimal valid data)
	canvasData := map[string]interface{}{
		"hash": "data:image/png;base64,abc123",
	}
	canvasJSON, _ := json.Marshal(canvasData)
	req.Header.Set(constants.HeaderCanvasFingerprint, string(canvasJSON))

	// WebGL data header — pick a renderer that is consistent with Windows
	renderer := bp.WebGLRenderers[0] // "NVIDIA GeForce RTX 4070"
	webglData := map[string]interface{}{
		"vendor":            bp.WebGLVendor,
		"renderer":          renderer,
		"unmasked_vendor":   bp.WebGLUnmaskedVendor,
		"unmasked_renderer": renderer,
		"unmaskedRenderer":  renderer,
		"version":           bp.WebGLVersion,
		"platform":          bp.WebGLPlatform,
	}
	webglJSON, _ := json.Marshal(webglData)
	req.Header.Set(constants.HeaderWebGLData, string(webglJSON))

	// Screen data header
	screenData := map[string]interface{}{
		"width":       float64(nav.ScreenOuterWidth),
		"height":      float64(nav.ScreenOuterHeight),
		"outer_width": float64(nav.ScreenOuterWidth),
		"inner_width": float64(nav.ScreenInnerWidth),
		"color_depth": float64(nav.ScreenColorDepth),
		"pixel_ratio": nav.PixelRatio,
	}
	screenJSON, _ := json.Marshal(screenData)
	req.Header.Set(constants.HeaderScreenData, string(screenJSON))

	// Font data header
	fontData := map[string]interface{}{
		"platform": nav.FontPlatform,
		"fonts":    bp.Fonts,
	}
	fontJSON, _ := json.Marshal(fontData)
	req.Header.Set(constants.HeaderFontData, string(fontJSON))

	// Behavioral data header (with error stack)
	behavData := map[string]interface{}{
		"errorStack": nav.ErrorStack,
	}
	behavJSON, _ := json.Marshal(behavData)
	req.Header.Set(constants.HeaderBehavioralData, string(behavJSON))

	// Build HTTPFingerprintInfo matching the headers
	httpInfo := &adversarial.HTTPFingerprintInfo{
		UserAgent:              bp.UserAgent,
		Platform:               bp.Platform,
		Accept:                 bp.Accept,
		AcceptLanguage:         bp.AcceptLanguage,
		AcceptEncoding:         bp.AcceptEncoding,
		SecCHUA:                bp.SecChUa,
		SecCHUAPlatform:        bp.SecChUaPlatform,
		SecCHUAMobile:          bp.SecChUaMobile,
		SecCHUAFullVersionList: bp.SecChUaFullVersionList,
		SecCHUAArch:            bp.SecChUaArch,
		SecCHUABitness:         bp.SecChUaBitness,
		SecFetchDest:           bp.SecFetchDest,
		SecFetchMode:           bp.SecFetchMode,
		SecFetchSite:           bp.SecFetchSite,
		SecFetchUser:           bp.SecFetchUser,
		// Header order — Sec-Ch-Ua before User-Agent (standard Chrome order)
		HeaderOrder: []string{
			"Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform",
			"User-Agent", "Accept", "Accept-Language", "Accept-Encoding",
			"Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site", "Sec-Fetch-User",
		},
		HeaderCount: 11,
	}

	// Run the IsomorphicAnalyzer
	ia := adversarial.NewIsomorphicAnalyzer()
	result := ia.Analyze(req, httpInfo)

	if result == nil {
		t.Fatal("expected non-nil detection vector")
	}

	if result.Score != 0 {
		t.Errorf("expected score=0, got score=%.2f", result.Score)
		t.Logf("Detected: %v", result.Detected)
		for _, ind := range result.Indicators {
			t.Logf("  indicator: %s", ind)
		}
		for _, cr := range result.CheckReports {
			t.Logf("  check: %s (score=%.2f) actual=%s expected=%s",
				cr.Name, cr.Score, cr.Actual, cr.Expected)
		}
	}

	if result.Detected {
		t.Errorf("expected Detected=false, got true")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
