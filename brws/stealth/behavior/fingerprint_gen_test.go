package behavior_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/skunkworq/stealth/brws/stealth/challenge"
	"github.com/skunkworq/stealth/brws/stealth/behavior"
	"github.com/skunkworq/stealth/brws/core/constants"
)

func TestGeneratePlatformFingerprints_Windows(t *testing.T) {
	fp := behavior.GeneratePlatformFingerprints("windows", "chrome", 42)
	if fp == nil {
		t.Fatal("expected non-nil fingerprints")
	}

	renderer := fp.Canvas.UnmaskedRenderer
	if !strings.Contains(renderer, "Direct3D") && !strings.Contains(renderer, "ANGLE") {
		t.Errorf("Windows renderer should contain Direct3D or ANGLE, got %q", renderer)
	}

	// WebGL should match canvas GPU.
	if fp.WebGL.UnmaskedRenderer != fp.Canvas.UnmaskedRenderer {
		t.Errorf("WebGL unmasked renderer %q should match canvas %q",
			fp.WebGL.UnmaskedRenderer, fp.Canvas.UnmaskedRenderer)
	}

	if fp.Canvas.MaxTextureSize < 8192 {
		t.Errorf("expected maxTextureSize >= 8192, got %d", fp.Canvas.MaxTextureSize)
	}

	if len(fp.Canvas.Extensions) == 0 {
		t.Error("expected non-empty extensions list")
	}
}

func TestGeneratePlatformFingerprints_MacOS(t *testing.T) {
	fp := behavior.GeneratePlatformFingerprints("macos", "chrome", 42)
	if fp == nil {
		t.Fatal("expected non-nil fingerprints")
	}

	renderer := fp.Canvas.UnmaskedRenderer
	isApple := strings.Contains(renderer, "Apple")
	isIntel := strings.Contains(renderer, "Intel")
	if !isApple && !isIntel {
		t.Errorf("macOS renderer should contain Apple or Intel, got %q", renderer)
	}

	// Must NOT contain Direct3D (Windows-only).
	if strings.Contains(renderer, "Direct3D") {
		t.Errorf("macOS renderer should not contain Direct3D, got %q", renderer)
	}
}

func TestGeneratePlatformFingerprints_Linux(t *testing.T) {
	fp := behavior.GeneratePlatformFingerprints("linux", "chrome", 42)
	if fp == nil {
		t.Fatal("expected non-nil fingerprints")
	}

	renderer := fp.Canvas.UnmaskedRenderer
	isMesa := strings.Contains(renderer, "Mesa")
	isNvidia := strings.Contains(renderer, "NVIDIA")
	if !isMesa && !isNvidia {
		t.Errorf("Linux renderer should contain Mesa or NVIDIA, got %q", renderer)
	}

	// Must NOT contain Direct3D (Windows-only) or Apple.
	if strings.Contains(renderer, "Direct3D") || strings.Contains(renderer, "Apple") {
		t.Errorf("Linux renderer should not contain Direct3D or Apple, got %q", renderer)
	}
}

func TestGeneratePlatformFingerprints_ChromeAudio(t *testing.T) {
	fp := behavior.GeneratePlatformFingerprints("windows", "chrome", 42)
	if fp == nil {
		t.Fatal("expected non-nil fingerprints")
	}

	if fp.Audio.SampleRate != 48000 {
		t.Errorf("Chrome sampleRate should be 48000, got %v", fp.Audio.SampleRate)
	}
	if fp.Audio.ChannelCount != 2 {
		t.Errorf("expected channelCount=2, got %d", fp.Audio.ChannelCount)
	}
	if fp.Audio.BaseLatency < 0.005 || fp.Audio.BaseLatency > 0.015 {
		t.Errorf("Chrome baseLatency should be 0.005-0.015, got %v", fp.Audio.BaseLatency)
	}
	if fp.Audio.CompressorHash == "" {
		t.Error("expected non-empty compressor hash")
	}
	if fp.Audio.State != "suspended" {
		t.Errorf("expected state=suspended, got %q", fp.Audio.State)
	}
}

func TestGeneratePlatformFingerprints_FirefoxAudio(t *testing.T) {
	fp := behavior.GeneratePlatformFingerprints("windows", "firefox", 42)
	if fp == nil {
		t.Fatal("expected non-nil fingerprints")
	}

	if fp.Audio.SampleRate != 44100 {
		t.Errorf("Firefox sampleRate should be 44100, got %v", fp.Audio.SampleRate)
	}
}

func TestCanvasFingerprint_PassesIsomorphicCheck(t *testing.T) {
	fp := behavior.GeneratePlatformFingerprints("windows", "chrome", 99)

	// Serialize canvas data as header JSON.
	canvasJSON, err := json.Marshal(fp.Canvas)
	if err != nil {
		t.Fatalf("failed to marshal canvas: %v", err)
	}
	webglJSON, err := json.Marshal(fp.WebGL)
	if err != nil {
		t.Fatalf("failed to marshal webgl: %v", err)
	}

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	req.Header.Set(constants.HeaderCanvasFingerprint, string(canvasJSON))
	req.Header.Set(constants.HeaderWebGLData, string(webglJSON))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)

	httpInfo := &challenge.HTTPFingerprintInfo{
		UserAgent:       req.Header.Get("User-Agent"),
		Platform:        "Windows",
		SecCHUA:         req.Header.Get("Sec-Ch-Ua"),
		SecCHUAPlatform: `"Windows"`,
		AcceptLanguage:  req.Header.Get("Accept-Language"),
		HeaderOrder:     []string{"Sec-Ch-Ua", "Sec-Ch-Ua-Platform", "User-Agent", "Accept", "Accept-Language"},
		HeaderCount:     5,
	}

	analyzer := challenge.NewIsomorphicAnalyzer()
	vec := analyzer.Analyze(req, httpInfo)

	if vec != nil && vec.Score > 0 {
		t.Errorf("isomorphic analyzer flagged Windows canvas fingerprint (score=%.2f): indicators=%v",
			vec.Score, vec.Indicators)
		for _, cr := range vec.CheckReports {
			t.Logf("  check %s: actual=%s expected=%s", cr.Name, cr.Actual, cr.Expected)
		}
	}
}

func TestFingerprints_Deterministic(t *testing.T) {
	fp1 := behavior.GeneratePlatformFingerprints("windows", "chrome", 12345)
	fp2 := behavior.GeneratePlatformFingerprints("windows", "chrome", 12345)

	if fp1.Canvas.Hash != fp2.Canvas.Hash {
		t.Errorf("same seed should produce same canvas hash: %q vs %q", fp1.Canvas.Hash, fp2.Canvas.Hash)
	}
	if fp1.Canvas.UnmaskedRenderer != fp2.Canvas.UnmaskedRenderer {
		t.Errorf("same seed should produce same renderer: %q vs %q",
			fp1.Canvas.UnmaskedRenderer, fp2.Canvas.UnmaskedRenderer)
	}
	if fp1.Audio.SampleRate != fp2.Audio.SampleRate {
		t.Errorf("same seed should produce same sample rate: %v vs %v",
			fp1.Audio.SampleRate, fp2.Audio.SampleRate)
	}
	if fp1.Audio.CompressorHash != fp2.Audio.CompressorHash {
		t.Errorf("same seed should produce same compressor hash: %q vs %q",
			fp1.Audio.CompressorHash, fp2.Audio.CompressorHash)
	}
	if fp1.Audio.BaseLatency != fp2.Audio.BaseLatency {
		t.Errorf("same seed should produce same base latency: %v vs %v",
			fp1.Audio.BaseLatency, fp2.Audio.BaseLatency)
	}
	if fp1.WebGL.UnmaskedRenderer != fp2.WebGL.UnmaskedRenderer {
		t.Errorf("same seed should produce same WebGL renderer: %q vs %q",
			fp1.WebGL.UnmaskedRenderer, fp2.WebGL.UnmaskedRenderer)
	}

	// Different seed should (very likely) produce different results.
	fp3 := behavior.GeneratePlatformFingerprints("windows", "chrome", 99999)
	if fp1.Canvas.Hash == fp3.Canvas.Hash {
		t.Error("different seeds should produce different canvas hashes")
	}
}
