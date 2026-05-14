package chromestealth

import (
	"strings"
	"testing"
)

func TestDefaultWebRTCConfig(t *testing.T) {
	cfg := DefaultWebRTCConfig()
	if cfg.Mode != WebRTCDisable {
		t.Errorf("expected default mode WebRTCDisable, got %d", cfg.Mode)
	}
	if cfg.PreserveMedia {
		t.Error("expected default PreserveMedia to be false")
	}
}

func TestGenerateWebRTCScript_DisableMode(t *testing.T) {
	cfg := &WebRTCConfig{
		Mode:          WebRTCDisable,
		PreserveMedia: false,
	}

	script := GenerateWebRTCScript(cfg)

	if !strings.Contains(script, "WebRTC Leak Prevention") {
		t.Error("script should contain WebRTC header comment")
	}
	if !strings.Contains(script, "Disable Mode") {
		t.Error("disable mode script should be labeled")
	}
	if !strings.Contains(script, "noopRTC") {
		t.Error("disable mode should define noopRTC constructor")
	}
	if !strings.Contains(script, "RTCPeerConnection") {
		t.Error("script should override RTCPeerConnection")
	}
	// Should also hide getUserMedia when PreserveMedia is false
	if !strings.Contains(script, "getUserMedia") {
		t.Error("should hide getUserMedia when PreserveMedia is false")
	}
	if !strings.Contains(script, "enumerateDevices") {
		t.Error("should hide enumerateDevices when PreserveMedia is false")
	}
}

func TestGenerateWebRTCScript_DisableMode_PreserveMedia(t *testing.T) {
	cfg := &WebRTCConfig{
		Mode:          WebRTCDisable,
		PreserveMedia: true,
	}

	script := GenerateWebRTCScript(cfg)

	if !strings.Contains(script, "noopRTC") {
		t.Error("should still disable RTCPeerConnection")
	}
	// Should NOT hide getUserMedia
	if strings.Contains(script, "enumerateDevices") {
		t.Error("should NOT hide enumerateDevices when PreserveMedia is true")
	}
}

func TestGenerateWebRTCScript_RelayOnlyMode(t *testing.T) {
	cfg := &WebRTCConfig{
		Mode:          WebRTCRelayOnly,
		PreserveMedia: true,
	}

	script := GenerateWebRTCScript(cfg)

	if !strings.Contains(script, "Relay Only Mode") {
		t.Error("relay mode script should be labeled")
	}
	if !strings.Contains(script, "iceTransportPolicy") {
		t.Error("relay mode should force iceTransportPolicy")
	}
	if !strings.Contains(script, "'relay'") {
		t.Error("should set transport policy to relay")
	}
	if !strings.Contains(script, "OriginalRTCPeerConnection") {
		t.Error("should store original constructor")
	}
	// Should filter non-relay candidates
	if !strings.Contains(script, "relay") {
		t.Error("should filter for relay candidates")
	}
}

func TestGenerateWebRTCScript_NilConfig(t *testing.T) {
	script := GenerateWebRTCScript(nil)

	// Should default to disable mode
	if !strings.Contains(script, "Disable Mode") {
		t.Error("nil config should default to disable mode")
	}
}

func TestWebRTCModeConstants(t *testing.T) {
	if WebRTCDisable != 0 {
		t.Errorf("WebRTCDisable should be 0, got %d", WebRTCDisable)
	}
	if WebRTCRelayOnly != 1 {
		t.Errorf("WebRTCRelayOnly should be 1, got %d", WebRTCRelayOnly)
	}
}
