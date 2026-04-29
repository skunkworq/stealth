package tlsfprint

import (
	"testing"
)

func TestCalculateWebSocketFingerprint(t *testing.T) {
	headers := map[string]string{
		"host":                   "example.com",
		"origin":                 "https://example.com",
		"connection":             "Upgrade",
		"upgrade":                "websocket",
		"sec-websocket-key":      "dGhlIHNhbXBsZSBub25jZQ==",
		"sec-websocket-version":  "13",
		"sec-websocket-protocol": "soap",
		"user-agent":             "Mozilla/5.0 Chrome/120.0",
	}

	fp := CalculateWebSocketFingerprint(headers)

	if fp == "" {
		t.Error("expected non-empty fingerprint")
	}

	t.Logf("WebSocket Fingerprint: %s", fp)
}

func TestCalculateJA3W(t *testing.T) {
	headers := map[string]string{
		"host":                  "example.com",
		"origin":                "https://example.com",
		"connection":            "Upgrade",
		"upgrade":               "websocket",
		"sec-websocket-key":     "dGhlIHNhbXBsZSBub25jZQ==",
		"sec-websocket-version": "13",
		"user-agent":            "Mozilla/5.0 Chrome/120.0",
	}

	ja3w := CalculateJA3W(headers)

	if ja3w == "" {
		t.Error("expected non-empty JA3W")
	}

	if len(ja3w) != 32 {
		t.Errorf("expected JA3W length 32, got %d", len(ja3w))
	}

	t.Logf("JA3W: %s", ja3w)
}

func TestWebSocketSignatures(t *testing.T) {
	for name, sig := range WebSocketSignatures {
		t.Run(name, func(t *testing.T) {
			if sig.Name == "" {
				t.Error("expected non-empty name")
			}
			if sig.Browser == "" {
				t.Error("expected non-empty browser")
			}
			t.Logf("%s: browser=%s, version=%s, extensions=%v", name, sig.Browser, sig.Version, sig.Extensions)
		})
	}
}

func TestDetectBrowserFromWebSocket(t *testing.T) {
	tests := []struct {
		headers       map[string]string
		expectedMatch string
	}{
		{
			headers: map[string]string{
				"user-agent": "Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36",
			},
			expectedMatch: "chrome",
		},
		{
			headers: map[string]string{
				"user-agent":               "Mozilla/5.0 Firefox/120.0",
				"sec-websocket-extensions": "permessage-deflate",
			},
			expectedMatch: "firefox",
		},
		{
			headers: map[string]string{
				"user-agent": "Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
			},
			expectedMatch: "edge",
		},
		{
			headers: map[string]string{
				"user-agent": "Mozilla/5.0 Safari/605.1.15",
			},
			expectedMatch: "safari",
		},
		{
			headers:       map[string]string{},
			expectedMatch: "unknown",
		},
		{
			headers: map[string]string{
				"sec-websocket-extensions": "permessage-deflate, client_max_window_bits",
			},
			expectedMatch: "chrome",
		},
	}

	for i, tt := range tests {
		result := DetectBrowserFromWebSocket(tt.headers)
		t.Logf("Test %d: headers=%v, result=%s, expected=%s", i, tt.headers, result, tt.expectedMatch)
		if result != tt.expectedMatch {
			t.Errorf("test %d: expected %s, got %s", i, tt.expectedMatch, result)
		}
	}
}

func TestWebSocketAnalyzer(t *testing.T) {
	analyzer := NewWebSocketAnalyzer()

	headers := map[string]string{
		"host":                     "example.com",
		"origin":                   "https://example.com",
		"connection":               "Upgrade",
		"upgrade":                  "websocket",
		"sec-websocket-key":        "dGhlIHNhbXBsZSBub25jZQ==",
		"sec-websocket-version":    "13",
		"sec-websocket-extensions": "permessage-deflate",
		"user-agent":               "Mozilla/5.0 Chrome/120.0",
	}

	obs := analyzer.Record(headers)

	if obs.JA3W == "" {
		t.Error("expected non-empty JA3W in observation")
	}

	if obs.DetectedBrowser != "chrome" {
		t.Errorf("expected chrome, got %s", obs.DetectedBrowser)
	}

	observations := analyzer.GetObservations()
	if len(observations) != 1 {
		t.Errorf("expected 1 observation, got %d", len(observations))
	}

	unique := analyzer.GetUniqueFingerprints()
	if len(unique) != 1 {
		t.Errorf("expected 1 unique fingerprint, got %d", len(unique))
	}

	dist := analyzer.GetBrowserDistribution()
	if dist["chrome"] != 1 {
		t.Errorf("expected chrome count 1, got %d", dist["chrome"])
	}
}

func TestValidateWebSocketKey(t *testing.T) {
	validKeys := []string{
		"dGhlIHNhbXBsZSBub25jZQ==",
		"YW55IGNhcmQgZm9yIG1heA==",
		"YW55IGNhcmQgZm9yIG1heA",
	}

	invalidKeys := []string{
		"",
		"short",
		"invalid!key@chars",
	}

	for _, key := range validKeys {
		if !ValidateWebSocketKey(key) {
			t.Errorf("expected valid key: %s", key)
		}
	}

	for _, key := range invalidKeys {
		if ValidateWebSocketKey(key) {
			t.Errorf("expected invalid key: %s", key)
		}
	}
}

func TestValidateWebSocketVersion(t *testing.T) {
	validVersions := []string{"13", "8", "7"}
	invalidVersions := []string{"", "abc", "13.0", "6", "0", "100"}

	for _, v := range validVersions {
		if !ValidateWebSocketVersion(v) {
			t.Errorf("expected valid version: %s", v)
		}
	}

	for _, v := range invalidVersions {
		if ValidateWebSocketVersion(v) {
			t.Errorf("expected invalid version: %s", v)
		}
	}
}

func TestGenerateWebSocketKey(t *testing.T) {
	key := GenerateWebSocketKey()

	if !ValidateWebSocketKey(key) {
		t.Errorf("generated key should be valid: %s", key)
	}

	if len(key) != 22 {
		t.Errorf("expected key length 22, got %d", len(key))
	}

	t.Logf("Generated WebSocket key: %s", key)
}

func TestWebSocketHandshakeAnalyzer(t *testing.T) {
	analyzer := NewWebSocketHandshakeAnalyzer()

	headers := map[string]string{
		"host":                  "example.com",
		"origin":                "https://example.com",
		"connection":            "Upgrade",
		"upgrade":               "websocket",
		"sec-websocket-key":     "dGhlIHNhbXBsZSBub25jZQ==",
		"sec-websocket-version": "13",
	}

	obs := analyzer.Record("GET", "/ws", headers)

	if !obs.IsValid {
		t.Error("expected valid WebSocket handshake")
	}

	invalidHeaders := map[string]string{
		"host":       "example.com",
		"connection": "close",
	}

	obs2 := analyzer.Record("GET", "/ws", invalidHeaders)
	if obs2.IsValid {
		t.Error("expected invalid WebSocket handshake")
	}

	valid := analyzer.GetValidCount()
	invalid := analyzer.GetInvalidCount()

	if valid != 1 {
		t.Errorf("expected 1 valid, got %d", valid)
	}
	if invalid != 1 {
		t.Errorf("expected 1 invalid, got %d", invalid)
	}

	originDist := analyzer.GetOriginDistribution()
	t.Logf("Origin distribution: %v", originDist)
}

func TestWebSocketFrameAnalyzer(t *testing.T) {
	analyzer := NewWebSocketFrameAnalyzer()

	frames := []WebSocketFrameFingerprint{
		{OpCode: 0x1, Masked: true, PayloadLength: 10, Fin: true},
		{OpCode: 0x2, Masked: false, PayloadLength: 100, Fin: true},
		{OpCode: 0x8, Masked: true, PayloadLength: 0, Fin: true},
		{OpCode: 0x9, Masked: true, PayloadLength: 5, Fin: true},
		{OpCode: 0xA, Masked: false, PayloadLength: 5, Fin: true},
	}

	for _, frame := range frames {
		analyzer.Record(frame)
	}

	allFrames := analyzer.GetFrames()
	if len(allFrames) != 5 {
		t.Errorf("expected 5 frames, got %d", len(allFrames))
	}

	opDist := analyzer.GetOpCodeDistribution()
	if opDist[0x1] != 1 {
		t.Errorf("expected 1 text frame, got %d", opDist[0x1])
	}
	if opDist[0x2] != 1 {
		t.Errorf("expected 1 binary frame, got %d", opDist[0x2])
	}
	if opDist[0x8] != 1 {
		t.Errorf("expected 1 close frame, got %d", opDist[0x8])
	}

	maskedRatio := analyzer.GetMaskedRatio()
	t.Logf("Masked ratio: %.2f", maskedRatio)
}

func TestWebSocketFingerprintEquality(t *testing.T) {
	headers1 := map[string]string{
		"host":       "example.com",
		"origin":     "https://example.com",
		"user-agent": "Mozilla/5.0 Chrome/120.0",
	}
	headers2 := map[string]string{
		"host":       "example.com",
		"origin":     "https://example.com",
		"user-agent": "Mozilla/5.0 Chrome/120.0",
	}

	fp1 := CalculateWebSocketFingerprint(headers1)
	fp2 := CalculateWebSocketFingerprint(headers2)

	if fp1 != fp2 {
		t.Errorf("expected equal fingerprints")
	}

	ja3w1 := CalculateJA3W(headers1)
	ja3w2 := CalculateJA3W(headers2)

	if ja3w1 != ja3w2 {
		t.Errorf("expected equal JA3W")
	}

	t.Logf("Fingerprint: %s, JA3W: %s", fp1, ja3w1)
}

func TestWebSocketFingerprintDifference(t *testing.T) {
	chromeHeaders := map[string]string{
		"user-agent":               "Mozilla/5.0 Chrome/120.0",
		"sec-websocket-extensions": "permessage-deflate, client_max_window_bits",
	}
	firefoxHeaders := map[string]string{
		"user-agent":               "Mozilla/5.0 Firefox/120.0",
		"sec-websocket-extensions": "permessage-deflate",
	}

	fp1 := CalculateWebSocketFingerprint(chromeHeaders)
	fp2 := CalculateWebSocketFingerprint(firefoxHeaders)

	if fp1 == fp2 {
		t.Error("expected different fingerprints")
	}

	t.Logf("Chrome FP: %s", fp1)
	t.Logf("Firefox FP: %s", fp2)
}

func TestWebSocketFrameFingerprintString(t *testing.T) {
	frame := WebSocketFrameFingerprint{
		OpCode:        0x1,
		Masked:        true,
		PayloadLength: 100,
		Fin:           true,
		RSV1:          false,
		RSV2:          false,
		RSV3:          false,
	}

	str := frame.String()
	t.Logf("Frame: %s", str)

	if str == "" {
		t.Error("expected non-empty string")
	}
}
