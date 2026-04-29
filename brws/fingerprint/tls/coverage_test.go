package tlsfprint

import (
	"testing"
	"time"
)

func TestTLSFingerprintFull(t *testing.T) {
	tls := &TLSFingerprint{
		Version:          "TLS 1.3",
		CipherSuites:     []uint16{0x1301, 0x1302, 0x1303},
		CipherSuiteNames: []string{"AES128GCM", "AES256GCM", "CHACHA20"},
		Extensions:       []uint16{0x0, 0xa, 0xd, 0x10, 0x2b, 0x2d, 0x33},
		ExtensionNames:   []string{"server_name", "supported_groups"},
		SupportedGroups:  []uint16{29, 23, 25},
		SignatureAlgs:    []uint16{1027, 1025, 2052, 1042},
		ALPN:             []string{"h3", "h3-29"},
		SNI:              "test.example.com",
		SessionID:        "session123",
		JA3:              "771,47-53-192",
		JA4:              "t13d0003h3e1299a1b2c3d4e5f6",
		HasGREASE:        true,
		IsTLS13:          true,
	}

	if !tls.IsTLS13 {
		t.Error("expected TLS 1.3")
	}

	if len(tls.CipherSuites) != 3 {
		t.Errorf("expected 3 cipher suites, got %d", len(tls.CipherSuites))
	}

	if !tls.HasGREASE {
		t.Error("expected GREASE")
	}
}

func TestHTTP2FingerprintFull(t *testing.T) {
	http2 := &HTTP2Fingerprint{
		Settings:          map[uint16]uint32{1: 4096, 3: 100, 4: 6291456, 5: 100, 6: 16, 7: 256},
		SettingsOrder:     []uint16{1, 3, 4, 5, 6, 7},
		PseudoHeaders:     []string{":method", ":path", ":authority", ":scheme"},
		HeaderOrder:       []string{"accept", "accept-encoding", "accept-language"},
		EnablePush:        false,
		InitialWindowSize: 65535,
		MaxFrameSize:      16384,
		MaxConcurrent:     100,
		JA3H2:             "test-ja3h2",
		JA3H2Fingerprint:  "test-ja3h2-fp",
	}

	if http2.InitialWindowSize != 65535 {
		t.Errorf("expected window 65535, got %d", http2.InitialWindowSize)
	}

	if len(http2.Settings) != 6 {
		t.Errorf("expected 6 settings, got %d", len(http2.Settings))
	}
}

func TestHTTP1FingerprintFull(t *testing.T) {
	http1 := &HTTP1Fingerprint{
		Headers: map[string]string{
			"user-agent":      "Mozilla/5.0 Chrome/120.0",
			"accept":          "text/html",
			"accept-language": "en-US",
			"accept-encoding": "gzip, deflate, br",
			"sec-ch-ua":       `"Not_A Brand";v="8"`,
		},
		HeaderOrder:     []string{"user-agent", "accept", "accept-language"},
		UserAgent:       "Mozilla/5.0 Chrome/120.0",
		Accept:          "text/html",
		AcceptLanguage:  "en-US",
		AcceptEncoding:  "gzip, deflate, br",
		SecChUa:         `"Not_A Brand";v="8"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
		SecFetchDest:    "document",
		JA3H1:           "test-ja3h1",
	}

	if len(http1.Headers) != 5 {
		t.Errorf("expected 5 headers, got %d", len(http1.Headers))
	}

	if http1.SecChUaMobile != "?0" {
		t.Error("expected mobile 0")
	}
}

func TestBehavioralSignature(t *testing.T) {
	sig := BehavioralSignatures["chrome-human"]
	if sig == nil {
		t.Fatal("expected chrome-human signature")
	}

	if sig.Browser != "chrome" {
		t.Errorf("expected chrome, got %s", sig.Browser)
	}

	if sig.MouseVariance <= 0 {
		t.Error("expected positive mouse variance")
	}
}

func TestBehavioralGenerator(t *testing.T) {
	sig := BehavioralSignatures["chrome-human"]
	gen := NewBehavioralGenerator(sig, 12345)

	movements := gen.GenerateMouseMovement(1000 * time.Millisecond)
	if len(movements) == 0 {
		t.Error("expected some movements")
	}

	typing := gen.GenerateTyping("hello world")
	if len(typing) == 0 {
		t.Error("expected some keystrokes")
	}

	scrolling := gen.GenerateScrolling(1000 * time.Millisecond)
	if len(scrolling) == 0 {
		t.Error("expected some scroll events")
	}
}

func TestCompleteFingerprintAllLayers(t *testing.T) {
	fp := &CompleteFingerprint{
		TraceID:         "trace-all-layers",
		TLS:             &TLSFingerprint{Version: "TLS 1.3", JA4: "t13d0003"},
		HTTP1:           &HTTP1Fingerprint{JA3H1: "h1-fp"},
		HTTP2:           &HTTP2Fingerprint{JA3H2: "h2-fp"},
		WebSocket:       &WSFingerprint{JA3W: "ws-fp"},
		Behavioral:      &BehavioralPrint{MouseVariance: 100},
		JA3:             "ja3-fp",
		JA4:             "ja4-fp",
		JA3H1:           "ja3h1-fp",
		JA3H2:           "ja3h2-fp",
		JA3W:            "ja3w-fp",
		DetectedBrowser: "chrome",
		Confidence:      0.95,
		Metadata:        map[string]string{"source": "test", "version": "1.0"},
	}

	if fp.TLS == nil {
		t.Error("expected TLS")
	}

	if fp.HTTP1 == nil {
		t.Error("expected HTTP1")
	}

	if fp.HTTP2 == nil {
		t.Error("expected HTTP2")
	}

	if fp.WebSocket == nil {
		t.Error("expected WebSocket")
	}

	if fp.Behavioral == nil {
		t.Error("expected Behavioral")
	}

	if fp.Confidence != 0.95 {
		t.Errorf("expected 0.95, got %f", fp.Confidence)
	}

	if fp.Metadata["version"] != "1.0" {
		t.Error("expected metadata version 1.0")
	}
}

func TestFingerprintFilterEmpty(t *testing.T) {
	fps := []*CompleteFingerprint{}

	filtered := NewFingerprintFilter().Filter(fps)

	if len(filtered) != 0 {
		t.Errorf("expected 0 filtered, got %d", len(filtered))
	}
}

func TestFingerprintFilterChainWithAll(t *testing.T) {
	now := time.Now()
	fps := []*CompleteFingerprint{
		{TraceID: "1", DetectedBrowser: "chrome", Confidence: 0.95, Timestamp: now},
		{TraceID: "2", DetectedBrowser: "chrome", Confidence: 0.85, Timestamp: now},
		{TraceID: "3", DetectedBrowser: "firefox", Confidence: 0.90, Timestamp: now},
		{TraceID: "4", DetectedBrowser: "safari", Confidence: 0.75, Timestamp: now},
	}

	filtered := NewFingerprintFilter().
		WithMinConfidence(0.8).
		WithBrowsers("chrome", "firefox").
		Filter(fps)

	if len(filtered) != 3 {
		t.Errorf("expected 3 filtered, got %d", len(filtered))
	}
}

func TestCompareFingerprintsEmpty(t *testing.T) {
	fp1 := &CompleteFingerprint{TLS: &TLSFingerprint{JA3: "a"}}
	fp2 := &CompleteFingerprint{TLS: &TLSFingerprint{JA3: "b"}}

	comp := CompareFingerprints(fp1, fp2)

	if comp.Similarity > 0.5 {
		t.Logf("Similarity: %f", comp.Similarity)
	}
}

func TestCompareFingerprintsFullMatch(t *testing.T) {
	fp1 := &CompleteFingerprint{
		TLS:             &TLSFingerprint{JA3: "test", JA4: "test", Version: "TLS 1.3"},
		HTTP1:           &HTTP1Fingerprint{JA3H1: "test"},
		HTTP2:           &HTTP2Fingerprint{JA3H2: "test"},
		DetectedBrowser: "chrome",
	}

	fp2 := &CompleteFingerprint{
		TLS:             &TLSFingerprint{JA3: "test", JA4: "test", Version: "TLS 1.3"},
		HTTP1:           &HTTP1Fingerprint{JA3H1: "test"},
		HTTP2:           &HTTP2Fingerprint{JA3H2: "test"},
		DetectedBrowser: "chrome",
	}

	comp := CompareFingerprints(fp1, fp2)

	t.Logf("Similarity: %f", comp.Similarity)
	t.Logf("MatchDetails: %v", comp.MatchDetails)
}

func TestFingerprintExporterEmpty(t *testing.T) {
	exporter := NewFingerprintExporter()

	json, err := exporter.ToJSON()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if json != "[]" {
		t.Errorf("expected [], got %s", json)
	}

	csv := exporter.ToCSV()
	expected := "trace_id,timestamp,tls_version,ja3,ja4,ja3h1,ja3h2,detected_browser,confidence"
	if csv != expected {
		t.Errorf("expected header only, got %s", csv)
	}
}

func TestFingerprintExporterMultiple(t *testing.T) {
	exporter := NewFingerprintExporter()

	for i := 0; i < 100; i++ {
		exporter.Add(&CompleteFingerprint{
			TraceID:         "test",
			JA3:             "test",
			DetectedBrowser: "chrome",
			Confidence:      0.9,
		})
	}

	json, err := exporter.ToJSON()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if len(json) == 0 {
		t.Error("expected non-empty JSON")
	}

	csv := exporter.ToCSV()
	lines := 0
	for _, c := range csv {
		if c == '\n' {
			lines++
		}
	}

	if lines != 100 {
		t.Logf("CSV lines: %d (expected 100)", lines)
	}
}

func TestBehavioralAnalyzerMouse(t *testing.T) {
	analyzer := NewBehavioralAnalyzer()

	now := time.Now()
	movements := []MouseMovement{
		{Timestamp: now, X: 100, Y: 100, VelocityX: 10, VelocityY: 5, IsClick: false},
		{Timestamp: now.Add(50 * time.Millisecond), X: 150, Y: 120, VelocityX: 10, VelocityY: 5, IsClick: true, Button: 0},
	}

	result := analyzer.AnalyzeMouseMovement(movements)

	t.Logf("Mouse analysis: IsHuman=%v, Confidence=%.2f, Velocity=%.2f",
		result.IsHuman, result.Confidence, result.AvgVelocity)
}

func TestBehavioralAnalyzerTyping(t *testing.T) {
	analyzer := NewBehavioralAnalyzer()

	now := time.Now()
	typing := []KeystrokeTiming{
		{Timestamp: now, Key: "h", PressTime: 50 * time.Millisecond, HoldTime: 50 * time.Millisecond, InterKey: 0},
		{Timestamp: now.Add(100 * time.Millisecond), Key: "e", PressTime: 45 * time.Millisecond, HoldTime: 45 * time.Millisecond, InterKey: 100 * time.Millisecond},
		{Timestamp: now.Add(200 * time.Millisecond), Key: "l", PressTime: 40 * time.Millisecond, HoldTime: 40 * time.Millisecond, InterKey: 80 * time.Millisecond},
	}

	result := analyzer.AnalyzeTyping(typing)

	t.Logf("Typing analysis: IsHuman=%v, Confidence=%.2f, KeyCount=%d",
		result.IsHuman, result.Confidence, result.KeyCount)
}

func TestBehavioralAnalyzerScrolling(t *testing.T) {
	analyzer := NewBehavioralAnalyzer()

	now := time.Now()
	scrolls := []ScrollEvent{
		{Timestamp: now, Y: 0, DeltaY: 100, Velocity: 500, IsTouch: true},
		{Timestamp: now.Add(100 * time.Millisecond), Y: 100, DeltaY: 150, Velocity: 750, IsTouch: true},
	}

	result := analyzer.AnalyzeScrolling(scrolls)

	t.Logf("Scroll analysis: IsHuman=%v, Confidence=%.2f, Velocity=%.2f",
		result.IsHuman, result.Confidence, result.AvgVelocity)
}

func TestBehavioralAnalyzerNetwork(t *testing.T) {
	analyzer := NewBehavioralAnalyzer()

	now := time.Now()
	requests := []NetworkRequest{
		{Timestamp: now, URL: "/api/data", Method: "GET", Status: 200, Duration: 100 * time.Millisecond, Cached: false},
		{Timestamp: now.Add(50 * time.Millisecond), URL: "/api/users", Method: "GET", Status: 200, Duration: 50 * time.Millisecond, Cached: true},
	}

	result := analyzer.AnalyzeNetworkPatterns(requests)

	t.Logf("Network analysis: IsHuman=%v, Confidence=%.2f, CacheRatio=%.2f",
		result.IsHuman, result.Confidence, result.CacheRatio)
}
