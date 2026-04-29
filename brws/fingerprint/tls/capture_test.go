package tlsfprint

import (
	"testing"
	"time"
)

func TestCompleteFingerprint(t *testing.T) {
	fp := &CompleteFingerprint{
		TraceID:         "test-123",
		Timestamp:       time.Now(),
		JA3:             "771,47-53-192-47",
		JA4:             "t12d0005h2e1267",
		DetectedBrowser: "chrome",
		Confidence:      0.85,
		Metadata:        map[string]string{"source": "test"},
	}

	if fp.TraceID != "test-123" {
		t.Errorf("expected trace ID test-123, got %s", fp.TraceID)
	}

	if fp.DetectedBrowser != "chrome" {
		t.Errorf("expected chrome, got %s", fp.DetectedBrowser)
	}

	if fp.Confidence != 0.85 {
		t.Errorf("expected 0.85, got %f", fp.Confidence)
	}

	if fp.Metadata["source"] != "test" {
		t.Errorf("expected metadata source test, got %s", fp.Metadata["source"])
	}
}

func TestFingerprintBuilder(t *testing.T) {
	fp := NewFingerprint().
		WithTLS(&TLSFingerprint{
			Version: "TLS 1.2",
			JA3:     "771,47-53",
			JA4:     "t12d0005h2e1267",
		}).
		WithHTTP1(&HTTP1Fingerprint{
			Headers: map[string]string{"user-agent": "Chrome/120"},
			JA3H1:   "test-ja3h1",
		}).
		WithDetectedBrowser("chrome").
		WithConfidence(0.9).
		WithMetadata("source", "test").
		Build()

	if fp.TLS == nil {
		t.Error("expected TLS to be set")
	}

	if fp.TLS.JA3 != "771,47-53" {
		t.Errorf("expected JA3 771,47-53, got %s", fp.TLS.JA3)
	}

	if fp.HTTP1 == nil {
		t.Error("expected HTTP1 to be set")
	}

	if fp.HTTP1.JA3H1 != "test-ja3h1" {
		t.Errorf("expected JA3H1 test-ja3h1, got %s", fp.HTTP1.JA3H1)
	}

	if fp.DetectedBrowser != "chrome" {
		t.Errorf("expected chrome, got %s", fp.DetectedBrowser)
	}

	if fp.Confidence != 0.7 {
		t.Errorf("expected 0.9, got %f", fp.Confidence)
	}

	if fp.Metadata["source"] != "test" {
		t.Errorf("expected test, got %s", fp.Metadata["source"])
	}
}

func TestFingerprintBuilderEmpty(t *testing.T) {
	fp := NewFingerprint().Build()

	if fp.TraceID == "" {
		t.Error("expected trace ID to be generated")
	}

	if fp.Timestamp.IsZero() {
		t.Error("expected timestamp to be set")
	}

	if fp.DetectedBrowser != "unknown" {
		t.Errorf("expected unknown, got %s", fp.DetectedBrowser)
	}

	if fp.Confidence != 0.0 {
		t.Errorf("expected 0.0, got %f", fp.Confidence)
	}
}

func TestFingerprintBuilderWithHTTP2(t *testing.T) {
	fp := NewFingerprint().
		WithHTTP2(&HTTP2Fingerprint{
			Settings: map[uint16]uint32{1: 4096, 3: 100},
			JA3H2:    "test-ja3h2",
		}).
		Build()

	if fp.HTTP2 == nil {
		t.Error("expected HTTP2 to be set")
	}

	if fp.JA3H2 != "test-ja3h2" {
		t.Errorf("expected JA3H2 test-ja3h2, got %s", fp.JA3H2)
	}
}

func TestFingerprintBuilderWithWebSocket(t *testing.T) {
	fp := NewFingerprint().
		WithWebSocket(&WSFingerprint{
			Version: "13",
			JA3W:    "test-ja3w",
		}).
		Build()

	if fp.WebSocket == nil {
		t.Error("expected WebSocket to be set")
	}

	if fp.JA3W != "test-ja3w" {
		t.Errorf("expected JA3W test-ja3w, got %s", fp.JA3W)
	}
}

func TestFingerprintBuilderWithBehavioral(t *testing.T) {
	fp := NewFingerprint().
		WithBehavioral(&BehavioralPrint{
			MouseVariance:  100.5,
			TypingSpeed:    200.0,
			ScrollVelocity: 500.0,
			CacheRatio:     0.3,
			IsHumanLike:    true,
		}).
		Build()

	if fp.Behavioral == nil {
		t.Error("expected Behavioral to be set")
	}

	if fp.Behavioral.MouseVariance != 100.5 {
		t.Errorf("expected 100.5, got %f", fp.Behavioral.MouseVariance)
	}

	if !fp.Behavioral.IsHumanLike {
		t.Error("expected IsHumanLike to be true")
	}
}

func TestFingerprintCapture(t *testing.T) {
	capture := NewFingerprintCapture()

	traceID := capture.CaptureTLS(&ClientHelloInfo{
		Version:    0x0303,
		VersionStr: "TLS 1.2",
		SNI:        "example.com",
		JA3:        "771,47-53",
		JA4:        "t12d0005h2e1267",
	})

	if traceID == "" {
		t.Error("expected non-empty trace ID")
	}

	capture.CaptureHTTP1(map[string]string{
		"user-agent": "Chrome/120",
		"accept":     "text/html",
	})

	capture.CaptureHTTP2(map[uint16]uint32{1: 4096, 3: 100}, []string{":method", ":path"})

	capture.CaptureWebSocket(map[string]string{
		"user-agent": "Chrome/120",
	})

	fp := capture.GetFingerprint()

	if fp.TLS == nil {
		t.Error("expected TLS to be captured")
	}

	if fp.TLS.SNI != "example.com" {
		t.Errorf("expected SNI example.com, got %s", fp.TLS.SNI)
	}

	if fp.HTTP1 == nil {
		t.Error("expected HTTP1 to be captured")
	}
}

func TestFingerprintCaptureGetAnalyzers(t *testing.T) {
	capture := NewFingerprintCapture()

	tlsAnalyzer := capture.GetTLSAnalyzer()
	if tlsAnalyzer == nil {
		t.Error("expected TLS analyzer")
	}

	http1Analyzer := capture.GetHTTP1Analyzer()
	if http1Analyzer == nil {
		t.Error("expected HTTP1 analyzer")
	}

	http2Analyzer := capture.GetHTTP2Analyzer()
	if http2Analyzer == nil {
		t.Error("expected HTTP2 analyzer")
	}

	wsAnalyzer := capture.GetWebSocketAnalyzer()
	if wsAnalyzer == nil {
		t.Error("expected WebSocket analyzer")
	}
}

func TestFingerprintCaptureReset(t *testing.T) {
	capture := NewFingerprintCapture()

	capture.CaptureTLS(&ClientHelloInfo{Version: 0x0303})
	capture.CaptureHTTP1(map[string]string{"user-agent": "test"})

	capture.Reset()

	fp := capture.GetFingerprint()
	if fp.TLS != nil {
		t.Error("expected TLS to be nil after reset")
	}

	if fp.HTTP1 != nil {
		t.Error("expected HTTP1 to be nil after reset")
	}
}

func TestFingerprintExporter(t *testing.T) {
	exporter := NewFingerprintExporter()

	exporter.Add(&CompleteFingerprint{
		TraceID:         "test-1",
		Timestamp:       time.Now(),
		JA3:             "771,47-53",
		DetectedBrowser: "chrome",
		Confidence:      0.9,
	})

	exporter.Add(&CompleteFingerprint{
		TraceID:         "test-2",
		Timestamp:       time.Now(),
		JA3:             "771,47-53-192",
		DetectedBrowser: "firefox",
		Confidence:      0.8,
	})

	json, err := exporter.ToJSON()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if json == "" {
		t.Error("expected non-empty JSON")
	}

	t.Logf("JSON: %s", json[:min(200, len(json))])
}

func TestFingerprintExporterToCSV(t *testing.T) {
	exporter := NewFingerprintExporter()

	exporter.Add(&CompleteFingerprint{
		TraceID:         "test-1",
		Timestamp:       time.Now(),
		JA3:             "771,47-53",
		JA4:             "t12d0005h2e1267",
		DetectedBrowser: "chrome",
		Confidence:      0.9,
	})

	exporter.Add(&CompleteFingerprint{
		TraceID:         "test-2",
		Timestamp:       time.Now(),
		JA3:             "771,47-53-192",
		JA4:             "t12d0005h2e9999",
		DetectedBrowser: "firefox",
		Confidence:      0.8,
	})

	csv := exporter.ToCSV()

	if csv == "" {
		t.Error("expected non-empty CSV")
	}

	lines := splitLines(csv)
	// Filter out empty lines (CSV has trailing newline)
	nonEmpty := 0
	for _, line := range lines {
		if len(line) > 0 {
			nonEmpty++
		}
	}
	if nonEmpty != 3 {
		t.Errorf("expected 3 non-empty lines (header + 2 data), got %d", nonEmpty)
	}

	t.Logf("CSV:\n%s", csv)
}

func TestFingerprintFilter(t *testing.T) {
	fps := []*CompleteFingerprint{
		{TraceID: "1", DetectedBrowser: "chrome", Confidence: 0.9, Timestamp: time.Now()},
		{TraceID: "2", DetectedBrowser: "firefox", Confidence: 0.7, Timestamp: time.Now()},
		{TraceID: "3", DetectedBrowser: "chrome", Confidence: 0.5, Timestamp: time.Now()},
		{TraceID: "4", DetectedBrowser: "safari", Confidence: 0.95, Timestamp: time.Now()},
	}

	filtered := NewFingerprintFilter().
		WithMinConfidence(0.6).
		Filter(fps)

	if len(filtered) != 3 {
		t.Errorf("expected 3 filtered, got %d", len(filtered))
	}
}

func TestFingerprintFilterByBrowser(t *testing.T) {
	fps := []*CompleteFingerprint{
		{TraceID: "1", DetectedBrowser: "chrome", Confidence: 0.9},
		{TraceID: "2", DetectedBrowser: "firefox", Confidence: 0.8},
		{TraceID: "3", DetectedBrowser: "chrome", Confidence: 0.7},
	}

	filtered := NewFingerprintFilter().
		WithBrowsers("chrome").
		Filter(fps)

	if len(filtered) != 2 {
		t.Errorf("expected 2 filtered, got %d", len(filtered))
	}

	for _, fp := range filtered {
		if fp.DetectedBrowser != "chrome" {
			t.Errorf("expected chrome, got %s", fp.DetectedBrowser)
		}
	}
}

func TestFingerprintFilterByTimeRange(t *testing.T) {
	now := time.Now()
	fps := []*CompleteFingerprint{
		{TraceID: "1", Timestamp: now.Add(-2 * time.Hour)},
		{TraceID: "2", Timestamp: now.Add(-1 * time.Hour)},
		{TraceID: "3", Timestamp: now},
		{TraceID: "4", Timestamp: now.Add(1 * time.Hour)},
	}

	// Filter for last 30 minutes (should include only trace 3 = now)
	filtered := NewFingerprintFilter().
		WithTimeRange(now.Add(-30*time.Minute), now.Add(30*time.Minute)).
		Filter(fps)

	// Should include trace 3 (now)
	if len(filtered) != 1 {
		t.Errorf("expected 1 filtered, got %d", len(filtered))
	}
}

func TestFingerprintFilterChain(t *testing.T) {
	fps := []*CompleteFingerprint{
		{TraceID: "1", DetectedBrowser: "chrome", Confidence: 0.95, Timestamp: time.Now()},
		{TraceID: "2", DetectedBrowser: "firefox", Confidence: 0.85, Timestamp: time.Now()},
		{TraceID: "3", DetectedBrowser: "chrome", Confidence: 0.5, Timestamp: time.Now()},
	}

	filtered := NewFingerprintFilter().
		WithMinConfidence(0.7).
		WithBrowsers("chrome").
		Filter(fps)

	if len(filtered) != 1 {
		t.Errorf("expected 1 filtered, got %d", len(filtered))
	}

	if filtered[0].TraceID != "1" {
		t.Errorf("expected trace ID 1, got %s", filtered[0].TraceID)
	}
}

func TestCompareFingerprints(t *testing.T) {
	fp1 := &CompleteFingerprint{
		TLS:             &TLSFingerprint{JA3: "771,47-53", JA4: "t12d0005h2e1267", Version: "TLS 1.2"},
		HTTP1:           &HTTP1Fingerprint{JA3H1: "test1"},
		DetectedBrowser: "chrome",
	}

	fp2 := &CompleteFingerprint{
		TLS:             &TLSFingerprint{JA3: "771,47-53", JA4: "t12d0005h2e1267", Version: "TLS 1.2"},
		HTTP1:           &HTTP1Fingerprint{JA3H1: "test1"},
		DetectedBrowser: "chrome",
	}

	comp := CompareFingerprints(fp1, fp2)

	if !comp.IsMatch(0.7) {
		t.Error("expected match with threshold 0.7")
	}

	if comp.MatchDetails["ja3"] != 1.0 {
		t.Errorf("expected ja3 match 1.0, got %f", comp.MatchDetails["ja3"])
	}
}

func TestCompareFingerprintsNoMatch(t *testing.T) {
	fp1 := &CompleteFingerprint{
		TLS:             &TLSFingerprint{JA3: "771,47-53", JA4: "t12d0005h2e1267"},
		DetectedBrowser: "chrome",
	}

	fp2 := &CompleteFingerprint{
		TLS:             &TLSFingerprint{JA3: "771,99-99", JA4: "t99d9999h9e9999"},
		DetectedBrowser: "firefox",
	}

	comp := CompareFingerprints(fp1, fp2)

	if comp.IsMatch(0.7) {
		t.Error("expected no match with threshold 0.7")
	}

	if comp.MatchDetails["ja3"] != 0 {
		t.Errorf("expected ja3 match 0, got %f", comp.MatchDetails["ja3"])
	}
}

func TestCompareFingerprintsPartial(t *testing.T) {
	fp1 := &CompleteFingerprint{
		TLS:             &TLSFingerprint{JA3: "771,47-53", JA4: "t12d0005h2e1267"},
		DetectedBrowser: "chrome",
	}

	fp2 := &CompleteFingerprint{
		TLS:             &TLSFingerprint{JA3: "771,47-53", JA4: "different"},
		DetectedBrowser: "firefox",
	}

	comp := CompareFingerprints(fp1, fp2)

	t.Logf("Similarity: %f, MatchDetails: %v", comp.Similarity, comp.MatchDetails)

	if comp.MatchDetails["ja3"] != 1.0 {
		t.Errorf("expected ja3 match 1.0, got %f", comp.MatchDetails["ja3"])
	}

	if comp.MatchDetails["ja4"] != 0 {
		t.Errorf("expected ja4 match 0, got %f", comp.MatchDetails["ja4"])
	}
}

func TestTLSFingerprint(t *testing.T) {
	tls := &TLSFingerprint{
		Version:          "TLS 1.2",
		CipherSuites:     []uint16{0x002f, 0x0035, 0x009c},
		CipherSuiteNames: []string{"AES128", "AES256", "GCM"},
		Extensions:       []uint16{0x0, 0xa, 0xd},
		ALPN:             []string{"h2", "http/1.1"},
		SNI:              "example.com",
		SessionID:        "abc123",
		JA3:              "771,47-53-192",
		JA4:              "t12d0005h2e1267",
		HasGREASE:        true,
		IsTLS13:          false,
	}

	if tls.Version != "TLS 1.2" {
		t.Errorf("expected TLS 1.2, got %s", tls.Version)
	}

	if len(tls.CipherSuites) != 3 {
		t.Errorf("expected 3 cipher suites, got %d", len(tls.CipherSuites))
	}

	if !tls.HasGREASE {
		t.Error("expected GREASE to be true")
	}

	if tls.IsTLS13 {
		t.Error("expected TLS13 to be false")
	}
}

func TestWSFingerprint(t *testing.T) {
	ws := &WSFingerprint{
		Version:         "13",
		SubProtocols:    []string{"soap", "wamp"},
		Extensions:      []string{"permessage-deflate"},
		Origin:          "https://example.com",
		SecWebSocketKey: "dGhlIHNhbXBsZSBub25jZQ==",
		JA3W:            "test-ja3w",
	}

	if ws.Version != "13" {
		t.Errorf("expected version 13, got %s", ws.Version)
	}

	if len(ws.SubProtocols) != 2 {
		t.Errorf("expected 2 subprotocols, got %d", len(ws.SubProtocols))
	}

	if ws.Origin != "https://example.com" {
		t.Errorf("expected origin https://example.com, got %s", ws.Origin)
	}
}

func TestBehavioralPrint(t *testing.T) {
	bp := &BehavioralPrint{
		MouseVariance:  150.5,
		TypingSpeed:    180.0,
		ScrollVelocity: 600.0,
		CacheRatio:     0.35,
		IsHumanLike:    true,
	}

	if bp.MouseVariance != 150.5 {
		t.Errorf("expected 150.5, got %f", bp.MouseVariance)
	}

	if !bp.IsHumanLike {
		t.Error("expected IsHumanLike to be true")
	}
}

func TestTimeRange(t *testing.T) {
	tr := &TimeRange{
		Start: time.Now().Add(-1 * time.Hour),
		End:   time.Now().Add(1 * time.Hour),
	}

	if tr.End.Before(tr.Start) {
		t.Error("expected End to be after Start")
	}
}

func TestFingerprintComparison(t *testing.T) {
	comp := &FingerprintComparison{
		Similarity:  0.85,
		Differences: []string{"JA4", "HTTP1"},
		MatchDetails: map[string]float64{
			"ja3":     1.0,
			"browser": 1.0,
		},
	}

	if !comp.IsMatch(0.7) {
		t.Error("expected match with 0.7 threshold")
	}

	if comp.IsMatch(0.9) {
		t.Error("expected no match with 0.9 threshold")
	}
}

//nolint:predeclared
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
