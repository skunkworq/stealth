package tlsfprint

import (
	"testing"
	"time"
)

type TLSClientScenario struct {
	Name         string
	Server       string
	TLSVersion   uint16
	CipherSuites []uint16
	SNI          string
	ALPN         []string
	Extensions   []uint16
}

func TestConsumerJourney_FingerprintHTTPSServer(t *testing.T) {
	scenarios := []TLSClientScenario{
		{
			Name:         "Chrome 120 Windows",
			Server:       "google.com",
			TLSVersion:   0x0303,
			CipherSuites: []uint16{0x1301, 0x1302, 0x1303, 0xcca8, 0xcca9, 0x002f, 0x0035},
			SNI:          "google.com",
			ALPN:         []string{"h2", "http/1.1"},
			Extensions:   []uint16{0, 5, 10, 11, 13, 16, 17, 23, 27, 35, 43, 45, 50, 51},
		},
		{
			Name:         "Firefox 120 macOS",
			Server:       "example.com",
			TLSVersion:   0x0303,
			CipherSuites: []uint16{0x1301, 0x1302, 0x1303, 0xcca9, 0x002f, 0x0035, 0x003c},
			SNI:          "example.com",
			ALPN:         []string{"h2", "http/1.1"},
			Extensions:   []uint16{0, 5, 10, 11, 13, 16, 23, 35, 43, 45, 51},
		},
	}

	analyzer := NewTLSAnalyzer()

	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			ch := &ClientHelloInfo{
				Version:        scenario.TLSVersion,
				VersionStr:     VersionToString(scenario.TLSVersion),
				CipherSuites:   scenario.CipherSuites,
				SNI:            scenario.SNI,
				ALPN:           scenario.ALPN,
				ExtensionsList: scenario.Extensions,
				GreaseDetected: hasGREASESuites(scenario.CipherSuites),
			}

			traceID := analyzer.RecordClientHello(ch)

			sh := &ServerHelloInfo{
				Version:     scenario.TLSVersion,
				VersionStr:  VersionToString(scenario.TLSVersion),
				CipherSuite: scenario.CipherSuites[0],
			}
			_ = analyzer.RecordServerHello(traceID, sh)

			handshake := analyzer.GetHandshake(traceID)
			if handshake == nil {
				t.Fatal("expected handshake to be found")
			}

			if handshake.ClientHello.SNI != scenario.SNI {
				t.Errorf("expected SNI %s, got %s", scenario.SNI, handshake.ClientHello.SNI)
			}
		})
	}

	summary := analyzer.GetSummary()
	t.Logf("Total handshakes: %d", summary.TotalHandshakes)
}

func TestConsumerJourney_MultiLayerFingerprintCapture(t *testing.T) {
	capture := NewFingerprintCapture()

	traceID := capture.CaptureTLS(&ClientHelloInfo{
		Version:        0x0303,
		VersionStr:     "TLS 1.2",
		SNI:            "api.example.com",
		JA3:            "771,47-53-192",
		JA4:            "t12d0005h2e1267",
		CipherSuites:   []uint16{0x002f, 0x0035},
		ExtensionsList: []uint16{0, 10, 11, 13, 16},
		ALPN:           []string{"h2"},
	})

	if traceID == "" {
		t.Fatal("expected trace ID")
	}

	capture.CaptureHTTP1(map[string]string{
		"user-agent":      "Mozilla/5.0 Chrome/120.0",
		"accept":          "text/html",
		"accept-language": "en-US",
	})

	capture.CaptureHTTP2(map[uint16]uint32{
		1: 4096, 3: 100, 4: 6291456,
	}, []string{":method", ":path"})

	capture.CaptureWebSocket(map[string]string{
		"user-agent": "Mozilla/5.0 Chrome/120.0",
	})

	fp := capture.GetFingerprint()

	if fp.TLS == nil {
		t.Error("expected TLS fingerprint")
	}

	if fp.TraceID != traceID {
		t.Errorf("expected trace ID to match, got different IDs")
	}

	t.Logf("Complete fingerprint captured: TLS=%s, HTTP1=%s", fp.JA3, fp.JA3H1)
}

func TestConsumerJourney_BehavioralAnalysis(t *testing.T) {
	analyzer := NewBehaviorProfileAnalyzer()
	generator := NewBehavioralGenerator(BehavioralSignatures["chrome-human"], 12345)

	typing := generator.GenerateTyping("Hello, world!")
	mouseMovements := generator.GenerateMouseMovement(2 * time.Second)
	scrolling := generator.GenerateScrolling(3 * time.Second)

	typingResult := analyzer.AnalyzeTyping(typing)
	mouseResult := analyzer.AnalyzeMouseMovement(mouseMovements)
	scrollResult := analyzer.AnalyzeScrolling(scrolling)

	t.Logf("Typing: human=%v, confidence=%.2f", typingResult.IsHuman, typingResult.Confidence)
	t.Logf("Mouse: human=%v, confidence=%.2f", mouseResult.IsHuman, mouseResult.Confidence)
	t.Logf("Scroll: human=%v, confidence=%.2f", scrollResult.IsHuman, scrollResult.Confidence)
}

func TestConsumerJourney_FingerprintComparison(t *testing.T) {
	fp1 := NewFingerprint().
		WithTLS(&TLSFingerprint{JA3: "771,47-53", JA4: "t12d0005", IsTLS13: false}).
		WithDetectedBrowser("chrome").
		Build()

	fp2 := NewFingerprint().
		WithTLS(&TLSFingerprint{JA3: "771,47-53", JA4: "t12d0005", IsTLS13: false}).
		WithDetectedBrowser("chrome").
		Build()

	comp := CompareFingerprints(fp1, fp2)

	if !comp.IsMatch(0.5) {
		t.Error("expected fingerprints to match")
	}

	t.Logf("Similarity: %.2f", comp.Similarity)
}

func TestConsumerJourney_FilterAndExport(t *testing.T) {
	now := time.Now()

	fingerprints := []*MultiProtocolCapture{
		{TraceID: "1", Timestamp: now, DetectedBrowser: "chrome", Confidence: 0.95},
		{TraceID: "2", Timestamp: now.Add(-1 * time.Hour), DetectedBrowser: "firefox", Confidence: 0.85},
		{TraceID: "3", Timestamp: now.Add(-2 * time.Hour), DetectedBrowser: "chrome", Confidence: 0.70},
	}

	highConfidence := NewFingerprintFilter().WithMinConfidence(0.8).Filter(fingerprints)

	if len(highConfidence) != 2 {
		t.Errorf("expected 2, got %d", len(highConfidence))
	}

	chromeOnly := NewFingerprintFilter().WithBrowsers("chrome").Filter(fingerprints)

	if len(chromeOnly) != 2 {
		t.Errorf("expected 2 chrome, got %d", len(chromeOnly))
	}

	exporter := NewFingerprintExporter()
	for _, fp := range highConfidence {
		exporter.Add(fp)
	}

	json, err := exporter.ToJSON()
	if err != nil {
		t.Fatalf("JSON export failed: %v", err)
	}

	if len(json) == 0 {
		t.Fatal("expected non-empty JSON")
	}

	t.Logf("Filtered: %d high confidence, %d chrome", len(highConfidence), len(chromeOnly))
}

func TestConsumerJourney_TLSAnalyzerWorkflow(t *testing.T) {
	analyzer := NewTLSAnalyzer()

	websites := []string{"google.com", "facebook.com", "github.com"}

	for _, site := range websites {
		ch := &ClientHelloInfo{
			Version:    0x0303,
			VersionStr: "TLS 1.2",
			SNI:        site,
		}

		traceID := analyzer.RecordClientHello(ch)

		sh := &ServerHelloInfo{Version: 0x0303, CipherSuite: 0xcca8}
		_ = analyzer.RecordServerHello(traceID, sh)
	}

	summary := analyzer.GetSummary()
	t.Logf("Summary: %+v", summary)

	recent := analyzer.GetRecentHandshakes(2)
	if len(recent) != 2 {
		t.Errorf("expected 2 recent, got %d", len(recent))
	}
}

func TestConsumerJourney_WebSocketAnalysis(t *testing.T) {
	analyzer := NewWebSocketAnalyzer()
	handshakeAnalyzer := NewWebSocketHandshakeAnalyzer()

	headers := map[string]string{
		"host":                  "echo.example.com",
		"origin":                "https://example.com",
		"connection":            "Upgrade",
		"upgrade":               "websocket",
		"sec-websocket-key":     "dGhlIHNhbXBsZSBub25jZQ==",
		"sec-websocket-version": "13",
		"user-agent":            "Mozilla/5.0 Chrome/120.0",
	}

	obs := analyzer.Record(headers)
	t.Logf("Browser: %s, JA3W: %s", obs.DetectedBrowser, obs.JA3W)

	valid := handshakeAnalyzer.Record("GET", "/ws", headers)
	t.Logf("Valid handshake: %v", valid.IsValid)

	dist := analyzer.GetBrowserDistribution()
	t.Logf("Browser distribution: %v", dist)
}

func TestConsumerJourney_JA4Generation(t *testing.T) {
	ch := &ClientHelloInfo{
		Version:        0x0304,
		VersionStr:     VersionToString(0x0304),
		CipherSuites:   []uint16{0x1301, 0x1302, 0x1303},
		ExtensionsList: []uint16{0, 43, 45, 50, 51},
		SNI:            "example.com",
		ALPN:           []string{"h3"},
	}

	spoofer := New()
	var alpnStr string
	if len(ch.ALPN) > 0 {
		alpnStr = ch.ALPN[0]
	}
	ja4 := spoofer.CalculateJA4(ch.Version, ch.CipherSuites[0], alpnStr, ch.ExtensionsList)
	ja3 := CalculateJA3FromParsed(VersionToString(ch.Version), ch.CipherSuites, ch.ExtensionsList, nil, nil, ch.ALPN)

	t.Logf("JA4: %s, JA3: %s", ja4, ja3)

	browser := DetectBrowserFromJA4(ja4)
	t.Logf("Detected: %s", browser)
}

func TestConsumerJourney_ConnectionTracking(t *testing.T) {
	tracker := NewConnectionStateTracker(100)

	tracker.AddConnection("conn-1", "1.1.1.1:443", "192.168.1.10:54321")
	tracker.UpdateTLS("conn-1", 0x0303, 0xcca8)
	tracker.MarkEstablished("conn-1", 50)
	tracker.IncrementRequests("conn-1")

	tracker.AddConnection("conn-2", "8.8.8.8:443", "192.168.1.10:54322")
	tracker.UpdateTLS("conn-2", 0x0304, 0x1301)
	tracker.MarkEstablished("conn-2", 40)

	active := tracker.GetActiveConnections()
	t.Logf("Active connections: %d", len(active))

	avgHandshake := tracker.GetAverageHandshakeTime()
	t.Logf("Average handshake: %dms", avgHandshake)
}

func TestConsumerJourney_TimeRangeFiltering(t *testing.T) {
	now := time.Now()

	fingerprints := make([]*MultiProtocolCapture, 0)
	for i := 0; i < 10; i++ {
		fp := &MultiProtocolCapture{
			TraceID:         "fp-" + string(rune('0'+i)),
			Timestamp:       now.Add(-time.Duration(i) * time.Hour),
			DetectedBrowser: []string{"chrome", "firefox", "safari"}[i%3],
		}
		fingerprints = append(fingerprints, fp)
	}

	lastHour := NewFingerprintFilter().
		WithTimeRange(now.Add(-1*time.Hour), now.Add(1*time.Hour)).
		Filter(fingerprints)

	t.Logf("Last hour: %d fingerprints", len(lastHour))
}

func TestConsumerJourney_OCSPAnalysis(t *testing.T) {
	analyzer := NewOCSPAnalyzer()

	analyzer.RecordStapling("good", time.Now().Unix(), time.Now().Add(24*time.Hour).Unix())
	analyzer.RecordStapling("good", time.Now().Unix(), time.Now().Add(24*time.Hour).Unix())
	analyzer.RecordStapling("revoked", time.Now().Unix(), time.Now().Add(24*time.Hour).Unix())

	ratio := analyzer.GetStaplingRatio()
	t.Logf("Stapling ratio: %.2f", ratio)
}

func TestConsumerJourney_TimingAnalysis(t *testing.T) {
	analyzer := NewHTTP2TimingAnalyzer()

	analyzer.RecordTLSHandshake(45)
	analyzer.RecordTLSHandshake(55)
	analyzer.RecordTLSHandshake(50)

	analyzer.RecordTTFB(120)
	analyzer.RecordTTFB(110)

	avgHS := analyzer.GetAverageHandshakeMs()
	avgTTFB := analyzer.GetAverageTTFB()

	t.Logf("Average TLS handshake: %dms", avgHS)
	t.Logf("Average TTFB: %dms", avgTTFB)
}

func TestConsumerJourney_ExportForML(t *testing.T) {
	exporter := NewFingerprintExporter()

	for i := 0; i < 20; i++ {
		fp := &MultiProtocolCapture{
			TraceID:    "ml-" + string(rune('0'+i%10)),
			Timestamp:  time.Now(),
			TLS:        &TLSFingerprint{JA3: "test"},
			Confidence: 0.5 + float64(i%5)*0.1,
			Metadata:   map[string]string{"source": "training"},
		}
		exporter.Add(fp)
	}

	json, err := exporter.ToJSON()
	if err != nil {
		t.Fatalf("JSON export failed: %v", err)
	}

	csv := exporter.ToCSV()

	t.Logf("ML data: %d samples, JSON: %d bytes", 20, len(json))
	t.Logf("CSV lines: %d", len(csv))
}
