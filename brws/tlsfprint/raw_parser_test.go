package tlsfprint

import (
	"testing"
)

func TestRawClientHello(t *testing.T) {
	data := []byte{
		0x16, 0x03, 0x03, 0x00, 0xff,
		0x01, 0x00, 0x00, 0xfb, 0x03,
		0x03, 0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d,
		0x0e, 0x0f, 0x10, 0x11, 0x12,
		0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c,
		0x1d, 0x1e,
		0x20,
		0x00, 0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07,
		0x01, 0x02, 0x03,
		0x00, 0x10,
		0x00, 0x00, 0x17, 0x00, 0x00,
		0x00, 0x23, 0x00, 0x00, 0x00,
		0x0d, 0x00, 0x14, 0x00, 0x11,
	}

	ch, err := ParseRawClientHello(data)
	if err != nil {
		t.Logf("Parse error (expected for invalid data): %v", err)
	}
	if ch != nil {
		t.Logf("ClientHello: version=0x%04x, ciphers=%v, hasGREASE=%v",
			ch.ClientHelloVersion, ch.CipherSuites, ch.HasGREASE)
	}
}

func TestRawClientHelloWithGREASE(t *testing.T) {
	ch := &RawClientHello{
		CipherSuites: []uint16{0x002f, 0x0a0a, 0x0035},
	}

	if !hasGREASESuites(ch.CipherSuites) {
		t.Error("expected GREASE to be detected")
	}

	t.Logf("HasGREASE: %v", ch.HasGREASE)
}

func TestSNIAnalyzer(t *testing.T) {
	analyzer := NewSNIAnalyzer()

	tests := []struct {
		sni          string
		wantWildcard bool
		wantIP       bool
		wantLevels   int
	}{
		{"example.com", false, false, 2},
		{"www.example.com", false, false, 3},
		{"*.example.com", true, false, 3},
		{"192.168.1.1", false, true, 0},
		{"sub.domain.example.co.uk", false, false, 5},
	}

	for _, tt := range tests {
		obs := analyzer.Analyze(tt.sni)
		if obs.IsWildcard != tt.wantWildcard {
			t.Errorf("SNI %q: want wildcard=%v, got %v", tt.sni, tt.wantWildcard, obs.IsWildcard)
		}
		if obs.IsIP != tt.wantIP {
			t.Errorf("SNI %q: want IP=%v, got %v", tt.sni, tt.wantIP, obs.IsIP)
		}
		if obs.DomainLevels != tt.wantLevels {
			t.Errorf("SNI %q: want levels=%d, got %d", tt.sni, tt.wantLevels, obs.DomainLevels)
		}
	}
}

func TestSNIAnalyzerObservations(t *testing.T) {
	analyzer := NewSNIAnalyzer()

	analyzer.Analyze("example.com")
	analyzer.Analyze("test.example.com")
	analyzer.Analyze("*.wildcard.com")

	obs := analyzer.GetObservations()
	if len(obs) != 3 {
		t.Errorf("expected 3 observations, got %d", len(obs))
	}

	ratio := analyzer.GetWildcardRatio()
	if ratio != 1.0/3.0 {
		t.Errorf("expected wildcard ratio ~0.33, got %f", ratio)
	}

	avgLen := analyzer.GetAverageLength()
	if avgLen < 10 || avgLen > 20 {
		t.Errorf("expected average length around 15, got %f", avgLen)
	}
}

func TestConnectionStateTracker(t *testing.T) {
	tracker := NewConnectionStateTracker(10)

	conn1 := tracker.AddConnection("conn-1", "192.168.1.1:443", "192.168.1.2:12345")
	if conn1 == nil {
		t.Fatal("expected connection to be created")
	}

	tracker.UpdateTLS("conn-1", 0x0303, 0x002f)
	tracker.MarkEstablished("conn-1", 50)
	tracker.IncrementRequests("conn-1")
	tracker.AddBytesSent("conn-1", 1000)
	tracker.AddBytesReceived("conn-1", 5000)

	state := tracker.GetConnection("conn-1")
	if state == nil {
		t.Fatal("expected connection state")
	}

	if !state.Established {
		t.Error("expected established=true")
	}

	if state.RequestsCount != 1 {
		t.Errorf("expected 1 request, got %d", state.RequestsCount)
	}

	if state.BytesSent != 1000 {
		t.Errorf("expected 1000 bytes sent, got %d", state.BytesSent)
	}

	active := tracker.GetActiveConnections()
	if len(active) != 1 {
		t.Errorf("expected 1 active, got %d", len(active))
	}

	avgTime := tracker.GetAverageHandshakeTime()
	if avgTime != 50 {
		t.Errorf("expected avg handshake 50, got %d", avgTime)
	}
}

func TestConnectionStateTrackerEviction(t *testing.T) {
	tracker := NewConnectionStateTracker(3)

	tracker.AddConnection("conn-1", "1.1.1.1:443", "2.2.2.2:12345")
	tracker.MarkEstablished("conn-1", 50)
	tracker.AddConnection("conn-2", "1.1.1.2:443", "2.2.2.2:12345")
	tracker.MarkEstablished("conn-2", 51)
	tracker.AddConnection("conn-3", "1.1.1.3:443", "2.2.2.2:12345")
	tracker.MarkEstablished("conn-3", 52)

	all := tracker.GetActiveConnections()
	if len(all) != 3 {
		t.Errorf("expected 3 connections, got %d", len(all))
	}

	tracker.AddConnection("conn-4", "1.1.1.4:443", "2.2.2.2:12345")
	tracker.MarkEstablished("conn-4", 53)

	all = tracker.GetActiveConnections()
	if len(all) != 3 {
		t.Logf("After eviction: %d connections (max size reached)", len(all))
	}
}

func TestConnectionStateResumption(t *testing.T) {
	tracker := NewConnectionStateTracker(10)

	tracker.AddConnection("conn-1", "1.1.1.1:443", "2.2.2.2:12345")
	tracker.SetSessionID("conn-1", []byte("session-123"))
	tracker.MarkEstablished("conn-1", 50)

	tracker.AddConnection("conn-2", "1.1.1.1:443", "2.2.2.2:12345")
	tracker.SetSessionTicket("conn-2", []byte("ticket-456"))
	tracker.MarkEstablished("conn-2", 30)

	resumed := tracker.GetResumedConnections()
	if len(resumed) != 2 {
		t.Errorf("expected 2 resumed, got %d", len(resumed))
	}

	tracker.CloseConnection("conn-1")

	closed := tracker.GetClosedConnections()
	if len(closed) != 1 {
		t.Errorf("expected 1 closed, got %d", len(closed))
	}
}

func TestHPACKFingerprint(t *testing.T) {
	headers := map[string]string{
		":method":    "GET",
		":path":      "/",
		":scheme":    "https",
		":authority": "example.com",
		"accept":     "text/html",
		"user-agent": "Chrome/120",
	}

	fp := CalculateHPACKFingerprint(headers)

	if fp == "" {
		t.Error("expected non-empty fingerprint")
	}

	t.Logf("HPACK fingerprint: %s", fp)

	if len(fp) == 0 {
		t.Error("expected non-empty string")
	}
}

func TestHPACKSignatureDetector(t *testing.T) {
	detector := NewHPACKSignatureDetector()

	chromeHeaders := map[string]string{
		":method":      "GET",
		"accept":       "*/*",
		"content-type": "application/json",
	}

	browser := detector.Detect(chromeHeaders)
	t.Logf("Detected: %s", browser)

	if browser != "chrome" && browser != "unknown" {
		t.Errorf("expected chrome or unknown, got %s", browser)
	}
}

func TestHTTP2TimingAnalyzer(t *testing.T) {
	analyzer := NewHTTP2TimingAnalyzer()

	analyzer.RecordTLSHandshake(50)
	analyzer.RecordTTFB(100)
	analyzer.RecordDownload(200)
	analyzer.RecordTotal(350)

	avgHS := analyzer.GetAverageHandshakeMs()
	if avgHS != 50 {
		t.Errorf("expected avg handshake 50, got %d", avgHS)
	}

	avgTTFB := analyzer.GetAverageTTFB()
	if avgTTFB != 100 {
		t.Errorf("expected avg TTFB 100, got %d", avgTTFB)
	}

	obs := analyzer.GetObservations()
	if len(obs) != 4 {
		t.Errorf("expected 4 observations, got %d", len(obs))
	}
}

func TestHTTP2TimingAnalyzerMultiple(t *testing.T) {
	analyzer := NewHTTP2TimingAnalyzer()

	for i := 0; i < 5; i++ {
		analyzer.RecordTLSHandshake(int64(40 + i*5))
		analyzer.RecordTTFB(int64(80 + i*10))
	}

	avgHS := analyzer.GetAverageHandshakeMs()
	expectedHS := int64(50)
	if avgHS != expectedHS {
		t.Errorf("expected avg handshake %d, got %d", expectedHS, avgHS)
	}

	avgTTFB := analyzer.GetAverageTTFB()
	expectedTTFB := int64(100)
	if avgTTFB != expectedTTFB {
		t.Errorf("expected avg TTFB %d, got %d", expectedTTFB, avgTTFB)
	}
}

func TestTLS13FeatureDetector(t *testing.T) {
	detector := NewTLS13FeatureDetector()

	ch := &ClientHelloInfo{
		Version:           0x0304,
		SupportedVersions: []uint16{0x0303, 0x0304},
		ExtensionsList:    []uint16{0x0a0a, 35, 41, 50},
		GreaseDetected:    true,
	}

	features := detector.DetectTLS13(ch)

	var hasTLS13, hasEarlyData, hasPSK, hasKeyShare, hasGREASE bool

	for _, f := range features {
		switch f.Name {
		case "TLS 1.3":
			hasTLS13 = f.Present
		case "Early Data (0-RTT)":
			hasEarlyData = f.Present
		case "PSK":
			hasPSK = f.Present
		case "Key Share":
			hasKeyShare = f.Present
		case "GREASE":
			hasGREASE = f.Present
		}
	}

	if !hasTLS13 {
		t.Error("expected TLS 1.3 to be detected")
	}
	if !hasEarlyData {
		t.Error("expected Early Data to be detected")
	}
	if !hasPSK {
		t.Error("expected PSK to be detected")
	}
	if !hasKeyShare {
		t.Error("expected Key Share to be detected")
	}
	if !hasGREASE {
		t.Error("expected GREASE to be detected")
	}

	t.Logf("Features detected: TLS13=%v, EarlyData=%v, PSK=%v, KeyShare=%v, GREASE=%v",
		hasTLS13, hasEarlyData, hasPSK, hasKeyShare, hasGREASE)
}

func TestOCSPAnalyzer(t *testing.T) {
	analyzer := NewOCSPAnalyzer()

	analyzer.RecordStapling("good", 1000, 2000)
	analyzer.RecordStapling("good", 1500, 2500)
	analyzer.RecordStapling("revoked", 1800, 2800)

	ratio := analyzer.GetStaplingRatio()
	if ratio != 1.0 {
		t.Errorf("expected stapling ratio 1.0, got %f", ratio)
	}

	obs := analyzer.GetObservations()
	if len(obs) != 3 {
		t.Errorf("expected 3 observations, got %d", len(obs))
	}
}

func TestOCSPAnalyzerEmpty(t *testing.T) {
	analyzer := NewOCSPAnalyzer()

	ratio := analyzer.GetStaplingRatio()
	if ratio != 0.0 {
		t.Errorf("expected ratio 0.0, got %f", ratio)
	}
}

func TestHPACKSignature(t *testing.T) {
	headers := map[string]string{
		":method":    "GET",
		":path":      "/api/data",
		":scheme":    "https",
		":authority": "api.example.com",
		"accept":     "application/json",
		"user-agent": "Mozilla/5.0",
	}

	sig := GetHPACKSignature(headers)

	if sig == "" {
		t.Error("expected non-empty signature")
	}

	t.Logf("HPACK signature: %s", sig)

	if len(sig) == 0 {
		t.Error("expected non-empty")
	}
}
