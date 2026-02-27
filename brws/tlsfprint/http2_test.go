package tlsfprint

import (
	"testing"
)

func TestCalculateHTTP2Fingerprint(t *testing.T) {
	settings := map[uint16]uint32{
		1: 4096,
		3: 100,
		4: 6291456,
		5: 100,
		6: 16,
		7: 256,
	}
	pseudoHeaders := []string{":method", ":path", ":authority", ":scheme"}

	fp := CalculateHTTP2Fingerprint(settings, pseudoHeaders)

	if fp == "" {
		t.Error("expected non-empty fingerprint")
	}

	t.Logf("HTTP/2 Fingerprint: %s", fp)
}

func TestCalculateJA3H2(t *testing.T) {
	settings := map[uint16]uint32{
		1: 4096,
		3: 100,
		4: 6291456,
		5: 100,
		6: 16,
		7: 256,
	}
	pseudoHeaders := []string{":method", ":path", ":authority", ":scheme"}

	ja3h2 := CalculateJA3H2(settings, pseudoHeaders)

	if ja3h2 == "" {
		t.Error("expected non-empty JA3H2")
	}

	if len(ja3h2) != 32 {
		t.Errorf("expected JA3H2 length 32, got %d", len(ja3h2))
	}

	t.Logf("JA3H2: %s", ja3h2)
}

func TestHTTP2Signatures(t *testing.T) {
	for name, sig := range HTTP2Signatures {
		t.Run(name, func(t *testing.T) {
			if sig.Name == "" {
				t.Error("expected non-empty name")
			}
			if sig.Platform == "" {
				t.Error("expected non-empty platform")
			}
			if sig.Settings == nil {
				t.Error("expected non-nil settings")
			}
			if len(sig.Settings) == 0 {
				t.Error("expected non-empty settings")
			}

			ja3h2 := CalculateJA3H2(sig.Settings, sig.PseudoHeaders)
			t.Logf("%s JA3H2: %s", name, ja3h2)
		})
	}
}

func TestDetectBrowserFromHTTP2(t *testing.T) {
	chromeSettings := map[uint16]uint32{
		1: 4096, 3: 100, 4: 6291456, 5: 100, 6: 16, 7: 256,
	}
	chromePseudo := []string{":method", ":path", ":authority", ":scheme"}

	browser := DetectBrowserFromHTTP2(chromeSettings, chromePseudo)
	t.Logf("Detected browser: %s", browser)

	firefoxSettings := map[uint16]uint32{
		1: 131072, 3: 200, 4: 65792, 5: 100, 6: 16, 7: 30,
	}
	firefoxPseudo := []string{":method", ":scheme", ":authority", ":path"}

	browser = DetectBrowserFromHTTP2(firefoxSettings, firefoxPseudo)
	t.Logf("Detected browser: %s", browser)
}

func TestHTTP2Analyzer(t *testing.T) {
	analyzer := NewHTTP2Analyzer()

	settings := map[uint16]uint32{
		1: 4096, 3: 100, 4: 6291456, 5: 100, 6: 16, 7: 256,
	}
	pseudoHeaders := []string{":method", ":path", ":authority", ":scheme"}

	obs := analyzer.Record(settings, pseudoHeaders, 65535, 16384)

	if obs.JA3H2 == "" {
		t.Error("expected non-empty JA3H2 in observation")
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
	t.Logf("Browser distribution: %v", dist)
}

func TestHTTP2Permutator(t *testing.T) {
	perm := NewHTTP2Permutator(false, 0)

	headers := []string{"accept", "content-type", "user-agent", "cache-control"}
	permuted := perm.PermuteHeaderOrder(headers)

	if len(headers) != len(permuted) {
		t.Error("permuted headers should have same length")
	}

	randomPerm := NewHTTP2Permutator(true, 12345)
	permuted = randomPerm.PermuteHeaderOrder(headers)
	t.Logf("Permuted headers: %v", permuted)
}

func TestHTTP2SignatureChrome120(t *testing.T) {
	sig := HTTP2Signatures["chrome-120-windows"]
	if sig == nil {
		t.Fatal("expected chrome-120-windows signature")
	}

	if sig.InitialWindowSize != 65535 {
		t.Errorf("expected window size 65535, got %d", sig.InitialWindowSize)
	}

	if sig.MaxFrameSize != 16384 {
		t.Errorf("expected frame size 16384, got %d", sig.MaxFrameSize)
	}

	expectedPseudo := []string{":method", ":path", ":authority", ":scheme"}
	if len(sig.PseudoHeaders) != len(expectedPseudo) {
		t.Errorf("expected %d pseudo headers, got %d", len(expectedPseudo), len(sig.PseudoHeaders))
	}

	t.Logf("Chrome 120 Windows signature: settings=%v, pseudo=%v", sig.Settings, sig.PseudoHeaders)
}

func TestHTTP2SignatureFirefox(t *testing.T) {
	sig := HTTP2Signatures["firefox-120-windows"]
	if sig == nil {
		t.Fatal("expected firefox-120-windows signature")
	}

	if sig.InitialWindowSize != 131072 {
		t.Errorf("expected window size 131072, got %d", sig.InitialWindowSize)
	}

	if sig.Settings[1] != 131072 {
		t.Errorf("expected SETTINGS_HEADER_TABLE_SIZE 131072, got %d", sig.Settings[1])
	}

	t.Logf("Firefox 120 Windows signature: settings=%v", sig.Settings)
}

func TestHTTP2SignatureSafari(t *testing.T) {
	sig := HTTP2Signatures["safari-17-macos"]
	if sig == nil {
		t.Fatal("expected safari-17-macos signature")
	}

	if sig.InitialWindowSize != 65536 {
		t.Errorf("expected window size 65536, got %d", sig.InitialWindowSize)
	}

	expectedPseudo := []string{":method", ":path", ":scheme", ":authority"}
	if len(sig.PseudoHeaders) != len(expectedPseudo) {
		t.Errorf("expected %d pseudo headers, got %d", len(expectedPseudo), len(sig.PseudoHeaders))
	}

	t.Logf("Safari 17 macOS signature: pseudo_headers=%v", sig.PseudoHeaders)
}

func TestHTTP2FingerprintEquality(t *testing.T) {
	settings1 := map[uint16]uint32{1: 4096, 3: 100, 4: 6291456, 5: 100, 6: 16, 7: 256}
	settings2 := map[uint16]uint32{1: 4096, 3: 100, 4: 6291456, 5: 100, 6: 16, 7: 256}
	pseudo := []string{":method", ":path", ":authority", ":scheme"}

	fp1 := CalculateHTTP2Fingerprint(settings1, pseudo)
	fp2 := CalculateHTTP2Fingerprint(settings2, pseudo)

	if fp1 != fp2 {
		t.Errorf("expected equal fingerprints, got %s vs %s", fp1, fp2)
	}

	ja3h2_1 := CalculateJA3H2(settings1, pseudo)
	ja3h2_2 := CalculateJA3H2(settings2, pseudo)

	if ja3h2_1 != ja3h2_2 {
		t.Errorf("expected equal JA3H2, got %s vs %s", ja3h2_1, ja3h2_2)
	}

	t.Logf("Fingerprint: %s, JA3H2: %s", fp1, ja3h2_1)
}

func TestHTTP2FingerprintDifference(t *testing.T) {
	settings1 := map[uint16]uint32{1: 4096, 3: 100, 4: 6291456, 5: 100, 6: 16, 7: 256}
	settings2 := map[uint16]uint32{1: 131072, 3: 200, 4: 65792, 5: 100, 6: 16, 7: 30}
	pseudo := []string{":method", ":path", ":authority", ":scheme"}

	fp1 := CalculateHTTP2Fingerprint(settings1, pseudo)
	fp2 := CalculateHTTP2Fingerprint(settings2, pseudo)

	if fp1 == fp2 {
		t.Error("expected different fingerprints")
	}

	t.Logf("Chrome FP: %s", fp1)
	t.Logf("Firefox FP: %s", fp2)
}
