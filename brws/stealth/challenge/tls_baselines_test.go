package challenge_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/skunkworq/stealth/brws/stealth/challenge"
	"github.com/skunkworq/stealth/brws/fingerprint/tls/parser"
	"github.com/skunkworq/stealth/brws/core/types"
)

// TestTLSDeepAnalysis_GoDefault verifies that Go's default TLS fingerprint
// is detected with high confidence by the deep TLS analyzer.
func TestTLSDeepAnalysis_GoDefault(t *testing.T) {
	goBaseline := challenge.GoDefaultBaseline()

	// Build a synthetic TLS fingerprint matching Go defaults
	fp := &types.TLSFingerprint{
		Version:     0x0303,
		VersionName: "TLS 1.2",
	}

	for i, c := range goBaseline.CipherSuiteOrder {
		fp.CipherSuites = append(fp.CipherSuites, types.CipherInfo{
			Value:    c,
			Name:     fmt.Sprintf("0x%04x", c),
			Position: i + 1,
		})
	}

	for i, e := range goBaseline.ExtensionOrder {
		fp.Extensions = append(fp.Extensions, types.ExtensionInfo{
			Type:     e,
			Name:     fmt.Sprintf("ext_%d", e),
			Position: i + 1,
		})
	}

	fp.ALPN = goBaseline.ALPN
	// Go does NOT use GREASE
	fp.GREASE = nil

	analysis := challenge.AnalyzeTLSDeep(fp, "chrome")
	t.Logf("Go Default Analysis:\n%s", challenge.FormatTLSAnalysis(analysis))

	if !analysis.IsGoTLS {
		t.Error("expected Go TLS to be detected as IsGoTLS")
	}
	if analysis.BotScore < 0.90 {
		t.Errorf("expected Go TLS bot score >= 0.90, got %.3f", analysis.BotScore)
	}
	if analysis.GREASEScore < 0.9 {
		t.Error("expected high GREASE score (no GREASE)")
	}
}

// TestTLSDeepAnalysis_Chrome146 verifies that a real Chrome 146 fingerprint
// captured from training data passes the deep TLS analyzer.
func TestTLSDeepAnalysis_Chrome146(t *testing.T) {
	baseline := challenge.Chrome146Baseline()

	// Build a synthetic fingerprint matching Chrome 146
	fp := buildFingerprintFromBaseline(baseline)

	analysis := challenge.AnalyzeTLSDeep(fp, "chrome")
	t.Logf("Chrome 146 Analysis:\n%s", challenge.FormatTLSAnalysis(analysis))

	if analysis.IsGoTLS {
		t.Error("Chrome 146 should NOT be detected as Go TLS")
	}
	if analysis.BotScore > 0.20 {
		t.Errorf("expected Chrome 146 bot score <= 0.20, got %.3f", analysis.BotScore)
	}
	if analysis.GREASEScore > 0 {
		t.Error("Chrome 146 should have GREASE (score 0)")
	}
	if analysis.MatchScore < 0.80 {
		t.Errorf("expected Chrome 146 match score >= 0.80, got %.3f", analysis.MatchScore)
	}
}

// TestTLSDeepAnalysis_Firefox128 verifies Firefox 128 fingerprint passes.
func TestTLSDeepAnalysis_Firefox128(t *testing.T) {
	baseline := challenge.Firefox128Baseline()
	fp := buildFingerprintFromBaseline(baseline)

	analysis := challenge.AnalyzeTLSDeep(fp, "firefox")
	t.Logf("Firefox 128 Analysis:\n%s", challenge.FormatTLSAnalysis(analysis))

	if analysis.IsGoTLS {
		t.Error("Firefox 128 should NOT be detected as Go TLS")
	}
	if analysis.BotScore > 0.20 {
		t.Errorf("expected Firefox 128 bot score <= 0.20, got %.3f", analysis.BotScore)
	}
}

// TestTLSDeepAnalysis_CapturedTrainingData parses the actual captured Chrome 146
// ClientHello from training-data/session-001 and validates it against baselines.
func TestTLSDeepAnalysis_CapturedTrainingData(t *testing.T) {
	captureFile := "../../training-data/session-001/capture_01_afterpay_com.json"
	data, err := os.ReadFile(captureFile)
	if err != nil {
		t.Skipf("training data not available: %v", err)
	}

	// The capture file structure: {tls_captures: [{tls: {...}, ...}, ...]}
	var capture struct {
		TLSCaptures []struct {
			TLS *types.TLSFingerprint `json:"tls"`
		} `json:"tls_captures"`
	}
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatalf("parse capture: %v", err)
	}

	if len(capture.TLSCaptures) == 0 {
		t.Skip("no TLS captures found in training data")
	}

	tlsFP := capture.TLSCaptures[0].TLS
	if tlsFP == nil {
		t.Skip("first TLS capture has no TLS data")
	}

	t.Logf("Captured TLS: JA3=%s JA4=%s ciphers=%d extensions=%d grease=%d",
		tlsFP.JA3Hash, tlsFP.JA4, len(tlsFP.CipherSuites), len(tlsFP.Extensions), len(tlsFP.GREASE))

	analysis := challenge.AnalyzeTLSDeep(tlsFP, "chrome")
	t.Logf("Training Data Analysis:\n%s", challenge.FormatTLSAnalysis(analysis))

	if analysis.IsGoTLS {
		t.Error("captured Chrome 146 should NOT be detected as Go TLS")
	}
	if analysis.BotScore > 0.25 {
		t.Errorf("expected captured Chrome bot score <= 0.25, got %.3f", analysis.BotScore)
	}

	// Compare against all baselines
	reports := challenge.CompareTLSToBaselines(tlsFP)
	for _, r := range reports {
		t.Logf("  vs %-15s cipher=%.0f%% ext=%.0f%% missing=%v extra=%v",
			r.Baseline, r.CipherSimilarity*100, r.ExtSimilarity*100, r.Missing, r.Extra)
	}
}

// TestTLSDeepAnalysis_RawClientHelloParse verifies we can parse a raw Chrome 146
// ClientHello from training data and match it against baselines.
func TestTLSDeepAnalysis_RawClientHelloParse(t *testing.T) {
	captureFile := "../../training-data/session-001/capture_01_afterpay_com.json"
	data, err := os.ReadFile(captureFile)
	if err != nil {
		t.Skipf("training data not available: %v", err)
	}

	// The capture file structure: {tls_captures: [{tls: {raw_client_hello: ...}}]}
	type tlsBlock struct {
		RawClientHello string `json:"raw_client_hello"`
		JA3Hash        string `json:"ja3_hash"`
		JA4            string `json:"ja4"`
	}
	type captureEntry struct {
		TLS tlsBlock `json:"tls"`
	}
	type captureBlock struct {
		TLSCaptures []captureEntry `json:"tls_captures"`
	}

	var cap captureBlock
	if err := json.Unmarshal(data, &cap); err != nil {
		t.Fatalf("parse: %v", err)
	}

	var rawHex string
	var expectedJA3, expectedJA4 string
	for _, entry := range cap.TLSCaptures {
		if entry.TLS.RawClientHello != "" {
			rawHex = entry.TLS.RawClientHello
			expectedJA3 = entry.TLS.JA3Hash
			expectedJA4 = entry.TLS.JA4
			break
		}
	}

	if rawHex == "" {
		t.Skip("no raw ClientHello found in training data")
	}

	rawBytes, err := hex.DecodeString(rawHex)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}

	ch, err := tlsparser.ParseClientHello(rawBytes)
	if err != nil {
		t.Fatalf("parse ClientHello: %v", err)
	}

	fp := ch.ToFingerprint()

	t.Logf("Parsed ClientHello: ciphers=%d extensions=%d grease=%d",
		len(fp.CipherSuites), len(fp.Extensions), len(fp.GREASE))
	t.Logf("JA3: %s (expected: %s)", fp.JA3Hash, expectedJA3)
	t.Logf("JA4: %s (expected: %s)", fp.JA4, expectedJA4)

	// Verify JA3/JA4 match captured values
	if expectedJA3 != "" && fp.JA3Hash != expectedJA3 {
		t.Errorf("JA3 mismatch: got %s, expected %s", fp.JA3Hash, expectedJA3)
	}
	if expectedJA4 != "" && fp.JA4 != expectedJA4 {
		t.Errorf("JA4 mismatch: got %s, expected %s", fp.JA4, expectedJA4)
	}

	// Run deep analysis
	analysis := challenge.AnalyzeTLSDeep(fp, "chrome")
	t.Logf("Parsed ClientHello Analysis:\n%s", challenge.FormatTLSAnalysis(analysis))

	if analysis.IsGoTLS {
		t.Error("parsed Chrome 146 ClientHello should NOT be detected as Go TLS")
	}
}

// TestTLSBaselineComparison runs comparison reports for all baselines.
func TestTLSBaselineComparison(t *testing.T) {
	baselines := []*challenge.TLSReferenceBaseline{
		challenge.Chrome146Baseline(),
		challenge.Firefox128Baseline(),
		challenge.GoDefaultBaseline(),
	}

	for _, bl := range baselines {
		t.Run(bl.Browser+"_"+bl.Version, func(t *testing.T) {
			fp := buildFingerprintFromBaseline(bl)
			analysis := challenge.AnalyzeTLSDeep(fp, bl.Browser)

			t.Logf("%-15s bot_score=%.3f match=%.3f is_go=%v indicators=%v",
				bl.Browser+"_"+bl.Version,
				analysis.BotScore, analysis.MatchScore,
				analysis.IsGoTLS, analysis.Indicators)

			reports := challenge.CompareTLSToBaselines(fp)
			for _, r := range reports {
				t.Logf("  vs %-15s cipher=%.0f%% ext=%.0f%%",
					r.Baseline, r.CipherSimilarity*100, r.ExtSimilarity*100)
			}
		})
	}
}

// TestTLSShieldIntegration verifies the AnalyzeRequestWithTLS method integrates
// deep TLS analysis with standard HTTP header analysis.
func TestTLSShieldIntegration(t *testing.T) {
	detector := challenge.NewStealthDetector()

	// Test 1: Go TLS + Chrome UA → should be detected
	t.Run("go_tls_chrome_ua", func(t *testing.T) {
		goFP := buildFingerprintFromBaseline(challenge.GoDefaultBaseline())

		req := buildChromeRequest("https://example.com")
		detection := detector.AnalyzeRequestWithTLS(req, goFP)

		t.Logf("Go TLS + Chrome UA: score=%.3f isBot=%v confidence=%.3f",
			detection.Score, detection.IsBot, detection.Confidence)
		for _, v := range detection.Vectors {
			if v.Score > 0 {
				t.Logf("  [%.3f] %s: %v", v.Score, v.Name, v.Indicators)
			}
		}

		if !detection.IsBot {
			t.Error("expected Go TLS + Chrome UA to be detected as bot")
		}
	})

	// Test 2: Chrome 146 TLS + Chrome UA → should pass
	t.Run("chrome_tls_chrome_ua", func(t *testing.T) {
		chromeFP := buildFingerprintFromBaseline(challenge.Chrome146Baseline())

		req := buildChromeRequest("https://example.com")
		detection := detector.AnalyzeRequestWithTLS(req, chromeFP)

		t.Logf("Chrome TLS + Chrome UA: score=%.3f isBot=%v confidence=%.3f",
			detection.Score, detection.IsBot, detection.Confidence)
		for _, v := range detection.Vectors {
			if v.Score > 0 {
				t.Logf("  [%.3f] %s: %v", v.Score, v.Name, v.Indicators)
			}
		}

		// TLS vector alone shouldn't flag Chrome as bot (HTTP vectors might)
		for _, v := range detection.Vectors {
			if v.Category == "tls" && v.Score > 0.20 {
				t.Errorf("expected Chrome TLS vector score <= 0.20, got %.3f", v.Score)
			}
		}
	})
}

// buildFingerprintFromBaseline constructs a types.TLSFingerprint from a baseline.
func buildFingerprintFromBaseline(bl *challenge.TLSReferenceBaseline) *types.TLSFingerprint {
	fp := &types.TLSFingerprint{
		Version:     0x0303,
		VersionName: "TLS 1.2",
		ALPN:        bl.ALPN,
	}

	// Add GREASE to ciphers if baseline has it
	if bl.HasGREASE {
		fp.CipherSuites = append(fp.CipherSuites, types.CipherInfo{
			Value:    0x5a5a,
			Name:     "GREASE",
			Position: 1,
			IsGREASE: true,
		})
		fp.GREASE = append(fp.GREASE, types.GREASEInfo{
			Value:   0x5a5a,
			Context: "cipher",
		})
	}

	for i, c := range bl.CipherSuiteOrder {
		pos := i + 1
		if bl.HasGREASE {
			pos = i + 2
		}
		fp.CipherSuites = append(fp.CipherSuites, types.CipherInfo{
			Value:    c,
			Name:     fmt.Sprintf("0x%04x", c),
			Position: pos,
		})
	}

	// Add GREASE to extensions
	if bl.HasGREASE {
		fp.Extensions = append(fp.Extensions, types.ExtensionInfo{
			Type:     0xeaea,
			Name:     "GREASE",
			Position: 1,
			IsGREASE: true,
		})
		fp.GREASE = append(fp.GREASE, types.GREASEInfo{
			Value:   0xeaea,
			Context: "extension",
		})
	}

	for i, e := range bl.ExtensionOrder {
		pos := i + 1
		if bl.HasGREASE {
			pos = i + 2
		}
		fp.Extensions = append(fp.Extensions, types.ExtensionInfo{
			Type:     e,
			Name:     fmt.Sprintf("ext_0x%04x", e),
			Position: pos,
		})
	}

	// Trailing GREASE extension
	if bl.HasGREASE {
		fp.Extensions = append(fp.Extensions, types.ExtensionInfo{
			Type:     0x5a5a,
			Name:     "GREASE",
			Position: len(fp.Extensions) + 1,
			IsGREASE: true,
		})
		fp.GREASE = append(fp.GREASE, types.GREASEInfo{
			Value:   0x5a5a,
			Context: "extension",
		})
	}

	fp.SupportedGroups = bl.SupportedGroups

	return fp
}

func buildChromeRequest(targetURL string) *http.Request {
	req, _ := http.NewRequest("GET", targetURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"macOS"`)
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("X-Stealth-Header-Order", "User-Agent,Accept,Accept-Language,Accept-Encoding,Sec-Fetch-Dest,Sec-Fetch-Mode,Sec-Fetch-Site,Sec-Fetch-User,Sec-Ch-Ua,Sec-Ch-Ua-Mobile,Sec-Ch-Ua-Platform,Upgrade-Insecure-Requests,Connection")
	return req
}
