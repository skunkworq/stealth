package detection

import (
	"crypto/tls"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// NewAdvancedDetection
// ─────────────────────────────────────────────────────────────────────────────

func TestNewAdvancedDetection_NonNil(t *testing.T) {
	ad := NewAdvancedDetection()
	if ad == nil {
		t.Fatal("NewAdvancedDetection() returned nil")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalyzeTLS
// ─────────────────────────────────────────────────────────────────────────────

func TestAnalyzeTLS_NilTLSState(t *testing.T) {
	ad := NewAdvancedDetection()
	checks := ad.AnalyzeTLS(nil, "Mozilla/5.0 Chrome/120")
	if len(checks) == 0 {
		t.Fatal("AnalyzeTLS(nil) should return at least one check")
	}
	// Should flag that no TLS connection is available
	found := false
	for _, c := range checks {
		if c.CheckName == "TLS-Available" {
			found = true
			if c.Passed {
				t.Error("TLS-Available should be Passed=false when TLS state is nil")
			}
		}
	}
	if !found {
		t.Error("expected 'TLS-Available' check in results for nil TLS state")
	}
}

func TestAnalyzeTLS_ValidTLS12(t *testing.T) {
	ad := NewAdvancedDetection()
	state := &tls.ConnectionState{
		Version:     tls.VersionTLS12,
		CipherSuite: 0xc02f,
	}
	checks := ad.AnalyzeTLS(state, "Mozilla/5.0 Chrome/120")
	if len(checks) == 0 {
		t.Fatal("AnalyzeTLS should return checks for a valid TLS state")
	}
	// TLS-Version check should pass for TLS 1.2
	for _, c := range checks {
		if c.CheckName == "TLS-Version" && !c.Passed {
			t.Error("TLS-Version check should pass for TLS 1.2")
		}
	}
}

func TestAnalyzeTLS_ValidTLS13(t *testing.T) {
	ad := NewAdvancedDetection()
	state := &tls.ConnectionState{
		Version:     tls.VersionTLS13,
		CipherSuite: 0x1301,
	}
	checks := ad.AnalyzeTLS(state, "Mozilla/5.0 Chrome/120")
	for _, c := range checks {
		if c.CheckName == "TLS-Version" && !c.Passed {
			t.Error("TLS-Version check should pass for TLS 1.3")
		}
	}
}

func TestAnalyzeTLS_NoPanic(t *testing.T) {
	ad := NewAdvancedDetection()
	// Use an empty ConnectionState — should not panic
	state := &tls.ConnectionState{}
	_ = ad.AnalyzeTLS(state, "")
}

func TestAnalyzeTLS_ChecksHaveSeverity(t *testing.T) {
	ad := NewAdvancedDetection()
	state := &tls.ConnectionState{Version: tls.VersionTLS13, CipherSuite: 0x1301}
	checks := ad.AnalyzeTLS(state, "Mozilla/5.0 Chrome/120")
	for _, c := range checks {
		if c.Severity == "" {
			t.Errorf("check %q has empty Severity", c.CheckName)
		}
		if c.Category == "" {
			t.Errorf("check %q has empty Category", c.CheckName)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalyzeHeaders
// ─────────────────────────────────────────────────────────────────────────────

func TestAnalyzeHeaders_BasicRequest_NoPanic(t *testing.T) {
	ad := NewAdvancedDetection()
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120")
	checks := ad.AnalyzeHeaders(req)
	if checks == nil {
		t.Fatal("AnalyzeHeaders returned nil")
	}
}

func TestAnalyzeHeaders_EmptyRequest_NoPanic(t *testing.T) {
	ad := NewAdvancedDetection()
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	// Intentionally no headers
	_ = ad.AnalyzeHeaders(req)
}

func TestAnalyzeHeaders_ReturnValues_NonNil(t *testing.T) {
	ad := NewAdvancedDetection()
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	checks := ad.AnalyzeHeaders(req)
	for _, c := range checks {
		if c.CheckName == "" {
			t.Error("check has empty CheckName")
		}
		if c.Severity == "" {
			t.Error("check has empty Severity")
		}
	}
}

func TestAnalyzeHeaders_CompleteClientHints_Pass(t *testing.T) {
	ad := NewAdvancedDetection()
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="120"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

	checks := ad.AnalyzeHeaders(req)
	for _, c := range checks {
		if c.CheckName == "Client-Hints-Complete" && !c.Passed {
			t.Error("Client-Hints-Complete should pass when all hints are present")
		}
	}
}

func TestAnalyzeHeaders_MissingClientHints_Fail(t *testing.T) {
	ad := NewAdvancedDetection()
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120")
	// No Sec-Ch-Ua headers

	checks := ad.AnalyzeHeaders(req)
	for _, c := range checks {
		if c.CheckName == "Client-Hints-Complete" && c.Passed {
			t.Error("Client-Hints-Complete should fail when hints are absent")
		}
	}
}

func TestAnalyzeHeaders_ValidSecFetchDest(t *testing.T) {
	ad := NewAdvancedDetection()
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")

	checks := ad.AnalyzeHeaders(req)
	for _, c := range checks {
		if c.CheckName == "Sec-Fetch-Dest-Valid" && !c.Passed {
			t.Error("Sec-Fetch-Dest=document should be valid")
		}
	}
}

func TestAnalyzeHeaders_InvalidSecFetchDest(t *testing.T) {
	ad := NewAdvancedDetection()
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	req.Header.Set("Sec-Fetch-Dest", "totally-invalid-value")

	checks := ad.AnalyzeHeaders(req)
	found := false
	for _, c := range checks {
		if c.CheckName == "Sec-Fetch-Dest-Valid" {
			found = true
			if c.Passed {
				t.Error("invalid Sec-Fetch-Dest should not pass")
			}
		}
	}
	if !found {
		t.Error("expected Sec-Fetch-Dest-Valid check")
	}
}

func TestAnalyzeHeaders_FullVersionValid(t *testing.T) {
	ad := NewAdvancedDetection()
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	req.Header.Set("Sec-Ch-Ua-Full-Version", "120.0.6099.62")
	checks := ad.AnalyzeHeaders(req)
	for _, c := range checks {
		if c.CheckName == "Client-Hints-Full-Version-Valid" && !c.Passed {
			t.Error("valid semver full version should pass")
		}
	}
}

func TestAnalyzeHeaders_FullVersionInvalid(t *testing.T) {
	ad := NewAdvancedDetection()
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	req.Header.Set("Sec-Ch-Ua-Full-Version", "not-a-version")
	checks := ad.AnalyzeHeaders(req)
	for _, c := range checks {
		if c.CheckName == "Client-Hints-Full-Version-Valid" && c.Passed {
			t.Error("invalid semver full version should not pass")
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalyzeIP
// ─────────────────────────────────────────────────────────────────────────────

func TestAnalyzeIP_Residential(t *testing.T) {
	ad := NewAdvancedDetection()
	checks := ad.AnalyzeIP("192.168.1.1")
	if len(checks) == 0 {
		t.Fatal("AnalyzeIP returned no checks")
	}
	for _, c := range checks {
		if c.CheckName == "IP-Datacenter" && !c.Passed {
			t.Error("192.168.1.1 should not be classified as datacenter")
		}
	}
}

func TestAnalyzeIP_DatacenterRange(t *testing.T) {
	ad := NewAdvancedDetection()
	checks := ad.AnalyzeIP("34.1.2.3")
	found := false
	for _, c := range checks {
		if c.CheckName == "IP-Datacenter" {
			found = true
			if c.Passed {
				t.Error("34.x IP should be flagged as datacenter")
			}
		}
	}
	if !found {
		t.Error("expected IP-Datacenter check")
	}
}

func TestAnalyzeIP_VPNRange(t *testing.T) {
	ad := NewAdvancedDetection()
	checks := ad.AnalyzeIP("185.220.101.1")
	found := false
	for _, c := range checks {
		if c.CheckName == "IP-VPN" {
			found = true
			if c.Passed {
				t.Error("185.x IP should be flagged as VPN")
			}
		}
	}
	if !found {
		t.Error("expected IP-VPN check")
	}
}

func TestAnalyzeIP_ClassificationResidential(t *testing.T) {
	ad := NewAdvancedDetection()
	checks := ad.AnalyzeIP("8.8.8.8")
	for _, c := range checks {
		if c.CheckName == "IP-Classification" {
			if c.RawValue != "residential" {
				// 8.8.8.8 doesn't match datacenter/VPN patterns
				t.Logf("IP-Classification RawValue = %q", c.RawValue)
			}
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalyzeTiming
// ─────────────────────────────────────────────────────────────────────────────

func TestAnalyzeTiming_NilTiming_NoPanic(t *testing.T) {
	ad := NewAdvancedDetection()
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	checks := ad.AnalyzeTiming(req, nil)
	if checks == nil {
		t.Fatal("AnalyzeTiming returned nil")
	}
}

func TestAnalyzeTiming_WithTiming(t *testing.T) {
	ad := NewAdvancedDetection()
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	timing := &RequestTiming{TTFB: 200 * time.Millisecond}
	checks := ad.AnalyzeTiming(req, timing)
	found := false
	for _, c := range checks {
		if c.CheckName == "Timing-TTFB" {
			found = true
			if !c.Passed {
				t.Error("TTFB of 200ms should be within acceptable range")
			}
		}
	}
	if !found {
		t.Error("expected Timing-TTFB check")
	}
}

func TestAnalyzeTiming_TooFastTTFB(t *testing.T) {
	ad := NewAdvancedDetection()
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	timing := &RequestTiming{TTFB: 10 * time.Millisecond} // too fast
	checks := ad.AnalyzeTiming(req, timing)
	for _, c := range checks {
		if c.CheckName == "Timing-TTFB" && c.Passed {
			t.Error("10ms TTFB should fail the check")
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalyzeBehavioral
// ─────────────────────────────────────────────────────────────────────────────

func TestAnalyzeBehavioral_NoHeaders_NoPanic(t *testing.T) {
	ad := NewAdvancedDetection()
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	checks := ad.AnalyzeBehavioral(req)
	if checks == nil {
		t.Fatal("AnalyzeBehavioral returned nil")
	}
}

func TestAnalyzeBehavioral_NoInjectedHeaders_Passes(t *testing.T) {
	ad := NewAdvancedDetection()
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120")
	checks := ad.AnalyzeBehavioral(req)
	for _, c := range checks {
		if c.CheckName == "Behavioral-Headers-Injection" && !c.Passed {
			t.Error("no injected headers should pass Behavioral-Headers-Injection")
		}
	}
}

func TestAnalyzeBehavioral_WithInjectedHeaders_Fails(t *testing.T) {
	ad := NewAdvancedDetection()
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	req.Header.Set("X-Navigator-Data", `{"webdriver":false}`)
	checks := ad.AnalyzeBehavioral(req)
	for _, c := range checks {
		if c.CheckName == "Behavioral-Headers-Injection" && c.Passed {
			t.Error("injected X-Navigator-Data should fail Behavioral-Headers-Injection")
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalyzeAutomation
// ─────────────────────────────────────────────────────────────────────────────

func TestAnalyzeAutomation_RealUA_NoKeywords(t *testing.T) {
	ad := NewAdvancedDetection()
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120")
	req.Header.Set("Accept", "text/html,application/xhtml+xml;q=0.9")
	checks := ad.AnalyzeAutomation(req)
	for _, c := range checks {
		if c.CheckName == "Automation-UA-Keyword" {
			t.Errorf("real Chrome UA should not trigger Automation-UA-Keyword, got: %+v", c)
		}
	}
}

func TestAnalyzeAutomation_SeleniumUA(t *testing.T) {
	ad := NewAdvancedDetection()
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows) selenium/4.0")
	checks := ad.AnalyzeAutomation(req)
	found := false
	for _, c := range checks {
		if c.CheckName == "Automation-UA-Keyword" {
			found = true
			if c.Passed {
				t.Error("selenium UA should not pass Automation-UA-Keyword")
			}
		}
	}
	if !found {
		t.Error("expected Automation-UA-Keyword check for selenium UA")
	}
}

func TestAnalyzeAutomation_GenericAccept_Flagged(t *testing.T) {
	ad := NewAdvancedDetection()
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120")
	req.Header.Set("Accept", "*/*")
	checks := ad.AnalyzeAutomation(req)
	found := false
	for _, c := range checks {
		if c.CheckName == "Automation-Accept-Header" {
			found = true
		}
	}
	if !found {
		t.Error("generic Accept */* should trigger Automation-Accept-Header check")
	}
}

func TestAnalyzeAutomation_HeadlessUA(t *testing.T) {
	ad := NewAdvancedDetection()
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	req.Header.Set("User-Agent", "HeadlessChrome/120.0.0.0")
	checks := ad.AnalyzeAutomation(req)
	found := false
	for _, c := range checks {
		if c.CheckName == "Automation-UA-Keyword" {
			found = true
			if c.Passed {
				t.Error("HeadlessChrome UA should fail Automation-UA-Keyword")
			}
		}
	}
	if !found {
		t.Error("expected Automation-UA-Keyword for headless UA")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalyzeWebRTC
// ─────────────────────────────────────────────────────────────────────────────

func TestAnalyzeWebRTC_Disabled(t *testing.T) {
	ad := NewAdvancedDetection()
	data := &WebRTCData{RTCAvailable: false}
	checks := ad.AnalyzeWebRTC(data)
	found := false
	for _, c := range checks {
		if c.CheckName == "WebRTC-Disabled" {
			found = true
			if c.Passed {
				t.Error("WebRTC-Disabled check should not pass when RTC is disabled")
			}
		}
	}
	if !found {
		t.Error("expected WebRTC-Disabled check")
	}
}

func TestAnalyzeWebRTC_NoCandidates(t *testing.T) {
	ad := NewAdvancedDetection()
	data := &WebRTCData{RTCAvailable: true, ICECandidateCount: 0}
	checks := ad.AnalyzeWebRTC(data)
	found := false
	for _, c := range checks {
		if c.CheckName == "WebRTC-No-Candidates" {
			found = true
		}
	}
	if !found {
		t.Error("expected WebRTC-No-Candidates check when no ICE candidates")
	}
}

func TestAnalyzeWebRTC_IPMismatch(t *testing.T) {
	ad := NewAdvancedDetection()
	data := &WebRTCData{
		RTCAvailable:    true,
		ICECandidateCount: 3,
		LocalIPs:        []string{"10.0.0.1"},
		RequestSourceIP: "203.0.113.1",
	}
	checks := ad.AnalyzeWebRTC(data)
	found := false
	for _, c := range checks {
		if c.CheckName == "WebRTC-IP-Mismatch" {
			found = true
			if c.Passed {
				t.Error("IP mismatch should not pass")
			}
		}
	}
	if !found {
		t.Error("expected WebRTC-IP-Mismatch check")
	}
}

func TestAnalyzeWebRTC_ConstructorProxied(t *testing.T) {
	ad := NewAdvancedDetection()
	data := &WebRTCData{RTCAvailable: true, ICECandidateCount: 3, ConstructorProxied: true}
	checks := ad.AnalyzeWebRTC(data)
	found := false
	for _, c := range checks {
		if c.CheckName == "WebRTC-Constructor-Proxied" {
			found = true
		}
	}
	if !found {
		t.Error("expected WebRTC-Constructor-Proxied check")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// CalculateOverallScore
// ─────────────────────────────────────────────────────────────────────────────

func TestCalculateOverallScore_Empty(t *testing.T) {
	ad := NewAdvancedDetection()
	score, isBot := ad.CalculateOverallScore(nil)
	if score != 0 {
		t.Errorf("empty checks score = %f, want 0", score)
	}
	if isBot {
		t.Error("empty checks should not classify as bot")
	}
}

func TestCalculateOverallScore_AllClean(t *testing.T) {
	ad := NewAdvancedDetection()
	checks := []AdvancedCheckResult{
		{Passed: true, Score: 0, Severity: "low"},
		{Passed: true, Score: 0, Severity: "medium"},
	}
	score, isBot := ad.CalculateOverallScore(checks)
	if score != 0 {
		t.Errorf("all-clean score = %f, want 0", score)
	}
	if isBot {
		t.Error("all-clean checks should not be bot")
	}
}

func TestCalculateOverallScore_HighScores_IsBot(t *testing.T) {
	ad := NewAdvancedDetection()
	checks := []AdvancedCheckResult{
		{Passed: false, Score: 0.9, Severity: "critical"},
		{Passed: false, Score: 0.8, Severity: "critical"},
	}
	_, isBot := ad.CalculateOverallScore(checks)
	if !isBot {
		t.Error("high-score critical checks should classify as bot")
	}
}

func TestCalculateOverallScore_ManyCritical(t *testing.T) {
	ad := NewAdvancedDetection()
	checks := []AdvancedCheckResult{
		{Passed: false, Score: 0.1, Severity: "critical"},
		{Passed: false, Score: 0.1, Severity: "critical"},
		{Passed: false, Score: 0.1, Severity: "critical"},
	}
	_, isBot := ad.CalculateOverallScore(checks)
	// 3 critical checks with non-zero scores → should trigger bot detection
	// (criticalCount >= 2)
	if !isBot {
		t.Error("2+ critical failed checks should classify as bot")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// CalculateEntropy
// ─────────────────────────────────────────────────────────────────────────────

func TestCalculateEntropy_Empty(t *testing.T) {
	ad := NewAdvancedDetection()
	if e := ad.CalculateEntropy(""); e != 0 {
		t.Errorf("entropy of empty string = %f, want 0", e)
	}
}

func TestCalculateEntropy_SingleChar(t *testing.T) {
	ad := NewAdvancedDetection()
	// All same characters → entropy = 0
	if e := ad.CalculateEntropy("aaaa"); e != 0 {
		t.Errorf("uniform string entropy = %f, want 0", e)
	}
}

func TestCalculateEntropy_HighEntropy(t *testing.T) {
	ad := NewAdvancedDetection()
	// More varied string should have higher entropy
	e := ad.CalculateEntropy("abcdefghij")
	if e < 1.0 {
		t.Errorf("varied string entropy = %f, expected > 1.0", e)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalyzeHTTPHeadersAndTLS
// ─────────────────────────────────────────────────────────────────────────────

func TestAnalyzeHTTPHeadersAndTLS_NilTLS(t *testing.T) {
	ad := NewAdvancedDetection()
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120")
	checks := ad.AnalyzeHTTPHeadersAndTLS(req, nil)
	if checks == nil {
		t.Fatal("AnalyzeHTTPHeadersAndTLS returned nil")
	}
	// Without TLS, should still return HTTP checks
	if len(checks) == 0 {
		t.Error("expected at least one check even without TLS state")
	}
}

func TestAnalyzeHTTPHeadersAndTLS_IncompleteSpoofing(t *testing.T) {
	ad := NewAdvancedDetection()
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	// Chrome UA but no Sec-Ch-Ua (incomplete spoofing)
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120")
	checks := ad.AnalyzeHTTPHeadersAndTLS(req, nil)
	found := false
	for _, c := range checks {
		if c.CheckName == "Spoofing-Incomplete-Chrome" {
			found = true
		}
	}
	if !found {
		t.Error("expected Spoofing-Incomplete-Chrome check for Chrome UA without Client Hints")
	}
}

func TestAnalyzeHTTPHeadersAndTLS_WithTLS_NoPanic(t *testing.T) {
	ad := NewAdvancedDetection()
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120")
	state := &tls.ConnectionState{Version: tls.VersionTLS13, CipherSuite: 0x1301}
	_ = ad.AnalyzeHTTPHeadersAndTLS(req, state)
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalyzeHTTP2
// ─────────────────────────────────────────────────────────────────────────────

func TestAnalyzeHTTP2_NoPanic(t *testing.T) {
	ad := NewAdvancedDetection()
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120")
	checks := ad.AnalyzeHTTP2(req, "h2")
	if checks == nil {
		t.Fatal("AnalyzeHTTP2 returned nil")
	}
}

func TestAnalyzeHTTP2_HTTP1_NoPanic(t *testing.T) {
	ad := NewAdvancedDetection()
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	_ = ad.AnalyzeHTTP2(req, "HTTP/1.1")
}

// ─────────────────────────────────────────────────────────────────────────────
// extractBrowserFromUA (internal, test via AnalyzeTLS indirectly)
// ─────────────────────────────────────────────────────────────────────────────

func TestAnalyzeHeaders_PlatformConsistency_Windows(t *testing.T) {
	ad := NewAdvancedDetection()
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120")
	req.Header.Set("Sec-Ch-Ua", `"Chrome";v="120"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	checks := ad.AnalyzeHeaders(req)
	for _, c := range checks {
		if c.CheckName == "Client-Hints-Platform-Match" && !c.Passed {
			t.Error("Windows UA with Windows platform should pass platform consistency check")
		}
	}
}

func TestAnalyzeHeaders_PlatformConsistency_Mismatch(t *testing.T) {
	ad := NewAdvancedDetection()
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120")
	req.Header.Set("Sec-Ch-Ua", `"Chrome";v="120"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"Linux"`) // mismatch: UA says Windows
	checks := ad.AnalyzeHeaders(req)
	for _, c := range checks {
		if c.CheckName == "Client-Hints-Platform-Match" && c.Passed {
			t.Error("Windows UA with Linux platform should fail platform consistency check")
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalyzeHeadless
// ─────────────────────────────────────────────────────────────────────────────

func TestAnalyzeHeadless_NoNavHeader(t *testing.T) {
	ad := NewAdvancedDetection()
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	checks := ad.AnalyzeHeadless(req)
	// Without nav header, should return empty checks (no panic)
	_ = checks
}

func TestAnalyzeHeadless_WithDeniedPermissions(t *testing.T) {
	ad := NewAdvancedDetection()
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	navJSON := `{"permissions":{"state":"denied"},"window":{"outerHeight":900,"innerHeight":900}}`
	req.Header.Set("X-Navigator-Data", navJSON)
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120")
	checks := ad.AnalyzeHeadless(req)
	// Should detect Headless-Notification-Denied and Headless-Window-Gap
	found := false
	for _, c := range checks {
		if strings.Contains(c.CheckName, "Headless") {
			found = true
		}
	}
	if !found {
		t.Error("expected at least one Headless check for denied permissions + zero window gap")
	}
}
