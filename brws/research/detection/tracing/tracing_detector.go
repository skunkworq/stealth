package tracing

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/skunkworq/stealth/brws/core/constants"
	"github.com/skunkworq/stealth/brws/core/detection"
)

// StealthDetector is an alias for detection.StealthDetector.
type StealthDetector = detection.StealthDetector

// TracingDetector wraps StealthDetector with detailed request tracing
type TracingDetector struct {
	*StealthDetector
}

// DetectionTrace contains detailed tracing information for detection results
type DetectionTrace struct {
	RequestID  string    `json:"request_id"`
	Timestamp  time.Time `json:"timestamp"`
	FinalScore float64   `json:"final_score"`
	IsBot      bool      `json:"is_bot"`
	IsStealth  bool      `json:"is_stealth"`

	AllChecks    []CheckResult `json:"all_checks"`
	FailedChecks []CheckResult `json:"failed_checks"`
	Warnings     []string      `json:"warnings"`

	RawHeaders map[string]string `json:"raw_headers"`
	Summary    string            `json:"summary"`
}

// CheckResult represents the result of a single detection check.
type CheckResult struct {
	CheckName string  `json:"check_name"`
	Category  string  `json:"category"`
	Passed    bool    `json:"passed"`
	Score     float64 `json:"score"`
	Details   string  `json:"details"`
	RawValue  string  `json:"raw_value"`
	Severity  string  `json:"severity"`
}

// NewTracingDetector creates a new tracing detector instance.
func NewTracingDetector() *TracingDetector {
	return &TracingDetector{
		StealthDetector: detection.NewStealthDetector(),
	}
}

// AnalyzeWithTrace performs detection analysis and returns a detailed trace.
func (td *TracingDetector) AnalyzeWithTrace(req *http.Request, tlsConn *tls.ConnectionState) *DetectionTrace {
	trace := &DetectionTrace{
		RequestID:    fmt.Sprintf("trace_%d", time.Now().UnixNano()),
		Timestamp:    time.Now(),
		AllChecks:    make([]CheckResult, 0),
		FailedChecks: make([]CheckResult, 0),
		Warnings:     make([]string, 0),
		RawHeaders:   make(map[string]string),
	}

	// Capture raw headers
	for k, v := range req.Header {
		if len(v) > 0 {
			trace.RequestID = k + ": " + v[0]
			trace.RawHeaders[k] = v[0]
		}
	}

	// Run all checks with detailed tracing

	// 1. TLS Fingerprint Check (if TLS available)
	trace.AllChecks = append(trace.AllChecks, td.traceTLSCheck(tlsConn)...)

	// 2. HTTP Header Checks
	trace.AllChecks = append(trace.AllChecks, td.traceHTTPHeaders(req)...)

	// 3. Navigator Checks
	trace.AllChecks = append(trace.AllChecks, td.traceNavigatorData(req)...)

	// 4. Canvas Checks
	trace.AllChecks = append(trace.AllChecks, td.traceCanvasData(req)...)

	// 5. Behavioral Checks
	trace.AllChecks = append(trace.AllChecks, td.traceBehavioralData(req)...)

	// 6. Timing Checks
	trace.AllChecks = append(trace.AllChecks, td.traceTimingData(req)...)

	// 7. Fingerprint Consistency Checks
	trace.AllChecks = append(trace.AllChecks, td.traceFingerprintConsistency(req)...)

	// Collect failed checks
	var totalScore float64
	for _, check := range trace.AllChecks {
		totalScore += check.Score
		if !check.Passed {
			trace.FailedChecks = append(trace.FailedChecks, check)
		}
	}

	// Calculate final score
	if len(trace.AllChecks) > 0 {
		trace.FinalScore = totalScore / float64(len(trace.AllChecks))
	}

	trace.IsBot = trace.FinalScore >= constants.DefaultThresholdBot
	trace.IsStealth = trace.FinalScore >= constants.DefaultThresholdSuspicious

	// Generate summary
	trace.Summary = td.generateSummary(trace)

	return trace
}

func (td *TracingDetector) traceHTTPHeaders(req *http.Request) []CheckResult {
	checks := []CheckResult{}

	ua := req.Header.Get("User-Agent")

	// Check 1: User-Agent presence
	checks = append(checks, CheckResult{
		CheckName: "User-Agent-Exists",
		Category:  "http",
		Passed:    ua != "",
		Details:   "User-Agent header must be present",
		RawValue:  ua,
		Severity:  "high",
	})
	if ua == "" {
		checks[len(checks)-1].Score = 0.5
	}

	// Check 2: Suspicious User-Agent
	suspiciousUA := []string{"python", "curl", "wget", "scrapy", "bot", "headless", "selenium"}
	isSuspicious := false
	for _, s := range suspiciousUA {
		if strings.Contains(strings.ToLower(ua), s) {
			isSuspicious = true
			break
		}
	}
	checks = append(checks, CheckResult{
		CheckName: "User-Agent-Clean",
		Category:  "http",
		Passed:    !isSuspicious,
		Details:   "User-Agent must not contain automation keywords",
		RawValue:  ua,
		Severity:  "critical",
	})
	if isSuspicious {
		checks[len(checks)-1].Score = 0.6
	}

	// Check 3: Accept header
	accept := req.Header.Get("Accept")
	checks = append(checks, CheckResult{
		CheckName: "Accept-Header",
		Category:  "http",
		Passed:    accept != "",
		Details:   "Accept header must be present",
		RawValue:  accept,
		Severity:  "medium",
	})
	if accept == "" {
		checks[len(checks)-1].Score = 0.2
	}

	// Check 4: Accept-Language header
	acceptLang := req.Header.Get("Accept-Language")
	checks = append(checks, CheckResult{
		CheckName: "Accept-Language-Header",
		Category:  "http",
		Passed:    acceptLang != "",
		Details:   "Accept-Language header must be present",
		RawValue:  acceptLang,
		Severity:  "medium",
	})
	if acceptLang == "" {
		checks[len(checks)-1].Score = 0.2
	}

	// Check 5: Client Hints present
	secChUa := req.Header.Get("Sec-Ch-Ua")
	secChPlatform := req.Header.Get("Sec-Ch-Ua-Platform")
	hasCH := secChUa != "" && secChPlatform != ""
	checks = append(checks, CheckResult{
		CheckName: "Client-Hints-Present",
		Category:  "http",
		Passed:    hasCH,
		Details:   "Sec-CH-UA headers must be present",
		RawValue:  fmt.Sprintf("Sec-Ch-Ua: %s, Sec-Ch-Ua-Platform: %s", secChUa, secChPlatform),
		Severity:  "high",
	})
	if !hasCH {
		checks[len(checks)-1].Score = 0.3
	}

	// Check 6: Client Hints consistency
	if hasCH {
		consistent := td.checkClientHintsConsistencyInternal(ua, secChUa, secChPlatform)
		checks = append(checks, CheckResult{
			CheckName: "Client-Hints-Consistency",
			Category:  "http",
			Passed:    consistent,
			Details:   "Sec-Ch-Ua must match User-Agent platform",
			RawValue:  fmt.Sprintf("UA: %s, Platform: %s", ua, secChPlatform),
			Severity:  "critical",
		})
		if !consistent {
			checks[len(checks)-1].Score = 0.5
		}
	}

	// Check 7: Header count
	headerCount := len(req.Header)
	checks = append(checks, CheckResult{
		CheckName: "Header-Count",
		Category:  "http",
		Passed:    headerCount >= 8,
		Details:   "At least 8 headers required",
		RawValue:  fmt.Sprintf("%d", headerCount),
		Severity:  "medium",
	})
	if headerCount < 8 {
		checks[len(checks)-1].Score = 0.2
	}

	return checks
}

func (td *TracingDetector) checkClientHintsConsistencyInternal(ua, secChUa, secChPlatform string) bool {
	uaLower := strings.ToLower(ua)
	platformLower := strings.ToLower(secChPlatform)

	if strings.Contains(uaLower, "windows") && !strings.Contains(platformLower, "windows") {
		return false
	}
	if strings.Contains(uaLower, "mac") && !strings.Contains(platformLower, "mac") {
		return false
	}
	if strings.Contains(uaLower, "linux") && !strings.Contains(platformLower, "linux") {
		return false
	}
	if strings.Contains(secChUa, "Not_A Brand") && strings.Contains(platformLower, "linux") {
		return false
	}
	return true
}

func (td *TracingDetector) traceNavigatorData(req *http.Request) []CheckResult {
	checks := []CheckResult{}

	navHeader := req.Header.Get(constants.HeaderNavigatorData)
	if navHeader == "" {
		// ABSENCE of this header is GOOD - real browsers don't send it
		checks = append(checks, CheckResult{
			CheckName: "Navigator-Data-Injected",
			Category:  "navigator",
			Passed:    true, // GOOD - no injection
			Details:   "No " + constants.HeaderNavigatorData + " header (real browser)",
			RawValue:  "",
			Severity:  "info",
		})
		checks[len(checks)-1].Score = 0
		return checks
	}

	var navData map[string]interface{}
	if err := json.Unmarshal([]byte(navHeader), &navData); err != nil {
		checks = append(checks, CheckResult{
			CheckName: "Navigator-Data-JSON",
			Category:  "navigator",
			Passed:    false,
			Details:   constants.HeaderNavigatorData + " is not valid JSON",
			RawValue:  navHeader[:minInt(100, len(navHeader))],
			Severity:  "high",
		})
		checks[len(checks)-1].Score = 0.4
		return checks
	}

	// Check webdriver
	if webdriver, ok := navData["webdriver"].(bool); ok && webdriver {
		checks = append(checks, CheckResult{
			CheckName: "Navigator-Webdriver",
			Category:  "navigator",
			Passed:    false,
			Details:   "navigator.webdriver is true (automation detected)",
			RawValue:  "true",
			Severity:  "critical",
		})
		checks[len(checks)-1].Score = 0.8
	}

	// Check for missing chrome
	if _, ok := navData["chrome"]; !ok {
		checks = append(checks, CheckResult{
			CheckName: "Navigator-Chrome-Runtime",
			Category:  "navigator",
			Passed:    false,
			Details:   "chrome.runtime is missing (suspicious)",
			RawValue:  "missing",
			Severity:  "high",
		})
		checks[len(checks)-1].Score = 0.4
	}

	// Check plugins
	if plugins, ok := navData["plugins"].([]interface{}); ok && len(plugins) == 0 {
		checks = append(checks, CheckResult{
			CheckName: "Navigator-Plugins",
			Category:  "navigator",
			Passed:    false,
			Details:   "plugins array is empty (unusual for real browser)",
			RawValue:  "[]",
			Severity:  "medium",
		})
		checks[len(checks)-1].Score = 0.3
	}

	// Check automation patterns
	automationPatterns := []string{"__webdriver_script_fn__", "__selenium_unwrapped", "callSelenium", "selenium", "puppeteer"}
	for _, pattern := range automationPatterns {
		if _, ok := navData[pattern]; ok {
			checks = append(checks, CheckResult{
				CheckName: "Navigator-Automation-Pattern",
				Category:  "navigator",
				Passed:    false,
				Details:   fmt.Sprintf("Found automation pattern: %s", pattern),
				RawValue:  pattern,
				Severity:  "critical",
			})
			checks[len(checks)-1].Score = 0.9
		}
	}

	// Check property count
	propCount := len(navData)
	if propCount < 10 {
		checks = append(checks, CheckResult{
			CheckName: "Navigator-Property-Count",
			Category:  "navigator",
			Passed:    false,
			Details:   fmt.Sprintf("Too few navigator properties: %d (real browser has 15+)", propCount),
			RawValue:  fmt.Sprintf("%d", propCount),
			Severity:  "medium",
		})
		checks[len(checks)-1].Score = 0.3
	}

	return checks
}

func (td *TracingDetector) traceCanvasData(req *http.Request) []CheckResult {
	checks := []CheckResult{}

	canvasHeader := req.Header.Get(constants.HeaderCanvasFingerprint)
	if canvasHeader == "" {
		return checks
	}

	// Check for randomization
	if strings.Contains(canvasHeader, "randomized") || strings.Contains(canvasHeader, "noise") {
		checks = append(checks, CheckResult{
			CheckName: "Canvas-Randomization",
			Category:  "canvas",
			Passed:    false,
			Details:   "Canvas fingerprint has randomization/noise (stealth mode detected)",
			RawValue:  canvasHeader[:minInt(100, len(canvasHeader))],
			Severity:  "critical",
		})
		checks[len(checks)-1].Score = 0.6
	}

	// Check for constant hash (suspicious)
	if strings.Contains(canvasHeader, "hash:") {
		checks = append(checks, CheckResult{
			CheckName: "Canvas-Hash",
			Category:  "canvas",
			Passed:    false,
			Details:   "Canvas hash detected (fingerprinting detected)",
			RawValue:  canvasHeader[:minInt(50, len(canvasHeader))],
			Severity:  "medium",
		})
		checks[len(checks)-1].Score = 0.3
	}

	// Check for software renderer
	if strings.Contains(canvasHeader, "swiftshader") || strings.Contains(canvasHeader, "llvmpipe") {
		checks = append(checks, CheckResult{
			CheckName: "Canvas-Software-Renderer",
			Category:  "canvas",
			Passed:    false,
			Details:   "Software renderer detected (often used in headless)",
			RawValue:  canvasHeader,
			Severity:  "medium",
		})
		checks[len(checks)-1].Score = 0.4
	}

	return checks
}

func (td *TracingDetector) traceBehavioralData(req *http.Request) []CheckResult {
	checks := []CheckResult{}

	behavHeader := req.Header.Get(constants.HeaderBehavioralData)
	if behavHeader == "" {
		return checks
	}

	var behav map[string]interface{}
	if err := json.Unmarshal([]byte(behavHeader), &behav); err != nil {
		return checks
	}

	// Check mouse variance
	if v, ok := behav["mouseStdDev"].(float64); ok && v == 0 {
		checks = append(checks, CheckResult{
			CheckName: "Behavioral-Mouse-Variance",
			Category:  "behavioral",
			Passed:    false,
			Details:   "Zero mouse movement variance (mechanical/automation)",
			RawValue:  "0.0",
			Severity:  "critical",
		})
		checks[len(checks)-1].Score = 0.6
	}

	// Check typing variance
	if v, ok := behav["typingStdDev"].(float64); ok && v == 0 {
		checks = append(checks, CheckResult{
			CheckName: "Behavioral-Typing-Variance",
			Category:  "behavioral",
			Passed:    false,
			Details:   "Zero typing variance (mechanical typing)",
			RawValue:  "0.0",
			Severity:  "critical",
		})
		checks[len(checks)-1].Score = 0.5
	}

	// Check mouse straightness
	if v, ok := behav["mouseStraightness"].(float64); ok && v > 0.95 {
		checks = append(checks, CheckResult{
			CheckName: "Behavioral-Mouse-Linearity",
			Category:  "behavioral",
			Passed:    false,
			Details:   fmt.Sprintf("Perfectly linear mouse movement (%.2f)", v),
			RawValue:  fmt.Sprintf("%f", v),
			Severity:  "critical",
		})
		checks[len(checks)-1].Score = 0.5
	}

	// Check event count
	if v, ok := behav["mouseEvents"].(float64); ok && v < 3 {
		checks = append(checks, CheckResult{
			CheckName: "Behavioral-Mouse-Count",
			Category:  "behavioral",
			Passed:    false,
			Details:   fmt.Sprintf("Too few mouse events: %d", int(v)),
			RawValue:  fmt.Sprintf("%d", int(v)),
			Severity:  "medium",
		})
		checks[len(checks)-1].Score = 0.3
	}

	return checks
}

func (td *TracingDetector) traceTimingData(req *http.Request) []CheckResult {
	checks := []CheckResult{}

	timingHeader := req.Header.Get(constants.HeaderTimingData)
	if timingHeader == "" {
		return checks
	}

	var timing map[string]interface{}
	if err := json.Unmarshal([]byte(timingHeader), &timing); err != nil {
		return checks
	}

	// Check TTFB
	if v, ok := timing["ttfb"].(float64); ok && v == 0 {
		checks = append(checks, CheckResult{
			CheckName: "Timing-TTFB",
			Category:  "timing",
			Passed:    false,
			Details:   "Zero TTFB (suspicious)",
			RawValue:  "0",
			Severity:  "medium",
		})
		checks[len(checks)-1].Score = 0.3
	}

	// Check load time
	if navStart, ok := timing["navigationStart"].(float64); ok {
		if loadEnd, ok := timing["loadEventEnd"].(float64); ok && loadEnd > 0 {
			totalTime := loadEnd - navStart
			if totalTime < 50 {
				checks = append(checks, CheckResult{
					CheckName: "Timing-Load-Time",
					Category:  "timing",
					Passed:    false,
					Details:   fmt.Sprintf("Suspiciously fast load: %.0fms", totalTime),
					RawValue:  fmt.Sprintf("%f", totalTime),
					Severity:  "medium",
				})
				checks[len(checks)-1].Score = 0.3
			}
		}
	}

	return checks
}

func (td *TracingDetector) generateSummary(trace *DetectionTrace) string {
	var b strings.Builder
	_, _ = fmt.Fprintf(&b, "Detection Score: %.2f | ", trace.FinalScore)
	if trace.IsBot {
		b.WriteString("BLOCKED")
	} else if trace.IsStealth {
		b.WriteString("SUSPICIOUS")
	} else {
		b.WriteString("ALLOWED")
	}
	_, _ = fmt.Fprintf(&b, "\nFailed Checks (%d):\n", len(trace.FailedChecks))
	for i, check := range trace.FailedChecks {
		_, _ = fmt.Fprintf(&b, "  %d. [%s] %s: %s\n", i+1, check.Severity, check.CheckName, check.Details)
	}
	return b.String()
}

// PrintTrace prints a detailed detection trace to stdout.
func (td *TracingDetector) PrintTrace(trace *DetectionTrace) {
	_, _ = fmt.Fprintln(os.Stdout, "\n"+strings.Repeat("=", 60))
	_, _ = fmt.Fprintln(os.Stdout, "DETAILED DETECTION TRACE")
	_, _ = fmt.Fprintln(os.Stdout, strings.Repeat("=", 60))
	_, _ = fmt.Fprintf(os.Stdout, "Request ID: %s\n", trace.RequestID)
	_, _ = fmt.Fprintf(os.Stdout, "Timestamp: %s\n", trace.Timestamp.Format(time.RFC3339))
	_, _ = fmt.Fprintf(os.Stdout, "\nFinal Score: %.2f\n", trace.FinalScore)
	_, _ = fmt.Fprintf(os.Stdout, "Decision: ")
	if trace.IsBot {
		_, _ = fmt.Fprintln(os.Stdout, "🚫 BLOCKED (Bot detected)")
	} else if trace.IsStealth {
		_, _ = fmt.Fprintln(os.Stdout, "⚠️  SUSPICIOUS (Possible automation)")
	} else {
		_, _ = fmt.Fprintln(os.Stdout, "✅ ALLOWED")
	}

	_, _ = fmt.Fprintln(os.Stdout, "\n"+strings.Repeat("-", 60))
	_, _ = fmt.Fprintln(os.Stdout, "ALL CHECKS:")
	_, _ = fmt.Fprintln(os.Stdout, strings.Repeat("-", 60))
	for _, check := range trace.AllChecks {
		status := "✅"
		if !check.Passed {
			status = "❌"
		}
		_, _ = fmt.Fprintf(os.Stdout, "%s [%s] %s\n", status, check.Category, check.CheckName)
		_, _ = fmt.Fprintf(os.Stdout, "    Details: %s\n", check.Details)
		if check.RawValue != "" {
			_, _ = fmt.Fprintf(os.Stdout, "    Raw: %s\n", check.RawValue)
		}
		_, _ = fmt.Fprintf(os.Stdout, "    Score: +%.2f\n", check.Score)
	}

	if len(trace.FailedChecks) > 0 {
		_, _ = fmt.Fprintln(os.Stdout, "\n"+strings.Repeat("!", 60))
		_, _ = fmt.Fprintln(os.Stdout, "FAILED CHECKS (Detection Reasons):")
		_, _ = fmt.Fprintln(os.Stdout, strings.Repeat("!", 60))
		for i, check := range trace.FailedChecks {
			_, _ = fmt.Fprintf(os.Stdout, "\n%d. [%s] %s\n", i+1, check.Severity, check.CheckName)
			_, _ = fmt.Fprintf(os.Stdout, "   Reason: %s\n", check.Details)
			_, _ = fmt.Fprintf(os.Stdout, "   This added %.2f to the detection score\n", check.Score)
		}
	}

	_, _ = fmt.Fprintln(os.Stdout, "\n"+strings.Repeat("=", 60))
	_, _ = fmt.Fprintln(os.Stdout, "RAW HEADERS:")
	_, _ = fmt.Fprintln(os.Stdout, strings.Repeat("=", 60))
	for k, v := range trace.RawHeaders {
		_, _ = fmt.Fprintf(os.Stdout, "  %s: %s\n", k, v)
	}
	_, _ = fmt.Fprintln(os.Stdout)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (td *TracingDetector) traceTLSCheck(tlsConn *tls.ConnectionState) []CheckResult {
	checks := []CheckResult{}

	if tlsConn == nil {
		return checks
	}

	// TLS Version Check
	tlsVersion := fmt.Sprintf("0x%04x", tlsConn.Version)
	checks = append(checks, CheckResult{
		CheckName: "TLS-Version",
		Category:  "tls",
		Passed:    tlsConn.Version == tls.VersionTLS13,
		Details:   "TLS 1.3 is preferred",
		RawValue:  tlsVersion,
		Severity:  "medium",
	})
	if tlsConn.Version != tls.VersionTLS13 {
		checks[len(checks)-1].Score = 0.2
	}

	// Cipher Suite Check
	cipherSuite := fmt.Sprintf("0x%04x", tlsConn.CipherSuite)
	isStrongCipher := false
	strongCiphers := []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	}
	for _, c := range strongCiphers {
		if tlsConn.CipherSuite == c {
			isStrongCipher = true
			break
		}
	}
	checks = append(checks, CheckResult{
		CheckName: "TLS-Cipher",
		Category:  "tls",
		Passed:    isStrongCipher,
		Details:   "Strong cipher suite preferred",
		RawValue:  cipherSuite,
		Severity:  "low",
	})
	if !isStrongCipher {
		checks[len(checks)-1].Score = 0.1
	}

	// SNI Check
	sni := tlsConn.ServerName
	checks = append(checks, CheckResult{
		CheckName: "TLS-SNI",
		Category:  "tls",
		Passed:    sni != "",
		Details:   "Server Name Indication should be present",
		RawValue:  sni,
		Severity:  "medium",
	})
	if sni == "" {
		checks[len(checks)-1].Score = 0.1
	}

	return checks
}

func (td *TracingDetector) traceFingerprintConsistency(req *http.Request) []CheckResult {
	checks := []CheckResult{}

	ua := req.Header.Get("User-Agent")
	secChUa := req.Header.Get("Sec-Ch-Ua")
	secChPlatform := req.Header.Get("Sec-Ch-Ua-Platform")
	secChUaMobile := req.Header.Get("Sec-Ch-Ua-Mobile")

	// Check 1: Platform consistency across headers
	platformInUA := ""
	if strings.Contains(ua, "Windows") {
		platformInUA = "Windows"
	} else if strings.Contains(ua, "Mac") {
		platformInUA = "macOS"
	} else if strings.Contains(ua, "Linux") {
		platformInUA = "Linux"
	}

	platformInCH := strings.Trim(secChPlatform, "\"")

	checks = append(checks, CheckResult{
		CheckName: "Fingerprint-Platform-Consistency",
		Category:  "consistency",
		Passed:    platformInUA == "" || platformInCH == "" || strings.Contains(strings.ToLower(platformInCH), strings.ToLower(platformInUA)),
		Details:   "Platform in User-Agent should match Sec-CH-UA-Platform",
		RawValue:  fmt.Sprintf("UA: %s, CH: %s", platformInUA, platformInCH),
		Severity:  "high",
	})
	if platformInUA != "" && platformInCH != "" && !strings.Contains(strings.ToLower(platformInCH), strings.ToLower(platformInUA)) {
		checks[len(checks)-1].Score = 0.5
	}

	// Check 2: Complete Client Hints
	chComplete := secChUa != "" && secChPlatform != "" && secChUaMobile != ""
	checks = append(checks, CheckResult{
		CheckName: "Fingerprint-ClientHints-Complete",
		Category:  "consistency",
		Passed:    chComplete,
		Details:   "All Client Hints should be present for fingerprinting",
		RawValue:  fmt.Sprintf("CH: %v, Platform: %v, Mobile: %v", secChUa != "", secChPlatform != "", secChUaMobile != ""),
		Severity:  "medium",
	})
	if !chComplete {
		checks[len(checks)-1].Score = 0.2
	}

	// Check 3: Header diversity
	headerCount := len(req.Header)
	checks = append(checks, CheckResult{
		CheckName: "Fingerprint-Header-Diversity",
		Category:  "consistency",
		Passed:    headerCount >= 10,
		Details:   "Real browsers send many headers",
		RawValue:  fmt.Sprintf("%d headers", headerCount),
		Severity:  "low",
	})
	if headerCount < 10 {
		checks[len(checks)-1].Score = 0.1
	}

	// Check 4: Accept header variety
	accept := req.Header.Get("Accept")
	hasQValues := strings.Contains(accept, "q=")
	checks = append(checks, CheckResult{
		CheckName: "Fingerprint-Accept-Quality",
		Category:  "consistency",
		Passed:    hasQValues || accept == "",
		Details:   "Accept header should either have quality values or be absent",
		RawValue:  accept,
		Severity:  "low",
	})
	if accept != "" && !hasQValues && !strings.Contains(accept, "*/*") {
		checks[len(checks)-1].Score = 0.1
	}

	return checks
}
