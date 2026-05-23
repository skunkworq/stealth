package detection

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/skunkworq/stealth/brws/core/constants"
)

func (sd *StealthDetector) analyzeHTTPHeaders(req *http.Request) *HTTPFingerprintInfo {
	ua := req.Header.Get("User-Agent")
	accept := req.Header.Get("Accept")
	if ua == "" || accept == "" {
		// bot indicators
	}
	info := &HTTPFingerprintInfo{
		UserAgent:              ua,
		Accept:                 accept,
		AcceptLanguage:         req.Header.Get("Accept-Language"),
		AcceptEncoding:         req.Header.Get("Accept-Encoding"),
		SecCHUA:                req.Header.Get("Sec-Ch-Ua"),
		SecCHUAMobile:          req.Header.Get("Sec-Ch-Ua-Mobile"),
		SecCHUAPlatform:        req.Header.Get("Sec-Ch-Ua-Platform"),
		SecCHUAFullVersion:     req.Header.Get("Sec-Ch-Ua-Full-Version"),
		SecCHUAFullVersionList: req.Header.Get("Sec-Ch-Ua-Full-Version-List"),
		SecCHUAArch:            req.Header.Get("Sec-Ch-Ua-Arch"),
		SecCHUABitness:         req.Header.Get("Sec-Ch-Ua-Bitness"),
		SecCHUAModel:           req.Header.Get("Sec-Ch-Ua-Model"),
		SecFetchDest:           req.Header.Get("Sec-Fetch-Dest"),
		SecFetchMode:           req.Header.Get("Sec-Fetch-Mode"),
		SecFetchSite:           req.Header.Get("Sec-Fetch-Site"),
		SecFetchUser:           req.Header.Get("Sec-Fetch-User"),
		UpgradeInsecure:        req.Header.Get("Upgrade-Insecure-Requests"),
		HeaderCount:            len(req.Header),
		HeaderOrder:            make([]string, 0),
		MissingHeaders:         make([]string, 0),
		SuspiciousHeaders:      make([]string, 0),
	}

	// If a simulated header order is provided (used for testing/evasion simulation), use it.
	// Otherwise, use the map iteration order (which is a detection indicator for Go-based requests).
	if orderStr := req.Header.Get("X-Stealth-Header-Order"); orderStr != "" {
		info.HeaderOrder = strings.Split(orderStr, ",")
		// Remove the simulation header from the count and order to be clean
		info.HeaderCount--
	} else {
		for k := range req.Header {
			info.HeaderOrder = append(info.HeaderOrder, k)
		}
	}

	// Parse User-Agent
	if info.UserAgent != "" {
		info.Platform = extractPlatform(info.UserAgent)
		info.BrowserVersion = extractBrowserVersion(info.UserAgent)
	}

	// Check for suspicious User-Agent strings
	if info.UserAgent == "" {
		info.SuspiciousHeaders = append(info.SuspiciousHeaders, "missing_user_agent")
	} else {
		uaLower := strings.ToLower(info.UserAgent)
		suspiciousPatterns := []string{"curl", "wget", "python", "scrapy", "bot", "spider", "headless", "selenium", "automation", "phantomjs", "go-http-client"}
		for _, pat := range suspiciousPatterns {
			if strings.Contains(uaLower, pat) {
				info.SuspiciousHeaders = append(info.SuspiciousHeaders, fmt.Sprintf("suspicious_ua_%s", pat))
				break
			}
		}
	}

	// Check for missing headers
	requiredHeaders := []string{"Accept", "Accept-Language"}
	for _, h := range requiredHeaders {
		if req.Header.Get(h) == "" {
			info.MissingHeaders = append(info.MissingHeaders, h)
		}
	}

	// Check Accept header format — bots often use simple "*/*" or omit quality values
	if accept := info.Accept; accept != "" {
		if accept == "*/*" {
			info.SuspiciousHeaders = append(info.SuspiciousHeaders, "generic_accept_header")
		}
	}

	// Check header count — real browsers send 8+ headers
	if info.HeaderCount < 5 {
		info.SuspiciousHeaders = append(info.SuspiciousHeaders, "too_few_headers")
	}

	// Check Sec-Fetch-* headers — Chrome/Edge always send these on navigation
	isChromeUA := strings.Contains(strings.ToLower(info.UserAgent), "chrome")
	isFirefoxUA := strings.Contains(strings.ToLower(info.UserAgent), "firefox")
	if isChromeUA {
		if info.SecFetchDest == "" || info.SecFetchMode == "" || info.SecFetchSite == "" {
			info.MissingHeaders = append(info.MissingHeaders, "Sec-Fetch-*")
		}
	}

	// Check Client Hints consistency
	info.ClientHintsConsistent = sd.checkClientHintsConsistency(info)

	if !info.ClientHintsConsistent {
		info.SuspiciousHeaders = append(info.SuspiciousHeaders, "inconsistent_client_hints")
	}

	// Check for missing Client Hints (Chrome should always send these; Firefox never does)
	if isChromeUA && (info.SecCHUA == "" || info.SecCHUAPlatform == "") {
		info.MissingHeaders = append(info.MissingHeaders, "Sec-Ch-Ua*")
		if info.SecFetchDest == "document" && info.SecFetchMode == "navigate" {
			info.SuspiciousHeaders = append(info.SuspiciousHeaders, "chrome_navigation_missing_client_hints")
		}
	}

	// Check for webdriver header (simple boolean flag from stealth bypass tools)
	if req.Header.Get("X-Navigator-Webdriver") == "true" {
		info.SuspiciousHeaders = append(info.SuspiciousHeaders, "webdriver_exposed")
	}

	// Check for proxy/CDN IP identification headers in a browser request.
	// Real browsers NEVER send X-Forwarded-For, X-Real-IP, True-Client-IP,
	// CF-Connecting-IP, or X-Client-IP — these are added by reverse proxies,
	// CDNs, and load balancers. A request with a browser UA that also carries
	// these headers is either coming through infrastructure (in which case
	// a single header is normal) or is a spoofing tool stuffing multiple headers
	// to impersonate infrastructure context. Multiple IP headers is a strong
	// signal of synthetic generation.
	if isChromeUA || isFirefoxUA {
		ipSpoofHeaders := []string{"X-Forwarded-For", "X-Real-Ip", "X-Client-Ip", "True-Client-Ip", "Cf-Connecting-Ip"}
		ipHeaderCount := 0
		for _, h := range ipSpoofHeaders {
			if req.Header.Get(h) != "" {
				ipHeaderCount++
			}
		}
		if ipHeaderCount >= 3 {
			info.SuspiciousHeaders = append(info.SuspiciousHeaders, fmt.Sprintf("browser_with_multiple_proxy_ip_headers_%d", ipHeaderCount))
		}
	}

	// Firefox should not present Chromium-style request priority metadata on a
	// synthetic top-level HTTP/1.x navigation without deeper browser context.
	if isFirefoxUA && req.Header.Get("Priority") != "" &&
		info.SecFetchDest == "document" && info.SecFetchMode == "navigate" &&
		(req.ProtoMajor <= 1 || req.Proto == "") && !hasJSFingerprintHeaders(req) {
		info.SuspiciousHeaders = append(info.SuspiciousHeaders, "firefox_navigation_priority_header")
		if strings.Contains(req.Header.Get("Priority"), ", i") {
			info.SuspiciousHeaders = append(info.SuspiciousHeaders, "firefox_chromium_priority_signature")
		}
	}

	return info
}

func (sd *StealthDetector) httpInfoToVector(info *HTTPFingerprintInfo) DetectionVector {
	vec := DetectionVector{
		Name:        "HTTP Headers",
		Category:    "http",
		Weight:      constants.WeightHTTP,
		Description: "Analyzes HTTP headers for browser fingerprint consistency",
	}

	indicators := make([]string, 0)
	indicators = append(indicators, info.MissingHeaders...)
	indicators = append(indicators, info.SuspiciousHeaders...)
	vec.Indicators = indicators
	vec.CheckReports = make([]CheckReport, 0, len(indicators))

	// Score missing headers
	for _, missing := range info.MissingHeaders {
		weight := scoreForHTTPIndicator(missing)
		vec.Score += weight
		vec.CheckReports = append(vec.CheckReports, buildHTTPCheckReport(missing, weight, info))
	}

	// Score suspicious headers with severity-based weights
	for _, s := range info.SuspiciousHeaders {
		weight := scoreForHTTPIndicator(s)
		vec.Score += weight
		vec.CheckReports = append(vec.CheckReports, buildHTTPCheckReport(s, weight, info))
	}

	if vec.Score > 1.0 {
		vec.Score = 1.0
	}

	vec.Detected = vec.Score > 0.3

	return vec
}

func scoreForHTTPIndicator(indicator string) float64 {
	switch {
	case strings.HasPrefix(indicator, "suspicious_ua_"):
		return constants.SeverityHigh
	case indicator == "missing_user_agent":
		return constants.SeverityHigh
	case indicator == "webdriver_exposed":
		return constants.SeverityHigh
	case indicator == "chrome_navigation_missing_client_hints":
		return constants.SeverityHigh
	case indicator == "firefox_navigation_priority_header":
		return constants.SeverityHigh
	case indicator == "firefox_chromium_priority_signature":
		return constants.SeverityHigh
	case indicator == "Sec-Ch-Ua*":
		return constants.SeverityHigh
	case strings.HasPrefix(indicator, "browser_with_multiple_proxy_ip_headers"):
		return 0.40 // Stronger than SeverityHigh — 3+ proxy IP headers from a browser is definitive
	case indicator == "Sec-Fetch-*":
		return constants.SeverityMedium
	case indicator == "too_few_headers":
		return constants.SeverityMedium
	case indicator == "generic_accept_header":
		return constants.SeverityLow
	case indicator == "Accept":
		return constants.SeverityLow
	case indicator == "Accept-Language":
		return constants.SeverityLow
	default:
		return 0.2
	}
}

func buildHTTPCheckReport(indicator string, weight float64, info *HTTPFingerprintInfo) CheckReport {
	report := CheckReport{
		Name:        indicator,
		Fired:       true,
		Weight:      weight,
		Score:       weight,
		Severity:    severityFromScore(weight),
		Description: "HTTP fingerprint anomaly",
	}

	switch indicator {
	case "Accept":
		report.Field = "Accept"
		report.Actual = info.Accept
		report.Expected = "non-empty browser accept header"
		report.Description = "The request is missing the standard Accept header used by browsers."
	case "Accept-Language":
		report.Field = "Accept-Language"
		report.Actual = info.AcceptLanguage
		report.Expected = "locale-aware browser language header"
		report.Description = "The request is missing Accept-Language, which is unusual for real browsers."
	case "Sec-Fetch-*":
		report.Field = "Sec-Fetch-*"
		report.Actual = strings.Join([]string{info.SecFetchDest, info.SecFetchMode, info.SecFetchSite}, "|")
		report.Expected = "document|navigate|none-style navigation metadata"
		report.Description = "Chrome-class browsers should include coherent Sec-Fetch navigation metadata."
	case "Sec-Ch-Ua*":
		report.Field = "Sec-CH-UA"
		report.Actual = strings.Join([]string{info.SecCHUA, info.SecCHUAPlatform, info.SecCHUAMobile}, "|")
		report.Expected = "Chrome-class client hints present"
		report.Description = "The request claims a Chromium browser but omits required client hints."
	case "chrome_navigation_missing_client_hints":
		report.Field = "User-Agent/Sec-CH-UA"
		report.Actual = info.UserAgent
		report.Expected = "Chrome navigation with client hints"
		report.Description = "A Chromium navigation without client hints is strongly indicative of spoofed headers."
	case "firefox_navigation_priority_header":
		report.Field = "Priority"
		report.Actual = "present"
		report.Expected = "absent for simple Firefox-style top-level navigation"
		report.Description = "The Firefox-style request carries Chromium-like priority metadata without other browser context."
	case "firefox_chromium_priority_signature":
		report.Field = "Priority"
		report.Actual = "contains ', i'"
		report.Expected = "Firefox-style request without Chromium incremental priority signature"
		report.Description = "The Priority header uses a Chromium-style incremental scheduling signature on a Firefox-claimed request."
	case "generic_accept_header":
		report.Field = "Accept"
		report.Actual = info.Accept
		report.Expected = "browser navigation accept header with negotiated content types"
		report.Description = "A generic */* Accept header is common in bots and uncommon on top-level browser navigations."
	case "too_few_headers":
		report.Field = "header_count"
		report.Actual = fmt.Sprintf("%d", info.HeaderCount)
		report.Expected = ">= 5"
		report.Description = "The request includes too few headers for a normal browser navigation."
	case "missing_user_agent":
		report.Field = "User-Agent"
		report.Actual = info.UserAgent
		report.Expected = "browser user agent"
		report.Description = "Missing User-Agent is a strong automation signal."
	case "webdriver_exposed":
		report.Field = "X-Navigator-Webdriver"
		report.Actual = "true"
		report.Expected = "absent or false"
		report.Description = "The request directly exposes navigator.webdriver."
	default:
		if strings.HasPrefix(indicator, "suspicious_ua_") {
			report.Field = "User-Agent"
			report.Actual = info.UserAgent
			report.Expected = "browser user agent without automation keywords"
			report.Description = "The User-Agent contains automation-specific keywords."
		}
	}

	return report
}

//nolint:unused
var chromeHeaderOrder = []string{
	":method", ":authority", ":path", "accept", "accept-encoding",
	"accept-language", "cache-control", "content-type", "content-length",
	"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
	"sec-ch-ua-arch", "sec-ch-ua-bitness", "sec-ch-ua-full-version",
	"sec-ch-ua-model", "sec-ch-ua-platform-version", "sec-ch-ua-wow64",
	"sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
	"upgrade-insecure-requests", "user-agent",
}

//nolint:unused
var goHeaderOrder = []string{
	"accept-encoding", "user-agent", "accept",
}

//nolint:unused
var automationScriptPatterns = []string{
	"window.cdc_adoQpoas",
	"window.selendroid",
	"window.__webdriver",
	"window.__selenium_unwrapped",
	"navigator.webdriver",
	"navigator.__webdriver_script",
	"_selenium",
	"callSelenium",
	"_Selenium_IDE_Recorder",
	"__webdriver_script_fn",
}

//nolint:unused
func (sd *StealthDetector) analyzeHeaderOrder(req *http.Request) *DetectionVector {
	vec := &DetectionVector{
		Name:        "Header Order",
		Category:    "http_order",
		Weight:      constants.WeightTLS,
		Description: "Analyzes HTTP header ordering for browser fingerprint",
	}

	order := make([]string, 0)
	for k := range req.Header {
		order = append(order, strings.ToLower(k))
	}

	// Score based on deviation from Chrome order
	score := 0.0
	indicators := make([]string, 0)

	// Check for Go's typical header order (very short)
	if len(order) < 5 {
		score += 0.4
		indicators = append(indicators, "too_few_headers")
	}

	// Check if order matches Go's typical order
	isGoOrder := false
	for _, goHeader := range goHeaderOrder {
		if len(order) > 0 && strings.Contains(order[0], goHeader) {
			isGoOrder = true
			break
		}
	}

	if isGoOrder {
		score += 0.5
		indicators = append(indicators, "go_header_order")
	}

	// Check for Chrome-specific headers missing
	missingChromeHeaders := 0
	for _, ch := range []string{"sec-ch-ua", "sec-fetch-dest", "upgrade-insecure-requests"} {
		found := false
		for _, h := range order {
			if strings.Contains(h, ch) {
				found = true
				break
			}
		}
		if !found {
			missingChromeHeaders++
		}
	}

	if missingChromeHeaders > 1 {
		score += 0.2 * float64(missingChromeHeaders)
		indicators = append(indicators, "missing_chrome_headers")
	}

	vec.Score = score
	vec.Detected = score > 0.2
	vec.Indicators = indicators

	return vec
}

//nolint:unused
func (sd *StealthDetector) analyzeAutomationScripts(req *http.Request) *DetectionVector {
	vec := &DetectionVector{
		Name:        "Automation Scripts",
		Category:    "automation_scripts",
		Weight:      0.2,
		Description: "Detects automation framework scripts and injection patterns",
	}

	indicators := make([]string, 0)
	score := 0.0

	// Check navigator data for automation patterns
	navHeader := req.Header.Get(constants.HeaderNavigatorData)
	if navHeader != "" {
		var navData map[string]interface{}
		if err := json.Unmarshal([]byte(navHeader), &navData); err == nil {
			// Check for common automation script globals
			for _, pattern := range automationScriptPatterns {
				if _, ok := navData[pattern]; ok {
					indicators = append(indicators, fmt.Sprintf("automation_script:%s", pattern))
					score += 0.5
				}
			}

			// Check for webdriver
			if v, ok := navData["webdriver"].(bool); ok && v {
				indicators = append(indicators, "webdriver_flag")
				score += 0.6
			}

			// Check for puppeteer specific
			if v, ok := navData["puppeteer"].(bool); ok && v {
				indicators = append(indicators, "puppeteer_detected")
				score += 0.7
			}

			// Check for CDP
			if v, ok := navData["__ CDP_CONNECTION"].(bool); ok && v {
				indicators = append(indicators, "cdp_connection")
				score += 0.5
			}
		}
	}

	// Check User-Agent for automation keywords
	ua := req.Header.Get("User-Agent")
	if ua != "" {
		uaLower := strings.ToLower(ua)
		automationUA := []string{"selenium", "webdriver", "puppeteer", "playwright", "chromedriver", "geckodriver"}
		for _, a := range automationUA {
			if strings.Contains(uaLower, a) {
				indicators = append(indicators, fmt.Sprintf("ua_contains:%s", a))
				score += 0.4
			}
		}
	}

	// Check for missing typical browser properties
	navHeader2 := req.Header.Get("X-Navigator-Data")
	if navHeader2 != "" {
		var navData map[string]interface{}
		if err := json.Unmarshal([]byte(navHeader2), &navData); err == nil {
			// Count navigator properties
			propCount := len(navData)
			if propCount < 12 {
				indicators = append(indicators, fmt.Sprintf("few_navigator_props:%d", propCount))
				score += 0.2
			}

			// Check for chrome runtime (should exist in real Chrome)
			if _, ok := navData["chrome"]; !ok {
				indicators = append(indicators, "missing_chrome_runtime")
				score += 0.3
			}

			// Check for plugins (should have some in real browser)
			if plugins, ok := navData["plugins"].([]interface{}); ok && len(plugins) == 0 {
				indicators = append(indicators, "zero_plugins")
				score += 0.2
			}
		}
	}

	vec.Score = score
	vec.Detected = score > 0.2
	vec.Indicators = indicators

	return vec
}

//nolint:unused
func (sd *StealthDetector) analyzeGenericFingerprint(req *http.Request) *DetectionVector {
	vec := &DetectionVector{
		Name:        "Generic Fingerprint",
		Category:    "generic_fp",
		Weight:      0.2,
		Description: "Detects generic/constant fingerprint patterns typical of spoofing",
	}

	indicators := make([]string, 0)
	score := 0.0

	// Check canvas fingerprinting
	canvasHeader := req.Header.Get(constants.HeaderCanvasFingerprint)
	if canvasHeader != "" {
		if strings.Contains(canvasHeader, "randomized") || strings.Contains(canvasHeader, "noise") {
			indicators = append(indicators, "canvas_noise")
			score += 0.4
		}
		if strings.Contains(canvasHeader, "hash:") {
			// Check for suspicious constant hashes
			indicators = append(indicators, "canvas_hash_detected")
			score += 0.2
		}
	}

	// Check behavioral patterns
	behavHeader := req.Header.Get(constants.HeaderBehavioralData)
	if behavHeader != "" {
		var behav map[string]interface{}
		if err := json.Unmarshal([]byte(behavHeader), &behav); err == nil {
			// Check for zero variance
			if v, ok := behav["mouseStdDev"].(float64); ok && v == 0 {
				indicators = append(indicators, "zero_mouse_variance")
				score += 0.4
			}
			if v, ok := behav["typingStdDev"].(float64); ok && v == 0 {
				indicators = append(indicators, "zero_typing_variance")
				score += 0.3
			}
			// Check for perfect linearity
			if v, ok := behav["mouseStraightness"].(float64); ok && v > 0.95 {
				indicators = append(indicators, "perfect_linear_movement")
				score += 0.3
			}
			// Check for suspiciously low event counts
			if v, ok := behav["mouseEvents"].(float64); ok && v < 3 {
				indicators = append(indicators, "too_few_events")
				score += 0.2
			}
		}
	}

	// Check timing anomalies
	timingHeader := req.Header.Get(constants.HeaderTimingData)
	if timingHeader != "" {
		var timing map[string]interface{}
		if err := json.Unmarshal([]byte(timingHeader), &timing); err == nil {
			if v, ok := timing["ttfb"].(float64); ok && v == 0 {
				indicators = append(indicators, "zero_ttfb")
				score += 0.3
			}
		}
	}

	// Check for generic spoofing patterns (multiple techniques)
	spoofCount := 0
	if canvasHeader != "" {
		spoofCount++
	}
	if behavHeader != "" {
		spoofCount++
	}
	if timingHeader != "" {
		spoofCount++
	}

	if spoofCount >= 2 {
		indicators = append(indicators, "multiple_spoofing_techniques")
		score += 0.2
	}

	vec.Score = score
	vec.Detected = score > 0.2
	vec.Indicators = indicators

	return vec
}

func (sd *StealthDetector) checkClientHintsConsistency(info *HTTPFingerprintInfo) bool {
	if info.SecCHUA == "" || info.SecCHUAPlatform == "" {
		return true // Can't determine inconsistency without both
	}

	uaLower := strings.ToLower(info.UserAgent)
	platformLower := strings.ToLower(info.SecCHUAPlatform)

	// Check Windows
	if strings.Contains(uaLower, "windows") && !strings.Contains(platformLower, "windows") {
		return false
	}

	// Check macOS
	if strings.Contains(uaLower, "mac") && !strings.Contains(platformLower, "mac") {
		return false
	}

	// Check Linux
	if strings.Contains(uaLower, "linux") && !strings.Contains(platformLower, "linux") {
		return false
	}

	// Check Not_A Brand with Linux (common stealth indicator)
	if strings.Contains(info.SecCHUA, "Not_A Brand") && strings.Contains(platformLower, "linux") {
		return false
	}

	return true
}
