package adversarial

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/skunkworq/stealth/brws/constants"
)

var (
	knownChromeJA4Patterns = []string{
		"t12d",
		"t13d",
	}

	
	datacenterIPPatterns = []*regexp.Regexp{
		regexp.MustCompile(`^3\.`),
		regexp.MustCompile(`^34\.`),
		regexp.MustCompile(`^35\.`),
		regexp.MustCompile(`^104\.`),
		regexp.MustCompile(`^13\.`),
		regexp.MustCompile(`^52\.`),
		regexp.MustCompile(`^54\.`),
		regexp.MustCompile(`^23\.`),
		regexp.MustCompile(`^40\.`),
		regexp.MustCompile(`^20\.`),
	}

	vpnIPPatterns = []*regexp.Regexp{
		regexp.MustCompile(`^91\.`),
		regexp.MustCompile(`^185\.`),
		regexp.MustCompile(`^194\.`),
		regexp.MustCompile(`^89\.`),
	}
)

// AdvancedDetection provides comprehensive bot and automation detection
type AdvancedDetection struct{}

// NewAdvancedDetection creates a new instance of AdvancedDetection
func NewAdvancedDetection() *AdvancedDetection {
	return &AdvancedDetection{}
}

// AdvancedCheckResult represents the outcome of a single detection check
type AdvancedCheckResult struct {
	CheckName string
	Category  string
	Passed    bool
	Score     float64
	Details   string
	RawValue  string
	Severity  string
}

// AnalyzeTLS performs TLS fingerprint analysis to detect automation tools
func (ad *AdvancedDetection) AnalyzeTLS(tlsConn *tls.ConnectionState, userAgent string) []AdvancedCheckResult {
	var checks []AdvancedCheckResult

	if tlsConn == nil {
		checks = append(checks, AdvancedCheckResult{
			CheckName: "TLS-Available",
			Category:  "tls",
			Passed:    false,
			Score:     0.3,
			Details:   "No TLS connection available",
			Severity:  "medium",
		})
		return checks
	}

	ja4 := ad.generateJA4Simple(tlsConn)
	uaBrowser := ad.extractBrowserFromUA(userAgent)
	ja4Match := ad.checkJA4BrowserMatch(ja4, uaBrowser)

	checks = append(checks, AdvancedCheckResult{
		CheckName: "TLS-Version",
		Category:  "tls",
		Passed:    tlsConn.Version == tls.VersionTLS12 || tlsConn.Version == tls.VersionTLS13,
		Score:     0,
		Details:   fmt.Sprintf("TLS version: %04x", tlsConn.Version),
		RawValue:  fmt.Sprintf("%d", tlsConn.Version),
		Severity:  "high",
	})
	if tlsConn.Version != tls.VersionTLS12 && tlsConn.Version != tls.VersionTLS13 {
		checks[len(checks)-1].Score = 0.5
	}

	checks = append(checks, AdvancedCheckResult{
		CheckName: "TLS-JA4-Fingerprint",
		Category:  "tls",
		Passed:    ja4Match,
		Score:     0,
		Details:   fmt.Sprintf("JA4: %s (browser: %s)", ja4, uaBrowser),
		RawValue:  ja4,
		Severity:  "critical",
	})
	if !ja4Match {
		checks[len(checks)-1].Score = 0.6
	}

	checks = append(checks, AdvancedCheckResult{
		CheckName: "TLS-Cipher-Suite",
		Category:  "tls",
		Passed:    true,
		Score:     0,
		Details:   fmt.Sprintf("Cipher suite: %04x", tlsConn.CipherSuite),
		RawValue:  fmt.Sprintf("%04x", tlsConn.CipherSuite),
		Severity:  "medium",
	})

	checks = append(checks, AdvancedCheckResult{
		CheckName: "TLS-ALPN-HTTP2",
		Category:  "tls",
		Passed:    true,
		Score:     0,
		Details:   fmt.Sprintf("Cipher suite: %04x", tlsConn.CipherSuite),
		RawValue:  fmt.Sprintf("%04x", tlsConn.CipherSuite),
		Severity:  "medium",
	})

	sni := tlsConn.ServerName
	if sni == "" {
		checks = append(checks, AdvancedCheckResult{
			CheckName: "TLS-SNI",
			Category:  "tls",
			Passed:    true,
			Score:     0,
			Details:   "No SNI (suspicious for HTTPS)",
			RawValue:  "",
			Severity:  "high",
		})
		checks[len(checks)-1].Score = 0.3
	}

	// NEW: Detect Go TLS fingerprint (used by many Go-based HTTP clients)
	isGoTLS, goJA4 := ad.detectGoTLSFingerprint(tlsConn)
	checks = append(checks, AdvancedCheckResult{
		CheckName: "TLS-Go-Fingerprint",
		Category:  "tls",
		Passed:    !isGoTLS,
		Score:     0,
		Details:   fmt.Sprintf("Go TLS detected: %v, JA4: %s", isGoTLS, goJA4),
		RawValue:  goJA4,
		Severity:  "critical",
	})
	if isGoTLS {
		// If Go TLS is detected, this is likely automation
		checks[len(checks)-1].Score = 0.7
	}

	return checks
}

func (ad *AdvancedDetection) generateJA4Simple(tlsConn *tls.ConnectionState) string {
	version := "12"
	if tlsConn.Version == tls.VersionTLS13 {
		version = "13"
	}

	cipher := fmt.Sprintf("%04x", tlsConn.CipherSuite)
	cipherShort := cipher
	if len(cipher) > 12 {
		cipherShort = cipher[:12]
	}

	return fmt.Sprintf("t%s__%s", version, cipherShort)
}

func (ad *AdvancedDetection) extractBrowserFromUA(ua string) string {
	ua = strings.ToLower(ua)
	if strings.Contains(ua, "chrome") && !strings.Contains(ua, "firefox") && !strings.Contains(ua, "safari") {
		return "chrome"
	}
	if strings.Contains(ua, "firefox") {
		return "firefox"
	}
	if strings.Contains(ua, "safari") {
		return "safari"
	}
	return "unknown"
}

func (ad *AdvancedDetection) checkJA4BrowserMatch(ja4, browser string) bool {
	if browser == "chrome" {
		for _, pattern := range knownChromeJA4Patterns {
			if strings.HasPrefix(ja4, pattern) {
				return true
			}
		}
	}
	if browser == "firefox" {
		return strings.HasPrefix(ja4, "t12d")
	}
	return false
}

func (ad *AdvancedDetection) detectGoTLSFingerprint(tlsConn *tls.ConnectionState) (bool, string) {
	ja4 := ad.generateJA4Simple(tlsConn)

	// Go's TLS cipher suite detection
	// TLS 1.3 ciphers: 0x1301, 0x1302, 0x1303
	// TLS 1.2 ciphers include: 0x002f, 0x0035, etc.

	cipherSuite := tlsConn.CipherSuite

	// Go's TLS 1.3 typically uses cipher 0x1301 (TLS_AES_128_GCM_SHA256)
	// Chrome also uses this, but the order might differ

	// Check for Go's typical TLS 1.2 ciphers
	// Go often uses 0x002f (TLS_RSA_WITH_AES_128_CBC_SHA) or 0x0035 (TLS_RSA_WITH_AES_256_CBC_SHA)
	if cipherSuite == 0x002f || cipherSuite == 0x0035 {
		return true, ja4
	}

	// Go's JA4 pattern - typically starts with "t13" without "d" suffix
	// Chrome's JA4 for TLS 1.3 typically has "d" suffix: "t13d"
	if strings.HasPrefix(ja4, "t13") && !strings.HasPrefix(ja4, "t13d") {
		return true, ja4
	}

	// Check TLS version - Go's default TLS 1.3 fingerprint
	if tlsConn.Version == tls.VersionTLS13 && cipherSuite == 0x1301 {
		// This could be Go or Chrome, need more context
		// But if JA4 doesn't match Chrome pattern, likely Go
		if !strings.HasPrefix(ja4, "t13d") {
			return true, ja4
		}
	}

	return false, ja4
}

// AnalyzeHTTP2 analyzes HTTP/2 protocol characteristics for anomalies
func (ad *AdvancedDetection) AnalyzeHTTP2(req *http.Request, proto string) []AdvancedCheckResult {
	var checks []AdvancedCheckResult

	isHTTP2 := proto == "h2"

	checks = append(checks, AdvancedCheckResult{
		CheckName: "HTTP2-Protocol",
		Category:  "http2",
		Passed:    !isHTTP2 || ad.isValidHTTP2Request(req),
		Score:     0,
		Details:   fmt.Sprintf("Protocol: %s", proto),
		RawValue:  proto,
		Severity:  "high",
	})
	if isHTTP2 && !ad.isValidHTTP2Request(req) {
		checks[len(checks)-1].Score = 0.4
	}

	headerOrder := ad.getHeaderOrder(req)
	expectedOrder := []string{":method", ":authority", ":scheme", ":path"}
	if ad.isFirefoxUserAgent(req.Header.Get("User-Agent")) {
		expectedOrder = []string{":method", ":path", ":authority", ":scheme"}
	}

	orderMatch := ad.compareHeaderOrder(headerOrder, expectedOrder)

	checks = append(checks, AdvancedCheckResult{
		CheckName: "HTTP2-Pseudo-Header-Order",
		Category:  "http2",
		Passed:    orderMatch,
		Score:     0,
		Details:   fmt.Sprintf("Header order: %v", headerOrder),
		RawValue:  strings.Join(headerOrder, ","),
		Severity:  "critical",
	})
	if !orderMatch {
		checks[len(checks)-1].Score = 0.5
	}

	return checks
}

func (ad *AdvancedDetection) isValidHTTP2Request(_ *http.Request) bool {
	return true
}

func (ad *AdvancedDetection) isFirefoxUserAgent(ua string) bool {
	return strings.Contains(strings.ToLower(ua), "firefox")
}

func (ad *AdvancedDetection) getHeaderOrder(req *http.Request) []string {
	var order []string
	for k := range req.Header {
		order = append(order, strings.ToLower(k))
	}
	sort.Strings(order)
	return order
}

func (ad *AdvancedDetection) compareHeaderOrder(actual, expected []string) bool {
	if len(actual) == 0 || len(expected) == 0 {
		return true
	}

	expectedIdx := 0
	for _, a := range actual {
		if expectedIdx < len(expected) && a == expected[expectedIdx] {
			expectedIdx++
		}
	}

	return expectedIdx == len(expected)
}

// AnalyzeHeaders analyzes HTTP headers for client hints and consistency
func (ad *AdvancedDetection) AnalyzeHeaders(req *http.Request) []AdvancedCheckResult {
	var checks []AdvancedCheckResult

	ua := req.Header.Get("User-Agent")
	secChUa := req.Header.Get("Sec-Ch-Ua")
	secChPlatform := req.Header.Get("Sec-Ch-Ua-Platform")
	secChMobile := req.Header.Get("Sec-Ch-Ua-Mobile")
	secChFullVersion := req.Header.Get("Sec-Ch-Ua-Full-Version")

	checks = append(checks, AdvancedCheckResult{
		CheckName: "Client-Hints-Complete",
		Category:  "http",
		Passed:    secChUa != "" && secChPlatform != "" && secChMobile != "",
		Score:     0,
		Details:   "Client hints must include Sec-Ch-Ua, Sec-Ch-Ua-Platform, Sec-Ch-Ua-Mobile",
		RawValue:  fmt.Sprintf("Ua:%t Platform:%t Mobile:%t", secChUa != "", secChPlatform != "", secChMobile != ""),
		Severity:  "high",
	})
	if secChUa == "" || secChPlatform == "" || secChMobile == "" {
		checks[len(checks)-1].Score = constants.SeverityMedium
	}

	if secChUa != "" && secChPlatform != "" {
		platformConsistent := ad.checkPlatformConsistency(ua, secChPlatform)
		checks = append(checks, AdvancedCheckResult{
			CheckName: "Client-Hints-Platform-Match",
			Category:  "http",
			Passed:    platformConsistent,
			Score:     0,
			Details:   "Platform in Client Hints must match User-Agent",
			RawValue:  fmt.Sprintf("UA platform check: %v", platformConsistent),
			Severity:  "critical",
		})
		if !platformConsistent {
			checks[len(checks)-1].Score = 0.6
		}
	}

	if secChFullVersion != "" {
		versionValid := ad.validateFullVersion(secChFullVersion)
		checks = append(checks, AdvancedCheckResult{
			CheckName: "Client-Hints-Full-Version-Valid",
			Category:  "http",
			Passed:    versionValid,
			Score:     0,
			Details:   "Sec-Ch-Ua-Full-Version must be valid semver",
			RawValue:  secChFullVersion,
			Severity:  "high",
		})
		if !versionValid {
			checks[len(checks)-1].Score = 0.3
		}
	}

	secFetchDest := req.Header.Get("Sec-Fetch-Dest")
	secFetchMode := req.Header.Get("Sec-Fetch-Mode")
	secFetchSite := req.Header.Get("Sec-Fetch-Site")

	secFetchPresent := secFetchDest != "" || secFetchMode != "" || secFetchSite != ""

	checks = append(checks, AdvancedCheckResult{
		CheckName: "Sec-Fetch-Metadata-Present",
		Category:  "http",
		Passed:    secFetchPresent,
		Score:     0,
		Details:   "Sec-Fetch-* headers should be present for Chrome",
		RawValue:  fmt.Sprintf("Dest:%s Mode:%s Site:%s", secFetchDest, secFetchMode, secFetchSite),
		Severity:  "medium",
	})
	if !secFetchPresent && strings.Contains(ua, "Chrome") {
		checks[len(checks)-1].Score = 0.2
	}

	if secFetchDest != "" {
		validDest := secFetchDest == "document" || secFetchDest == "image" ||
			secFetchDest == "script" || secFetchDest == "style" || secFetchDest == "fetch" ||
			secFetchDest == "font" || secFetchDest == "object" || secFetchDest == "worker" ||
			secFetchDest == "manifest" || secFetchDest == "xmlhttprequest"

		checks = append(checks, AdvancedCheckResult{
			CheckName: "Sec-Fetch-Dest-Valid",
			Category:  "http",
			Passed:    validDest,
			Score:     0,
			Details:   "Sec-Fetch-Dest must be valid fetch destination",
			RawValue:  secFetchDest,
			Severity:  "medium",
		})
		if !validDest {
			checks[len(checks)-1].Score = 0.2
		}
	}

	upgradeInsecure := req.Header.Get("Upgrade-Insecure-Requests")
	checks = append(checks, AdvancedCheckResult{
		CheckName: "Upgrade-Insecure-Requests",
		Category:  "http",
		Passed:    upgradeInsecure == "1" || upgradeInsecure == "",
		Score:     0,
		Details:   "Upgrade-Insecure-Requests should be 1 or absent",
		RawValue:  upgradeInsecure,
		Severity:  "low",
	})

	return checks
}

func (ad *AdvancedDetection) checkPlatformConsistency(ua, secChPlatform string) bool {
	if ua == "" || secChPlatform == "" {
		return true
	}

	uaLower := strings.ToLower(ua)
	platformLower := strings.ToLower(secChPlatform)

	platformMap := map[string][]string{
		"windows": {"windows", "win32", "win64"},
		"mac":     {"mac", "macos", "darwin", "ios"},
		"linux":   {"linux", "ubuntu", "debian", "fedora", "centos"},
		"android": {"android"},
		"ios":     {"ios", "iphone", "ipad"},
	}

	for platform, patterns := range platformMap {
		for _, pattern := range patterns {
			if strings.Contains(uaLower, pattern) {
				if !strings.Contains(platformLower, platform) {
					return false
				}
				break
			}
		}
	}

	return true
}

func (ad *AdvancedDetection) validateFullVersion(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) < 3 {
		return false
	}

	for _, p := range parts[:3] {
		if _, err := strconv.Atoi(p); err != nil {
			return false
		}
	}

	return true
}


// AnalyzeIP analyzes the client IP for datacenter or VPN classification
func (ad *AdvancedDetection) AnalyzeIP(clientIP string) []AdvancedCheckResult {
	var checks []AdvancedCheckResult

	isDatacenter := ad.isDatacenterIP(clientIP)

	checks = append(checks, AdvancedCheckResult{
		CheckName: "IP-Datacenter",
		Category:  "ip",
		Passed:    !isDatacenter,
		Score:     0,
		Details:   fmt.Sprintf("IP %s is from datacenter", clientIP),
		RawValue:  clientIP,
		Severity:  "high",
	})
	if isDatacenter {
		checks[len(checks)-1].Score = 0.4
	}

	isVPN := ad.isVPNIP(clientIP)

	checks = append(checks, AdvancedCheckResult{
		CheckName: "IP-VPN",
		Category:  "ip",
		Passed:    !isVPN,
		Score:     0,
		Details:   fmt.Sprintf("IP %s is from VPN", clientIP),
		RawValue:  clientIP,
		Severity:  "critical",
	})
	if isVPN {
		checks[len(checks)-1].Score = 0.6
	}

	ipClass := ad.classifyIP(clientIP)

	checks = append(checks, AdvancedCheckResult{
		CheckName: "IP-Classification",
		Category:  "ip",
		Passed:    ipClass != "unknown",
		Score:     0,
		Details:   fmt.Sprintf("IP classification: %s", ipClass),
		RawValue:  ipClass,
		Severity:  "medium",
	})
	if ipClass == "unknown" {
		checks[len(checks)-1].Score = 0.1
	}

	return checks
}

func (ad *AdvancedDetection) isDatacenterIP(ip string) bool {
	for _, pattern := range datacenterIPPatterns {
		if pattern.MatchString(ip) {
			return true
		}
	}
	return false
}

func (ad *AdvancedDetection) isVPNIP(ip string) bool {
	for _, pattern := range vpnIPPatterns {
		if pattern.MatchString(ip) {
			return true
		}
	}
	return false
}

func (ad *AdvancedDetection) classifyIP(ip string) string {
	if ad.isDatacenterIP(ip) {
		return "datacenter"
	}
	if ad.isVPNIP(ip) {
		return "vpn"
	}
	return "residential"
}

// AnalyzeTiming analyzes request timing patterns for bot detection.
func (ad *AdvancedDetection) AnalyzeTiming(_ *http.Request, timing *RequestTiming) []AdvancedCheckResult {
	var checks []AdvancedCheckResult

	now := time.Now()
	hourOfDay := now.Hour()

	isBusinessHours := hourOfDay >= 9 && hourOfDay <= 17

	checks = append(checks, AdvancedCheckResult{
		CheckName: "Timing-Business-Hours",
		Category:  "timing",
		Passed:    true,
		Score:     0,
		Details:   fmt.Sprintf("Request at %d:00 (business hours: %v)", hourOfDay, isBusinessHours),
		RawValue:  strconv.Itoa(hourOfDay),
		Severity:  "low",
	})
	if !isBusinessHours {
		checks[len(checks)-1].Score = 0.05
	}

	if timing != nil {
		ttfbSeconds := timing.TTFB.Seconds()

		checks = append(checks, AdvancedCheckResult{
			CheckName: "Timing-TTFB",
			Category:  "timing",
			Passed:    ttfbSeconds > 0.05 && ttfbSeconds < 5.0,
			Score:     0,
			Details:   fmt.Sprintf("TTFB: %.3fs (0.05-5.0s expected)", ttfbSeconds),
			RawValue:  fmt.Sprintf("%.3f", ttfbSeconds),
			Severity:  "medium",
		})
		if ttfbSeconds < 0.05 {
			checks[len(checks)-1].Score = 0.3
		}
	}

	dayOfWeek := int(now.Weekday())
	isWeekend := dayOfWeek == 0 || dayOfWeek == 6

	checks = append(checks, AdvancedCheckResult{
		CheckName: "Timing-Weekend",
		Category:  "timing",
		Passed:    true,
		Score:     0,
		Details:   fmt.Sprintf("Request on day %d (weekend: %v)", dayOfWeek, isWeekend),
		RawValue:  strconv.Itoa(dayOfWeek),
		Severity:  "low",
	})
	if isWeekend {
		checks[len(checks)-1].Score = 0.02
	}

	return checks
}

// AnalyzeBehavioral analyzes behavioral data from request headers
func (ad *AdvancedDetection) AnalyzeBehavioral(req *http.Request) []AdvancedCheckResult {
	var checks []AdvancedCheckResult

	navHeader := req.Header.Get(constants.HeaderNavigatorData)
	behavHeader := req.Header.Get(constants.HeaderBehavioralData)
	canvasHeader := req.Header.Get(constants.HeaderCanvasFingerprint)

	checks = append(checks, AdvancedCheckResult{
		CheckName: "Behavioral-Headers-Injection",
		Category:  "behavioral",
		Passed:    navHeader == "" && behavHeader == "" && canvasHeader == "",
		Score:     0,
		Details:   "No behavioral injection headers (good)",
		RawValue:  fmt.Sprintf("Nav:%v Behav:%v Canvas:%v", navHeader != "", behavHeader != "", canvasHeader != ""),
		Severity:  "high",
	})
	if navHeader != "" || behavHeader != "" || canvasHeader != "" {
		checks[len(checks)-1].Score = 0.5
	}

	if behavHeader != "" {
		var behavData map[string]interface{}
		if err := json.Unmarshal([]byte(behavHeader), &behavData); err == nil {
			if mouseStdDev, ok := behavData["mouseStdDev"].(float64); ok && mouseStdDev < 0.1 {
				checks = append(checks, AdvancedCheckResult{
					CheckName: "Behavioral-Mouse-Variance",
					Category:  "behavioral",
					Passed:    false,
					Score:     0.4,
					Details:   "Zero/low mouse variance (bot-like)",
					RawValue:  fmt.Sprintf("mouseStdDev: %f", mouseStdDev),
					Severity:  "critical",
				})
			}

			if typingStdDev, ok := behavData["typingStdDev"].(float64); ok && typingStdDev < 0.1 {
				checks = append(checks, AdvancedCheckResult{
					CheckName: "Behavioral-Typing-Variance",
					Category:  "behavioral",
					Passed:    false,
					Score:     0.3,
					Details:   "Zero/low typing variance (bot-like)",
					RawValue:  fmt.Sprintf("typingStdDev: %f", typingStdDev),
					Severity:  "high",
				})
			}
		}
	}

	if canvasHeader != "" && strings.Contains(canvasHeader, "randomized=true") {
		checks = append(checks, AdvancedCheckResult{
			CheckName: "Behavioral-Canvas-Randomized",
			Category:  "behavioral",
			Passed:    false,
			Score:     0.5,
			Details:   "Canvas explicitly marked as randomized (suspicious)",
			RawValue:  canvasHeader,
			Severity:  "critical",
		})
	}

	return checks
}

// AnalyzeAutomation checks for automation tool signatures in the request
func (ad *AdvancedDetection) AnalyzeAutomation(req *http.Request) []AdvancedCheckResult {
	var checks []AdvancedCheckResult

	ua := strings.ToLower(req.Header.Get("User-Agent"))

	automationPatterns := []string{
		"headlesschrome",
		"headless",
		"selenium",
		"webdriver",
		"puppeteer",
		"playwright",
		"automation",
		"python",
		"curl",
		"wget",
		"scrapy",
		"bot",
	}

	for _, pattern := range automationPatterns {
		if strings.Contains(ua, pattern) {
			checks = append(checks, AdvancedCheckResult{
				CheckName: "Automation-UA-Keyword",
				Category:  "automation",
				Passed:    false,
				Score:     0.7,
				Details:   fmt.Sprintf("User-Agent contains automation keyword: %s", pattern),
				RawValue:  pattern,
				Severity:  "critical",
			})
			break
		}
	}

	navHeader := req.Header.Get(constants.HeaderNavigatorData)
	if navHeader != "" {
		var navData map[string]interface{}
		if err := json.Unmarshal([]byte(navHeader), &navData); err == nil {
			uaStr := req.Header.Get("User-Agent")
			isChromeBrowser := strings.Contains(strings.ToLower(uaStr), "chrome")

			if webdriver, ok := navData["webdriver"].(bool); ok && webdriver {
				checks = append(checks, AdvancedCheckResult{
					CheckName: "Automation-Webdriver-Flag",
					Category:  "automation",
					Passed:    false,
					Score:     0.9,
					Details:   "navigator.webdriver is true",
					RawValue:  "true",
					Severity:  "critical",
				})
			}

			// Empty plugins only suspicious for Chrome (Firefox has 0 plugins by design)
			if isChromeBrowser {
				if plugins, ok := navData["plugins"].([]interface{}); ok && len(plugins) == 0 {
					checks = append(checks, AdvancedCheckResult{
						CheckName: "Automation-Empty-Plugins",
						Category:  "automation",
						Passed:    false,
						Score:     0.4,
						Details:   "No plugins detected (suspicious)",
						RawValue:  "empty",
						Severity:  "high",
					})
				}
			}

			// chrome.runtime is Chrome-only — Firefox doesn't have it
			if isChromeBrowser {
				chromeVal, chromeExists := navData["chrome"]
				if !chromeExists || chromeVal == nil {
					checks = append(checks, AdvancedCheckResult{
						CheckName: "Automation-Chrome-Runtime",
						Category:  "automation",
						Passed:    false,
						Score:     0.3,
						Details:   "chrome.runtime missing",
						RawValue:  "missing",
						Severity:  "high",
					})
				}
			}
		}
	}

	accept := req.Header.Get("Accept")
	if accept == "*/*" || accept == "" {
		checks = append(checks, AdvancedCheckResult{
			CheckName: "Automation-Accept-Header",
			Category:  "automation",
			Passed:    false,
			Score:     0.2,
			Details:   "Generic Accept header (*/*) is suspicious",
			RawValue:  accept,
			Severity:  "medium",
		})
	}

	return checks
}

// AnalyzeWebRTC checks for WebRTC leak indicators and spoofing artifacts
func (ad *AdvancedDetection) AnalyzeWebRTC(data *WebRTCData) []AdvancedCheckResult {
	var checks []AdvancedCheckResult

	if !data.RTCAvailable {
		checks = append(checks, AdvancedCheckResult{
			CheckName: "WebRTC-Disabled",
			Category:  "webrtc",
			Passed:    false,
			Score:     0.3,
			Details:   "WebRTC completely disabled — unusual for standard browsers",
			RawValue:  "disabled",
			Severity:  "medium",
		})
	}

	if data.RTCAvailable && data.ICECandidateCount == 0 {
		checks = append(checks, AdvancedCheckResult{
			CheckName: "WebRTC-No-Candidates",
			Category:  "webrtc",
			Passed:    false,
			Score:     0.4,
			Details:   "WebRTC enabled but no ICE candidates — relay-only or blocked",
			RawValue:  "0",
			Severity:  "high",
		})
	}

	if data.RequestSourceIP != "" && len(data.LocalIPs) > 0 {
		mismatch := true
		for _, ip := range data.LocalIPs {
			if ip == data.RequestSourceIP {
				mismatch = false
				break
			}
		}
		if mismatch {
			checks = append(checks, AdvancedCheckResult{
				CheckName: "WebRTC-IP-Mismatch",
				Category:  "webrtc",
				Passed:    false,
				Score:     0.7,
				Details:   "WebRTC-disclosed IP does not match HTTP source IP (proxy/VPN leak)",
				RawValue:  fmt.Sprintf("webrtc:%v http:%s", data.LocalIPs, data.RequestSourceIP),
				Severity:  "critical",
			})
		}
	}

	if data.ConstructorProxied {
		checks = append(checks, AdvancedCheckResult{
			CheckName: "WebRTC-Constructor-Proxied",
			Category:  "webrtc",
			Passed:    false,
			Score:     0.3,
			Details:   "RTCPeerConnection constructor appears to be proxied or wrapped",
			RawValue:  "proxied",
			Severity:  "medium",
		})
	}

	return checks
}

// AnalyzeHeadless checks for headless browser indicators from navigator data
func (ad *AdvancedDetection) AnalyzeHeadless(req *http.Request) []AdvancedCheckResult {
	var checks []AdvancedCheckResult

	navHeader := req.Header.Get(constants.HeaderNavigatorData)
	if navHeader == "" {
		return checks
	}

	var navData map[string]interface{}
	if err := json.Unmarshal([]byte(navHeader), &navData); err != nil {
		return checks
	}

	// Check window dimension gaps (outerHeight - innerHeight should be >0 in real browsers)
	if windowData, ok := navData["window"].(map[string]interface{}); ok {
		outerH, outerOk := windowData["outerHeight"].(float64)
		innerH, innerOk := windowData["innerHeight"].(float64)
		if outerOk && innerOk {
			gap := outerH - innerH
			if gap <= 0 {
				checks = append(checks, AdvancedCheckResult{
					CheckName: "Headless-Window-Gap",
					Category:  "automation",
					Passed:    false,
					Score:     0.5,
					Details:   fmt.Sprintf("outerHeight-innerHeight gap is %.0f (expected >0 for real browser chrome)", gap),
					RawValue:  fmt.Sprintf("outer=%.0f inner=%.0f", outerH, innerH),
					Severity:  "high",
				})
			}
		}
	}

	// Check Notification.permission (headless returns 'denied')
	if permissions, ok := navData["permissions"].(map[string]interface{}); ok {
		if state, ok := permissions["state"].(string); ok && state == "denied" {
			checks = append(checks, AdvancedCheckResult{
				CheckName: "Headless-Notification-Denied",
				Category:  "automation",
				Passed:    false,
				Score:     0.3,
				Details:   "Notification.permission is 'denied' — common in headless environments",
				RawValue:  "denied",
				Severity:  "medium",
			})
		}
	}

	// Check chrome.loadTimes presence (absent in some headless modes)
	if _, ok := navData["chrome_loadTimes"]; !ok {
		// Only flag if claiming to be Chrome
		ua := req.Header.Get("User-Agent")
		if strings.Contains(strings.ToLower(ua), "chrome") {
			checks = append(checks, AdvancedCheckResult{
				CheckName: "Headless-No-LoadTimes",
				Category:  "automation",
				Passed:    false,
				Score:     0.30,
				Details:   "chrome.loadTimes() not detected — indicates non-standard Chrome environment",
				RawValue:  "missing",
				Severity:  "medium",
			})
		}
	}

	return checks
}

// CalculateOverallScore calculates the final bot detection score
func (ad *AdvancedDetection) CalculateOverallScore(allChecks []AdvancedCheckResult) (float64, bool) {
	if len(allChecks) == 0 {
		return 0, false
	}

	var totalScore float64
	var criticalCount, highCount int

	for _, check := range allChecks {
		totalScore += check.Score

		switch check.Severity {
		case "critical":
			criticalCount++
		case "high":
			highCount++
		}
	}

	avgScore := totalScore / float64(len(allChecks))

	isBot := avgScore >= constants.DefaultThresholdBot || criticalCount >= 2 || highCount >= 4

	return avgScore, isBot
}

// RequestTiming holds timing metrics for a request
type RequestTiming struct {
	TTFB    time.Duration
	Total   time.Duration
	Blocked time.Duration
	DNS     time.Duration
	Connect time.Duration
	SSL     time.Duration
	Send    time.Duration
	Wait    time.Duration
	Receive time.Duration
}

// CalculateEntropy calculates Shannon entropy for a given string
func (ad *AdvancedDetection) CalculateEntropy(data string) float64 {
	if len(data) == 0 {
		return 0
	}

	freq := make(map[rune]float64)
	for _, c := range data {
		freq[c]++
	}

	var entropy float64
	for _, count := range freq {
		p := count / float64(len(data))
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// AnalyzeHTTPHeadersAndTLS performs combined analysis of HTTP headers and TLS
func (ad *AdvancedDetection) AnalyzeHTTPHeadersAndTLS(req *http.Request, tlsConn *tls.ConnectionState) []AdvancedCheckResult {
	var checks []AdvancedCheckResult

	// First get HTTP-only analysis
	httpChecks := ad.AnalyzeHeaders(req)
	checks = append(checks, httpChecks...)

	// Then add TLS analysis if available
	if tlsConn != nil {
		tlsChecks := ad.AnalyzeTLS(tlsConn, req.Header.Get("User-Agent"))
		checks = append(checks, tlsChecks...)
	}

	// CRITICAL: Cross-check HTTP browser claims vs TLS fingerprint
	ua := req.Header.Get("User-Agent")
	if ua != "" && tlsConn != nil {
		// Check if claiming Chrome but TLS doesn't match Chrome
		if strings.Contains(strings.ToLower(ua), "chrome") {
			isGoTLS, _ := ad.detectGoTLSFingerprint(tlsConn)
			if isGoTLS {
				checks = append(checks, AdvancedCheckResult{
					CheckName: "Spoofing-Chrome-Headers-Go-TLS",
					Category:  "spoofing",
					Passed:    false,
					Score:     0.8,
					Details:   "HTTP headers claim Chrome but TLS fingerprint is Go (likely spoofing)",
					RawValue:  "chrome_ua_go_tls",
					Severity:  "critical",
				})
			}
		}

		// Check if claiming Firefox but using Chrome TLS
		if strings.Contains(strings.ToLower(ua), "firefox") {
			ja4 := ad.generateJA4Simple(tlsConn)
			if strings.HasPrefix(ja4, "t13d") || strings.HasPrefix(ja4, "t12d") {
				// Firefox typically doesn't use "d" suffix patterns
				// This could be Chrome TLS spoofing as Firefox
				checks = append(checks, AdvancedCheckResult{
					CheckName: "Spoofing-Firefox-Headers-Chrome-TLS",
					Category:  "spoofing",
					Passed:    false,
					Score:     0.7,
					Details:   "HTTP headers claim Firefox but TLS fingerprint looks like Chrome",
					RawValue:  "firefox_ua_chrome_tls",
					Severity:  "critical",
				})
			}
		}

		// Check for platform mismatch
		secChPlatform := req.Header.Get("Sec-Ch-Ua-Platform")
		if secChPlatform != "" {
			platformConsistent := ad.checkPlatformConsistency(ua, secChPlatform)
			if !platformConsistent {
				checks = append(checks, AdvancedCheckResult{
					CheckName: "Spoofing-Platform-Mismatch",
					Category:  "spoofing",
					Passed:    false,
					Score:     0.6,
					Details:   "User-Agent platform doesn't match Sec-Ch-Ua-Platform",
					RawValue:  fmt.Sprintf("UA:%s Platform:%s", ua, secChPlatform),
					Severity:  "critical",
				})
			}
		}
	}

	// Check for incomplete spoofing (Chrome headers but no Client Hints)
	if strings.Contains(strings.ToLower(ua), "chrome") {
		if req.Header.Get("Sec-Ch-Ua") == "" {
			checks = append(checks, AdvancedCheckResult{
				CheckName: "Spoofing-Incomplete-Chrome",
				Category:  "spoofing",
				Passed:    false,
				Score:     0.5,
				Details:   "Chrome User-Agent but missing Client Hints (likely incomplete spoofing)",
				RawValue:  "incomplete_chrome",
				Severity:  "high",
			})
		}
	}

	return checks
}
