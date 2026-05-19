package detection

import (
	"fmt"
	"net/http"
	"strings"
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
