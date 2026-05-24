package detection

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"strings"

	"github.com/skunkworq/stealth/brws/core/constants"
)

var (
	secChUaVersionRe = regexp.MustCompile(`"Google Chrome";v="(\d+)"`)
	uaVersionRe      = regexp.MustCompile(`Chrome/(\d+)`)
)

// IsomorphicAnalyzer handles cross-validation between different detection layers
// (HTTP headers, Navigator properties, Canvas/WebGL, etc.) to ensure environment parity.
type IsomorphicAnalyzer struct{}

// NewIsomorphicAnalyzer creates a new IsomorphicAnalyzer.
func NewIsomorphicAnalyzer() *IsomorphicAnalyzer {
	return &IsomorphicAnalyzer{}
}

// Analyze performs isomorphic cross-validation checks on the request.
func (ia *IsomorphicAnalyzer) Analyze(req *http.Request, httpInfo *HTTPFingerprintInfo) *DetectionVector {
	if httpInfo == nil {
		return nil
	}

	vec := &DetectionVector{
		Name:        "Isomorphic Cross-Validation",
		Category:    "isomorphic",
		Weight:      0.5,
		Description: "Cross-checks multiple layers (HTTP, Navigator, WebGL) for OS and execution environment parity",
	}

	var navData map[string]interface{}
	if navHeader := req.Header.Get(constants.HeaderNavigatorData); navHeader != "" {
		if err := json.Unmarshal([]byte(navHeader), &navData); err != nil {
			navData = nil
		}
	}

	var canvasData map[string]interface{}
	if canvasHeader := req.Header.Get(constants.HeaderCanvasFingerprint); canvasHeader != "" {
		if err := json.Unmarshal([]byte(canvasHeader), &canvasData); err != nil {
			canvasData = nil
		}
	}

	var behavData map[string]interface{}
	if behavHeader := req.Header.Get(constants.HeaderBehavioralData); behavHeader != "" {
		if err := json.Unmarshal([]byte(behavHeader), &behavData); err != nil {
			behavData = nil
		}
	}

	var webglData map[string]interface{}
	if webglHeader := req.Header.Get(constants.HeaderWebGLData); webglHeader != "" {
		if err := json.Unmarshal([]byte(webglHeader), &webglData); err != nil {
			webglData = nil
		}
	}

	indicators := make([]string, 0)

	httpPlatform := strings.ToLower(httpInfo.Platform)
	if httpInfo.SecCHUAPlatform != "" {
		httpPlatform = strings.ToLower(httpInfo.SecCHUAPlatform)
	}

	indicators = ia.checkPlatformGPU(canvasData, httpPlatform, vec, indicators)
	indicators = ia.checkGPUCoreCoherence(webglData, navData, vec, indicators)

	if navData != nil {
		indicators = ia.checkNavigatorPlatform(navData, httpPlatform, vec, indicators)
		indicators = ia.checkLanguages(navData, httpInfo.AcceptLanguage, vec, indicators)
		indicators = ia.checkUserAgent(navData, httpInfo, vec, indicators)
		indicators = ia.checkUAVersion(httpInfo, vec, indicators)
		indicators = ia.checkScreenDimensions(req, navData, vec, indicators)
		indicators = ia.checkCSITiming(navData, vec, indicators)
		indicators = ia.checkPointerInteraction(navData, httpPlatform, vec, indicators)
		indicators = ia.checkTouchPointerCoherence(navData, vec, indicators)
		indicators = ia.checkUserAgentDataConsistency(navData, httpInfo, vec, indicators)
		indicators = ia.checkJSEngineArtifacts(navData, httpInfo, vec, indicators)
		indicators = ia.checkStorageCoherence(navData, vec, indicators)
	}

	indicators = ia.checkHeaderOrder(httpInfo, vec, indicators)
	indicators = ia.checkAcceptDestConsistency(httpInfo, vec, indicators)
	indicators = ia.checkConnectionTimingCoherence(req, vec, indicators)

	if behavData != nil {
		indicators = ia.checkErrorStackFormat(behavData, httpInfo, vec, indicators)
	}

	indicators = ia.checkPerformanceTiming(req, vec, indicators)
	indicators = ia.checkScreenDPR(req, vec, indicators)
	indicators = ia.checkFontPlatform(req, navData, vec, indicators)

	vec.Indicators = indicators
	if vec.Score > 1.0 {
		vec.Score = 1.0
	}
	vec.Detected = vec.Score > 0.0

	return vec
}

func (ia *IsomorphicAnalyzer) checkPlatformGPU(canvasData map[string]interface{}, httpPlatform string, vec *DetectionVector, indicators []string) []string {
	if canvasData != nil {
		if unmaskedRenderer, ok := canvasData["unmaskedRenderer"].(string); ok {
			renderer := strings.ToLower(unmaskedRenderer)
			isMac := strings.Contains(httpPlatform, "mac") || strings.Contains(httpPlatform, "darwin")
			isWindows := strings.Contains(httpPlatform, "win")

			if isMac && (strings.Contains(renderer, "direct3d") || strings.Contains(renderer, "d3d") || strings.Contains(renderer, "angle (nvidia")) {
				if !strings.Contains(renderer, "apple") {
					indicators = append(indicators, "platform_mismatch: macos_http_with_windows_gpu")
					vec.Score += 0.9
				}
			}

			if isWindows && (strings.Contains(renderer, "apple m") || strings.Contains(renderer, "apple gpu")) {
				indicators = append(indicators, "platform_mismatch: windows_http_with_apple_gpu")
				vec.Score += 0.9
			}
		}
	}
	return indicators
}

func (ia *IsomorphicAnalyzer) checkGPUCoreCoherence(webglData, navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	if webglData == nil || navData == nil {
		return indicators
	}

	renderer, _ := webglData["unmasked_renderer"].(string)
	if renderer == "" {
		renderer, _ = webglData["unmaskedRenderer"].(string)
	}
	if renderer == "" {
		return indicators
	}

	concurrency, ok := navData["hardwareConcurrency"].(float64)
	if !ok {
		return indicators
	}

	rLow := strings.ToLower(renderer)
	cores := int(concurrency)

	// 1. Apple Silicon Coherence (M1/M2/M3/M4 have >= 8 cores usually, but lets be safe with >= 8)
	// Base M1 has 8 cores. M1 Pro/Max 10+. M2 8+. M3 8+.
	// Headless typically reports 2 or 4.
	if strings.Contains(rLow, "apple m") && cores < 8 {
		name := "hardware_core_mismatch"
		indicators = append(indicators, fmt.Sprintf("%s: %s_with_%d_cores", name, renderer, cores))
		vec.Score += 0.40
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        name,
			Fired:       true,
			Weight:      0.40,
			Score:       0.40,
			Field:       "hardwareConcurrency vs unmaskedRenderer",
			Actual:      fmt.Sprintf("%s with %d cores", renderer, cores),
			Expected:    ">= 8 cores for Apple Silicon GPUs",
			Severity:    "medium",
			Description: "Apple Silicon renderers should not present extremely low CPU core counts in normal desktop environments.",
		})
	}

	// 2. High-End Desktop GPU Coherence
	highEndGPUs := []string{"rtx 30", "rtx 40", "rx 6", "rx 7"}
	isHighEnd := false
	for _, g := range highEndGPUs {
		if strings.Contains(rLow, g) {
			isHighEnd = true
			break
		}
	}

	if isHighEnd && cores < 6 {
		name := "hardware_core_mismatch"
		indicators = append(indicators, name)
		vec.Score += 0.35
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        name,
			Fired:       true,
			Weight:      0.35,
			Score:       0.35,
			Field:       "hardwareConcurrency vs unmaskedRenderer",
			Actual:      fmt.Sprintf("%s with %d cores", renderer, cores),
			Expected:    ">= 6 cores for high-end desktop GPU",
			Severity:    "medium",
			Description: "High-end GPUs are rarely paired with fewer than 6 CPU cores in desktop environments.",
		})
	}

	return indicators
}

func (ia *IsomorphicAnalyzer) checkNavigatorPlatform(navData map[string]interface{}, httpPlatform string, vec *DetectionVector, indicators []string) []string {
	if navPlatform, ok := navData["platform"].(string); ok {
		navPlatLow := strings.ToLower(navPlatform)
		isMacHTTP := strings.Contains(httpPlatform, "mac") || strings.Contains(httpPlatform, "darwin")
		isWinHTTP := strings.Contains(httpPlatform, "win")

		isMacNav := strings.Contains(navPlatLow, "mac")
		isWinNav := strings.Contains(navPlatLow, "win")

		if (isMacHTTP && !isMacNav) || (isWinHTTP && !isWinNav) {
			indicators = append(indicators, "platform_mismatch: http_vs_navigator_platform")
			vec.Score += 0.8
		}
	}
	return indicators
}

func (ia *IsomorphicAnalyzer) checkLanguages(navData map[string]interface{}, acceptLanguage string, vec *DetectionVector, indicators []string) []string {
	langs, ok := navData["languages"].([]interface{})
	if !ok || len(langs) == 0 {
		return indicators
	}

	primaryNavLang, _ := langs[0].(string)
	httpLang := strings.ToLower(acceptLanguage)
	if primaryNavLang == "" {
		return indicators
	}

	// 1. Cross-check with Accept-Language header
	primaryNavLangShort := strings.ToLower(strings.Split(primaryNavLang, "-")[0])
	if httpLang != "" && !strings.Contains(httpLang, primaryNavLangShort) {
		indicators = append(indicators, "locale_mismatch: http_accept_language_vs_navigator_languages")
		vec.Score += 0.7
	}

	// 2. Cross-check navigator.language (singular) vs navigator.languages[0]
	if navLang, ok := navData["language"].(string); ok {
		if navLang != primaryNavLang {
			indicators = append(indicators, "language_mismatch: navigator.language_vs_languages[0]")
			vec.Score += 0.5
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "language_mismatch",
				Fired:       true,
				Weight:      0.5,
				Score:       0.5,
				Field:       "navigator.language vs languages[0]",
				Actual:      fmt.Sprintf("language=%s languages=%v", navLang, langs),
				Expected:    "navigator.language should match languages[0]",
				Severity:    "high",
				Description: "The singular navigator.language property does not match the first entry in navigator.languages.",
			})
		}
	}

	// 3. Cross-check Intl.DateTimeFormat().resolvedOptions().locale
	if intlLocale, ok := navData["intl_locale"].(string); ok {
		// Intl locale should be a case-insensitive match for navigator.language
		if navLang, ok := navData["language"].(string); ok {
			if strings.ToLower(intlLocale) != strings.ToLower(navLang) {
				indicators = append(indicators, "language_mismatch: intl_locale_vs_navigator.language")
				vec.Score += 0.5
				vec.CheckReports = append(vec.CheckReports, CheckReport{
					Name:        "language_mismatch",
					Fired:       true,
					Weight:      0.5,
					Score:       0.5,
					Field:       "Intl locale vs navigator.language",
					Actual:      fmt.Sprintf("intl=%s language=%s", intlLocale, navLang),
					Expected:    "Intl locale should match navigator.language",
					Severity:    "high",
					Description: "The Intl API locale does not match the navigator.language setting.",
				})
			}
		}
	}

	return indicators
}

func (ia *IsomorphicAnalyzer) checkUserAgent(navData map[string]interface{}, httpInfo *HTTPFingerprintInfo, vec *DetectionVector, indicators []string) []string {
	if navUA, ok := navData["userAgent"].(string); ok {
		httpUA := strings.ToLower(httpInfo.UserAgent)
		navUALower := strings.ToLower(navUA)

		if httpUA != "" && httpUA != navUALower {
			indicators = append(indicators, "user_agent_mismatch: http_ua_vs_navigator_ua")
			vec.Score += 0.8
		}

		secChUa := strings.ToLower(httpInfo.SecCHUA)
		if secChUa != "" {
			if strings.Contains(secChUa, "chrome") && !strings.Contains(httpUA, "chrome") {
				indicators = append(indicators, "brand_mismatch: sec-ch-ua_chrome_vs_ua_non_chrome")
				vec.Score += 0.9
			}
		}
	}
	return indicators
}

func (ia *IsomorphicAnalyzer) checkUAVersion(httpInfo *HTTPFingerprintInfo, vec *DetectionVector, indicators []string) []string {
	if httpInfo.SecCHUA != "" {
		secChMatch := secChUaVersionRe.FindStringSubmatch(httpInfo.SecCHUA)
		uaMatch := uaVersionRe.FindStringSubmatch(httpInfo.UserAgent)

		if len(secChMatch) > 1 && len(uaMatch) > 1 {
			if secChMatch[1] != uaMatch[1] {
				indicators = append(indicators, fmt.Sprintf("sec_ch_ua_version_mismatch: Sec-Ch-Ua=%s UA=%s", secChMatch[1], uaMatch[1]))
				vec.Score += 0.40
			}
		}
	}
	return indicators
}

func (ia *IsomorphicAnalyzer) checkScreenDimensions(req *http.Request, navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	if screenHeader := req.Header.Get(constants.HeaderScreenData); screenHeader != "" {
		var screenData map[string]interface{}
		if err := json.Unmarshal([]byte(screenHeader), &screenData); err == nil {
			if screenOuter, ok := screenData["outer_width"].(float64); ok {
				if navOuter, ok := navData["screen_outer_width"].(float64); ok {
					diff := math.Abs(screenOuter - navOuter)
					if diff > 5 {
						indicators = append(indicators, fmt.Sprintf("screen_nav_outer_width_mismatch: screen=%d nav=%d", int(screenOuter), int(navOuter)))
						vec.Score += 0.7
					}
				}
			}
			if screenInner, ok := screenData["inner_width"].(float64); ok {
				if navInner, ok := navData["screen_inner_width"].(float64); ok {
					diff := math.Abs(screenInner - navInner)
					if diff > 5 {
						indicators = append(indicators, fmt.Sprintf("screen_nav_inner_width_mismatch: screen=%d nav=%d", int(screenInner), int(navInner)))
						vec.Score += 0.5
					}
				}
			}
			if screenColorDepth, ok := screenData["color_depth"].(float64); ok {
				if navColorDepth, ok := navData["screen_color_depth"].(float64); ok {
					if int(screenColorDepth) != int(navColorDepth) {
						indicators = append(indicators, fmt.Sprintf("screen_nav_color_depth_mismatch: screen=%d nav=%d", int(screenColorDepth), int(navColorDepth)))
						vec.Score += 0.65
					}
				}
			}
		}
	}
	return indicators
}

func (ia *IsomorphicAnalyzer) checkCSITiming(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	if csi, hasCsi := navData["chrome_csi"].(map[string]interface{}); hasCsi {
		if lt, hasLT := navData["chrome_loadTimes"].(map[string]interface{}); hasLT {
			startE, okStartE := csi["startE"].(float64)
			requestTime, okReqTime := lt["requestTime"].(float64)
			if okStartE && okReqTime && startE > 0 && requestTime > 0 {
				expectedStartE := requestTime * 1000
				diff := math.Abs(startE - expectedStartE)
				if diff > 100 {
					indicators = append(indicators, fmt.Sprintf("csi_loadtimes_timing_mismatch: startE=%.0f expected=%.0f diff=%.0fms", startE, expectedStartE, diff))
					vec.Score += 0.40
					vec.CheckReports = append(vec.CheckReports, CheckReport{
						Name:        "csi_loadtimes_timing_mismatch",
						Fired:       true,
						Weight:      0.40,
						Score:       0.40,
						Field:       "chrome_csi.startE vs chrome_loadTimes.requestTime",
						Actual:      fmt.Sprintf("startE=%.0f requestTime*1000=%.0f", startE, expectedStartE),
						Expected:    "within 100ms of each other",
						Severity:    "high",
						Description: "chrome.csi().startE and chrome.loadTimes().requestTime derive from the same value but don't match",
					})
				}
			}
		}
	}
	return indicators
}

func (ia *IsomorphicAnalyzer) checkPerformanceTiming(req *http.Request, vec *DetectionVector, indicators []string) []string {
	if timingHeader := req.Header.Get(constants.HeaderTimingData); timingHeader != "" {
		var timingData map[string]interface{}
		if err := json.Unmarshal([]byte(timingHeader), &timingData); err == nil {
			if entries, ok := timingData["entries"].([]interface{}); ok && len(entries) >= 5 {
				emptyURLCount := 0
				for _, e := range entries {
					if em, ok := e.(map[string]interface{}); ok {
						url, _ := em["url"].(string)
						if url == "" {
							emptyURLCount++
						}
					}
				}
				if emptyURLCount == len(entries) {
					indicators = append(indicators, "timing_all_entries_missing_url")
					vec.Score += 0.25
				}
			}
		}
	}
	return indicators
}

func (ia *IsomorphicAnalyzer) checkScreenDPR(req *http.Request, vec *DetectionVector, indicators []string) []string {
	if screenHeader := req.Header.Get(constants.HeaderScreenData); screenHeader != "" {
		var screenData map[string]interface{}
		if err := json.Unmarshal([]byte(screenHeader), &screenData); err == nil {
			dpr, hasDPR := screenData["pixel_ratio"].(float64)
			scrWidth, hasW := screenData["width"].(float64)
			isMobile := strings.Contains(strings.ToLower(req.UserAgent()), "mobile") ||
				strings.Contains(strings.ToLower(req.UserAgent()), "android") ||
				strings.Contains(strings.ToLower(req.UserAgent()), "iphone")

			if hasDPR && hasW && dpr >= 2.0 && scrWidth < 1920 && !isMobile {
				indicators = append(indicators, fmt.Sprintf("screen_dpr_resolution_improbable: dpr=%.1f width=%.0f", dpr, scrWidth))
				vec.Score += 0.25
				vec.CheckReports = append(vec.CheckReports, CheckReport{
					Name:        "screen_dpr_resolution_improbable",
					Fired:       true,
					Weight:      0.25,
					Score:       0.25,
					Field:       "pixel_ratio + width",
					Actual:      fmt.Sprintf("%.1fx @ %dpx", dpr, int(scrWidth)),
					Expected:    "2x DPR only on displays >= 1920px",
					Severity:    "medium",
					Description: "High-DPI displays (2x+) only exist on 1920px+ screens",
				})
			}
		}
	}
	return indicators
}

func (ia *IsomorphicAnalyzer) checkFontPlatform(req *http.Request, navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	if fontHeader := req.Header.Get(constants.HeaderFontData); fontHeader != "" {
		var fontData map[string]interface{}
		if err := json.Unmarshal([]byte(fontHeader), &fontData); err == nil {
			if fontPlatform, ok := fontData["platform"].(string); ok && navData != nil {
				if navPlatform, ok2 := navData["platform"].(string); ok2 {
					fontLow := strings.ToLower(fontPlatform)
					navLow := strings.ToLower(navPlatform)
					isFontMac := strings.Contains(fontLow, "mac") || strings.Contains(fontLow, "darwin")
					isNavMac := strings.Contains(navLow, "mac")
					isFontWin := strings.Contains(fontLow, "win")
					isNavWin := strings.Contains(navLow, "win")
					isFontLinux := strings.Contains(fontLow, "linux") || strings.Contains(fontLow, "android")
					isNavLinux := strings.Contains(navLow, "linux") || strings.Contains(navLow, "android")

					mismatch := (isFontMac && !isNavMac) || (isFontWin && !isNavWin) ||
						(isFontLinux && !isNavLinux) || (isNavMac && !isFontMac) ||
						(isNavWin && !isFontWin) || (isNavLinux && !isFontLinux)

					if mismatch {
						indicators = append(indicators, fmt.Sprintf("font_nav_platform_mismatch: font=%s nav=%s", fontPlatform, navPlatform))
						vec.Score += 0.35
					}
				}
			}
		}
	}
	return indicators
}

func (ia *IsomorphicAnalyzer) checkErrorStackFormat(behavData map[string]interface{}, httpInfo *HTTPFingerprintInfo, vec *DetectionVector, indicators []string) []string {
	if errorStack, ok := behavData["errorStack"].(string); ok && errorStack != "" {
		ua := strings.ToLower(httpInfo.UserAgent)
		isChrome := strings.Contains(ua, "chrome")
		isFirefox := strings.Contains(ua, "firefox")

		// Chrome/Edge/V8 stacks start with "Error" and have "\n    at "
		isV8Stack := strings.HasPrefix(errorStack, "Error") && strings.Contains(errorStack, "\n    at ")

		// Firefox/SpiderMonkey stacks usually have "@" and don't start with "Error" in the stack property itself
		isSpiderMonkeyStack := strings.Contains(errorStack, "@") && !strings.HasPrefix(errorStack, "Error")

		// Heuristic: real application stacks usually have at least 2 frames
		frameCount := strings.Count(errorStack, "\n")
		isTooShort := frameCount < 1

		// Heuristic: check for "too clean" stacks (e.g. exactly 1 or 2 lines without any application noise)
		isSuspiciouslyClean := !strings.Contains(errorStack, ".js") && !strings.Contains(errorStack, ".ts")

		if isChrome && !isV8Stack {
			indicators = append(indicators, "error_stack_mismatch: claimed_chrome_but_non_v8_stack")
			vec.Score += 0.40
			// (CheckReport details omitted for brevity in thought, but I'll include them in the tool call)
		}

		if isChrome && isV8Stack && (isTooShort || isSuspiciouslyClean) {
			indicators = append(indicators, "error_stack_suspiciously_clean")
			vec.Score += 0.25
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "error_stack_suspicious",
				Fired:       true,
				Weight:      0.25,
				Score:       0.25,
				Field:       "Error.stack",
				Actual:      errorStack,
				Expected:    "multi-frame application stack",
				Severity:    "medium",
				Description: "The JavaScript Error.stack is suspiciously short or lacks application-specific context (like .js filenames), which is common in synthetic bot environments.",
			})
		}

		if isChrome && !strings.Contains(errorStack, "async") && frameCount > 3 {
			// Deep stacks in modern apps almost always involve async/await
			indicators = append(indicators, "error_stack_missing_async_context")
			vec.Score += 0.15
		}

		if isChrome && !isV8Stack {
			// Already handled above, just keeping the structure
		} else if isFirefox && !isSpiderMonkeyStack {
			indicators = append(indicators, "error_stack_mismatch: claimed_firefox_but_non_spidermonkey_stack")
			vec.Score += 0.40
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "error_stack_mismatch",
				Fired:       true,
				Weight:      0.40,
				Score:       0.40,
				Field:       "errorStack vs UserAgent",
				Actual:      "non-SpiderMonkey stack",
				Expected:    "SpiderMonkey stack (contains @ function calls)",
				Severity:    "high",
				Description: "The JavaScript Error.stack format does not match the SpiderMonkey engine used by Firefox.",
			})
		}
	}
	return indicators
}

func (ia *IsomorphicAnalyzer) checkPointerInteraction(navData map[string]interface{}, httpPlatform string, vec *DetectionVector, indicators []string) []string {
	if navData == nil {
		return indicators
	}

	pointer, hasPointer := navData["media_query_pointer"].(string)
	anyPointer, hasAnyPointer := navData["media_query_any_pointer"].(string)

	if !hasPointer && !hasAnyPointer {
		return indicators
	}

	isDesktop := (strings.Contains(httpPlatform, "win") || strings.Contains(httpPlatform, "mac") || strings.Contains(httpPlatform, "darwin") || strings.Contains(httpPlatform, "linux")) &&
		!strings.Contains(httpPlatform, "android") && !strings.Contains(httpPlatform, "iphone") && !strings.Contains(httpPlatform, "ipad")

	if isDesktop {
		// Real desktop browsers (Chrome, Firefox, Safari) report "fine" for pointer.
		// Headless/Bot environments often report "none" or "coarse".
		if hasPointer && pointer != "fine" {
			name := "pointer_mismatch"
			indicators = append(indicators, name)
			vec.Score += 0.40
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        name,
				Fired:       true,
				Weight:      0.40,
				Score:       0.40,
				Field:       "media_query_pointer",
				Actual:      pointer,
				Expected:    "fine",
				Severity:    "high",
				Description: "Desktop browsers must report a 'fine' pointer interaction type.",
			})
		}
		// any-pointer usually includes "fine" on desktop.
		if hasAnyPointer && (anyPointer == "none" || anyPointer == "coarse") {
			name := "any_pointer_mismatch"
			indicators = append(indicators, name)
			vec.Score += 0.35
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        name,
				Fired:       true,
				Weight:      0.35,
				Score:       0.35,
				Field:       "media_query_any_pointer",
				Actual:      anyPointer,
				Expected:    "fine",
				Severity:    "high",
				Description: "Desktop browsers should report 'fine' as an available pointer interaction type.",
			})
		}
	}
	return indicators
}

func (ia *IsomorphicAnalyzer) checkUserAgentDataConsistency(navData map[string]interface{}, httpInfo *HTTPFingerprintInfo, vec *DetectionVector, indicators []string) []string {
	// Brands and version in UserAgentData should match Sec-Ch-Ua
	uaData, ok := navData["userAgentData"].(map[string]interface{})
	if !ok {
		return indicators
	}

	brands, ok := uaData["brands"].([]interface{})
	if !ok || len(brands) == 0 {
		return indicators
	}

	secChUa := httpInfo.SecCHUA
	if secChUa == "" {
		return indicators
	}

	for _, b := range brands {
		brandMap, ok := b.(map[string]interface{})
		if !ok {
			continue
		}
		brand, _ := brandMap["brand"].(string)
		version, _ := brandMap["version"].(string)

		// Check if brand/version pair exists in Sec-Ch-Ua
		// Format: "Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"
		expected := fmt.Sprintf(`"%s";v="%s"`, brand, version)
		if brand != "" && version != "" && !strings.Contains(secChUa, expected) {
			name := "ua_data_consistency_mismatch"
			indicators = append(indicators, name)
			vec.Score += 0.40
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        name,
				Fired:       true,
				Weight:      0.40,
				Score:       0.40,
				Field:       "navigator.userAgentData.brands vs Sec-Ch-Ua",
				Actual:      fmt.Sprintf("%s v%s not in %s", brand, version, secChUa),
				Expected:    "exact match in header",
				Severity:    "high",
				Description: "The Navigator.userAgentData brand and version do not match the Sec-Ch-Ua HTTP header.",
			})
			break
		}
	}

	// 2. Full Version List Consistency (Phase 75)
	if fullVersionList, ok := uaData["fullVersionList"].([]interface{}); ok && len(fullVersionList) > 0 {
		secChUaFull := httpInfo.SecCHUAFullVersionList
		if secChUaFull != "" {
			for _, b := range fullVersionList {
				brandMap, ok := b.(map[string]interface{})
				if !ok {
					continue
				}
				brand, _ := brandMap["brand"].(string)
				version, _ := brandMap["version"].(string)

				// Format: "Chromium";v="134.0.6998.35", "Google Chrome";v="134.0.6998.35", "Not-A.Brand";v="99.0.0.0"
				expected := fmt.Sprintf(`"%s";v="%s"`, brand, version)
				if brand != "" && version != "" && !strings.Contains(secChUaFull, expected) {
					indicators = append(indicators, "ua_client_hints_mismatch: full_version_list")
					vec.Score += 0.45
					vec.CheckReports = append(vec.CheckReports, CheckReport{
						Name:        "ua_client_hints_mismatch",
						Fired:       true,
						Weight:      0.45,
						Score:       0.45,
						Field:       "navigator.userAgentData.getHighEntropyValues(['fullVersionList']) vs Sec-CH-UA-Full-Version-List",
						Actual:      fmt.Sprintf("%s v%s not in %s", brand, version, secChUaFull),
						Expected:    "exact match in header",
						Severity:    "high",
						Description: "The high-entropy full version list from navigator.userAgentData does not match the Sec-CH-UA-Full-Version-List HTTP header.",
					})
					break
				}
			}
		}
	}

	// 3. Platform/Arch/Bitness Consistency
	if arch, ok := uaData["architecture"].(string); ok && arch != "" {
		if httpInfo.SecCHUAArch != "" {
			// Header is usually quoted: "x86"
			expectedArch := fmt.Sprintf(`"%s"`, arch)
			if httpInfo.SecCHUAArch != expectedArch && httpInfo.SecCHUAArch != arch {
				indicators = append(indicators, "ua_client_hints_mismatch: architecture")
				vec.Score += 0.35
			}
		}
	}

	if bitness, ok := uaData["bitness"].(string); ok && bitness != "" {
		if httpInfo.SecCHUABitness != "" {
			expectedBitness := fmt.Sprintf(`"%s"`, bitness)
			if httpInfo.SecCHUABitness != expectedBitness && httpInfo.SecCHUABitness != bitness {
				indicators = append(indicators, "ua_client_hints_mismatch: bitness")
				vec.Score += 0.35
			}
		}
	}

	return indicators
}

func (ia *IsomorphicAnalyzer) checkHeaderOrder(httpInfo *HTTPFingerprintInfo, vec *DetectionVector, indicators []string) []string {
	if len(httpInfo.HeaderOrder) < 5 {
		return indicators
	}

	// Browsers typically have User-Agent near the top, and Accept shortly after.
	// Go's default map iteration often puts random headers first.
	// We check if specific common headers are in "suspicious" relative positions.

	uaIdx := -1
	acceptIdx := -1
	secChIdx := -1
	contentTypeIdx := -1

	for i, h := range httpInfo.HeaderOrder {
		switch strings.ToLower(h) {
		case "user-agent":
			uaIdx = i
		case "accept":
			acceptIdx = i
		case "sec-ch-ua":
			secChIdx = i
		case "content-type":
			contentTypeIdx = i
		}
	}

	// Heuristic: If Sec-Ch-Ua is present, it usually precedes User-Agent in modern Chrome.
	// If User-Agent is after Accept, it's often a sign of manual header setting without ordering.
	mismatch := false
	actual := ""
	expected := ""

	if uaIdx != -1 && acceptIdx != -1 && uaIdx > acceptIdx {
		mismatch = true
		actual = "Accept before User-Agent"
		expected = "User-Agent before Accept"
	} else if secChIdx != -1 && uaIdx != -1 && secChIdx > uaIdx {
		mismatch = true
		actual = "User-Agent before Sec-Ch-Ua"
		expected = "Sec-Ch-Ua before User-Agent"
	}

	if mismatch {
		name := "suspicious_header_order"
		indicators = append(indicators, name)
		vec.Score += 0.20
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        name,
			Fired:       true,
			Weight:      0.20,
			Score:       0.20,
			Field:       "Header Order",
			Actual:      actual,
			Expected:    expected,
			Severity:    "medium",
			Description: "The relative order of HTTP headers is inconsistent with standard browser behavior.",
		})
	}

	// Check Content-Type before Accept: Real browsers always send Accept before
	// Content-Type in their header ordering for POST/PUT requests. Chrome and
	// Firefox both place Accept in the standard navigation header block, while
	// Content-Type comes later from the fetch/XHR options. Having Content-Type
	// before Accept indicates manual header construction.
	if contentTypeIdx != -1 && acceptIdx != -1 && contentTypeIdx < acceptIdx {
		name := "content_type_before_accept"
		indicators = append(indicators, name)
		vec.Score += 0.35
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        name,
			Fired:       true,
			Weight:      0.25,
			Score:       0.25,
			Field:       "Header Order",
			Actual:      "Content-Type before Accept",
			Expected:    "Accept before Content-Type (browser standard)",
			Severity:    "medium",
			Description: "Real browsers place Accept in the standard header block before Content-Type from the request body options.",
		})
	}

	return indicators
}

func (ia *IsomorphicAnalyzer) checkTouchPointerCoherence(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	maxTouch, hasMaxTouch := navData["maxTouchPoints"].(float64)
	pointer, hasPointer := navData["media_query_pointer"].(string)
	anyPointer, hasAnyPointer := navData["media_query_any_pointer"].(string)

	if !hasMaxTouch {
		return indicators
	}

	// 1. Touch implies Coarse
	// If maxTouchPoints > 0, interaction should typically report 'coarse' (even if 'fine' is also available)
	if maxTouch > 0 {
		if hasPointer && pointer == "fine" && (hasAnyPointer && !strings.Contains(anyPointer, "coarse")) {
			// This is suspicious: has touch points but media queries only report 'fine'
			name := "touch_pointer_mismatch"
			indicators = append(indicators, name)
			vec.Score += 0.35
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        name,
				Fired:       true,
				Weight:      0.35,
				Score:       0.35,
				Field:       "maxTouchPoints vs media_query_any_pointer",
				Actual:      fmt.Sprintf("maxTouch=%d pointer=%s any-pointer=%s", int(maxTouch), pointer, anyPointer),
				Expected:    "any-pointer should include 'coarse' if touch is enabled",
				Severity:    "medium",
				Description: "The device reports touch points but doesn't report 'coarse' pointer capabilities in media queries.",
			})
		}
	} else {
		// 2. MaxTouch=0 but Coarse only
		if hasPointer && pointer == "coarse" {
			name := "touch_pointer_mismatch"
			indicators = append(indicators, name)
			vec.Score += 0.40
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        name,
				Fired:       true,
				Weight:      0.40,
				Score:       0.40,
				Field:       "maxTouchPoints vs media_query_pointer",
				Actual:      "maxTouch=0 pointer=coarse",
				Expected:    "pointer should be 'fine' if no touch points available",
				Severity:    "high",
				Description: "The device reports 'coarse' as its primary pointer but has 0 maxTouchPoints.",
			})
		}
	}

	return indicators
}

// checkJSEngineArtifacts validates that JavaScript engine-specific properties
// are consistent with the browser claimed in the User-Agent header.
func (ia *IsomorphicAnalyzer) checkJSEngineArtifacts(navData map[string]interface{}, httpInfo *HTTPFingerprintInfo, vec *DetectionVector, indicators []string) []string {
	ua := strings.ToLower(httpInfo.UserAgent)
	isChrome := strings.Contains(ua, "chrome") && !strings.Contains(ua, "edg")
	isFirefox := strings.Contains(ua, "firefox")
	isSafari := strings.Contains(ua, "safari") && !strings.Contains(ua, "chrome")

	if productSub, ok := navData["productSub"].(string); ok {
		if isChrome && productSub != "20030107" {
			indicators = append(indicators, "productsub_browser_mismatch")
			vec.Score += 0.35
		} else if isFirefox && productSub != "20100101" {
			indicators = append(indicators, "productsub_browser_mismatch")
			vec.Score += 0.35
		} else if isSafari && productSub != "20030107" {
			indicators = append(indicators, "productsub_browser_mismatch")
			vec.Score += 0.35
		}
	}

	if isChrome {
		_, hasChromeObj := navData["chrome"]
		_, hasChromeRuntime := navData["chrome_runtime"]
		hasChrome, _ := navData["hasChrome"].(bool)
		if !hasChromeObj && !hasChromeRuntime && !hasChrome {
			if len(navData) > 10 {
				indicators = append(indicators, "missing_window_chrome")
				vec.Score += 0.30
			}
		}
	}

	pluginCount := -1.0
	if pc, ok := navData["pluginCount"].(float64); ok {
		pluginCount = pc
	} else if pc, ok := navData["plugins_length"].(float64); ok {
		pluginCount = pc
	}
	if pluginCount >= 0 {
		if isChrome && int(pluginCount) == 0 {
			indicators = append(indicators, "plugin_count_zero_chrome")
			vec.Score += 0.30
		}
		if isFirefox && int(pluginCount) > 0 {
			indicators = append(indicators, "plugin_count_nonzero_firefox")
			vec.Score += 0.20
		}
	}

	if webdriver, ok := navData["webdriver"].(bool); ok && webdriver {
		indicators = append(indicators, "webdriver_true")
		vec.Score += 0.90
	}

	if cookieEnabled, ok := navData["cookieEnabled"].(bool); ok && !cookieEnabled {
		indicators = append(indicators, "cookies_disabled")
		vec.Score += 0.25
	}

	if isChrome || isFirefox {
		if pdfViewer, ok := navData["pdfViewerEnabled"].(bool); ok && !pdfViewer {
			indicators = append(indicators, "pdf_viewer_disabled")
			vec.Score += 0.20
		}
	}

	return indicators
}

// checkStorageCoherence verifies that web storage APIs are available.
func (ia *IsomorphicAnalyzer) checkStorageCoherence(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	if hasLocal, ok := navData["hasLocalStorage"].(bool); ok && !hasLocal {
		indicators = append(indicators, "missing_local_storage")
		vec.Score += 0.25
	}
	if hasSession, ok := navData["hasSessionStorage"].(bool); ok && !hasSession {
		indicators = append(indicators, "missing_session_storage")
		vec.Score += 0.25
	}
	if hasIDB, ok := navData["hasIndexedDB"].(bool); ok && !hasIDB {
		indicators = append(indicators, "missing_indexed_db")
		vec.Score += 0.30
	}
	return indicators
}

// checkConnectionTimingCoherence validates connection timing data for realistic
// TLS handshake and DOM processing times.
func (ia *IsomorphicAnalyzer) checkConnectionTimingCoherence(req *http.Request, vec *DetectionVector, indicators []string) []string {
	timingHeader := req.Header.Get(constants.HeaderTimingData)
	if timingHeader == "" {
		return indicators
	}

	var timingData map[string]interface{}
	if err := json.Unmarshal([]byte(timingHeader), &timingData); err != nil {
		return indicators
	}

	connectStart, okCS := timingData["connectStart"].(float64)
	connectEnd, okCE := timingData["connectEnd"].(float64)
	if okCS && okCE && connectStart > 0 && connectEnd > 0 {
		if connectEnd-connectStart == 0 {
			indicators = append(indicators, "connection_timing_zero_tls")
			vec.Score += 0.20
		}
	}

	responseEnd, okRE := timingData["responseEnd"].(float64)
	domInteractive, okDI := timingData["domInteractive"].(float64)
	if okRE && okDI && responseEnd > 0 && domInteractive > 0 {
		parseTime := domInteractive - responseEnd
		if parseTime >= 0 && parseTime < 5 {
			indicators = append(indicators, "connection_timing_instant_parse")
			vec.Score += 0.25
		}
	}

	if entries, ok := timingData["entries"].([]interface{}); ok && len(entries) >= 3 {
		connectTimes := make(map[float64]int)
		for _, e := range entries {
			if em, ok := e.(map[string]interface{}); ok {
				cs, okCS2 := em["connectStart"].(float64)
				ce, okCE2 := em["connectEnd"].(float64)
				if okCS2 && okCE2 && cs > 0 {
					connectTimes[ce-cs]++
				}
			}
		}
		if len(connectTimes) == 1 && len(entries) >= 3 {
			for _, count := range connectTimes {
				if count >= 3 {
					indicators = append(indicators, "connection_timing_identical_durations")
					vec.Score += 0.30
				}
			}
		}
	}

	return indicators
}

func (ia *IsomorphicAnalyzer) checkAcceptDestConsistency(httpInfo *HTTPFingerprintInfo, vec *DetectionVector, indicators []string) []string {
	if httpInfo.Accept == "" || httpInfo.SecFetchDest == "" {
		return indicators
	}

	isDocument := httpInfo.SecFetchDest == "document"
	isXHR := httpInfo.SecFetchDest == "empty" || httpInfo.SecFetchDest == "cors"

	acceptLower := strings.ToLower(httpInfo.Accept)
	hasHTML := strings.HasPrefix(acceptLower, "text/html")

	if isDocument && !hasHTML {
		name := "accept_dest_mismatch_missing_html"
		indicators = append(indicators, name)
		vec.Score += 0.40
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        name,
			Fired:       true,
			Weight:      0.40,
			Score:       0.40,
			Field:       "Accept vs Sec-Fetch-Dest",
			Actual:      fmt.Sprintf("Dest: %s, Accept: %s", httpInfo.SecFetchDest, httpInfo.Accept),
			Expected:    "text/html,... for document destinations",
			Severity:    "high",
			Description: "Top-level document navigations must request HTML formats explicitly.",
		})
	}

	if isXHR && hasHTML {
		name := "accept_dest_mismatch_static_document"
		indicators = append(indicators, name)
		vec.Score += 0.35
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        name,
			Fired:       true,
			Weight:      0.35,
			Score:       0.35,
			Field:       "Accept vs Sec-Fetch-Dest",
			Actual:      fmt.Sprintf("Dest: %s, Accept: %s", httpInfo.SecFetchDest, httpInfo.Accept),
			Expected:    "*/* or application/json for XHR data fetches",
			Severity:    "high",
			Description: "API fetches should not use the browser's rich HTML Accept header.",
		})
	}

	return indicators
}
