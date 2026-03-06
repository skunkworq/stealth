package adversarial

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/skunkworq/stealth/brws/constants"
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
		_ = json.Unmarshal([]byte(navHeader), &navData)
	}

	var canvasData map[string]interface{}
	if canvasHeader := req.Header.Get(constants.HeaderCanvasFingerprint); canvasHeader != "" {
		_ = json.Unmarshal([]byte(canvasHeader), &canvasData)
	}

	indicators := make([]string, 0)

	httpPlatform := strings.ToLower(httpInfo.Platform)
	if httpInfo.SecCHUAPlatform != "" {
		httpPlatform = strings.ToLower(httpInfo.SecCHUAPlatform)
	}

	indicators = ia.checkPlatformGPU(canvasData, httpPlatform, vec, indicators)
	
	if navData != nil {
		indicators = ia.checkNavigatorPlatform(navData, httpPlatform, vec, indicators)
		indicators = ia.checkLanguages(navData, httpInfo.AcceptLanguage, vec, indicators)
		indicators = ia.checkUserAgent(navData, httpInfo, vec, indicators)
		indicators = ia.checkUAVersion(httpInfo, vec, indicators)
		indicators = ia.checkScreenDimensions(req, navData, vec, indicators)
		indicators = ia.checkCSITiming(navData, vec, indicators)
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
	if langs, ok := navData["languages"].([]interface{}); ok {
		if len(langs) > 0 {
			primaryNavLang, _ := langs[0].(string)
			httpLang := strings.ToLower(acceptLanguage)
			if primaryNavLang != "" {
				primaryNavLang = strings.ToLower(strings.Split(primaryNavLang, "-")[0])
				if httpLang != "" && !strings.Contains(httpLang, primaryNavLang) {
					indicators = append(indicators, "locale_mismatch: http_accept_language_vs_navigator_languages")
					vec.Score += 0.7
				}
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
		secChUaVersionRe := regexp.MustCompile(`"Google Chrome";v="(\d+)"`)
		uaVersionRe := regexp.MustCompile(`Chrome/(\d+)`)

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
		if json.Unmarshal([]byte(screenHeader), &screenData) == nil {
			if screenOuter, ok := screenData["outer_width"].(float64); ok {
				if navOuter, ok := navData["screen_outer_width"].(float64); ok {
					diff := screenOuter - navOuter
					if diff < 0 {
						diff = -diff
					}
					if diff > 5 {
						indicators = append(indicators, fmt.Sprintf("screen_nav_outer_width_mismatch: screen=%d nav=%d", int(screenOuter), int(navOuter)))
						vec.Score += 0.7
					}
				}
			}
			if screenInner, ok := screenData["inner_width"].(float64); ok {
				if navInner, ok := navData["screen_inner_width"].(float64); ok {
					diff := screenInner - navInner
					if diff < 0 {
						diff = -diff
					}
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
				diff := startE - expectedStartE
				if diff < 0 {
					diff = -diff
				}
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
		if json.Unmarshal([]byte(timingHeader), &timingData) == nil {
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
		if json.Unmarshal([]byte(screenHeader), &screenData) == nil {
			dpr, hasDPR := screenData["pixel_ratio"].(float64)
			scrWidth, hasW := screenData["width"].(float64)
			if hasDPR && hasW && dpr >= 2.0 && scrWidth < 1920 {
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
		if json.Unmarshal([]byte(fontHeader), &fontData) == nil {
			if fontPlatform, ok := fontData["platform"].(string); ok && navData != nil {
				if navPlatform, ok2 := navData["platform"].(string); ok2 {
					fontLow := strings.ToLower(fontPlatform)
					navLow := strings.ToLower(navPlatform)
					isFontMac := strings.Contains(fontLow, "mac") || strings.Contains(fontLow, "darwin")
					isNavMac := strings.Contains(navLow, "mac")
					isFontWin := strings.Contains(fontLow, "win")
					isNavWin := strings.Contains(navLow, "win")
					isFontLinux := strings.Contains(fontLow, "linux")
					isNavLinux := strings.Contains(navLow, "linux")

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
