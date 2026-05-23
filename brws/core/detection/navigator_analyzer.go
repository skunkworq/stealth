package detection

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/skunkworq/stealth/brws/core/constants"
)

// navigatorAnalyzer handles detection of automation via navigator object properties.
type navigatorAnalyzer struct{}

// newNavigatorAnalyzer creates a new instance of navigatorAnalyzer.
func newNavigatorAnalyzer() *navigatorAnalyzer {
	return &navigatorAnalyzer{}
}

// Analyze performs deep analysis of navigator properties sent via custom headers.
func (na *navigatorAnalyzer) Analyze(req *http.Request) *DetectionVector {
	navHeader := req.Header.Get(constants.HeaderNavigatorData)
	if navHeader == "" {
		return nil
	}

	vec := &DetectionVector{
		Name:        "Navigator Properties",
		Category:    "navigator",
		Weight:      0.2,
		Description: "Analyzes navigator object properties for automation detection",
	}

	var navData map[string]interface{}
	if err := json.Unmarshal([]byte(navHeader), &navData); err != nil {
		return nil
	}

	indicators := make([]string, 0)
	reqUA := req.Header.Get("User-Agent")

	indicators = na.checkWebdriver(navData, vec, indicators)
	indicators = na.checkChromeRuntime(navData, vec, indicators, reqUA)
	indicators = na.checkAudioLatency(req, vec, indicators)
	indicators = na.checkAudioBaseLatency(req, vec, indicators)
	indicators = na.checkAutomationFlags(navData, vec, indicators)
	indicators = na.checkMandatoryProperties(navData, vec, indicators)
	indicators = na.checkAppVersion(navData, vec, indicators)
	indicators = na.checkPDFViewer(navData, vec, indicators)
	indicators = na.checkHardwareCoherence(navData, vec, indicators)
	indicators = na.checkTimezone(navData, vec, indicators)

	// Auxiliary checks
	indicators = na.checkNetworkInformation(navData, vec, indicators)
	indicators = na.checkPluginsArray(navData, vec, indicators)
	indicators = na.checkScreenGeometry(navData, vec, indicators)
	indicators = na.checkScreenOrientation(navData, vec, indicators)
	indicators = na.checkVideoElement(navData, vec, indicators)
	indicators = na.checkPermissionsAPI(navData, vec, indicators)
	indicators = na.checkTimezoneParity(navData, vec, indicators)
	indicators = na.checkKeyboardAPI(navData, vec, indicators, reqUA)
	indicators = na.checkVendor(navData, vec, indicators, reqUA)
	indicators = na.checkNetworkCoherence(navData, vec, indicators)
	indicators = na.checkNotificationPermission(navData, vec, indicators)
	indicators = na.checkMediaQueryHover(navData, vec, indicators, reqUA)
	indicators = na.checkWebGPUSupport(navData, vec, indicators, reqUA)
	indicators = na.checkPermissionsExtended(navData, vec, indicators)
	indicators = na.checkBatteryStatus(navData, vec, indicators)
	indicators = na.checkStorageQuota(navData, vec, indicators)
	indicators = na.checkStorageQuotaCoherence(navData, vec, indicators)
	indicators = na.checkStoragePersistence(navData, vec, indicators)
	indicators = na.checkMediaDevices(navData, vec, indicators)
	indicators = na.checkWebRTC(navData, vec, indicators, reqUA)
	indicators = na.checkUserAgentData(navData, vec, indicators, req)
	indicators = na.checkMaxTouchPointsConsistency(navData, vec, indicators, reqUA)
	indicators = na.checkUserActivation(navData, vec, indicators, reqUA)
	indicators = na.checkSchedulingAPI(navData, vec, indicators, reqUA)
	indicators = na.checkLocksAPI(navData, vec, indicators, reqUA)
	indicators = na.checkIntlConsistency(navData, vec, indicators)
	indicators = na.checkMemoryPlausibility(navData, vec, indicators)
	indicators = na.checkAutomationLeaks(navData, vec, indicators)
	indicators = na.checkAudioWorklet(navData, vec, indicators, reqUA)
	indicators = na.checkNavigatorVibrate(navData, vec, indicators)
	indicators = na.checkNavigatorConnectivity(navData, vec, indicators)
	indicators = na.checkNavigatorHardwareAPIs(navData, vec, indicators)
	indicators = na.checkNavigatorModernAPIs(navData, vec, indicators)
	indicators = na.checkNavigatorMediaAPIs(navData, vec, indicators)
	indicators = na.checkNavigatorWorkers(navData, vec, indicators)
	indicators = na.checkGamepadAPI(navData, vec, indicators)
	indicators = na.checkNavigatorPrototype(navData, vec, indicators)
	indicators = na.checkWorkerContextCoherence(navData, vec, indicators)
	indicators = na.checkRuntimeIntrospection(navData, vec, indicators)
	indicators = na.checkCanvasMeasureText(navData, vec, indicators)
	indicators = na.checkMathPrecision(navData, vec, indicators)

	// Browser-mode stealth detection
	indicators = na.checkPluginAnachronism(navData, vec, indicators, reqUA)
	indicators = na.checkLoadTimesFirstPaintAfterLoad(navData, vec, indicators)
	indicators = na.checkGeometryGapSignature(navData, vec, indicators)
	indicators = na.checkToStringOverride(navData, vec, indicators)

	vec.Indicators = indicators
	vec.Detected = len(indicators) > 0
	return vec
}

func (na *navigatorAnalyzer) checkUserAgentData(navData map[string]interface{}, vec *DetectionVector, indicators []string, req *http.Request) []string {
	uaData, hasUAData := navData["userAgentData"].(map[string]interface{})
	isChrome := strings.Contains(strings.ToLower(req.Header.Get("User-Agent")), "chrome")

	if isChrome && !hasUAData {
		indicators = append(indicators, "missing_navigator_userAgentData")
		vec.Score += 0.35
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        "missing_navigator_userAgentData",
			Fired:       true,
			Weight:      0.35,
			Score:       0.35,
			Field:       "navigator.userAgentData",
			Actual:      "absent",
			Expected:    "present (for Chrome)",
			Severity:    "high",
			Description: "Modern Chromium browsers always expose navigator.userAgentData for Client Hints parity.",
		})
	}

	if hasUAData {
		// Cross-check platform with Sec-CH-UA-Platform header if present
		if platform, ok := uaData["platform"].(string); ok {
			chPlatform := req.Header.Get("Sec-CH-UA-Platform")
			if chPlatform != "" {
				trimmedCH := strings.Trim(chPlatform, "\"")
				if !strings.EqualFold(platform, trimmedCH) {
					indicators = na.addindicator(vec, indicators, "inconsistent_userAgentData_platform", 0.40, "userAgentData.platform", platform, trimmedCH, "high", "Navigator userAgentData.platform does not match Sec-CH-UA-Platform header.")
				}
			}
		}

		// Phase 96: check architecture
		if arch, ok := uaData["architecture"].(string); ok {
			chArch := req.Header.Get("Sec-CH-UA-Arch")
			if chArch != "" {
				trimmedCH := strings.Trim(chArch, "\"")
				if !strings.EqualFold(arch, trimmedCH) {
					indicators = na.addindicator(vec, indicators, "inconsistent_userAgentData_arch", 0.30, "userAgentData.architecture", arch, trimmedCH, "medium", "Navigator userAgentData.architecture does not match Sec-CH-UA-Arch header.")
				}
			}
		}

		// Phase 96: check bitness
		if bitness, ok := uaData["bitness"].(string); ok {
			chBitness := req.Header.Get("Sec-CH-UA-Bitness")
			if chBitness != "" {
				trimmedCH := strings.Trim(chBitness, "\"")
				if bitness != trimmedCH {
					indicators = na.addindicator(vec, indicators, "inconsistent_userAgentData_bitness", 0.30, "userAgentData.bitness", bitness, trimmedCH, "medium", "Navigator userAgentData.bitness does not match Sec-CH-UA-Bitness header.")
				}
			}
		}

		// Phase 96: check fullVersionList correlation
		if fullVersionList, ok := uaData["fullVersionList"].([]interface{}); ok {
			chFullVersion := req.Header.Get("Sec-CH-UA-Full-Version-List")
			if chFullVersion != "" {
				// We won't do a perfect string match because order might vary,
				// but we'll check if the brands and full versions exist.
				for _, brand := range fullVersionList {
					if bMap, ok := brand.(map[string]interface{}); ok {
						bName, _ := bMap["brand"].(string)
						bVersion, _ := bMap["version"].(string)
						if bName != "" && bVersion != "" {
							if !strings.Contains(chFullVersion, fmt.Sprintf("\"%s\";v=\"%s\"", bName, bVersion)) {
								indicators = na.addindicator(vec, indicators, "inconsistent_userAgentData_fullVersionList", 0.40, "userAgentData.fullVersionList", fmt.Sprintf("%s:%s", bName, bVersion), "present in header", "high", "Navigator userAgentData.fullVersionList contains brands not present in Sec-CH-UA-Full-Version-List header.")
								break
							}
						}
					}
				}
			}
		}
	}

	return indicators
}

func (na *navigatorAnalyzer) addindicator(vec *DetectionVector, indicators []string, name string, score float64, field, actual, expected, severity, desc string) []string {
	indicators = append(indicators, name)
	vec.Score += score
	vec.CheckReports = append(vec.CheckReports, CheckReport{
		Name:        name,
		Fired:       true,
		Weight:      score,
		Score:       score,
		Field:       field,
		Actual:      actual,
		Expected:    expected,
		Severity:    severity,
		Description: desc,
	})
	return indicators
}

// --- Browser-Mode Stealth Detection ---

// checkPluginAnachronism detects plugins that no longer exist in modern Chrome.
// Native Client was removed from Chrome 87+ (2020). Claiming it with Chrome 120+
// is a dead giveaway of a stealth script using outdated plugin lists.
func (na *navigatorAnalyzer) checkPluginAnachronism(navData map[string]interface{}, vec *DetectionVector, indicators []string, reqUA string) []string {
	if !strings.Contains(strings.ToLower(reqUA), "chrome") {
		return indicators
	}

	// Check for plugin names via structured data
	if plugins, ok := navData["plugins"].([]interface{}); ok {
		hasNativeClient := false
		hasBothPDFVariants := false
		chromePDF := false
		chromiumPDF := false

		for _, p := range plugins {
			pm, ok := p.(map[string]interface{})
			if !ok {
				continue
			}
			name, _ := pm["name"].(string)
			switch name {
			case "Native Client":
				hasNativeClient = true
			case "Chrome PDF Plugin":
				chromePDF = true
			case "Chromium PDF Plugin":
				chromiumPDF = true
			}
		}

		hasBothPDFVariants = chromePDF && chromiumPDF

		if hasNativeClient {
			indicators = append(indicators, "plugin_anachronism_native_client")
			vec.Score += 0.45
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:     "plugin_anachronism_native_client",
				Fired:    true,
				Weight:   0.45,
				Score:    0.45,
				Field:    "navigator.plugins",
				Actual:   "Native Client present",
				Expected: "absent in Chrome 87+",
				Severity: "high",
				Description: "Native Client plugin was removed from Chrome 87 (2020). " +
					"Its presence with a modern Chrome UA indicates a stealth injection script.",
			})
		}

		if hasBothPDFVariants {
			indicators = append(indicators, "plugin_dual_pdf_signature")
			vec.Score += 0.35
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "plugin_dual_pdf_signature",
				Fired:       true,
				Weight:      0.35,
				Score:       0.35,
				Field:       "navigator.plugins",
				Actual:      "both Chrome PDF Plugin and Chromium PDF Plugin",
				Expected:    "only one PDF plugin variant",
				Severity:    "high",
				Description: "Real Chrome has only one PDF plugin. Having both Chrome and Chromium PDF variants is a known stealth kit signature.",
			})
		}
	}

	// Also check plugin_names array if sent as flat list
	if names, ok := navData["plugin_names"].([]interface{}); ok {
		for _, n := range names {
			if name, ok := n.(string); ok && name == "Native Client" {
				indicators = append(indicators, "plugin_anachronism_native_client")
				vec.Score += 0.45
				break
			}
		}
	}

	return indicators
}

// checkLoadTimesFirstPaintAfterLoad detects spoofed chrome.loadTimes() where
// firstPaintAfterLoadTime is always 0. In real Chrome, this value is non-zero
// when a paint occurs after the load event.
func (na *navigatorAnalyzer) checkLoadTimesFirstPaintAfterLoad(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	lt, ok := navData["chrome_loadTimes"].(map[string]interface{})
	if !ok {
		return indicators
	}

	fpal, hasFPAL := lt["firstPaintAfterLoadTime"].(float64)
	finishT, hasFinish := lt["finishLoadTime"].(float64)

	// firstPaintAfterLoadTime===0 while finishLoadTime is non-zero is suspicious.
	// Real Chrome sets this to 0 only if no paint occurred after load (rare for HTML pages).
	if hasFPAL && hasFinish && fpal == 0 && finishT > 0 {
		indicators = append(indicators, "loadtimes_zero_first_paint_after_load")
		vec.Score += 0.35
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        "loadtimes_zero_first_paint_after_load",
			Fired:       true,
			Weight:      0.35,
			Score:       0.35,
			Field:       "chrome.loadTimes().firstPaintAfterLoadTime",
			Actual:      "0",
			Expected:    "> 0 for pages with visible content",
			Severity:    "medium",
			Description: "chrome.loadTimes().firstPaintAfterLoadTime is always 0 in known stealth scripts that use Math.random() for other fields.",
		})
	}

	// Check for loadTimes values that are too close together (all derived from Date.now())
	requestT, _ := lt["requestTime"].(float64)
	startT, _ := lt["startLoadTime"].(float64)
	commitT, _ := lt["commitLoadTime"].(float64)
	firstPaintT, _ := lt["firstPaintTime"].(float64)

	if requestT > 0 && startT > 0 && commitT > 0 && firstPaintT > 0 && finishT > 0 {
		span := finishT - requestT
		if span > 0 {
			commitGap := commitT - startT
			paintGap := firstPaintT - commitT
			if commitGap > 0 && paintGap > 0 {
				allTight := commitGap < 0.5 && paintGap < 0.5 && span < 3.5
				if allTight {
					indicators = append(indicators, "loadtimes_suspiciously_tight_clustering")
					vec.Score += 0.25
				}
			}
		}
	}

	return indicators
}

// checkGeometryGapSignature detects stealth scripts that set outerHeight = innerHeight + constant.
// Real browser chrome gaps vary by OS, extensions, bookmarks bar, zoom level, etc.
func (na *navigatorAnalyzer) checkGeometryGapSignature(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	var outerH, innerH float64
	var hasOuter, hasInner bool

	if window, ok := navData["window"].(map[string]interface{}); ok {
		outerH, hasOuter = window["outerHeight"].(float64)
		innerH, hasInner = window["innerHeight"].(float64)
	}
	if !hasOuter {
		outerH, hasOuter = navData["outerHeight"].(float64)
	}
	if !hasInner {
		innerH, hasInner = navData["innerHeight"].(float64)
	}

	if !hasOuter || !hasInner || outerH <= 0 || innerH <= 0 {
		return indicators
	}

	gap := outerH - innerH

	// Known stealth script gap signatures
	knownStealthGaps := map[float64]bool{
		85:  true,
		165: true,
	}

	if knownStealthGaps[gap] {
		indicators = append(indicators, fmt.Sprintf("geometry_gap_stealth_signature_%.0f", gap))
		vec.Score += 0.30
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        "geometry_gap_stealth_signature",
			Fired:       true,
			Weight:      0.30,
			Score:       0.30,
			Field:       "outerHeight - innerHeight",
			Actual:      fmt.Sprintf("%.0f", gap),
			Expected:    "variable (52-112, OS/config dependent)",
			Severity:    "medium",
			Description: "Window geometry gap is a known stealth script signature value.",
		})
	}

	return indicators
}

// checkToStringOverride detects patched Function.prototype.toString.
func (na *navigatorAnalyzer) checkToStringOverride(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	if overridden, ok := navData["toString_overridden"].(bool); ok && overridden {
		indicators = append(indicators, "function_tostring_override_detected")
		vec.Score += 0.40
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        "function_tostring_override_detected",
			Fired:       true,
			Weight:      0.40,
			Score:       0.40,
			Field:       "Function.prototype.toString",
			Actual:      "overridden",
			Expected:    "native",
			Severity:    "high",
			Description: "Function.prototype.toString has been overridden — a hallmark of stealth injection scripts.",
		})
	}

	return indicators
}
