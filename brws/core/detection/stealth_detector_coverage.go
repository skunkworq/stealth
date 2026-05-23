package detection

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/skunkworq/stealth/brws/core/constants"
)

// analyzeFingerprintCoverage uses graduated scoring based on JS fingerprint header coverage.
//   - 0 headers with Client Hints → 0.50 (HTTP impersonation, e.g., curl-impersonate)
//   - 1-5 headers → 0.30 * (1 - ratio) (partial: cherry-picked headers)
//   - 6-9 headers → 0.00 (normal partial coverage)
//   - Dense 8-10 header bundle on initial navigation → strong detection
//   - All 10 headers → 0.10 baseline suspicious completeness unless provenance is impossible
func (sd *StealthDetector) analyzeFingerprintCoverage(req *http.Request) *DetectionVector {
	allJSHeaders := []string{
		constants.HeaderNavigatorData,
		constants.HeaderWebGLData,
		constants.HeaderPluginData,
		constants.HeaderScreenData,
		constants.HeaderFontData,
		constants.HeaderWebRTCData,
		constants.HeaderBehavioralData,
		constants.HeaderTimingData,
		constants.HeaderAudioData,
		constants.HeaderCanvasFingerprint,
	}

	presentCount := 0
	for _, h := range allJSHeaders {
		if req.Header.Get(h) != "" {
			presentCount++
		}
	}

	secChUa := req.Header.Get("Sec-Ch-Ua")
	if secChUa == "" && presentCount < 8 {
		return nil
	}

	totalHeaders := len(allJSHeaders)
	vec := &DetectionVector{
		Name:         "Fingerprint Coverage",
		Category:     string(VectorFingerprintCoverage),
		Weight:       1.0,
		Description:  "Graduated fingerprint header coverage analysis",
		Indicators:   make([]string, 0),
		CheckReports: make([]CheckReport, 0),
	}

	switch {
	case presentCount == 0:
		// Pure HTTP impersonator — no JS context at all
		vec.Score = 0.50
		vec.Detected = true
		vec.Indicators = append(vec.Indicators, "http_impersonation_no_js_context")
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        "http_impersonation_no_js_context",
			Fired:       true,
			Weight:      constants.SeverityHigh,
			Score:       vec.Score,
			Field:       "X-*-Fingerprint-Headers",
			Actual:      fmt.Sprintf("%d of %d present", presentCount, totalHeaders),
			Expected:    "at least one coherent JS/runtime fingerprint surface",
			Severity:    "high",
			Description: "The request claims a browser navigation context but exposes no JS-derived runtime fingerprint data.",
		})
		if isRichChromiumNavigationWithoutRuntimeState(req) {
			vec.Score = 0.65
			vec.Indicators = append(vec.Indicators, "rich_chromium_headers_without_runtime_state")
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "rich_chromium_headers_without_runtime_state",
				Fired:       true,
				Weight:      constants.SeverityHigh,
				Score:       vec.Score,
				Field:       "Sec-Ch-Ua/Accept/Accept-Encoding",
				Actual:      "rich Chromium navigation bundle with 0 runtime surfaces",
				Expected:    "runtime surfaces consistent with a rich Chromium navigation bundle",
				Severity:    "high",
				Description: "The request sends a high-fidelity Chromium navigation header set, but still exposes no navigator, timing, canvas, or behavioral runtime state.",
			})
		}

	case presentCount <= 5:
		// Partial coverage — some cherry-picked headers
		ratio := float64(presentCount) / float64(totalHeaders)
		vec.Score = 0.30 * (1.0 - ratio)
		vec.Detected = vec.Score > 0.15
		vec.Indicators = append(vec.Indicators, fmt.Sprintf("partial_js_coverage_%d_of_%d", presentCount, totalHeaders))

	case presentCount == totalHeaders:
		// Suspiciously complete — real pages rarely collect all 10 simultaneously.
		// WebRTC needs getUserMedia permission, Audio needs AudioContext creation,
		// Canvas needs explicit toDataURL call — unlikely all on first page load.
		vec.Score = 0.10
		vec.Detected = false
		vec.Indicators = append(vec.Indicators, "suspiciously_complete_js_coverage")

	default:
		// 6-9 headers = normal partial coverage unless the bundle is impossibly dense
		// for an initial top-level navigation.
		if presentCount < 8 {
			return nil
		}
		vec.Score = 0.08
		vec.Detected = false
		vec.Indicators = append(vec.Indicators, fmt.Sprintf("dense_js_coverage_%d_of_%d", presentCount, totalHeaders))
	}

	if isInitialNavigationDenseRuntimeBundle(req, presentCount) {
		vec.Score = 0.82
		vec.Detected = true
		vec.Indicators = append(vec.Indicators, "pre_request_full_runtime_bundle")
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        "pre_request_full_runtime_bundle",
			Fired:       true,
			Weight:      constants.SeverityHigh,
			Score:       vec.Score,
			Field:       "X-*-Fingerprint-Headers",
			Actual:      fmt.Sprintf("%d of %d runtime headers on initial navigation", presentCount, totalHeaders),
			Expected:    "sparse or no JS/runtime headers before the page executes client-side probes",
			Severity:    "high",
			Description: "A first-party top-level navigation arrived with a dense runtime bundle that would normally require client-side execution after the document response.",
		})

		postLoadHeaders := countPresentHeaders(req, []string{
			constants.HeaderBehavioralData,
			constants.HeaderTimingData,
			constants.HeaderCanvasFingerprint,
			constants.HeaderAudioData,
			constants.HeaderWebRTCData,
		})
		if postLoadHeaders >= 3 {
			vec.Indicators = append(vec.Indicators, "post_load_telemetry_on_initial_navigation")
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "post_load_telemetry_on_initial_navigation",
				Fired:       true,
				Weight:      constants.SeverityHigh,
				Score:       vec.Score,
				Field:       "X-Behavioral-Data/X-Timing-Data/X-Canvas-Fingerprint/X-Audio-Data/X-WebRTC-Data",
				Actual:      fmt.Sprintf("%d post-load telemetry surfaces attached to initial navigation", postLoadHeaders),
				Expected:    "post-load telemetry should be submitted after the document has executed, not on the first navigation request",
				Severity:    "high",
				Description: "The request includes multiple telemetry surfaces that require user interaction, rendering, timing collection, or permission-gated APIs before they can exist.",
			})
		}
	}

	return vec
}

func isInitialNavigationDenseRuntimeBundle(req *http.Request, presentCount int) bool {
	if req == nil || presentCount < 8 || !isInitialTopLevelNavigation(req) {
		return false
	}

	postLoadHeaders := countPresentHeaders(req, []string{
		constants.HeaderBehavioralData,
		constants.HeaderTimingData,
		constants.HeaderCanvasFingerprint,
		constants.HeaderAudioData,
		constants.HeaderWebRTCData,
	})
	if postLoadHeaders < 3 {
		return false
	}

	permissionGatedHeaders := countPresentHeaders(req, []string{
		constants.HeaderAudioData,
		constants.HeaderWebRTCData,
		constants.HeaderBehavioralData,
	})

	return permissionGatedHeaders >= 2 || req.Header.Get(constants.HeaderTimingData) != ""
}

func isInitialTopLevelNavigation(req *http.Request) bool {
	if req == nil {
		return false
	}

	return req.Header.Get("Sec-Fetch-Dest") == "document" &&
		req.Header.Get("Sec-Fetch-Mode") == "navigate" &&
		req.Header.Get("Sec-Fetch-Site") == "none" &&
		req.Header.Get("Sec-Fetch-User") == "?1" &&
		req.Header.Get("Referer") == ""
}

func countPresentHeaders(req *http.Request, headers []string) int {
	count := 0
	for _, header := range headers {
		if req.Header.Get(header) != "" {
			count++
		}
	}
	return count
}

func totalHeaderValueBytes(req *http.Request, headers []string) int {
	total := 0
	for _, header := range headers {
		total += len(req.Header.Get(header))
	}
	return total
}

func isRichChromiumNavigationWithoutRuntimeState(req *http.Request) bool {
	uaLower := strings.ToLower(req.Header.Get("User-Agent"))
	secChLower := strings.ToLower(req.Header.Get("Sec-Ch-Ua"))
	if !strings.Contains(uaLower, "chrome") && !strings.Contains(secChLower, "chrom") {
		return false
	}

	if req.Header.Get("Sec-Fetch-Dest") != "document" ||
		req.Header.Get("Sec-Fetch-Mode") != "navigate" ||
		req.Header.Get("Upgrade-Insecure-Requests") != "1" {
		return false
	}

	richSignals := 0
	if strings.Contains(req.Header.Get("Accept"), "application/signed-exchange") {
		richSignals++
	}
	if strings.Contains(req.Header.Get("Accept-Encoding"), "zstd") {
		richSignals++
	}
	if req.Header.Get("Sec-Ch-Ua-Full-Version-List") != "" {
		richSignals++
	}
	if req.Header.Get("Sec-Ch-Ua-Arch") != "" || req.Header.Get("Sec-Ch-Ua-Bitness") != "" {
		richSignals++
	}
	if req.Header.Get("Priority") != "" {
		richSignals++
	}

	return richSignals >= 2
}
