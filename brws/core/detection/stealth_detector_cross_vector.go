package detection

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/skunkworq/stealth/brws/core/constants"
)

// crossVecCtx holds request-level values pre-computed once and shared across
// all sub-checks in analyzeCrossVectorConsistency.
type crossVecCtx struct {
	runtimeHeaderCount    int
	postLoadHeaderCount   int
	jsFingerprintCount    int
	bodySnapshot          []byte
	bodyErr               error
	bodyText              string
	bodyTooSmall          bool
	missingRuntimePayload bool
	hasRuntimeBody        bool
}

func newCrossVecCtx(req *http.Request) crossVecCtx {
	runtimeHeaders := []string{
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
	postLoadHeaders := []string{
		constants.HeaderBehavioralData,
		constants.HeaderTimingData,
		constants.HeaderCanvasFingerprint,
		constants.HeaderAudioData,
		constants.HeaderWebRTCData,
	}
	jsFPHeaders := []string{
		constants.HeaderNavigatorData,
		constants.HeaderWebGLData,
		constants.HeaderPluginData,
		constants.HeaderScreenData,
		constants.HeaderFontData,
		constants.HeaderWebRTCData,
	}

	bodySnapshot, bodyErr := snapshotRequestBody(req)
	bodyText := strings.TrimSpace(string(bodySnapshot))
	bodyTooSmall := bodyErr == nil && len(bodySnapshot) > 0 && len(bodySnapshot) < 512
	missingRuntimePayload := bodyErr == nil && len(bodySnapshot) > 0 && !bodyContainsRuntimePayload(bodyText)
	hasRuntimeBody := bodyErr == nil && len(bodySnapshot) >= 512 && bodyContainsRuntimePayload(bodyText)

	return crossVecCtx{
		runtimeHeaderCount:    countPresentHeaders(req, runtimeHeaders),
		postLoadHeaderCount:   countPresentHeaders(req, postLoadHeaders),
		jsFingerprintCount:    countPresentHeaders(req, jsFPHeaders),
		bodySnapshot:          bodySnapshot,
		bodyErr:               bodyErr,
		bodyText:              bodyText,
		bodyTooSmall:          bodyTooSmall,
		missingRuntimePayload: missingRuntimePayload,
		hasRuntimeBody:        hasRuntimeBody,
	}
}

// crossVecResult carries the output of a single cross-vector sub-check.
type crossVecResult struct {
	score      float64
	indicators []string
	reports    []CheckReport
}

// cvCheckBehavioralTiming detects behavioral timestamps that predate page load,
// which indicates synthetic generation where events start from zero rather than
// after load completion.
func (sd *StealthDetector) cvCheckBehavioralTiming(req *http.Request, _ crossVecCtx) crossVecResult {
	behavHeader := req.Header.Get(constants.HeaderBehavioralData)
	timingHeader := req.Header.Get(constants.HeaderTimingData)
	if behavHeader == "" || timingHeader == "" {
		return crossVecResult{}
	}

	var behav map[string]interface{}
	var timing map[string]interface{}
	if err := json.Unmarshal([]byte(behavHeader), &behav); err != nil {
		return crossVecResult{}
	}
	if err := json.Unmarshal([]byte(timingHeader), &timing); err != nil {
		return crossVecResult{}
	}

	earliestBehavTs := int64(-1)
	if mouseTs, ok := behav["mouseTimestamps"].([]interface{}); ok && len(mouseTs) > 0 {
		if v, ok := mouseTs[0].(float64); ok {
			earliestBehavTs = int64(v)
		}
	}

	pageLoadEnd := int64(0)
	if entries, ok := timing["entries"].([]interface{}); ok {
		for _, entry := range entries {
			if e, ok := entry.(map[string]interface{}); ok {
				if end, ok := e["responseEnd"].(float64); ok {
					if int64(end) > pageLoadEnd {
						pageLoadEnd = int64(end)
					}
				}
			}
		}
	}
	if le, ok := timing["loadEventEnd"].(float64); ok && int64(le) > pageLoadEnd {
		pageLoadEnd = int64(le)
	}

	if earliestBehavTs >= 0 && earliestBehavTs < 1_000_000_000_000 {
		return crossVecResult{
			score: 0.35,
			indicators: []string{fmt.Sprintf(
				"behavioral_before_epoch: first_mouse_ts=%d (sub-epoch)", earliestBehavTs)},
		}
	}
	if pageLoadEnd > 0 && earliestBehavTs >= 0 && earliestBehavTs < pageLoadEnd {
		return crossVecResult{
			score: 0.35,
			indicators: []string{fmt.Sprintf(
				"behavioral_before_page_load: mouse_start=%d < page_load_end=%d", earliestBehavTs, pageLoadEnd)},
		}
	}
	return crossVecResult{}
}

// cvCheckMouseViewport detects mouse positions that fall outside the claimed
// screen dimensions, indicating synthetic position generation.
func (sd *StealthDetector) cvCheckMouseViewport(req *http.Request, _ crossVecCtx) crossVecResult {
	behavHeader := req.Header.Get(constants.HeaderBehavioralData)
	screenHeader := req.Header.Get(constants.HeaderScreenData)
	if behavHeader == "" || screenHeader == "" {
		return crossVecResult{}
	}

	var behav map[string]interface{}
	var screen map[string]interface{}
	if err := json.Unmarshal([]byte(behavHeader), &behav); err != nil {
		return crossVecResult{}
	}
	if err := json.Unmarshal([]byte(screenHeader), &screen); err != nil {
		return crossVecResult{}
	}

	screenW, _ := screen["width"].(float64)
	screenH, _ := screen["height"].(float64)
	if screenW <= 0 || screenH <= 0 {
		return crossVecResult{}
	}

	if positions, ok := behav["mousePositions"].([]interface{}); ok {
		for _, p := range positions {
			if pt, ok := p.(map[string]interface{}); ok {
				x, _ := pt["x"].(float64)
				y, _ := pt["y"].(float64)
				if x > screenW || y > screenH || x < 0 || y < 0 {
					return crossVecResult{
						score: 0.30,
						indicators: []string{fmt.Sprintf(
							"mouse_outside_viewport: pos(%.0f,%.0f) exceeds screen(%v×%v)",
							x, y, screenW, screenH)},
					}
				}
			}
		}
	}
	return crossVecResult{}
}

// cvCheckNoneContextProvenance detects spoofed none-context telemetry fetches.
// Sec-Fetch-Site: none means no referrer — combined with a dense runtime header
// bundle or a synthetic beacon pattern this is strong evidence of fabrication.
func (sd *StealthDetector) cvCheckNoneContextProvenance(req *http.Request, ctx crossVecCtx) crossVecResult {
	if !isNoneContextTelemetryFetch(req) {
		return crossVecResult{}
	}

	var score float64
	var indicators []string

	if req.Method == http.MethodPost && ctx.runtimeHeaderCount >= 4 {
		score += 0.80
		indicators = append(indicators, fmt.Sprintf(
			"none_context_runtime_bundle: %d runtime/%d post_load headers",
			ctx.runtimeHeaderCount, ctx.postLoadHeaderCount))

		if ctx.postLoadHeaderCount >= 3 {
			score += 0.18
			indicators = append(indicators, fmt.Sprintf(
				"none_context_postload_headers_present: %d runtime/%d post_load headers",
				ctx.runtimeHeaderCount, ctx.postLoadHeaderCount))
		}

		if isOriginSameAsRequestURL(req) {
			score += 0.14
			indicators = append(indicators, "none_context_first_party_origin_claim")
		}

		if ctx.bodyErr == nil && len(ctx.bodySnapshot) > 0 {
			if ctx.bodyTooSmall {
				score += 0.24
				indicators = append(indicators, fmt.Sprintf(
					"none_context_body_too_small_for_claimed_runtime: %d bytes", len(ctx.bodySnapshot)))
			}
			if ctx.missingRuntimePayload {
				score += 0.26
				indicators = append(indicators, "none_context_body_missing_runtime_payload")
			}
		}
	}

	// Mid-range none-context POST (1-3 runtime headers) with browser UA but no
	// Sec-Ch-Ua: the F-series strategies send 2-3 post-load headers with site=none
	// to slip between the >=4 and ==0 gates.
	if req.Method == http.MethodPost && ctx.runtimeHeaderCount >= 1 && ctx.runtimeHeaderCount <= 3 {
		ua := strings.ToLower(req.Header.Get("User-Agent"))
		isBrowserUA := strings.Contains(ua, "chrome") || strings.Contains(ua, "firefox") || strings.Contains(ua, "safari")
		hasSecChUa := req.Header.Get("Sec-Ch-Ua") != ""
		if isBrowserUA && !hasSecChUa {
			score += 0.62
			indicators = append(indicators, fmt.Sprintf(
				"none_context_post_mid_range_headers: %d runtime/%d post_load headers on none-context POST",
				ctx.runtimeHeaderCount, ctx.postLoadHeaderCount))
		}
	}

	if req.Method == http.MethodPost && ctx.runtimeHeaderCount == 0 {
		ua := strings.ToLower(req.Header.Get("User-Agent"))
		isBrowserUA := strings.Contains(ua, "chrome") || strings.Contains(ua, "firefox") || strings.Contains(ua, "safari")
		if isBrowserUA {
			score += 0.38
			indicators = append(indicators, "none_context_zero_header_synthetic_beacon")
			if req.Header.Get("Origin") == "" {
				score += 0.15
				indicators = append(indicators, "none_context_post_missing_origin")
			}
			if ctx.bodyErr == nil && len(ctx.bodySnapshot) > 0 && ctx.bodyTooSmall && ctx.missingRuntimePayload {
				score += 0.12
				indicators = append(indicators, fmt.Sprintf(
					"none_context_small_body_no_runtime: %d bytes", len(ctx.bodySnapshot)))
			}
		}
	}

	return crossVecResult{score: score, indicators: indicators}
}

// cvCheckSameSiteProvenance detects fabricated same-site telemetry fetches where
// the request claims same-site while origin/referer points at itself, or where
// the runtime header bundle is inconsistent with a genuine same-site analytics POST.
func (sd *StealthDetector) cvCheckSameSiteProvenance(req *http.Request, ctx crossVecCtx) crossVecResult {
	if !isSameSiteTelemetryFetch(req) {
		return crossVecResult{}
	}

	var score float64
	var indicators []string

	mode := req.Header.Get("Sec-Fetch-Mode")
	sameOriginClaim := false
	requiredRuntimeHeaders := 4
	telemetryTarget := looksLikeTelemetryEndpointPath(req.URL)
	apiLikeHost := looksLikeAPIHostname(req.URL)

	if req.Method == http.MethodGet && ctx.jsFingerprintCount == 0 && ctx.postLoadHeaderCount >= 1 && (telemetryTarget || apiLikeHost) {
		score += 0.68
		indicators = append(indicators, fmt.Sprintf(
			"same_site_postload_cherry_pick: %d post_load/%d jsFP headers on telemetry GET",
			ctx.postLoadHeaderCount, ctx.jsFingerprintCount))
	}

	if req.Method == http.MethodGet && mode == "cors" && ctx.runtimeHeaderCount >= 6 {
		score += 0.78
		indicators = append(indicators, fmt.Sprintf(
			"same_site_get_runtime_bundle: %d runtime/%d post_load headers",
			ctx.runtimeHeaderCount, ctx.postLoadHeaderCount))
		if ctx.bodyErr == nil && len(ctx.bodySnapshot) > 0 {
			score += 0.26
			indicators = append(indicators, fmt.Sprintf(
				"same_site_get_with_body: %d bytes", len(ctx.bodySnapshot)))
		}
		if req.Header.Get("Content-Type") != "" {
			score += 0.18
			indicators = append(indicators, fmt.Sprintf(
				"same_site_get_with_content_type: %s", req.Header.Get("Content-Type")))
		}
	}

	if req.Method == http.MethodPost && mode == "same-origin" && ctx.runtimeHeaderCount >= 3 {
		requiredRuntimeHeaders = 3
		score += 0.78
		indicators = append(indicators, fmt.Sprintf(
			"same_site_same_origin_mode_mismatch: %d runtime/%d post_load headers",
			ctx.runtimeHeaderCount, ctx.postLoadHeaderCount))
	}

	if req.Method == http.MethodPost && ctx.runtimeHeaderCount >= requiredRuntimeHeaders {
		if isOriginSameAsRequestURL(req) {
			score += 0.70
			indicators = append(indicators, "same_site_claim_on_same_origin_post")
			sameOriginClaim = true
		}
		if isRefererSameAsRequestURL(req) {
			score += 0.22
			indicators = append(indicators, "same_site_telemetry_self_referer")
			sameOriginClaim = true
		}
	}

	if req.Method == http.MethodPost && mode == "cors" && req.Header.Get("Sec-Fetch-User") == "?1" {
		score += 0.24
		indicators = append(indicators, "same_site_xhr_with_user_activation")
	}

	if req.Method == http.MethodPost && ctx.runtimeHeaderCount >= 6 && ctx.hasRuntimeBody {
		if sameOriginClaim && ctx.postLoadHeaderCount >= 3 {
			score += 0.30
			indicators = append(indicators, fmt.Sprintf(
				"telemetry_runtime_duplicated_in_body_and_headers: %d runtime/%d post_load headers",
				ctx.runtimeHeaderCount, ctx.postLoadHeaderCount))
		}
		if !sameOriginClaim && ctx.runtimeHeaderCount >= 8 && ctx.postLoadHeaderCount >= 3 {
			score += 0.72
			indicators = append(indicators, fmt.Sprintf(
				"same_site_dense_runtime_body_header_duplication: %d runtime/%d post_load headers",
				ctx.runtimeHeaderCount, ctx.postLoadHeaderCount))
		}
	}

	if req.Method == http.MethodPost && ctx.runtimeHeaderCount >= requiredRuntimeHeaders && ctx.bodyErr == nil && len(ctx.bodySnapshot) > 0 {
		if ctx.postLoadHeaderCount >= 3 && (ctx.bodyTooSmall || ctx.missingRuntimePayload) {
			score += 0.24
			indicators = append(indicators, fmt.Sprintf(
				"same_site_runtime_hidden_in_headers: %d runtime/%d post_load headers",
				ctx.runtimeHeaderCount, ctx.postLoadHeaderCount))
		}
		if ctx.bodyTooSmall {
			score += 0.42
			indicators = append(indicators, fmt.Sprintf(
				"same_site_body_too_small_for_claimed_runtime: %d bytes", len(ctx.bodySnapshot)))
		}
		if ctx.missingRuntimePayload {
			score += 0.34
			indicators = append(indicators, "same_site_body_missing_runtime_payload")
		}
	}

	// Catches both zero-header synthetic beacons and cherry-picked header patterns
	// on same-site POSTs: real analytics SDKs send the full runtime set or put the
	// data in the body, not in selective headers.
	if req.Method == http.MethodPost && ctx.runtimeHeaderCount <= 3 {
		ua := strings.ToLower(req.Header.Get("User-Agent"))
		isBrowserUA := strings.Contains(ua, "chrome") || strings.Contains(ua, "firefox") || strings.Contains(ua, "safari")
		if isBrowserUA {
			largeTelemetryBody := len(ctx.bodySnapshot) >= 1024
			siblingOriginClaim := req.Header.Get("Origin") != "" && !isOriginSameAsRequestURL(req)
			missingReferer := req.Referer() == ""

			if ctx.runtimeHeaderCount == 0 && ctx.bodyErr == nil && len(ctx.bodySnapshot) > 0 {
				if !bodyContainsRuntimePayload(ctx.bodyText) {
					score += 0.42
					indicators = append(indicators, fmt.Sprintf(
						"same_site_synthetic_beacon: browser_ua body_size=%d no_runtime_in_body_or_headers",
						len(ctx.bodySnapshot)))
				} else {
					score += 0.42
					indicators = append(indicators, fmt.Sprintf(
						"same_site_runtime_data_migration: browser_ua body_size=%d runtime_in_body_but_zero_headers",
						len(ctx.bodySnapshot)))
				}
				if largeTelemetryBody && siblingOriginClaim {
					score += 0.18
					indicators = append(indicators, fmt.Sprintf(
						"same_site_sibling_origin_zero_header_post: body_size=%d", len(ctx.bodySnapshot)))
				}
				if largeTelemetryBody && missingReferer {
					score += 0.12
					indicators = append(indicators, "same_site_zero_header_missing_referer")
				}
			} else if ctx.runtimeHeaderCount > 0 && ctx.runtimeHeaderCount <= 3 && ctx.jsFingerprintCount == 0 {
				score += 0.50
				indicators = append(indicators, fmt.Sprintf(
					"same_site_cherry_picked_postload_headers: %d runtime_headers but 0 js_fingerprint_headers",
					ctx.runtimeHeaderCount))
			}
		}
	}

	return crossVecResult{score: score, indicators: indicators}
}

// cvCheckCrossSiteProvenance detects fabricated cross-site telemetry fetches where
// origin/referer points at the same host, or where the runtime header bundle is
// inconsistent with a genuine third-party analytics POST.
func (sd *StealthDetector) cvCheckCrossSiteProvenance(req *http.Request, ctx crossVecCtx) crossVecResult {
	if !isCrossSiteTelemetryFetch(req) {
		return crossVecResult{}
	}

	var score float64
	var indicators []string

	mode := req.Header.Get("Sec-Fetch-Mode")
	crossSiteClaim := false
	requiredRuntimeHeaders := 4
	telemetryTarget := looksLikeTelemetryEndpointPath(req.URL)
	apiLikeHost := looksLikeAPIHostname(req.URL)

	if req.Method == http.MethodGet && ctx.runtimeHeaderCount >= 5 && (telemetryTarget || apiLikeHost) {
		score += 0.74
		indicators = append(indicators, fmt.Sprintf(
			"cross_site_get_runtime_bundle: %d runtime/%d post_load headers",
			ctx.runtimeHeaderCount, ctx.postLoadHeaderCount))
		if ctx.postLoadHeaderCount >= 2 {
			score += 0.16
			indicators = append(indicators, fmt.Sprintf(
				"cross_site_get_postload_runtime_headers: %d post_load headers", ctx.postLoadHeaderCount))
		}
		if ctx.jsFingerprintCount >= 2 && ctx.postLoadHeaderCount >= 2 {
			score += 0.12
			indicators = append(indicators, "cross_site_get_mixed_runtime_surfaces")
		}
	}

	if req.Method == http.MethodGet && ctx.jsFingerprintCount == 0 && ctx.postLoadHeaderCount >= 1 && (telemetryTarget || apiLikeHost) {
		score += 0.68
		indicators = append(indicators, fmt.Sprintf(
			"cross_site_postload_cherry_pick: %d post_load/%d jsFP headers on telemetry GET",
			ctx.postLoadHeaderCount, ctx.jsFingerprintCount))
	}

	if req.Method == http.MethodPost && mode == "same-origin" && ctx.runtimeHeaderCount >= 3 {
		requiredRuntimeHeaders = 3
		score += 0.80
		indicators = append(indicators, fmt.Sprintf(
			"cross_site_same_origin_mode_mismatch: %d runtime/%d post_load headers",
			ctx.runtimeHeaderCount, ctx.postLoadHeaderCount))
	}

	if req.Method == http.MethodPost && ctx.runtimeHeaderCount >= requiredRuntimeHeaders {
		if isOriginSameAsRequestURL(req) {
			score += 0.72
			indicators = append(indicators, "cross_site_claim_on_same_origin_post")
			crossSiteClaim = true
		}
		if isRefererSameAsRequestURL(req) {
			score += 0.22
			indicators = append(indicators, "cross_site_telemetry_self_referer")
			crossSiteClaim = true
		}
	}

	if req.Method == http.MethodPost && ctx.runtimeHeaderCount >= requiredRuntimeHeaders && ctx.bodyErr == nil && len(ctx.bodySnapshot) > 0 {
		if ctx.postLoadHeaderCount >= 3 && (ctx.bodyTooSmall || ctx.missingRuntimePayload) {
			score += 0.28
			indicators = append(indicators, fmt.Sprintf(
				"cross_site_runtime_hidden_in_headers: %d runtime/%d post_load headers",
				ctx.runtimeHeaderCount, ctx.postLoadHeaderCount))
		}
		if ctx.bodyTooSmall {
			score += 0.42
			indicators = append(indicators, fmt.Sprintf(
				"cross_site_body_too_small_for_claimed_runtime: %d bytes", len(ctx.bodySnapshot)))
		}
		if ctx.missingRuntimePayload {
			score += 0.34
			indicators = append(indicators, "cross_site_body_missing_runtime_payload")
		}
		if crossSiteClaim && ctx.postLoadHeaderCount >= 3 {
			score += 0.20
			indicators = append(indicators, fmt.Sprintf(
				"cross_site_runtime_with_first_party_origin: %d runtime/%d post_load headers",
				ctx.runtimeHeaderCount, ctx.postLoadHeaderCount))
		}
	}

	return crossVecResult{score: score, indicators: indicators}
}

// cvCheckNoCORSProvenance detects no-cors telemetry beacons carrying custom X-*
// runtime headers, which is impossible in a real browser since no-cors mode
// restricts custom headers.
func (sd *StealthDetector) cvCheckNoCORSProvenance(req *http.Request, ctx crossVecCtx) crossVecResult {
	if !isNoCORSTelemetryFetch(req) {
		return crossVecResult{}
	}

	var score float64
	var indicators []string

	contentType := req.Header.Get("Content-Type")
	telemetryTarget := looksLikeTelemetryEndpointPath(req.URL)
	apiLikeHost := looksLikeAPIHostname(req.URL)

	if req.Method == http.MethodGet && ctx.runtimeHeaderCount >= 5 && (telemetryTarget || apiLikeHost) {
		score += 0.76
		indicators = append(indicators, fmt.Sprintf(
			"nocors_get_runtime_bundle: %d runtime/%d post_load headers",
			ctx.runtimeHeaderCount, ctx.postLoadHeaderCount))
		if ctx.postLoadHeaderCount >= 2 {
			score += 0.16
			indicators = append(indicators, fmt.Sprintf(
				"nocors_get_postload_runtime_headers: %d post_load headers", ctx.postLoadHeaderCount))
		}
		if ctx.jsFingerprintCount >= 2 && ctx.postLoadHeaderCount >= 2 {
			score += 0.12
			indicators = append(indicators, "nocors_get_mixed_runtime_surfaces")
		}
	}

	if req.Method == http.MethodGet && ctx.jsFingerprintCount == 0 && ctx.postLoadHeaderCount >= 1 && (telemetryTarget || apiLikeHost) {
		score += 0.70
		indicators = append(indicators, fmt.Sprintf(
			"nocors_postload_cherry_pick: %d post_load/%d jsFP headers on telemetry GET",
			ctx.postLoadHeaderCount, ctx.jsFingerprintCount))
	}

	if req.Method == http.MethodPost && ctx.runtimeHeaderCount >= 5 {
		score += 0.72
		indicators = append(indicators, fmt.Sprintf(
			"nocors_impossible_custom_runtime_headers: %d runtime/%d post_load headers",
			ctx.runtimeHeaderCount, ctx.postLoadHeaderCount))
		if ctx.postLoadHeaderCount >= 3 {
			score += 0.18
			indicators = append(indicators, fmt.Sprintf(
				"nocors_postload_headers_present: %d runtime/%d post_load headers",
				ctx.runtimeHeaderCount, ctx.postLoadHeaderCount))
		}
		if !isNoCORSSafelistedContentType(contentType) {
			score += 0.40
			indicators = append(indicators, fmt.Sprintf(
				"nocors_non_safelisted_content_type: %s", contentType))
		}
		if isOriginSameAsRequestURL(req) {
			score += 0.12
			indicators = append(indicators, "nocors_same_origin_beacon")
		}
		if ctx.bodyErr == nil && len(ctx.bodySnapshot) > 0 {
			if ctx.bodyTooSmall {
				score += 0.26
				indicators = append(indicators, fmt.Sprintf(
					"nocors_body_too_small_for_claimed_runtime: %d bytes", len(ctx.bodySnapshot)))
			}
			if ctx.missingRuntimePayload {
				score += 0.22
				indicators = append(indicators, "nocors_body_missing_runtime_payload")
			}
		}
	} else if req.Method == http.MethodPost && ctx.runtimeHeaderCount >= 1 && ctx.runtimeHeaderCount <= 4 {
		// 1-4 runtime headers on a no-cors POST is structurally impossible: browsers
		// cannot add X-* headers on no-cors requests.
		ua := strings.ToLower(req.Header.Get("User-Agent"))
		isBrowserUA := strings.Contains(ua, "chrome") || strings.Contains(ua, "firefox") || strings.Contains(ua, "safari")
		hasSecChUa := req.Header.Get("Sec-Ch-Ua") != ""
		if isBrowserUA && !hasSecChUa {
			score += 0.68
			indicators = append(indicators, fmt.Sprintf(
				"nocors_post_mid_range_runtime_headers: %d runtime/%d post_load headers on no-cors POST",
				ctx.runtimeHeaderCount, ctx.postLoadHeaderCount))
		}
	} else if req.Method == http.MethodPost && ctx.runtimeHeaderCount == 0 {
		ua := strings.ToLower(req.Header.Get("User-Agent"))
		isBrowserUA := strings.Contains(ua, "chrome") || strings.Contains(ua, "firefox") || strings.Contains(ua, "safari")
		hasAccept := req.Header.Get("Accept") != ""
		hasAcceptEncoding := req.Header.Get("Accept-Encoding") != ""
		fetchSite := strings.ToLower(req.Header.Get("Sec-Fetch-Site"))
		hasProvenance := fetchSite == "same-site" || fetchSite == "cross-site" || fetchSite == "same-origin"
		hasSecChUa := req.Header.Get("Sec-Ch-Ua") != ""

		if isBrowserUA && hasProvenance && !hasSecChUa {
			score += 0.38
			indicators = append(indicators, "nocors_zero_header_synthetic_beacon")
			if hasAccept {
				score += 0.20
				indicators = append(indicators, fmt.Sprintf(
					"nocors_beacon_has_accept: %s", req.Header.Get("Accept")))
			}
			if hasAcceptEncoding {
				score += 0.15
				indicators = append(indicators, fmt.Sprintf(
					"nocors_beacon_has_accept_encoding: %s", req.Header.Get("Accept-Encoding")))
			}
			if isNoCORSSafelistedContentType(contentType) {
				score += 0.10
				indicators = append(indicators, "nocors_beacon_safelisted_content_type")
			}
			if ctx.bodyTooSmall && ctx.missingRuntimePayload {
				score += 0.12
				indicators = append(indicators, fmt.Sprintf(
					"nocors_beacon_small_body_no_runtime: %d bytes", len(ctx.bodySnapshot)))
			}
			if isSiblingSubdomainOrigin(req) {
				score += 0.10
				indicators = append(indicators, "nocors_beacon_sibling_origin")
			}
		}
	}

	return crossVecResult{score: score, indicators: indicators}
}

// cvCheckDocumentNavigation detects document navigations carrying synthetic
// runtime telemetry headers (impossible in real navigations) or targeting
// telemetry/API endpoints without user activation.
func (sd *StealthDetector) cvCheckDocumentNavigation(req *http.Request, ctx crossVecCtx) crossVecResult {
	if !isDocumentNavigation(req) {
		return crossVecResult{}
	}

	var score float64
	var indicators []string

	uaLower := strings.ToLower(req.Header.Get("User-Agent"))
	isBrowserUA := strings.Contains(uaLower, "chrome") || strings.Contains(uaLower, "firefox") || strings.Contains(uaLower, "safari")
	telemetryTarget := looksLikeTelemetryEndpointPath(req.URL)
	apiLikeHost := looksLikeAPIHostname(req.URL)

	if ctx.runtimeHeaderCount >= 4 {
		score += 0.78
		indicators = append(indicators, fmt.Sprintf(
			"document_navigation_impossible_runtime_headers: %d runtime/%d post_load headers",
			ctx.runtimeHeaderCount, ctx.postLoadHeaderCount))
		if ctx.postLoadHeaderCount >= 3 {
			score += 0.20
			indicators = append(indicators, fmt.Sprintf(
				"document_navigation_postload_headers_present: %d runtime/%d post_load headers",
				ctx.runtimeHeaderCount, ctx.postLoadHeaderCount))
		}
		if ctx.bodyErr == nil && len(ctx.bodySnapshot) > 0 && !bodyContainsRuntimePayload(ctx.bodyText) {
			score += 0.18
			indicators = append(indicators, "document_navigation_body_missing_runtime_payload")
		}
	}

	// Any runtime X-* headers on a document navigation are structurally impossible.
	if req.Method == http.MethodGet &&
		ctx.runtimeHeaderCount >= 1 && ctx.runtimeHeaderCount <= 3 &&
		isBrowserUA {
		score += 0.55
		indicators = append(indicators, fmt.Sprintf(
			"document_navigation_synthetic_runtime_headers: %d runtime headers on page load",
			ctx.runtimeHeaderCount))
		if ctx.postLoadHeaderCount >= 1 {
			score += 0.20
			indicators = append(indicators, fmt.Sprintf(
				"document_navigation_postload_on_navigation: %d post-load headers present",
				ctx.postLoadHeaderCount))
		}
	}

	// Large or base64-encoded query string on a document navigation indicates
	// fingerprint data smuggling via URL parameters.
	if req.Method == http.MethodGet && isBrowserUA && req.URL != nil {
		queryLen := len(req.URL.RawQuery)
		if queryLen > 512 {
			score += 0.45
			indicators = append(indicators, fmt.Sprintf(
				"document_navigation_suspicious_query_string: %d bytes in query params", queryLen))
		}
		if queryLen > 0 && looksLikeEncodedPayload(req.URL.RawQuery) {
			score += 0.35
			indicators = append(indicators, "document_navigation_encoded_query_payload")
		}
	}

	if req.Method == http.MethodGet &&
		ctx.runtimeHeaderCount <= 3 &&
		isBrowserUA &&
		(telemetryTarget || apiLikeHost) {
		acceptLower := strings.ToLower(req.Header.Get("Accept"))
		score += 0.40
		indicators = append(indicators, fmt.Sprintf(
			"document_navigation_to_telemetry_target: %s", normalizedURLPath(req.URL)))
		if telemetryTarget {
			score += 0.10
			indicators = append(indicators, "document_navigation_non_page_endpoint")
		}
		if apiLikeHost {
			score += 0.20
			indicators = append(indicators, fmt.Sprintf(
				"document_navigation_api_hostname: %s", normalizedURLHost(req.URL)))
		}
		if req.Header.Get("Sec-Fetch-Site") != "same-origin" {
			score += 0.22
			indicators = append(indicators, fmt.Sprintf(
				"document_navigation_non_same_origin_target: site=%s",
				req.Header.Get("Sec-Fetch-Site")))
		}
		if req.Referer() == "" {
			score += 0.18
			indicators = append(indicators, "document_navigation_missing_referer_to_telemetry_target")
		}
		if strings.Contains(acceptLower, "text/html") {
			score += 0.16
			indicators = append(indicators, "document_navigation_html_accept_to_telemetry_target")
		}
		if req.Header.Get("Upgrade-Insecure-Requests") == "1" {
			score += 0.12
			indicators = append(indicators, "document_navigation_upgrade_insecure_requests_to_telemetry_target")
		}
		if req.Header.Get("Sec-Fetch-User") == "?1" {
			score += 0.12
			indicators = append(indicators, "document_navigation_user_activation_to_telemetry_target")
		}
		if ctx.runtimeHeaderCount >= 1 {
			score += 0.14
			indicators = append(indicators, fmt.Sprintf(
				"document_navigation_runtime_headers_on_telemetry_target: %d runtime headers",
				ctx.runtimeHeaderCount))
		}
	}

	if req.Method == http.MethodGet &&
		ctx.runtimeHeaderCount == 0 &&
		isBrowserUA &&
		req.Header.Get("Sec-Fetch-Site") == "same-origin" &&
		req.Referer() != "" {
		ghostHeaders := ghostHeadersInDeclaredOrder(req, []string{"Content-Type", "Origin"})
		if len(ghostHeaders) > 0 {
			score += 0.44
			indicators = append(indicators, fmt.Sprintf(
				"document_navigation_header_order_ghost_headers: %s",
				strings.Join(ghostHeaders, ",")))
		}
		if looksLikeTelemetryEndpointPath(req.URL) {
			score += 0.52
			indicators = append(indicators, fmt.Sprintf(
				"document_navigation_to_telemetry_endpoint: %s", normalizedURLPath(req.URL)))
		}
		if req.Header.Get("Sec-Fetch-User") == "" {
			score += 0.18
			indicators = append(indicators, "document_navigation_missing_user_activation")
		}
		if req.Header.Get("Upgrade-Insecure-Requests") == "" {
			score += 0.12
			indicators = append(indicators, "document_navigation_missing_upgrade_insecure_requests")
		}
		if req.ProtoMajor == 1 && req.Header.Get("Connection") == "" {
			score += 0.20
			indicators = append(indicators, "document_navigation_missing_connection_header")
		}
		if strings.Contains(uaLower, "firefox") {
			acceptLower := strings.ToLower(req.Header.Get("Accept"))
			if !strings.Contains(acceptLower, "image/avif") || !strings.Contains(acceptLower, "image/webp") {
				score += 0.28
				indicators = append(indicators, "document_navigation_firefox_accept_missing_image_codecs")
			}
		}
		order := declaredHeaderOrder(req)
		upgradeIdx := headerOrderIndex(order, "upgrade-insecure-requests")
		uaIdx := headerOrderIndex(order, "user-agent")
		acceptIdx := headerOrderIndex(order, "accept")
		acceptLangIdx := headerOrderIndex(order, "accept-language")
		if upgradeIdx != -1 &&
			((uaIdx != -1 && upgradeIdx < uaIdx) ||
				(acceptIdx != -1 && upgradeIdx < acceptIdx) ||
				(acceptLangIdx != -1 && upgradeIdx < acceptLangIdx)) {
			score += 0.24
			indicators = append(indicators, fmt.Sprintf(
				"document_navigation_improbable_header_order: upgrade-insecure-requests@%d",
				upgradeIdx))
		}
	}

	return crossVecResult{score: score, indicators: indicators}
}

// cvCheckSameOriginTelemetry detects fabricated same-origin telemetry POSTs where
// the runtime payload is smuggled into headers rather than the body, or where
// the body/header balance is inconsistent with genuine analytics SDK traffic.
func (sd *StealthDetector) cvCheckSameOriginTelemetry(req *http.Request, ctx crossVecCtx) crossVecResult {
	if !isSameOriginTelemetryFetch(req) {
		return crossVecResult{}
	}

	var score float64
	var indicators []string

	postLoadHeaderBytes := totalHeaderValueBytes(req, []string{
		constants.HeaderBehavioralData,
		constants.HeaderTimingData,
		constants.HeaderCanvasFingerprint,
		constants.HeaderAudioData,
		constants.HeaderWebRTCData,
	})
	behaviorHeaderBytes := len(req.Header.Get(constants.HeaderBehavioralData))
	timingHeaderBytes := len(req.Header.Get(constants.HeaderTimingData))
	telemetryTarget := looksLikeTelemetryEndpointPath(req.URL)
	apiLikeHost := looksLikeAPIHostname(req.URL)

	if req.Method == http.MethodGet && ctx.runtimeHeaderCount >= 5 && (telemetryTarget || apiLikeHost) {
		score += 0.70
		indicators = append(indicators, fmt.Sprintf(
			"same_origin_get_runtime_bundle: %d runtime/%d post_load headers",
			ctx.runtimeHeaderCount, ctx.postLoadHeaderCount))
		if ctx.postLoadHeaderCount >= 2 {
			score += 0.16
			indicators = append(indicators, fmt.Sprintf(
				"same_origin_get_postload_runtime_headers: %d post_load headers", ctx.postLoadHeaderCount))
		}
		if ctx.jsFingerprintCount >= 2 && ctx.postLoadHeaderCount >= 2 {
			score += 0.10
			indicators = append(indicators, "same_origin_get_mixed_runtime_surfaces")
		}
	}

	if req.Method == http.MethodGet && ctx.jsFingerprintCount == 0 && ctx.postLoadHeaderCount >= 1 && (telemetryTarget || apiLikeHost) {
		score += 0.66
		indicators = append(indicators, fmt.Sprintf(
			"same_origin_postload_cherry_pick: %d post_load/%d jsFP headers on telemetry GET",
			ctx.postLoadHeaderCount, ctx.jsFingerprintCount))
	}

	// Same-origin POST with post-load headers but no JS fingerprint headers is
	// the shape of adaptive evasion that truncates headers to stay under byte gates.
	if req.Method == http.MethodPost && ctx.postLoadHeaderCount >= 1 && ctx.postLoadHeaderCount <= 4 && ctx.jsFingerprintCount == 0 && (telemetryTarget || apiLikeHost) {
		ua := strings.ToLower(req.Header.Get("User-Agent"))
		isBrowserUA := strings.Contains(ua, "chrome") || strings.Contains(ua, "firefox") || strings.Contains(ua, "safari")
		hasSecChUa := req.Header.Get("Sec-Ch-Ua") != ""
		if isBrowserUA && !hasSecChUa {
			score += 0.58
			indicators = append(indicators, fmt.Sprintf(
				"same_origin_post_cherry_picked_postload: %d post_load/%d jsFP headers on telemetry POST",
				ctx.postLoadHeaderCount, ctx.jsFingerprintCount))
		}
	}

	if req.Method == http.MethodPost && postLoadHeaderBytes >= 1536 {
		score += 0.36
		indicators = append(indicators, fmt.Sprintf(
			"telemetry_postload_blob_in_headers: %d bytes across %d post_load headers",
			postLoadHeaderBytes, ctx.postLoadHeaderCount))
		if timingHeaderBytes >= 1024 {
			score += 0.22
			indicators = append(indicators, fmt.Sprintf(
				"telemetry_timing_blob_in_headers: %d bytes", timingHeaderBytes))
		}
		if behaviorHeaderBytes >= 1024 {
			score += 0.10
			indicators = append(indicators, "telemetry_behavioral_payload_in_headers")
		}
		if ctx.bodyErr == nil && len(ctx.bodySnapshot) > 0 {
			if strings.Contains(strings.ToLower(req.Header.Get("Content-Type")), "application/json") && !json.Valid(ctx.bodySnapshot) {
				score += 0.55
				indicators = append(indicators, "telemetry_invalid_json_body")
			}
			if postLoadHeaderBytes > len(ctx.bodySnapshot)*4 {
				score += 0.18
				indicators = append(indicators, fmt.Sprintf(
					"telemetry_header_body_imbalance: %d header bytes vs %d body bytes",
					postLoadHeaderBytes, len(ctx.bodySnapshot)))
			}
		}
	}

	if req.Method == http.MethodPost && ctx.postLoadHeaderCount >= 3 && postLoadHeaderBytes >= 2048 {
		score += 0.44
		indicators = append(indicators, fmt.Sprintf(
			"telemetry_bulk_payload_in_headers: %d bytes across %d post_load headers",
			postLoadHeaderBytes, ctx.postLoadHeaderCount))
	}

	if ctx.runtimeHeaderCount >= 6 && ctx.postLoadHeaderCount >= 3 {
		if req.Method == http.MethodPost {
			score += 0.42
			indicators = append(indicators, fmt.Sprintf(
				"telemetry_header_surface_overload: %d runtime/%d post_load headers",
				ctx.runtimeHeaderCount, ctx.postLoadHeaderCount))
		}
		if req.Method == http.MethodGet {
			score += 0.30
			indicators = append(indicators, fmt.Sprintf(
				"telemetry_payload_on_get_request: %d runtime headers", ctx.runtimeHeaderCount))
		}
		if isRefererSameAsRequestURL(req) {
			score += 0.40
			indicators = append(indicators, "telemetry_self_referer")
		}
		if req.Header.Get("Content-Type") == "" && req.ContentLength <= 0 {
			score += 0.30
			indicators = append(indicators, fmt.Sprintf(
				"telemetry_stuffed_into_headers: %d runtime/%d post_load headers without body",
				ctx.runtimeHeaderCount, ctx.postLoadHeaderCount))
		}
		if req.Method == http.MethodPost {
			score += 0.20
			indicators = append(indicators, fmt.Sprintf(
				"telemetry_runtime_hidden_in_headers: %d runtime/%d post_load headers",
				ctx.runtimeHeaderCount, ctx.postLoadHeaderCount))
			if ctx.bodyErr != nil || len(ctx.bodySnapshot) == 0 {
				score += 0.30
				indicators = append(indicators, "telemetry_post_missing_body_payload")
			} else {
				if len(ctx.bodySnapshot) < 256 {
					score += 0.22
					indicators = append(indicators, fmt.Sprintf(
						"telemetry_body_too_small_for_claimed_runtime: %d bytes", len(ctx.bodySnapshot)))
				}
				if !bodyContainsRuntimePayload(ctx.bodyText) {
					score += 0.22
					indicators = append(indicators, "telemetry_body_missing_runtime_payload")
				}
			}
		}
	}

	return crossVecResult{score: score, indicators: indicators}
}

// cvCheckFetchMetadataConsistency detects a logical impossibility: a request
// claiming Sec-Fetch-Site: cross-site while its Origin header matches the request
// URL host. A real browser would have set same-origin instead.
func (sd *StealthDetector) cvCheckFetchMetadataConsistency(req *http.Request, _ crossVecCtx) crossVecResult {
	if !(req.Header.Get("Sec-Fetch-Site") == "cross-site" && isOriginSameAsRequestURL(req)) {
		return crossVecResult{}
	}
	return crossVecResult{
		score:      0.50,
		indicators: []string{"cross_site_provenance_lie: origin_matches_request_url"},
		reports: []CheckReport{{
			Name:        "cross_site_provenance_lie",
			Fired:       true,
			Weight:      constants.SeverityHigh,
			Score:       0.50,
			Field:       "Sec-Fetch-Site + Origin",
			Actual:      fmt.Sprintf("Sec-Fetch-Site=cross-site but Origin=%s matches request host", req.Header.Get("Origin")),
			Expected:    "cross-site requests must originate from a different host",
			Severity:    "high",
			Description: "The request claims cross-site provenance but its Origin header matches the request URL host, which is impossible in a real browser.",
		}},
	}
}

// cvCheckCrossSiteBrowserPost detects cross-site POSTs with a browser UA but zero
// runtime context, matching the pattern of synthetic beacon generation or runtime
// data migration from headers to body.
func (sd *StealthDetector) cvCheckCrossSiteBrowserPost(req *http.Request, ctx crossVecCtx) crossVecResult {
	if !isCrossSiteTelemetryFetch(req) || req.Method != http.MethodPost {
		return crossVecResult{}
	}
	if ctx.runtimeHeaderCount > 4 {
		return crossVecResult{}
	}

	ua := strings.ToLower(req.Header.Get("User-Agent"))
	isBrowserUA := strings.Contains(ua, "chrome") || strings.Contains(ua, "firefox") || strings.Contains(ua, "safari")
	if !isBrowserUA {
		return crossVecResult{}
	}

	var score float64
	var indicators []string

	if ctx.runtimeHeaderCount == 0 {
		if ctx.bodyErr == nil && len(ctx.bodySnapshot) > 0 {
			if !bodyContainsRuntimePayload(ctx.bodyText) {
				score += 0.35
				indicators = append(indicators, fmt.Sprintf(
					"cross_site_synthetic_beacon: browser_ua body_size=%d no_runtime_in_body_or_headers",
					len(ctx.bodySnapshot)))
			} else {
				score += 0.35
				indicators = append(indicators, fmt.Sprintf(
					"cross_site_runtime_data_migration: browser_ua body_size=%d runtime_in_body_but_zero_headers",
					len(ctx.bodySnapshot)))
			}
		}
	} else if ctx.jsFingerprintCount == 0 {
		// Cherry-picked post-load headers on cross-site POST — no JS fingerprint headers.
		score += 0.50
		indicators = append(indicators, fmt.Sprintf(
			"cross_site_cherry_picked_postload_headers: %d runtime_headers but 0 js_fingerprint_headers",
			ctx.runtimeHeaderCount))
	}

	return crossVecResult{score: score, indicators: indicators}
}

// cvCheckExoticDest detects sub-resource loads (iframe, script, image, etc.) that
// target telemetry or API endpoints, which is structurally impossible in real
// browsing — indicating strategy rotation to bypass dest=empty and dest=document gates.
func (sd *StealthDetector) cvCheckExoticDest(req *http.Request, ctx crossVecCtx) crossVecResult {
	dest := strings.ToLower(req.Header.Get("Sec-Fetch-Dest"))
	isExoticDest := dest != "" && dest != "empty" && dest != "document"
	if !isExoticDest || req.URL == nil {
		return crossVecResult{}
	}

	telemetryTarget := looksLikeTelemetryEndpointPath(req.URL)
	apiLikeHost := looksLikeAPIHostname(req.URL)
	if !telemetryTarget && !apiLikeHost {
		return crossVecResult{}
	}

	var score float64
	var indicators []string

	score += 0.45
	indicators = append(indicators, fmt.Sprintf(
		"exotic_dest_to_telemetry_target: dest=%s url=%s", dest, normalizedURLPath(req.URL)))
	if telemetryTarget {
		score += 0.10
		indicators = append(indicators, "exotic_dest_telemetry_endpoint_path")
	}
	if apiLikeHost {
		score += 0.15
		indicators = append(indicators, fmt.Sprintf(
			"exotic_dest_api_hostname: %s", normalizedURLHost(req.URL)))
	}
	if ctx.runtimeHeaderCount == 0 {
		score += 0.10
		indicators = append(indicators, "exotic_dest_zero_runtime_headers")
	}
	ua := strings.ToLower(req.Header.Get("User-Agent"))
	hasSecChUa := req.Header.Get("Sec-Ch-Ua") != ""
	if !hasSecChUa && (strings.Contains(ua, "chrome") || strings.Contains(ua, "firefox")) {
		score += 0.08
		indicators = append(indicators, "exotic_dest_no_sec_ch_ua")
	}

	return crossVecResult{score: score, indicators: indicators}
}

// cvCheckZeroHeaderCatchAll catches fetch-like requests (dest=empty or unset) with
// browser UA and zero runtime headers but no Sec-Ch-Ua. This fires as a fallback
// when no gate-specific sub-check has already scored ≥ 0.35. The caller enforces
// the score threshold; this function does not need to be aware of accumulated score.
func (sd *StealthDetector) cvCheckZeroHeaderCatchAll(req *http.Request, ctx crossVecCtx) crossVecResult {
	if req.Method != http.MethodPost && req.Method != http.MethodGet {
		return crossVecResult{}
	}
	dest := req.Header.Get("Sec-Fetch-Dest")
	if dest != "empty" && dest != "" {
		return crossVecResult{}
	}
	if ctx.runtimeHeaderCount != 0 {
		return crossVecResult{}
	}

	ua := strings.ToLower(req.Header.Get("User-Agent"))
	isBrowserUA := strings.Contains(ua, "chrome") || strings.Contains(ua, "firefox") || strings.Contains(ua, "safari")
	hasSecChUa := req.Header.Get("Sec-Ch-Ua") != ""
	if !isBrowserUA || hasSecChUa {
		return crossVecResult{}
	}

	mode := req.Header.Get("Sec-Fetch-Mode")
	site := req.Header.Get("Sec-Fetch-Site")
	var score float64
	var indicators []string

	if req.Method == http.MethodPost {
		if ctx.bodyErr == nil && len(ctx.bodySnapshot) > 0 {
			hasRuntimeInBody := bodyContainsRuntimePayload(ctx.bodyText)
			if hasRuntimeInBody {
				score += 0.52
				indicators = append(indicators, fmt.Sprintf(
					"zero_header_runtime_data_migration: dest=%s mode=%s site=%s body=%d",
					dest, mode, site, len(ctx.bodySnapshot)))
			} else {
				score += 0.52
				indicators = append(indicators, fmt.Sprintf(
					"zero_header_browser_post_catchall: dest=%s mode=%s site=%s body=%d",
					dest, mode, site, len(ctx.bodySnapshot)))
			}
			if req.Header.Get("Accept") == "" {
				score += 0.10
				indicators = append(indicators, "zero_header_post_no_accept")
			}
		}
	} else {
		score += 0.48
		indicators = append(indicators, fmt.Sprintf(
			"zero_header_browser_get_catchall: dest=%s mode=%s site=%s",
			dest, mode, site))
	}

	return crossVecResult{score: score, indicators: indicators}
}
