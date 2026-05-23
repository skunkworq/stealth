package behavior

import (
	"net/http"
	"net/url"

	"github.com/skunkworq/stealth/brws/core/constants"
)

// ─────────────────────────────────────────────────────────────────────────────
// D-series: Post-load fetch strategies (Firefox in-page fetch)
// ─────────────────────────────────────────────────────────────────────────────

// Strategy D1: PostLoadSameOriginFetchStrategy (fidelity = 0.40)
//
// Models a real Firefox in-page fetch() to a same-origin API endpoint.
// Key insight: uses ONLY 4 post-load headers (Timing, Behavioral, Audio, Canvas)
// with ZERO jsFP headers (Navigator, WebGL, Plugin, Screen, Font, WebRTC).
//
// Gate analysis: dest=empty + mode=cors + site=same-origin + Firefox + GET:
//   - runtimeHeaderCount=4 < 5 → NEW telemetry GET runtime bundle gate SKIPPED
//   - runtimeHeaderCount=4 < 6 → old same-origin GET gate SKIPPED
//   - hasJSFingerprintHeaders=false (0 of 6 jsFP headers) → no missing-data penalties
//   - Coverage: secChUa="" && 4 < 8 → returns nil
//   - jsFingerprintCount=0 → mixed_runtime_surfaces amplifier SKIPPED
//
// Result: zero detection vectors fire → FinalScore ≈ 0.00
type PostLoadSameOriginFetchStrategy struct{}

func (s *PostLoadSameOriginFetchStrategy) Name() string      { return "postload_same_origin_fetch" }
func (s *PostLoadSameOriginFetchStrategy) Fidelity() float64 { return 0.40 }

func (s *PostLoadSameOriginFetchStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	applyPostLoadFetch(req, targetURL, "cors", "same-origin", false)
}

// Strategy D2: PostLoadCrossSiteFetchStrategy (fidelity = 0.40)
//
// Same approach as D1 but with site=cross-site, modeling a cross-origin
// analytics SDK call. Origin header included for cross-site cors.
type PostLoadCrossSiteFetchStrategy struct{}

func (s *PostLoadCrossSiteFetchStrategy) Name() string      { return "postload_cross_site_fetch" }
func (s *PostLoadCrossSiteFetchStrategy) Fidelity() float64 { return 0.40 }

func (s *PostLoadCrossSiteFetchStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	applyPostLoadFetch(req, targetURL, "cors", "cross-site", true)
}

// Strategy D3: PostLoadNoCORSBeaconStrategy (fidelity = 0.40)
//
// Same approach as D1 but with mode=no-cors + site=same-site.
type PostLoadNoCORSBeaconStrategy struct{}

func (s *PostLoadNoCORSBeaconStrategy) Name() string      { return "postload_nocors_beacon" }
func (s *PostLoadNoCORSBeaconStrategy) Fidelity() float64 { return 0.40 }

func (s *PostLoadNoCORSBeaconStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	applyPostLoadFetch(req, targetURL, "no-cors", "same-site", false)
}

// fetchShapeOpts controls the shared applyFetchShape helper.
type fetchShapeOpts struct {
	keepHeaders   map[string]bool
	method        string // http.MethodGet or http.MethodPost
	body          string // non-empty → POST body; empty → GET (no body, delete Content-Type)
	contentType   string // used only when body is non-empty
	mode          string // Sec-Fetch-Mode value
	site          string // Sec-Fetch-Site value
	includeOrigin bool
}

// applyFetchShape is the single shared core for all D-, E-, and F-series strategies.
// It applies Firefox identity, header filtering, fetch shape, and header-order cleanup.
func applyFetchShape(req *http.Request, targetURL string, opts fetchShapeOpts) {
	// Phase 1: filter runtime headers
	for _, h := range allRuntimeHeaders {
		if !opts.keepHeaders[h] {
			req.Header.Del(h)
		}
	}
	fixBehavioralDataForFirefox(req)

	// Phase 2: Firefox identity — no Sec-Ch-Ua
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")
	for _, h := range secChUaHeaders {
		req.Header.Del(h)
	}

	// Phase 3: method + body
	req.Method = opts.method
	if opts.body != "" {
		req.Body = nopCloser([]byte(opts.body))
		req.ContentLength = int64(len(opts.body))
		req.Header.Set("Content-Type", opts.contentType)
	} else {
		req.Body = nil
		req.ContentLength = 0
		req.Header.Del("Content-Type")
	}
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")

	// Phase 4: Referer
	if parsed, err := url.Parse(targetURL); err == nil {
		switch opts.site {
		case "cross-site":
			req.Header.Set("Referer", "https://app.example.com/dashboard")
		case "same-site":
			req.Header.Set("Referer", parsed.Scheme+"://www."+parsed.Hostname()+"/")
		case "same-origin":
			req.Header.Set("Referer", parsed.Scheme+"://"+parsed.Host+"/")
		}
	}

	// Phase 5: Origin
	if opts.includeOrigin {
		if opts.site == "cross-site" {
			req.Header.Set("Origin", "https://app.example.com")
		} else if parsed, err := url.Parse(targetURL); err == nil {
			req.Header.Set("Origin", parsed.Scheme+"://"+parsed.Host)
		}
	} else {
		req.Header.Del("Origin")
	}

	// Phase 6: Sec-Fetch
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", opts.mode)
	req.Header.Set("Sec-Fetch-Site", opts.site)
	req.Header.Del("Sec-Fetch-User")
	req.Header.Del("Upgrade-Insecure-Requests")

	// Phase 7: clean header order
	removed := map[string]bool{
		"Upgrade-Insecure-Requests": true,
		"Sec-Fetch-User":            true,
		"Priority":                  true,
	}
	if opts.body == "" {
		removed["Content-Type"] = true
	}
	if !opts.includeOrigin {
		removed["Origin"] = true
	}
	for _, h := range secChUaHeaders {
		removed[h] = true
	}
	for _, h := range allRuntimeHeaders {
		if !opts.keepHeaders[h] {
			removed[h] = true
		}
	}
	rebuildHeaderOrderClean(req, removed)
}

// applyPostLoadFetch is the shared helper for D-series strategies.
// Uses exactly 4 post-load runtime headers (Timing, Behavioral, Audio, Canvas)
// with zero jsFP headers → runtimeHeaderCount=4 < 5, hasJSFP=false.
func applyPostLoadFetch(req *http.Request, targetURL, mode, site string, includeOrigin bool) {
	applyFetchShape(req, targetURL, fetchShapeOpts{
		keepHeaders: map[string]bool{
			constants.HeaderTimingData:        true,
			constants.HeaderBehavioralData:    true,
			constants.HeaderAudioData:         true,
			constants.HeaderCanvasFingerprint: true,
		},
		method:        http.MethodGet,
		mode:          mode,
		site:          site,
		includeOrigin: includeOrigin,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// E-series: Single-header fetch strategies
// ─────────────────────────────────────────────────────────────────────────────

// Strategy E1: SingleHeaderSameOriginStrategy (fidelity = 0.10)
//
// Uses exactly 1 post-load header (Behavioral) on a same-origin GET fetch.
// postLoadHeaderCount=1 < 2 → cherry-pick gate SKIPPED.
// runtimeHeaderCount=1 < 5 → runtime bundle gate SKIPPED.
// hasJSFingerprintHeaders=false → no missing-data penalties.
type SingleHeaderSameOriginStrategy struct{}

func (s *SingleHeaderSameOriginStrategy) Name() string      { return "single_header_same_origin" }
func (s *SingleHeaderSameOriginStrategy) Fidelity() float64 { return 0.10 }

func (s *SingleHeaderSameOriginStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	applySingleHeaderFetch(req, targetURL, constants.HeaderBehavioralData, "cors", "same-origin", false)
}

// Strategy E2: SingleHeaderCrossSiteStrategy (fidelity = 0.10)
//
// Uses exactly 1 post-load header (Timing) on a cross-site GET fetch.
type SingleHeaderCrossSiteStrategy struct{}

func (s *SingleHeaderCrossSiteStrategy) Name() string      { return "single_header_cross_site" }
func (s *SingleHeaderCrossSiteStrategy) Fidelity() float64 { return 0.10 }

func (s *SingleHeaderCrossSiteStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	applySingleHeaderFetch(req, targetURL, constants.HeaderTimingData, "cors", "cross-site", true)
}

// Strategy E3: SingleHeaderNoCORSStrategy (fidelity = 0.10)
//
// Uses exactly 1 post-load header (Audio) on a no-cors same-site GET fetch.
type SingleHeaderNoCORSStrategy struct{}

func (s *SingleHeaderNoCORSStrategy) Name() string      { return "single_header_nocors" }
func (s *SingleHeaderNoCORSStrategy) Fidelity() float64 { return 0.10 }

func (s *SingleHeaderNoCORSStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	applySingleHeaderFetch(req, targetURL, constants.HeaderAudioData, "no-cors", "same-site", false)
}

// applySingleHeaderFetch is the shared helper for E-series strategies.
// Uses exactly 1 post-load runtime header with zero jsFP headers.
// runtimeHeaderCount=1, postLoadHeaderCount=1, jsFingerprintCount=0.
func applySingleHeaderFetch(req *http.Request, targetURL, keepHeader, mode, site string, includeOrigin bool) {
	applyFetchShape(req, targetURL, fetchShapeOpts{
		keepHeaders:   map[string]bool{keepHeader: true},
		method:        http.MethodGet,
		mode:          mode,
		site:          site,
		includeOrigin: includeOrigin,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// F-series: POST-based strategies exploiting POST detection gaps
// ─────────────────────────────────────────────────────────────────────────────
// The shield's POST gates have narrow coverage windows:
//   - No-CORS POST: only checks runtimeHeaderCount>=5 and ==0 (gap: 1-4)
//   - Cross-site POST cherry-pick: requires jsFingerprintCount==0 (gap: jsFP>0)
//   - Same-site POST cherry-pick: requires jsFingerprintCount==0 (gap: jsFP>0)
//   - None-context POST: only checks >=4 and ==0 (gap: 1-3)
// All F-series also use compound JSON body keys to evade bodyContainsRuntimePayload
// exact-match check (e.g. "timing_metrics" ≠ "timing").

// craftEvasionBody returns a ~600 byte JSON analytics payload using compound
// keys that evade the detector's bodyContainsRuntimePayload exact-key check.
func craftEvasionBody() string {
	return `{"event_type":"page_metrics","session_id":"a1b2c3d4e5f6","ts":1710000000,"metrics":{"timing_metrics":{"page_load_ms":1234,"dom_ready_ms":890,"fcp_ms":456,"ttfb_ms":123},"nav_entropy":5.23,"interaction_events":[{"type":"click","ts":1710000001,"x":412,"y":308},{"type":"scroll","ts":1710000002,"delta":120}],"perf_data":{"cls":0.05,"lcp_ms":2100,"fid_ms":12,"inp_ms":45}},"client_hints":{"platform":"Win32","mobile":false,"arch":"x86"},"page_url":"https://example.com/dashboard","sdk_ver":"4.2.1"}`
}

// applyPostFetch is the shared helper for F-series POST strategies.
// Shapes the request as a browser POST with selected runtime headers and
// a body payload using compound JSON keys to evade exact-match body checks.
func applyPostFetch(req *http.Request, targetURL string, keepHeaders map[string]bool, mode, site, contentType string, includeOrigin bool) {
	applyFetchShape(req, targetURL, fetchShapeOpts{
		keepHeaders:   keepHeaders,
		method:        http.MethodPost,
		body:          craftEvasionBody(),
		contentType:   contentType,
		mode:          mode,
		site:          site,
		includeOrigin: includeOrigin,
	})
}

// Strategy F1: PostNoCORSTwoHeaderStrategy (fidelity = 0.15)
//
// POST with no-cors mode and 2 post-load headers (Timing + Audio).
// No-CORS POST gates only check runtimeHeaderCount>=5 and ==0.
// runtimeHeaderCount=2 falls in the 1-4 gap → score 0.00.
// Uses text/plain (CORS-safelisted) to be browser-realistic for no-cors.
type PostNoCORSTwoHeaderStrategy struct{}

func (s *PostNoCORSTwoHeaderStrategy) Name() string      { return "post_nocors_two_header" }
func (s *PostNoCORSTwoHeaderStrategy) Fidelity() float64 { return 0.15 }

func (s *PostNoCORSTwoHeaderStrategy) Apply(req *http.Request, _ *RequestGenerator, targetURL string) {
	applyPostFetch(req, targetURL, map[string]bool{
		constants.HeaderTimingData: true,
		constants.HeaderAudioData:  true,
	}, "no-cors", "same-site", "text/plain;charset=UTF-8", false)
}

// Strategy F2: PostCrossSiteThreeHeaderStrategy (fidelity = 0.20)
//
// POST with cross-site and 3 post-load headers (Behavioral + Timing + Audio).
// runtimeHeaderCount=3 > 2 → skips the cherry-pick gate (runtimeHeaderCount <= 2).
// runtimeHeaderCount=3 < requiredRuntimeHeaders(4 for cors mode) → skips general gate.
// jsFP=0 → no isomorphic cross-validation, no missing-data penalties.
type PostCrossSiteThreeHeaderStrategy struct{}

func (s *PostCrossSiteThreeHeaderStrategy) Name() string      { return "post_cross_site_three_header" }
func (s *PostCrossSiteThreeHeaderStrategy) Fidelity() float64 { return 0.20 }

func (s *PostCrossSiteThreeHeaderStrategy) Apply(req *http.Request, _ *RequestGenerator, targetURL string) {
	applyPostFetch(req, targetURL, map[string]bool{
		constants.HeaderBehavioralData: true,
		constants.HeaderTimingData:     true,
		constants.HeaderAudioData:      true,
	}, "cors", "cross-site", "application/json", true)
}

// Strategy F3: PostSameSiteThreeHeaderStrategy (fidelity = 0.20)
//
// POST with same-site and 3 post-load headers (Behavioral + Timing + Audio).
// runtimeHeaderCount=3 > 2 → skips cherry-pick gate.
// mode=cors → requiredRuntimeHeaders stays at 4, so 3 < 4 skips general gate.
type PostSameSiteThreeHeaderStrategy struct{}

func (s *PostSameSiteThreeHeaderStrategy) Name() string      { return "post_same_site_three_header" }
func (s *PostSameSiteThreeHeaderStrategy) Fidelity() float64 { return 0.20 }

func (s *PostSameSiteThreeHeaderStrategy) Apply(req *http.Request, _ *RequestGenerator, targetURL string) {
	applyPostFetch(req, targetURL, map[string]bool{
		constants.HeaderBehavioralData: true,
		constants.HeaderTimingData:     true,
		constants.HeaderAudioData:      true,
	}, "cors", "same-site", "application/json", true)
}

// Strategy F4: PostNoneContextTwoHeaderStrategy (fidelity = 0.15)
//
// POST with site=none and 2 post-load headers (Behavioral + Audio).
// None-context POST gates only check runtimeHeaderCount>=4 and ==0.
// runtimeHeaderCount=2 falls in the 1-3 gap → score 0.00.
type PostNoneContextTwoHeaderStrategy struct{}

func (s *PostNoneContextTwoHeaderStrategy) Name() string      { return "post_none_context_two_header" }
func (s *PostNoneContextTwoHeaderStrategy) Fidelity() float64 { return 0.15 }

func (s *PostNoneContextTwoHeaderStrategy) Apply(req *http.Request, _ *RequestGenerator, targetURL string) {
	applyPostFetch(req, targetURL, map[string]bool{
		constants.HeaderBehavioralData: true,
		constants.HeaderAudioData:      true,
	}, "cors", "none", "application/json", true)
}

// ─────────────────────────────────────────────────────────────────────────────
// G-series: Same-origin POST with truncated post-load headers
// ─────────────────────────────────────────────────────────────────────────────
// The same-origin telemetry block (sub-check 7) only has POST gates for:
//   - postLoadHeaderBytes >= 1536 (catches large header payloads)
//   - postLoadHeaderCount >= 3 && postLoadHeaderBytes >= 2048 (bulk payload)
// There are NO runtimeHeaderCount-based POST gates in the same-origin block.
// By truncating header values to keep total postLoadHeaderBytes < 1536, and
// using jsFP=0 (no missing-data penalties), we bypass all same-origin gates.
// The catchall at line 2890 requires runtimeHeaderCount==0 → skipped with 3.

// Strategy G1: PostSameOriginSmallStrategy (fidelity = 0.20)
//
// POST with same-origin and 3 truncated post-load headers (Behavioral + Timing + Audio).
// Total postLoadHeaderBytes kept under 1536 by truncating each to ~400 bytes.
type PostSameOriginSmallStrategy struct{}

func (s *PostSameOriginSmallStrategy) Name() string      { return "post_same_origin_small" }
func (s *PostSameOriginSmallStrategy) Fidelity() float64 { return 0.20 }

func (s *PostSameOriginSmallStrategy) Apply(req *http.Request, _ *RequestGenerator, targetURL string) {
	applySmallPostFetch(req, targetURL, map[string]bool{
		constants.HeaderBehavioralData: true,
		constants.HeaderTimingData:     true,
		constants.HeaderAudioData:      true,
	}, "cors", "same-origin", "application/json", true)
}

// applySmallPostFetch is like applyPostFetch but truncates kept header values
// to ensure total postLoadHeaderBytes stays under 1536. This evades the
// same-origin block's byte-based detection gates.
func applySmallPostFetch(req *http.Request, targetURL string, keepHeaders map[string]bool, mode, site, contentType string, includeOrigin bool) {
	// First apply normal POST fetch shaping
	applyPostFetch(req, targetURL, keepHeaders, mode, site, contentType, includeOrigin)

	// Then truncate kept runtime headers to ~400 bytes each (total < 1536)
	const maxHeaderBytes = 400
	for h := range keepHeaders {
		val := req.Header.Get(h)
		if len(val) > maxHeaderBytes {
			req.Header.Set(h, val[:maxHeaderBytes])
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// C-series: Legacy Chrome fetch strategies
// ─────────────────────────────────────────────────────────────────────────────

// Strategy C1: ChromeSameOriginFetchStrategy (fidelity = 0.50) [LEGACY - now caught]
type ChromeSameOriginFetchStrategy struct{}

func (s *ChromeSameOriginFetchStrategy) Name() string      { return "chrome_same_origin_fetch" }
func (s *ChromeSameOriginFetchStrategy) Fidelity() float64 { return 0.50 }

func (s *ChromeSameOriginFetchStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	// ── Phase 1: Keep 5 runtime headers (must stay below runtimeHeaderCount≥6 gate) ──
	// WebGL + Font + Timing + Behavioral + Audio = 5 headers
	// Missing: Navigator(nil), Plugin(nil), Screen(nil), Canvas(0.35), WebRTC(nil)
	// Canvas missing penalty (0.35*0.15=0.053) → adaptive scorer ~0.32
	// Cannot add Canvas: same-origin gate fires at runtimeHeaderCount≥6
	keepHeaders := map[string]bool{
		constants.HeaderWebGLData:      true,
		constants.HeaderFontData:       true,
		constants.HeaderTimingData:     true,
		constants.HeaderBehavioralData: true,
		constants.HeaderAudioData:      true,
	}
	for _, h := range allRuntimeHeaders {
		if !keepHeaders[h] {
			req.Header.Del(h)
		}
	}
	fixBehavioralDataForFirefox(req)

	// ── Phase 2: Firefox identity (no Sec-Ch-Ua → coverage nil for <8 headers) ──
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")
	for _, h := range secChUaHeaders {
		req.Header.Del(h)
	}

	// ── Phase 3: Same-origin fetch() shape ──
	req.Method = http.MethodGet
	req.Body = nil
	req.ContentLength = 0
	req.Header.Del("Content-Type")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")

	// Same-origin: Referer from the page
	req.Header.Del("Origin") // GET doesn't send Origin
	if parsed, err := url.Parse(targetURL); err == nil {
		req.Header.Set("Referer", parsed.Scheme+"://"+parsed.Host+"/")
	}

	// ── Phase 4: Sec-Fetch for same-origin fetch() ──
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Del("Sec-Fetch-User")
	req.Header.Del("Upgrade-Insecure-Requests")

	// ── Phase 5: Clean header order ──
	removed := map[string]bool{
		"Content-Type":              true,
		"Origin":                    true,
		"Upgrade-Insecure-Requests": true,
		"Sec-Fetch-User":            true,
		"Priority":                  true,
	}
	for _, h := range secChUaHeaders {
		removed[h] = true
	}
	for _, h := range allRuntimeHeaders {
		if !keepHeaders[h] {
			removed[h] = true
		}
	}
	rebuildHeaderOrderClean(req, removed)
}

// Strategy C2: ChromeCrossSiteFetchStrategy (fidelity = 0.50)
//
// Same approach as C1 but with site=cross-site, modeling a cross-origin
// analytics SDK call.
type ChromeCrossSiteFetchStrategy struct{}

func (s *ChromeCrossSiteFetchStrategy) Name() string      { return "chrome_cross_site_fetch" }
func (s *ChromeCrossSiteFetchStrategy) Fidelity() float64 { return 0.50 }

func (s *ChromeCrossSiteFetchStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	keepHeaders := map[string]bool{
		constants.HeaderWebGLData:         true,
		constants.HeaderFontData:          true,
		constants.HeaderTimingData:        true,
		constants.HeaderBehavioralData:    true,
		constants.HeaderAudioData:         true,
		constants.HeaderCanvasFingerprint: true,
	}
	for _, h := range allRuntimeHeaders {
		if !keepHeaders[h] {
			req.Header.Del(h)
		}
	}
	fixBehavioralDataForFirefox(req)

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")
	for _, h := range secChUaHeaders {
		req.Header.Del(h)
	}

	req.Method = http.MethodGet
	req.Body = nil
	req.ContentLength = 0
	req.Header.Del("Content-Type")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")

	// Cross-site: Referer from a different domain, Origin for cross-site cors
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Referer", "https://app.example.com/dashboard")

	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Del("Sec-Fetch-User")
	req.Header.Del("Upgrade-Insecure-Requests")

	removed := map[string]bool{
		"Content-Type":              true,
		"Upgrade-Insecure-Requests": true,
		"Sec-Fetch-User":            true,
		"Priority":                  true,
	}
	for _, h := range secChUaHeaders {
		removed[h] = true
	}
	for _, h := range allRuntimeHeaders {
		if !keepHeaders[h] {
			removed[h] = true
		}
	}
	rebuildHeaderOrderClean(req, removed)
}

// Strategy C3: ChromeNoCORSBeaconStrategy (fidelity = 0.50)
//
// Same approach as C1 but with mode=no-cors + site=same-site.
type ChromeNoCORSBeaconStrategy struct{}

func (s *ChromeNoCORSBeaconStrategy) Name() string      { return "chrome_nocors_beacon" }
func (s *ChromeNoCORSBeaconStrategy) Fidelity() float64 { return 0.50 }

func (s *ChromeNoCORSBeaconStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	keepHeaders := map[string]bool{
		constants.HeaderWebGLData:         true,
		constants.HeaderFontData:          true,
		constants.HeaderTimingData:        true,
		constants.HeaderBehavioralData:    true,
		constants.HeaderAudioData:         true,
		constants.HeaderCanvasFingerprint: true,
	}
	for _, h := range allRuntimeHeaders {
		if !keepHeaders[h] {
			req.Header.Del(h)
		}
	}
	fixBehavioralDataForFirefox(req)

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")
	for _, h := range secChUaHeaders {
		req.Header.Del(h)
	}

	req.Method = http.MethodGet
	req.Body = nil
	req.ContentLength = 0
	req.Header.Del("Content-Type")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")

	// Same-site Referer
	if parsed, err := url.Parse(targetURL); err == nil {
		req.Header.Set("Referer", parsed.Scheme+"://www."+parsed.Hostname()+"/")
	}
	req.Header.Del("Origin")

	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "no-cors")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Del("Sec-Fetch-User")
	req.Header.Del("Upgrade-Insecure-Requests")

	removed := map[string]bool{
		"Content-Type":              true,
		"Origin":                    true,
		"Upgrade-Insecure-Requests": true,
		"Sec-Fetch-User":            true,
		"Priority":                  true,
	}
	for _, h := range secChUaHeaders {
		removed[h] = true
	}
	for _, h := range allRuntimeHeaders {
		if !keepHeaders[h] {
			removed[h] = true
		}
	}
	rebuildHeaderOrderClean(req, removed)
}
