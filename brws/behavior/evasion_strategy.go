package behavior

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/skunkworq/stealth/brws/constants"
)

// EvasionStrategy defines a fingerprint evasion technique. Strategies are
// ordered by priority — the adaptive FSM tries highest priority first and
// falls back on detection.
type EvasionStrategy interface {
	Name() string
	Fidelity() float64 // 0.0–1.0: fraction of fingerprint data preserved
	Apply(req *http.Request, rg *RequestGenerator, targetURL string)
}

// allRuntimeHeaders lists all 10 fingerprint header names the shield checks.
var allRuntimeHeaders = []string{
	constants.HeaderNavigatorData,
	constants.HeaderWebGLData,
	constants.HeaderPluginData,
	constants.HeaderScreenData,
	constants.HeaderFontData,
	constants.HeaderWebRTCData,
	constants.HeaderBehavioralData,
	constants.HeaderTimingData,
	constants.HeaderCanvasFingerprint,
	constants.HeaderAudioData,
}

// safeHeaders are runtime headers with no missing_* penalty when stripped.
var safeHeaders = []string{
	constants.HeaderNavigatorData,
	constants.HeaderWebGLData,
	constants.HeaderPluginData,
	constants.HeaderScreenData,
	constants.HeaderFontData,
	constants.HeaderWebRTCData,
}

// DefaultStrategies returns evasion strategies ordered by priority (highest first).
func DefaultStrategies() []EvasionStrategy {
	return []EvasionStrategy{
		&RealBrowserStrategy{},                // Models real Chrome telemetry POST from lab captures — 0 X-* headers (EVASION)
		&NoneContextCorsStrategy{},            // cors + site=none = total gate bypass, 6 headers (CAUGHT)
		&SameOriginSubThresholdStrategy{},     // same-origin + same-site, 6 headers (CAUGHT)
		&SameOriginSameSiteStrategy{},         // same-origin mode + same-site = gate gap, 7 headers (CAUGHT)
		&SameOriginSameSiteMinimalStrategy{},  // same-origin mode + same-site, 3 headers (CAUGHT)
		&SameSiteCorsStrategy{},               // cors + same-site + no-referer, 7 headers (CAUGHT)
		&CrossSiteNavigateStrategy{},          // dest=document, navigate, cross-site, 7 headers (CAUGHT)
		&CrossSiteCorsStrategy{},              // cors + cross-site + no-referer, 7 headers (CAUGHT)
		&SameSiteMinimalStrategy{},            // cors + same-site + no-referer, 4 headers (CAUGHT)
		&NavigateMinimalStrategy{},            // dest=document, navigate, cross-site, 4 headers (CAUGHT)
		&BodyMigrationStrategy{},              // all data in body (CAUGHT)
		&SelectiveStripStrategy{},             // minimal headers (CAUGHT)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy R: RealBrowserStrategy (fidelity = 0.00)
// ─────────────────────────────────────────────────────────────────────────────
// Models a REAL Chrome 146 cross-site telemetry POST exactly as observed in lab
// captures (MITM proxy + CDP). The lab shows that Sentry, Amplitude, FullStory,
// and other real analytics beacons use:
//
//   POST /api/.../envelope  HTTP/2
//   Sec-Fetch-Dest: empty
//   Sec-Fetch-Mode: cors
//   Sec-Fetch-Site: cross-site
//   Content-Type: text/plain;charset=UTF-8
//   Origin: https://www.example.com
//   Referer: https://www.example.com/
//   (NO custom X-* headers — ever)
//
// This strategy strips ALL X-* runtime headers because no real browser sends them.
// This makes 15 of 19 detection vectors return nil (no data to analyze).
//
// Coverage analysis (presentCount=0):
//   - Chrome profiles: Sec-Ch-Ua present → score 0.50 (http_impersonation_no_js_context)
//     BUT this is a false positive — real Chrome telemetry POSTs also have 0 X-* headers.
//     The key: isRichChromiumNavigationWithoutRuntimeState only fires on dest=document +
//     mode=navigate + Upgrade-Insecure-Requests=1 — NOT on dest=empty + mode=cors.
//     So we avoid the 0.65 bump. With only coverage at 0.50 and all other vectors nil,
//     the adaptive scorer gives:
//       WeightedAvg ≈ 0.50 (only coverage contributes)
//       MaxScore = 0.50
//       MajorityVote = 0.0 (only 1/19 vectors positive)
//       Final = 0.50*0.50 + 0.30*0.50 + 0.20*0.0 = 0.40
//     This is ABOVE the 0.35 threshold for Chrome profiles.
//
//   - Firefox profiles: No Sec-Ch-Ua → coverage returns nil immediately (line 1334).
//     All other vectors nil → score 0.00. Firefox profiles pass cleanly.
//
//   - For Chrome profiles: We strip Sec-Ch-Ua headers. Without dest=document +
//     mode=navigate, the chrome_navigation_missing_client_hints check doesn't fire.
//     This gives us presentCount=0, secChUa="" → coverage returns nil.
//     The UA still says Chrome but that only triggers the Sec-Ch-Ua* check in
//     analyzeHTTPHeaders IF dest=document && mode=navigate — which we avoid.
//
// Cross-vector consistency (all gates miss):
//   - runtimeHeaderCount = 0 → all gates require >= 3-4 → SKIP
//   - Sub-checks 1-2: require X-Behavioral-Data/X-Timing-Data → absent → SKIP
//
// Header order: Without X-Stealth-Header-Order, Go's map iteration order is used.
// This IS a detection signal but the shield only uses it for fingerprinting, not scoring.
type RealBrowserStrategy struct{}

func (s *RealBrowserStrategy) Name() string      { return "real_browser" }
func (s *RealBrowserStrategy) Fidelity() float64  { return 0.0 } // no fingerprint data preserved

func (s *RealBrowserStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	// Phase 1: Strip ALL custom X-* runtime headers.
	// The shield now covers every header count:
	//   - 0 headers → zero-header synthetic beacon gate (score 0.35)
	//   - 1-2 post-load only → cherry-pick gate (score 0.50)
	//   - 3+ with JS fingerprint → missing_* penalties cascade (score 1.0)
	//   - 6-7 headers → deep fingerprint analysis catches fabrication (score 1.0)
	// Zero headers gives the LOWEST detection score (0.38 via adaptive scorer),
	// so it's the least-bad option. The sword is fundamentally trapped.
	for _, h := range allRuntimeHeaders {
		req.Header.Del(h)
	}

	// IP spoofing is disabled at the config level (SpoofLocalIPs=false in
	// MaxEvasionConfig) because real browsers never send proxy IP headers.

	// Chrome profiles are fundamentally detectable from Go HTTP:
	//   - No GREASE in TLS (Go crypto/tls vs Chrome's BoringSSL)
	//   - Client Hints dilemma: keep → coverage 0.50, strip → Sec-Ch-Ua* 0.35
	//   - Both paths lead to detection via adaptive scorer MajorityVote amplifier
	//
	// The pragmatic fix: adopt a Firefox-compatible identity. Firefox doesn't use
	// Client Hints, and its TLS profile is closer to Go's. This matches what real
	// stealth tools do — consistent identity over high-fidelity impersonation.
	//
	// From lab captures, Firefox cross-site telemetry POSTs look identical to Chrome
	// except: no Sec-Ch-Ua*, no Priority header, Firefox-style Accept.
	if rg.profile.Browser == "chrome" {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")
	}
	req.Header.Del("Sec-Ch-Ua")
	req.Header.Del("Sec-Ch-Ua-Mobile")
	req.Header.Del("Sec-Ch-Ua-Platform")
	req.Header.Del("Sec-Ch-Ua-Full-Version-List")
	req.Header.Del("Sec-Ch-Ua-Arch")
	req.Header.Del("Sec-Ch-Ua-Bitness")
	req.Header.Del("Sec-Ch-Ua-Model")

	// Phase 2: Model as cross-site telemetry POST — matching real Sentry/FullStory
	// beacons from lab captures.
	req.Method = http.MethodPost

	body := buildCleanAnalyticsBody(rg)
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))

	// Use application/json — this triggers a CORS preflight in a real browser,
	// but the shield's synthetic beacon check only fires for CORS-safe content
	// types (text/plain, form-urlencoded, multipart). Using application/json
	// bypasses the isCorsSafe gate. Real internal analytics endpoints that use
	// CORS with preflight commonly use application/json.
	req.Header.Set("Content-Type", "application/json")

	// Same-site CORS fetch metadata — models a cross-subdomain analytics POST
	// (e.g. app.example.com → api.example.com). This is how real internal
	// analytics endpoints work: the dashboard and API share a registrable domain.
	// The shield's same-site gate requires runtimeHeaderCount >= 3-4 for all
	// checks, so zero-header requests pass through silently.
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Del("Sec-Fetch-User")

	// Same-site: Origin is a sibling subdomain of the request URL host.
	// E.g. request to api.example.com has Origin: https://app.example.com
	if parsed, err := url.Parse(targetURL); err == nil {
		host := parsed.Host
		if !strings.Contains(host, ":") {
			host = "app." + host
		} else {
			parts := strings.SplitN(host, ":", 2)
			host = "app." + parts[0] + ":" + parts[1]
		}
		req.Header.Set("Origin", parsed.Scheme+"://"+host)
		req.Header.Del("Referer") // no-referrer policy — common for internal analytics
	}

	req.Header.Del("Upgrade-Insecure-Requests")
	// Use XHR/fetch Accept — avoid bare "*/*" which the shield flags as generic.
	// Lab captures show real portal/API calls use this format (e.g. Afterpay portal).
	req.Header.Set("Accept", "application/json, text/plain, */*")

	// Firefox doesn't send Priority header on fetch POSTs.
	// Since we adopt Firefox identity for all profiles, always strip it.
	req.Header.Del("Priority")

	// Rebuild header order — strip all removed headers but keep correct relative
	// order to avoid suspicious_header_order (isomorphic analyzer checks UA vs Accept).
	removed := map[string]bool{
		"Upgrade-Insecure-Requests":    true,
		"Sec-Fetch-User":              true,
		"Sec-Ch-Ua":                   true,
		"Sec-Ch-Ua-Mobile":            true,
		"Sec-Ch-Ua-Platform":          true,
		"Sec-Ch-Ua-Full-Version-List": true,
		"Sec-Ch-Ua-Arch":              true,
		"Sec-Ch-Ua-Bitness":           true,
		"Sec-Ch-Ua-Model":             true,
		"Priority":                    true,
	}
	for _, h := range allRuntimeHeaders {
		removed[h] = true
	}
	rebuildHeaderOrder(req, removed)
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy N: NoneContextCorsStrategy (fidelity = 0.60)
// ─────────────────────────────────────────────────────────────────────────────
// Threshold-proof evasion that targets score = 0.00 by exploiting three
// independent structural invariants in the shield:
//
//  1. Provenance bypass: site=none matches NO gate function (sub-checks 3-7
//     all require same-site, cross-site, same-origin, or document+navigate).
//
//  2. Coverage nil band: presentCount in [6,7] with < 8 → analyzeFingerprintCoverage
//     returns nil, emitting no vector at all. No threshold change can catch zero.
//
//  3. Missing-header immunity: all 4 must-keep headers present (Behavioral,
//     Timing, Canvas, Audio) so no missing_* penalty fires even though
//     hasJSFingerprintHeaders=true (Navigator, WebGL are included).
//
// The shield cannot lower the bot threshold below 0. The only counter is to
// remove the nil band, add a new gate for site=none, or flag the specific
// 6-header composition — all of which are structural changes, not knob turns.
type NoneContextCorsStrategy struct{}

func (s *NoneContextCorsStrategy) Name() string      { return "none_context_cors" }
func (s *NoneContextCorsStrategy) Fidelity() float64  { return 0.6 }

func (s *NoneContextCorsStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	req.Method = http.MethodPost

	body := buildCleanAnalyticsBody(rg)
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/json")

	// site=none bypasses ALL provenance gate functions.
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Del("Sec-Fetch-User")
	req.Header.Del("Referer")

	if parsed, err := url.Parse(targetURL); err == nil {
		req.Header.Set("Origin", parsed.Scheme+"://"+parsed.Host)
	}

	req.Header.Del("Upgrade-Insecure-Requests")
	req.Header.Set("Accept", "application/json, text/plain, */*")

	if rg.profile.Browser == "chrome" {
		req.Header.Set("Priority", "u=1, i")
	}

	// Keep exactly 6 runtime headers = 4 must-keep + 2 safe:
	//   Must-keep: Behavioral, Timing, Canvas, Audio → no missing_* penalties
	//   Safe:      Navigator, WebGL → hasJSFP=true but irrelevant (all must-keep present)
	//   Stripped:  Plugin, Screen, Font, WebRTC (4 safe headers removed)
	// presentCount=6 → coverage nil band → score 0.00
	req.Header.Del(constants.HeaderPluginData)
	req.Header.Del(constants.HeaderScreenData)
	req.Header.Del(constants.HeaderFontData)
	req.Header.Del(constants.HeaderWebRTCData)

	removed := map[string]bool{
		"Upgrade-Insecure-Requests":  true,
		"Sec-Fetch-User":            true,
		"Referer":                   true,
		constants.HeaderPluginData:   true,
		constants.HeaderScreenData:   true,
		constants.HeaderFontData:     true,
		constants.HeaderWebRTCData:   true,
	}
	rebuildHeaderOrder(req, removed)
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy S: SameOriginSubThresholdStrategy (fidelity = 0.55)
// ─────────────────────────────────────────────────────────────────────────────
// Fallback zero-score strategy using a different provenance path.
// Uses mode=same-origin + site=same-site (enters sub-check 3 gate) but with
// only 2 runtime headers (below the 3-header threshold), so all interior
// checks skip. Combined with the coverage nil band at 6 headers for zero score.
//
// Wait — with mode=same-origin + site=same-site, if we use 6 headers,
// runtimeHeaderCount=6 >= 3 triggers same_site_same_origin_mode_mismatch.
// So this strategy uses site=cross-site instead:
//   - Sub-check 3: requires site=same-site → cross-site → SKIP
//   - Sub-check 4: requires mode=cors → same-origin → SKIP
//   - Sub-check 7: requires site=same-origin → cross-site → SKIP
// All gates skipped, 6 headers in nil band → score 0.00.
type SameOriginSubThresholdStrategy struct{}

func (s *SameOriginSubThresholdStrategy) Name() string      { return "cross_site_same_origin" }
func (s *SameOriginSubThresholdStrategy) Fidelity() float64  { return 0.55 }

func (s *SameOriginSubThresholdStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	req.Method = http.MethodPost

	body := buildCleanAnalyticsBody(rg)
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/json")

	// mode=same-origin + site=cross-site: bypasses ALL gate functions.
	// Sub-check 3 needs site=same-site, sub-check 4 needs mode=cors,
	// sub-check 7 needs site=same-origin.
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "same-origin")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Del("Sec-Fetch-User")
	req.Header.Del("Referer")

	if parsed, err := url.Parse(targetURL); err == nil {
		host := parsed.Host
		if !strings.Contains(host, ":") {
			host = "app." + host
		} else {
			parts := strings.SplitN(host, ":", 2)
			host = "app." + parts[0] + ":" + parts[1]
		}
		req.Header.Set("Origin", parsed.Scheme+"://"+host)
	}

	req.Header.Del("Upgrade-Insecure-Requests")
	req.Header.Set("Accept", "application/json, text/plain, */*")

	if rg.profile.Browser == "chrome" {
		req.Header.Set("Priority", "u=1, i")
	}

	// Keep exactly 6 runtime headers: 4 must-keep + 2 safe → nil coverage band
	req.Header.Del(constants.HeaderPluginData)
	req.Header.Del(constants.HeaderScreenData)
	req.Header.Del(constants.HeaderFontData)
	req.Header.Del(constants.HeaderWebRTCData)

	removed := map[string]bool{
		"Upgrade-Insecure-Requests":  true,
		"Sec-Fetch-User":            true,
		"Referer":                   true,
		constants.HeaderPluginData:   true,
		constants.HeaderScreenData:   true,
		constants.HeaderFontData:     true,
		constants.HeaderWebRTCData:   true,
	}
	rebuildHeaderOrder(req, removed)
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy 0a: SameOriginSameSiteStrategy (fidelity = 0.70)
// ─────────────────────────────────────────────────────────────────────────────
// Exploits the gate gap between sub-check 3 (requires mode=cors) and sub-check 7
// (requires site=same-origin). By using mode=same-origin + site=same-site, ALL
// provenance sub-checks (3-7) are bypassed.
//
// Gate analysis:
//   - Sub-check 3 (same-site cors): requires mode=cors → we use same-origin → SKIP
//   - Sub-check 4 (cross-site cors): requires site=cross-site → same-site → SKIP
//   - Sub-check 5 (no-cors): requires mode=no-cors → same-origin → SKIP
//   - Sub-check 6 (navigate): requires dest=document + mode=navigate → SKIP
//   - Sub-check 7 (same-origin): requires site=same-origin → same-site → SKIP
//
// Coverage: presentCount=7 → nil band (6-7 returns nil).
// hasJSFP=true (safe headers present) but all must-keep headers are present → no missing_*.
type SameOriginSameSiteStrategy struct{}

func (s *SameOriginSameSiteStrategy) Name() string     { return "same_site_telemetry" }
func (s *SameOriginSameSiteStrategy) Fidelity() float64 { return 0.7 }

func (s *SameOriginSameSiteStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	req.Method = http.MethodPost

	body := buildCleanAnalyticsBody(rg)
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/json")

	// mode=same-origin + site=same-site: falls through ALL gate functions.
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "same-origin")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Del("Sec-Fetch-User")
	req.Header.Del("Referer")

	if parsed, err := url.Parse(targetURL); err == nil {
		// Set Origin to a sibling subdomain so it doesn't match the request URL
		// (avoids isOriginSameAsRequestURL even though sub-checks don't fire).
		host := parsed.Host
		if !strings.Contains(host, ":") {
			host = "app." + host
		} else {
			parts := strings.SplitN(host, ":", 2)
			host = "app." + parts[0] + ":" + parts[1]
		}
		req.Header.Set("Origin", parsed.Scheme+"://"+host)
	}

	req.Header.Del("Upgrade-Insecure-Requests")
	req.Header.Set("Accept", "application/json, text/plain, */*")

	if rg.profile.Browser == "chrome" {
		req.Header.Set("Priority", "u=1, i")
	}

	// Strip 3 safe headers → presentCount=7 (coverage nil at 6-7).
	req.Header.Del(constants.HeaderFontData)
	req.Header.Del(constants.HeaderWebRTCData)
	req.Header.Del(constants.HeaderScreenData)

	rebuildHeaderOrder(req, map[string]bool{
		"Upgrade-Insecure-Requests": true,
		"Sec-Fetch-User":           true,
		"Referer":                  true,
		constants.HeaderFontData:   true,
		constants.HeaderWebRTCData: true,
		constants.HeaderScreenData: true,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy 0b: SameOriginSameSiteMinimalStrategy (fidelity = 0.40)
// ─────────────────────────────────────────────────────────────────────────────
// Same gate-gap exploit as Strategy 0a but with only 3 must-keep headers,
// providing a lower-fidelity fallback. With presentCount=3 and secChUa present,
// coverage score = 0.30*(1-0.3)=0.21 which is below the 0.35 bot threshold.
// hasJSFP=false (no safe headers) → no missing_* penalties.
type SameOriginSameSiteMinimalStrategy struct{}

func (s *SameOriginSameSiteMinimalStrategy) Name() string     { return "reduced_beacon" }
func (s *SameOriginSameSiteMinimalStrategy) Fidelity() float64 { return 0.4 }

func (s *SameOriginSameSiteMinimalStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	req.Method = http.MethodPost

	body := buildCleanAnalyticsBody(rg)
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/json")

	// mode=same-origin + site=same-site: falls through ALL gate functions.
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "same-origin")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Del("Sec-Fetch-User")
	req.Header.Del("Referer")

	if parsed, err := url.Parse(targetURL); err == nil {
		host := parsed.Host
		if !strings.Contains(host, ":") {
			host = "app." + host
		} else {
			parts := strings.SplitN(host, ":", 2)
			host = "app." + parts[0] + ":" + parts[1]
		}
		req.Header.Set("Origin", parsed.Scheme+"://"+host)
	}

	req.Header.Del("Upgrade-Insecure-Requests")
	req.Header.Set("Accept", "application/json, text/plain, */*")

	if rg.profile.Browser == "chrome" {
		req.Header.Set("Priority", "u=1, i")
	}

	// Strip ALL safe headers + Audio → presentCount=3 (Behavioral, Timing, Canvas)
	for _, h := range safeHeaders {
		req.Header.Del(h)
	}
	req.Header.Del(constants.HeaderAudioData)

	removed := map[string]bool{
		"Upgrade-Insecure-Requests": true,
		"Sec-Fetch-User":           true,
		"Referer":                  true,
	}
	for _, h := range safeHeaders {
		removed[h] = true
	}
	removed[constants.HeaderAudioData] = true
	rebuildHeaderOrder(req, removed)
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy 1: SameSiteCorsStrategy (fidelity = 0.70)  [CAUGHT by hardened shield]
// ─────────────────────────────────────────────────────────────────────────────
// Models a cross-subdomain XHR (e.g. app.example.com → api.example.com)
// under Referrer-Policy: no-referrer.
//
// Gate analysis:
//   - Sub-check 3 (same-site cors): requires Referer!="" → we suppress Referer → SKIP
//   - Sub-check 5 (no-cors): requires mode=no-cors → we use mode=cors → SKIP
//   - Sub-check 6 (navigate): requires dest=document → we use dest=empty → SKIP
//   - Sub-check 7 (same-origin): requires site=same-origin → we use same-site → SKIP
//
// Coverage: presentCount=7 → nil band (6-7 returns nil).
type SameSiteCorsStrategy struct{}

func (s *SameSiteCorsStrategy) Name() string     { return "same_site_cors_telemetry" }
func (s *SameSiteCorsStrategy) Fidelity() float64 { return 0.7 }

func (s *SameSiteCorsStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	req.Method = http.MethodPost

	body := buildCleanAnalyticsBody(rg)
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/json")

	// mode=cors + site=same-site: dodges Sub-check 7 (needs same-origin)
	// and Sub-check 3 (needs Referer). Sub-check 5 needs no-cors.
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Del("Sec-Fetch-User")
	req.Header.Del("Referer")

	if parsed, err := url.Parse(targetURL); err == nil {
		req.Header.Set("Origin", parsed.Scheme+"://"+parsed.Host)
	}

	req.Header.Del("Upgrade-Insecure-Requests")
	req.Header.Set("Accept", "application/json, text/plain, */*")

	if rg.profile.Browser == "chrome" {
		req.Header.Set("Priority", "u=1, i")
	}

	// Strip 3 safe headers → presentCount=7 (coverage nil at 6-7).
	req.Header.Del(constants.HeaderFontData)
	req.Header.Del(constants.HeaderWebRTCData)
	req.Header.Del(constants.HeaderScreenData)

	rebuildHeaderOrder(req, map[string]bool{
		"Upgrade-Insecure-Requests":  true,
		"Sec-Fetch-User":            true,
		"Referer":                   true,
		constants.HeaderFontData:    true,
		constants.HeaderWebRTCData:  true,
		constants.HeaderScreenData:  true,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy 2: CrossSiteNavigateStrategy (fidelity = 0.65)
// ─────────────────────────────────────────────────────────────────────────────
// Models a cross-site form submission (e.g. shop.com → payment-gateway.com).
//
// Gate analysis:
//   - Sub-check 6 (navigate): requires site=same-origin → we use cross-site → SKIP
//   - Sub-checks 3-5,7: require dest=empty → we use dest=document → SKIP
//   - isInitialNavigation: requires site=none → we use cross-site → SKIP
//
// Coverage: presentCount=7 → nil band.
type CrossSiteNavigateStrategy struct{}

func (s *CrossSiteNavigateStrategy) Name() string     { return "navigate_form" }
func (s *CrossSiteNavigateStrategy) Fidelity() float64 { return 0.65 }

func (s *CrossSiteNavigateStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	req.Method = http.MethodPost

	body := buildCleanFormBody(rg)
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// dest=document bypasses all dest=empty gates.
	// site=cross-site bypasses Sub-check 6 (needs same-origin).
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Del("Referer")

	if parsed, err := url.Parse(targetURL); err == nil {
		req.Header.Set("Origin", parsed.Scheme+"://"+parsed.Host)
	}

	req.Header.Set("Upgrade-Insecure-Requests", "1")
	if rg.profile.Browser == "chrome" {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
		req.Header.Set("Priority", "u=0, i")
	} else {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
		req.Header.Del("Priority")
	}

	// Strip 3 safe headers → presentCount=7 (coverage nil at 6-7).
	req.Header.Del(constants.HeaderFontData)
	req.Header.Del(constants.HeaderWebRTCData)
	req.Header.Del(constants.HeaderScreenData)

	rebuildHeaderOrder(req, map[string]bool{
		"Referer":                   true,
		constants.HeaderFontData:    true,
		constants.HeaderWebRTCData:  true,
		constants.HeaderScreenData:  true,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy 3: CrossSiteCorsStrategy (fidelity = 0.55)
// ─────────────────────────────────────────────────────────────────────────────
// Models a third-party API call (e.g. analytics.thirdparty.com) under
// Referrer-Policy: no-referrer.
//
// Gate analysis:
//   - Sub-check 4 (cross-site cors): requires Referer!="" → no Referer → SKIP
//   - Sub-check 7 (same-origin): requires site=same-origin → cross-site → SKIP
//   - Sub-check 5 (no-cors): requires mode=no-cors → cors → SKIP
//   - Sub-check 6 (navigate): requires dest=document → empty → SKIP
//
// Coverage: presentCount=7 → nil band.
type CrossSiteCorsStrategy struct{}

func (s *CrossSiteCorsStrategy) Name() string     { return "cross_site_cors" }
func (s *CrossSiteCorsStrategy) Fidelity() float64 { return 0.55 }

func (s *CrossSiteCorsStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	req.Method = http.MethodPost

	body := buildCleanAnalyticsBody(rg)
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/json")

	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Del("Sec-Fetch-User")
	req.Header.Del("Referer")

	if parsed, err := url.Parse(targetURL); err == nil {
		req.Header.Set("Origin", parsed.Scheme+"://"+parsed.Host)
	}

	req.Header.Del("Upgrade-Insecure-Requests")
	req.Header.Set("Accept", "application/json, text/plain, */*")

	if rg.profile.Browser == "chrome" {
		req.Header.Set("Priority", "u=1, i")
	}

	req.Header.Del(constants.HeaderFontData)
	req.Header.Del(constants.HeaderWebRTCData)
	req.Header.Del(constants.HeaderScreenData)

	rebuildHeaderOrder(req, map[string]bool{
		"Upgrade-Insecure-Requests":  true,
		"Sec-Fetch-User":            true,
		"Referer":                   true,
		constants.HeaderFontData:    true,
		constants.HeaderWebRTCData:  true,
		constants.HeaderScreenData:  true,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy 4: SameSiteMinimalStrategy (fidelity = 0.40)
// ─────────────────────────────────────────────────────────────────────────────
// Same-site cors approach with only 4 must-keep headers. Falls below any
// runtimeHeaderCount >= 5 gate. hasJSFP=false → no missing_* penalties.
// Coverage: presentCount=4, secChUa present → 0.30*(1-0.4)=0.18 → below threshold.
type SameSiteMinimalStrategy struct{}

func (s *SameSiteMinimalStrategy) Name() string     { return "cors_reduced_beacon" }
func (s *SameSiteMinimalStrategy) Fidelity() float64 { return 0.4 }

func (s *SameSiteMinimalStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	req.Method = http.MethodPost

	body := buildCleanAnalyticsBody(rg)
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/json")

	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Del("Sec-Fetch-User")
	req.Header.Del("Referer")

	if parsed, err := url.Parse(targetURL); err == nil {
		req.Header.Set("Origin", parsed.Scheme+"://"+parsed.Host)
	}

	req.Header.Del("Upgrade-Insecure-Requests")
	req.Header.Set("Accept", "application/json, text/plain, */*")

	if rg.profile.Browser == "chrome" {
		req.Header.Set("Priority", "u=1, i")
	}

	for _, h := range safeHeaders {
		req.Header.Del(h)
	}

	removed := map[string]bool{
		"Upgrade-Insecure-Requests": true,
		"Sec-Fetch-User":           true,
		"Referer":                  true,
	}
	for _, h := range safeHeaders {
		removed[h] = true
	}
	rebuildHeaderOrder(req, removed)
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy 5: NavigateMinimalStrategy (fidelity = 0.30)
// ─────────────────────────────────────────────────────────────────────────────
// Cross-site navigate with only 4 must-keep headers. Double protection:
// dest=document bypasses dest=empty gates, 4 headers below count thresholds.
type NavigateMinimalStrategy struct{}

func (s *NavigateMinimalStrategy) Name() string     { return "navigate_minimal" }
func (s *NavigateMinimalStrategy) Fidelity() float64 { return 0.3 }

func (s *NavigateMinimalStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	req.Method = http.MethodPost

	body := buildCleanFormBody(rg)
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Del("Referer")

	if parsed, err := url.Parse(targetURL); err == nil {
		req.Header.Set("Origin", parsed.Scheme+"://"+parsed.Host)
	}

	req.Header.Set("Upgrade-Insecure-Requests", "1")
	if rg.profile.Browser == "chrome" {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
		req.Header.Set("Priority", "u=0, i")
	} else {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
		req.Header.Del("Priority")
	}

	for _, h := range safeHeaders {
		req.Header.Del(h)
	}

	removed := map[string]bool{
		"Referer": true,
	}
	for _, h := range safeHeaders {
		removed[h] = true
	}
	rebuildHeaderOrder(req, removed)
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy 6 (fallback): BodyMigrationStrategy (fidelity = 1.0)
// ─────────────────────────────────────────────────────────────────────────────
type BodyMigrationStrategy struct{}

func (s *BodyMigrationStrategy) Name() string     { return "body_migration" }
func (s *BodyMigrationStrategy) Fidelity() float64 { return 1.0 }

func (s *BodyMigrationStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	fpData := collectHeaderValues(req, allRuntimeHeaders)
	applySameOriginPostTransform(req, rg, targetURL)

	body := buildBodyWithMigratedData(rg, fpData)
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/json")

	for _, h := range allRuntimeHeaders {
		req.Header.Del(h)
	}

	if v, ok := fpData[constants.HeaderBehavioralData]; ok && v != "" {
		req.Header.Set(constants.HeaderBehavioralData, v)
	}
	if v, ok := fpData[constants.HeaderTimingData]; ok && v != "" {
		req.Header.Set(constants.HeaderTimingData, v)
	}

	removed := make(map[string]bool)
	for _, h := range allRuntimeHeaders {
		removed[h] = true
	}
	removed["Upgrade-Insecure-Requests"] = true
	removed["Sec-Fetch-User"] = true
	delete(removed, constants.HeaderBehavioralData)
	delete(removed, constants.HeaderTimingData)
	rebuildHeaderOrder(req, removed)
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy 7 (fallback): SelectiveStripStrategy (fidelity = 0.2)
// ─────────────────────────────────────────────────────────────────────────────
type SelectiveStripStrategy struct{}

func (s *SelectiveStripStrategy) Name() string     { return "selective_strip" }
func (s *SelectiveStripStrategy) Fidelity() float64 { return 0.2 }

func (s *SelectiveStripStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	applySameOriginPostTransform(req, rg, targetURL)

	body := buildMinimalTelemetryBody(rg)
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/json")

	headersToStrip := []string{
		constants.HeaderNavigatorData,
		constants.HeaderWebGLData,
		constants.HeaderPluginData,
		constants.HeaderFontData,
		constants.HeaderScreenData,
		constants.HeaderWebRTCData,
		constants.HeaderCanvasFingerprint,
		constants.HeaderAudioData,
	}
	for _, h := range headersToStrip {
		req.Header.Del(h)
	}

	removed := make(map[string]bool)
	for _, h := range headersToStrip {
		removed[h] = true
	}
	removed["Upgrade-Insecure-Requests"] = true
	removed["Sec-Fetch-User"] = true
	rebuildHeaderOrder(req, removed)
}

// ─────────────────────────────────────────────────────────────────────────────
// AdaptiveEvasionFSM
// ─────────────────────────────────────────────────────────────────────────────

type AdaptiveEvasionFSM struct {
	strategies         []EvasionStrategy
	stateIdx           int
	states             []*FSMState
	transitions        []FSMTransition
	mu                 sync.Mutex
	banSignals         int
	banSignalThreshold int
	exhausted          bool
}

type FSMState struct {
	Strategy   EvasionStrategy
	Attempts   int
	Detections int
	TotalScore float64
}

type FSMTransition struct {
	From   string
	To     string
	Score  float64
	Reason string
}

func NewAdaptiveEvasionFSM(strategies ...EvasionStrategy) *AdaptiveEvasionFSM {
	if len(strategies) == 0 {
		strategies = DefaultStrategies()
	}
	states := make([]*FSMState, len(strategies))
	for i, s := range strategies {
		states[i] = &FSMState{Strategy: s}
	}
	return &AdaptiveEvasionFSM{
		strategies:         strategies,
		states:             states,
		banSignalThreshold: 3,
	}
}

func (fsm *AdaptiveEvasionFSM) CurrentStrategy() EvasionStrategy {
	fsm.mu.Lock()
	defer fsm.mu.Unlock()
	if fsm.stateIdx >= len(fsm.strategies) {
		return fsm.strategies[len(fsm.strategies)-1]
	}
	return fsm.strategies[fsm.stateIdx]
}

func (fsm *AdaptiveEvasionFSM) RecordResult(score float64, detected bool) {
	fsm.mu.Lock()
	defer fsm.mu.Unlock()

	state := fsm.states[fsm.stateIdx]
	state.Attempts++
	state.TotalScore += score
	if detected {
		state.Detections++
	}

	if state.Attempts >= 3 {
		detectionRate := float64(state.Detections) / float64(state.Attempts)
		if detectionRate > 0.5 {
			from := fsm.strategies[fsm.stateIdx].Name()
			if fsm.stateIdx < len(fsm.strategies)-1 {
				fsm.stateIdx++
				to := fsm.strategies[fsm.stateIdx].Name()
				fsm.transitions = append(fsm.transitions, FSMTransition{
					From:   from,
					To:     to,
					Score:  score,
					Reason: fmt.Sprintf("detection_rate=%.0f%% after %d trials", detectionRate*100, state.Attempts),
				})
			} else {
				// Terminal strategy also failing — signal exhaustion
				fsm.exhausted = true
				fsm.transitions = append(fsm.transitions, FSMTransition{
					From:   from,
					To:     "browser_escalation",
					Score:  score,
					Reason: fmt.Sprintf("terminal_exhausted: detection_rate=%.0f%% after %d trials", detectionRate*100, state.Attempts),
				})
			}
		}
	}
}

// Exhausted returns true when all strategies have been tried and the terminal
// strategy also exceeds the detection threshold.
func (fsm *AdaptiveEvasionFSM) Exhausted() bool {
	fsm.mu.Lock()
	defer fsm.mu.Unlock()
	return fsm.exhausted
}

// RecordBanSignal increments the ban signal counter for HTTP-level ban responses.
func (fsm *AdaptiveEvasionFSM) RecordBanSignal(statusCode int) {
	fsm.mu.Lock()
	defer fsm.mu.Unlock()
	fsm.banSignals++
}

// ShouldEscalate returns true if the FSM recommends escalating to browser mode,
// either because all strategies are exhausted or ban signals exceed the threshold.
func (fsm *AdaptiveEvasionFSM) ShouldEscalate() bool {
	fsm.mu.Lock()
	defer fsm.mu.Unlock()
	return fsm.exhausted || fsm.banSignals >= fsm.banSignalThreshold
}

// EscalationReason returns why escalation is recommended.
func (fsm *AdaptiveEvasionFSM) EscalationReason() string {
	fsm.mu.Lock()
	defer fsm.mu.Unlock()
	if fsm.exhausted {
		return "fsm_exhausted"
	}
	if fsm.banSignals >= fsm.banSignalThreshold {
		return "ban_signals"
	}
	return ""
}

// ResetBanSignals clears the ban signal counter (e.g. after a successful browser request).
func (fsm *AdaptiveEvasionFSM) ResetBanSignals() {
	fsm.mu.Lock()
	defer fsm.mu.Unlock()
	fsm.banSignals = 0
}

func (fsm *AdaptiveEvasionFSM) Converged() bool {
	fsm.mu.Lock()
	defer fsm.mu.Unlock()
	state := fsm.states[fsm.stateIdx]
	if state.Attempts < 3 {
		return false
	}
	return float64(state.Detections)/float64(state.Attempts) < 0.5
}

func (fsm *AdaptiveEvasionFSM) Summary() string {
	fsm.mu.Lock()
	defer fsm.mu.Unlock()

	var sb strings.Builder
	sb.WriteString("=== Adaptive Evasion FSM ===\n")
	for i, state := range fsm.states {
		if state.Attempts == 0 {
			continue
		}
		avgScore := state.TotalScore / float64(state.Attempts)
		detRate := float64(state.Detections) / float64(state.Attempts)
		marker := "  "
		if i == fsm.stateIdx {
			marker = "> "
		}
		fmt.Fprintf(&sb, "%s%-22s fidelity=%.0f%%  %d/%d detected (%.0f%%)  avg_score=%.3f\n",
			marker, state.Strategy.Name(), state.Strategy.Fidelity()*100,
			state.Detections, state.Attempts, detRate*100, avgScore)
	}
	for _, t := range fsm.transitions {
		fmt.Fprintf(&sb, "  transition: %s -> %s (%s)\n", t.From, t.To, t.Reason)
	}
	fmt.Fprintf(&sb, "  exhausted=%v ban_signals=%d/%d\n", fsm.exhausted, fsm.banSignals, fsm.banSignalThreshold)
	return sb.String()
}

func (fsm *AdaptiveEvasionFSM) StateIndex() int {
	fsm.mu.Lock()
	defer fsm.mu.Unlock()
	return fsm.stateIdx
}

func (fsm *AdaptiveEvasionFSM) Transitions() []FSMTransition {
	fsm.mu.Lock()
	defer fsm.mu.Unlock()
	return append([]FSMTransition{}, fsm.transitions...)
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

func collectHeaderValues(req *http.Request, headers []string) map[string]string {
	data := make(map[string]string)
	for _, h := range headers {
		if v := req.Header.Get(h); v != "" {
			data[h] = v
		}
	}
	return data
}

func applySameOriginPostTransform(req *http.Request, rg *RequestGenerator, targetURL string) {
	req.Method = http.MethodPost
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "same-origin")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Del("Sec-Fetch-User")

	if parsed, err := url.Parse(targetURL); err == nil {
		originPage := parsed.Scheme + "://" + parsed.Host + "/"
		req.Header.Set("Referer", originPage)
		req.Header.Set("Origin", parsed.Scheme+"://"+parsed.Host)
	}

	req.Header.Del("Upgrade-Insecure-Requests")
	req.Header.Set("Accept", "application/json, text/plain, */*")

	if rg.profile.Browser == "chrome" {
		req.Header.Set("Priority", "u=1, i")
	}
}

func buildCleanAnalyticsBody(rg *RequestGenerator) []byte {
	sessionID := fmt.Sprintf("%x", rg.rng.Uint64())
	ts := time.Now().Add(-time.Duration(2000+rg.rng.Intn(5000)) * time.Millisecond).UnixMilli()
	// Build a realistic analytics envelope matching FullStory/Amplitude-style format.
	// Real SDKs include standalone runtime data objects at the top level — the shield
	// now checks for exact JSON key matches ("navigator", "timing", "canvas") rather
	// than substring matching, so we must use genuine runtime key names with realistic
	// browser data structures.
	//
	// These fields mirror what real browser-side telemetry SDKs collect:
	//   - navigator: window.navigator properties
	//   - timing: performance.timing / PerformanceNavigationTiming API
	//   - canvas: CanvasRenderingContext2D fingerprint hash
	bodyJSON := fmt.Sprintf(
		`{"sid":"%s","ts":%d,"page":"/","v":"2.1.0","seq":%d,`+
			`"navigator":{"userAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0","language":"en-US","languages":["en-US","en"],"hardwareConcurrency":%d,"deviceMemory":%d,"platform":"Win32","maxTouchPoints":0,"cookieEnabled":true,"doNotTrack":null},`+
			`"timing":{"connectStart":%d,"domComplete":%d,"domContentLoadedEventEnd":%d,"domInteractive":%d,"fetchStart":%d,"loadEventEnd":%d,"responseEnd":%d,"responseStart":%d},`+
			`"canvas":"%x%x",`+
			`"perf":{"ttfb":%d,"fcp":%d,"lcp":%d,"cls":0.%d,"inp":%d},`+
			`"viewport":{"w":%d,"h":%d,"dpr":%d},`+
			`"session":{"referrer":"https://www.google.com/search?q=example","entry":"/","depth":%d,"duration":%d},`+
			`"sdk":{"name":"web-vitals","version":"3.5.2","integrations":["BrowserTracing","Replay"]},`+
			`"env":{"release":"prod-2024.%d.%d","environment":"production","dist":"%x"},`+
			`"tags":{"transaction":"/api/data","http.method":"GET","http.status_code":"200"},`+
			`"breadcrumbs":[{"type":"navigation","timestamp":%d,"data":{"from":"/","to":"/dashboard"}},`+
			`{"type":"ui.click","timestamp":%d,"message":"button.submit","data":{"nodeId":%d}}],`+
			`"contexts":{"device":{"family":"Desktop"},"os":{"name":"Windows","version":"10"},"browser":{"name":"Firefox","version":"128.0"}}}`,
		sessionID, ts, 1+rg.rng.Intn(5),
		// navigator
		4+rg.rng.Intn(12), 4+rg.rng.Intn(4)*4,
		// timing (relative to fetchStart baseline)
		ts-int64(3000+rg.rng.Intn(2000)), ts+int64(800+rg.rng.Intn(2000)),
		ts+int64(400+rg.rng.Intn(1500)), ts+int64(300+rg.rng.Intn(1200)),
		ts-int64(3000+rg.rng.Intn(2000)), ts+int64(900+rg.rng.Intn(2500)),
		ts+int64(100+rg.rng.Intn(500)), ts+int64(80+rg.rng.Intn(400)),
		// canvas hash
		rg.rng.Uint64(), rg.rng.Uint64(),
		// perf
		80+rg.rng.Intn(300), 180+rg.rng.Intn(400), 380+rg.rng.Intn(800),
		1+rg.rng.Intn(200), 50+rg.rng.Intn(200),
		// viewport
		1280+rg.rng.Intn(640), 720+rg.rng.Intn(360), 1+rg.rng.Intn(2),
		// session
		1+rg.rng.Intn(8), 5000+rg.rng.Intn(30000),
		// env
		1+rg.rng.Intn(12), 1+rg.rng.Intn(30), rg.rng.Uint32(),
		// breadcrumbs
		ts-int64(1000+rg.rng.Intn(3000)), ts-int64(500+rg.rng.Intn(1500)),
		100+rg.rng.Intn(500))
	return []byte(bodyJSON)
}

func buildCleanFormBody(rg *RequestGenerator) []byte {
	sessionID := fmt.Sprintf("%x", rg.rng.Uint64())
	ts := time.Now().Add(-time.Duration(2000+rg.rng.Intn(5000)) * time.Millisecond).UnixMilli()
	body := fmt.Sprintf(
		"sid=%s&ts=%d&page=%%2F&v=2.1.0&seq=%d&w=%d&h=%d&depth=%d",
		sessionID, ts, 1+rg.rng.Intn(5),
		1280+rg.rng.Intn(640), 720+rg.rng.Intn(360),
		1+rg.rng.Intn(8))
	return []byte(body)
}

func buildBodyWithMigratedData(rg *RequestGenerator, fpData map[string]string) []byte {
	sessionID := fmt.Sprintf("%x", rg.rng.Uint64())
	pageLoadTs := time.Now().Add(-time.Duration(2000+rg.rng.Intn(5000)) * time.Millisecond).UnixMilli()
	ttfb := 80 + rg.rng.Intn(300)
	fcp := ttfb + 100 + rg.rng.Intn(400)
	lcp := fcp + 200 + rg.rng.Intn(800)

	payload := map[string]any{
		"sid":  sessionID,
		"ts":   pageLoadTs,
		"page": "/",
		"v":    "2.1.0",
		"seq":  1 + rg.rng.Intn(5),
		"navigator": map[string]any{
			"lang":  rg.profile.AcceptLanguage,
			"cores": rg.profile.HardwareConcurrency,
			"mem":   rg.profile.DeviceMemory,
		},
		"timing": map[string]any{
			"ttfb": ttfb,
			"fcp":  fcp,
			"lcp":  lcp,
		},
		"canvas": fmt.Sprintf("%x", rg.rng.Uint64()),
		"audio":  fmt.Sprintf("%x", rg.rng.Uint64()),
		"webgl": map[string]any{
			"vendor":   "Google Inc.",
			"renderer": "ANGLE",
		},
	}

	if len(fpData) > 0 {
		runtime := make(map[string]string)
		for header, value := range fpData {
			key := strings.TrimPrefix(header, "X-")
			key = strings.ReplaceAll(key, "-", "_")
			key = strings.ToLower(key)
			runtime[key] = value
		}
		payload["runtime"] = runtime
	}

	body, _ := json.Marshal(payload)
	return body
}

func buildMinimalTelemetryBody(rg *RequestGenerator) []byte {
	sessionID := fmt.Sprintf("%x", rg.rng.Uint64())
	pageLoadTs := time.Now().Add(-time.Duration(2000+rg.rng.Intn(5000)) * time.Millisecond).UnixMilli()
	ttfb := 80 + rg.rng.Intn(300)
	fcp := ttfb + 100 + rg.rng.Intn(400)
	lcp := fcp + 200 + rg.rng.Intn(800)

	bodyJSON := fmt.Sprintf(
		`{"sid":"%s","ts":%d,"page":"/","v":"1.4.2","seq":%d,`+
			`"navigator":{"lang":"%s","cores":%d,"mem":%d},`+
			`"timing":{"ttfb":%d,"fcp":%d,"lcp":%d},`+
			`"canvas":"%x","audio":"%x",`+
			`"webgl":{"vendor":"Google Inc.","renderer":"ANGLE"}}`,
		sessionID, pageLoadTs, 1+rg.rng.Intn(5),
		rg.profile.AcceptLanguage, rg.profile.HardwareConcurrency, rg.profile.DeviceMemory,
		ttfb, fcp, lcp,
		rg.rng.Uint64(), rg.rng.Uint64())
	return []byte(bodyJSON)
}

func rebuildHeaderOrder(req *http.Request, removed map[string]bool) {
	order := req.Header.Get("X-Stealth-Header-Order")
	if order == "" {
		return
	}

	parts := strings.Split(order, ",")
	filtered := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if !removed[trimmed] {
			filtered = append(filtered, trimmed)
		}
	}

	includeReferer := !removed["Referer"]
	final := make([]string, 0, len(filtered)+3)
	originAdded := false
	for _, h := range filtered {
		final = append(final, h)
		if h == "Accept" {
			// Content-Type AFTER Accept — real browsers place Accept in the
			// standard header block before Content-Type from the fetch body options.
			final = append(final, "Content-Type")
		}
		if h == "Accept-Language" && !originAdded {
			final = append(final, "Origin")
			if includeReferer {
				final = append(final, "Referer")
			}
			originAdded = true
		}
	}
	if !originAdded {
		final = append(final, "Origin")
		if includeReferer {
			final = append(final, "Referer")
		}
	}
	req.Header.Set("X-Stealth-Header-Order", strings.Join(final, ","))
}
