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

	"github.com/skunkworq/stealth/brws/constants"
)

// nopCloser wraps a byte slice as an io.ReadCloser for request bodies.
func nopCloser(data []byte) io.ReadCloser {
	return io.NopCloser(bytes.NewReader(data))
}

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

// DefaultStrategies returns evasion strategies ordered by priority (highest first).
func DefaultStrategies() []EvasionStrategy {
	return []EvasionStrategy{
		&SendBeaconStrategy{},                // Models navigator.sendBeacon() no-cors POST — bypasses ALL provenance gates (EVASION)
		&RealBrowserStrategy{},               // Models real Chrome telemetry POST from lab captures — 0 X-* headers (EVASION)
		&NoneContextCorsStrategy{},           // cors + site=none = total gate bypass, 6 headers (CAUGHT)
		&SameOriginSubThresholdStrategy{},    // same-origin + same-site, 6 headers (CAUGHT)
		&SameOriginSameSiteStrategy{},        // same-origin mode + same-site = gate gap, 7 headers (CAUGHT)
		&SameOriginSameSiteMinimalStrategy{}, // same-origin mode + same-site, 3 headers (CAUGHT)
		&SameSiteCorsStrategy{},              // cors + same-site + no-referer, 7 headers (CAUGHT)
		&CrossSiteNavigateStrategy{},         // dest=document, navigate, cross-site, 7 headers (CAUGHT)
		&CrossSiteCorsStrategy{},             // cors + cross-site + no-referer, 7 headers (CAUGHT)
		&SameSiteMinimalStrategy{},           // cors + same-site + no-referer, 4 headers (CAUGHT)
		&NavigateMinimalStrategy{},           // dest=document, navigate, cross-site, 4 headers (CAUGHT)
		&BodyMigrationStrategy{},             // all data in body (CAUGHT)
		&SelectiveStripStrategy{},            // minimal headers (CAUGHT)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy B: SendBeaconStrategy (fidelity = 0.00)
// ─────────────────────────────────────────────────────────────────────────────
// Models a real Firefox initial page load — the one request shape the shield
// explicitly allows (proven by the real_firefox_should_pass test at score < 0.20).
//
// The key insight: dest=document + mode=navigate bypasses ALL provenance gates
// because they ALL require dest=empty. Combined with site=none (initial
// navigation, like typing a URL in the address bar), the document navigation
// sub-check at line 2307 also skips (it only fires for site=same-origin).
//
// Gate analysis with Sec-Fetch-Dest: document + Mode: navigate + Site: none:
//   - isSameSiteTelemetryFetch: requires dest=empty → NO MATCH
//   - isCrossSiteTelemetryFetch: requires dest=empty → NO MATCH
//   - isNoCORSTelemetryFetch: requires dest=empty → NO MATCH
//   - isNoneContextTelemetryFetch: requires dest=empty → NO MATCH
//   - isSameOriginTelemetryFetch: requires dest=empty → NO MATCH
//   - isDocumentNavigation: MATCHES, but sub-checks:
//     a) runtimeHeaderCount >= 4 → NO (0 headers)
//     b) GET + runtimeHeaderCount==0 + site=="same-origin" → NO (site=none)
//   - Catch-all: requires dest="empty" || dest="" → NO (dest=document)
//
// Coverage: analyzeFingerprintCoverage:
//   - secChUa="" (Firefox) && presentCount(0) < 8 → returns nil immediately
//
// Missing data: hasJSFingerprintHeaders = false (0 of 6) → no penalties
//
// Result: zero provenance vectors, zero coverage, zero missing data.
// Final score ≈ 0.00 — identical to a real Firefox navigation.
type SendBeaconStrategy struct{}

func (s *SendBeaconStrategy) Name() string      { return "send_beacon" }
func (s *SendBeaconStrategy) Fidelity() float64 { return 0.00 }

func (s *SendBeaconStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	// ── Phase 1: Strip ALL runtime headers ──
	// Zero runtime headers → hasJSFingerprintHeaders=false → no missing_data penalties.
	// Zero headers also means no per-header quality analysis vectors fire at all.
	for _, h := range allRuntimeHeaders {
		req.Header.Del(h)
	}

	// ── Phase 2: Firefox identity ──
	// Firefox doesn't send Sec-Ch-Ua → analyzeFingerprintCoverage returns nil
	// (secChUa=="" && presentCount=0 < 8). This is the critical gate bypass.
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")
	for _, h := range []string{
		"Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform",
		"Sec-Ch-Ua-Full-Version-List", "Sec-Ch-Ua-Arch", "Sec-Ch-Ua-Bitness", "Sec-Ch-Ua-Model",
	} {
		req.Header.Del(h)
	}

	// ── Phase 3: Document navigation (initial page load) ──
	// GET with dest=document bypasses ALL dest=empty provenance gates.
	// site=none models an initial navigation (typing URL, bookmark click).
	req.Method = http.MethodGet
	req.Body = nil
	req.ContentLength = 0
	req.Header.Del("Content-Type")
	req.Header.Del("Origin")

	// ── Phase 4: Real Firefox navigation headers ──
	// Accept with image/avif + image/webp avoids firefox_accept_missing_image_codecs check.
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Del("Priority")

	// ── Phase 5: Sec-Fetch for initial navigation ──
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")

	// ── Phase 6: Clean header order matching real Firefox ──
	// Firefox canonical order: User-Agent, Accept, Accept-Language,
	// Accept-Encoding, Connection, Upgrade-Insecure-Requests,
	// Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, Sec-Fetch-User
	removed := map[string]bool{
		"Content-Type": true,
		"Origin":       true,
		"Referer":      true,
		"Priority":     true,
	}
	for _, h := range []string{
		"Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform",
		"Sec-Ch-Ua-Full-Version-List", "Sec-Ch-Ua-Arch", "Sec-Ch-Ua-Bitness", "Sec-Ch-Ua-Model",
	} {
		removed[h] = true
	}
	for _, h := range allRuntimeHeaders {
		removed[h] = true
	}
	rebuildHeaderOrderClean(req, removed)
}

// ─────────────────────────────────────────────────────────────────────────────
// applyDocumentNavigation — shared helper for document navigation evasion
// ─────────────────────────────────────────────────────────────────────────────
// All strategies exploit the same structural gap:
//   - dest=document + mode=navigate bypasses ALL provenance gates (they require dest=empty)
//   - site != same-origin bypasses document navigation sub-check (line 2307)
//   - Max 3 non-jsFP runtime headers avoids dense-header check (≥4 → +0.78)
//   - Only Canvas/Timing/Behavioral/Audio kept (NOT in hasJSFingerprintHeaders set)
//     so no missing_data penalties fire
//   - Firefox UA + no Sec-Ch-Ua → analyzeFingerprintCoverage returns nil for <8 headers
func applyDocumentNavigation(req *http.Request, _ *RequestGenerator, targetURL, site string, headersToKeep map[string]bool) {
	// Strip ALL runtime headers except those in headersToKeep
	for _, h := range allRuntimeHeaders {
		if !headersToKeep[h] {
			req.Header.Del(h)
		}
	}

	// Firefox identity — no Sec-Ch-Ua headers
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")
	for _, h := range []string{
		"Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform",
		"Sec-Ch-Ua-Full-Version-List", "Sec-Ch-Ua-Arch", "Sec-Ch-Ua-Bitness", "Sec-Ch-Ua-Model",
	} {
		req.Header.Del(h)
	}

	// Document navigation GET — no body
	req.Method = http.MethodGet
	req.Body = nil
	req.ContentLength = 0
	req.Header.Del("Content-Type")
	req.Header.Del("Priority")

	// Real Firefox navigation headers
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	// Sec-Fetch for document navigation
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", site)
	req.Header.Set("Sec-Fetch-User", "?1")

	// Referer based on site value
	req.Header.Del("Origin") // GET navigations don't send Origin
	switch site {
	case "none":
		req.Header.Del("Referer") // initial navigation — no referer
	case "cross-site":
		req.Header.Set("Referer", "https://www.google.com/")
	case "same-site":
		if parsed, err := url.Parse(targetURL); err == nil {
			req.Header.Set("Referer", parsed.Scheme+"://www."+parsed.Hostname()+"/")
		} else {
			req.Header.Set("Referer", "https://www.example.com/")
		}
	}

	// Clean header order
	removed := map[string]bool{
		"Content-Type": true,
		"Origin":       true,
		"Priority":     true,
	}
	for _, h := range []string{
		"Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform",
		"Sec-Ch-Ua-Full-Version-List", "Sec-Ch-Ua-Arch", "Sec-Ch-Ua-Bitness", "Sec-Ch-Ua-Model",
	} {
		removed[h] = true
	}
	for _, h := range allRuntimeHeaders {
		if !headersToKeep[h] {
			removed[h] = true
		}
	}
	if site == "none" {
		removed["Referer"] = true
	}
	rebuildHeaderOrderClean(req, removed)
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy F: FullBrowserStrategy (fidelity = 0.30)
// ─────────────────────────────────────────────────────────────────────────────
// Document navigation with 3 non-jsFP headers: Canvas + Timing + Behavioral.
// site=none (initial navigation). Max headers kept without triggering dense check.
type FullBrowserStrategy struct{}

func (s *FullBrowserStrategy) Name() string      { return "full_browser" }
func (s *FullBrowserStrategy) Fidelity() float64 { return 0.30 }

func (s *FullBrowserStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	applyDocumentNavigation(req, rg, targetURL, "none", map[string]bool{
		constants.HeaderCanvasFingerprint: true,
		constants.HeaderTimingData:        true,
		constants.HeaderBehavioralData:    true,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy R: RealBrowserStrategy (fidelity = 0.00)
// ─────────────────────────────────────────────────────────────────────────────
// Models a Firefox cross-site link click — navigating from search results to
// the target page. Uses dest=document + mode=navigate (bypasses all dest=empty
// gates) with site=cross-site (bypasses the same-origin document navigation
// sub-check at line 2307 which only fires for site=same-origin).
//
// This is a distinct evasion path from SendBeaconStrategy (which uses site=none).
// Both exploit the same structural gap: document navigation + non-same-origin
// site value = no detection sub-checks fire.
type RealBrowserStrategy struct{}

func (s *RealBrowserStrategy) Name() string      { return "real_browser" }
func (s *RealBrowserStrategy) Fidelity() float64 { return 0.00 }

func (s *RealBrowserStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	// ── Phase 1: Strip ALL runtime headers ──
	for _, h := range allRuntimeHeaders {
		req.Header.Del(h)
	}

	// ── Phase 2: Firefox identity ──
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")
	for _, h := range []string{
		"Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform",
		"Sec-Ch-Ua-Full-Version-List", "Sec-Ch-Ua-Arch", "Sec-Ch-Ua-Bitness", "Sec-Ch-Ua-Model",
	} {
		req.Header.Del(h)
	}

	// ── Phase 3: Cross-site document navigation (link click from search results) ──
	req.Method = http.MethodGet
	req.Body = nil
	req.ContentLength = 0
	req.Header.Del("Content-Type")

	// ── Phase 4: Real Firefox navigation headers ──
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Del("Priority")

	// Origin from referrer site (e.g. Google search results → target page).
	req.Header.Del("Origin") // GET navigations don't send Origin
	req.Header.Set("Referer", "https://www.google.com/")

	// ── Phase 5: Sec-Fetch for cross-site navigation ──
	// site=cross-site (not same-origin) → document navigation sub-check skips.
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Sec-Fetch-User", "?1")

	// ── Phase 6: Clean header order ──
	removed := map[string]bool{
		"Content-Type": true,
		"Origin":       true,
		"Priority":     true,
	}
	for _, h := range []string{
		"Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform",
		"Sec-Ch-Ua-Full-Version-List", "Sec-Ch-Ua-Arch", "Sec-Ch-Ua-Bitness", "Sec-Ch-Ua-Model",
	} {
		removed[h] = true
	}
	for _, h := range allRuntimeHeaders {
		removed[h] = true
	}
	rebuildHeaderOrderClean(req, removed)
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy N: NoneContextCorsStrategy (fidelity = 0.20)
// ─────────────────────────────────────────────────────────────────────────────
// Document navigation with 2 non-jsFP headers: Canvas + Behavioral.
// site=cross-site (link click from external search results).
type NoneContextCorsStrategy struct{}

func (s *NoneContextCorsStrategy) Name() string      { return "none_context_cors" }
func (s *NoneContextCorsStrategy) Fidelity() float64 { return 0.20 }

func (s *NoneContextCorsStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	applyDocumentNavigation(req, rg, targetURL, "cross-site", map[string]bool{
		constants.HeaderCanvasFingerprint: true,
		constants.HeaderBehavioralData:    true,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy S: SameOriginSubThresholdStrategy (fidelity = 0.20)
// ─────────────────────────────────────────────────────────────────────────────
// Document navigation with 2 non-jsFP headers: Timing + Behavioral.
// site=same-site (same-site link click).
type SameOriginSubThresholdStrategy struct{}

func (s *SameOriginSubThresholdStrategy) Name() string      { return "cross_site_same_origin" }
func (s *SameOriginSubThresholdStrategy) Fidelity() float64 { return 0.20 }

func (s *SameOriginSubThresholdStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	applyDocumentNavigation(req, rg, targetURL, "same-site", map[string]bool{
		constants.HeaderTimingData:     true,
		constants.HeaderBehavioralData: true,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy 0a: SameOriginSameSiteStrategy (fidelity = 0.30)
// ─────────────────────────────────────────────────────────────────────────────
// Document navigation with 3 non-jsFP headers: Canvas + Timing + Audio.
// site=cross-site (link click from external).
type SameOriginSameSiteStrategy struct{}

func (s *SameOriginSameSiteStrategy) Name() string      { return "same_site_telemetry" }
func (s *SameOriginSameSiteStrategy) Fidelity() float64 { return 0.30 }

func (s *SameOriginSameSiteStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	applyDocumentNavigation(req, rg, targetURL, "cross-site", map[string]bool{
		constants.HeaderCanvasFingerprint: true,
		constants.HeaderTimingData:        true,
		constants.HeaderAudioData:         true,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy 0b: SameOriginSameSiteMinimalStrategy (fidelity = 0.10)
// ─────────────────────────────────────────────────────────────────────────────
// Document navigation with 1 non-jsFP header: Canvas.
// site=none (initial navigation).
type SameOriginSameSiteMinimalStrategy struct{}

func (s *SameOriginSameSiteMinimalStrategy) Name() string      { return "reduced_beacon" }
func (s *SameOriginSameSiteMinimalStrategy) Fidelity() float64 { return 0.10 }

func (s *SameOriginSameSiteMinimalStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	applyDocumentNavigation(req, rg, targetURL, "none", map[string]bool{
		constants.HeaderCanvasFingerprint: true,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy 1: SameSiteCorsStrategy (fidelity = 0.10)
// ─────────────────────────────────────────────────────────────────────────────
// Document navigation with 1 non-jsFP header: Behavioral.
// site=cross-site.
type SameSiteCorsStrategy struct{}

func (s *SameSiteCorsStrategy) Name() string      { return "same_site_cors_telemetry" }
func (s *SameSiteCorsStrategy) Fidelity() float64 { return 0.10 }

func (s *SameSiteCorsStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	applyDocumentNavigation(req, rg, targetURL, "cross-site", map[string]bool{
		constants.HeaderBehavioralData: true,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy 2: CrossSiteNavigateStrategy (fidelity = 0.10)
// ─────────────────────────────────────────────────────────────────────────────
// Document navigation with 1 non-jsFP header: Timing.
// site=same-site.
type CrossSiteNavigateStrategy struct{}

func (s *CrossSiteNavigateStrategy) Name() string      { return "navigate_form" }
func (s *CrossSiteNavigateStrategy) Fidelity() float64 { return 0.10 }

func (s *CrossSiteNavigateStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	applyDocumentNavigation(req, rg, targetURL, "same-site", map[string]bool{
		constants.HeaderTimingData: true,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy 3: CrossSiteCorsStrategy (fidelity = 0.20)
// ─────────────────────────────────────────────────────────────────────────────
// Document navigation with 2 non-jsFP headers: Canvas + Timing.
// site=none.
type CrossSiteCorsStrategy struct{}

func (s *CrossSiteCorsStrategy) Name() string      { return "cross_site_cors" }
func (s *CrossSiteCorsStrategy) Fidelity() float64 { return 0.20 }

func (s *CrossSiteCorsStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	applyDocumentNavigation(req, rg, targetURL, "none", map[string]bool{
		constants.HeaderCanvasFingerprint: true,
		constants.HeaderTimingData:        true,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy 4: SameSiteMinimalStrategy (fidelity = 0.10)
// ─────────────────────────────────────────────────────────────────────────────
// Document navigation with 1 non-jsFP header: Audio.
// site=cross-site.
type SameSiteMinimalStrategy struct{}

func (s *SameSiteMinimalStrategy) Name() string      { return "cors_reduced_beacon" }
func (s *SameSiteMinimalStrategy) Fidelity() float64 { return 0.10 }

func (s *SameSiteMinimalStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	applyDocumentNavigation(req, rg, targetURL, "cross-site", map[string]bool{
		constants.HeaderAudioData: true,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy 5: NavigateMinimalStrategy (fidelity = 0.20)
// ─────────────────────────────────────────────────────────────────────────────
// Document navigation with 2 non-jsFP headers: Audio + Canvas.
// site=same-site.
type NavigateMinimalStrategy struct{}

func (s *NavigateMinimalStrategy) Name() string      { return "navigate_minimal" }
func (s *NavigateMinimalStrategy) Fidelity() float64 { return 0.20 }

func (s *NavigateMinimalStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	applyDocumentNavigation(req, rg, targetURL, "same-site", map[string]bool{
		constants.HeaderAudioData:         true,
		constants.HeaderCanvasFingerprint: true,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy 6: BodyMigrationStrategy (fidelity = 0.30)
// ─────────────────────────────────────────────────────────────────────────────
// Document navigation with 3 non-jsFP headers: Behavioral + Audio + Canvas.
// site=cross-site.
type BodyMigrationStrategy struct{}

func (s *BodyMigrationStrategy) Name() string      { return "body_migration" }
func (s *BodyMigrationStrategy) Fidelity() float64 { return 0.30 }

func (s *BodyMigrationStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	applyDocumentNavigation(req, rg, targetURL, "cross-site", map[string]bool{
		constants.HeaderBehavioralData:    true,
		constants.HeaderAudioData:         true,
		constants.HeaderCanvasFingerprint: true,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy 7: SelectiveStripStrategy (fidelity = 0.00)
// ─────────────────────────────────────────────────────────────────────────────
// Document navigation with 0 runtime headers (pure page load).
// site=same-site.
type SelectiveStripStrategy struct{}

func (s *SelectiveStripStrategy) Name() string      { return "selective_strip" }
func (s *SelectiveStripStrategy) Fidelity() float64 { return 0.00 }

func (s *SelectiveStripStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	applyDocumentNavigation(req, rg, targetURL, "same-site", map[string]bool{})
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy D1: PostLoadSameOriginFetchStrategy (fidelity = 0.40)
// ─────────────────────────────────────────────────────────────────────────────
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

// ─────────────────────────────────────────────────────────────────────────────
// Strategy D2: PostLoadCrossSiteFetchStrategy (fidelity = 0.40)
// ─────────────────────────────────────────────────────────────────────────────
// Same approach as D1 but with site=cross-site, modeling a cross-origin
// analytics SDK call. Origin header included for cross-site cors.
type PostLoadCrossSiteFetchStrategy struct{}

func (s *PostLoadCrossSiteFetchStrategy) Name() string      { return "postload_cross_site_fetch" }
func (s *PostLoadCrossSiteFetchStrategy) Fidelity() float64 { return 0.40 }

func (s *PostLoadCrossSiteFetchStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	applyPostLoadFetch(req, targetURL, "cors", "cross-site", true)
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy D3: PostLoadNoCORSBeaconStrategy (fidelity = 0.40)
// ─────────────────────────────────────────────────────────────────────────────
// Same approach as D1 but with mode=no-cors + site=same-site.
type PostLoadNoCORSBeaconStrategy struct{}

func (s *PostLoadNoCORSBeaconStrategy) Name() string      { return "postload_nocors_beacon" }
func (s *PostLoadNoCORSBeaconStrategy) Fidelity() float64 { return 0.40 }

func (s *PostLoadNoCORSBeaconStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	applyPostLoadFetch(req, targetURL, "no-cors", "same-site", false)
}

// applyPostLoadFetch is the shared helper for D-series strategies.
// Uses exactly 4 post-load runtime headers (Timing, Behavioral, Audio, Canvas)
// with zero jsFP headers → runtimeHeaderCount=4 < 5, hasJSFP=false.
func applyPostLoadFetch(req *http.Request, targetURL, mode, site string, includeOrigin bool) {
	// ── Phase 1: Keep ONLY post-load headers (no jsFP headers) ──
	keepHeaders := map[string]bool{
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

	// ── Phase 2: Firefox identity (no Sec-Ch-Ua → coverage nil for <8 headers) ──
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")
	for _, h := range []string{
		"Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform",
		"Sec-Ch-Ua-Full-Version-List", "Sec-Ch-Ua-Arch", "Sec-Ch-Ua-Bitness", "Sec-Ch-Ua-Model",
	} {
		req.Header.Del(h)
	}

	// ── Phase 3: Fetch shape ──
	req.Method = http.MethodGet
	req.Body = nil
	req.ContentLength = 0
	req.Header.Del("Content-Type")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")

	// Referer
	if parsed, err := url.Parse(targetURL); err == nil {
		if site == "cross-site" {
			req.Header.Set("Referer", "https://app.example.com/dashboard")
		} else if site == "same-site" {
			req.Header.Set("Referer", parsed.Scheme+"://www."+parsed.Hostname()+"/")
		} else {
			req.Header.Set("Referer", parsed.Scheme+"://"+parsed.Host+"/")
		}
	}

	if includeOrigin {
		req.Header.Set("Origin", "https://app.example.com")
	} else {
		req.Header.Del("Origin")
	}

	// ── Phase 4: Sec-Fetch ──
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", mode)
	req.Header.Set("Sec-Fetch-Site", site)
	req.Header.Del("Sec-Fetch-User")
	req.Header.Del("Upgrade-Insecure-Requests")

	// ── Phase 5: Clean header order ──
	removed := map[string]bool{
		"Content-Type":              true,
		"Upgrade-Insecure-Requests": true,
		"Sec-Fetch-User":            true,
		"Priority":                  true,
	}
	if !includeOrigin {
		removed["Origin"] = true
	}
	for _, h := range []string{
		"Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform",
		"Sec-Ch-Ua-Full-Version-List", "Sec-Ch-Ua-Arch", "Sec-Ch-Ua-Bitness", "Sec-Ch-Ua-Model",
	} {
		removed[h] = true
	}
	for _, h := range allRuntimeHeaders {
		if !keepHeaders[h] {
			removed[h] = true
		}
	}
	rebuildHeaderOrderClean(req, removed)
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy E1: SingleHeaderSameOriginStrategy (fidelity = 0.10)
// ─────────────────────────────────────────────────────────────────────────────
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

// ─────────────────────────────────────────────────────────────────────────────
// Strategy E2: SingleHeaderCrossSiteStrategy (fidelity = 0.10)
// ─────────────────────────────────────────────────────────────────────────────
// Uses exactly 1 post-load header (Timing) on a cross-site GET fetch.
type SingleHeaderCrossSiteStrategy struct{}

func (s *SingleHeaderCrossSiteStrategy) Name() string      { return "single_header_cross_site" }
func (s *SingleHeaderCrossSiteStrategy) Fidelity() float64 { return 0.10 }

func (s *SingleHeaderCrossSiteStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
	applySingleHeaderFetch(req, targetURL, constants.HeaderTimingData, "cors", "cross-site", true)
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy E3: SingleHeaderNoCORSStrategy (fidelity = 0.10)
// ─────────────────────────────────────────────────────────────────────────────
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
	keepHeaders := map[string]bool{keepHeader: true}
	for _, h := range allRuntimeHeaders {
		if !keepHeaders[h] {
			req.Header.Del(h)
		}
	}
	fixBehavioralDataForFirefox(req)

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")
	for _, h := range []string{
		"Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform",
		"Sec-Ch-Ua-Full-Version-List", "Sec-Ch-Ua-Arch", "Sec-Ch-Ua-Bitness", "Sec-Ch-Ua-Model",
	} {
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

	if parsed, err := url.Parse(targetURL); err == nil {
		if site == "cross-site" {
			req.Header.Set("Referer", "https://app.example.com/dashboard")
		} else if site == "same-site" {
			req.Header.Set("Referer", parsed.Scheme+"://www."+parsed.Hostname()+"/")
		} else {
			req.Header.Set("Referer", parsed.Scheme+"://"+parsed.Host+"/")
		}
	}

	if includeOrigin {
		req.Header.Set("Origin", "https://app.example.com")
	} else {
		req.Header.Del("Origin")
	}

	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", mode)
	req.Header.Set("Sec-Fetch-Site", site)
	req.Header.Del("Sec-Fetch-User")
	req.Header.Del("Upgrade-Insecure-Requests")

	removed := map[string]bool{
		"Content-Type":              true,
		"Upgrade-Insecure-Requests": true,
		"Sec-Fetch-User":            true,
		"Priority":                  true,
	}
	if !includeOrigin {
		removed["Origin"] = true
	}
	for _, h := range []string{
		"Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform",
		"Sec-Ch-Ua-Full-Version-List", "Sec-Ch-Ua-Arch", "Sec-Ch-Ua-Bitness", "Sec-Ch-Ua-Model",
	} {
		removed[h] = true
	}
	for _, h := range allRuntimeHeaders {
		if !keepHeaders[h] {
			removed[h] = true
		}
	}
	rebuildHeaderOrderClean(req, removed)
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
	// ── Phase 1: Keep ONLY selected runtime headers ──
	for _, h := range allRuntimeHeaders {
		if !keepHeaders[h] {
			req.Header.Del(h)
		}
	}
	fixBehavioralDataForFirefox(req)

	// ── Phase 2: Firefox identity (no Sec-Ch-Ua) ──
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")
	for _, h := range []string{
		"Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform",
		"Sec-Ch-Ua-Full-Version-List", "Sec-Ch-Ua-Arch", "Sec-Ch-Ua-Bitness", "Sec-Ch-Ua-Model",
	} {
		req.Header.Del(h)
	}

	// ── Phase 3: POST shape with body ──
	body := craftEvasionBody()
	req.Method = http.MethodPost
	req.Body = nopCloser([]byte(body))
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")

	// ── Phase 4: Origin + Referer ──
	if parsed, err := url.Parse(targetURL); err == nil {
		if site == "cross-site" {
			req.Header.Set("Referer", "https://app.example.com/dashboard")
		} else if site == "same-site" {
			req.Header.Set("Referer", parsed.Scheme+"://www."+parsed.Hostname()+"/")
		} else if site == "same-origin" {
			req.Header.Set("Referer", parsed.Scheme+"://"+parsed.Host+"/")
		}
		// No Referer for site=none (bookmarklet/extension context)
	}

	if includeOrigin {
		if site == "cross-site" {
			req.Header.Set("Origin", "https://app.example.com")
		} else if parsed, err := url.Parse(targetURL); err == nil {
			req.Header.Set("Origin", parsed.Scheme+"://"+parsed.Host)
		}
	} else {
		req.Header.Del("Origin")
	}

	// ── Phase 5: Sec-Fetch ──
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", mode)
	req.Header.Set("Sec-Fetch-Site", site)
	req.Header.Del("Sec-Fetch-User")
	req.Header.Del("Upgrade-Insecure-Requests")

	// ── Phase 6: Clean header order ──
	removed := map[string]bool{
		"Upgrade-Insecure-Requests": true,
		"Sec-Fetch-User":            true,
		"Priority":                  true,
	}
	if !includeOrigin {
		removed["Origin"] = true
	}
	for _, h := range []string{
		"Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform",
		"Sec-Ch-Ua-Full-Version-List", "Sec-Ch-Ua-Arch", "Sec-Ch-Ua-Bitness", "Sec-Ch-Ua-Model",
	} {
		removed[h] = true
	}
	for _, h := range allRuntimeHeaders {
		if !keepHeaders[h] {
			removed[h] = true
		}
	}
	rebuildHeaderOrderClean(req, removed)
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy F1: PostNoCORSTwoHeaderStrategy (fidelity = 0.15)
// ─────────────────────────────────────────────────────────────────────────────
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

// ─────────────────────────────────────────────────────────────────────────────
// Strategy F2: PostCrossSiteThreeHeaderStrategy (fidelity = 0.20)
// ─────────────────────────────────────────────────────────────────────────────
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

// ─────────────────────────────────────────────────────────────────────────────
// Strategy F3: PostSameSiteThreeHeaderStrategy (fidelity = 0.20)
// ─────────────────────────────────────────────────────────────────────────────
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

// ─────────────────────────────────────────────────────────────────────────────
// Strategy F4: PostNoneContextTwoHeaderStrategy (fidelity = 0.15)
// ─────────────────────────────────────────────────────────────────────────────
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

// ─────────────────────────────────────────────────────────────────────────────
// Strategy G1: PostSameOriginSmallStrategy (fidelity = 0.20)
// ─────────────────────────────────────────────────────────────────────────────
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
// Strategy C1: ChromeSameOriginFetchStrategy (fidelity = 0.50) [LEGACY - now caught]
// ─────────────────────────────────────────────────────────────────────────────
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
	for _, h := range []string{
		"Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform",
		"Sec-Ch-Ua-Full-Version-List", "Sec-Ch-Ua-Arch", "Sec-Ch-Ua-Bitness", "Sec-Ch-Ua-Model",
	} {
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
	for _, h := range []string{
		"Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform",
		"Sec-Ch-Ua-Full-Version-List", "Sec-Ch-Ua-Arch", "Sec-Ch-Ua-Bitness", "Sec-Ch-Ua-Model",
	} {
		removed[h] = true
	}
	for _, h := range allRuntimeHeaders {
		if !keepHeaders[h] {
			removed[h] = true
		}
	}
	rebuildHeaderOrderClean(req, removed)
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy C2: ChromeCrossSiteFetchStrategy (fidelity = 0.50)
// ─────────────────────────────────────────────────────────────────────────────
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
	for _, h := range []string{
		"Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform",
		"Sec-Ch-Ua-Full-Version-List", "Sec-Ch-Ua-Arch", "Sec-Ch-Ua-Bitness", "Sec-Ch-Ua-Model",
	} {
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
	for _, h := range []string{
		"Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform",
		"Sec-Ch-Ua-Full-Version-List", "Sec-Ch-Ua-Arch", "Sec-Ch-Ua-Bitness", "Sec-Ch-Ua-Model",
	} {
		removed[h] = true
	}
	for _, h := range allRuntimeHeaders {
		if !keepHeaders[h] {
			removed[h] = true
		}
	}
	rebuildHeaderOrderClean(req, removed)
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy C3: ChromeNoCORSBeaconStrategy (fidelity = 0.50)
// ─────────────────────────────────────────────────────────────────────────────
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
	for _, h := range []string{
		"Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform",
		"Sec-Ch-Ua-Full-Version-List", "Sec-Ch-Ua-Arch", "Sec-Ch-Ua-Bitness", "Sec-Ch-Ua-Model",
	} {
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
	for _, h := range []string{
		"Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform",
		"Sec-Ch-Ua-Full-Version-List", "Sec-Ch-Ua-Arch", "Sec-Ch-Ua-Bitness", "Sec-Ch-Ua-Model",
	} {
		removed[h] = true
	}
	for _, h := range allRuntimeHeaders {
		if !keepHeaders[h] {
			removed[h] = true
		}
	}
	rebuildHeaderOrderClean(req, removed)
}

// ─────────────────────────────────────────────────────────────────────────────
// URL Classification — determines whether a target URL looks like a telemetry
// endpoint (triggers shield telemetry target detection) or a normal page URL.
// ─────────────────────────────────────────────────────────────────────────────

// URLType classifies a request URL for strategy selection.
type URLType int

const (
	URLTypePage      URLType = iota // Normal web page — document navigation is safe
	URLTypeTelemetry                // Telemetry/API endpoint — exotic dest strategies required
)

// classifyURL mirrors the shield's looksLikeTelemetryEndpointPath and
// looksLikeAPIHostname to predict which URLs will trigger telemetry detection.
func classifyURL(targetURL string) URLType {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return URLTypePage
	}

	// Mirror shield's looksLikeAPIHostname prefixes
	hostLower := strings.ToLower(parsed.Hostname())
	apiPrefixes := []string{"api.", "metrics.", "telemetry.", "events.", "collect.", "track.", "beacon."}
	for _, p := range apiPrefixes {
		if strings.HasPrefix(hostLower, p) {
			return URLTypeTelemetry
		}
	}

	// Mirror shield's looksLikeTelemetryEndpointPath patterns
	pathLower := strings.ToLower(parsed.Path)
	telemetryPatterns := []string{"/api/telemetry", "/api/ml/", "/collect", "/beacon", "/metrics", "/track", "/events", "/trap"}
	for _, pattern := range telemetryPatterns {
		if strings.Contains(pathLower, pattern) {
			return URLTypeTelemetry
		}
	}

	return URLTypePage
}

// ─────────────────────────────────────────────────────────────────────────────
// Exotic dest strategies — bypass ALL shield provenance gates.
//
// The shield's named gates only cover:
//   - dest=empty (all 5 named telemetry gates)
//   - dest=document (isDocumentNavigation)
// The catch-all only fires for dest=empty or dest="".
//
// Any other dest value (iframe, script, image, style, worker) passes through
// ALL detection layers with zero provenance score. Combined with Firefox UA
// (no Sec-Ch-Ua → analyzeFingerprintCoverage returns nil) and zero runtime
// headers (no missing data penalties), these score ≈ 0.00.
// ─────────────────────────────────────────────────────────────────────────────

// applyExoticDest is the shared helper for non-document, non-empty dest strategies.
func applyExoticDest(req *http.Request, targetURL, dest, mode, site, accept string, includeReferer bool) {
	// Strip ALL runtime headers — zero fingerprint surface
	for _, h := range allRuntimeHeaders {
		req.Header.Del(h)
	}

	// Firefox identity — no Sec-Ch-Ua → analyzeFingerprintCoverage returns nil
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")
	for _, h := range []string{
		"Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform",
		"Sec-Ch-Ua-Full-Version-List", "Sec-Ch-Ua-Arch", "Sec-Ch-Ua-Bitness", "Sec-Ch-Ua-Model",
	} {
		req.Header.Del(h)
	}

	// GET — no body
	req.Method = http.MethodGet
	req.Body = nil
	req.ContentLength = 0
	req.Header.Del("Content-Type")
	req.Header.Del("Origin")
	req.Header.Del("Priority")

	// Standard Firefox sub-resource headers
	req.Header.Set("Accept", accept)
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")

	// No UIR or SFU for sub-resource fetches (only document navigations)
	req.Header.Del("Upgrade-Insecure-Requests")
	req.Header.Del("Sec-Fetch-User")

	// Sec-Fetch headers
	req.Header.Set("Sec-Fetch-Dest", dest)
	req.Header.Set("Sec-Fetch-Mode", mode)
	req.Header.Set("Sec-Fetch-Site", site)

	// Referer — sub-resource requests typically include the embedding page
	if includeReferer {
		if parsed, err := url.Parse(targetURL); err == nil {
			req.Header.Set("Referer", parsed.Scheme+"://"+parsed.Hostname()+"/")
		}
	} else {
		req.Header.Del("Referer")
	}

	// Clean header order
	removed := map[string]bool{
		"Content-Type":              true,
		"Origin":                    true,
		"Priority":                  true,
		"Upgrade-Insecure-Requests": true,
		"Sec-Fetch-User":            true,
	}
	for _, h := range []string{
		"Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform",
		"Sec-Ch-Ua-Full-Version-List", "Sec-Ch-Ua-Arch", "Sec-Ch-Ua-Bitness", "Sec-Ch-Ua-Model",
	} {
		removed[h] = true
	}
	for _, h := range allRuntimeHeaders {
		removed[h] = true
	}
	if !includeReferer {
		removed["Referer"] = true
	}
	rebuildHeaderOrderClean(req, removed)
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy I1: IframeNavigationStrategy (fidelity = 0.00)
// ─────────────────────────────────────────────────────────────────────────────
// Models <iframe src="target"> — a page embedding the target URL in an iframe.
// dest=iframe bypasses isDocumentNavigation (requires dest=document) and all
// dest=empty gates. The catch-all also skips (requires dest=empty or "").
type IframeNavigationStrategy struct{}

func (s *IframeNavigationStrategy) Name() string      { return "iframe_navigation" }
func (s *IframeNavigationStrategy) Fidelity() float64 { return 0.00 }

func (s *IframeNavigationStrategy) Apply(req *http.Request, _ *RequestGenerator, targetURL string) {
	// Iframe navigations use mode=navigate but dest=iframe (not document)
	applyExoticDest(req, targetURL, "iframe", "navigate", "cross-site",
		"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", true)
	// Iframes do send UIR (nested navigation) but NOT SFU (not user-activated)
	req.Header.Set("Upgrade-Insecure-Requests", "1")
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy I2: ScriptFetchStrategy (fidelity = 0.00)
// ─────────────────────────────────────────────────────────────────────────────
// Models <script src="target"> — loading a JavaScript resource from the target.
// dest=script + mode=no-cors is the standard shape for cross-origin script tags.
type ScriptFetchStrategy struct{}

func (s *ScriptFetchStrategy) Name() string      { return "script_fetch" }
func (s *ScriptFetchStrategy) Fidelity() float64 { return 0.00 }

func (s *ScriptFetchStrategy) Apply(req *http.Request, _ *RequestGenerator, targetURL string) {
	applyExoticDest(req, targetURL, "script", "no-cors", "cross-site", "*/*", true)
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy I3: ImagePixelStrategy (fidelity = 0.00)
// ─────────────────────────────────────────────────────────────────────────────
// Models <img src="target"> — a tracking pixel or image load from the target.
// Extremely common pattern for analytics (Facebook Pixel, Google Analytics, etc.).
type ImagePixelStrategy struct{}

func (s *ImagePixelStrategy) Name() string      { return "image_pixel" }
func (s *ImagePixelStrategy) Fidelity() float64 { return 0.00 }

func (s *ImagePixelStrategy) Apply(req *http.Request, _ *RequestGenerator, targetURL string) {
	applyExoticDest(req, targetURL, "image", "no-cors", "cross-site",
		"image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8", true)
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy I4: StyleFetchStrategy (fidelity = 0.00)
// ─────────────────────────────────────────────────────────────────────────────
// Models <link rel="stylesheet" href="target"> — loading a CSS resource.
type StyleFetchStrategy struct{}

func (s *StyleFetchStrategy) Name() string      { return "style_fetch" }
func (s *StyleFetchStrategy) Fidelity() float64 { return 0.00 }

func (s *StyleFetchStrategy) Apply(req *http.Request, _ *RequestGenerator, targetURL string) {
	applyExoticDest(req, targetURL, "style", "no-cors", "cross-site",
		"text/css,*/*;q=0.1", true)
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy I5: WorkerImportStrategy (fidelity = 0.00)
// ─────────────────────────────────────────────────────────────────────────────
// Models importScripts("target") inside a Service Worker — loading a script
// resource from within a worker context.
type WorkerImportStrategy struct{}

func (s *WorkerImportStrategy) Name() string      { return "worker_import" }
func (s *WorkerImportStrategy) Fidelity() float64 { return 0.00 }

func (s *WorkerImportStrategy) Apply(req *http.Request, _ *RequestGenerator, targetURL string) {
	applyExoticDest(req, targetURL, "worker", "same-origin", "same-origin", "*/*", false)
}

// ─────────────────────────────────────────────────────────────────────────────
// URL-aware strategy selection
// ─────────────────────────────────────────────────────────────────────────────

// StrategiesForURL returns an ordered strategy list adapted to the target URL.
// For telemetry/API endpoints, exotic dest strategies (iframe, script, image)
// are prioritized since they bypass all shield gates. For normal page URLs,
// document navigation strategies come first.
func StrategiesForURL(targetURL string) []EvasionStrategy {
	urlType := classifyURL(targetURL)

	switch urlType {
	case URLTypeTelemetry:
		// F-series: POST-based strategies exploiting POST detection gaps.
		// Prioritized first — these target confirmed gaps in POST gate coverage.
		return []EvasionStrategy{
			// G-series: Same-origin POST with truncated headers (bypasses byte-based gates)
			&PostSameOriginSmallStrategy{},
			// F-series: POST-based strategies (now caught by mid-range/cherry-pick gates)
			&PostNoCORSTwoHeaderStrategy{},
			&PostCrossSiteThreeHeaderStrategy{},
			&PostSameSiteThreeHeaderStrategy{},
			&PostNoneContextTwoHeaderStrategy{},
			// E-series: 1 post-load GET header (now caught by postload cherry-pick)
			&SingleHeaderSameOriginStrategy{},
			&SingleHeaderCrossSiteStrategy{},
			&SingleHeaderNoCORSStrategy{},
			// D-series legacy (now caught by post-load cherry-pick gate)
			&PostLoadSameOriginFetchStrategy{},
			&PostLoadCrossSiteFetchStrategy{},
			&PostLoadNoCORSBeaconStrategy{},
			// C-series legacy (now caught by >=5 runtime header gate)
			&ChromeSameOriginFetchStrategy{},
			&ChromeCrossSiteFetchStrategy{},
			&ChromeNoCORSBeaconStrategy{},
			// Exotic dest strategies
			&IframeNavigationStrategy{},
			&ScriptFetchStrategy{},
			&ImagePixelStrategy{},
			&StyleFetchStrategy{},
			&WorkerImportStrategy{},
			// Fallback to document navigation strategies
			&SendBeaconStrategy{},
			&RealBrowserStrategy{},
			&NoneContextCorsStrategy{},
			&SameOriginSubThresholdStrategy{},
			&SameOriginSameSiteStrategy{},
			&SameOriginSameSiteMinimalStrategy{},
			&SameSiteCorsStrategy{},
			&CrossSiteNavigateStrategy{},
			&CrossSiteCorsStrategy{},
			&SameSiteMinimalStrategy{},
			&NavigateMinimalStrategy{},
			&BodyMigrationStrategy{},
			&SelectiveStripStrategy{},
		}
	default:
		// Normal page URLs — document navigation first, F/E/D/C-series + exotic as fallback
		return []EvasionStrategy{
			&SendBeaconStrategy{},
			&RealBrowserStrategy{},
			&PostSameOriginSmallStrategy{},
			&PostNoCORSTwoHeaderStrategy{},
			&PostCrossSiteThreeHeaderStrategy{},
			&PostSameSiteThreeHeaderStrategy{},
			&PostNoneContextTwoHeaderStrategy{},
			&SingleHeaderSameOriginStrategy{},
			&SingleHeaderCrossSiteStrategy{},
			&SingleHeaderNoCORSStrategy{},
			&PostLoadSameOriginFetchStrategy{},
			&PostLoadCrossSiteFetchStrategy{},
			&PostLoadNoCORSBeaconStrategy{},
			&ChromeSameOriginFetchStrategy{},
			&ChromeCrossSiteFetchStrategy{},
			&ChromeNoCORSBeaconStrategy{},
			&IframeNavigationStrategy{},
			&ScriptFetchStrategy{},
			&ImagePixelStrategy{},
			&NoneContextCorsStrategy{},
			&SameOriginSubThresholdStrategy{},
			&SameOriginSameSiteStrategy{},
			&SameOriginSameSiteMinimalStrategy{},
			&SameSiteCorsStrategy{},
			&CrossSiteNavigateStrategy{},
			&CrossSiteCorsStrategy{},
			&SameSiteMinimalStrategy{},
			&NavigateMinimalStrategy{},
			&BodyMigrationStrategy{},
			&StyleFetchStrategy{},
			&WorkerImportStrategy{},
			&SelectiveStripStrategy{},
		}
	}
}

// NewAdaptiveEvasionFSMForURL creates an FSM with strategy ordering optimized
// for the target URL. Telemetry URLs get exotic dest strategies first.
func NewAdaptiveEvasionFSMForURL(targetURL string) *AdaptiveEvasionFSM {
	return NewAdaptiveEvasionFSM(StrategiesForURL(targetURL)...)
}

// ─────────────────────────────────────────────────────────────────────────────
// DetectionResult / DetectionAnalyzer — interface for self-analysis pre-flight
// ─────────────────────────────────────────────────────────────────────────────

// DetectionResult captures the shield's verdict on a request.
type DetectionResult struct {
	IsBot      bool
	Score      float64
	Indicators []string
}

// DetectionAnalyzer runs a request through local detection and returns a result.
// In tests this is the StealthDetector; in production it can be nil (rely on
// HTTP ban signals instead).
type DetectionAnalyzer func(req *http.Request) DetectionResult

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

func (fsm *AdaptiveEvasionFSM) Strategies() []EvasionStrategy {
	fsm.mu.Lock()
	defer fsm.mu.Unlock()
	return fsm.strategies
}

func (fsm *AdaptiveEvasionFSM) Transitions() []FSMTransition {
	fsm.mu.Lock()
	defer fsm.mu.Unlock()
	return append([]FSMTransition{}, fsm.transitions...)
}

// GenerateAdaptiveRequest tries strategies with pre-flight self-analysis.
// It walks the FSM, generating a request with each strategy and checking it
// against the analyzer. If the analyzer detects the request, it records a
// failure and advances to the next strategy. Returns the first request that
// passes, or the last attempt if all strategies are caught.
//
// When analyzer is nil (production mode), returns the current strategy's
// request without self-analysis — detection is handled by HTTP ban signals
// fed back via RecordResult/RecordBanSignal.
func (fsm *AdaptiveEvasionFSM) GenerateAdaptiveRequest(
	profile *BrowserProfile,
	targetURL string,
	analyzer DetectionAnalyzer,
) *http.Request {
	maxAttempts := len(fsm.strategies)
	var lastReq *http.Request

	for attempt := 0; attempt < maxAttempts; attempt++ {
		strategy := fsm.CurrentStrategy()

		config := MaxEvasionConfig(profile)
		config.EvasionStrategy = strategy

		gen := NewRequestGenerator(config)
		req := gen.GenerateRequest(targetURL)
		lastReq = req

		// No analyzer → return immediately (production: rely on HTTP ban signals)
		if analyzer == nil {
			return req
		}

		// Self-analyze
		result := analyzer(req)
		if !result.IsBot {
			// Strategy evades — record success and return
			fsm.RecordResult(result.Score, false)
			return req
		}

		// Strategy caught — record failure (this advances FSM if detection rate > 50%)
		fsm.RecordResult(result.Score, true)

		// Check if FSM advanced to a new strategy
		nextStrategy := fsm.CurrentStrategy()
		if nextStrategy.Name() == strategy.Name() {
			// FSM didn't advance yet (needs more attempts) — force immediate advance
			// for the self-analysis loop since we know this attempt failed
			fsm.mu.Lock()
			if fsm.stateIdx < len(fsm.strategies)-1 {
				from := fsm.strategies[fsm.stateIdx].Name()
				fsm.stateIdx++
				to := fsm.strategies[fsm.stateIdx].Name()
				fsm.transitions = append(fsm.transitions, FSMTransition{
					From:   from,
					To:     to,
					Score:  result.Score,
					Reason: fmt.Sprintf("self_analysis_detected: score=%.3f indicators=%v", result.Score, result.Indicators),
				})
			} else {
				fsm.exhausted = true
			}
			fsm.mu.Unlock()
		}

		if fsm.Exhausted() {
			break
		}
	}

	return lastReq
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

// fixBehavioralDataForFirefox patches the errorStack in X-Behavioral-Data to
// use SpiderMonkey (Firefox) format instead of V8 (Chrome) format. The isomorphic
// analyzer cross-checks the error stack format against the claimed UA.
func fixBehavioralDataForFirefox(req *http.Request) {
	behavHeader := req.Header.Get(constants.HeaderBehavioralData)
	if behavHeader == "" {
		return
	}
	var behavData map[string]interface{}
	if json.Unmarshal([]byte(behavHeader), &behavData) != nil {
		return
	}
	// Replace V8-style error stack with SpiderMonkey-style
	behavData["errorStack"] = "captureStack@https://cdn.example.com/analytics.js:142:15\nonLoad@https://www.example.com/index.html:30:3\n@https://www.example.com/index.html:1:1"
	fixed, err := json.Marshal(behavData)
	if err != nil {
		return
	}
	req.Header.Set(constants.HeaderBehavioralData, string(fixed))
}

// rebuildHeaderOrderClean strips removed headers from X-Stealth-Header-Order
// WITHOUT injecting any headers that aren't actually present on the request.
// This prevents ghost header detection where the declared order lists headers
// (like Content-Type, Origin) that don't exist on the actual request.
func rebuildHeaderOrderClean(req *http.Request, removed map[string]bool) {
	order := req.Header.Get("X-Stealth-Header-Order")
	if order == "" {
		return
	}

	parts := strings.Split(order, ",")
	filtered := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if removed[trimmed] {
			continue
		}
		// Only keep headers that are actually present on the request
		if req.Header.Get(trimmed) == "" {
			continue
		}
		filtered = append(filtered, trimmed)
	}

	req.Header.Set("X-Stealth-Header-Order", strings.Join(filtered, ","))
}
