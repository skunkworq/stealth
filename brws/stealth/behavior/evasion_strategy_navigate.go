package behavior

import (
	"net/http"
	"net/url"

	"github.com/skunkworq/stealth/brws/core/constants"
)

// ─────────────────────────────────────────────────────────────────────────────
// Strategy B: FirefoxInitNavStrategy (fidelity = 0.00)
// ─────────────────────────────────────────────────────────────────────────────
// Models a real Firefox initial page load — the one request shape the shield
// explicitly allows (proven by the real_firefox_should_pass test at score < 0.20).
// This is direct navigation: typing a URL in the address bar or opening a bookmark.
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
type FirefoxInitNavStrategy struct{}

func (s *FirefoxInitNavStrategy) Name() string      { return "firefox_init_nav" }
func (s *FirefoxInitNavStrategy) Fidelity() float64 { return 0.00 }

func (s *FirefoxInitNavStrategy) Apply(req *http.Request, rg *RequestGenerator, targetURL string) {
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
	for _, h := range secChUaHeaders {
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
	for _, h := range secChUaHeaders {
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
	for _, h := range secChUaHeaders {
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
	for _, h := range secChUaHeaders {
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
// This is a distinct evasion path from FirefoxInitNavStrategy (which uses site=none).
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
	for _, h := range secChUaHeaders {
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
	for _, h := range secChUaHeaders {
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
	for _, h := range secChUaHeaders {
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
	for _, h := range secChUaHeaders {
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
