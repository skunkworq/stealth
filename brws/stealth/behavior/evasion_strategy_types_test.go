package behavior

import (
	"net/http"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// DefaultStrategies / StrategiesForURL constructors
// ─────────────────────────────────────────────────────────────────────────────

func TestDefaultStrategies_NonEmpty(t *testing.T) {
	strategies := DefaultStrategies()
	if len(strategies) == 0 {
		t.Fatal("DefaultStrategies() returned empty slice")
	}
}

func TestDefaultStrategies_NamesUnique(t *testing.T) {
	seen := make(map[string]bool)
	for _, s := range DefaultStrategies() {
		if seen[s.Name()] {
			t.Errorf("duplicate strategy name: %q", s.Name())
		}
		seen[s.Name()] = true
	}
}

func TestDefaultStrategies_FidelityRange(t *testing.T) {
	for _, s := range DefaultStrategies() {
		f := s.Fidelity()
		if f < 0.0 || f > 1.0 {
			t.Errorf("strategy %q has out-of-range fidelity: %f", s.Name(), f)
		}
	}
}

func TestStrategiesForURL_PageURL(t *testing.T) {
	strategies := StrategiesForURL("https://example.com/page")
	if len(strategies) == 0 {
		t.Fatal("StrategiesForURL() returned empty slice for page URL")
	}
}

func TestStrategiesForURL_TelemetryURL(t *testing.T) {
	strategies := StrategiesForURL("https://api.example.com/collect")
	if len(strategies) == 0 {
		t.Fatal("StrategiesForURL() returned empty slice for telemetry URL")
	}
}

func TestStrategiesForURL_TelemetryFirst(t *testing.T) {
	// For telemetry URLs, POST/single-header strategies should appear first
	strategies := StrategiesForURL("https://metrics.example.com/track")
	if len(strategies) == 0 {
		t.Fatal("no strategies returned")
	}
	// First strategy should NOT be FirefoxInitNav — telemetry URLs get POST strategies first
	first := strategies[0].Name()
	if first == "firefox_init_nav" {
		t.Errorf("telemetry URL strategy list starts with firefox_init_nav, expected POST-based strategy first")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// classifyURL
// ─────────────────────────────────────────────────────────────────────────────

func TestClassifyURL_Page(t *testing.T) {
	cases := []string{
		"https://example.com/",
		"https://example.com/page",
		"https://www.news.com/article",
	}
	for _, u := range cases {
		if classifyURL(u) != URLTypePage {
			t.Errorf("classifyURL(%q) = Telemetry, want Page", u)
		}
	}
}

func TestClassifyURL_Telemetry_ByHost(t *testing.T) {
	telemetryHosts := []string{
		"https://api.example.com/data",
		"https://metrics.example.com/",
		"https://telemetry.example.com/",
		"https://events.example.com/",
		"https://collect.example.com/",
		"https://track.example.com/",
		"https://beacon.example.com/",
	}
	for _, u := range telemetryHosts {
		if classifyURL(u) != URLTypeTelemetry {
			t.Errorf("classifyURL(%q) = Page, want Telemetry", u)
		}
	}
}

func TestClassifyURL_Telemetry_ByPath(t *testing.T) {
	telemetryPaths := []string{
		"https://example.com/api/telemetry",
		"https://example.com/collect",
		"https://example.com/beacon",
		"https://example.com/metrics",
		"https://example.com/track",
		"https://example.com/events",
	}
	for _, u := range telemetryPaths {
		if classifyURL(u) != URLTypeTelemetry {
			t.Errorf("classifyURL(%q) = Page, want Telemetry", u)
		}
	}
}

func TestClassifyURL_InvalidURL(t *testing.T) {
	// Malformed URL should fall back to Page (not panic)
	result := classifyURL("://not-a-url")
	if result != URLTypePage {
		t.Errorf("classifyURL(invalid) = %v, want URLTypePage", result)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy Name/Fidelity contract for each concrete type
// ─────────────────────────────────────────────────────────────────────────────

type strategySpec struct {
	strategy EvasionStrategy
	name     string
	fidelity float64
}

func allConcreteStrategies() []strategySpec {
	return []strategySpec{
		{&FirefoxInitNavStrategy{}, "firefox_init_nav", 0.00},
		{&RealBrowserStrategy{}, "real_browser", 0.00},
		{&NoneContextCorsStrategy{}, "none_context_cors", 0.20},
		{&SameOriginSubThresholdStrategy{}, "cross_site_same_origin", 0.20},
		{&SameOriginSameSiteStrategy{}, "same_site_telemetry", 0.30},
		{&SameOriginSameSiteMinimalStrategy{}, "reduced_beacon", 0.10},
		{&SameSiteCorsStrategy{}, "same_site_cors_telemetry", 0.10},
		{&CrossSiteNavigateStrategy{}, "navigate_form", 0.10},
		{&CrossSiteCorsStrategy{}, "cross_site_cors", 0.20},
		{&SameSiteMinimalStrategy{}, "cors_reduced_beacon", 0.10},
		{&NavigateMinimalStrategy{}, "navigate_minimal", 0.20},
		{&BodyMigrationStrategy{}, "body_migration", 0.30},
		{&SelectiveStripStrategy{}, "selective_strip", 0.00},
		{&PostLoadSameOriginFetchStrategy{}, "postload_same_origin_fetch", 0.40},
		{&PostLoadCrossSiteFetchStrategy{}, "postload_cross_site_fetch", 0.40},
		{&PostLoadNoCORSBeaconStrategy{}, "postload_nocors_beacon", 0.40},
		{&SingleHeaderSameOriginStrategy{}, "single_header_same_origin", 0.10},
		{&SingleHeaderCrossSiteStrategy{}, "single_header_cross_site", 0.10},
		{&SingleHeaderNoCORSStrategy{}, "single_header_nocors", 0.10},
		{&PostNoCORSTwoHeaderStrategy{}, "post_nocors_two_header", 0.15},
		{&PostCrossSiteThreeHeaderStrategy{}, "post_cross_site_three_header", 0.20},
		{&PostSameSiteThreeHeaderStrategy{}, "post_same_site_three_header", 0.20},
		{&PostNoneContextTwoHeaderStrategy{}, "post_none_context_two_header", 0.15},
		{&PostSameOriginSmallStrategy{}, "post_same_origin_small", 0.20},
		{&ChromeSameOriginFetchStrategy{}, "chrome_same_origin_fetch", 0.50},
		{&ChromeCrossSiteFetchStrategy{}, "chrome_cross_site_fetch", 0.50},
		{&ChromeNoCORSBeaconStrategy{}, "chrome_nocors_beacon", 0.50},
		{&IframeNavigationStrategy{}, "iframe_navigation", 0.00},
		{&ScriptFetchStrategy{}, "script_fetch", 0.00},
		{&ImagePixelStrategy{}, "image_pixel", 0.00},
		{&StyleFetchStrategy{}, "style_fetch", 0.00},
		{&WorkerImportStrategy{}, "worker_import", 0.00},
	}
}

func TestAllStrategyNames(t *testing.T) {
	for _, spec := range allConcreteStrategies() {
		if spec.strategy.Name() != spec.name {
			t.Errorf("%T.Name() = %q, want %q", spec.strategy, spec.strategy.Name(), spec.name)
		}
	}
}

func TestAllStrategyFidelities(t *testing.T) {
	const eps = 1e-9
	for _, spec := range allConcreteStrategies() {
		got := spec.strategy.Fidelity()
		if got < spec.fidelity-eps || got > spec.fidelity+eps {
			t.Errorf("%T.Fidelity() = %f, want %f", spec.strategy, got, spec.fidelity)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Apply — smoke-test every strategy (no panic, method=GET set)
// ─────────────────────────────────────────────────────────────────────────────

func TestAllStrategies_Apply_NoPanic(t *testing.T) {
	rg := NewRequestGenerator(nil)
	for _, spec := range allConcreteStrategies() {
		spec := spec
		t.Run(spec.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, "https://example.com/data", nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120")
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", "https://example.com")
			spec.strategy.Apply(req, rg, "https://example.com/data")
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// AdaptiveEvasionFSM constructor and basic state
// ─────────────────────────────────────────────────────────────────────────────

func TestNewAdaptiveEvasionFSM_DefaultStrategies(t *testing.T) {
	fsm := NewAdaptiveEvasionFSM()
	if fsm == nil {
		t.Fatal("NewAdaptiveEvasionFSM() returned nil")
	}
	if len(fsm.Strategies()) == 0 {
		t.Error("FSM should have at least one strategy")
	}
}

func TestNewAdaptiveEvasionFSM_CustomStrategies(t *testing.T) {
	fsm := NewAdaptiveEvasionFSM(&FirefoxInitNavStrategy{}, &RealBrowserStrategy{})
	if len(fsm.Strategies()) != 2 {
		t.Errorf("expected 2 strategies, got %d", len(fsm.Strategies()))
	}
}

func TestAdaptiveEvasionFSM_CurrentStrategy_Initial(t *testing.T) {
	fsm := NewAdaptiveEvasionFSM(&FirefoxInitNavStrategy{}, &RealBrowserStrategy{})
	if fsm.CurrentStrategy().Name() != "firefox_init_nav" {
		t.Errorf("initial strategy = %q, want firefox_init_nav", fsm.CurrentStrategy().Name())
	}
}

func TestAdaptiveEvasionFSM_StateIndex_Initial(t *testing.T) {
	fsm := NewAdaptiveEvasionFSM()
	if fsm.StateIndex() != 0 {
		t.Errorf("initial state index = %d, want 0", fsm.StateIndex())
	}
}

func TestAdaptiveEvasionFSM_NotExhaustedInitially(t *testing.T) {
	fsm := NewAdaptiveEvasionFSM()
	if fsm.Exhausted() {
		t.Error("FSM should not be exhausted initially")
	}
}

func TestAdaptiveEvasionFSM_ShouldNotEscalateInitially(t *testing.T) {
	fsm := NewAdaptiveEvasionFSM()
	if fsm.ShouldEscalate() {
		t.Error("FSM should not recommend escalation initially")
	}
}

func TestAdaptiveEvasionFSM_BanSignals(t *testing.T) {
	fsm := NewAdaptiveEvasionFSM()
	fsm.RecordBanSignal(403)
	fsm.RecordBanSignal(429)
	if fsm.LastBanStatus() != 429 {
		t.Errorf("LastBanStatus() = %d, want 429", fsm.LastBanStatus())
	}
	fsm.ResetBanSignals()
	if fsm.ShouldEscalate() {
		t.Error("ShouldEscalate() should be false after ResetBanSignals")
	}
}

func TestAdaptiveEvasionFSM_EscalatesAfterBanThreshold(t *testing.T) {
	fsm := NewAdaptiveEvasionFSM()
	// banSignalThreshold is 3
	fsm.RecordBanSignal(403)
	fsm.RecordBanSignal(403)
	fsm.RecordBanSignal(403)
	if !fsm.ShouldEscalate() {
		t.Error("ShouldEscalate() should be true after 3 ban signals")
	}
	if fsm.EscalationReason() != "ban_signals" {
		t.Errorf("EscalationReason() = %q, want 'ban_signals'", fsm.EscalationReason())
	}
}

func TestAdaptiveEvasionFSM_CaptchaTracking(t *testing.T) {
	fsm := NewAdaptiveEvasionFSM()
	fsm.RecordCaptchaDetected()
	fsm.RecordCaptchaDetected()
	fsm.RecordCaptchaSolveResult(true)
	fsm.RecordCaptchaSolveResult(false)

	det, solves, fails := fsm.CaptchaStats()
	if det != 2 {
		t.Errorf("captcha detections = %d, want 2", det)
	}
	if solves != 1 {
		t.Errorf("captcha solves = %d, want 1", solves)
	}
	if fails != 1 {
		t.Errorf("captcha failures = %d, want 1", fails)
	}
}

func TestAdaptiveEvasionFSM_CaptchaExhaustion(t *testing.T) {
	fsm := NewAdaptiveEvasionFSM()
	// captchaMaxRetries is 2
	fsm.RecordCaptchaSolveResult(false)
	fsm.RecordCaptchaSolveResult(false)
	if !fsm.ShouldEscalate() {
		t.Error("ShouldEscalate() should be true after captcha failures >= max")
	}
	if fsm.EscalationReason() != "captcha_solve_exhausted" {
		t.Errorf("EscalationReason() = %q, want 'captcha_solve_exhausted'", fsm.EscalationReason())
	}
}

func TestAdaptiveEvasionFSM_ShouldAttemptCaptcha(t *testing.T) {
	fsm := NewAdaptiveEvasionFSM()
	if !fsm.ShouldAttemptCaptcha() {
		t.Error("ShouldAttemptCaptcha() should be true initially")
	}
	fsm.RecordCaptchaSolveResult(false)
	fsm.RecordCaptchaSolveResult(false)
	if fsm.ShouldAttemptCaptcha() {
		t.Error("ShouldAttemptCaptcha() should be false after max retries")
	}
}

func TestAdaptiveEvasionFSM_ConvergedFalseWhenFewAttempts(t *testing.T) {
	fsm := NewAdaptiveEvasionFSM()
	if fsm.Converged() {
		t.Error("Converged() should be false when no attempts recorded")
	}
}

func TestAdaptiveEvasionFSM_Transitions_EmptyInitially(t *testing.T) {
	fsm := NewAdaptiveEvasionFSM()
	if len(fsm.Transitions()) != 0 {
		t.Errorf("expected 0 transitions initially, got %d", len(fsm.Transitions()))
	}
}

func TestAdaptiveEvasionFSM_Summary_NoPanic(t *testing.T) {
	fsm := NewAdaptiveEvasionFSM()
	fsm.RecordResult(0.8, true)
	fsm.RecordResult(0.9, true)
	fsm.RecordResult(0.85, true)
	summary := fsm.Summary()
	if summary == "" {
		t.Error("Summary() returned empty string")
	}
}

func TestAdaptiveEvasionFSM_RecordResult_AdvancesState(t *testing.T) {
	fsm := NewAdaptiveEvasionFSM(&FirefoxInitNavStrategy{}, &RealBrowserStrategy{})
	// Force detection_rate > 50% after 3 attempts
	fsm.RecordResult(0.9, true)
	fsm.RecordResult(0.9, true)
	fsm.RecordResult(0.9, true)
	// Should have advanced to strategy index 1
	if fsm.StateIndex() == 0 {
		t.Error("FSM should have advanced past index 0 after high detection rate")
	}
}

func TestNewAdaptiveEvasionFSMForURL_NoPanic(t *testing.T) {
	fsm := NewAdaptiveEvasionFSMForURL("https://example.com/page")
	if fsm == nil {
		t.Fatal("NewAdaptiveEvasionFSMForURL() returned nil")
	}
	if len(fsm.Strategies()) == 0 {
		t.Error("FSM should have strategies")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// craftEvasionBody
// ─────────────────────────────────────────────────────────────────────────────

func TestCraftEvasionBody_NonEmpty(t *testing.T) {
	body := craftEvasionBody()
	if body == "" {
		t.Fatal("craftEvasionBody() returned empty string")
	}
}

func TestCraftEvasionBody_HasEvasionKeys(t *testing.T) {
	body := craftEvasionBody()
	if !strings.Contains(body, "timing_metrics") {
		t.Error("craftEvasionBody() should contain 'timing_metrics' compound key")
	}
	if !strings.Contains(body, "perf_data") {
		t.Error("craftEvasionBody() should contain 'perf_data' compound key")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// rebuildHeaderOrderClean
// ─────────────────────────────────────────────────────────────────────────────

func TestRebuildHeaderOrderClean_RemovesEntry(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	req.Header.Set("X-Stealth-Header-Order", "User-Agent,Content-Type,Accept")
	req.Header.Set("User-Agent", "test")
	req.Header.Set("Accept", "text/html")
	// Content-Type is not set on the request (should be filtered out)

	removed := map[string]bool{"Content-Type": true}
	rebuildHeaderOrderClean(req, removed)

	order := req.Header.Get("X-Stealth-Header-Order")
	if strings.Contains(order, "Content-Type") {
		t.Errorf("rebuildHeaderOrderClean should remove Content-Type, got: %q", order)
	}
	if !strings.Contains(order, "User-Agent") {
		t.Errorf("rebuildHeaderOrderClean should retain User-Agent, got: %q", order)
	}
}

func TestRebuildHeaderOrderClean_NoOrder_NoOp(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	// No X-Stealth-Header-Order header set — should not panic
	rebuildHeaderOrderClean(req, map[string]bool{"X-Foo": true})
}

// ─────────────────────────────────────────────────────────────────────────────
// URLType constants
// ─────────────────────────────────────────────────────────────────────────────

func TestURLType_Values(t *testing.T) {
	if URLTypePage != 0 {
		t.Errorf("URLTypePage = %d, want 0", URLTypePage)
	}
	if URLTypeTelemetry != 1 {
		t.Errorf("URLTypeTelemetry = %d, want 1", URLTypeTelemetry)
	}
}
