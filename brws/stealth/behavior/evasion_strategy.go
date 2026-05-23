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

	"github.com/skunkworq/stealth/brws/core/constants"
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

// secChUaHeaders lists the Chromium client-hint headers absent in Firefox.
var secChUaHeaders = []string{
	"Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform",
	"Sec-Ch-Ua-Full-Version-List", "Sec-Ch-Ua-Arch", "Sec-Ch-Ua-Bitness", "Sec-Ch-Ua-Model",
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
		&FirefoxInitNavStrategy{},             // Models Firefox initial page navigation (address bar) — bypasses ALL provenance gates (EVASION)
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
			&FirefoxInitNavStrategy{},
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
			&FirefoxInitNavStrategy{},
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
// RequestEvaluation / DetectionAnalyzer — interface for self-analysis pre-flight
// ─────────────────────────────────────────────────────────────────────────────

// RequestEvaluation captures the shield's verdict on a single outgoing request.
// Distinct from challenge.DetectionResult, which is the richer inbound detection
// result used by the server-side challenge/fingerprint pipeline.
type RequestEvaluation struct {
	IsBot      bool
	Score      float64
	Indicators []string
}

// DetectionAnalyzer runs a request through local detection and returns an evaluation.
// In tests this is the StealthDetector; in production it can be nil (rely on
// HTTP ban signals instead).
type DetectionAnalyzer func(req *http.Request) RequestEvaluation

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
	lastBanStatus      int
	exhausted          bool

	// Captcha tracking
	captchaDetections int // total captcha challenges encountered
	captchaSolves     int // successful solves
	captchaFailures   int // failed solve attempts
	captchaMaxRetries int // max failures before escalation (default 2)
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
		captchaMaxRetries:  2,
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
	fsm.lastBanStatus = statusCode
}

// ShouldEscalate returns true if the FSM recommends escalating to browser mode,
// either because all strategies are exhausted, ban signals exceed the threshold,
// or captcha solving has been exhausted.
func (fsm *AdaptiveEvasionFSM) ShouldEscalate() bool {
	fsm.mu.Lock()
	defer fsm.mu.Unlock()
	return fsm.exhausted ||
		fsm.banSignals >= fsm.banSignalThreshold ||
		fsm.captchaFailures >= fsm.captchaMaxRetries
}

// EscalationReason returns why escalation is recommended.
func (fsm *AdaptiveEvasionFSM) EscalationReason() string {
	fsm.mu.Lock()
	defer fsm.mu.Unlock()
	if fsm.captchaFailures >= fsm.captchaMaxRetries {
		return "captcha_solve_exhausted"
	}
	if fsm.exhausted {
		return "fsm_exhausted"
	}
	if fsm.banSignals >= fsm.banSignalThreshold {
		return "ban_signals"
	}
	return ""
}

// LastBanStatus returns the HTTP status code of the most recent ban signal.
func (fsm *AdaptiveEvasionFSM) LastBanStatus() int {
	fsm.mu.Lock()
	defer fsm.mu.Unlock()
	return fsm.lastBanStatus
}

// ResetBanSignals clears the ban signal counter (e.g. after a successful browser request).
func (fsm *AdaptiveEvasionFSM) ResetBanSignals() {
	fsm.mu.Lock()
	defer fsm.mu.Unlock()
	fsm.banSignals = 0
}

// RecordCaptchaDetected records that a captcha challenge was encountered.
func (fsm *AdaptiveEvasionFSM) RecordCaptchaDetected() {
	fsm.mu.Lock()
	defer fsm.mu.Unlock()
	fsm.captchaDetections++
}

// RecordCaptchaSolveResult records the outcome of a captcha solve attempt.
// On failure, it also counts as a ban signal since the site is actively blocking.
func (fsm *AdaptiveEvasionFSM) RecordCaptchaSolveResult(solved bool) {
	fsm.mu.Lock()
	defer fsm.mu.Unlock()
	if solved {
		fsm.captchaSolves++
	} else {
		fsm.captchaFailures++
		fsm.banSignals++ // failed captcha = effectively blocked
	}
}

// ShouldAttemptCaptcha returns true if captcha solving should be attempted
// before escalating to browser mode. Returns false after repeated failures.
func (fsm *AdaptiveEvasionFSM) ShouldAttemptCaptcha() bool {
	fsm.mu.Lock()
	defer fsm.mu.Unlock()
	return fsm.captchaFailures < fsm.captchaMaxRetries
}

// CaptchaStats returns captcha detection/solve/failure counts.
func (fsm *AdaptiveEvasionFSM) CaptchaStats() (detections, solves, failures int) {
	fsm.mu.Lock()
	defer fsm.mu.Unlock()
	return fsm.captchaDetections, fsm.captchaSolves, fsm.captchaFailures
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
	fmt.Fprintf(&sb, "  exhausted=%v ban_signals=%d/%d captcha=%d/%d/%d (det/solve/fail)\n",
		fsm.exhausted, fsm.banSignals, fsm.banSignalThreshold,
		fsm.captchaDetections, fsm.captchaSolves, fsm.captchaFailures)
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
