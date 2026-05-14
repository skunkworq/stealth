package stealth

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
	"github.com/skunkworq/stealth/brws/stealth/behavior"
	"github.com/skunkworq/stealth/brws/stealth/challenge"

	"github.com/skunkworq/stealth/brws/browser/engine"
	pool "github.com/skunkworq/stealth/brws/network/proxy/connpool"
	wf "github.com/skunkworq/stealth/brws/browser/engine/meta/waterfall"
	"github.com/skunkworq/stealth/brws/core/instrumentation"
	"github.com/skunkworq/stealth/brws/ml"
	"github.com/skunkworq/stealth/brws/content/understand"
	"github.com/skunkworq/stealth/brws/stealth/profile/session"
	"github.com/skunkworq/stealth/brws/stealth/captcha/external_service"
	challengefsm "github.com/skunkworq/stealth/brws/stealth/challenge/fsm"
)

// Adaptive is the main entry point for the stealth browser automation library.
type Adaptive struct {
	engine        engine.Engine
	config        *Config
	options       *Options
	sessionMgr    *session.Manager
	policyLoader  *ml.PolicyLoader
	behavTracker  *BehavioralTracker
	captchaSolver *CaptchaSolver
	cfSolver      *CloudflareSolverClient

	// Anti-bot escalation
	waterfall         *wf.Waterfall
	tierTracker       *pool.TierTracker
	escalation        *EscalationConfig
	evasionFSM        *behavior.AdaptiveEvasionFSM
	evasionFSMEnabled bool

	// Captcha solving with trace replay
	traceLibrary *challenge.TraceLibrary

	logger       *instrumentation.Logger
	tracer       *instrumentation.Tracer
	hooks        *instrumentation.HookRegistry
	fsm          *instrumentation.FSM
	orchestrator *challengefsm.ChallengeOrchestrator
}

// Config holds configuration for the stealth client.
type Config struct {
	EngineName      string
	Headless        bool
	Proxy           string
	PolicyModelPath string

	Stealth         engine.StealthConfig
	Challenge       *ChallengeConfig
	Session         *SessionConfig
	Instrumentation *InstrumentationConfig

	// Anti-bot escalation
	Escalation         *EscalationConfig
	WaterfallEngine    *wf.Waterfall
	TieredProxies      []pool.TieredProxy
	EvasionFSMDisabled bool // Set true to disable the adaptive evasion FSM (enabled by default)

	// Trace-based captcha solving
	TraceDataDir string // path to trace data directory for replay-based solving
}

// ChallengeConfig configures challenge handling.
type ChallengeConfig struct {
	AutoDetect      bool
	AutoSolve       bool
	SolverAPIKey    string
	SolverType      string
	VerifyURL       string // Override captcha verify endpoint (derived from target if empty)
	MaxSolveRetries int    // Max captcha solve attempts before giving up (default 1)
}

// SessionConfig configures session management.
type SessionConfig struct {
	Enabled     bool
	ProfileDir  string
	SessionName string
}

// InstrumentationConfig configures logging and tracing.
type InstrumentationConfig struct {
	LogLevel      string
	EnableTracing bool
	EnableJSONLog bool
}

// Options holds runtime options.
type Options struct {
	Timeout time.Duration
}

// New creates a new stealth client with default configuration.
func NewAdaptive(opts ...Option) (*Adaptive, error) {
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(cfg)
	}
	return NewAdaptiveWithConfig(cfg)
}

// NewAdaptiveFromConfig creates an Adaptive from a value-typed Config.
func NewAdaptiveFromConfig(cfg Config) (*Adaptive, error) {
	return NewAdaptiveWithConfig(&cfg)
}

// NewAdaptiveWithConfig creates an Adaptive from a pointer-typed Config.
func NewAdaptiveWithConfig(cfg *Config) (*Adaptive, error) {
	logLevel := "info"
	if cfg.Instrumentation != nil {
		logLevel = cfg.Instrumentation.LogLevel
	}
	logger, err := instrumentation.NewLogger(&instrumentation.Config{
		LogLevel:          logLevel,
		EnableJSONLogging: cfg.Instrumentation != nil && cfg.Instrumentation.EnableJSONLog,
	})
	if err != nil {
		return nil, fmt.Errorf("create logger: %w", err)
	}

	logger.Info("initializing stealth client", "engine", cfg.EngineName)

	// Lazily create default stealth config for known engines
	if cfg.Stealth == nil {
		cfg.Stealth = engine.DefaultStealthConfigFor(cfg.EngineName)
	}

	stealthEnabled := cfg.Stealth != nil && cfg.Stealth.IsEnabled()
	eng, err := engine.New(cfg.EngineName, engine.Options{
		Headless:         cfg.Headless,
		Proxy:            cfg.Proxy,
		ProfileDir:       cfg.Session.ProfileDir,
		Stealth:          stealthEnabled,
		StealthTLS:       stealthEnabled,
		ProfileName:      "chrome-120-macos",
		StealthConfigRaw: cfg.Stealth,
	})
	if err != nil {
		return nil, fmt.Errorf("create engine: %w", err)
	}

	return newAdaptiveWithEngine(eng, cfg, logger)
}

// NewAdaptiveWithEngine creates an Adaptive that reuses an existing engine.
// This is useful when the caller already manages the browser lifecycle
// (e.g. an agent that needs persistent tabs).
func NewAdaptiveWithEngine(eng engine.Engine, cfg *Config) (*Adaptive, error) {
	logLevel := "info"
	if cfg.Instrumentation != nil {
		logLevel = cfg.Instrumentation.LogLevel
	}
	logger, err := instrumentation.NewLogger(&instrumentation.Config{
		LogLevel:          logLevel,
		EnableJSONLogging: cfg.Instrumentation != nil && cfg.Instrumentation.EnableJSONLog,
	})
	if err != nil {
		return nil, fmt.Errorf("create logger: %w", err)
	}

	logger.Info("initializing stealth client with existing engine", "engine", eng.Name())
	return newAdaptiveWithEngine(eng, cfg, logger)
}

func newAdaptiveWithEngine(eng engine.Engine, cfg *Config, logger *instrumentation.Logger) (*Adaptive, error) {
	var sessMgr *session.Manager
	if cfg.Session.Enabled && cfg.Session.ProfileDir != "" {
		sessMgr, _ = session.NewManager(cfg.Session.ProfileDir)
	}

	tracer := instrumentation.NewTracer()
	hooks := instrumentation.DefaultHookRegistry()
	fsm := instrumentation.NewRequestFSM()

	fsm.SetTransitionFunc(func(ctx context.Context, from, to instrumentation.State, event instrumentation.Event) error {
		logger.Debug("state transition", "from", from, "to", to, "event", event)
		return nil
	})

	// Load RL policy if configured
	var policyLoader *ml.PolicyLoader
	if cfg.PolicyModelPath != "" {
		var err error
		policyLoader, err = ml.NewPolicyLoader(cfg.PolicyModelPath)
		if err != nil {
			logger.Warn("failed to load RL policy, falling back to hardcoded", "path", cfg.PolicyModelPath, "error", err)
		} else {
			logger.Info("RL policy loaded", "model_id", policyLoader.ModelID(), "input_dim", policyLoader.InputDim())
		}
	}

	// Initialize captcha solver if auto-solve is enabled
	var captchaSolver *CaptchaSolver
	if cfg.Challenge.AutoSolve {
		captchaSolver = NewCaptchaSolver()
		logger.Info("captcha auto-solver initialized")
	}

	// Initialize Cloudflare solver if auto-solve is enabled
	var cfSolver *CloudflareSolverClient
	if cfg.Challenge.AutoSolve {
		cfSolver = NewCloudflareSolverClient()
		logger.Info("cloudflare auto-solver initialized")
	}

	// Initialize challenge orchestrator if auto-solve is enabled
	var orchestrator *challengefsm.ChallengeOrchestrator
	if cfg.Challenge.AutoSolve {
		registry := challengefsm.NewSolverRegistry()
		solverConfig := &challengefsm.SolverConfig{
			APIKey:     cfg.Challenge.SolverAPIKey,
			MaxRetries: cfg.Challenge.MaxSolveRetries,
			Timeout:    30 * time.Second,
			HumanDelay: true,
			VerifyURL:  cfg.Challenge.VerifyURL,
		}
		if solverConfig.MaxRetries <= 0 {
			solverConfig.MaxRetries = 1
		}

		orchestrator = challengefsm.NewChallengeOrchestrator(registry, solverConfig, logger)
		logger.Info("challenge orchestrator initialized")

		// Solvers will be registered after client creation (need client methods)
	}

	logger.Info("stealth client initialized")

	// Set up anti-bot escalation components
	var waterfallEng *wf.Waterfall
	if cfg.WaterfallEngine != nil {
		waterfallEng = cfg.WaterfallEngine
	}
	var tierTracker *pool.TierTracker
	if len(cfg.TieredProxies) > 0 {
		tierTracker = pool.NewTierTracker(cfg.TieredProxies)
	}
	escalation := cfg.Escalation
	if escalation == nil {
		escalation = DefaultEscalationConfig()
	}

	// Evasion FSM is created lazily on first Navigate() so it can select
	// URL-aware strategies (telemetry URLs get exotic dest strategies first).
	// The evasionFSMEnabled flag controls whether it will be created.
	evasionFSMEnabled := !cfg.EvasionFSMDisabled
	if evasionFSMEnabled {
		logger.Info("evasion FSM enabled (will initialize on first request)")
	}
	var evasionFSM *behavior.AdaptiveEvasionFSM

	// Load trace library for replay-based captcha solving
	var traceLib *challenge.TraceLibrary
	if cfg.TraceDataDir != "" {
		traceLib = challenge.NewTraceLibrary(cfg.TraceDataDir)
		if err := traceLib.LoadAll(); err != nil {
			logger.Warn("failed to load trace library", "error", err)
		} else {
			logger.Info("trace library loaded", "recordings", traceLib.Count())
		}
	}

	c := &Adaptive{
		engine:            eng,
		options:           &Options{Timeout: 30 * time.Second},
		config:            cfg,
		sessionMgr:        sessMgr,
		policyLoader:      policyLoader,
		behavTracker:      NewBehavioralTracker(),
		captchaSolver:     captchaSolver,
		cfSolver:          cfSolver,
		waterfall:         waterfallEng,
		tierTracker:       tierTracker,
		escalation:        escalation,
		evasionFSM:        evasionFSM,
		evasionFSMEnabled: evasionFSMEnabled,
		traceLibrary:      traceLib,
		logger:            logger,
		tracer:            tracer,
		hooks:             hooks,
		fsm:               fsm,
		orchestrator:      orchestrator,
	}

	// Register solvers with the orchestrator (need client methods bound)
	if orchestrator != nil {
		c.registerSolvers(orchestrator.Registry())
	}

	return c, nil
}

// Navigate performs a GET request to the specified URL.
func (c *Adaptive) Navigate(ctx context.Context, url string) (*Response, error) {
	return c.navigate(ctx, url, nil)
}

// NavigateOnTab performs a GET request on an existing browser tab.
// The stealth engine runs its setup (scripts, headers, permissions) directly
// on the provided tabCtx, then navigates it. This eliminates the wasteful
// double-navigation pattern when the stealth client and agent share a tab.
func (c *Adaptive) NavigateOnTab(ctx context.Context, tabCtx context.Context, url string) (*Response, error) {
	return c.navigate(ctx, url, tabCtx)
}

// navigate is the shared implementation for Navigate and NavigateOnTab.
// When tabCtx is nil, it uses engine.Do() (creates a temp tab).
// When tabCtx is non-nil, it uses engine.DoOnTab() (operates on existing tab).
func (c *Adaptive) navigate(ctx context.Context, url string, tabCtx context.Context) (*Response, error) {
	ctx, span := c.tracer.StartSpan(ctx, "navigate", instrumentation.SpanKindRequest)

	span.SetAttribute("url", url)
	defer span.End()

	c.logger.Info("navigating", "url", url)

	// Lazy FSM init — select URL-aware strategies on first request
	if c.evasionFSMEnabled && c.evasionFSM == nil {
		c.evasionFSM = behavior.NewAdaptiveEvasionFSMForURL(url)
		c.logger.Info("evasion FSM initialized with URL-aware strategies", "url", url)
	}

	_ = c.hooks.Execute(ctx, instrumentation.HookNames.OnRequestStart)
	c.fsm.ResetState(instrumentation.RequestStates.Idle)
	_ = c.fsm.Transition(ctx, instrumentation.RequestEvents.Start)

	var resp *engine.Response
	var err error
	var challengeSolved bool
	maxRetries := 3

	// Use waterfall engine when available, otherwise raw engine
	activeEngine := c.ActiveEngine()

	// Determine request function: DoOnTab when tabCtx provided, otherwise Do
	var doRequest func(context.Context, *engine.Request) (*engine.Response, error)
	if tabCtx != nil {
		if te, ok := activeEngine.(engine.TabEngine); ok {
			doRequest = func(ctx context.Context, req *engine.Request) (*engine.Response, error) {
				return te.DoOnTab(ctx, tabCtx, req)
			}
		} else {
			return nil, fmt.Errorf("engine %q does not support DoOnTab", activeEngine.Name())
		}
	} else {
		doRequest = activeEngine.Do
	}

	for attempt := 1; attempt <= maxRetries; attempt++ {
		resp, err = doRequest(ctx, &engine.Request{
			URL:     url,
			Timeout: c.options.Timeout,
		})
		if err != nil {
			span.SetAttribute("error", err.Error())
			c.logger.Error("navigation failed", "url", url, "error", err)
			return nil, err
		}

		// Check for WAF/challenge markers in the response body/headers.
		// The engine now returns raw responses; challenge detection lives here.
		if isWAFResponse(resp) && attempt < maxRetries {
			c.logger.Warn("WAF challenge detected in response. Adapting stealth config and retrying",
				"attempt", attempt, "status", resp.Status)

			// FSM State Transition
			_ = c.fsm.Transition(ctx, instrumentation.RequestEvents.Retry)

			// RL-driven stealth adaptation or hardcoded fallback
			if c.policyLoader != nil && c.config.Stealth != nil {
				stateVec := BuildStateVector(extractAnomaliesFromResponse(resp), nil, nil)
				actionIdx, qValue := c.policyLoader.SelectAction(stateVec)
				applied, field := ApplyAction(c.config.Stealth, actionIdx)
				c.logger.Info("RL policy action", "action", field, "q_value", qValue, "applied", applied)
			} else if c.config.Stealth != nil {
				c.config.Stealth.ToggleFeature("CanvasNoise")
				c.config.Stealth.ToggleFeature("WebGLSpoof")
				c.config.Stealth.ToggleFeature("ClientHints")
			}
			// We wait randomly to let the previous context clear gracefully
			time.Sleep(time.Duration(500+attempt*1500) * time.Millisecond)

			continue
		}

		// Clean response received
		break
	}

	// EVASION FSM: on ban signal, rotate strategy and retry before escalating
	if c.evasionFSM != nil && resp != nil {
		detected := isBanSignal(c.escalation, resp.Status)
		score := 0.0
		if detected {
			score = 1.0
		}
		c.evasionFSM.RecordResult(score, detected)
		if detected {
			c.evasionFSM.RecordBanSignal(resp.Status)

			// Retry with rotated strategy before escalating to browser mode
			prevStrategy := c.evasionFSM.CurrentStrategy().Name()
			for fsmRetry := 0; fsmRetry < len(c.evasionFSM.Strategies()) && !c.evasionFSM.ShouldEscalate(); fsmRetry++ {
				nextStrategy := c.evasionFSM.CurrentStrategy().Name()
				if fsmRetry > 0 && nextStrategy == prevStrategy {
					break // FSM didn't advance — stop retrying
				}
				prevStrategy = nextStrategy
				c.logger.Info("evasion FSM retry", "strategy", nextStrategy, "attempt", fsmRetry+1)

				resp, err = doRequest(ctx, &engine.Request{
					URL:     url,
					Timeout: c.options.Timeout,
				})
				if err != nil {
					break
				}

				retryDetected := isBanSignal(c.escalation, resp.Status)
				retryScore := 0.0
				if retryDetected {
					retryScore = 1.0
				}
				c.evasionFSM.RecordResult(retryScore, retryDetected)
				if retryDetected {
					c.evasionFSM.RecordBanSignal(resp.Status)
				} else {
					break // Strategy evaded — stop retrying
				}
			}
		}
		if c.evasionFSM.ShouldEscalate() && c.waterfall != nil {
			reason := c.evasionFSM.EscalationReason()
			tierName := escalationTierFor(c.escalation, resp.Status)
			c.waterfall.PromoteTier(tierName)
			c.logger.Info("evasion FSM escalation", "reason", reason, "promoting", tierName)
		}
	}

	// ANTI-BOT ESCALATION: on ban-signal status codes, escalate and retry
	if resp != nil && c.escalation != nil && c.escalation.Enabled && isBanSignal(c.escalation, resp.Status) {
		for escAttempt := 0; escAttempt < c.escalation.MaxEscalationRetries; escAttempt++ {
			shouldRetry := c.escalate(ctx, resp, url, nil)
			if !shouldRetry {
				break
			}
			c.logger.Info("escalation retry", "attempt", escAttempt+1, "status", resp.Status)

			resp, err = doRequest(ctx, &engine.Request{
				URL:     url,
				Timeout: c.options.Timeout,
			})
			if err != nil || !isBanSignal(c.escalation, resp.Status) {
				break
			}
		}
	}

	// CAPTCHA SOLVING: detect captcha in response, attempt solve with trace replay before escalating
	if c.evasionFSM != nil && resp != nil && c.isCaptchaResponse(resp) {
		c.evasionFSM.RecordCaptchaDetected()
		c.logger.Info("captcha detected in response", "url", url, "status", resp.Status)

		if c.evasionFSM.ShouldAttemptCaptcha() {
			solvedResp, solveErr := c.attemptCaptchaSolve(ctx, url, resp)
			if solveErr == nil && solvedResp != nil {
				c.evasionFSM.RecordCaptchaSolveResult(true)
				resp = solvedResp
				challengeSolved = true
				span.AddEvent("captcha_solved_via_fsm", nil)
				c.logger.Info("captcha solved via FSM", "url", url)
			} else {
				c.evasionFSM.RecordCaptchaSolveResult(false)
				c.logger.Warn("captcha solve failed", "url", url, "error", solveErr)

				// Check if we should escalate to browser after captcha failure
				if c.evasionFSM.ShouldEscalate() && c.waterfall != nil {
					reason := c.evasionFSM.EscalationReason()
					tierName := escalationTierFor(c.escalation, resp.Status)
					c.waterfall.PromoteTier(tierName)
					c.logger.Info("captcha solve exhausted, escalating", "reason", reason, "promoting", tierName)
				}
			}
		} else {
			c.logger.Info("captcha solve exhausted, skipping to orchestrator")
		}
	}

	// CHALLENGE HANDLING: delegate to orchestrator for anything the FSM didn't solve
	if c.orchestrator != nil && c.config.Challenge.AutoSolve && !c.isCleanResponse(resp) {
		_ = c.fsm.Transition(ctx, instrumentation.RequestEvents.ChallengeDetected)
		solvedResp, _ := c.orchestrator.HandleResponse(ctx, url, resp, c.engine, c.options.Timeout)
		if solvedResp != nil {
			resp = solvedResp
			challengeSolved = true
			span.AddEvent("challenge_solved", nil)
		}
	} else if c.config.Challenge.AutoDetect && resp != nil && !c.isCleanResponse(resp) {
		// Fallback to generic challenge detection (no orchestrator)
		detector := challenge.NewDetector()
		if ch := detector.Detect(resp.Body, resp.Headers); ch != nil {
			span.AddEvent("challenge_detected", map[string]interface{}{"type": string(ch.Type)})
			c.logger.Info("challenge detected", "type", ch.Type)
		}
	}

	if resp == nil {
		return nil, fmt.Errorf("navigation failed: no response received")
	}

	span.SetAttribute("status", resp.Status)
	span.SetAttribute("body_size", len(resp.Body))
	_ = c.fsm.Transition(ctx, instrumentation.RequestEvents.Complete)
	_ = c.hooks.Execute(ctx, instrumentation.HookNames.OnRequestEnd)

	c.logger.Info("navigation complete", "url", url, "status", resp.Status, "size", len(resp.Body))

	return &Response{
		Status:          resp.Status,
		Headers:         resp.Headers,
		Body:            resp.Body,
		FinalURL:        resp.FinalURL,
		Trace:           resp.Trace,
		ChallengeSolved: challengeSolved,
	}, nil
}

// Scrape fetches a URL and returns the response.
// It is a convenience alias for Navigate with a name that reflects the
// high-level scraping intent.
func (c *Adaptive) Scrape(ctx context.Context, url string) (*Response, error) {
	return c.Navigate(ctx, url)
}

// NavigateWithReferrer performs a navigation with an explicit referrer.
// When the underlying engine is a Chromium StealthEngine with StealthPlus
// enabled, this sets both the HTTP Referer header and document.referrer.
func (c *Adaptive) NavigateWithReferrer(ctx context.Context, url string, referrer string) (*Response, error) {
	c.logger.Info("navigating with referrer", "url", url, "referrer", referrer)

	activeEngine := c.ActiveEngine()
	resp, err := activeEngine.Do(ctx, &engine.Request{
		URL:      url,
		Referrer: referrer,
		Timeout:  c.options.Timeout,
	})
	if err != nil {
		return nil, err
	}

	return &Response{
		Status:   resp.Status,
		Headers:  resp.Headers,
		Body:     resp.Body,
		FinalURL: resp.FinalURL,
		Trace:    resp.Trace,
	}, nil
}

// NavigateWithSearchProfile navigates to url using a pre-built search engine
// referrer profile.  Supported profiles: "google", "bing", "duckduckgo", "random".
// When the engine implements ProfileNavigator, the full referrer profile is
// applied via the engine; otherwise the referrer is passed as a header.
func (c *Adaptive) NavigateWithSearchProfile(ctx context.Context, url string, profile string) (*Response, error) {
	c.logger.Info("navigating with search profile", "url", url, "profile", profile)

	// Extract domain for profile construction
	domain := url
	if idx := strings.Index(domain, "://"); idx != -1 {
		domain = domain[idx+3:]
	}
	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[:idx]
	}

	var referrer string
	switch strings.ToLower(profile) {
	case "google":
		referrer = buildGoogleReferrer(domain)
	case "bing":
		referrer = buildBingReferrer(domain)
	case "duckduckgo", "ddg":
		referrer = buildDuckDuckGoReferrer(domain)
	case "random":
		referrer = pickRandomSearchReferrer(domain)
	default:
		return nil, fmt.Errorf("unknown search profile: %s (use google, bing, duckduckgo, random)", profile)
	}

	// If the engine supports profile navigation, delegate to it
	if pn, ok := c.engine.(engine.ProfileNavigator); ok {
		if err := pn.NavigateWithReferrer(ctx, url, referrer); err != nil {
			return nil, fmt.Errorf("profile navigation failed: %w", err)
		}
		// After profile navigation, fetch the page content to return a Response
		return c.Navigate(ctx, url)
	}

	// Fallback: just use the referrer via the generic engine interface
	return c.NavigateWithReferrer(ctx, url, referrer)
}

// isCaptchaResponse returns true if the response contains a captcha/challenge.
func (c *Adaptive) isCaptchaResponse(resp *engine.Response) bool {
	if resp == nil {
		return false
	}
	// Use orchestrator's unified detector if available
	if c.orchestrator != nil {
		ud := challengefsm.NewUnifiedDetector()
		if ch := ud.Detect(resp); ch != nil {
			return true
		}
	}
	// Fallback: check headers and body
	return challengefsm.HasCaptchaHeader(resp.Headers)
}

// isCleanResponse returns true if the response doesn't contain a challenge.
func (c *Adaptive) isCleanResponse(resp *engine.Response) bool {
	if resp == nil {
		return false
	}
	return resp.Status >= 200 && resp.Status < 400 && !c.isCaptchaResponse(resp)
}

// isWAFResponse returns true if the response contains WAF/challenge markers.
// This replaces the engine-level WAF detection that was removed from
// stealth_engine.go; challenge detection now lives entirely in the client.
func isWAFResponse(resp *engine.Response) bool {
	if resp == nil {
		return false
	}
	flatHeaders := make(map[string]string, len(resp.Headers))
	for k, v := range resp.Headers {
		if len(v) > 0 {
			flatHeaders[strings.ToLower(k)] = v[0]
		}
	}
	waf := instrumentation.DetectChallenge(resp.Status, flatHeaders, resp.Body)
	return waf != instrumentation.WAFUnknown
}

// attemptCaptchaSolve tries to solve a detected captcha, using trace-replayed
// events when available, falling back to synthetic event generation.
func (c *Adaptive) attemptCaptchaSolve(ctx context.Context, targetURL string, resp *engine.Response) (*engine.Response, error) {
	if c.orchestrator == nil {
		return nil, fmt.Errorf("no challenge orchestrator configured")
	}

	// Generate trace-based events if trace library has recordings
	var traceEvents []challenge.CaptchaEvent
	if c.traceLibrary != nil && c.traceLibrary.Count() > 0 {
		rng := rand.New(rand.NewSource(time.Now().UnixNano()))
		// Try to find a matching trace for the challenge type
		ud := challengefsm.NewUnifiedDetector()
		if ch := ud.Detect(resp); ch != nil {
			challengeType := string(ch.Type)
			events, err := c.traceLibrary.GenerateFromTrace(challengeType, "", rng.Float64)
			if err == nil {
				traceEvents = events
				c.logger.Info("using trace-replayed events for captcha solve",
					"type", challengeType, "events", len(traceEvents))
			}
		}
	}

	// Use orchestrator with trace events injected
	solvedResp, err := c.orchestrator.HandleResponseWithTraceEvents(
		ctx, targetURL, resp, c.engine, c.options.Timeout, traceEvents,
	)
	if err != nil {
		return nil, err
	}
	if solvedResp != nil && solvedResp != resp {
		return solvedResp, nil
	}
	return nil, fmt.Errorf("captcha solve did not produce a clean response")
}

// WithTraceLibrary configures a trace data directory for replay-based captcha solving.
func WithTraceLibrary(dataDir string) Option {
	return func(c *Config) {
		c.TraceDataDir = dataDir
	}
}

// Response represents the result of a navigation.
type Response struct {
	Status   int
	Headers  map[string][]string
	Body     []byte
	FinalURL string
	Trace    engine.Trace
	Tree     *understand.SemanticTree

	// ChallengeSolved is true if an anti-bot challenge was detected and
	// successfully solved during this request.
	ChallengeSolved bool

	// Lazy-parsing fields for extraction methods.
	parseOnce sync.Once
	doc       *html.Node
	bodyStr   string
}

// AttachSemanticTree associates a pre-built semantic tree with this response,
// enabling extraction methods to delegate to the tree instead of regex.
func (r *Response) AttachSemanticTree(tree *understand.SemanticTree) {
	r.Tree = tree
}

// Mouse moves the mouse to the specified coordinates.
// When the underlying engine supports interaction, it delegates to the engine.
func (c *Adaptive) Mouse(x, y float64) error {
	_ = c.hooks.Execute(context.Background(), instrumentation.HookNames.OnMouseMove)
	c.behavTracker.RecordMouseMove(x, y)
	if ie, ok := c.engine.(engine.InteractiveEngine); ok {
		return ie.Mouse(x, y)
	}
	c.logger.Debug("mouse move (no interactive engine)", "x", x, "y", y)
	return nil
}

// Click performs a mouse click at coordinates.
// When the underlying engine supports interaction, it delegates to the engine.
func (c *Adaptive) Click(x, y float64) error {
	c.behavTracker.RecordMouseMove(x, y)
	if ie, ok := c.engine.(engine.InteractiveEngine); ok {
		return ie.Click(x, y)
	}
	c.logger.Debug("click (no interactive engine)", "x", x, "y", y)
	return nil
}

// ClickSelector clicks an element matching the CSS selector.
// Uses JavaScript to find and click the element. Requires a JS-capable engine.
func (c *Adaptive) ClickSelector(ctx context.Context, selector string) error {
	if !c.engine.Capabilities().JavaScript {
		return fmt.Errorf("click by selector requires JavaScript-capable engine")
	}

	clickScript := fmt.Sprintf(`
		(function() {
			var el = document.querySelector("%s");
			if (el) {
				el.click();
				return true;
			}
			return false;
		})()
	`, selector)

	_, err := c.engine.Do(ctx, &engine.Request{
		URL:             "about:blank",
		ScriptToExecute: clickScript,
		Timeout:         c.options.Timeout,
	})
	if err != nil {
		c.logger.Warn("click selector failed", "selector", selector, "error", err)
		return err
	}

	c.logger.Debug("clicked selector", "selector", selector)
	return nil
}

// Type simulates typing text.
// When the underlying engine supports interaction, it delegates to the engine.
func (c *Adaptive) Type(text string) error {
	_ = c.hooks.Execute(context.Background(), instrumentation.HookNames.OnType)
	c.behavTracker.RecordKeystroke()
	if ie, ok := c.engine.(engine.InteractiveEngine); ok {
		return ie.Type(text)
	}
	c.logger.Debug("type (no interactive engine)", "length", len(text))
	return nil
}

// Scroll scrolls the page.
// When the underlying engine supports interaction, it delegates to the engine.
func (c *Adaptive) Scroll(pixels float64) error {
	_ = c.hooks.Execute(context.Background(), instrumentation.HookNames.OnScroll)
	if ie, ok := c.engine.(engine.InteractiveEngine); ok {
		return ie.Scroll(pixels)
	}
	c.logger.Debug("scroll (no interactive engine)", "pixels", pixels)
	return nil
}

// BehavioralSnapshot returns the accumulated behavioral data from this session.
// Useful for training data collection and self-evaluation.
func (c *Adaptive) BehavioralSnapshot() *behavior.EventData {
	return c.behavTracker.Snapshot()
}

// ResetBehavioralTracker clears the accumulated behavioral data.
func (c *Adaptive) ResetBehavioralTracker() {
	c.behavTracker = NewBehavioralTracker()
}

// BrowserContext returns the browser allocator context if the underlying engine
// supports it. This allows external callers (e.g. the agent) to create
// persistent tabs inside the same browser instance so that cookies and session
// state are shared with the stealth client.
func (c *Adaptive) BrowserContext() (context.Context, bool) {
	if ae, ok := c.engine.(engine.AllocatorEngine); ok {
		return ae.Allocator(), true
	}
	return nil, false
}

// NewTab creates a new persistent tab inside the stealth browser.
// The caller is responsible for calling the returned cancel function.
// Cookies and session state from previous stealth navigations are shared.
func (c *Adaptive) NewTab() (context.Context, context.CancelFunc, bool) {
	if tc, ok := c.engine.(engine.TabCreator); ok {
		ctx, cancel := tc.NewTab()
		return ctx, cancel, true
	}
	return nil, nil, false
}

// Engine returns the underlying engine for advanced use cases.
func (c *Adaptive) Engine() engine.Engine {
	return c.ActiveEngine()
}

// ActiveEngine returns the waterfall engine if configured, otherwise the raw engine.
func (c *Adaptive) ActiveEngine() engine.Engine {
	if c.waterfall != nil {
		return c.waterfall
	}
	return c.engine
}

// Close closes the client and all associated resources.
func (c *Adaptive) Close() error {
	c.logger.Info("closing stealth client")
	_ = c.hooks.Execute(context.Background(), instrumentation.HookNames.OnBrowserClose)
	return c.engine.Close()
}

// EscalationMetrics returns a snapshot of escalation-related metrics.
func (c *Adaptive) EscalationMetrics() *EscalationMetricsSnapshot {
	snap := &EscalationMetricsSnapshot{}

	if c.waterfall != nil {
		wm := c.waterfall.Metrics()
		snap.WaterfallWins = wm.Wins
		snap.WaterfallErrors = wm.Errors
	}

	if c.tierTracker != nil {
		snap.TierStats = c.tierTracker.Stats()
	}

	if c.evasionFSM != nil {
		snap.FSMExhausted = c.evasionFSM.Exhausted()
		snap.FSMEscalationReason = c.evasionFSM.EscalationReason()
		snap.FSMSummary = c.evasionFSM.Summary()
	}

	return snap
}

// EscalationMetricsSnapshot is a read-only view of all escalation subsystem state.
type EscalationMetricsSnapshot struct {
	// Waterfall engine metrics
	WaterfallWins   map[string]int64 `json:"waterfall_wins,omitempty"`
	WaterfallErrors map[string]int64 `json:"waterfall_errors,omitempty"`

	// Per-domain proxy tier state
	TierStats map[string]pool.DomainTierSnapshot `json:"tier_stats,omitempty"`

	// Evasion FSM state
	FSMExhausted        bool   `json:"fsm_exhausted"`
	FSMEscalationReason string `json:"fsm_escalation_reason,omitempty"`
	FSMSummary          string `json:"fsm_summary,omitempty"`
}

// Orchestrator returns the challenge orchestrator, if configured.
func (c *Adaptive) Orchestrator() *challengefsm.ChallengeOrchestrator {
	return c.orchestrator
}

// registerSolvers registers all available solvers with the orchestrator registry.
// Solvers are registered in priority order: CF → CAPTCHA → DataDome.
func (c *Adaptive) registerSolvers(registry *challengefsm.SolverRegistry) {
	// 1. Cloudflare solver (wraps existing cfSolver)
	if c.cfSolver != nil {
		cfSolver := challengefsm.NewCloudflareFSMSolver(
			c.detectCFChallenge,
			c.solveCFChallenge,
		)
		registry.Register(cfSolver)
		c.logger.Info("registered cloudflare FSM solver")
	}

	// 2. Captcha solver (wraps existing captchaSolver)
	if c.captchaSolver != nil {
		captchaSolver := challengefsm.NewCaptchaFSMSolver(
			func(body []byte, headers map[string][]string) *challengefsm.CaptchaDetection {
				cr := c.captchaSolver.DetectCaptchaResponse(body, headers)
				if cr == nil {
					return nil
				}
				return &challengefsm.CaptchaDetection{
					ChallengeID:   cr.ChallengeID,
					Type:          cr.Type,
					CaptchaID:     cr.CaptchaID,
					ImageBase64:   cr.ImageBase64,
					ChallengeData: cr.ChallengeData,
				}
			},
			func(body []byte, headers map[string][]string) (*challengefsm.CaptchaSolveOutput, *challengefsm.CaptchaDetection, error) {
				result, cr, err := c.captchaSolver.SolveFromResponse(body, headers)
				if err != nil {
					return nil, nil, err
				}
				var out *challengefsm.CaptchaSolveOutput
				if result != nil {
					out = &challengefsm.CaptchaSolveOutput{
						Solution:    result.Solution,
						Confidence:  result.Confidence,
						SolveTimeMs: result.SolveTimeMs,
						Token:       result.Token,
					}
				}
				var det *challengefsm.CaptchaDetection
				if cr != nil {
					det = &challengefsm.CaptchaDetection{
						ChallengeID:   cr.ChallengeID,
						Type:          cr.Type,
						CaptchaID:     cr.CaptchaID,
						ImageBase64:   cr.ImageBase64,
						ChallengeData: cr.ChallengeData,
					}
				}
				return out, det, nil
			},
			func(baseURL string) (*challengefsm.ReCaptchaV2Output, error) {
				result, err := c.captchaSolver.SolveReCaptchaV2(baseURL)
				if err != nil {
					return nil, err
				}
				return &challengefsm.ReCaptchaV2Output{
					Token:           result.Token,
					BehavioralScore: result.BehavioralScore,
					Passed:          result.Passed,
					NeedChallenge:   result.NeedChallenge,
					SolveAttempts:   result.SolveAttempts,
					RefreshCount:    result.RefreshCount,
					TotalTimeMs:     result.TotalTimeMs,
				}, nil
			},
			c.captchaSolver.SubmitSolution,
			func(solveTimeMs int64, solution string) []challenge.CaptchaEvent {
				return c.captchaSolver.GenerateHumanEvents(solveTimeMs, HumanEventOpts{Solution: solution})
			},
			c.captchaSolver.LastToken,
			c.engine,
		)
		registry.Register(captchaSolver)
		c.logger.Info("registered captcha FSM solver")
	}

	// 3. DataDome solver
	dataDomeSolver := challengefsm.NewDataDomeFSMSolver()
	registry.Register(dataDomeSolver)
	c.logger.Info("registered datadome FSM solver")

	// 4. Dynamic solver (catch-all, registered last for lowest priority)
	// Uses challenge classification + trace replay for unknown challenge types.
	if c.traceLibrary != nil && c.traceLibrary.Count() > 0 {
		dynSolver := challenge.NewDynamicSolver(c.traceLibrary, c.config.TraceDataDir)
		dynamicFSM := challengefsm.NewDynamicFSMSolver(dynSolver, c.engine)
		registry.Register(dynamicFSM)
		c.logger.Info("registered dynamic FSM solver", "traces", c.traceLibrary.Count())
	}
}

// Hooks returns the hook registry for custom behavior.
func (c *Adaptive) Hooks() *instrumentation.HookRegistry {
	return c.hooks
}

// Tracer returns the tracer for request tracing.
func (c *Adaptive) Tracer() *instrumentation.Tracer {
	return c.tracer
}

// FSM returns the request state machine.
func (c *Adaptive) FSM() *instrumentation.FSM {
	return c.fsm
}

// Logger returns the logger.
func (c *Adaptive) Logger() *instrumentation.Logger {
	return c.logger
}

// Config returns the client's configuration.
func (c *Adaptive) Config() *Config {
	return c.config
}

// EvasionFSM returns the adaptive evasion FSM, or nil if not initialized.
func (c *Adaptive) EvasionFSM() *behavior.AdaptiveEvasionFSM {
	return c.evasionFSM
}

// NewAdaptiveFromEngines builds a minimal Adaptive wrapping the provided engine
// and optional waterfall. Intended for unit tests that need direct engine/waterfall
// injection without going through the full constructor.
func NewAdaptiveFromEngines(eng engine.Engine, wfall *wf.Waterfall) *Adaptive {
	logger, _ := instrumentation.NewLogger(&instrumentation.Config{LogLevel: "error"})
	return &Adaptive{
		engine:    eng,
		waterfall: wfall,
		config:    DefaultConfig(),
		options:   &Options{Timeout: 30 * time.Second},
		logger:    logger,
		tracer:    instrumentation.NewTracer(),
		hooks:     instrumentation.DefaultHookRegistry(),
		fsm:       instrumentation.NewRequestFSM(),
	}
}

// Solver returns a challenge solver (requires API key configuration).
func (c *Adaptive) Solver() (external_service.Solver, error) {
	if c.config.Challenge.SolverAPIKey == "" {
		return nil, fmt.Errorf("solver API key not configured")
	}
	return external_service.NewSolver(external_service.SolverConfig{
		Provider: c.config.Challenge.SolverType,
		APIKey:   c.config.Challenge.SolverAPIKey,
	})
}

// Option is a functional option for configuring the client.
type Option func(*Config)

// WithEngine sets the browser engine.
func WithEngine(name string) Option {
	return func(c *Config) {
		c.EngineName = name
	}
}

// WithHeadless sets headless mode.
func WithHeadless(headless bool) Option {
	return func(c *Config) {
		c.Headless = headless
	}
}

// WithProxy sets the proxy server.
func WithProxy(proxy string) Option {
	return func(c *Config) {
		c.Proxy = proxy
	}
}

// WithStealth enables stealth mode.
func WithStealth(enabled bool) Option {
	return func(c *Config) {
		if c.Stealth == nil {
			c.Stealth = engine.DefaultStealthConfigFor(c.EngineName)
		}
		if c.Stealth != nil {
			c.Stealth.SetEnabled(enabled)
		}
	}
}

// WithChallengeSolver configures challenge solving.
func WithChallengeSolver(provider, apiKey string) Option {
	return func(c *Config) {
		c.Challenge.AutoSolve = true
		c.Challenge.SolverType = provider
		c.Challenge.SolverAPIKey = apiKey
	}
}

// WithSession enables session management.
func WithSession(profileDir, name string) Option {
	return func(c *Config) {
		c.Session.Enabled = true
		c.Session.ProfileDir = profileDir
		c.Session.SessionName = name
	}
}

// WithEvasionFSM enables the adaptive evasion FSM for browser mode escalation.
// This is the default behavior — call this only if you previously disabled it.
func WithEvasionFSM() Option {
	return func(c *Config) {
		c.EvasionFSMDisabled = false
	}
}

// WithoutEvasionFSM disables the adaptive evasion FSM.
func WithoutEvasionFSM() Option {
	return func(c *Config) {
		c.EvasionFSMDisabled = true
	}
}

// WithLogging configures logging.
func WithLogging(level string, json bool) Option {
	return func(c *Config) {
		if c.Instrumentation == nil {
			c.Instrumentation = &InstrumentationConfig{}
		}
		c.Instrumentation.LogLevel = level
		c.Instrumentation.EnableJSONLog = json
	}
}

// WithTracing enables request tracing.
func WithTracing(enabled bool) Option {
	return func(c *Config) {
		if c.Instrumentation == nil {
			c.Instrumentation = &InstrumentationConfig{}
		}
		c.Instrumentation.EnableTracing = enabled
	}
}

// detectCFChallenge checks if the response is a Cloudflare challenge page.
func (c *Adaptive) detectCFChallenge(resp *engine.Response) *challenge.CloudflareChallenge {
	httpHeaders := make(http.Header)
	for k, vals := range resp.Headers {
		for _, v := range vals {
			httpHeaders.Add(k, v)
		}
	}
	return challenge.DetectChallenge(resp.Status, httpHeaders, resp.Body)
}

// solveCFChallenge attempts to solve a detected CF challenge and retry the request.
func (c *Adaptive) solveCFChallenge(ctx context.Context, targetURL string, resp *engine.Response, ch *challenge.CloudflareChallenge) (*engine.Response, error) {
	switch ch.Type {
	case challenge.ChallengeJS, challenge.ChallengeManaged:
		// Extract PoW params from the challenge page body
		if ch.PoWParams == nil {
			return nil, fmt.Errorf("no PoW params in challenge page")
		}

		// Solve the PoW
		solution, err := c.cfSolver.solvePoW(ch.PoWParams.Prefix, ch.PoWParams.Difficulty)
		if err != nil {
			return nil, fmt.Errorf("PoW solve failed: %w", err)
		}

		// For managed challenges, also generate fingerprint + behavioral events
		var fp *challenge.FingerprintPayload
		var events []challenge.CaptchaEvent
		if ch.Type == challenge.ChallengeManaged {
			fp = c.cfSolver.generateFingerprint()
			events = c.cfSolver.eventGen.GenerateHumanEvents(5000)
		}

		// Human-like delay before submitting
		//nolint:gosec
		time.Sleep(time.Duration(1500+rand.Intn(3000)) * time.Millisecond)

		// Submit solution to the challenge API endpoint
		baseURL := deriveBaseURL(targetURL)
		clearanceCookie, err := c.cfSolver.submitSolution(baseURL, ch, solution, fp, events)
		if err != nil {
			return nil, err
		}

		// Retry the original request with the clearance cookie
		retryReq := &engine.Request{
			URL:     targetURL,
			Timeout: c.options.Timeout,
			ExtraHeaders: map[string]string{
				"Cookie": fmt.Sprintf("cf_clearance=%s", clearanceCookie.Value),
			},
		}
		return c.engine.Do(ctx, retryReq)

	case challenge.ChallengeBlocked:
		return nil, fmt.Errorf("hard blocked by Cloudflare (403, no challenge to solve)")

	default:
		return nil, fmt.Errorf("unsupported CF challenge type: %s", ch.Type)
	}
}

// ============================================================================
// Search profile referrer builders (engine-agnostic)
// ============================================================================

func buildGoogleReferrer(domain string) string {
	queries := []string{
		fmt.Sprintf("https://www.google.com/search?q=%s&source=hp&ei=abc", domain),
		fmt.Sprintf("https://www.google.com/search?q=%s+reviews&oq=%s+reviews", domain, domain),
		fmt.Sprintf("https://www.google.com/search?q=site%%3A%s", domain),
		fmt.Sprintf("https://www.google.com/search?q=%s+login&source=lmns", domain),
	}
	return queries[rand.Intn(len(queries))]
}

func buildBingReferrer(domain string) string {
	queries := []string{
		fmt.Sprintf("https://www.bing.com/search?q=%s&form=QBLH", domain),
		fmt.Sprintf("https://www.bing.com/search?q=%s+official&qs=n", domain),
		fmt.Sprintf("https://www.bing.com/search?q=site%%3A%s&form=QBRE", domain),
	}
	return queries[rand.Intn(len(queries))]
}

func buildDuckDuckGoReferrer(domain string) string {
	queries := []string{
		fmt.Sprintf("https://duckduckgo.com/?q=%s&ia=web", domain),
		fmt.Sprintf("https://duckduckgo.com/?q=%s+reviews&ia=web", domain),
		fmt.Sprintf("https://duckduckgo.com/?q=site%%3A%s&ia=web", domain),
	}
	return queries[rand.Intn(len(queries))]
}

func pickRandomSearchReferrer(domain string) string {
	builders := []func(string) string{
		buildGoogleReferrer,
		buildBingReferrer,
		buildDuckDuckGoReferrer,
	}
	return builders[rand.Intn(len(builders))](domain)
}

// DefaultConfig returns the default configuration.
func DefaultConfig() *Config {
	return &Config{
		EngineName: "chromium-stealth",
		Headless:   true,
		Challenge: &ChallengeConfig{
			AutoDetect: true,
			AutoSolve:  false,
		},
		Session: &SessionConfig{
			Enabled: false,
		},
		Instrumentation: &InstrumentationConfig{
			LogLevel:      "info",
			EnableTracing: true,
		},
	}
}
