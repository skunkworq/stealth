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

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/semantic"
	"github.com/skunkworq/stealth/brws/behavior"
	"github.com/skunkworq/stealth/brws/challenge"
	"github.com/skunkworq/stealth/brws/engine"
	"github.com/skunkworq/stealth/brws/instrumentation"
	"github.com/skunkworq/stealth/brws/ml"
	"github.com/skunkworq/stealth/brws/session"
	"github.com/skunkworq/stealth/brws/solver"
	"github.com/skunkworq/stealth/brws/stealth/challengefsm"
)

// Client is the main entry point for the stealth browser automation library.
type Client struct {
	engine        engine.Engine
	config        *Config
	options       *Options
	sessionMgr    *session.Manager
	policyLoader  *ml.PolicyLoader
	behavTracker  *BehavioralTracker
	captchaSolver *CaptchaSolver
	cfSolver      *CloudflareSolverClient

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

	Stealth         *StealthConfig
	Behavior        *BehaviorConfig
	Challenge       *ChallengeConfig
	Session         *SessionConfig
	Instrumentation *InstrumentationConfig
}

// StealthConfig configures stealth capabilities.
type StealthConfig struct {
	Enabled         bool
	RemoveWebDriver bool
	CanvasNoise     bool
	WebGLSpoof      bool
	ClientHints     bool
	FakeScreen      bool
	FakeTimezone    bool
	RandomUserAgent bool
	UserAgent       string
	ViewportWidth   int
	ViewportHeight  int

	// Phase 14 & 16: Dynamic RL Mutable Heuristics
	HardwareSync    bool
	NetworkSync     bool
	PluginsSync     bool
	GeometrySync    bool
	VideoSync       bool
	PermissionsSync bool
	TimezoneSync    bool
}

// BehaviorConfig configures human behavior simulation.
type BehaviorConfig struct {
	HumanizeMouse  bool
	RandomDelays   bool
	TypingSpeedMin time.Duration
	TypingSpeedMax time.Duration
	ScrollBehavior string
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
func New(opts ...Option) (*Client, error) {
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(cfg)
	}
	return NewWithConfig(cfg)
}

// NewWithConfig creates a new stealth client with custom configuration.
func NewWithConfig(cfg *Config) (*Client, error) {
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

	eng, err := engine.New(cfg.EngineName, engine.Options{
		Headless:         cfg.Headless,
		Proxy:            cfg.Proxy,
		ProfileDir:       cfg.Session.ProfileDir,
		StealthConfigRaw: cfg.Stealth,
	})
	if err != nil {
		return nil, fmt.Errorf("create engine: %w", err)
	}

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

	c := &Client{
		engine:        eng,
		options:       &Options{Timeout: 30 * time.Second},
		config:        cfg,
		sessionMgr:    sessMgr,
		policyLoader:  policyLoader,
		behavTracker:  NewBehavioralTracker(),
		captchaSolver: captchaSolver,
		cfSolver:      cfSolver,
		logger:        logger,
		tracer:        tracer,
		hooks:         hooks,
		fsm:           fsm,
		orchestrator:  orchestrator,
	}

	// Register solvers with the orchestrator (need client methods bound)
	if orchestrator != nil {
		c.registerSolvers(orchestrator.Registry())
	}

	return c, nil
}

// Navigate performs a GET request to the specified URL.
func (c *Client) Navigate(ctx context.Context, url string) (*Response, error) {
	ctx, span := c.tracer.StartSpan(ctx, "navigate", instrumentation.SpanKindRequest)

	span.SetAttribute("url", url)
	defer span.End()

	c.logger.Info("navigating", "url", url)

	_ = c.hooks.Execute(ctx, instrumentation.HookNames.OnRequestStart)
	c.fsm.ResetState(instrumentation.RequestStates.Idle)
	_ = c.fsm.Transition(ctx, instrumentation.RequestEvents.Start)

	var resp *engine.Response
	var err error
	maxRetries := 3

	for attempt := 1; attempt <= maxRetries; attempt++ {
		resp, err = c.engine.Do(ctx, &engine.Request{
			URL:     url,
			Timeout: c.options.Timeout,
		})
		if err != nil {
			if strings.Contains(err.Error(), "WAF Challenge Detected") && attempt < maxRetries {
				c.logger.Warn("WAF Blocked. Adapting Stealth Config and Retrying", "attempt", attempt, "error", err)

				// FSM State Transition
				_ = c.fsm.Transition(ctx, instrumentation.RequestEvents.Retry)

				// RL-driven stealth adaptation or hardcoded fallback
				if c.policyLoader != nil {
					stateVec := BuildStateVector(extractAnomalies(err), nil, nil)
					actionIdx, qValue := c.policyLoader.SelectAction(stateVec)
					applied, field := ApplyAction(c.config.Stealth, actionIdx)
					c.logger.Info("RL policy action", "action", field, "q_value", qValue, "applied", applied)
				} else {
					c.config.Stealth.CanvasNoise = true
					c.config.Stealth.WebGLSpoof = true
					c.config.Stealth.ClientHints = true
				}
				// We wait randomly to let the previous context clear gracefully
				time.Sleep(time.Duration(500+attempt*1500) * time.Millisecond)

				continue
			}

			span.SetAttribute("error", err.Error())
			c.logger.Error("navigation failed", "url", url, "error", err)
			return nil, err
		}

		// Unblocked response received
		break
	}

	// CHALLENGE HANDLING: delegate entirely to orchestrator
	if c.orchestrator != nil && c.config.Challenge.AutoSolve {
		_ = c.fsm.Transition(ctx, instrumentation.RequestEvents.ChallengeDetected)
		solvedResp, _ := c.orchestrator.HandleResponse(ctx, url, resp, c.engine, c.options.Timeout)
		if solvedResp != nil {
			resp = solvedResp
			span.AddEvent("challenge_solved", nil)
		}
	} else if c.config.Challenge.AutoDetect {
		// Fallback to generic challenge detection (no orchestrator)
		detector := challenge.NewDetector()
		if ch := detector.Detect(resp.Body, resp.Headers); ch != nil {
			span.AddEvent("challenge_detected", map[string]interface{}{"type": string(ch.Type)})
			c.logger.Info("challenge detected", "type", ch.Type)
		}
	}

	span.SetAttribute("status", resp.Status)
	span.SetAttribute("body_size", len(resp.Body))
	_ = c.fsm.Transition(ctx, instrumentation.RequestEvents.Complete)
	_ = c.hooks.Execute(ctx, instrumentation.HookNames.OnRequestEnd)

	c.logger.Info("navigation complete", "url", url, "status", resp.Status, "size", len(resp.Body))

	return &Response{
		Status:   resp.Status,
		Headers:  resp.Headers,
		Body:     resp.Body,
		FinalURL: resp.FinalURL,
		Trace:    resp.Trace,
	}, nil
}

// Response represents the result of a navigation.
type Response struct {
	Status   int
	Headers  map[string][]string
	Body     []byte
	FinalURL string
	Trace    engine.Trace
	Tree     *semantic.SemanticTree

	// Lazy-parsing fields for extraction methods.
	parseOnce sync.Once
	doc       *html.Node
	bodyStr   string
}

// AttachSemanticTree associates a pre-built semantic tree with this response,
// enabling extraction methods to delegate to the tree instead of regex.
func (r *Response) AttachSemanticTree(tree *semantic.SemanticTree) {
	r.Tree = tree
}

// Mouse moves the mouse to the specified coordinates.
func (c *Client) Mouse(x, y float64) error {
	_ = c.hooks.Execute(context.Background(), instrumentation.HookNames.OnMouseMove)
	c.behavTracker.RecordMouseMove(x, y)
	c.logger.Debug("mouse move", "x", x, "y", y)
	return nil
}

// Click performs a mouse click at coordinates.
func (c *Client) Click(x, y float64) error {
	sim := behavior.NewMouseSimulator(0)
	_ = sim.ClickAt(x, y)
	c.behavTracker.RecordMouseMove(x, y)
	c.logger.Debug("click", "x", x, "y", y)
	return nil
}

// ClickSelector clicks an element matching the CSS selector.
// Uses JavaScript to find and click the element. Requires a JS-capable engine.
func (c *Client) ClickSelector(ctx context.Context, selector string) error {
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
func (c *Client) Type(text string) error {
	_ = c.hooks.Execute(context.Background(), instrumentation.HookNames.OnType)
	c.behavTracker.RecordKeystroke()
	c.logger.Debug("type", "length", len(text))
	return nil
}

// Scroll scrolls the page.
func (c *Client) Scroll(pixels float64) error {
	_ = c.hooks.Execute(context.Background(), instrumentation.HookNames.OnScroll)
	c.logger.Debug("scroll", "pixels", pixels)
	return nil
}

// BehavioralSnapshot returns the accumulated behavioral data from this session.
// Useful for training data collection and self-evaluation.
func (c *Client) BehavioralSnapshot() *behavior.EventData {
	return c.behavTracker.Snapshot()
}

// ResetBehavioralTracker clears the accumulated behavioral data.
func (c *Client) ResetBehavioralTracker() {
	c.behavTracker = NewBehavioralTracker()
}

// Close closes the client and all associated resources.
func (c *Client) Close() error {
	c.logger.Info("closing stealth client")
	_ = c.hooks.Execute(context.Background(), instrumentation.HookNames.OnBrowserClose)
	return c.engine.Close()
}

// Orchestrator returns the challenge orchestrator, if configured.
func (c *Client) Orchestrator() *challengefsm.ChallengeOrchestrator {
	return c.orchestrator
}

// registerSolvers registers all available solvers with the orchestrator registry.
// Solvers are registered in priority order: CF → CAPTCHA → DataDome.
func (c *Client) registerSolvers(registry *challengefsm.SolverRegistry) {
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
			func(solveTimeMs int64, solution string) []adversarial.CaptchaEvent {
				return c.captchaSolver.GenerateHumanEvents(solveTimeMs, HumanEventOpts{Solution: solution})
			},
			c.captchaSolver.LastToken,
			c.engine,
		)
		registry.Register(captchaSolver)
		c.logger.Info("registered captcha FSM solver")
	}

	// 3. DataDome solver (new)
	dataDomeSolver := challengefsm.NewDataDomeFSMSolver()
	registry.Register(dataDomeSolver)
	c.logger.Info("registered datadome FSM solver")
}

// Hooks returns the hook registry for custom behavior.
func (c *Client) Hooks() *instrumentation.HookRegistry {
	return c.hooks
}

// Tracer returns the tracer for request tracing.
func (c *Client) Tracer() *instrumentation.Tracer {
	return c.tracer
}

// FSM returns the request state machine.
func (c *Client) FSM() *instrumentation.FSM {
	return c.fsm
}

// Logger returns the logger.
func (c *Client) Logger() *instrumentation.Logger {
	return c.logger
}

// Solver returns a challenge solver (requires API key configuration).
func (c *Client) Solver() (solver.Solver, error) {
	if c.config.Challenge.SolverAPIKey == "" {
		return nil, fmt.Errorf("solver API key not configured")
	}
	return solver.NewSolver(solver.SolverConfig{
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
		c.Stealth.Enabled = enabled
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
func (c *Client) detectCFChallenge(resp *engine.Response) *adversarial.CloudflareChallenge {
	httpHeaders := make(http.Header)
	for k, vals := range resp.Headers {
		for _, v := range vals {
			httpHeaders.Add(k, v)
		}
	}
	return adversarial.DetectChallenge(resp.Status, httpHeaders, resp.Body)
}

// solveCFChallenge attempts to solve a detected CF challenge and retry the request.
func (c *Client) solveCFChallenge(ctx context.Context, targetURL string, resp *engine.Response, ch *adversarial.CloudflareChallenge) (*engine.Response, error) {
	switch ch.Type {
	case adversarial.ChallengeJS, adversarial.ChallengeManaged:
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
		var fp *adversarial.FingerprintPayload
		var events []adversarial.CaptchaEvent
		if ch.Type == adversarial.ChallengeManaged {
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

	case adversarial.ChallengeBlocked:
		return nil, fmt.Errorf("hard blocked by Cloudflare (403, no challenge to solve)")

	default:
		return nil, fmt.Errorf("unsupported CF challenge type: %s", ch.Type)
	}
}

// DefaultConfig returns the default configuration.
func DefaultConfig() *Config {
	return &Config{
		EngineName: "chromium-stealth",
		Headless:   true,
		Stealth: &StealthConfig{
			Enabled:         true,
			RemoveWebDriver: true,
			CanvasNoise:     true,
			WebGLSpoof:      true,
			ClientHints:     true,
			FakeScreen:      true,
			RandomUserAgent: true,
			ViewportWidth:   1920,
			ViewportHeight:  1080,
		},
		Behavior: &BehaviorConfig{
			HumanizeMouse:  true,
			RandomDelays:   true,
			TypingSpeedMin: 50 * time.Millisecond,
			TypingSpeedMax: 150 * time.Millisecond,
		},
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
