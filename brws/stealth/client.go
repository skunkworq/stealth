package stealth

import (
	"context"
	"fmt"
	"time"

	"github.com/skunkworq/stealth/brws/browser/engine"
	wf "github.com/skunkworq/stealth/brws/browser/engine/meta/waterfall"
	"github.com/skunkworq/stealth/brws/core/config"
	"github.com/skunkworq/stealth/brws/core/constants"
	"github.com/skunkworq/stealth/brws/core/instrumentation"
	"github.com/skunkworq/stealth/brws/ml"
	pool "github.com/skunkworq/stealth/brws/network/proxy/connpool"
	"github.com/skunkworq/stealth/brws/stealth/behavior"
	"github.com/skunkworq/stealth/brws/stealth/behavior/tracker"
	"github.com/skunkworq/stealth/brws/stealth/captcha/external_service"
	"github.com/skunkworq/stealth/brws/stealth/challenge"
	challengefsm "github.com/skunkworq/stealth/brws/stealth/challenge/fsm"
	"github.com/skunkworq/stealth/brws/stealth/profile/session"
)

// Adaptive is the main entry point for the stealth browser automation library.
type Adaptive struct {
	engine        engine.Engine
	config        *Config
	options       *Options
	sessionMgr    *session.Manager
	policyLoader  *ml.PolicyLoader
	behavTracker  *tracker.BehavioralTracker
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

// SessionConfig is the canonical session configuration from core/config.
type SessionConfig = config.SessionConfig

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

// NewAdaptive creates an Adaptive stealth client with default configuration.
func NewAdaptive(opts ...Option) (*Adaptive, error) {
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(cfg)
	}
	return NewAdaptiveWithConfig(cfg)
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
		var err error
		sessMgr, err = session.NewManager(cfg.Session.ProfileDir)
		if err != nil {
			logger.Warn("failed to initialize session manager, sessions disabled", "path", cfg.Session.ProfileDir, "error", err)
		}
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
			Timeout:    constants.DefaultTimeout,
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
		options:           &Options{Timeout: constants.DefaultTimeout},
		config:            cfg,
		sessionMgr:        sessMgr,
		policyLoader:      policyLoader,
		behavTracker:      tracker.New(),
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

// newAdaptiveFromEngines builds a minimal Adaptive wrapping the provided engine
// and optional waterfall for tests that need direct engine/waterfall injection.
func newAdaptiveFromEngines(eng engine.Engine, wfall *wf.Waterfall) *Adaptive {
	logger := instrumentation.ForLevel("error")
	return &Adaptive{
		engine:    eng,
		waterfall: wfall,
		config:    DefaultConfig(),
		options:   &Options{Timeout: constants.DefaultTimeout},
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

// WithTraceLibrary configures a trace data directory for replay-based captcha solving.
func WithTraceLibrary(dataDir string) Option {
	return func(c *Config) {
		c.TraceDataDir = dataDir
	}
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
