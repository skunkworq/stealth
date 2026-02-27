// Package stealth provides a high-level API for stealth browser automation.
package stealth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/stealth/brwslab/brws/behavior"
	"github.com/stealth/brwslab/brws/challenge"
	"github.com/stealth/brwslab/brws/engine"
	"github.com/stealth/brwslab/brws/instrumentation"
	"github.com/stealth/brwslab/brws/session"
	"github.com/stealth/brwslab/brws/solver"
)

// Client is the main entry point for the stealth browser automation library.
type Client struct {
	engine     engine.Engine
	config     *Config
	options    *Options
	sessionMgr *session.Manager

	logger *instrumentation.Logger
	tracer *instrumentation.Tracer
	hooks  *instrumentation.HookRegistry
	fsm    *instrumentation.FSM
}

// Config holds configuration for the stealth client.
type Config struct {
	EngineName string
	Headless   bool
	Proxy      string

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
	AutoDetect   bool
	AutoSolve    bool
	SolverAPIKey string
	SolverType   string
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
		Headless:   cfg.Headless,
		Proxy:      cfg.Proxy,
		ProfileDir: cfg.Session.ProfileDir,
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

	logger.Info("stealth client initialized")

	return &Client{
		engine:     eng,
		config:     cfg,
		sessionMgr: sessMgr,
		logger:     logger,
		tracer:     tracer,
		hooks:      hooks,
		fsm:        fsm,
	}, nil
}

// Navigate performs a GET request to the specified URL.
func (c *Client) Navigate(ctx context.Context, url string) (*Response, error) {
	ctx, span := c.tracer.StartSpan(ctx, "navigate", instrumentation.SpanKindRequest)
	span.SetAttribute("url", url)
	defer span.End()

	c.logger.Info("navigating", "url", url)

	_ = c.hooks.Execute(ctx, instrumentation.HookNames.OnRequestStart)
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

				// Mutate the stealth configuration specifically to become more adversarial
				// Example: force max webGL spoofing, max canvas noise, rotate completely new UA
				c.config.Stealth.CanvasNoise = true
				c.config.Stealth.WebGLSpoof = true
				c.config.Stealth.ClientHints = true
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

	if c.config.Challenge.AutoDetect {
		detector := challenge.NewDetector()
		if ch := detector.Detect(resp.Body, resp.Headers); ch != nil {
			span.AddEvent("challenge_detected", map[string]interface{}{"type": string(ch.Type)})
			c.logger.Info("challenge detected", "type", ch.Type)

			if c.config.Challenge.AutoSolve {
				_ = c.fsm.Transition(ctx, instrumentation.RequestEvents.ChallengeDetected)
			}
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
}

// Mouse moves the mouse to the specified coordinates.
func (c *Client) Mouse(x, y float64) error {
	_ = c.hooks.Execute(context.Background(), instrumentation.HookNames.OnMouseMove)
	c.logger.Debug("mouse move", "x", x, "y", y)
	return nil
}

// Click performs a mouse click.
func (c *Client) Click(x, y float64) error {
	sim := behavior.NewMouseSimulator(0)
	_ = sim.ClickAt(x, y)
	c.logger.Debug("click", "x", x, "y", y)
	return nil
}

// Type simulates typing text.
func (c *Client) Type(text string) error {
	_ = c.hooks.Execute(context.Background(), instrumentation.HookNames.OnType)
	c.logger.Debug("type", "length", len(text))
	return nil
}

// Scroll scrolls the page.
func (c *Client) Scroll(pixels float64) error {
	_ = c.hooks.Execute(context.Background(), instrumentation.HookNames.OnScroll)
	c.logger.Debug("scroll", "pixels", pixels)
	return nil
}

// Close closes the client and all associated resources.
func (c *Client) Close() error {
	c.logger.Info("closing stealth client")
	_ = c.hooks.Execute(context.Background(), instrumentation.HookNames.OnBrowserClose)
	return c.engine.Close()
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
