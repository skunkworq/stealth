// Package chromium provides a stealth-enhanced Chromium engine.
//
//nolint:gosec // G404: math/rand used intentionally for non-cryptographic jitter/randomization
package chromium

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/skunkworq/stealth/brws/behavior"
	"github.com/skunkworq/stealth/brws/engine"
	"github.com/skunkworq/stealth/brws/instrumentation"
	"github.com/skunkworq/stealth/brws/types"
)

func init() {
	engine.Register("chromium-stealth", NewStealth)
}

// StealthEngine extends Chromium with advanced anti-detection capabilities
type StealthEngine struct {
	allocCtx    context.Context
	allocCancel context.CancelFunc
	config      *StealthConfig
	fingerprint *types.CompleteFingerprint
	stealthOpts StealthOptions
	browserOpts BrowserOptions

	// Instrumentation
	logger *instrumentation.Logger
	tracer *instrumentation.Tracer
	hooks  *instrumentation.HookRegistry
	fsm    *instrumentation.FSM
}

// BrowserOptions contains browser launch options
type BrowserOptions struct {
	// Chrome executable path
	ExecutablePath string

	// Proxy server (e.g., "http://proxy:8080")
	Proxy string

	// Profile directory for persistent sessions
	ProfileDir string

	// User data dir
	UserDataDir string

	// Additional Chrome arguments
	ExtraArgs []string

	// Disable headless mode (show browser window)
	Headless bool
}

// StealthOptions contains additional options for stealth mode
type StealthOptions struct {
	// Enable stealth script injection
	EnableStealth bool

	// Enable human-like mouse movements
	HumanizeMouse bool

	// Enable random delays between actions
	RandomDelays bool

	// Enable age gate handling
	HandleAgeGate bool

	// Enable session warming (visit homepage first)
	SessionWarming bool

	// Custom viewport size
	ViewportWidth  int
	ViewportHeight int

	// Wait for network idle after navigation
	WaitNetworkIdle bool

	// Network idle timeout
	NetworkIdleTimeout time.Duration
}

// DefaultStealthOptions returns default stealth options
func DefaultStealthOptions() StealthOptions {
	return StealthOptions{
		EnableStealth:      true,
		HumanizeMouse:      true,
		RandomDelays:       true,
		HandleAgeGate:      false,
		SessionWarming:     false,
		ViewportWidth:      1920,
		ViewportHeight:     1080,
		WaitNetworkIdle:    true,
		NetworkIdleTimeout: 3 * time.Second,
	}
}

// DefaultBrowserOptions returns default browser options
func DefaultBrowserOptions() BrowserOptions {
	return BrowserOptions{
		Headless: true,
	}
}

// NewStealth creates a new stealth-enhanced Chromium engine
func NewStealth(opts engine.Options) (engine.Engine, error) {
	return NewStealthWithFingerprint(opts, nil)
}

// NewStealthWithFingerprint creates an engine tightly bound to a specific captured fingerprint
func NewStealthWithFingerprint(opts engine.Options, fp *types.CompleteFingerprint) (engine.Engine, error) {
	log := instrumentation.Named("chromium-stealth")
	log.Info("initializing stealth engine")

	// Build allocator options with stealth flags
	allocOpts := buildStealthAllocatorOptions(opts)

	if opts.ProfileDir != "" {
		allocOpts = append(allocOpts, chromedp.UserDataDir(opts.ProfileDir))
	}

	if opts.ExecutablePath != "" {
		allocOpts = append(allocOpts, chromedp.ExecPath(opts.ExecutablePath))
	}

	if opts.Proxy != "" {
		allocOpts = append(allocOpts, chromedp.ProxyServer(opts.Proxy))
	}

	var stealthCfg *StealthConfig
	if fp != nil {
		stealthCfg = StealthConfigFromFingerprint(fp)
		allocOpts = append(allocOpts, chromedp.UserAgent(fp.HTTP.UserAgent))
	} else {
		stealthCfg = DefaultStealthConfig()
		allocOpts = append(allocOpts, chromedp.UserAgent(RandomUserAgent()))
	}

	// Dynamically map advanced AI Spoofer properties if injected from Proxy Client (train_shield_sword)
	if opts.StealthConfigRaw != nil {
		if rawBytes, err := json.Marshal(opts.StealthConfigRaw); err == nil {
			_ = json.Unmarshal(rawBytes, &stealthCfg)
		}
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), allocOpts...)

	// Initialize instrumentation
	tracer := instrumentation.NewTracer()
	hooks := instrumentation.DefaultHookRegistry()
	fsm := instrumentation.NewRequestFSM()
	fsm.SetTransitionFunc(func(_ context.Context, from, to instrumentation.State, event instrumentation.Event) error {
		log.Debug("FSM transition", "from", from, "to", to, "event", event)
		return nil
	})

	log.Info("stealth engine initialized")

	return &StealthEngine{
		allocCtx:    allocCtx,
		allocCancel: allocCancel,
		config:      stealthCfg,
		fingerprint: fp,
		stealthOpts: DefaultStealthOptions(),
		browserOpts: DefaultBrowserOptions(),
		logger:      log,
		tracer:      tracer,
		hooks:       hooks,
		fsm:         fsm,
	}, nil
}

func buildStealthAllocatorOptions(opts engine.Options) []chromedp.ExecAllocatorOption {
	allocOpts := []chromedp.ExecAllocatorOption{
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.Flag("headless", opts.Headless),
		chromedp.DisableGPU,

		// Stealth-specific flags (nodriver-style)
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
		chromedp.Flag("disable-infobars", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-setuid-sandbox", true),
		chromedp.Flag("disable-accelerated-2d-canvas", true),
		chromedp.Flag("disable-accelerated-jpeg-decoding", true),
		chromedp.Flag("disable-accelerated-mjpeg-decode", true),
		chromedp.Flag("disable-accelerated-video-decode", true),
		chromedp.Flag("disable-app-list-dismiss-on-blur", true),
		chromedp.Flag("disable-apps-in-app-list", true),
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("disable-breakpad", true),
		chromedp.Flag("disable-checker-imaging", true),
		chromedp.Flag("disable-component-extensions-with-background-pages", true),
		chromedp.Flag("disable-default-apps", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-features", "TranslateUI,BlinkGenPropertyTrees,InterestFeedContentSuggestions,MediaRouter,OptimizationHints"),
		chromedp.Flag("disable-hang-monitor", true),
		chromedp.Flag("disable-ipc-flooding-protection", true),
		chromedp.Flag("disable-notifications", true),
		chromedp.Flag("disable-popup-blocking", true),
		chromedp.Flag("disable-prompt-on-repost", true),
		chromedp.Flag("disable-renderer-backgrounding", true),
		chromedp.Flag("force-color-profile", "srgb"),
		chromedp.Flag("metrics-recording-only", true),
		chromedp.Flag("safebrowsing-disable-auto-update", true),
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("disable-translate", true),

		// Random window size with slight variation
		chromedp.WindowSize(
			1920+rand.Intn(100)-50,
			1080+rand.Intn(100)-50,
		),

		// Allow remote origins
		chromedp.Flag("remote-allow-origins", "*"),

		// Disable password store
		chromedp.Flag("password-store", "basic"),

		// Disable auto-update
		chromedp.Flag("disable-update", true),
		chromedp.Flag("disable-background-updates", true),
	}

	return allocOpts
}

// Name returns the engine identifier
func (s *StealthEngine) Name() string {
	return "chromium-stealth"
}

// Capabilities returns what this engine supports
func (s *StealthEngine) Capabilities() engine.Capabilities {
	return engine.Capabilities{
		JavaScript:        true,
		HTTP2:             true,
		HTTP3:             true,
		PersistentProfile: true,
		NetLogExport:      true,
		WebSocket:         true,
		Intercept:         true,
	}
}

// Do executes a request with stealth enhancements
func (s *StealthEngine) Do(ctx context.Context, req *engine.Request) (*engine.Response, error) {
	// Start tracing
	ctx, span := s.tracer.StartSpan(ctx, "stealth.fetch", instrumentation.SpanKindRequest)
	span.SetAttribute("url", req.URL)

	span.SetAttribute("method", req.Method)
	defer span.End()

	s.logger.Info("starting request", "url", req.URL, "request_id", span.SpanID)

	// Execute hooks
	_ = s.hooks.Execute(ctx, instrumentation.HookNames.OnRequestStart)

	// Transition FSM
	if err := s.fsm.Transition(ctx, instrumentation.RequestEvents.Start); err != nil {
		s.logger.Error("FSM transition failed", "error", err)
	}

	requestID := string(span.SpanID)
	trace := &engine.Trace{
		Engine:    s.Name(),
		RequestID: requestID,
		Entries:   []engine.TraceEntry{},
	}

	// Create a new tab context
	tabCtx, tabCancel := chromedp.NewContext(s.allocCtx)
	defer tabCancel()

	timeout := req.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	tabCtx, cancel := context.WithTimeout(tabCtx, timeout)
	defer cancel()

	// Random delay before navigation
	if s.stealthOpts.RandomDelays {
		span.AddEvent("delay_before_navigation", map[string]interface{}{"min_ms": 500, "max_ms": 1500})
		delay := RandomDelay(500*time.Millisecond, 1500*time.Millisecond)
		time.Sleep(delay)
	}

	// Transition FSM to preparing
	if err := s.fsm.Transition(ctx, instrumentation.RequestEvents.Prepared); err != nil {
		s.logger.Error("FSM transition failed", "error", err)
	}

	// Build stealth script
	var initScript string
	if s.stealthOpts.EnableStealth {
		span.AddEvent("injecting_stealth_scripts", nil)
		initScript = GenerateStealthScript(s.config)
		_ = s.hooks.Execute(ctx, instrumentation.HookNames.OnStealthInject)
	}

	// Get viewport dimensions
	viewportWidth := int64(s.stealthOpts.ViewportWidth)
	viewportHeight := int64(s.stealthOpts.ViewportHeight)

	// Build actions
	actions := []chromedp.Action{
		network.Enable(),
		page.Enable(),
		chromedp.EmulateViewport(viewportWidth, viewportHeight),
	}

	// Apply precise isomorphic network headers
	if s.fingerprint != nil {
		extraHeaders := BuildNetworkHeaders(s.fingerprint)
		actions = append(actions, network.SetExtraHTTPHeaders(network.Headers(extraHeaders)))
	}

	// Add stealth script before navigation (persistently across the page load)
	if initScript != "" {
		actions = append(actions, chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(initScript).Do(ctx)
			return err
		}))
	}

	// Transition FSM to navigating
	if err := s.fsm.Transition(ctx, instrumentation.RequestEvents.Navigate); err != nil {
		s.logger.Error("FSM transition failed", "error", err)
	}

	// Navigate
	actions = append(actions, chromedp.Navigate(req.URL))

	// Wait for body
	actions = append(actions, chromedp.WaitReady("body"))

	// Wait for JS to settle
	if s.stealthOpts.RandomDelays {
		actions = append(actions, chromedp.Sleep(RandomDelay(1*time.Second, 3*time.Second)))
	}

	// Execute script if requested
	if req.ScriptToExecute != "" {
		actions = append(actions, chromedp.Evaluate(req.ScriptToExecute, nil))
	}

	// Get page content
	var body string
	actions = append(actions, chromedp.OuterHTML("html", &body))

	start := time.Now()

	if err := chromedp.Run(tabCtx, actions...); err != nil {
		return nil, fmt.Errorf("stealth run: %w", err)
	}
	total := time.Since(start)

	trace.Entries = append(trace.Entries, engine.TraceEntry{
		RequestID:   requestID,
		URL:         req.URL,
		Method:      "GET",
		RequestTime: start,
		Timing:      engine.TimingInfo{Total: total},
	})

	span.SetAttribute("status", 200)
	span.SetAttribute("body_size", len(body))
	span.SetAttribute("duration_ms", total.Milliseconds())
	span.AddEvent("request_complete", map[string]interface{}{"status": 200, "body_size": len(body)})

	// Transition FSM to detecting for shield validations
	if err := s.fsm.Transition(ctx, instrumentation.RequestEvents.ChallengeDetected); err != nil {
		s.logger.Error("FSM transition failed", "error", err)
	}

	// Scan the page for WAF Fingerprints
	waf := instrumentation.DetectChallenge(200, map[string]string{}, []byte(body))
	if waf != instrumentation.WAFUnknown {
		s.logger.Warn("WAF challenge detected during stealth navigation", "waf", waf, "url", req.URL)

		// Transition FSM to fail (which signals Adapting Retry)
		_ = s.fsm.Transition(ctx, instrumentation.RequestEvents.Fail)

		// Return specific error triggering the Adaptive loop upstream
		return nil, fmt.Errorf("WAF Challenge Detected: %s", waf)
	}

	// Transition FSM to complete
	if err := s.fsm.Transition(ctx, instrumentation.RequestEvents.Complete); err != nil {
		s.logger.Error("FSM transition failed", "error", err)
	}

	// Execute hooks
	_ = s.hooks.Execute(ctx, instrumentation.HookNames.OnRequestEnd)

	s.logger.Info("request completed", "url", req.URL, "duration_ms", total.Milliseconds(), "body_size", len(body))

	return &engine.Response{
		Status:   200,
		Body:     []byte(body),
		FinalURL: req.URL,
		Protocol: "h2",
		Trace:    *trace,
		Timing: engine.TimingInfo{
			Total: total,
		},
	}, nil
}

// Close cleans up resources
func (s *StealthEngine) Close() error {
	s.logger.Info("closing stealth engine")
	_ = s.hooks.Execute(context.Background(), instrumentation.HookNames.OnBrowserClose)
	if s.allocCancel != nil {
		s.allocCancel()
	}
	return nil
}

// SetStealthConfig updates the stealth configuration
func (s *StealthEngine) SetStealthConfig(config *StealthConfig) {
	s.config = config
}

// SetStealthOptions updates the stealth options
func (s *StealthEngine) SetStealthOptions(opts StealthOptions) {
	s.stealthOpts = opts
}

// Mouse moves to the specified coordinates with human-like behavior
func (s *StealthEngine) Mouse(x, y float64) error {
	sim := behavior.NewMouseSimulator(s.getBehaviorDelay())
	js := sim.MoveTo(x, y)

	tabCtx, _ := chromedp.NewContext(s.allocCtx)
	return chromedp.Run(tabCtx, chromedp.Evaluate(js, nil))
}

// Click performs a human-like click at the specified coordinates
func (s *StealthEngine) Click(x, y float64) error {
	sim := behavior.NewMouseSimulator(s.getBehaviorDelay())
	js := sim.ClickAt(x, y)

	tabCtx, _ := chromedp.NewContext(s.allocCtx)
	return chromedp.Run(tabCtx, chromedp.Evaluate(js, nil))
}

// Type simulates human-like typing with occasional errors and corrections
func (s *StealthEngine) Type(text string) error {
	sim := behavior.NewTypingSimulator(s.getBehaviorDelay())
	js := sim.Type(text)

	tabCtx, _ := chromedp.NewContext(s.allocCtx)
	return chromedp.Run(tabCtx, chromedp.Evaluate(js, nil))
}

// Scroll scrolls the page by the specified pixels
func (s *StealthEngine) Scroll(pixels float64) error {
	sim := behavior.NewScrollSimulator(s.getBehaviorDelay())
	js := sim.ScrollDown(pixels)

	tabCtx, _ := chromedp.NewContext(s.allocCtx)
	return chromedp.Run(tabCtx, chromedp.Evaluate(js, nil))
}

// ScrollTo scrolls to a specific position on the page
func (s *StealthEngine) ScrollTo(y float64) error {
	sim := behavior.NewScrollSimulator(s.getBehaviorDelay())
	js := sim.ScrollTo(y)

	tabCtx, _ := chromedp.NewContext(s.allocCtx)
	return chromedp.Run(tabCtx, chromedp.Evaluate(js, nil))
}

// getBehaviorDelay returns the precise delay extracted from the captured fingerprint
func (s *StealthEngine) getBehaviorDelay() time.Duration {
	if s.fingerprint != nil && s.fingerprint.Behavior != nil {
		if s.fingerprint.Behavior.RequestPattern.RequestPacing > 0 {
			return s.fingerprint.Behavior.RequestPattern.RequestPacing
		}
	}
	return 0
}

// WaitRandom adds a random delay for human-like behavior.
func (s *StealthEngine) WaitRandom(minDelay, maxDelay time.Duration) {
	delay := RandomDelay(minDelay, maxDelay)
	time.Sleep(delay)
}

// Hooks returns the hook registry for adding custom behavior
func (s *StealthEngine) Hooks() *instrumentation.HookRegistry {
	return s.hooks
}

// Tracer returns the tracer for request tracing
func (s *StealthEngine) Tracer() *instrumentation.Tracer {
	return s.tracer
}

// FSM returns the request FSM
func (s *StealthEngine) FSM() *instrumentation.FSM {
	return s.fsm
}

// Logger returns the logger
func (s *StealthEngine) Logger() *instrumentation.Logger {
	return s.logger
}
