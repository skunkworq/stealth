// Package chromium provides a stealth-enhanced Chromium engine.
//
//nolint:gosec // G404: math/rand used intentionally for non-cryptographic jitter/randomization
package chromium

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"

	"github.com/skunkworq/stealth/brws/stealth/behavior"
	"github.com/skunkworq/stealth/brws/browser/engine"
	"github.com/skunkworq/stealth/brws/core/instrumentation"
	"github.com/skunkworq/stealth/brws/core/types"
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

	// Directly apply stealth config if provided (eliminates brittle JSON round-trip)
	if opts.StealthConfigRaw != nil {
		if cfg, ok := opts.StealthConfigRaw.(*StealthConfig); ok {
			stealthCfg = cfg
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

		// GPU: use ANGLE for hardware-accelerated rendering via native graphics API.
		// This avoids SwiftShader (software renderer) which is trivially detectable
		// via WebGL unmaskedRenderer. ANGLE produces real GPU-backed canvas/WebGL
		// fingerprints indistinguishable from a normal browser.
		// NOTE: DisableGPU is intentionally NOT set — it forces SwiftShader.
		chromedp.Flag("use-gl", "angle"),
		chromedp.Flag("use-angle", "default"),

		// Stealth-specific flags (nodriver-style)
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
		chromedp.Flag("disable-infobars", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-setuid-sandbox", true),
		// NOTE: disable-accelerated-2d-canvas is intentionally NOT set — it forces
		// software canvas rendering which produces detectable IDAT entropy patterns.
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

		chromedp.Flag("disable-update", true),
		chromedp.Flag("disable-background-updates", true),
	}

	if opts.InsecureSkipVerify {
		allocOpts = append(allocOpts, chromedp.Flag("ignore-certificate-errors", true))
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
// Allocator returns the chromedp allocator context for creating persistent tabs.
func (s *StealthEngine) Allocator() context.Context {
	return s.allocCtx
}

// NewTab creates a new persistent tab in the stealth browser.
// The caller is responsible for calling the returned cancel function.
func (s *StealthEngine) NewTab() (context.Context, context.CancelFunc) {
	return chromedp.NewContext(s.allocCtx)
}

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

	// Create a new tab context
	tabCtx, tabCancel := chromedp.NewContext(s.allocCtx)
	defer tabCancel()

	timeout := req.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	tabCtx, cancel := context.WithTimeout(tabCtx, timeout)
	defer cancel()

	resp, err := s.DoOnTab(ctx, tabCtx, req)

	// Transition FSM to complete or fail
	if err != nil {
		_ = s.fsm.Transition(ctx, instrumentation.RequestEvents.Fail)
	} else {
		_ = s.fsm.Transition(ctx, instrumentation.RequestEvents.Complete)
	}

	// Execute hooks
	_ = s.hooks.Execute(ctx, instrumentation.HookNames.OnRequestEnd)

	return resp, err
}

// DoOnTab executes a request on an existing tab context. This allows the stealth
// engine to operate on a caller-managed tab (e.g. an agent's persistent tab)
// instead of creating a fresh tab per request.
func (s *StealthEngine) DoOnTab(ctx context.Context, tabCtx context.Context, req *engine.Request) (*engine.Response, error) {
	requestID := ""
	if span := instrumentation.SpanFromContext(ctx); span != nil {
		requestID = string(span.SpanID)
	}
	trace := &engine.Trace{
		Engine:    s.Name(),
		RequestID: requestID,
		Entries:   []engine.TraceEntry{},
	}

	// Random delay before navigation
	if s.stealthOpts.RandomDelays {
		delay := RandomDelay(500*time.Millisecond, 1500*time.Millisecond)
		time.Sleep(delay)
	}

	// Build stealth script
	var initScript string
	if s.stealthOpts.EnableStealth {
		initScript = GenerateStealthScript(s.config)
		_ = s.hooks.Execute(ctx, instrumentation.HookNames.OnStealthInject)
	}

	// Get viewport dimensions
	viewportWidth := int64(s.stealthOpts.ViewportWidth)
	viewportHeight := int64(s.stealthOpts.ViewportHeight)

	// StealthPlus: grant all browser permissions to remove prompts
	if s.config.StealthPlus {
		_ = s.GrantAllPermissions(tabCtx)
	}

	// Build actions
	actions := []chromedp.Action{
		network.Enable(),
		page.Enable(),
		chromedp.EmulateViewport(viewportWidth, viewportHeight),
	}

	// Apply precise isomorphic network headers
	var extraHeaders map[string]interface{}
	if s.fingerprint != nil {
		extraHeaders = BuildNetworkHeaders(s.fingerprint)
	}

	// Apply Local IP spoofing if enabled
	if s.config != nil && s.config.SpoofLocalIPs {
		if extraHeaders == nil {
			extraHeaders = make(map[string]interface{})
		}
		spoofedIP := RandomLocalIP()
		extraHeaders["X-Forwarded-For"] = spoofedIP
		extraHeaders["X-Real-IP"] = spoofedIP
		extraHeaders["X-Client-IP"] = spoofedIP
		extraHeaders["True-Client-IP"] = spoofedIP
		extraHeaders["CF-Connecting-IP"] = spoofedIP
	}

	if extraHeaders != nil {
		actions = append(actions, network.SetExtraHTTPHeaders(network.Headers(extraHeaders)))
	}

	// Add stealth script before navigation (persistently across the page load)
	if initScript != "" {
		actions = append(actions, chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(initScript).Do(ctx)
			return err
		}))
	}

	// Set up network event listener to capture all sub-resource requests.
	var netMu sync.Mutex
	netRequests := make(map[network.RequestID]*engine.TraceEntry)
	chromedp.ListenTarget(tabCtx, func(ev interface{}) {
		switch e := ev.(type) {
		case *network.EventRequestWillBeSent:
			netMu.Lock()
			netRequests[e.RequestID] = &engine.TraceEntry{
				RequestID:   string(e.RequestID),
				URL:         e.Request.URL,
				Method:      e.Request.Method,
				RequestTime: time.Now(),
				Request: engine.TraceRequest{
					Headers: flattenHeaders(e.Request.Headers),
				},
			}
			netMu.Unlock()
		case *network.EventResponseReceived:
			netMu.Lock()
			if entry, ok := netRequests[e.RequestID]; ok {
				entry.Status = int(e.Response.Status)
				entry.Protocol = e.Response.Protocol
				entry.RemoteAddr = fmt.Sprintf("%s:%d", e.Response.RemoteIPAddress, e.Response.RemotePort)
				entry.Response = engine.TraceResponse{
					Headers:  flattenHeaders(e.Response.Headers),
					BodySize: int64(e.Response.EncodedDataLength),
					MimeType: e.Response.MimeType,
				}
			}
			netMu.Unlock()
		}
	})

	// Navigate — with referrer when StealthPlus is enabled
	if s.config.StealthPlus && req.Referrer != "" {
		actions = append(actions, chromedp.ActionFunc(func(c context.Context) error {
			_, _, _, _, err := page.Navigate(req.URL).
				WithReferrer(req.Referrer).
				Do(c)
			return err
		}))
	} else {
		actions = append(actions, chromedp.Navigate(req.URL))
	}

	// Wait for body or pre (JSON endpoints)
	actions = append(actions, chromedp.WaitReady("body, pre"))

	// Wait for JS to settle
	if s.stealthOpts.RandomDelays {
		actions = append(actions, chromedp.Sleep(RandomDelay(1*time.Second, 3*time.Second)))
	}

	// Execute script if requested
	var scriptResult interface{}
	if req.ScriptToExecute != "" {
		if s.config.StealthPlus {
			// StealthPlus: use user-gesture evaluation to unlock gated APIs
			actions = append(actions, chromedp.ActionFunc(func(c context.Context) error {
				res, err := s.EvaluateWithGesture(c, req.ScriptToExecute)
				if err != nil {
					return err
				}
				scriptResult = res
				return nil
			}))
		} else {
			actions = append(actions, chromedp.Evaluate(req.ScriptToExecute, &scriptResult))
		}
	}

	// Get page content
	var body string
	actions = append(actions, chromedp.OuterHTML("html", &body))

	start := time.Now()

	if err := chromedp.Run(tabCtx, actions...); err != nil {
		return nil, fmt.Errorf("stealth run: %w", err)
	}
	total := time.Since(start)

	// Collect captured network entries into the trace.
	netMu.Lock()
	for _, entry := range netRequests {
		trace.Entries = append(trace.Entries, *entry)
	}
	netMu.Unlock()

	// If no network entries were captured, add the primary navigation entry.
	if len(trace.Entries) == 0 {
		trace.Entries = append(trace.Entries, engine.TraceEntry{
			RequestID:   requestID,
			URL:         req.URL,
			Method:      "GET",
			RequestTime: start,
			Timing:      engine.TimingInfo{Total: total},
		})
	}

	s.logger.Info("request completed", "url", req.URL, "duration_ms", total.Milliseconds(), "body_size", len(body))

	raw := map[string]interface{}{}
	if scriptResult != nil {
		raw["script_result"] = scriptResult
	}
	trace.Raw = raw

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
	if s.config.StealthPlus {
		_, err := s.EvaluateWithGesture(tabCtx, js)
		return err
	}
	return chromedp.Run(tabCtx, chromedp.Evaluate(js, nil))
}

// Click performs a human-like click at the specified coordinates
func (s *StealthEngine) Click(x, y float64) error {
	sim := behavior.NewMouseSimulator(s.getBehaviorDelay())
	js := sim.ClickAt(x, y)

	tabCtx, _ := chromedp.NewContext(s.allocCtx)
	if s.config.StealthPlus {
		_, err := s.EvaluateWithGesture(tabCtx, js)
		return err
	}
	return chromedp.Run(tabCtx, chromedp.Evaluate(js, nil))
}

// Type simulates human-like typing with occasional errors and corrections
func (s *StealthEngine) Type(text string) error {
	sim := behavior.NewTypingSimulator(s.getBehaviorDelay())
	js := sim.Type(text)

	tabCtx, _ := chromedp.NewContext(s.allocCtx)
	if s.config.StealthPlus {
		_, err := s.EvaluateWithGesture(tabCtx, js)
		return err
	}
	return chromedp.Run(tabCtx, chromedp.Evaluate(js, nil))
}

// Scroll scrolls the page by the specified pixels
func (s *StealthEngine) Scroll(pixels float64) error {
	sim := behavior.NewScrollSimulator(s.getBehaviorDelay())
	js := sim.ScrollDown(pixels)

	tabCtx, _ := chromedp.NewContext(s.allocCtx)
	if s.config.StealthPlus {
		_, err := s.EvaluateWithGesture(tabCtx, js)
		return err
	}
	return chromedp.Run(tabCtx, chromedp.Evaluate(js, nil))
}

// ScrollTo scrolls to a specific position on the page
func (s *StealthEngine) ScrollTo(y float64) error {
	sim := behavior.NewScrollSimulator(s.getBehaviorDelay())
	js := sim.ScrollTo(y)

	tabCtx, _ := chromedp.NewContext(s.allocCtx)
	if s.config.StealthPlus {
		_, err := s.EvaluateWithGesture(tabCtx, js)
		return err
	}
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
