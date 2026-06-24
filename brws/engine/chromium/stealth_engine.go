// Package chromium provides a stealth-enhanced Chromium engine.
//
//nolint:gosec // G404: math/rand used intentionally for non-cryptographic jitter/randomization
package chromium

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"sync"
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

	// ChallengeSettleBudget bounds how long Do() will wait, after the initial
	// navigation, for an anti-bot JS challenge (Kasada, Akamai, Cloudflare,
	// DataDome) to run and redirect/reload into the real page before the DOM is
	// captured. These shields serve a tiny pre-challenge stub, execute JS, then
	// navigate to the genuine document several seconds later; capturing before
	// that point yields only the stub. The wait ends early once the network goes
	// idle on a non-challenge document, so this is an upper bound, not a fixed
	// sleep.
	ChallengeSettleBudget time.Duration
}

// DefaultStealthOptions returns default stealth options
func DefaultStealthOptions() StealthOptions {
	return StealthOptions{
		EnableStealth:         true,
		HumanizeMouse:         true,
		RandomDelays:          true,
		HandleAgeGate:         false,
		SessionWarming:        false,
		ViewportWidth:         1920,
		ViewportHeight:        1080,
		WaitNetworkIdle:       true,
		NetworkIdleTimeout:    3 * time.Second,
		ChallengeSettleBudget: 10 * time.Second,
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

// NewStealthWithFingerprint creates an engine tightly bound to a specific captured fingerprint.
// If opts.DebuggerURL is set, connects to an already-running Chrome instance via
// CDP — the most reliable bypass against aggressive anti-bot (Amazon, AliExpress, Temu),
// since the host browser carries the user's residential IP, real cookies, and any
// past challenge solutions. In that mode the heavy stealth allocator flags are
// skipped (they only apply at launch time).
func NewStealthWithFingerprint(opts engine.Options, fp *types.CompleteFingerprint) (engine.Engine, error) {
	log := instrumentation.Named("chromium-stealth")
	log.Info("initializing stealth engine")

	var stealthCfg *StealthConfig
	if fp != nil {
		stealthCfg = StealthConfigFromFingerprint(fp)
	} else {
		stealthCfg = DefaultStealthConfig()
	}

	if opts.StealthConfigRaw != nil {
		if rawBytes, err := json.Marshal(opts.StealthConfigRaw); err == nil {
			_ = json.Unmarshal(rawBytes, &stealthCfg)
		}
	}

	var allocCtx context.Context
	var allocCancel context.CancelFunc
	if opts.DebuggerURL != "" {
		log.Info("attaching to remote Chrome via CDP", "url", opts.DebuggerURL)
		allocCtx, allocCancel = chromedp.NewRemoteAllocator(context.Background(), opts.DebuggerURL)
	} else {
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
		if fp != nil {
			allocOpts = append(allocOpts, chromedp.UserAgent(fp.HTTP.UserAgent))
		} else {
			allocOpts = append(allocOpts, chromedp.UserAgent(RandomUserAgent()))
		}
		allocCtx, allocCancel = chromedp.NewExecAllocator(context.Background(), allocOpts...)
	}

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

	// Transition FSM to navigating
	if err := s.fsm.Transition(ctx, instrumentation.RequestEvents.Navigate); err != nil {
		s.logger.Error("FSM transition failed", "error", err)
	}

	// Set up network event listener to capture all sub-resource requests and to
	// track in-flight requests + frame navigations. The in-flight counter and the
	// last-navigation timestamp drive the challenge-settle wait below: anti-bot
	// shields (Kasada/Akamai/Cloudflare/DataDome) serve a tiny stub that runs JS
	// and then reloads/redirects to the real document a few seconds later, so we
	// must wait for the network to go quiet *after* that second navigation before
	// capturing the DOM.
	var netMu sync.Mutex
	netRequests := make(map[network.RequestID]*engine.TraceEntry)
	var inFlight int
	var lastActivity time.Time
	var navCount int
	markActivity := func() { lastActivity = time.Now() }
	chromedp.ListenTarget(tabCtx, func(ev interface{}) {
		switch e := ev.(type) {
		case *network.EventRequestWillBeSent:
			netMu.Lock()
			inFlight++
			markActivity()
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
		case *network.EventLoadingFinished:
			netMu.Lock()
			if inFlight > 0 {
				inFlight--
			}
			markActivity()
			netMu.Unlock()
		case *network.EventLoadingFailed:
			netMu.Lock()
			if inFlight > 0 {
				inFlight--
			}
			markActivity()
			netMu.Unlock()
		case *page.EventFrameNavigated:
			// A new top-level document committed — this is the challenge
			// redirecting/reloading into the real page. Reset the idle clock so
			// the settle loop waits for the *new* document's resources.
			if e.Frame != nil && e.Frame.ParentID == "" {
				netMu.Lock()
				navCount++
				markActivity()
				netMu.Unlock()
			}
		}
	})

	// Navigate
	actions = append(actions, chromedp.Navigate(req.URL))

	// Wait for body or pre (JSON endpoints)
	actions = append(actions, chromedp.WaitReady("body, pre"))

	// Wait for JS to settle
	if s.stealthOpts.RandomDelays {
		actions = append(actions, chromedp.Sleep(RandomDelay(1*time.Second, 3*time.Second)))
	}

	// Wait for the anti-bot challenge (if any) to run and settle into the real
	// page before capturing. See challengeSettle for the network-idle / redirect
	// detection logic. Bounded by ChallengeSettleBudget so a hung challenge can't
	// stall the request indefinitely.
	settleBudget := s.stealthOpts.ChallengeSettleBudget
	if settleBudget <= 0 {
		settleBudget = 10 * time.Second
	}
	idleWindow := s.stealthOpts.NetworkIdleTimeout
	if idleWindow <= 0 {
		idleWindow = 500 * time.Millisecond
	}
	actions = append(actions, chromedp.ActionFunc(func(ctx context.Context) error {
		s.challengeSettle(ctx, &netMu, &inFlight, &lastActivity, &navCount, settleBudget, idleWindow)
		return nil
	}))

	// Execute script if requested
	var scriptResult interface{}
	if req.ScriptToExecute != "" {
		actions = append(actions, chromedp.Evaluate(req.ScriptToExecute, &scriptResult))
	}

	// Get page content. Captured AFTER the challenge-settle wait so Body is the
	// real post-challenge document, not the pre-challenge stub. document.
	// documentElement.outerHTML returns the full live DOM including any nodes the
	// challenge JS injected/replaced.
	var body string
	actions = append(actions, chromedp.OuterHTML(":root", &body, chromedp.ByQuery))

	// Capture the final (post-redirect) URL so callers see where the challenge
	// landed them, not the URL they originally requested.
	var finalURL string
	actions = append(actions, chromedp.Location(&finalURL))

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

	span.SetAttribute("status", 200)
	span.SetAttribute("body_size", len(body))
	span.SetAttribute("duration_ms", total.Milliseconds())
	span.AddEvent("request_complete", map[string]interface{}{"status": 200, "body_size": len(body)})

	// FSM: the navigation has loaded and we're done waiting for it to settle, so
	// move out of Navigating into Waiting (PageLoaded), then into Detecting to
	// inspect the page for a residual anti-bot challenge.
	if err := s.fsm.Transition(ctx, instrumentation.RequestEvents.PageLoaded); err != nil {
		s.logger.Error("FSM transition failed", "error", err)
	}
	if err := s.fsm.Transition(ctx, instrumentation.RequestEvents.ChallengeDetected); err != nil {
		s.logger.Error("FSM transition failed", "error", err)
	}

	// Scan the *post-settle* page for WAF fingerprints. If the challenge JS
	// successfully redirected into the real document this is now clean; if the
	// shield is still blocking us, the stub markers persist and we surface a
	// retryable error so the adaptive loop upstream can escalate.
	waf := instrumentation.DetectChallenge(200, map[string]string{}, []byte(body))
	if waf != instrumentation.WAFUnknown {
		s.logger.Warn("WAF challenge detected during stealth navigation", "waf", waf, "url", req.URL)

		// Transition FSM to fail (which signals Adapting Retry)
		_ = s.fsm.Transition(ctx, instrumentation.RequestEvents.Fail)

		// Return specific error triggering the Adaptive loop upstream
		return nil, fmt.Errorf("WAF Challenge Detected: %s", waf)
	}

	// No (or cleared) challenge: walk the happy path Detecting -> Extracting ->
	// Complete. Extracting models pulling content out of the settled DOM.
	if err := s.fsm.Transition(ctx, instrumentation.RequestEvents.Extract); err != nil {
		s.logger.Error("FSM transition failed", "error", err)
	}
	if err := s.fsm.Transition(ctx, instrumentation.RequestEvents.Complete); err != nil {
		s.logger.Error("FSM transition failed", "error", err)
	}

	// Execute hooks
	_ = s.hooks.Execute(ctx, instrumentation.HookNames.OnRequestEnd)

	s.logger.Info("request completed", "url", req.URL, "duration_ms", total.Milliseconds(), "body_size", len(body), "navigations", navCount)

	raw := map[string]interface{}{}
	if scriptResult != nil {
		raw["script_result"] = scriptResult
	}
	trace.Raw = raw

	// Prefer the post-redirect URL the page actually settled on; fall back to the
	// requested URL if Location couldn't be read.
	resolvedURL := finalURL
	if resolvedURL == "" {
		resolvedURL = req.URL
	}

	return &engine.Response{
		Status:   200,
		Body:     []byte(body),
		FinalURL: resolvedURL,
		Protocol: "h2",
		Trace:    *trace,
		Timing: engine.TimingInfo{
			Total: total,
		},
	}, nil
}

// challengeSettle blocks until the page has gone quiet after navigation or the
// budget expires. Anti-bot shields (Kasada/Akamai/Cloudflare/DataDome) return a
// small stub document, run JS, then reload or redirect into the real page; that
// second navigation arrives several seconds after the first response, so a fixed
// short sleep captures only the stub.
//
// The wait is satisfied when the network has been idle (no in-flight requests)
// for idleWindow AND at least one extra top-level navigation has been observed
// since entry OR the idleWindow has elapsed with no navigation at all (a clean
// page that never challenged). It is hard-bounded by budget so a challenge that
// never resolves can't hang the request. All shared counters are read under mu
// because they are mutated from the CDP event goroutine.
func (s *StealthEngine) challengeSettle(
	ctx context.Context,
	mu *sync.Mutex,
	inFlight *int,
	lastActivity *time.Time,
	navCount *int,
	budget time.Duration,
	idleWindow time.Duration,
) {
	deadline := time.Now().Add(budget)
	mu.Lock()
	navAtEntry := *navCount
	mu.Unlock()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		if time.Now().After(deadline) {
			s.logger.Debug("challenge settle budget exhausted", "budget_ms", budget.Milliseconds())
			return
		}

		mu.Lock()
		idleFor := time.Since(*lastActivity)
		quiet := *inFlight <= 0 && idleFor >= idleWindow
		redirected := *navCount > navAtEntry
		mu.Unlock()

		// Settled: network is quiet. If a post-load navigation (challenge
		// redirect) has fired we know we're on the real page; if none ever
		// fired this was a clean page that simply finished loading.
		if quiet {
			if redirected {
				s.logger.Debug("challenge settled after redirect", "navigations", *navCount)
			}
			return
		}
	}
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
