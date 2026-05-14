// Package chromium implements the Engine interface using Chrome DevTools Protocol (CDP)
// via chromedp. This provides authentic browser TLS/HTTP2/HTTP3 behavior.
package chromium

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/google/uuid"

	"github.com/skunkworq/stealth/brws/browser/engine"
	"github.com/skunkworq/stealth/brws/core/constants"
	"github.com/skunkworq/stealth/brws/core/instrumentation"
)

func init() {
	engine.Register("chromium", New)
}

// Chromium implements the Engine interface using CDP/chromedp.
// It also implements TabEngine, AllocatorEngine, TabCreator, and InteractiveEngine.
type Chromium struct {
	allocCtx    context.Context
	allocCancel context.CancelFunc
	tabCtx      context.Context // current persistent tab, set by DoOnTab
	trace       *engine.Trace
	options     engine.Options

	logger *instrumentation.Logger
	tracer *instrumentation.Tracer
	hooks  *instrumentation.HookRegistry
	fsm    *instrumentation.FSM
}

// New creates a new Chromium engine.
func New(opts engine.Options) (engine.Engine, error) {
	allocOpts := []chromedp.ExecAllocatorOption{
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.Headless,
		chromedp.DisableGPU,
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
		chromedp.UserAgent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36"),
	}

	if !opts.Headless {
		allocOpts = append(allocOpts, chromedp.Flag("headless", false))
	}
	if opts.ProfileDir != "" {
		allocOpts = append(allocOpts, chromedp.UserDataDir(opts.ProfileDir))
	}
	if opts.ExecutablePath != "" {
		allocOpts = append(allocOpts, chromedp.ExecPath(opts.ExecutablePath))
	}
	if opts.Proxy != "" {
		allocOpts = append(allocOpts, chromedp.ProxyServer(opts.Proxy))
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), allocOpts...)

	logger, _ := instrumentation.NewLogger(&instrumentation.Config{LogLevel: "info"})
	tracer := instrumentation.NewTracer()
	hooks := instrumentation.DefaultHookRegistry()
	fsm := instrumentation.NewRequestFSM()

	return &Chromium{
		allocCtx:    allocCtx,
		allocCancel: allocCancel,
		options:     opts,
		logger:      logger,
		tracer:      tracer,
		hooks:       hooks,
		fsm:         fsm,
	}, nil
}

// Name returns the engine identifier.
func (c *Chromium) Name() string { return "chromium" }

// Capabilities returns what this engine supports.
func (c *Chromium) Capabilities() engine.Capabilities {
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

// ---------------------------------------------------------------------------
// engine.Engine
// ---------------------------------------------------------------------------

// Do executes a request on a fresh tab, closing it when done.
func (c *Chromium) Do(_ context.Context, req *engine.Request) (*engine.Response, error) {
	tabCtx, tabCancel := chromedp.NewContext(c.allocCtx)
	defer tabCancel()

	timeout := req.Timeout
	if timeout == 0 {
		timeout = constants.DefaultTimeout
	}
	tabCtx, cancel := context.WithTimeout(tabCtx, timeout)
	defer cancel()

	return c.DoOnTab(context.Background(), tabCtx, req)
}

// Close cleans up browser resources.
func (c *Chromium) Close() error {
	if c.allocCancel != nil {
		c.allocCancel()
	}
	return nil
}

// ---------------------------------------------------------------------------
// engine.TabEngine
// ---------------------------------------------------------------------------

// DoOnTab executes a request on an existing tab context, allowing the caller
// to reuse a persistent tab across multiple requests.
func (c *Chromium) DoOnTab(_ context.Context, tabCtx context.Context, req *engine.Request) (*engine.Response, error) {
	c.tabCtx = tabCtx

	requestID := uuid.New().String()
	c.trace = &engine.Trace{
		Engine:    c.Name(),
		RequestID: requestID,
		Entries:   []engine.TraceEntry{},
	}

	var networkEntries []engine.TraceEntry
	_ = network.Enable().Do(tabCtx)

	chromedp.ListenTarget(tabCtx, func(ev interface{}) {
		switch ev := ev.(type) {
		case *network.EventResponseReceived:
			resp := ev.Response
			entry := engine.TraceEntry{
				RequestID:  string(ev.RequestID),
				URL:        resp.URL,
				Status:     int(resp.Status),
				Protocol:   resp.Protocol,
				RemoteAddr: resp.RemoteIPAddress,
				Response: engine.TraceResponse{
					Headers:  FlattenHeaders(resp.Headers),
					MimeType: resp.MimeType,
				},
			}
			if resp.ResponseTime != nil {
				entry.RequestTime = resp.ResponseTime.Time()
			} else {
				entry.RequestTime = time.Now()
			}
			networkEntries = append(networkEntries, entry)
		case *network.EventRequestWillBeSent:
			for i := range networkEntries {
				if networkEntries[i].RequestID == string(ev.RequestID) {
					networkEntries[i].Method = ev.Request.Method
					networkEntries[i].Request = engine.TraceRequest{
						Headers: FlattenHeaders(ev.Request.Headers),
					}
					break
				}
			}
		}
	})

	actions := []chromedp.Action{network.Enable()}

	if len(req.ExtraHeaders) > 0 {
		headers := make(map[string]interface{})
		for k, v := range req.ExtraHeaders {
			headers[k] = v
		}
		actions = append(actions, network.SetExtraHTTPHeaders(network.Headers(headers)))
	}

	actions = append(actions, navigateWithStrategy(req.URL, req.LoadStrategy))

	if req.WaitForSelector != "" {
		actions = append(actions, chromedp.WaitVisible(req.WaitForSelector))
	}

	if req.ScriptToExecute != "" {
		var result *runtime.RemoteObject
		actions = append(actions, chromedp.Evaluate(req.ScriptToExecute, &result))
	}

	var body string
	actions = append(actions, chromedp.OuterHTML("html", &body))

	start := time.Now()
	if err := chromedp.Run(tabCtx, actions...); err != nil {
		return nil, fmt.Errorf("chromedp run: %w", err)
	}
	total := time.Since(start)

	c.trace.Entries = networkEntries

	if len(networkEntries) > 0 {
		e := networkEntries[0]
		return &engine.Response{
			Status:     e.Status,
			StatusText: fmt.Sprintf("%d", e.Status),
			Headers:    UnflattenHeaders(e.Response.Headers),
			Body:       []byte(body),
			FinalURL:   e.URL,
			Protocol:   e.Protocol,
			Trace:      *c.trace,
			Timing:     engine.TimingInfo{Total: total},
		}, nil
	}
	return &engine.Response{
		Status:   200,
		Body:     []byte(body),
		FinalURL: req.URL,
		Protocol: "h2",
		Trace:    *c.trace,
		Timing:   engine.TimingInfo{Total: total},
	}, nil
}

// ---------------------------------------------------------------------------
// engine.AllocatorEngine
// ---------------------------------------------------------------------------

// Allocator returns the chromedp allocator context for creating persistent tabs.
func (c *Chromium) Allocator() context.Context { return c.allocCtx }

// ---------------------------------------------------------------------------
// engine.TabCreator
// ---------------------------------------------------------------------------

// NewTab creates a new persistent tab. The caller is responsible for calling cancel.
func (c *Chromium) NewTab() (context.Context, context.CancelFunc) {
	return chromedp.NewContext(c.allocCtx)
}

// ---------------------------------------------------------------------------
// engine.InteractiveEngine — raw CDP, no behavioral simulation
// ---------------------------------------------------------------------------

// Mouse moves the cursor to the specified coordinates via CDP input events.
func (c *Chromium) Mouse(x, y float64) error {
	if c.tabCtx == nil {
		return fmt.Errorf("no active tab: call DoOnTab first")
	}
	return chromedp.Run(c.tabCtx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			return chromedp.MouseClickXY(x, y, chromedp.ButtonNone).Do(ctx)
		}),
	)
}

// Click performs a mouse click at the specified coordinates.
func (c *Chromium) Click(x, y float64) error {
	if c.tabCtx == nil {
		return fmt.Errorf("no active tab: call DoOnTab first")
	}
	return chromedp.Run(c.tabCtx, chromedp.MouseClickXY(x, y))
}

// Type sends keystrokes to the currently focused element.
func (c *Chromium) Type(text string) error {
	if c.tabCtx == nil {
		return fmt.Errorf("no active tab: call DoOnTab first")
	}
	return chromedp.Run(c.tabCtx, chromedp.SendKeys("body", text, chromedp.ByQuery))
}

// Scroll scrolls the page by the specified number of pixels.
func (c *Chromium) Scroll(pixels float64) error {
	if c.tabCtx == nil {
		return fmt.Errorf("no active tab: call DoOnTab first")
	}
	return chromedp.Run(c.tabCtx,
		chromedp.Evaluate(fmt.Sprintf("window.scrollBy(0, %f)", pixels), nil),
	)
}

// ScrollTo scrolls to a specific Y position on the page.
func (c *Chromium) ScrollTo(y float64) error {
	if c.tabCtx == nil {
		return fmt.Errorf("no active tab: call DoOnTab first")
	}
	return chromedp.Run(c.tabCtx,
		chromedp.Evaluate(fmt.Sprintf("window.scrollTo(0, %f)", y), nil),
	)
}

// ---------------------------------------------------------------------------
// Instrumentation accessors
// ---------------------------------------------------------------------------

func (c *Chromium) Hooks() *instrumentation.HookRegistry { return c.hooks }
func (c *Chromium) Tracer() *instrumentation.Tracer      { return c.tracer }
func (c *Chromium) FSM() *instrumentation.FSM            { return c.fsm }
func (c *Chromium) Logger() *instrumentation.Logger      { return c.logger }

// ---------------------------------------------------------------------------
// CookieJar
// ---------------------------------------------------------------------------

// GetCookies returns all cookies visible to url. Pass "" to return all cookies.
// Uses the active tab context; falls back to the allocator context if no tab is open.
func (c *Chromium) GetCookies(ctx context.Context, url string) ([]engine.Cookie, error) {
	tabCtx := c.activeCtx()
	cmd := network.GetCookies()
	if url != "" {
		cmd = cmd.WithURLs([]string{url})
	}
	raw, err := cmd.Do(tabCtx)
	if err != nil {
		return nil, fmt.Errorf("get cookies: %w", err)
	}
	out := make([]engine.Cookie, 0, len(raw))
	for _, ck := range raw {
		var exp time.Time
		if !ck.Session && ck.Expires > 0 {
			exp = time.Unix(int64(ck.Expires), 0).UTC()
		}
		out = append(out, engine.Cookie{
			Name:     ck.Name,
			Value:    ck.Value,
			Domain:   ck.Domain,
			Path:     ck.Path,
			Expires:  exp,
			Secure:   ck.Secure,
			HTTPOnly: ck.HTTPOnly,
			SameSite: string(ck.SameSite),
		})
	}
	return out, nil
}

// SetCookies writes cookies into the browser's cookie store.
func (c *Chromium) SetCookies(ctx context.Context, cookies []engine.Cookie) error {
	tabCtx := c.activeCtx()
	params := make([]*network.CookieParam, len(cookies))
	for i, ck := range cookies {
		p := &network.CookieParam{
			Name:     ck.Name,
			Value:    ck.Value,
			Domain:   ck.Domain,
			Path:     ck.Path,
			Secure:   ck.Secure,
			HTTPOnly: ck.HTTPOnly,
			SameSite: network.CookieSameSite(ck.SameSite),
		}
		if !ck.Expires.IsZero() {
			ts := cdp.TimeSinceEpoch(ck.Expires)
			p.Expires = &ts
		}
		params[i] = p
	}
	if err := network.SetCookies(params).Do(tabCtx); err != nil {
		return fmt.Errorf("set cookies: %w", err)
	}
	return nil
}

// activeCtx returns the active tab context, falling back to the allocator.
func (c *Chromium) activeCtx() context.Context {
	if c.tabCtx != nil {
		return c.tabCtx
	}
	return c.allocCtx
}


// ---------------------------------------------------------------------------
// GetNetLog
// ---------------------------------------------------------------------------

// GetNetLog exports Chromium NetLog if available.
func (c *Chromium) GetNetLog() ([]byte, error) {
	return nil, fmt.Errorf("NetLog export not yet implemented")
}

// ---------------------------------------------------------------------------
// Load strategy
// ---------------------------------------------------------------------------

// navigateWithStrategy returns a chromedp Action that navigates to url and
// yields control when the requested load condition is met.
//
//   - commit          — first response bytes received; document starts loading
//   - domcontentloaded — DOM parsed; subresources may still be in-flight
//   - load (default)  — window.onload; all subresources done
//   - networkidle     — no in-flight requests for 500 ms (good for SPAs)
func navigateWithStrategy(url string, strategy engine.LoadStrategy) chromedp.Action {
	switch strategy {
	case engine.LoadCommit:
		return chromedp.ActionFunc(func(ctx context.Context) error {
			_, _, _, _, err := page.Navigate(url).Do(ctx)
			return err
		})

	case engine.LoadDOMContentLoaded:
		return chromedp.ActionFunc(func(ctx context.Context) error {
			done := make(chan struct{}, 1)
			chromedp.ListenTarget(ctx, func(ev interface{}) {
				if _, ok := ev.(*page.EventDomContentEventFired); ok {
					select {
					case done <- struct{}{}:
					default:
					}
				}
			})
			if _, _, _, _, err := page.Navigate(url).Do(ctx); err != nil {
				return err
			}
			select {
			case <-done:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})

	case engine.LoadNetworkIdle:
		return chromedp.ActionFunc(func(ctx context.Context) error {
			if err := page.SetLifecycleEventsEnabled(true).Do(ctx); err != nil {
				return err
			}
			done := make(chan struct{}, 1)
			chromedp.ListenTarget(ctx, func(ev interface{}) {
				if lc, ok := ev.(*page.EventLifecycleEvent); ok && lc.Name == "networkIdle" {
					select {
					case done <- struct{}{}:
					default:
					}
				}
			})
			if _, _, _, _, err := page.Navigate(url).Do(ctx); err != nil {
				return err
			}
			select {
			case <-done:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})

	default: // LoadLoad and zero value
		return chromedp.Navigate(url)
	}
}

// ---------------------------------------------------------------------------
// Header helpers
// ---------------------------------------------------------------------------

func FlattenHeaders(headers map[string]interface{}) map[string]string {
	result := make(map[string]string)
	for key, value := range headers {
		switch v := value.(type) {
		case string:
			result[key] = v
		default:
			if b, err := json.Marshal(v); err == nil {
				result[key] = string(b)
			}
		}
	}
	return result
}

func UnflattenHeaders(headers map[string]string) map[string][]string {
	result := make(map[string][]string)
	for key, value := range headers {
		result[key] = []string{value}
	}
	return result
}
