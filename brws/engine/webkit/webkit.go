// Package webkit implements the Engine interface using Playwright for WebKit.
// This provides Safari-like behavior through Playwright's WebKit support.
package webkit

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/playwright-community/playwright-go"

	"github.com/skunkworq/stealth/brws/engine"
)

func init() {
	engine.Register("webkit", New)
}

// WebKit implements the Engine interface using Playwright.
type WebKit struct {
	pw      *playwright.Playwright
	browser playwright.Browser
	options engine.Options
	trace   *engine.Trace
}

// New creates a new WebKit engine.
func New(opts engine.Options) (engine.Engine, error) {
	pw, err := playwright.Run()
	if err != nil {
		return nil, fmt.Errorf("starting playwright: %w", err)
	}

	browserOpts := playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(true),
	}

	if !opts.Headless {
		browserOpts.Headless = playwright.Bool(false)
	}

	if opts.ExecutablePath != "" {
		browserOpts.ExecutablePath = playwright.String(opts.ExecutablePath)
	}

	if opts.Proxy != "" {
		browserOpts.Proxy = &playwright.Proxy{
			Server: opts.Proxy,
		}
	}

	browser, err := pw.WebKit.Launch(browserOpts)
	if err != nil {
		_ = pw.Stop()
		return nil, fmt.Errorf("launching webkit: %w", err)
	}

	return &WebKit{
		pw:      pw,
		browser: browser,
		options: opts,
	}, nil
}

// Name returns the engine identifier.
func (w *WebKit) Name() string {
	return "webkit"
}

// Capabilities returns what this engine supports.
func (w *WebKit) Capabilities() engine.Capabilities {
	return engine.Capabilities{
		JavaScript:        true,
		HTTP2:             true,
		HTTP3:             true,
		PersistentProfile: true,
		NetLogExport:      false,
		WebSocket:         true,
		Intercept:         true,
	}
}

// Do executes a request using WebKit.
func (w *WebKit) Do(_ context.Context, req *engine.Request) (*engine.Response, error) {
	requestID := uuid.New().String()
	w.trace = &engine.Trace{
		Engine:    w.Name(),
		RequestID: requestID,
		Entries:   []engine.TraceEntry{},
	}

	// Create browser context
	contextOpts := playwright.BrowserNewContextOptions{}

	if req.UserAgent != "" {
		contextOpts.UserAgent = playwright.String(req.UserAgent)
	}

	if req.Viewport != nil {
		contextOpts.Viewport = &playwright.Size{
			Width:  req.Viewport.Width,
			Height: req.Viewport.Height,
		}
	}

	browserCtx, err := w.browser.NewContext(contextOpts)
	if err != nil {
		return nil, fmt.Errorf("creating browser context: %w", err)
	}

	defer func() { _ = browserCtx.Close() }()

	// Enable request/response tracing
	networkEntries := make(map[string]*engine.TraceEntry)

	browserCtx.On("request", func(request playwright.Request) {
		entry := &engine.TraceEntry{
			RequestID:   request.URL(),
			URL:         request.URL(),
			Method:      request.Method(),
			RequestTime: time.Now(),
			Request: engine.TraceRequest{
				Headers:  convertMap(request.Headers()),
				BodySize: 0,
			},
		}
		networkEntries[request.URL()] = entry
	})

	browserCtx.On("response", func(response playwright.Response) {
		if entry, ok := networkEntries[response.URL()]; ok {
			entry.Status = response.Status()
			entry.Response = engine.TraceResponse{
				Headers:  convertMap(response.Headers()),
				BodySize: 0,
				MimeType: response.Headers()["content-type"],
			}
		}
	})

	// Create page and navigate
	page, err := browserCtx.NewPage()
	if err != nil {
		return nil, fmt.Errorf("creating page: %w", err)
	}

	// Set extra headers if provided
	if len(req.ExtraHeaders) > 0 {
		if err := page.SetExtraHTTPHeaders(req.ExtraHeaders); err != nil {
			return nil, fmt.Errorf("setting extra headers: %w", err)
		}
	}

	start := time.Now()

	// Navigate
	_, err = page.Goto(req.URL, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateNetworkidle,
	})
	if err != nil {
		return nil, fmt.Errorf("navigating: %w", err)
	}

	// Wait for selector if specified
	if req.WaitForSelector != "" {
		_, err := page.WaitForSelector(req.WaitForSelector) //nolint:staticcheck // SA1019: Intentional use of deprecated API
		if err != nil {
			return nil, fmt.Errorf("waiting for selector: %w", err)
		}
	}

	// Execute JS if requested
	if req.ScriptToExecute != "" {
		_, err = page.Evaluate(req.ScriptToExecute)
		if err != nil {
			return nil, fmt.Errorf("executing script: %w", err)
		}
	}

	// Get page content
	content, err := page.Content()
	if err != nil {
		return nil, fmt.Errorf("getting content: %w", err)
	}

	total := time.Since(start)

	// Build trace entries
	for _, entry := range networkEntries {
		entry.Timing.Total = total
		w.trace.Entries = append(w.trace.Entries, *entry)
	}

	return &engine.Response{
		Status:   200,
		Body:     []byte(content),
		FinalURL: page.URL(),
		Protocol: "h2",
		Trace:    *w.trace,
		Timing: engine.TimingInfo{
			Total: total,
		},
	}, nil
}

// Close cleans up browser resources.
func (w *WebKit) Close() error {
	if w.browser != nil {
		_ = w.browser.Close()
	}
	if w.pw != nil {
		_ = w.pw.Stop()
	}
	return nil
}

func convertMap(m map[string]string) map[string]string {
	result := make(map[string]string)
	for k, v := range m {
		result[k] = v
	}
	return result
}
