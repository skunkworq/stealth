// Package firefox implements the Engine interface using Playwright.
// Firefox doesn't have as mature a CDP implementation as Chromium,
// so Playwright provides the most stable automation surface.
package firefox

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/playwright-community/playwright-go"
	"github.com/stealth/brwslab/brws/engine"
)

func init() {
	engine.Register("firefox", New)
}

// Firefox implements the Engine interface using Playwright.
type Firefox struct {
	pw      *playwright.Playwright
	browser playwright.Browser
	context playwright.BrowserContext 
	options engine.Options
	trace   *engine.Trace
}

// New creates a new Firefox engine.
func New(opts engine.Options) (engine.Engine, error) {
	// Install Playwright if needed
	if err := installPlaywright(); err != nil {
		return nil, fmt.Errorf("installing playwright: %w", err)
	}

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

	browser, err := pw.Firefox.Launch(browserOpts)
	if err != nil {
		_ = pw.Stop()
		return nil, fmt.Errorf("launching firefox: %w", err)
	}

	return &Firefox{
		pw:      pw,
		browser: browser,
		options: opts,
	}, nil
}

// Name returns the engine identifier.
func (f *Firefox) Name() string {
	return "firefox"
}

// Capabilities returns what this engine supports.
func (f *Firefox) Capabilities() engine.Capabilities {
	return engine.Capabilities{
		JavaScript:        true,
		HTTP2:             true,
		HTTP3:             true,
		PersistentProfile: true,
		NetLogExport:      false, // Firefox doesn't have NetLog equivalent
		WebSocket:         true,
		Intercept:         true,
	}
}

// Do executes a request using Firefox.
func (f *Firefox) Do(_ context.Context, req *engine.Request) (*engine.Response, error) {
	requestID := uuid.New().String()
	f.trace = &engine.Trace{
		Engine:    f.Name(),
		RequestID: requestID,
		Entries:   []engine.TraceEntry{},
	}

	// Create browser context with options
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

	browserCtx, err := f.browser.NewContext(contextOpts)
	if err != nil {
		return nil, fmt.Errorf("creating browser context: %w", err)
	}

	defer func() { _ = browserCtx.Close() }()

	// Enable request/response tracing
	networkEntries := make(map[string]*engine.TraceEntry)

	browserCtx.On("request", func(request playwright.Request) {
		entry := &engine.TraceEntry{
			RequestID:   request.URL(), // Using URL as ID since Playwright doesn't expose internal request ID
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
			entry.Protocol = response.Headers()["server-protocol"] // May not be available
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
		f.trace.Entries = append(f.trace.Entries, *entry)
	}

	// Get main response details
	finalURL := page.URL()
	status := 200 // Default, would need to track via response event

	// Get status from first response entry if available
	if len(networkEntries) > 0 {
		for _, entry := range networkEntries {
			if entry.URL == req.URL || entry.URL == finalURL {
				status = entry.Status
				break
			}
		}
	}

	return &engine.Response{
		Status:   status,
		Body:     []byte(content),
		FinalURL: finalURL,
		Protocol: "h2", // Firefox uses HTTP/2 by default
		Trace:    *f.trace,
		Timing: engine.TimingInfo{
			Total: total,
		},
	}, nil
}

// Close cleans up browser resources.
func (f *Firefox) Close() error {
	if f.browser != nil {
		_ = f.browser.Close()
	}
	if f.pw != nil {
		_ = f.pw.Stop()
	}
	return nil
}

func installPlaywright() error {
	// Check if playwright is already installed
	_, err := playwright.Run()
	if err == nil {
		return nil
	}
	// Note: In production, you'd want to handle driver installation
	// For now, assume the user has run: go run github.com/playwright-community/playwright-go/cmd/playwright@latest install --with-deps
	return nil
}

func convertMap(m map[string]string) map[string]string {
	result := make(map[string]string)
	for k, v := range m {
		result[k] = v
	}
	return result
}
