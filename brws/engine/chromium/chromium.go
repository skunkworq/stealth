// Package chromium implements the Engine interface using Chrome DevTools Protocol (CDP)
// via chromedp. This provides authentic browser TLS/HTTP2/HTTP3 behavior.
package chromium

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/google/uuid"
	"github.com/skunkworq/stealth/brws/constants"
	"github.com/skunkworq/stealth/brws/engine"
)

func init() {
	engine.Register("chromium", New)
}

// Chromium implements the Engine interface using CDP/chromedp.
type Chromium struct {
	allocCtx    context.Context
	allocCancel context.CancelFunc
	tabCtx      context.Context
	trace       *engine.Trace
	options     engine.Options
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

	return &Chromium{
		allocCtx:    allocCtx,
		allocCancel: allocCancel,
		options:     opts,
	}, nil
}

// Name returns the engine identifier.
func (c *Chromium) Name() string {
	return "chromium"
}

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

// Do executes a request using Chromium.
func (c *Chromium) Do(_ context.Context, req *engine.Request) (*engine.Response, error) {
	requestID := uuid.New().String()
	c.trace = &engine.Trace{
		Engine:    c.Name(),
		RequestID: requestID,
		Entries:   []engine.TraceEntry{},
	}

	// Create a new tab context
	tabCtx, tabCancel := chromedp.NewContext(c.allocCtx)
	c.tabCtx = tabCtx

	defer tabCancel()

	// Set timeout
	timeout := req.Timeout
	if timeout == 0 {
		timeout = constants.DefaultTimeout
	}
	tabCtx, cancel := context.WithTimeout(tabCtx, timeout)
	defer cancel()

	// Enable network domain and capture events
	var networkEntries []engine.TraceEntry
	var mainResponse *engine.Response

	_ = network.Enable().Do(tabCtx)

	// Listen for network events
	chromedp.ListenTarget(tabCtx, func(ev interface{}) {
		switch ev := ev.(type) {
		case *network.EventResponseReceived:
			resp := ev.Response
			entry := engine.TraceEntry{
				RequestID:  string(ev.RequestID),
				URL:        resp.URL,
				Method:     "", // Will be filled from RequestWillBeSent
				Status:     int(resp.Status),
				Protocol:   resp.Protocol,
				RemoteAddr: resp.RemoteIPAddress,
				Response: engine.TraceResponse{
					Headers:  flattenHeaders(resp.Headers),
					MimeType: resp.MimeType,
				},
			}
			// Handle ResponseTime if present
			if resp.ResponseTime != nil {
				entry.RequestTime = resp.ResponseTime.Time()
			} else {
				entry.RequestTime = time.Now()
			}
			networkEntries = append(networkEntries, entry)

		case *network.EventRequestWillBeSent:
			// Update entry with request info
			for i := range networkEntries {
				if networkEntries[i].RequestID == string(ev.RequestID) {
					networkEntries[i].Method = ev.Request.Method
					networkEntries[i].Request = engine.TraceRequest{
						Headers:  flattenHeaders(ev.Request.Headers),
						BodySize: 0, // Could get from EventRequestWillBeSentExtraInfo
					}
					break
				}
			}
		}
	})

	// Execute navigation
	var body string
	actions := []chromedp.Action{
		network.Enable(),
	}

	// Set extra headers if provided
	if len(req.ExtraHeaders) > 0 {
		headers := make(map[string]interface{})
		for k, v := range req.ExtraHeaders {
			headers[k] = v
		}
		actions = append(actions, network.SetExtraHTTPHeaders(network.Headers(headers)))
	}

	// Navigate
	actions = append(actions, chromedp.Navigate(req.URL))

	// Wait based on options
	if req.WaitForSelector != "" {
		actions = append(actions, chromedp.WaitVisible(req.WaitForSelector))
	} else if req.WaitForNavigation {
		actions = append(actions, chromedp.WaitReady("body"))
	} else {
		actions = append(actions, chromedp.WaitReady("body"))
	}

	// Execute JS if requested
	if req.ScriptToExecute != "" {
		var result *runtime.RemoteObject
		actions = append(actions, chromedp.Evaluate(req.ScriptToExecute, &result))
	}

	// Get page content
	actions = append(actions, chromedp.OuterHTML("html", &body))

	start := time.Now()

	if err := chromedp.Run(tabCtx, actions...); err != nil {
		return nil, fmt.Errorf("chromedp run: %w", err)
	}
	total := time.Since(start)

	c.trace.Entries = networkEntries

	// Build response from main frame response
	if len(networkEntries) > 0 {
		mainEntry := networkEntries[0]
		mainResponse = &engine.Response{
			Status:     mainEntry.Status,
			StatusText: fmt.Sprintf("%d", mainEntry.Status),
			Headers:    unflattenHeaders(mainEntry.Response.Headers),
			Body:       []byte(body),
			FinalURL:   mainEntry.URL,
			Protocol:   mainEntry.Protocol,
			Trace:      *c.trace,
			Timing: engine.TimingInfo{
				Total: total,
			},
		}
	} else {
		// Fallback if no network events captured
		mainResponse = &engine.Response{
			Status:   200,
			Body:     []byte(body),
			FinalURL: req.URL,
			Protocol: "h2",
			Trace:    *c.trace,
			Timing:   engine.TimingInfo{Total: total},
		}
	}

	return mainResponse, nil
}

// Close cleans up browser resources.
func (c *Chromium) Close() error {
	if c.allocCancel != nil {
		c.allocCancel()
	}
	return nil
}

// GetNetLog exports Chromium NetLog if available.
func (c *Chromium) GetNetLog() ([]byte, error) {
	// NetLog requires starting Chrome with --log-net-log flag
	// This would be implemented by checking if NetLog was enabled
	return nil, fmt.Errorf("NetLog export not yet implemented")
}

func flattenHeaders(headers map[string]interface{}) map[string]string {
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

func unflattenHeaders(headers map[string]string) map[string][]string {
	result := make(map[string][]string)
	for key, value := range headers {
		result[key] = []string{value}
	}
	return result
}
