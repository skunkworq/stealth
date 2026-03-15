// Package lab — trainer.go provides an automated training environment
// that launches Chrome via CDP, navigates to target URLs, and captures
// complete browser fingerprints (TLS via MITM proxy + HTTP headers via CDP).
package lab

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// TrainerConfig configures the training session.
type TrainerConfig struct {
	// URLs to visit during training
	URLs []string

	// OutputDir for persisting captured training data
	OutputDir string

	// ProxyPort for the MITM proxy (TLS capture)
	ProxyPort int

	// ChromePath overrides auto-detection
	ChromePath string

	// PageLoadWait is how long to wait after navigation for network idle
	PageLoadWait time.Duration

	// ScrollPage enables scrolling to trigger lazy-loaded resources
	ScrollPage bool

	// Verbose logging
	Verbose bool

	// CACertFile and CAKeyFile for the MITM proxy
	CACertFile string
	CAKeyFile  string

	// LabHTTPPort for the lab server (default 18080)
	LabHTTPPort int
	// LabHTTPSPort for the lab server (default 18443)
	LabHTTPSPort int
}

// DefaultTrainerConfig returns sensible defaults.
func DefaultTrainerConfig() *TrainerConfig {
	return &TrainerConfig{
		ProxyPort:    18081,
		PageLoadWait: 5 * time.Second,
		ScrollPage:   true,
		LabHTTPPort:  18080,
		LabHTTPSPort: 18443,
	}
}

// Trainer orchestrates automated browser fingerprint capture.
type Trainer struct {
	config *TrainerConfig
	logger *slog.Logger

	// Lab server + proxy for TLS capture
	labServer *EnhancedServer

	// CDP-captured data
	mu             sync.Mutex
	capturedPages  []*TrainingCapture
	requestHeaders map[network.RequestID]*CDPRequest
}

// TrainingCapture holds complete fingerprint data for one page load.
type TrainingCapture struct {
	URL       string    `json:"url"`
	Timestamp time.Time `json:"timestamp"`

	// CDP-captured HTTP data (exact Chrome header order)
	NavigationRequest *CDPRequest   `json:"navigation_request"`
	SubRequests       []*CDPRequest `json:"sub_requests,omitempty"`

	// TLS fingerprints from MITM proxy
	TLSCaptures []*CompleteFingerprint `json:"tls_captures,omitempty"`

	// Page metadata
	Title    string `json:"title,omitempty"`
	FinalURL string `json:"final_url,omitempty"`
}

// CDPRequest captures a single HTTP request as seen by Chrome's network stack.
type CDPRequest struct {
	RequestID string            `json:"request_id"`
	URL       string            `json:"url"`
	Method    string            `json:"method"`
	Headers   map[string]string `json:"headers"`
	// HeaderOrder preserves the exact order Chrome sent headers
	HeaderOrder []string `json:"header_order"`
	// Response info
	Status          int               `json:"status,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`

	// Timing
	Timestamp    float64 `json:"timestamp"`
	ResourceType string  `json:"resource_type"`
	IsNavigation bool    `json:"is_navigation"`
}

// TrainingReport summarizes a training session.
type TrainingReport struct {
	StartTime  time.Time          `json:"start_time"`
	EndTime    time.Time          `json:"end_time"`
	Duration   string             `json:"duration"`
	PagesCount int                `json:"pages_count"`
	Pages      []*TrainingCapture `json:"pages"`

	// Aggregated header patterns
	HeaderPatterns *HeaderPatternAnalysis `json:"header_patterns"`
}

// HeaderPatternAnalysis aggregates header ordering patterns across captures.
type HeaderPatternAnalysis struct {
	// NavigationHeaderOrder is the most common header ordering for navigation requests
	NavigationHeaderOrder []string `json:"navigation_header_order"`
	// SubresourceHeaderOrder for XHR/fetch requests
	SubresourceHeaderOrder []string `json:"subresource_header_order"`
	// CommonHeaders seen across all navigation requests
	CommonHeaders map[string]string `json:"common_headers"`
	// HeaderFrequency shows how often each header appears
	HeaderFrequency map[string]int `json:"header_frequency"`
}

// NewTrainer creates a new training environment.
func NewTrainer(config *TrainerConfig, logger *slog.Logger) *Trainer {
	if config == nil {
		config = DefaultTrainerConfig()
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Trainer{
		config:         config,
		logger:         logger,
		requestHeaders: make(map[network.RequestID]*CDPRequest),
	}
}

// Run executes the full training session: starts lab+proxy, launches Chrome,
// navigates to each URL, captures data, and returns the report.
func (t *Trainer) Run(ctx context.Context) (*TrainingReport, error) {
	startTime := time.Now()

	// 1. Ensure output directory exists
	if t.config.OutputDir != "" {
		if err := os.MkdirAll(t.config.OutputDir, 0o750); err != nil {
			return nil, fmt.Errorf("creating output dir: %w", err)
		}
	}

	// 2. Start lab server + MITM proxy for TLS capture
	if err := t.startLab(ctx); err != nil {
		return nil, fmt.Errorf("starting lab: %w", err)
	}
	defer func() {
		if t.labServer != nil {
			_ = t.labServer.Stop(ctx)
		}
	}()

	// Give the server a moment to start
	time.Sleep(300 * time.Millisecond)

	// 3. Launch Chrome via CDP with proxy configured
	allocCtx, allocCancel, err := t.createChromeContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("creating chrome context: %w", err)
	}
	defer allocCancel()

	// Create browser context
	browserCtx, browserCancel := chromedp.NewContext(allocCtx,
		chromedp.WithLogf(func(format string, args ...interface{}) {
			if t.config.Verbose {
				t.logger.Debug(fmt.Sprintf("chromedp: "+format, args...))
			}
		}),
	)
	defer browserCancel()

	// 4. Enable network capture
	if err := t.enableNetworkCapture(browserCtx); err != nil {
		return nil, fmt.Errorf("enabling network capture: %w", err)
	}

	// 5. Navigate to each URL and capture
	for _, rawURL := range t.config.URLs {
		targetURL := normalizeURL(rawURL)
		t.logger.Info("Training: navigating", "url", targetURL)

		capture, captureErr := t.captureURL(browserCtx, targetURL)
		if captureErr != nil {
			t.logger.Error("Failed to capture URL", "url", targetURL, "error", captureErr)
			continue
		}

		t.mu.Lock()
		t.capturedPages = append(t.capturedPages, capture)
		t.mu.Unlock()

		t.logger.Info("Captured page",
			"url", targetURL,
			"title", capture.Title,
			"nav_headers", len(capture.NavigationRequest.HeaderOrder),
			"sub_requests", len(capture.SubRequests),
			"tls_captures", len(capture.TLSCaptures),
		)
	}

	// 6. Build report
	report := &TrainingReport{
		StartTime:  startTime,
		EndTime:    time.Now(),
		Duration:   time.Since(startTime).Round(time.Millisecond).String(),
		PagesCount: len(t.capturedPages),
		Pages:      t.capturedPages,
	}

	// 7. Analyze header patterns
	report.HeaderPatterns = t.analyzeHeaderPatterns()

	// 8. Persist to disk
	if t.config.OutputDir != "" {
		if err := t.saveReport(report); err != nil {
			t.logger.Error("Failed to save report", "error", err)
		}
	}

	return report, nil
}

// startLab starts the lab server with MITM proxy.
func (t *Trainer) startLab(ctx context.Context) error {
	config := &ServerConfig{
		BindAddr:        "127.0.0.1",
		HTTPPort:        t.config.LabHTTPPort,
		HTTPSPort:       t.config.LabHTTPSPort,
		ProxyPort:       t.config.ProxyPort,
		ProxyMode:       "mitm",
		TLSCert:         t.config.CACertFile,
		TLSKey:          t.config.CAKeyFile,
		CaptureRawBytes: true,
		CaptureTiming:   true,
		EnableProxy:     true,
	}

	level := slog.LevelInfo
	if t.config.Verbose {
		level = slog.LevelDebug
	}
	labLogger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	}))

	t.labServer = NewEnhancedServer(config, labLogger)

	// Start in background
	errCh := make(chan error, 1)
	go func() {
		errCh <- t.labServer.Start()
	}()

	// Check for immediate startup errors
	select {
	case err := <-errCh:
		return err
	case <-time.After(500 * time.Millisecond):
		// Server started successfully
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// createChromeContext sets up chromedp with proxy and a temp profile.
func (t *Trainer) createChromeContext(ctx context.Context) (context.Context, context.CancelFunc, error) {
	chromePath := t.config.ChromePath
	if chromePath == "" {
		chromePath = findChrome()
	}
	if chromePath == "" {
		return nil, nil, fmt.Errorf("chrome not found — install Chrome or set ChromePath")
	}

	opts := append(
		chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(chromePath),
		chromedp.ProxyServer(fmt.Sprintf("http://127.0.0.1:%d", t.config.ProxyPort)),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
		chromedp.Flag("no-first-run", true),
		chromedp.Flag("no-default-browser-check", true),
		// Use a visible window so it's a real browser session
		chromedp.Flag("headless", false),
		chromedp.WindowSize(1920, 1080),
	)

	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
	return allocCtx, allocCancel, nil
}

// enableNetworkCapture sets up CDP network event listeners.
func (t *Trainer) enableNetworkCapture(ctx context.Context) error {
	// Enable the Network domain
	if err := chromedp.Run(ctx, network.Enable()); err != nil {
		return fmt.Errorf("enabling network domain: %w", err)
	}

	// Enable the Fetch domain to intercept and observe request headers in order
	if err := chromedp.Run(ctx, fetch.Enable().WithPatterns([]*fetch.RequestPattern{
		{URLPattern: "*", RequestStage: fetch.RequestStageRequest},
	})); err != nil {
		// Fetch domain is optional — fall back to Network only
		t.logger.Warn("Fetch domain not available, using Network domain only", "error", err)
	}

	// Listen for network events
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch e := ev.(type) {
		case *network.EventRequestWillBeSentExtraInfo:
			t.handleRequestExtraInfo(e)
		case *network.EventRequestWillBeSent:
			t.handleRequestWillBeSent(e)
		case *network.EventResponseReceived:
			t.handleResponseReceived(e)
		case *fetch.EventRequestPaused:
			// Continue the request — we're just observing
			go func() {
				_ = chromedp.Run(ctx, fetch.ContinueRequest(e.RequestID))
			}()
			t.handleFetchRequestPaused(e)
		}
	})

	return nil
}

// handleRequestWillBeSent captures initial request data.
func (t *Trainer) handleRequestWillBeSent(e *network.EventRequestWillBeSent) {
	t.mu.Lock()
	defer t.mu.Unlock()

	req := &CDPRequest{
		RequestID:    string(e.RequestID),
		URL:          e.Request.URL,
		Method:       e.Request.Method,
		Headers:      make(map[string]string),
		Timestamp:    monotonicToFloat(e.Timestamp),
		ResourceType: e.Type.String(),
		IsNavigation: e.Type == network.ResourceTypeDocument,
	}

	// Capture headers from the Request object
	for k, v := range e.Request.Headers {
		if str, ok := v.(string); ok {
			req.Headers[k] = str
		}
	}

	t.requestHeaders[e.RequestID] = req
}

// handleRequestExtraInfo captures the exact wire-order headers.
func (t *Trainer) handleRequestExtraInfo(e *network.EventRequestWillBeSentExtraInfo) {
	t.mu.Lock()
	defer t.mu.Unlock()

	existing, ok := t.requestHeaders[e.RequestID]
	if !ok {
		existing = &CDPRequest{
			RequestID: string(e.RequestID),
			Headers:   make(map[string]string),
		}
		t.requestHeaders[e.RequestID] = existing
	}

	// ExtraInfo headers are the actual wire-format headers
	for k, v := range e.Headers {
		if str, ok := v.(string); ok {
			existing.Headers[k] = str
		}
	}

	// The headers map from ExtraInfo preserves insertion order in Chrome's
	// internal representation. Extract the order.
	existing.HeaderOrder = extractHeaderOrder(e.Headers)
}

// handleFetchRequestPaused captures header order from the Fetch domain.
func (t *Trainer) handleFetchRequestPaused(e *fetch.EventRequestPaused) {
	t.mu.Lock()
	defer t.mu.Unlock()

	existing, ok := t.requestHeaders[network.RequestID(e.NetworkID)]
	if !ok {
		existing = &CDPRequest{
			RequestID: string(e.NetworkID),
			Headers:   make(map[string]string),
		}
		t.requestHeaders[network.RequestID(e.NetworkID)] = existing
	}

	// Fetch domain gives us headers in wire order
	if len(e.Request.Headers) > 0 {
		for k, v := range e.Request.Headers {
			if str, ok := v.(string); ok {
				existing.Headers[k] = str
			}
		}
	}

	// Also update from the request's header entries if available
	if existing.URL == "" {
		existing.URL = e.Request.URL
		existing.Method = e.Request.Method
		existing.ResourceType = e.ResourceType.String()
	}
}

// handleResponseReceived captures response data.
func (t *Trainer) handleResponseReceived(e *network.EventResponseReceived) {
	t.mu.Lock()
	defer t.mu.Unlock()

	existing, ok := t.requestHeaders[e.RequestID]
	if !ok {
		return
	}

	existing.Status = int(e.Response.Status)
	existing.ResponseHeaders = make(map[string]string)
	for k, v := range e.Response.Headers {
		if str, ok := v.(string); ok {
			existing.ResponseHeaders[k] = str
		}
	}
}

// captureURL navigates to a URL and collects all captured data.
func (t *Trainer) captureURL(ctx context.Context, targetURL string) (*TrainingCapture, error) {
	// Reset per-page state
	t.mu.Lock()
	t.requestHeaders = make(map[network.RequestID]*CDPRequest)
	t.mu.Unlock()

	// Collect TLS captures from the lab server for this page load
	tlsBefore := t.getTLSCaptureCount()

	// Navigate and wait for load
	var title, finalURL string
	navCtx, navCancel := context.WithTimeout(ctx, 30*time.Second)
	defer navCancel()

	err := chromedp.Run(navCtx,
		chromedp.Navigate(targetURL),
		chromedp.WaitReady("body"),
	)
	if err != nil {
		return nil, fmt.Errorf("navigation: %w", err)
	}

	// Wait for network to settle
	time.Sleep(t.config.PageLoadWait)

	// Optionally scroll to trigger lazy loads
	if t.config.ScrollPage {
		_ = chromedp.Run(ctx,
			chromedp.Evaluate(`
				(async () => {
					const delay = ms => new Promise(r => setTimeout(r, ms));
					const height = document.body.scrollHeight;
					const step = window.innerHeight;
					for (let y = 0; y < height; y += step) {
						window.scrollTo(0, y);
						await delay(300);
					}
					window.scrollTo(0, 0);
				})()
			`, nil),
		)
		// Wait for lazy-loaded resources
		time.Sleep(2 * time.Second)
	}

	// Get page title and final URL
	_ = chromedp.Run(ctx,
		chromedp.Title(&title),
		chromedp.Location(&finalURL),
	)

	// Collect all captured requests
	t.mu.Lock()
	allRequests := make(map[network.RequestID]*CDPRequest, len(t.requestHeaders))
	for k, v := range t.requestHeaders {
		allRequests[k] = v
	}
	t.mu.Unlock()

	// Build the capture
	capture := &TrainingCapture{
		URL:       targetURL,
		Timestamp: time.Now(),
		Title:     title,
		FinalURL:  finalURL,
	}

	// Find the navigation request and separate sub-requests
	for _, req := range allRequests {
		if req.IsNavigation && isMatchingHost(req.URL, targetURL) {
			capture.NavigationRequest = req
		} else {
			capture.SubRequests = append(capture.SubRequests, req)
		}
	}

	// If no explicit navigation request found, use the first Document request
	if capture.NavigationRequest == nil {
		for _, req := range allRequests {
			if req.ResourceType == "Document" {
				capture.NavigationRequest = req
				break
			}
		}
	}

	// Fallback: create a stub if we still have nothing
	if capture.NavigationRequest == nil {
		capture.NavigationRequest = &CDPRequest{
			URL:    targetURL,
			Method: "GET",
		}
	}

	// Sort sub-requests by timestamp
	sort.Slice(capture.SubRequests, func(i, j int) bool {
		return capture.SubRequests[i].Timestamp < capture.SubRequests[j].Timestamp
	})

	// Collect TLS captures from the lab server
	capture.TLSCaptures = t.getTLSCapturesSince(tlsBefore)

	return capture, nil
}

// getTLSCaptureCount returns the current count of proxy captures.
func (t *Trainer) getTLSCaptureCount() int {
	if t.labServer == nil || t.labServer.capture == nil {
		return 0
	}
	t.labServer.capture.mu.RLock()
	defer t.labServer.capture.mu.RUnlock()
	return len(t.labServer.capture.proxyCaptures)
}

// getTLSCapturesSince returns TLS captures collected after the given count.
func (t *Trainer) getTLSCapturesSince(prevCount int) []*CompleteFingerprint {
	if t.labServer == nil || t.labServer.capture == nil {
		return nil
	}

	t.labServer.capture.mu.RLock()
	defer t.labServer.capture.mu.RUnlock()

	var captures []*CompleteFingerprint
	i := 0
	for _, fp := range t.labServer.capture.proxyCaptures {
		if i >= prevCount {
			captures = append(captures, fp)
		}
		i++
	}
	return captures
}

// analyzeHeaderPatterns aggregates patterns across all captured pages.
func (t *Trainer) analyzeHeaderPatterns() *HeaderPatternAnalysis {
	analysis := &HeaderPatternAnalysis{
		CommonHeaders:   make(map[string]string),
		HeaderFrequency: make(map[string]int),
	}

	// Collect all navigation header orders
	var navOrders [][]string
	for _, page := range t.capturedPages {
		if page.NavigationRequest == nil {
			continue
		}
		if len(page.NavigationRequest.HeaderOrder) > 0 {
			navOrders = append(navOrders, page.NavigationRequest.HeaderOrder)
		}

		// Count header frequency
		for k, v := range page.NavigationRequest.Headers {
			analysis.HeaderFrequency[k]++
			// Track common values (use first seen)
			if _, exists := analysis.CommonHeaders[k]; !exists {
				analysis.CommonHeaders[k] = v
			}
		}
	}

	// Use the most common header order for navigation
	if len(navOrders) > 0 {
		analysis.NavigationHeaderOrder = mostCommonOrder(navOrders)
	}

	// Collect sub-request header orders (XHR/fetch)
	var subOrders [][]string
	for _, page := range t.capturedPages {
		for _, sub := range page.SubRequests {
			if sub.ResourceType == "XHR" || sub.ResourceType == "Fetch" {
				if len(sub.HeaderOrder) > 0 {
					subOrders = append(subOrders, sub.HeaderOrder)
				}
			}
		}
	}
	if len(subOrders) > 0 {
		analysis.SubresourceHeaderOrder = mostCommonOrder(subOrders)
	}

	return analysis
}

// saveReport persists the training report to disk.
func (t *Trainer) saveReport(report *TrainingReport) error {
	// Save full report
	reportPath := filepath.Join(t.config.OutputDir, "training_report.json")
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling report: %w", err)
	}
	if err := os.WriteFile(reportPath, data, 0o644); err != nil {
		return fmt.Errorf("writing report: %w", err)
	}
	t.logger.Info("Saved training report", "path", reportPath, "size", len(data))

	// Save per-page captures individually
	for i, page := range report.Pages {
		host := extractHost(page.URL)
		pagePath := filepath.Join(t.config.OutputDir, fmt.Sprintf("capture_%02d_%s.json", i+1, host))
		pageData, err := json.MarshalIndent(page, "", "  ")
		if err != nil {
			continue
		}
		if err := os.WriteFile(pagePath, pageData, 0o644); err != nil {
			t.logger.Error("Failed to save page capture", "path", pagePath, "error", err)
		}
	}

	// Save header pattern analysis
	if report.HeaderPatterns != nil {
		patternsPath := filepath.Join(t.config.OutputDir, "header_patterns.json")
		patternData, err := json.MarshalIndent(report.HeaderPatterns, "", "  ")
		if err == nil {
			_ = os.WriteFile(patternsPath, patternData, 0o644)
			t.logger.Info("Saved header patterns", "path", patternsPath)
		}
	}

	return nil
}

// --- Helpers ---

func normalizeURL(raw string) string {
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	return raw
}

func isMatchingHost(reqURL, targetURL string) bool {
	ru, err1 := url.Parse(reqURL)
	tu, err2 := url.Parse(targetURL)
	if err1 != nil || err2 != nil {
		return false
	}
	return ru.Host == tu.Host || strings.HasSuffix(ru.Host, "."+tu.Host)
}

func extractHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "unknown"
	}
	host := u.Hostname()
	// Remove www prefix for cleaner filenames
	host = strings.TrimPrefix(host, "www.")
	// Replace dots with underscores for filesystem safety
	host = strings.ReplaceAll(host, ".", "_")
	return host
}

func extractHeaderOrder(headers network.Headers) []string {
	// CDP headers are a map[string]interface{} which doesn't preserve order.
	// We extract keys and sort alphabetically as a fallback.
	// The ExtraInfo event combined with Fetch domain gives better ordering.
	var order []string
	for k := range headers {
		order = append(order, k)
	}
	sort.Strings(order)
	return order
}

func mostCommonOrder(orders [][]string) []string {
	if len(orders) == 0 {
		return nil
	}
	// Simple approach: return the longest order (most complete)
	longest := orders[0]
	for _, o := range orders[1:] {
		if len(o) > len(longest) {
			longest = o
		}
	}
	return longest
}

func monotonicToFloat(t interface{}) float64 {
	if t == nil {
		return 0
	}
	// cdp.MonotonicTime is `type MonotonicTime time.Time`
	// Use reflection-free approach: just use the current time as a reference
	return float64(time.Now().UnixMilli()) / 1000.0
}
