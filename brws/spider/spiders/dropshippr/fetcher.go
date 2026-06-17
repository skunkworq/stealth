package dropshippr

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/skunkworq/stealth/brws/engine"
	// Side-effect imports: register engines into the global engine registry.
	_ "github.com/skunkworq/stealth/brws/engine/chromium"
	_ "github.com/skunkworq/stealth/brws/engine/native"
)

// Fetcher wraps a stealth-configured native engine with sane defaults.
// It impersonates Chrome 120 macOS at the TLS layer (uTLS HelloChrome_Auto)
// and applies the matching header profile, which is enough to clear most
// non-Cloudflare TLS/HTTP2 fingerprint checks. For Cloudflare-managed sites,
// callers should wrap this in `brws/stealth.Client` with AutoSolve enabled.
type Fetcher struct {
	eng       engine.Engine
	timeout   time.Duration
	warmedMu  sync.Mutex
	warmedSet map[string]time.Time // host → last warm-up at
}

var (
	fetcherMu  sync.Mutex
	fetcherMap = map[string]*Fetcher{}
)

// DefaultFetcher returns the process-wide native-stealth Fetcher.
func DefaultFetcher() (*Fetcher, error) {
	return FetcherFor(FetcherKey{EngineName: "native", ProfileName: "chrome-120-macos"})
}

// FetcherKey identifies a memoised Fetcher.
type FetcherKey struct {
	EngineName  string
	ProfileName string
	Proxy       string
	DebuggerURL string // CDP URL of an already-running Chrome (http://host:port)
}

// FetcherFor returns a memoised Fetcher for the given key tuple.
func FetcherFor(k FetcherKey) (*Fetcher, error) {
	if k.EngineName == "" {
		k.EngineName = "native"
	}
	if k.ProfileName == "" {
		k.ProfileName = "chrome-120-macos"
	}
	cacheKey := k.EngineName + "|" + k.ProfileName + "|" + k.Proxy + "|" + k.DebuggerURL
	fetcherMu.Lock()
	defer fetcherMu.Unlock()
	if f, ok := fetcherMap[cacheKey]; ok {
		return f, nil
	}
	f, err := NewFetcher(FetcherOptions{
		EngineName:  k.EngineName,
		ProfileName: k.ProfileName,
		Proxy:       k.Proxy,
		DebuggerURL: k.DebuggerURL,
		Timeout:     30 * time.Second,
		HTTP2:       true,
	})
	if err != nil {
		return nil, err
	}
	fetcherMap[cacheKey] = f
	return f, nil
}

type FetcherOptions struct {
	EngineName  string // "native" (default), "chromium", "chromium-stealth", "firefox", "webkit"
	ProfileName string
	Proxy       string
	DebuggerURL string // CDP URL — when set, attach to running Chrome instead of spawning headless
	Timeout     time.Duration
	HTTP2       bool
}

func NewFetcher(o FetcherOptions) (*Fetcher, error) {
	if o.EngineName == "" {
		o.EngineName = "native"
	}
	if o.ProfileName == "" {
		o.ProfileName = "chrome-120-macos"
	}
	if o.Timeout == 0 {
		o.Timeout = 30 * time.Second
	}
	eng, err := engine.New(o.EngineName, engine.Options{
		Stealth:     true,
		StealthTLS:  true,
		ProfileName: o.ProfileName,
		Proxy:       o.Proxy,
		DebuggerURL: o.DebuggerURL,
		Timeout:     o.Timeout,
		HTTP2:       o.HTTP2,
		Headless:    true,
	})
	if err != nil {
		return nil, fmt.Errorf("init %s stealth engine: %w", o.EngineName, err)
	}
	return &Fetcher{
		eng:       eng,
		timeout:   o.Timeout,
		warmedSet: make(map[string]time.Time),
	}, nil
}

// WarmUp navigates the engine to a site's home page once per host so the
// session inherits cookies, analytics tokens, and first-touch fingerprint
// before the actual search URLs hit. Subsequent calls for the same host
// within `freshness` are no-ops.
//
// This matters for AE/Amazon: cold sessions opening 30 consecutive search
// URLs trip rate-limiters; a single home-page navigate + brief pause
// dramatically extends the safe-burst window.
func (f *Fetcher) WarmUp(ctx context.Context, homeURL string, freshness time.Duration) error {
	host := hostOf(homeURL)
	f.warmedMu.Lock()
	last, ok := f.warmedSet[host]
	f.warmedMu.Unlock()
	if ok && time.Since(last) < freshness {
		return nil
	}
	if _, err := f.Get(ctx, homeURL, map[string]string{
		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	}); err != nil {
		return fmt.Errorf("warmup %s: %w", homeURL, err)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(2 * time.Second):
	}
	f.warmedMu.Lock()
	f.warmedSet[host] = time.Now()
	f.warmedMu.Unlock()
	return nil
}

func hostOf(rawURL string) string {
	s := strings.TrimPrefix(rawURL, "https://")
	s = strings.TrimPrefix(s, "http://")
	if i := strings.Index(s, "/"); i >= 0 {
		s = s[:i]
	}
	return s
}

// FetcherFromJob picks a Fetcher matching the CrawlJob's engine_hint and
// params. Recognised params:
//
//	profile        — uTLS / Chrome profile name (default "chrome-120-macos")
//	proxy          — proxy URL
//	debugger_url   — CDP endpoint of an already-running Chrome (e.g.
//	                 "http://localhost:9222"). Requires ENGINE_CHROMIUM.
//
// ENGINE_CHROMIUM routes through "chromium-stealth" which sets the full
// nodriver-style allocator flag set. When debugger_url is set, the stealth
// engine instead attaches to the existing Chrome session — far more reliable
// against Amazon/AliExpress/Temu since you inherit the host's residential IP,
// real cookies, and any past CAPTCHA clearances.
func FetcherFromJob(hint string, params map[string]string) (*Fetcher, error) {
	name := "native"
	switch strings.ToLower(hint) {
	case "engine_chromium", "chromium":
		name = "chromium-stealth"
	case "engine_firefox", "firefox":
		name = "firefox"
	}
	return FetcherFor(FetcherKey{
		EngineName:  name,
		ProfileName: params["profile"],
		Proxy:       params["proxy"],
		DebuggerURL: params["debugger_url"],
	})
}

// FetchResult bundles the response body with its status and final URL.
type FetchResult struct {
	Body       []byte
	Status     int
	FinalURL   string
	DurationMs int64
}

// Get issues a GET with optional header overrides.
func (f *Fetcher) Get(ctx context.Context, url string, extraHeaders map[string]string) (*FetchResult, error) {
	start := time.Now()
	resp, err := f.eng.Do(ctx, &engine.Request{
		Method:          "GET",
		URL:             url,
		FollowRedirects: true,
		Timeout:         f.timeout,
		ExtraHeaders:    extraHeaders,
	})
	if err != nil {
		return nil, err
	}
	r := &FetchResult{
		Body:       resp.Body,
		Status:     resp.Status,
		FinalURL:   resp.FinalURL,
		DurationMs: time.Since(start).Milliseconds(),
	}
	if resp.Status >= 400 {
		return r, fmt.Errorf("http %d", resp.Status)
	}
	return r, nil
}

// GetReader returns the response body as a reader for streaming JSON decoders.
func (f *Fetcher) GetReader(ctx context.Context, url string, extra map[string]string) (io.Reader, int, error) {
	r, err := f.Get(ctx, url, extra)
	if err != nil && r == nil {
		return nil, 0, err
	}
	if r == nil {
		return nil, 0, err
	}
	return strings.NewReader(string(r.Body)), r.Status, err
}
