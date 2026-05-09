// Package engine defines the core interfaces for HTTP clients that can
// execute requests through different underlying implementations (native Go,
// Chromium, Firefox, WebKit).
package engine

import (
	"context"
	"fmt"
	"time"
)

// Engine is the abstraction for any HTTP request engine.
// Implementations include native Go net/http, Chromium CDP, Firefox/WebKit via Playwright.
type Engine interface {
	// Name returns the engine identifier (e.g., "native", "chromium", "firefox", "webkit")
	Name() string

	// Capabilities returns what this engine supports
	Capabilities() Capabilities

	// Do executes a request and returns a response
	Do(ctx context.Context, req *Request) (*Response, error)

	// Close cleans up any resources (browser processes, connections, etc.)
	Close() error
}

// Capabilities describes what an engine can do.
type Capabilities struct {
	JavaScript        bool // Can execute JS
	HTTP2             bool // Supports HTTP/2
	HTTP3             bool // Supports HTTP/3/QUIC
	PersistentProfile bool // Can use persistent browser profiles
	NetLogExport      bool // Can export detailed network logs (Chromium NetLog)
	WebSocket         bool // Supports WebSocket connections
	Intercept         bool // Can intercept/modify requests
}

// InteractiveEngine is an optional interface that engines may implement
// to support human-like browser interactions (mouse, keyboard, scroll).
// Callers should check capabilities or type-assert before using these methods.
type InteractiveEngine interface {
	Engine
	// Mouse moves the cursor to the specified coordinates.
	Mouse(x, y float64) error
	// Click performs a mouse click at the specified coordinates.
	Click(x, y float64) error
	// Type simulates human-like typing.
	Type(text string) error
	// Scroll scrolls the page by the specified amount.
	Scroll(pixels float64) error
	// ScrollTo scrolls to a specific Y position.
	ScrollTo(y float64) error
}

// TabEngine is an optional interface that engines may implement
// to support executing requests on an existing browser tab context
// instead of creating a fresh tab per request.
type TabEngine interface {
	Engine
	// DoOnTab executes a request on an existing tab context.
	// The tabCtx must be a valid chromedp context.
	DoOnTab(ctx context.Context, tabCtx context.Context, req *Request) (*Response, error)
}

// Request is a unified HTTP request structure.
type Request struct {
	Method  string
	URL     string
	Headers map[string][]string
	Body    []byte

	// Behavior knobs
	FollowRedirects bool
	MaxRedirects    int
	Timeout         time.Duration

	// Session integration
	SessionID     string
	FingerprintID string // Links to a cached CompleteFingerprint for consistent identity

	// Browser-specific options
	WaitForNavigation bool              // Wait for page load complete (browser engines)
	WaitForSelector   string            // Wait for specific element (browser engines)
	ScriptToExecute   string            // Execute JS after load (browser engines)
	Viewport          *Viewport         // Browser viewport settings
	UserAgent         string            // Override User-Agent
	ExtraHeaders      map[string]string // Additional headers to inject
	Referrer          string            // Navigation referrer for history/context simulation (StealthPlus)
}

// Viewport defines browser viewport dimensions.
type Viewport struct {
	Width  int
	Height int
}

// Response is a unified HTTP response structure.
type Response struct {
	Status     int
	StatusText string
	Headers    map[string][]string
	Body       []byte
	FinalURL   string
	Protocol   string // "h2", "h3", "http/1.1"

	// Trace contains engine-specific trace data (HAR-like, NetLog, etc.)
	Trace Trace

	// Timing information
	Timing TimingInfo
}

// Trace holds diagnostic information about the request execution.
type Trace struct {
	Engine    string                 `json:"engine"`
	RequestID string                 `json:"request_id"`
	Entries   []TraceEntry           `json:"entries,omitempty"`
	Raw       map[string]interface{} `json:"raw,omitempty"` // Engine-specific extras
}

// TraceEntry represents a single network event (HAR-like).
type TraceEntry struct {
	RequestID   string        `json:"request_id"`
	URL         string        `json:"url"`
	Method      string        `json:"method"`
	Status      int           `json:"status"`
	Protocol    string        `json:"protocol,omitempty"`
	RemoteAddr  string        `json:"remote_addr,omitempty"`
	RequestTime time.Time     `json:"request_time"`
	Timing      TimingInfo    `json:"timing,omitempty"`
	Request     TraceRequest  `json:"request"`
	Response    TraceResponse `json:"response,omitempty"`
}

// TraceRequest captures request details for tracing.
type TraceRequest struct {
	Headers  map[string]string `json:"headers"`
	BodySize int64             `json:"body_size"`
}

// TraceResponse captures response details for tracing.
type TraceResponse struct {
	Headers  map[string]string `json:"headers"`
	BodySize int64             `json:"body_size"`
	MimeType string            `json:"mime_type,omitempty"`
}

// TimingInfo holds timing data for a request (HAR-like).
type TimingInfo struct {
	Blocked time.Duration `json:"blocked,omitempty"`
	DNS     time.Duration `json:"dns,omitempty"`
	Connect time.Duration `json:"connect,omitempty"`
	SSL     time.Duration `json:"ssl,omitempty"`
	Send    time.Duration `json:"send,omitempty"`
	Wait    time.Duration `json:"wait,omitempty"`
	Receive time.Duration `json:"receive,omitempty"`
	Total   time.Duration `json:"total,omitempty"`
}

// Registry holds engine constructors.
var registry = make(map[string]Constructor)

// Constructor creates a new Engine instance.
type Constructor func(opts Options) (Engine, error)

// Options for creating an engine.
type Options struct {
	// General options
	Proxy              string
	DNS                string
	IPv6               bool
	HTTP2              bool
	HTTP3              bool
	Timeout            time.Duration
	InsecureSkipVerify bool

	// Stealth options
	Stealth          bool        // Enable automatic header spoofing
	StealthTLS       bool        // Enable TLS fingerprint spoofing
	StealthConfigRaw interface{} // Pass-through for advanced dynamic RL Spoofer configs

	// Browser profile (for Stealth mode)
	// Examples: "chrome-120-macos", "firefox-120-windows", "safari-16-macos", "edge-120-windows"
	ProfileName string

	// Custom headers (merged with profile headers)
	CustomHeaders map[string]string

	// Browser-specific options
	Headless       bool
	ProfileDir     string
	ExecutablePath string
	UserDataDir    string

	// CDP/WebDriver options
	DebuggerURL string
	WSURL       string
}

// BrowserProfile defines what browser to emulate for fingerprinting.
type BrowserProfile struct {
	Name           string            // chrome, firefox, safari, edge
	Version        string            // browser version (e.g., "120")
	Platform       string            // windows, macos, linux, android, ios
	Mobile         bool              // mobile device emulation
	Headers        map[string]string // Custom headers (merged with defaults)
	TLSFingerprint string            // TLS fingerprint to use (chrome_120, firefox_120, safari_16, etc.)
}

// GetFingerprint returns the TLS fingerprint identifier for this profile.
func (bp *BrowserProfile) GetFingerprint() string {
	if bp.TLSFingerprint != "" {
		return bp.TLSFingerprint
	}
	return bp.Name + "_" + bp.Version
}

// Register adds an engine constructor to the registry.
func Register(name string, ctor Constructor) {
	registry[name] = ctor
}

// New creates an engine by name.
func New(name string, opts Options) (Engine, error) {
	ctor, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown engine: %s", name)
	}
	return ctor(opts)
}

// Available returns the list of registered engine names.
func Available() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	return names
}
