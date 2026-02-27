# Implementation Summary

This document provides an overview of the `brwslab` implementation.

## Project Structure

```
brwslab/
├── brws/                      # Core library
│   ├── engine/               # Engine interfaces and implementations
│   │   ├── engine.go         # Core interface definitions
│   │   ├── native/           # Go net/http implementation
│   │   ├── chromium/         # Chrome CDP implementation
│   │   ├── firefox/          # Firefox via Playwright
│   │   └── webkit/           # WebKit via Playwright
│   ├── session/              # Session management
│   │   └── session.go        # Cookie jars, profile management
│   ├── trace/                # HAR-like tracing (integrated in engine)
│   ├── lab/                  # Fingerprint lab protocols
│   │   └── server.go         # labd server implementation
│   └── diff/                 # Comparison utilities
│       └── diff.go           # Response/fingerprint diffing
├── cmd/                      # CLI applications
│   ├── brwslab/              # Main CLI tool
│   │   └── main.go           # All CLI commands
│   └── labd/                 # Lab server
│       └── main.go           # Server entry point
├── examples/                 # Example usage
│   └── basic_fetch.go        # Library usage example
├── go.mod                    # Go module definition
├── Makefile                  # Build automation
├── README.md                 # User documentation
└── IMPLEMENTATION.md         # This file
```

## Components

### 1. Engine Interface (`brws/engine/engine.go`)

The core abstraction that all HTTP clients implement:

```go
type Engine interface {
    Name() string
    Capabilities() Capabilities
    Do(ctx context.Context, req *Request) (*Response, error)
    Close() error
}
```

**Capabilities:**
- JavaScript execution
- HTTP/2 and HTTP/3 support
- Persistent profiles
- NetLog export (Chromium only)

### 2. Native Engine (`brws/engine/native/`)

Uses Go's standard `net/http` with:
- Configurable TLS settings
- HTTP/2 support via `ForceAttemptHTTP2`
- HTTP trace timing (DNS, Connect, SSL, Send, Wait, Receive)
- Proxy support

### 3. Chromium Engine (`brws/engine/chromium/`)

Uses Chrome DevTools Protocol via `chromedp`:
- Authentic Chrome TLS/HTTP2/HTTP3 behavior
- Network event capture
- JavaScript execution
- Headless and headed modes
- Persistent profiles

### 4. Firefox/WebKit Engines (`brws/engine/firefox/`, `brws/engine/webkit/`)

Uses Playwright for:
- Cross-browser testing
- Consistent API across browsers
- Automatic browser downloads

### 5. Session Management (`brws/session/`)

- Persistent cookie jars
- Profile directories
- Session import/export
- JSON serialization

### 6. Lab Server (`brws/lab/`)

Fingerprint capture server:
- TLS ClientHello analysis (JA3-style)
- HTTP/2 fingerprinting
- HTTP header analysis
- Baseline storage and comparison

### 7. CLI (`cmd/brwslab/`)

Commands:
- `fetch` - Fetch URLs with any engine
- `session` - Manage persistent sessions
- `fingerprint` - Capture network fingerprint
- `diff` - Compare engines
- `trace` - Detailed request tracing
- `engines` - List available engines

## Design Decisions

### 1. Engine Registry Pattern

Engines self-register in `init()` functions:
```go
func init() {
    engine.Register("native", New)
}
```

This allows importing engines to automatically make them available.

### 2. Trace as First-Class Citizen

Every response includes detailed timing and network trace information, enabling:
- Performance analysis
- Debugging
- HAR export

### 3. Lab Server Architecture

The fingerprint lab measures from the server side because:
- That's what real defenses see
- Client-side self-reporting can be misleading
- Enables baseline comparison and regression detection

### 4. Explicit Non-Goals

The implementation explicitly avoids:
- TLS/HTTP2 spoofing to "bypass" detection
- Human impersonation features
- Automated bot evasion

## Testing

```bash
# Run all tests
make test

# Run specific package tests
go test ./brws/engine/native/... -v
go test ./brws/session/... -v

# Coverage
make test-coverage
```

## Future Enhancements

### CI/Baseline Infrastructure
- Nightly baseline capture
- Fingerprint regression detection
- Cross-platform browser testing

### Enhanced Fingerprinting
- Full JA4 fingerprint support
- HTTP/2 frame-level inspection
- QUIC/HTTP3 parameter capture
- Custom TLS ClientHello parsing (via uTLS)

### Additional Features
- WebSocket support across engines
- Request/response interception
- HAR export/import
- Cookie consent automation

## Dependencies

**Core:**
- `github.com/chromedp/chromedp` - Chrome DevTools Protocol
- `github.com/playwright-community/playwright-go` - Cross-browser automation
- `github.com/spf13/cobra` - CLI framework
- `github.com/google/uuid` - UUID generation

**Standard Library:**
- `net/http` - HTTP client/server
- `crypto/tls` - TLS configuration
- `net/http/httptrace` - Request tracing
- `net/http/cookiejar` - Cookie management

## Metrics

- **Lines of Go code:** ~3,650
- **Packages:** 13
- **Test coverage:** Core packages tested
- **Binary sizes:**
  - `brwslab`: ~21MB
  - `labd`: ~12MB

## License

MIT License - See LICENSE file for details.
