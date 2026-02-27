# brwslab

A Go CLI + library for **browser-grade network fidelity** and **fingerprint observability**.

## Overview

`brwslab` provides legitimate testing capabilities by supporting real browser engines alongside native Go networking. It focuses on:

1. **Real browser networking stacks** - Use Chromium (CDP), Firefox, or WebKit for authentic TLS/HTTP2/HTTP3 behavior
2. **Instrumentation and fingerprint diffs** - See exactly what a server/CDN/WAF would see
3. **Authorized automation and compatibility testing** - Deterministic, testable, observable behavior

## Philosophy

This tool is designed for **legitimate testing**, not evasion:
- ✅ Network compatibility testing
- ✅ Security research on your own systems
- ✅ Performance benchmarking across engines
- ✅ Fingerprint baseline tracking
- ❌ Bot detection bypass
- ❌ Unauthorized automation
- ❌ "Indistinguishable from human" spoofing

## Installation

```bash
go install github.com/stealth/brwslab/cmd/brwslab@latest
go install github.com/stealth/brwslab/cmd/labd@latest
```

### Prerequisites

**For Chromium engine:**
- Chrome or Chromium browser installed

**For Firefox/WebKit engines:**
```bash
go run github.com/playwright-community/playwright-go/cmd/playwright@latest install --with-deps
```

## Quick Start

### 1. Start the fingerprint lab server

```bash
labd --addr :8080
```

### 2. Fetch with different engines

```bash
# Native Go engine
brwslab fetch https://example.com --engine=native

# Real Chromium browser
brwslab fetch https://example.com --engine=chromium

# Firefox via Playwright
brwslab fetch https://example.com --engine=firefox
```

### 3. Capture your fingerprint

```bash
brwslab fingerprint --engine=chromium --lab=http://localhost:8080
```

### 4. Compare engines

```bash
brwslab diff --engine=native --engine=chromium --lab=http://localhost:8080
```

## CLI Commands

### `fetch <url>`

Fetch a URL using the specified engine.

```bash
brwslab fetch https://example.com \
  --engine=chromium \
  --proxy=http://localhost:8080 \
  --output=json \
  --trace=har
```

### `session`

Manage persistent browser sessions.

```bash
# Create a session
brwslab session new --name=mytest --engine=chromium

# List sessions
brwslab session list

# Use session in fetch
brwslab fetch https://example.com --session=<session-id>
```

### `fingerprint`

Capture and display network fingerprint against a lab server.

```bash
brwslab fingerprint --engine=chromium --lab=http://localhost:8080
```

### `diff`

Compare fingerprints between multiple engines.

```bash
brwslab diff --engine=native --engine=chromium --engine=firefox --lab=http://localhost:8080
```

### `trace`

Trace a request with detailed timing and HAR output.

```bash
brwslab trace https://example.com --engine=chromium --output=json
```

### `engines`

List available engines.

```bash
brwslab engines
```

## Library Usage

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/stealth/brwslab/brws/engine"
    _ "github.com/stealth/brwslab/brws/engine/chromium"
    _ "github.com/stealth/brwslab/brws/engine/native"
)

func main() {
    // Create engine
    eng, err := engine.New("chromium", engine.Options{
        Headless: true,
    })
    if err != nil {
        log.Fatal(err)
    }
    defer eng.Close()

    // Make request
    resp, err := eng.Do(context.Background(), &engine.Request{
        Method: "GET",
        URL:    "https://example.com",
    })
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Status: %d\n", resp.Status)
    fmt.Printf("Protocol: %s\n", resp.Protocol)
}
```

## Engines

| Engine | TLS | HTTP/2 | HTTP/3 | JS | Profile | Notes |
|--------|-----|--------|--------|-----|---------|-------|
| `native` | Go stdlib | Yes | No | No | No | Fast, stable, not browser-identical |
| `chromium` | Chrome | Yes | Yes | Yes | Yes | Full CDP access, NetLog export |
| `firefox` | Firefox | Yes | Yes | Yes | Yes | Via Playwright |
| `webkit` | Safari | Yes | Yes | Yes | Yes | Via Playwright |

## Fingerprint Lab Server

The `labd` server captures complete browser fingerprints:

### Quick Start

```bash
# Start with auto-generated certificates and MITM proxy
go run ./cmd/labd

# Or launch Chrome automatically with proxy configured
go run ./cmd/labd -chrome

# Configure browser manually to use:
#   PAC file: http://localhost:8080/proxy.pac
#   Or proxy: localhost:8081
```

### What It Captures

- **TLS ClientHello**: Version, cipher suites, extensions, JA3/JA4 hashes
- **HTTP/2**: SETTINGS, WINDOW_UPDATE, pseudo-header ordering
- **HTTP**: Headers, ordering, compression

### Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Web UI with real-time updates |
| `GET /capture/json` | JSON fingerprint |
| `GET /capture/yaml` | YAML export |
| `GET /debug` | Server status |
| `GET /proxy.pac` | Proxy auto-configuration |
| `WS /ws` | WebSocket for live updates |

### MITM Proxy Mode

Configure your browser to use the proxy:
- **PAC file**: `http://localhost:8080/proxy.pac`
- **Manual**: HTTP proxy `localhost:8081`

All HTTPS traffic through the proxy will have its TLS ClientHello captured.

### Options

```
-bind string        Bind address (default "0.0.0.0")
-http-port int      HTTP port (default 8080)
-https-port int     HTTPS port (default 8443)
-proxy-port int     MITM proxy port, 0 to disable (default 8081)
-auto-certs         Auto-generate certificates (default true)
-tls-cert string    TLS certificate file (optional)
-tls-key string     TLS private key file (optional)
-store string       Directory to store captures
-chrome             Launch Chrome with proxy configured
-chrome-path string Path to Chrome executable (auto-detected if empty)
-v                  Verbose logging
```

### Chrome Integration

**Auto-launch Chrome (easiest):**
```bash
./labd -chrome -v
```

**Transparent mode (preserves Chrome's TLS fingerprint):**
```bash
./labd -proxy-mode transparent -chrome -v
```
In transparent mode, the proxy captures the ClientHello then forwards the raw TLS connection. Chrome negotiates TLS directly with the target server, preserving its original fingerprint (JA3). Use this for sites with bot protection.

**Manual Chrome launch:**
```bash
# macOS
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
  --proxy-server="localhost:8081" \
  --ignore-certificate-errors \
  --user-data-dir=/tmp/chrome-test

# Linux  
google-chrome \
  --proxy-server="localhost:8081" \
  --ignore-certificate-errors \
  --user-data-dir=/tmp/chrome-test

# Windows
chrome --proxy-server="localhost:8081" ^
       --ignore-certificate-errors ^
       --user-data-dir=C:\temp\chrome-test
```

**Using PAC file:**
1. Open Chrome Settings → System → Open proxy settings
2. Enable "Automatic proxy configuration"
3. Enter URL: `http://localhost:8080/proxy.pac`

## Project Structure

```
brwslab/
├── brws/               # Library
│   ├── client/         # High-level client API
│   ├── engine/         # Engine interfaces
│   │   ├── native/     # Go net/http
│   │   ├── chromium/   # Chrome CDP
│   │   ├── firefox/    # Firefox via Playwright
│   │   └── webkit/     # WebKit via Playwright
│   ├── session/        # Cookie jars, profiles
│   ├── trace/          # HAR-like tracing
│   ├── lab/            # Fingerprint protocols
│   ├── proxy/          # MITM proxy for capture
│   ├── tlsparser/      # TLS ClientHello parser
│   ├── types/          # Shared fingerprint types
│   └── diff/           # Comparison utilities
├── cmd/
│   ├── brwslab/        # CLI tool
│   └── labd/           # Fingerprint server
└── internal/
    └── fingerprint/    # Internal fingerprinting
```

## Configuration

Environment variables:
- `BRWSLAB_SESSIONS_DIR` - Session storage location (default: `~/.brwslab/sessions`)
- `BRWSLAB_LAB_URL` - Default lab server URL
- `CHROME_PATH` / `CHROMIUM_PATH` - Browser executable path

## Development

```bash
# Run tests
go test ./...

# Build
make build

# Run lab server locally
go run ./cmd/labd

# Test fetch
go run ./cmd/brwslab fetch https://example.com --engine=native
```

## License

MIT - See LICENSE file for details.

## Acknowledgments

- Inspired by [curl-impersonate](https://github.com/lwthiker/curl-impersonate)
- TLS fingerprinting research by [lwt hiker](https://lwthiker.com/)
- [JA3/JA4](https://github.com/salesforce/ja3) fingerprinting from Salesforce
- [HTTP/2 fingerprinting](https://www.blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf) research by Akamai
