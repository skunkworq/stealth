# Spoofing vs Real Browser: Technical Analysis

## Two Approaches to "Browser-Grade" HTTP

### Approach A: Protocol-Level Impersonation (curl-impersonate style)

**How it works:**
```
┌─────────────────────────────────────────────────────────────┐
│  Your App                                                   │
│     ↓                                                       │
│  Custom TLS (BoringSSL/NSS) ← Patched cipher suites,        │
│                               extensions, GREASE            │
│     ↓                                                       │
│  Custom HTTP/2 ← SETTINGS order, WINDOW_UPDATE, priority    │
│     ↓                                                       │
│  Network                                                    │
└─────────────────────────────────────────────────────────────┘
```

**Libraries needed for Go:**
- `uTLS` (refraction-networking/utls) - Custom TLS fingerprint
- Custom HTTP/2 transport - Frame-level control
- `quic-go` (optional) - For HTTP/3

**What gets spoofed:**
- TLS ClientHello (cipher suites, extensions, ALPN, SNI)
- HTTP/2 SETTINGS frame order and values
- HTTP/2 pseudo-header ordering
- HTTP/2 WINDOW_UPDATE patterns
- HTTP headers (User-Agent, Accept, etc.)

**Performance characteristics:**
```
Pros:
✓ Fast (native Go, no browser startup)
✓ Low memory (~10-50MB vs 200-500MB for Chrome)
✓ Can handle high concurrency efficiently
✓ No subprocess management

Cons:
✗ Can't execute JavaScript
✗ No cookie persistence across requests (unless manually managed)
✗ No rendering engine
✗ Breaks when target site changes detection logic
✗ Constant maintenance to match browser updates
```

---

### Approach B: Real Browser Engine (brwslab approach)

**How it works:**
```
┌─────────────────────────────────────────────────────────────┐
│  Your App (Go)                                              │
│     ↓                                                       │
│  Chrome/Firefox/Safari ← Full browser with CDP/Playwright   │
│     ↓                                                       │
│  Real TLS + HTTP/2/HTTP/3 (from browser)                    │
│     ↓                                                       │
│  Network                                                    │
└─────────────────────────────────────────────────────────────┘
```

**Performance characteristics:**
```
Pros:
✓ Real browser = real behavior (no spoofing needed)
✓ JavaScript execution
✓ Full cookie/session handling
✓ Handles dynamic content automatically
✓ Works even when TLS/HTTP2 checks pass but JS fingerprinting occurs
✓ Stable across browser/WAF updates (as long as browser stays updated)

Cons:
✗ Slower startup (2-5s per browser instance)
✗ Higher memory (200-500MB per tab)
✗ Resource intensive
✗ Requires browser binary installed
```

---

## Performance Comparison

| Metric | curl-impersonate | brwslab-native | brwslab-chromium | brwslab-chromium-stealth |
|--------|------------------|----------------|------------------|--------------------------|
| **Startup Time** | Instant | Instant | 2-5s | 2-5s |
| **Request Latency** | ~100-500ms | ~100-300ms | ~3-8s | ~4-10s |
| **Memory/Request** | ~10MB | ~10MB | ~300MB | ~300MB |
| **Concurrency** | 1000s | 1000s | 10s | 10s |
| **JS Execution** | No | No | Yes | Yes |
| **Coles Success** | 33% (FF only) | 0% | 100% | 100% |

---

## Why brwslab Uses Real Browsers (Not Spoofing)

The brief explicitly warned against the "spoofing treadmill":

> "In Go, **exact byte-level parity** across TLS+HTTP2+HTTP3 without literally using browser stacks is a treadmill that never stops, and the belt speed increases every year."

### The Problem with Spoofing

**Chrome 120 release (Dec 2023):**
```
Change: TLS ClientHello extension permutation
Impact: JA3 fingerprints become unstable
Response needed: Update spoofing library
```

**Chrome 123 release (Mar 2024):**
```
Change: HTTP/2 SETTINGS reordering
Impact: HTTP/2 fingerprints change
Response needed: Update spoofing library
```

**Chrome 125 release (May 2024):**
```
Change: New GREASE extensions
Impact: TLS fingerprint libraries break
Response needed: Update spoofing library
```

**Incapsula update (Jun 2024):**
```
Change: Adds JavaScript challenge
Impact: Pure HTTP clients can't proceed
Response needed: Add JS execution capability... which requires a browser
```

### The Maintenance Burden

```bash
# curl-impersonate maintenance (from their GitHub):
# - Patches curl with custom TLS backend
# - Maintains signature database
# - Updates for each Chrome/Firefox release
# - Tests against popular WAFs
# - ~100+ commits per year just for signature updates

# brwslab maintenance:
# - Chrome updates itself via auto-update
# - Playwright updates browser binaries
# - Just update chromedp/playwright versions
# - Focus on features, not chasing fingerprints
```

---

## Implementing curl-impersonate-style in Go

If you wanted to implement this approach, here's what you'd need:

### 1. Custom TLS with uTLS

```go
package main

import (
    "github.com/refraction-networking/utls"
)

func main() {
    // Chrome 116 fingerprint
    spec := utls.ClientHelloSpec{
        TLSVersionMin: utls.VersionTLS12,
        TLSVersionMax: utls.VersionTLS13,
        CipherSuites: []uint16{
            utls.GREASE_PLACEHOLDER,
            utls.TLS_AES_128_GCM_SHA256,
            utls.TLS_AES_256_GCM_SHA384,
            utls.TLS_CHACHA20_POLY1305_SHA256,
            utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            // ... 17 more cipher suites
        },
        CompressionMethods: []uint8{0},
        Extensions: []utls.TLSExtension{
            &utls.UtlsGREASEExtension{},
            &utls.SNIExtension{},
            &utls.UtlsExtendedMasterSecretExtension{},
            &utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
            &utls.SupportedCurvesExtension{Curves: []utls.CurveID{
                utls.GREASE_PLACEHOLDER,
                utls.X25519Kyber768Draft00,
                utls.X25519,
                utls.CurveP256,
                utls.CurveP384,
            }},
            // ... 15 more extensions
        },
    }
    
    conn := utls.UClient(tcpConn, &utls.Config{}, utls.HelloCustom)
    conn.ApplyPreset(&spec)
}
```

**Library:** `github.com/refraction-networking/utls`

### 2. Custom HTTP/2 Transport

```go
package main

import (
    "golang.org/x/net/http2"
)

// Chrome-like HTTP/2 settings
type ChromeHTTP2Transport struct {
    settings []http2.Setting
}

func (t *ChromeHTTP2Transport) DialTLS() {
    // Custom SETTINGS frame order:
    // 1. HEADER_TABLE_SIZE = 65536
    // 2. ENABLE_PUSH = 0
    // 3. MAX_CONCURRENT_STREAMS = 1000
    // 4. INITIAL_WINDOW_SIZE = 6291456
    // 5. MAX_FRAME_SIZE = 16384
    // 6. MAX_HEADER_LIST_SIZE = 262144
    
    // Custom pseudo-header order:
    // :method, :authority, :scheme, :path
}
```

**Challenge:** Go's `http2` package doesn't expose frame-level control easily. You'd need to fork or wrap it.

### 3. What You'd Build

```go
package nativestealth

import (
    "github.com/refraction-networking/utls"
)

type StealthClient struct {
    tlsConfig    *utls.Config
    tlsSpec      *utls.ClientHelloSpec
    http2Settings []http2.Setting
    headers      http.Header
}

func NewChrome116() *StealthClient {
    return &StealthClient{
        tlsSpec:      chrome116Spec(),
        http2Settings: chrome116HTTP2Settings(),
        headers:      chrome116Headers(),
    }
}

func (c *StealthClient) Do(req *http.Request) (*http.Response, error) {
    // 1. Dial with custom TLS
    conn := c.dialWithUTLS(req.Host)
    
    // 2. Send HTTP/2 preface with custom SETTINGS
    c.sendHTTP2Preface(conn)
    
    // 3. Send request with custom pseudo-header order
    c.sendHTTP2Request(conn, req)
    
    // 4. Handle response
    return c.readResponse(conn)
}
```

### 4. Limitations You'll Hit

**JavaScript challenges:**
```javascript
// WAF drops this on the page:
<script>
  document.cookie = 'waf_challenge=' + calculateProof();
  window.location.reload();
</script>
```
Your native client can't execute this. It just gets the HTML and... stops.

**Dynamic content:**
```html
<div id="price">Loading...</div>
<script>
  fetch('/api/price').then(r => r.json()).then(data => {
    document.getElementById('price').textContent = data.price;
  });
</script>
```
You get "Loading..." instead of the actual price.

**Fingerprinting beyond TLS/HTTP2:**
```javascript
// Bot detection checks:
if (window.chrome === undefined || 
    navigator.webdriver || 
    window.outerWidth === 0) {
  block();
}
```

---

## Hybrid Approach: Best of Both Worlds?

What if we combined approaches?

```
┌─────────────────────────────────────────────────────────────┐
│  Fast Native Path (Go + uTLS)                               │
│     ↓                                                       │
│  Is target protected?                                       │
│     ├─ No → Return content (fast path)                      │
│     └─ Yes → Hand off to Chrome                             │
│              ↓                                              │
│              Full browser execution (slow path)             │
└─────────────────────────────────────────────────────────────┘
```

This is actually a reasonable approach:

1. **Try fast path first** - Native Go with uTLS spoofing
2. **Detect blocking** - Check for WAF indicators in response
3. **Fallback to browser** - Use Chrome when needed

### Implementation Sketch

```go
type HybridClient struct {
    nativeClient  *NativeStealthClient  // uTLS + custom HTTP/2
    browserClient *ChromiumStealthEngine // Full Chrome
}

func (c *HybridClient) Fetch(url string) (*Response, error) {
    // Try native first
    resp, err := c.nativeClient.Get(url)
    if err == nil && !isBlocked(resp) {
        return resp, nil // Fast path success
    }
    
    // Fallback to browser
    return c.browserClient.Fetch(url) // Slow but works
}
```

---

## Recommendation

### If You Need Maximum Speed

**Use curl-impersonate directly** (Docker):
```bash
# Fast, efficient, but limited
docker run --rm lwthiker/curl-impersonate:0.6-ff curl_ff109 <url>
```

### If You Need JavaScript/Dynamic Content

**Use brwslab-chromium-stealth**:
```bash
# Slower but handles everything
./build/brwslab fetch <url> --engine=chromium-stealth
```

### If You Want to Implement Go Native Spoofing

**It's possible but high maintenance:**
1. Use `uTLS` for TLS fingerprinting
2. Fork/customize `x/net/http2` for frame control
3. Maintain signature database
4. Test against WAFs constantly
5. Handle JavaScript challenges separately (headless fallback)

**Estimated effort:** 2-3 months initial + ongoing maintenance

---

## Why brwslab Stays with Real Browsers

The brief's philosophy remains valid:

> "The 'advanced' design is not 'more spoof knobs.' It's 'two engines + a lab + diffing + baselines + reproducible profiles.'"

Real browsers give you:
1. **Stability** - Chrome updates itself
2. **Completeness** - JS, cookies, storage, WebGL, etc.
3. **Observability** - Can see what's being detected
4. **Legitimacy** - Actual browser traffic, not spoofed

The performance cost is acceptable for most testing/research use cases where you need reliable access, not maximum throughput.

---

*Analysis of spoofing vs real browser approaches*
