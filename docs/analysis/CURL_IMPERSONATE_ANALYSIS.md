# curl-impersonate Deep Analysis: Why It Works Where Go Spoofing Fails

## Executive Summary

After deep analysis of curl-impersonate's implementation, I've identified the critical differences between curl-impersonate and our Go spoofing implementation. The key finding:

> **curl-impersonate doesn't just spoof TLS fingerprints - it patches curl, BoringSSL/NSS, AND nghttp2 (HTTP/2 library) to match browser behavior at every layer.**

---

## Architecture Comparison

### curl-impersonate (Full Stack Patching)

```
┌─────────────────────────────────────────────────────────────┐
│  Application (curl or libcurl user)                         │
└─────────────────┬───────────────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────────────┐
│  curl (patched)                                             │
│  ├── Header ordering (HTTP/1.1)                            │
│  ├── Pseudo-header ordering (HTTP/2)                       │
│  └── HTTPBASEHEADER merging logic                          │
└─────────────────┬───────────────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────────────┐
│  nghttp2 (patched) - HTTP/2 Library                        │
│  ├── SETTINGS frame values & order                         │
│  ├── WINDOW_UPDATE timing & values                       │
│  └── Stream priority & weight                              │
└─────────────────┬───────────────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────────────┐
│  BoringSSL (Chrome) or NSS (Firefox) - TLS Library         │
│  ├── Cipher suites & order                                 │
│  ├── Extensions & order (with GREASE)                      │
│  ├── ALPS (Application Layer Protocol Settings)            │
│  ├── Certificate compression (brotli)                      │
│  └── Extension permutation (Chrome 110+)                   │
└─────────────────┬───────────────────────────────────────────┘
                  │
│  Network                                                    │
└─────────────────────────────────────────────────────────────┘
```

### Our Go Implementation (TLS Spoofing Only)

```
┌─────────────────────────────────────────────────────────────┐
│  Application (Go code)                                      │
└─────────────────┬───────────────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────────────┐
│  Go net/http (unmodified)                                   │
│  ├── Standard header handling                              │
│  └── Standard HTTP/2 behavior (x/net/http2)                │
└─────────────────┬───────────────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────────────┐
│  x/net/http2 (unmodified)                                   │
│  ├── Default SETTINGS (Go's values, not Chrome's)          │
│  └── Default pseudo-header order                           │
└─────────────────┬───────────────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────────────┐
│  uTLS (patched TLS)                                         │
│  ├── Chrome/Firefox cipher suites                          │
│  ├── Chrome/Firefox extensions                             │
│  └── BUT: Limited GREASE, no ALPS, no cert compression     │
└─────────────────┬───────────────────────────────────────────┘
                  │
│  Network                                                    │
└─────────────────────────────────────────────────────────────┘
```

---

## Critical Differences

### 1. TLS Library: BoringSSL vs uTLS

| Feature | curl-impersonate (BoringSSL) | Our Go (uTLS) |
|---------|------------------------------|---------------|
| **GREASE Generation** | Native BoringSSL support | Emulated (limited) |
| **ALPS Extension** | Full support | Not implemented |
| **Cert Compression** | Brotli decompression | Not implemented |
| **Extension Permutation** | `SSL_CTX_set_permute_extensions()` | Manual ordering only |
| **TLS 1.3 Key Share** | X25519Kyber768Draft00 | X25519 only |

**Why this matters:**
- Chrome uses BoringSSL-specific features like ALPS
- Without ALPS, you're missing a Chrome-specific TLS extension
- GREASE in BoringSSL has specific timing and placement

### 2. HTTP/2 SETTINGS Frame

**Chrome SETTINGS (curl-impersonate sends):**
```
1. SETTINGS_HEADER_TABLE_SIZE = 65536
2. SETTINGS_ENABLE_PUSH = 0
3. SETTINGS_MAX_CONCURRENT_STREAMS = 1000
4. SETTINGS_INITIAL_WINDOW_SIZE = 6291456  ← 6MB!
5. SETTINGS_MAX_FRAME_SIZE = 16384
```

**Go's Default SETTINGS:**
```
1. SETTINGS_HEADER_TABLE_SIZE = 4096       ← Different!
2. SETTINGS_ENABLE_PUSH = 0
3. SETTINGS_INITIAL_WINDOW_SIZE = 65535    ← Different!
4. SETTINGS_MAX_FRAME_SIZE = 16384
```

**Detection vector:** The INITIAL_WINDOW_SIZE (6MB vs 64KB) is a MAJOR fingerprinting signal!

### 3. HTTP/2 Pseudo-Header Order

**Chrome Order (curl-impersonate):**
```
:method
:authority
:scheme
:path
```

**Go's Order (x/net/http2):**
```
:method
:path
:authority
:scheme
```

**Detection vector:** Incapsula checks this order. Different = bot.

### 4. HTTP/2 WINDOW_UPDATE

**Chrome sends:**
- Connection-level WINDOW_UPDATE with 6MB increment immediately after handshake

**Go sends:**
- Different timing and values
- No initial WINDOW_UPDATE

### 5. Header Order and Values

**Chrome Headers (curl-impersonate exact match):**
```
sec-ch-ua: "Chromium";v="110", "Not A(Brand)";v="24", "Google Chrome";v="110"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif...
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
```

**Go's Headers:**
- Different order (Go's http client sorts headers)
- Missing `sec-ch-ua*` headers
- Different Accept header
- Missing `Sec-Fetch-*` headers

---

## Why curl-impersonate-ff Succeeds on Coles

Our testing showed curl-impersonate-ff (Firefox) succeeds while Chrome fails. Here's why:

### Firefox Advantages

1. **Lower Bot Traffic Volume**
   - Chrome signatures are more commonly spoofed by bots
   - Firefox TLS signatures appear more "organic" to ML models
   - Less training data for Firefox bot detection

2. **Different HTTP/2 Behavior**
   ```
   Firefox SETTINGS:
   - HEADER_TABLE_SIZE = 65536
   - INITIAL_WINDOW_SIZE = 131072 (128KB)
   - Fewer SETTINGS overall (3 vs Chrome's 5)
   
   Firefox Pseudo-Headers:
   - :method, :path, :authority, :scheme (different order!)
   ```

3. **NSS vs BoringSSL**
   - NSS (Firefox's TLS) has different timing characteristics
   - Different extension handling
   - No GREASE (simpler, more consistent)

4. **Additional Headers**
   ```
   Firefox sends "TE: trailers" which Chrome doesn't
   ```

### Why Chrome Fails

1. **Higher Scrutiny**
   - Chrome 110+ has TLS permutation (randomized extension order)
   - WAFs may detect uTLS's deterministic ordering
   - Chrome signatures are heavily targeted by bot detection

2. **Missing BoringSSL Features**
   - ALPS extension not fully implemented in uTLS
   - Certificate compression not implemented
   - Extension permutation not truly random

---

## What Would Make Our Go Implementation Work

### Option 1: Full HTTP/2 Fork (High Effort)

Fork `x/net/http2` to control:
```go
// Custom http2.Transport
&http2.Transport{
    // Chrome SETTINGS
    InitialSettings: []Setting{
        {ID: SettingHeaderTableSize, Val: 65536},
        {ID: SettingEnablePush, Val: 0},
        {ID: SettingMaxConcurrentStreams, Val: 1000},
        {ID: SettingInitialWindowSize, Val: 6291456}, // 6MB
    },
    // Pseudo-header order
    PseudoHeaderOrder: []string{
        ":method",
        ":authority", 
        ":scheme",
        ":path",
    },
    // Window update
    InitialWindowUpdate: 6291456,
}
```

**Effort:** 2-3 months
**Complexity:** Very High

### Option 2: Use Pre-built Parrots (Medium Effort)

Use uTLS built-in parrots which are more complete:

```go
// Instead of custom spec:
conn := utls.UClient(tcpConn, config, utls.HelloChrome_Auto)

// Or specific version:
conn := utls.UClient(tcpConn, config, utls.HelloChrome_102)
```

**Limitation:** Still doesn't fix HTTP/2 layer

### Option 3: HTTP/1.1 Only (Quick Fix)

Force HTTP/1.1 where possible:
```go
transport.ForceAttemptHTTP2 = false
tlsConfig.NextProtos = []string{"http/1.1"}
```

**Limitation:** Many sites require HTTP/2

### Option 4: Use Real Browser for HTTP/2 (Hybrid)

What curl-impersonate essentially does - use the actual browser libraries:

```
For HTTPS sites:
1. Try HTTP/1.1 with uTLS spoofing (fast)
2. If that fails, use headless Chrome (slow but works)
```

---

## Specific Technical Gaps

### Gap 1: ALPS Extension

**What it is:** Application Layer Protocol Settings - sends HTTP/2 SETTINGS during TLS handshake

**Chrome uses it:** Yes
**uTLS implements:** No
**Impact:** Missing Chrome-specific extension = detection

### Gap 2: Certificate Compression

**What it is:** Brotli-compressed certificates (Chrome supports)

**Chrome uses it:** Brotli decompression
**uTLS implements:** No
**Impact:** Missing extension = detection

### Gap 3: HTTP/2 SETTINGS Order

**Chrome sends:**
```
[HEADER_TABLE_SIZE, ENABLE_PUSH, MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE]
```

**Go sends:**
```
Different order, different values
```

**Impact:** HTTP/2 fingerprint mismatch

### Gap 4: Extension Permutation

**Chrome 110+:** Randomizes TLS extension order
**uTLS:** Fixed order based on spec
**Impact:** JA3 unstable, but also detectable as non-Chrome

---

## Reverse Engineering Browser Signatures

### Step 1: Capture Real Browser Traffic

```bash
# Capture TLS + HTTP/2
sudo tshark -i any -w chrome_capture.pcap 'host example.com and port 443'

# Or use browserleaks.com
# https://browserleaks.com/tls
# https://browserleaks.com/http2
```

### Step 2: Analyze ClientHello

```bash
# Extract JA3
tshark -r chrome_capture.pcap -V -Y 'tls.handshake.type == 1' | grep -A100 "Client Hello"

# Look for:
# - Cipher suite list (exact order)
# - Extensions list (exact order)
# - GREASE values
# - ALPN values
# - Supported groups
```

### Step 3: Analyze HTTP/2

```bash
# Extract HTTP/2 SETTINGS
tshark -r chrome_capture.pcap -Y 'http2.settings' -V

# Look for:
# - SETTINGS order
# - SETTINGS values
# - WINDOW_UPDATE timing
# - Pseudo-header order in HEADERS frames
```

### Step 4: Create YAML Signature

```yaml
# chrome_120_signature.yaml
name: chrome_120_win11

signature:
  tls_client_hello:
    version: TLS_1_3
    ciphersuites:
      - GREASE
      - 0x1301  # TLS_AES_128_GCM_SHA256
      - 0x1302  # TLS_AES_256_GCM_SHA384
      # ... exact order
    extensions:
      - type: GREASE
      - type: server_name
      - type: extended_master_secret
      # ... exact order
    
  http2:
    settings:
      - HEADER_TABLE_SIZE: 65536
      - ENABLE_PUSH: 0
      - MAX_CONCURRENT_STREAMS: 1000
      - INITIAL_WINDOW_SIZE: 6291456
    
    pseudo_headers: [':method', ':authority', ':scheme', ':path']
    
    window_update: 6291456
```

### Step 5: Implement in Code

```go
// Convert YAML to uTLS ClientHelloSpec
spec := &utls.ClientHelloSpec{
    CipherSuites: yamlToCiphers(sig.TLS.Ciphersuites),
    Extensions: yamlToExtensions(sig.TLS.Extensions),
    // ...
}

// Convert YAML to custom http2.Transport
h2Transport := &customhttp2.Transport{
    Settings: yamlToSettings(sig.HTTP2.Settings),
    PseudoHeaderOrder: sig.HTTP2.PseudoHeaders,
    WindowUpdate: sig.HTTP2.WindowUpdate,
}
```

---

## Recommendations

### For Maximum Success (Production)

**Use curl-impersonate directly:**
```bash
docker run --rm lwthiker/curl-impersonate:0.6-ff curl_ff109 <url>
```

**Why:** Full stack patching, proven to work

### For Go Implementation (Research/Testing)

**Accept limitations:**
- Our Go spoofing works for simple TLS-only detection
- Fails against sophisticated WAFs (Incapsula, Cloudflare Bot Management)
- Use real browsers (chromedp/Playwright) for those cases

**Hybrid approach:**
```go
func Fetch(url string) (*Response, error) {
    // Fast path: Try spoofed native client
    if resp, err := spoofClient.Get(url); err == nil && !blocked(resp) {
        return resp, nil
    }
    
    // Slow path: Use headless browser
    return browserClient.Fetch(url)
}
```

### For Reverse Engineering

**Tooling to build:**
1. Signature capture tool (tshark wrapper)
2. YAML signature database
3. Automated diff tool (compare fingerprints)
4. Test harness (try against real WAFs)

---

## Conclusion

curl-impersonate succeeds because it patches the ENTIRE stack:
1. **Application layer** (curl - header ordering)
2. **HTTP/2 layer** (nghttp2 - SETTINGS, pseudo-headers, window)
3. **TLS layer** (BoringSSL/NSS - cipher suites, extensions, GREASE, ALPS)

Our Go implementation only patches layer 3 (TLS) partially, and doesn't control layers 1-2. This is why curl-impersonate bypasses Incapsula while our implementation fails.

**The brutal truth:** Matching browser fingerprints requires either:
1. Using the actual browser libraries (curl-impersonate approach)
2. OR forking and patching every layer (months of work)
3. OR using real browsers (chromedp approach)

For most practical purposes, **option 1 (curl-impersonate) or option 3 (real browsers) are the only reliable solutions.**

---

## References

- [curl-impersonate GitHub](https://github.com/lwthiker/curl-impersonate)
- [curl-impersonate Patch Analysis](docs/curl-impersonate/chrome/patches/curl-impersonate.patch)
- [uTLS Documentation](https://github.com/refraction-networking/utls)
- [nghttp2 Documentation](https://nghttp2.org/)
- [BoringSSL Documentation](https://boringssl.googlesource.com/boringssl/)
