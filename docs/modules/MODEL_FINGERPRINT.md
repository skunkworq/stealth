# Model: Fingerprint Module

> **Purpose:** Capture, analyze, reproduce, and spoof browser fingerprints across all network layers (TLS, HTTP/1.1, HTTP/2, WebSocket) to masquerade as real browsers.

---

## Architecture Overview

```
Real Browser Traffic
        │
        ▼
┌───────────────┐     ┌───────────────┐     ┌───────────────┐
│  Lab Capture  │────▶│  TLS Parser   │────▶│  Fingerprint  │
│  (MITM Proxy) │     │  (JA3/JA4)    │     │  Database     │
└───────────────┘     └───────────────┘     └───────┬───────┘
                                                    │
                              ┌─────────────────────┘
                              ▼
                    ┌─────────────────┐
                    │  TLS Spoofer    │
                    │  (uTLS-based)   │
                    └─────────────────┘
                              │
                              ▼
                     Spoofed ClientHello
```

---

## Main Components

| Subdirectory | Purpose |
|---|---|
| `tls/` | Core TLS fingerprinting: spoofing, capture, parsing, JA3/JA4 calculation, HTTP1/HTTP2/WS fingerprints |
| `lab/` | Fingerprint capture laboratory: intercepts real browser traffic, builds `CompleteFingerprint` structs |
| `bench/` | Benchmarks for spoof engines, TLS parsing, pool management, session handling |
| `train/datagen/` | ML training data collection: SQLite-backed collector for stealth episodes and outcomes |
| `core/types/` | Shared canonical types (`CompleteFingerprint`, `TLSFingerprint`, `HTTP2Fingerprint`) |

---

## Key Types

### `CompleteFingerprint` (`brws/core/types/fingerprint.go`)

Top-level container with all fingerprint layers:

```go
type CompleteFingerprint struct {
    ID         string
    Timestamp  time.Time
    SourceIP   string
    ServerName string
    TLS        *TLSFingerprint
    HTTP2      *HTTP2Fingerprint
    HTTP       *HTTPFingerprint
    HTTPResp   *HTTPResponseFingerprint
    Behavior   *BehaviorFingerprint
}
```

### `TLSFingerprint`

```go
type TLSFingerprint struct {
    Version         uint16
    CipherSuites    []CipherInfo
    Extensions      []ExtensionInfo
    GREASE          []GREASEInfo
    SupportedGroups []uint16
    ALPN            []string
    JA3Hash         string
    JA4             string
    RawClientHello  string
}
```

---

## JA3 / JA4 Fingerprinting

### JA3

Composed of 5 comma-separated fields:
1. SSLVersion (e.g., `769` for TLS 1.2, `772` for TLS 1.3)
2. Cipher suites (dash-separated, GREASE excluded)
3. Extensions (dash-separated, GREASE excluded)
4. Elliptic curves
5. EC point formats

**JA3 Hash** = MD5 of the above string.

### JA4

Format: `t[protocol][version][SNI][cipher_count][ext_count][ALPN]_[cipher_hash]_[ext_hash]`

Example: `t13d1516h2_8daaf6152771_02713d6af862`

### GREASE Detection

```go
func IsGREASE(val uint16) bool {
    return (val&0x0F0F) == 0x0A0A && ((val>>4)&0x0F) == ((val>>12)&0x0F)
}
```

GREASE values are excluded from JA3/JA4 hashes but tracked separately.

---

## TLS Spoofer (`tls/spoofer.go`)

Built on **uTLS** (`github.com/refraction-networking/utls`).

**Supported browser fingerprints:**

| Browser | Versions |
|---|---|
| Chrome | Auto, 120, 133 |
| Firefox | Auto, 120, 105 |
| Safari | 16.0 |
| Edge | Auto, 106 |
| iOS | 14, 13 |
| Android | 11 OkHttp |

**Spoofing modes:**
- **Static** — fixed fingerprint per browser/version
- **Randomized** — fully randomized ClientHello
- **Rotating** — random pick from pool of all fingerprints
- **Per-browser random** — vary within a browser family

**Builder pattern:**
```go
id := tlsfprint.NewFingerprintGenerator().
    Browser(tlsfprint.Chrome).
    Version("133").
    ALPN(true).
    Seed(42).
    Build()
```

---

## Lab Capture System

### MITM Proxy (`proxy/proxy.go`)

- Peeks first 8 bytes of connection to detect TLS vs HTTP CONNECT vs plain HTTP
- Captures raw `ClientHello` via `tlsCaptureConn` wrapper
- Discovers ALPN by connecting to target first, then forces client to match
- Generates per-host leaf certificates via `CertificateManager`

### Certificate Manager (`proxy/certs.go`)

- Loads external CA or auto-generates realistic CA (DigiCert, Let's Encrypt, Google, Amazon)
- 3-tier chain: Root CA → Intermediate → Leaf
- Per-host caching with realistic details (SANs, KeyUsage, 90-day validity)

### Capture Server (`lab/capture.go`)

- HTTP middleware that builds `CompleteFingerprint` from intercepted traffic
- Stores captures by remote address
- Exports to JSON and curl-impersonate-compatible YAML

---

## Data Flow

1. **Capture**: Real browser → MITM Proxy → `parser/parser.go` parses ClientHello
2. **Analysis**: `TLSAnalyzer` computes JA3, JA4, JA3H1, JA3H2
3. **Signature Database**: `tls/signatures.go` stores known-good `FingerprintSignature` records
4. **Spoofing**: `Spoofer` / `AdaptiveSpoofer` selects `utls.ClientHelloID` → uTLS emits matching ClientHello
5. **Training**: `datagen.Collector` records episode outcomes → ML models improve selection
6. **Benchmarking**: `bench/` validates performance under load

---

## Rust FFI Bridge

`tls/rust/src/lib.rs` provides a CGo bridge:
- `ConnectAndFingerprint(host, port)` — live TLS connection returning full `Fingerprint` struct with JA3, JA4, cipher suites, extensions, anomalies

---

## Files

| File | Lines | Description |
|---|---|---|
| `tls/spoofer.go` | ~508 | Core spoofing logic, browser fingerprint selection |
| `tls/capture.go` | ~200+ | TLS capture and handshake analysis |
| `tls/parser/parser.go` | ~400+ | Binary TLS ClientHello parser |
| `tls/handshake.go` | ~300+ | Handshake recording and analysis |
| `tls/http1.go` | ~200+ | HTTP/1.1 fingerprinting |
| `tls/http2.go` | ~200+ | HTTP/2 fingerprinting |
| `lab/capture.go` | ~300+ | Lab capture server and export |
| `lab/training_api.go` | ~200+ | Training API for fingerprint comparison |
| `bench/benchmark_test.go` | ~500+ | Performance benchmarks |
| `core/types/fingerprint.go` | ~300+ | Canonical fingerprint types |
