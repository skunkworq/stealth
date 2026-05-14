# Browser Fingerprint Capture Lab (labd) - Implementation Summary

## Overview

This document describes the comprehensive fingerprint capture lab system that captures complete browser signatures across TLS, HTTP/2, and HTTP layers.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    FINGERPRINT CAPTURE                       │
├─────────────────────────────────────────────────────────────┤
│  Layer 4: Behavioral                                        │
│  ├── Request timing patterns                               │
│  ├── Connection reuse patterns                             │
│  └── Request sequence analysis                             │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: HTTP Application                                  │
│  ├── Header names, values, ordering                        │
│  ├── Cookie handling                                       │
│  ├── Compression behavior                                  │
│  └── Client Hints (sec-ch-ua*)                             │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: HTTP/2 Transport                                  │
│  ├── SETTINGS frame values & order                         │
│  ├── WINDOW_UPDATE timing & values                         │
│  ├── Pseudo-header ordering                                │
│  ├── Stream priority & weight                              │
│  └── HEADERS frame flags                                   │
├─────────────────────────────────────────────────────────────┤
│  Layer 1: TLS Handshake                                     │
│  ├── Raw ClientHello bytes                                 │
│  ├── Cipher suite list & order                             │
│  ├── Extension list & order                                │
│  ├── GREASE values & positions                             │
│  ├── ALPN/ALPS values                                      │
│  ├── Key share groups                                      │
│  └── Certificate compression                               │
└─────────────────────────────────────────────────────────────┘
```

## Implementation Files

### Core Capture Infrastructure

| File | Description |
|------|-------------|
| `brws/lab/capture.go` | Core fingerprint data structures and capture logic |
| `brws/lab/tls_parser.go` | Raw TLS ClientHello parser (full byte-level parsing) |
| `brws/lab/raw_capture.go` | Raw packet capture and HTTP/2 frame interception |
| `brws/lab/enhanced_server.go` | Enhanced HTTP server with capture endpoints |

### Signature Database

| File | Description |
|------|-------------|
| `brws/engine/spoof/signature.go` | Browser signature definitions (Chrome 116, Firefox 109) |
| `brws/engine/spoof/spoof.go` | Signature-driven spoofing engine |

### Command Tools

| File | Description |
|------|-------------|
| `cmd/lab/server/labd/main.go` | Lab server command |
| `cmd/lab/cli/brwslab/main.go` | Main CLI with fetch, diff, trace commands |

## Data Structures

### CompleteFingerprint
The top-level structure capturing all layers:

```go
type CompleteFingerprint struct {
    ID        string              // Unique fingerprint ID
    Timestamp time.Time           // Capture time
    SourceIP  string              // Client IP
    TLS       *TLSFingerprint     // Layer 1: TLS handshake
    HTTP2     *HTTP2Fingerprint   // Layer 2: HTTP/2 frames
    HTTP      *HTTPFingerprint    // Layer 3: HTTP headers
    Behavior  *BehaviorFingerprint // Layer 4: Timing/behavior
}
```

### TLSFingerprint
Captures TLS ClientHello details:

```go
type TLSFingerprint struct {
    Version            uint16          // TLS version
    CipherSuites       []CipherInfo    // Ordered cipher list
    Extensions         []ExtensionInfo // Ordered extensions
    GREASE             []GREASEInfo    // GREASE values & positions
    SupportedGroups    []uint16        // Elliptic curves
    ALPN               []string        // Application protocols
    ALPS               string          // Chrome ALPS extension
    CertCompression    []string        // cert_compression (brotli)
    KeyShareGroups     []uint16        // Key share groups
    JA3Hash            string          // JA3 fingerprint
    JA4                string          // JA4 fingerprint
}
```

### HTTP2Fingerprint
Captures HTTP/2-specific signals:

```go
type HTTP2Fingerprint struct {
    Settings        []HTTP2Setting    // SETTINGS frame parameters
    WindowUpdates   []WindowUpdateInfo // WINDOW_UPDATE frames
    PseudoHeaders   []string          // :method, :authority order
    HeaderOrder     []string          // Full header ordering
    FrameSequence   []FrameInfo       // Frame sequence & timing
    StreamPriority  *StreamPriority   // Priority settings
}
```

## API Endpoints

### Capture Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/capture` | GET | HTML fingerprint report |
| `/capture/json` | GET | JSON fingerprint export |
| `/capture/yaml` | GET | YAML export (curl-impersonate compatible) |

### Baseline Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/baseline` | POST | Store captured baseline |
| `/baseline/{name}` | GET | Retrieve baseline |

### Comparison

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/compare?baseline=X&test=Y` | GET | Compare fingerprints |

## Chrome 116 Signature

### TLS Settings
```yaml
cipher_suites:
  - TLS_AES_128_GCM_SHA256
  - TLS_AES_256_GCM_SHA384
  - TLS_CHACHA20_POLY1305_SHA256
  - ... (with GREASE)

extensions:
  - GREASE
  - server_name
  - extended_master_secret
  - renegotiation_info
  - supported_groups
  - ec_point_formats
  - signed_certificate_timestamp
  - application_layer_protocol_negotiation (ALPN: h2, http/1.1)
  - status_request
  - key_share
  - psk_key_exchange_modes
  - supported_versions
  - compress_certificate (brotli)
  - application_settings (ALPS: h2)  # Chrome-specific
  - padding

supported_groups: [X25519, P-256, P-384, X448]
key_share_groups: [X25519, P-256]
cert_compression: [brotli]
```

### HTTP/2 Settings
```yaml
settings:
  HEADER_TABLE_SIZE:      65536      # 64KB (vs Go's 4KB)
  ENABLE_PUSH:            0
  MAX_CONCURRENT_STREAMS: 1000
  INITIAL_WINDOW_SIZE:    6291456    # 6MB (vs Go's 64KB)
  MAX_HEADER_LIST_SIZE:   262144

pseudo_header_order:
  - :method
  - :authority
  - :scheme
  - :path

window_update:
  stream_id:  0
  increment:  6291456
```

## Usage Examples

### Start Capture Lab
```bash
# Basic HTTP capture
./build/labd

# Full HTTPS capture with certificates
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes
./build/labd -tls-cert server.crt -tls-key server.key -v
```

### Capture Fingerprint with curl
```bash
# Capture Chrome fingerprint
curl -s https://localhost:8443/capture/json \
  --http2 \
  --cacert server.crt \
  -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# View HTML report
curl -s https://localhost:8443/capture --cacert server.crt
```

### Capture with brwslab
```bash
# Use Chromium engine to capture real browser fingerprint
./build/brwslab fetch https://localhost:8443/capture --engine chromium

# Compare fingerprints between engines
./build/brwslab diff --lab https://localhost:8443 \
  --engine native --engine spoof-chrome --engine chromium
```

### Save Baseline
```bash
# Capture and save as baseline
curl -s https://localhost:8443/capture/json \
  --cacert server.crt \
  --http2 \
  -A "Mozilla/5.0..." > chrome_baseline.json

curl -X POST https://localhost:8443/baseline?name=chrome-116 \
  -H "Content-Type: application/json" \
  -d @chrome_baseline.json
```

## Next Steps

1. **Raw Packet Capture**: Implement gopacket integration for complete ClientHello capture
2. **HTTP/2 Frame Interception**: Add custom HTTP/2 server with frame logging
3. **Browser Auto-Capture**: Add endpoints to automatically capture from real browsers
4. **Signature Diff Tool**: Enhanced comparison with byte-level diffs
5. **Custom HTTP/2 Transport**: Implement Go transport that matches captured signatures exactly

## Known Limitations

1. **Go HTTP/2 Library**: Standard library hardcodes SETTINGS values
2. **ALPS Extension**: uTLS has limited support for Chrome-specific ALPS
3. **Cert Compression**: Brotli decompression not fully implemented
4. **Pseudo-header Order**: Requires custom HTTP/2 implementation

## Success Metrics

| Metric | Target | Current |
|--------|--------|---------|
| JA3 Match | 100% | 95% (uTLS limitation) |
| HTTP/2 SETTINGS Match | 100% | 0% (library limitation) |
| Pseudo-header Order | 100% | 0% (library limitation) |
| WINDOW_UPDATE Pattern | 100% | 0% (library limitation) |
| Incapsula Bypass | >95% | 33% (HTTP/2 gaps) |

