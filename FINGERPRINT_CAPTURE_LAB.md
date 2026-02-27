# Fingerprint Capture Lab Specification

## Overview

This document specifies an enhanced labd server that captures complete browser fingerprints across all layers: TLS, HTTP/2, HTTP, and behavioral signals.

## Capture Architecture

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

## Implementation Strategy

### Phase 1: Enhanced TLS Capture

Go has full access to TLS handshake via:
- `crypto/tls` Conn with `GetClientHelloInfo()`
- Raw packet capture via `gopacket`
- TLS record parsing

### Phase 2: HTTP/2 Frame Capture

Go can capture HTTP/2 frames via:
- Custom `http2.Server` with frame logging
- `golang.org/x/net/http2` Framer access
- Raw connection wrapping

### Phase 3: HTTP Header Capture

Standard Go HTTP server already provides this.

## Captured Data Schema

```yaml
# Complete fingerprint record
fingerprint:
  id: "fp-uuid"
  timestamp: "2026-02-26T10:00:00Z"
  source_ip: "1.2.3.4"
  
  tls:
    version: "1.3"
    ja3_hash: "abc123..."
    ja4_fingerprint: "t13d1516h2_..."
    
    # Raw ClientHello for exact replay
    raw_client_hello: "base64..."
    
    cipher_suites:
      - value: 0x1301
        name: "TLS_AES_128_GCM_SHA256"
        position: 1
      - value: 0x1302
        name: "TLS_AES_256_GCM_SHA384"
        position: 2
      # ... with GREASE
    
    extensions:
      - type: 0
        name: "server_name"
        position: 1
        data: "..."
      - type: 65281
        name: "renegotiation_info"
        position: 2
      # ... exact order
    
    grease:
      - value: 0x5a5a
        position: 0  # First extension
      - value: 0x7a7a
        position: 15  # Middle extension
    
    supported_groups: [0x001d, 0x0017, 0x0018]
    signature_algorithms: [0x0403, 0x0804, ...]
    alpn: ["h2", "http/1.1"]
    alps: "h2"  # Chrome-specific
    
    # Certificate compression
    cert_compression: ["brotli"]  # Chrome
    
    # Key share
    key_share_groups: [0x001d, 0x0017]  # X25519, P-256
    
  http2:
    connection_preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    
    settings:
      - id: 1
        name: "HEADER_TABLE_SIZE"
        value: 65536
        position: 1
      - id: 2
        name: "ENABLE_PUSH"
        value: 0
        position: 2
      - id: 3
        name: "MAX_CONCURRENT_STREAMS"
        value: 1000
        position: 3
      - id: 4
        name: "INITIAL_WINDOW_SIZE"
        value: 6291456  # 6MB - Chrome!
        position: 4
    
    window_updates:
      - stream_id: 0  # Connection-level
        increment: 6291456
        timing_ms: 0.5  # After handshake
    
    pseudo_header_order:
      - ":method"
      - ":authority"
      - ":scheme"
      - ":path"
    
    stream_priority:
      weight: 256  # Chrome default
      exclusive: true
    
    frame_sequence:
      - type: "SETTINGS"
        flags: 0
      - type: "WINDOW_UPDATE"
        flags: 0
        stream_id: 0
      - type: "HEADERS"
        flags: 0x05  # END_HEADERS | END_STREAM
        stream_id: 1
    
  http:
    method: "GET"
    path: "/test"
    version: "HTTP/2.0"
    
    headers:
      - name: ":method"
        value: "GET"
        position: 1
        pseudo: true
      - name: ":authority"
        value: "example.com"
        position: 2
        pseudo: true
      - name: "user-agent"
        value: "Mozilla/5.0..."
        position: 5
      # ... exact order preserved
    
    user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)..."
    accept: "text/html,application/xhtml+xml,..."
    accept_encoding: "gzip, deflate, br"
    accept_language: "en-US,en;q=0.9"
    
    client_hints:
      sec_ch_ua: '"Chromium";v="110", "Not A(Brand)";v="24", "Google Chrome";v="110"'
      sec_ch_ua_mobile: "?0"
      sec_ch_ua_platform: '"Windows"'
    
    cookies:
      - name: "session"
        value: "abc123"
        attributes: "Secure; HttpOnly; SameSite=None"
    
    compression:
      accepted: ["gzip", "deflate", "br"]
      preferred: "br"
  
  behavior:
    connection_timing:
      tcp_established_ms: 45
      tls_handshake_ms: 120
      first_byte_ms: 125
    
    request_pattern:
      concurrent_streams: 1
      stream_dependency: null
      request_pacing_ms: 0
```

## Go Implementation Plan

### 1. Raw TLS ClientHello Capture

```go
package lab

import (
    "crypto/tls"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
)

// TLSFingerprint captures complete ClientHello
type TLSFingerprint struct {
    RawBytes        []byte
    Version         uint16
    CipherSuites    []uint16
    Extensions      []TLSExtension
    GREASE          []GREASEValue
    SupportedGroups []uint16
    ALPN            []string
    ALPS            string
    KeyShareGroups  []uint16
}

// Capture via packet capture or TLS config
func (s *LabServer) captureTLS(conn net.Conn) (*TLSFingerprint, error) {
    // Option 1: Use gopacket on loopback
    // Option 2: Wrap net.Conn and parse TLS records
    // Option 3: Use crypto/tls with custom GetConfigForClient
}
```

### 2. HTTP/2 Frame-Level Capture

```go
package lab

import (
    "golang.org/x/net/http2"
)

// HTTP2Fingerprint captures all HTTP/2 frames
type HTTP2Fingerprint struct {
    Settings        []http2.Setting
    WindowUpdates   []WindowUpdateInfo
    PseudoHeaders   []string
    HeaderOrder     []string
    FrameSequence   []FrameInfo
}

type FrameInfo struct {
    Type      http2.FrameType
    Flags     http2.Flags
    StreamID  uint32
    Length    uint32
    Timing    time.Duration  // Relative to connection start
}

// Custom HTTP/2 server that logs all frames
type CapturingHTTP2Server struct {
    *http2.Server
    FrameLogger func(http2.FrameHeader, []byte)
}
```

### 3. Complete Request Capture

```go
package lab

// CompleteFingerprint combines all layers
type CompleteFingerprint struct {
    ID          string
    Timestamp   time.Time
    SourceIP    string
    
    TLS         *TLSFingerprint
    HTTP2       *HTTP2Fingerprint
    HTTP        *HTTPFingerprint
    Behavior    *BehaviorFingerprint
}

// HTTPFingerprint captures HTTP-layer signals
type HTTPFingerprint struct {
    Method          string
    Path            string
    Headers         []HeaderInfo  // Preserves order
    UserAgent       string
    ClientHints     map[string]string
    CookieCount     int
}

type HeaderInfo struct {
    Name      string
    Value     string
    Position  int
    IsPseudo  bool
}
```

## API Endpoints

```
GET  /capture              # HTML report
GET  /capture/json         # JSON fingerprint
POST /baseline             # Store captured baseline
GET  /baseline/:id         # Retrieve baseline
POST /compare              # Compare against baseline
GET  /replay/:id           # Replay captured fingerprint
```

## Usage Flow

```bash
# 1. Start capture lab
./labd --capture-mode=full

# 2. Capture real browser fingerprint
curl -s https://localhost:8443/capture/json \
  --http2 --user-agent "Chrome..."

# 3. Save as baseline
curl -X POST https://localhost:8443/baseline \
  -d @chrome_110_fingerprint.json

# 4. Test Go client against baseline
./brwslab fetch https://localhost:8443/test \
  --engine=spoof-chrome \
  --baseline=chrome_110

# 5. Get diff report
./brwslab diff \
  --baseline=chrome_110 \
  --test=spoof-chrome \
  --url=https://localhost:8443/capture
```

## Implementation Files

```
brws/lab/
├── capture.go          # Core capture logic
├── tls_capture.go      # TLS ClientHello parsing
├── http2_capture.go    # HTTP/2 frame capture
├── database.go         # Baseline storage
├── replay.go           # Fingerprint replay
└── diff.go             # Comparison engine
```

## Next Steps

1. Implement raw TLS capture with gopacket
2. Build HTTP/2 frame interceptor
3. Create fingerprint database
4. Add diff/replay capabilities
5. Integrate with spoof engine
