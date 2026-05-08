# Model: Network Module

> **Purpose:** Network infrastructure for fingerprint capture labs, proxy rotation, tiered escalation, and raw packet sniffing.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        Network Layer                         │
├─────────────────┬─────────────────┬─────────────────────────┤
│   MITM Proxy    │   Proxy Pool    │    Packet Sniffer       │
│  (Capture Lab)  │  (Rotation)     │   (Raw Capture)         │
└────────┬────────┴────────┬────────┴───────────┬─────────────┘
         │                 │                    │
         ▼                 ▼                    ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ TLS ClientHello │ │ Tier Escalation │ │ libpcap / Rust  │
│ HTTP Headers    │ │ Round-Robin     │ │ FFI Bridge      │
│ Certificate Gen │ │ Health Tracking │ │ Packet Events   │
└─────────────────┘ └─────────────────┘ └─────────────────┘
```

---

## MITM Proxy (`proxy/proxy.go`)

A TCP proxy that intercepts TLS and HTTP traffic for fingerprint capture.

### Protocol Detection

Peeks first 8 bytes:
- **TLS direct** (`0x16` record) → `handleTLS()`
- **HTTP CONNECT** → `handleHTTPConnect()` → optional MITM or tunnel
- **Plain HTTP** → `handleHTTP()`

### TLS Capture Flow

1. **Accept connection** → wrap in `capturedConn`
2. **TLS wrapping** → `tlsCaptureConn` buffers reads until complete ClientHello
3. **Parse** → `tlsparser.ParseClientHello()` extracts cipher suites, extensions, SNI
4. **ALPN discovery** → connects to real target first to discover negotiated ALPN
5. **Certificate injection** → generates leaf cert for SNI via `CertificateManager`
6. **Proxy** → bidirectional copy with optional HTTP inspection

### Transparent Mode

`TransparentMode: true`:
- Reads raw TLS record header + ClientHello
- Parses for fingerprinting
- Forwards **raw bytes unchanged** to target
- Pipes rest bidirectionally without terminating TLS

---

## Certificate Manager (`proxy/certs.go`)

Generates realistic certificate chains:

- **External CA**: load from PEM files
- **Auto-generated CA**: mimics DigiCert, Let's Encrypt, Google Trust, Amazon
- **3-tier chain**: Root CA → Intermediate → Leaf
- **Per-host caching**: `map[string]*tls.Certificate`
- **Realistic details**: backdated `NotBefore`, KeyUsage, SANs with `www.` variants, 90-day validity

---

## Proxy Pool (`proxy/pool/pool.go`)

Manages upstream proxies with health tracking.

```go
type Pool struct {
    proxies  []*Proxy
    current  int
    strategy Strategy
    stats    PoolStats
}
```

### Selection Strategies

| Strategy | Behavior |
|---|---|
| `RoundRobin` | Cycles sequentially |
| `Random` | Uniform random pick |
| `LeastUsed` | Lowest `Uses` count |
| `Fastest` | Lowest recorded latency |
| `Weighted` | Weighted distribution (stub) |

### Health Tracking

- `RecordSuccess(url, latency)` — updates latency, marks healthy
- `RecordFailure(url)` — increments failure counter
- **>5 failures** → proxy marked `IsWorking = false` and excluded

### Automatic Rotation Client

```go
rotation, _ := pool.NewRotation(proxyURLs, pool.StrategyRandom)
resp, err := rotation.Get("https://example.com")
```

Dynamically sets `transport.Proxy` per request and records outcomes.

---

## Tiered Proxy Escalation (`proxy/pool/tier.go`)

Per-domain adaptive proxy quality escalation.

```go
type TierTracker struct {
    tiers  []TieredProxy  // 0=cheapest, 2=premium
    states sync.Map       // map[eTLD+1]*domainTierState
    EscalateThreshold int // default 30
    DeescalateAt      int // default -10
    ErrorWeight       int // default 10
    SuccessWeight     int // default 1
}
```

### Escalation Logic

1. All domains start at **tier 0** (datacenter)
2. On error: `errorScore += ErrorWeight` (+10)
3. When `errorScore >= EscalateThreshold` (30): escalate to next tier (residential/mobile)
4. On success: `errorScore -= SuccessWeight` (-1)
5. When `errorScore <= DeescalateAt` (-10): de-escalate to cheaper tier
6. State keyed by **eTLD+1** via `golang.org/x/net/publicsuffix`

---

## HTTP Client Factory (`client/httpclient.go`)

Creates `http.Client` instances with:
- Configurable timeouts, keep-alives, idle connection limits
- Optional proxy or custom dialer injection
- HTTP/2 enabled by default

---

## Packet Sniffer (`sniff/sniffer.go`)

CGO bindings to Rust library (`libstealth_sniffer`) using libpcap:
- Converts C `PacketEventC` structs to Go `Packet` structs
- Captures timestamps, IPs, protocol, payload

---

## Files

| File | Description |
|---|---|
| `proxy/proxy.go` | MITM TLS/HTTP proxy, protocol detection, capture |
| `proxy/certs.go` | Certificate authority and per-host cert generation |
| `proxy/pool/pool.go` | Proxy pool with health tracking and strategies |
| `proxy/pool/tier.go` | Per-domain tiered proxy escalation |
| `client/httpclient.go` | HTTP client factory |
| `sniff/sniffer.go` | CGO packet capture bridge to Rust/libpcap |
