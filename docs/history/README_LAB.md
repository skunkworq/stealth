# Browser Fingerprint Lab

A comprehensive system for capturing, analyzing, and replaying browser fingerprints across TLS, HTTP/2, and HTTP layers.

## Quick Start

```bash
# Build everything
make build

# Generate certificates (for HTTPS capture)
make certs

# Start the lab server (foreground with visible logs)
make run-lab-https

# Or run in background
make run-lab-bg
# Then check logs: tail -f labd.log
```

### Access the UI

- **HTTP**: http://localhost:8080
- **HTTPS**: https://localhost:8443

**Note about HTTPS:** The certificate is self-signed, so browsers will show a security warning:
- Chrome: Click "Advanced" → "Proceed to localhost (unsafe)"
- Firefox: Click "Advanced" → "Accept the Risk and Continue"
- Safari: Click "Show Details" → "visit this website"
- curl: Use `-k` flag (e.g., `curl -k https://localhost:8443/health`)

## Features

### 🔬 Fingerprint Capture Lab (`labd`)

The lab server captures complete browser signatures:

- **TLS Layer**: ClientHello, cipher suites, extensions, JA3/JA4 fingerprints, ALPS
- **HTTP/2 Layer**: SETTINGS frames, WINDOW_UPDATE, pseudo-header order, stream priority
- **HTTP Layer**: Headers, client hints, cookie handling
- **Behavioral**: Timing patterns, connection reuse

### Web UI

Browse to `http://localhost:8080` for a modern, interactive fingerprint viewer:

![UI Preview](docs/ui-preview.png)

Features:
- Real-time fingerprint capture
- Detailed TLS/HTTP2/HTTP breakdown
- JSON/YAML export
- Visual fingerprint comparison

### Configuration System

Define fingerprint schemas in JSON:

```json
{
  "name": "chrome-116-mac",
  "browser": {"name": "chrome", "version": "116"},
  "os": {"name": "macos", "version": "14"},
  "tls": {
    "cipher_suites": [...],
    "extensions": [...],
    "alpn": ["h2", "http/1.1"],
    "alps": "h2"
  },
  "http2": {
    "settings": {
      "header_table_size": 65536,
      "initial_window_size": 6291456
    },
    "pseudo_header_order": [":method", ":authority", ":scheme", ":path"]
  }
}
```

## Commands

### Lab Server

```bash
# Start lab server
make run-lab-https

# Or manually
./build/labd --http-port 8080 --https-port 8443 \
  --tls-cert server.crt --tls-key server.key -v
```

### CLI (brwslab)

```bash
# List fingerprint presets
./build/brwslab config list

# Show preset details
./build/brwslab config show chrome-116-windows

# Export preset to JSON
./build/brwslab config export chrome-116-windows > my-config.json

# Capture your fingerprint
./build/brwslab fingerprint --lab http://localhost:8080

# Compare fingerprints between engines
./build/brwslab diff --lab http://localhost:8080 \
  --engine native --engine chromium

# Fetch with specific engine
./build/brwslab fetch https://example.com --engine chromium
```

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Modern web UI |
| `GET /capture` | Fingerprint capture page |
| `GET /capture/json` | JSON fingerprint export |
| `GET /capture/yaml` | YAML export (curl-impersonate compatible) |
| `POST /baseline` | Store baseline fingerprint |
| `GET /baseline/:name` | Retrieve baseline |
| `GET /compare` | Compare fingerprints |
| `GET /health` | Health check |

## Fingerprint Configuration

### Built-in Presets

- `chrome-116-windows` - Chrome 116 on Windows 10
- `firefox-109` - Firefox 109

### Custom Configurations

Place JSON files in `./fingerprints/`:

```bash
mkdir -p fingerprints
cat > fingerprints/my-browser.json << 'EOF'
{
  "name": "my-browser",
  "browser": {"name": "chrome", "version": "120"},
  "os": {"name": "linux"},
  "tls": { ... },
  "http2": { ... },
  "http": { ... }
}
EOF
```

### Configuration Schema

```go
type FingerprintConfig struct {
    Name        string          // Configuration name
    Browser     BrowserIdentity // Browser info
    OS          OSIdentity      // OS info
    TLS         *TLSConfig      // TLS settings
    HTTP2       *HTTP2Config    // HTTP/2 settings
    HTTP        *HTTPConfig     // HTTP settings
}
```

See `brws/config/fingerprint.go` for full schema.

## Chrome 116 Signature Details

### TLS Configuration

```yaml
Cipher Suites:
  - TLS_AES_128_GCM_SHA256
  - TLS_AES_256_GCM_SHA384
  - TLS_CHACHA20_POLY1305_SHA256
  - GREASE
  - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  - ...

Extensions:
  - GREASE
  - server_name
  - extended_master_secret
  - renegotiation_info
  - supported_groups [X25519, P-256, P-384]
  - ec_point_formats
  - signed_certificate_timestamp
  - application_layer_protocol_negotiation [h2, http/1.1]
  - status_request
  - GREASE
  - key_share [X25519, P-256]
  - psk_key_exchange_modes
  - supported_versions [TLS 1.3, 1.2]
  - compress_certificate [brotli]
  - application_settings (ALPS: h2)
  - GREASE
  - padding

ALPN: [h2, http/1.1]
ALPS: h2
cert_compression: [brotli]
```

### HTTP/2 Configuration

```yaml
SETTINGS:
  HEADER_TABLE_SIZE:      65536      # 64KB
  ENABLE_PUSH:            0
  MAX_CONCURRENT_STREAMS: 1000
  INITIAL_WINDOW_SIZE:    6291456    # 6MB (Go uses 64KB!)
  MAX_HEADER_LIST_SIZE:   262144

Pseudo-Header Order:
  1. :method
  2. :authority
  3. :scheme
  4. :path

WINDOW_UPDATE:
  Stream: 0 (connection-level)
  Increment: 6291456
```

### HTTP Headers

```
:method: GET
:authority: example.com
:scheme: https
:path: /
sec-ch-ua: "Chromium";v="116", "Not)A;Brand";v="24", "Google Chrome";v="116"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
upgrade-insecure-requests: 1
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...
accept: text/html,application/xhtml+xml,application/xml;q=0.9,...
sec-fetch-site: none
sec-fetch-mode: navigate
sec-fetch-user: ?1
sec-fetch-dest: document
accept-encoding: gzip, deflate, br
accept-language: en-US,en;q=0.9
```

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
│  └── Client Hints (sec-ch-ua*)                             │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: HTTP/2 Transport                                  │
│  ├── SETTINGS frame values & order                         │
│  ├── WINDOW_UPDATE timing & values                         │
│  ├── Pseudo-header ordering                                │
│  └── Stream priority & weight                              │
├─────────────────────────────────────────────────────────────┤
│  Layer 1: TLS Handshake                                     │
│  ├── Raw ClientHello bytes                                 │
│  ├── Cipher suite list & order                             │
│  ├── Extension list & order                                │
│  ├── GREASE values & positions                             │
│  ├── ALPN/ALPS values                                      │
│  └── Certificate compression                               │
└─────────────────────────────────────────────────────────────┘
```

## Makefile Targets

```
make help              # Show all available targets
make build             # Build all binaries
make certs             # Generate TLS certificates
make run-lab-https     # Start lab server with HTTPS
make run-lab-debug     # Start with verbose logging
make test              # Run tests
make capture-chrome    # Capture Chrome fingerprint
make diff-fingerprints # Compare fingerprints
make clean             # Clean build artifacts
make dev-setup         # Setup development environment
```

## Browser Support Matrix

| Feature | Chrome | Firefox | Safari | Edge |
|---------|--------|---------|--------|------|
| TLS 1.3 | ✓ | ✓ | ✓ | ✓ |
| ALPS Extension | ✓ | ✗ | ✗ | ✓ |
| Cert Compression | ✓ | ✗ | ✗ | ✓ |
| Client Hints | ✓ | ✗ | ✗ | ✓ |
| HTTP/2 PRIORITY | ✓ | ✓ | ✓ | ✓ |
| Unique SETTINGS | ✓ | ✓ | ✓ | ✓ |

## Development

### Project Structure

```
brws/
├── config/          # Configuration structures
├── engine/          # HTTP client engines
│   ├── spoof/       # Fingerprint spoofing
│   ├── chromium/    # Chrome CDP
│   ├── firefox/     # Firefox Playwright
│   └── ...
├── lab/             # Fingerprint capture lab
│   ├── static/      # Web UI files
│   ├── capture.go   # Capture logic
│   ├── tls_parser.go
│   └── ...
└── session/         # Session management

cmd/
├── labd/            # Lab server command
├── brwslab/         # CLI command
└── evalbench/       # Benchmark tool

fingerprints/        # Custom fingerprint configs
```

### Adding a New Preset

1. Edit `brws/config/fingerprint.go`
2. Add preset to `GetPreset()` and `ListPresets()`
3. Rebuild: `make build`

## License

MIT License - See LICENSE file for details
