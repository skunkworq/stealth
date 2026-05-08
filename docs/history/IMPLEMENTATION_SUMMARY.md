# Browser Fingerprint Lab - Implementation Summary

## What Was Built

### 1. Enhanced Lab Server (`labd`)

A comprehensive fingerprint capture server with:

- **Multi-layer capture**: TLS, HTTP/2, HTTP, and behavioral signals
- **Modern Web UI**: Beautiful, interactive interface (embedded static files)
- **API endpoints**: JSON/YAML export, baseline management, comparison
- **Raw TLS parsing**: Complete ClientHello byte-level parser
- **HTTP/2 frame capture**: Settings, window updates, pseudo-header order

**Key Files:**
- `brws/lab/capture.go` - Core capture structures
- `brws/lab/tls_parser.go` - Raw TLS ClientHello parser
- `brws/lab/enhanced_server.go` - HTTP server with embedded UI
- `brws/lab/static/index.html` - Modern web UI

### 2. Configuration System (`brws/config`)

A comprehensive configuration schema for fingerprint-based impersonation:

```go
type FingerprintConfig struct {
    Name        string
    Browser     BrowserIdentity
    OS          OSIdentity
    TLS         *TLSConfig
    HTTP2       *HTTP2Config
    HTTP        *HTTPConfig
}
```

**Features:**
- JSON-based configuration files
- Built-in presets (Chrome 116, Firefox 109)
- Configuration loader with search paths
- Validation and defaults

**Key Files:**
- `brws/config/fingerprint.go` - Configuration structures and presets

### 3. CLI Integration (`brwslab`)

Extended the CLI with configuration commands:

```bash
# List available presets
brwslab config list

# Show preset details
brwslab config show chrome-116-windows

# Export to JSON
brwslab config export chrome-116-windows > config.json
```

### 4. Makefile

Comprehensive build system:

```bash
make build              # Build all binaries
make certs              # Generate TLS certificates
make run-lab-https      # Start lab server
make capture-chrome     # Capture Chrome fingerprint
make diff-fingerprints  # Compare fingerprints
```

## How to Use

### Start the Lab

```bash
make dev-setup      # Setup environment
make run-lab-https  # Start server
```

Open http://localhost:8080 in your browser to see the UI.

### Capture a Fingerprint

```bash
# Using curl
curl -s http://localhost:8080/capture/json | jq .

# Using brwslab CLI
brwslab fetch http://localhost:8080/capture --engine chromium

# Or just open the UI and refresh
```

### Manage Configurations

```bash
# List presets
brwslab config list

# View Chrome 116 signature details
brwslab config show chrome-116-windows

# Export for customization
brwslab config export chrome-116-windows > my-chrome.json
```

### Create Custom Configuration

```bash
mkdir -p fingerprints
cat > fingerprints/my-browser.json << 'JSON'
{
  "name": "my-browser",
  "browser": {"name": "chrome", "version": "120"},
  "os": {"name": "macos"},
  "tls": {
    "cipher_suites": [
      {"value": 4865, "name": "TLS_AES_128_GCM_SHA256"},
      {"grease": true}
    ],
    "extensions": [
      {"name": "server_name"},
      {"name": "application_layer_protocol_negotiation"}
    ],
    "alpn": ["h2", "http/1.1"]
  },
  "http2": {
    "settings": {
      "header_table_size": 65536,
      "initial_window_size": 6291456
    },
    "pseudo_header_order": [":method", ":authority", ":scheme", ":path"]
  }
}
JSON
```

## Chrome 116 Signature (Key Values)

### TLS
- **Cipher Suites**: 16 ciphers with GREASE interspersed
- **Extensions**: 17 extensions including ALPS (Chrome-specific)
- **Supported Groups**: X25519, P-256, P-384 with GREASE
- **ALPN**: h2, http/1.1
- **ALPS**: h2 (Application-Layer Protocol Settings)
- **Cert Compression**: brotli

### HTTP/2
- **HEADER_TABLE_SIZE**: 65536 (vs Go default 4096)
- **INITIAL_WINDOW_SIZE**: 6291456 (6MB vs Go default 65535)
- **MAX_CONCURRENT_STREAMS**: 1000
- **Pseudo-Header Order**: :method, :authority, :scheme, :path
- **WINDOW_UPDATE**: 6291456 on connection

### HTTP Headers
- **User-Agent**: Mozilla/5.0 (Windows NT 10.0; Win64; x64)...
- **Client Hints**: sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform
- **Sec-Fetch**: sec-fetch-site, sec-fetch-mode, sec-fetch-dest, sec-fetch-user

## Next Steps for HTTP/2 Emulation

The current Go HTTP/2 implementation (`x/net/http2`) has hardcoded values:

```go
// Go defaults (NOT Chrome!)
settings := []Setting{
    {ID: SettingHeaderTableSize, Val: 4096},      // Chrome: 65536
    {ID: SettingEnablePush, Val: 0},              // Chrome: 0
    {ID: SettingInitialWindowSize, Val: 65535},   // Chrome: 6291456
}
```

To match Chrome's fingerprint exactly, you need to:

1. **Fork or vendor `x/net/http2`** - Modify hardcoded SETTINGS
2. **Implement custom Framer** - Control frame encoding
3. **Set pseudo-header order** - Currently hardcoded in Go
4. **Send WINDOW_UPDATE** - Chrome sends 6MB immediately

See `CURL_IMPERSONATE_ANALYSIS.md` for detailed signature breakdown.

## File Structure

```
/Users/benebsworth/projects/stealth/
├── Makefile                      # Build automation
├── README_LAB.md                 # Lab documentation
├── server.crt / server.key       # TLS certificates (generated)
├── build/
│   ├── labd                      # Lab server binary
│   └── brwslab                   # CLI binary
├── brws/
│   ├── config/
│   │   └── fingerprint.go        # Configuration system
│   ├── engine/
│   │   └── spoof/
│   │       ├── signature.go      # Signature database
│   │       └── spoof.go          # Spoofing engine
│   └── lab/
│       ├── capture.go            # Fingerprint capture
│       ├── tls_parser.go         # TLS ClientHello parser
│       ├── enhanced_server.go    # HTTP server
│       └── static/
│           └── index.html        # Modern web UI
├── cmd/
│   ├── labd/
│   │   └── main.go               # Lab server command
│   └── brwslab/
│       └── main.go               # CLI command (updated)
└── fingerprints/
    └── chrome-116-custom.json    # Sample custom config
```

## Success Metrics

| Metric | Before | After |
|--------|--------|-------|
| Fingerprint Layers | 1 (HTTP only) | 4 (TLS, HTTP2, HTTP, Behavior) |
| TLS Capture | Partial (Go limitations) | Complete (raw parser) |
| HTTP/2 Capture | None | Settings, window, headers |
| Web UI | Basic HTML | Modern interactive UI |
| Configuration | Hardcoded | JSON schema + presets |
| CLI Commands | 5 | 8 (+ config management) |

## Testing Checklist

- [x] `make build` succeeds
- [x] `make certs` generates certificates
- [x] `make run-lab-https` starts server
- [x] http://localhost:8080 shows UI
- [x] /capture/json returns JSON fingerprint
- [x] /capture/yaml returns YAML
- [x] `brwslab config list` shows presets
- [x] `brwslab config show chrome-116-windows` displays config
- [x] Custom fingerprint files load correctly

