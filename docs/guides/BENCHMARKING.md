# Benchmarking Stealth Capabilities

This guide covers the benchmarking and evaluation tools for measuring how well the stealth platform evades bot detection, fingerprinting, and access controls.

## Quick Reference

| Tool | Path | Purpose | Engine-agnostic |
|------|------|---------|-----------------|
| `benchmark` | `cmd/ml/bench/benchmark` | Comprehensive benchmark suite (endpoints, capabilities, fingerprint, performance) | Yes — discovers engines via registry |
| `evalbench` | `cmd/ml/bench/evalbench` | Real-world endpoint testing against live protected sites | No — hardcoded tools |
| `eval_e2e` | `cmd/ml/bench/eval_e2e` | End-to-end smoke test against local lab | No |
| `labd` | `cmd/lab/server/labd` | Local fingerprint capture lab server | N/A |
| `brwslab` | `cmd/lab/cli/brwslab` | CLI for the fingerprint lab | N/A |
| `vecbench` | `cmd/ml/bench/vecbench` | Vector search backend benchmarks | N/A |

---

## 1. `benchmark` — Comprehensive Suite

The primary benchmarking tool. It runs structured tests across multiple dimensions and can discover any engine registered in `brws/browser/engine`.

### Building

```bash
go build -o build/benchmark ./cmd/ml/bench/benchmark
```

### Suites

```bash
# List available engines
./build/benchmark engines

# List available endpoint categories
./build/benchmark list

# Endpoint testing — hit real URLs with different protection levels
./build/benchmark --suite endpoints --categories protected,cloudflare

# Capability testing — verify JS, HTTP/2, HTTP/3, WebSocket support
./build/benchmark --suite capabilities

# Fingerprint consistency — check if fingerprint is stable across requests
./build/benchmark --suite fingerprint --iterations 5

# Performance benchmarking — measure latency and throughput
./build/benchmark --suite performance --iterations 10

# Run everything
./build/benchmark --suite all
```

### Engine Selection

```bash
# Test specific engines only
./build/benchmark --engines native,chromium --suite endpoints

# Test all available engines (default)
./build/benchmark --suite all
```

Currently registered engines:

| Engine | Description |
|--------|-------------|
| `native` | Go `net/http` with TLS spoofing |
| `chromium` | Chrome via CDP |
| `chromium-stealth` | Chrome with full stealth patches |
| `firefox` | Firefox via Playwright |
| `webkit` | WebKit via Playwright |

### Shield Detection Evaluation

Evaluate how well the internal **shield detector** identifies evasion profiles:

```bash
# Full evaluation with behavioral analysis
./build/benchmark shield

# HTTP-only (no behavioral data)
./build/benchmark shield --no-behavioral

# JSON output for CI
./build/benchmark shield --json
```

This runs profiles ranging from bare bots (`curl`, `python-requests`) to advanced stealth (full Chrome impersonation with behavioral data) and reports accuracy, precision, recall, F1, and per-vector coverage.

### Competitive Comparison

Compare the project's stealth against popular scraping tools:

```bash
# Rank tools by evasion rate
./build/benchmark compare

# Verbose per-vector detail
./build/benchmark compare -v --json
```

Tools compared: `python-requests`, `Scrapy`, `Playwright`, `Puppeteer`, `curl-impersonate`, `nodriver`, `Scrapling` (stealth + playwright variants), and the project's own stealth sword.

### Blackbox Testing

Run real external tool processes against a local `labd` server:

```bash
# Terminal 1: start lab
go run ./cmd/lab/server/labd --http-port 8080

# Terminal 2: blackbox test
./build/benchmark blackbox --base-url http://127.0.0.1:8080

# Specific tools only
./build/benchmark blackbox --tools scrapy_default,nodriver
```

Each tool is probed against `/capture/json` (raw fingerprint) and `/api/stealth-test` (shield scoring).

### Output Formats

```bash
./build/benchmark --suite all --format json --output results.json
./build/benchmark --suite all --format table        # default
```

---

## 2. `evalbench` — Real-World Endpoint Testing

Tests actual HTTP clients against live protected sites. Unlike `benchmark`, `evalbench` has hardcoded implementations for each tool it tests.

### Building

```bash
go build -o build/evalbench ./cmd/ml/bench/evalbench
```

### Usage

```bash
# Test all default tools against all targets
./build/evalbench

# Enable stealth mode (adds brwslab-chromium-stealth to the list)
./build/evalbench --stealth

# Side-by-side comparison: brwslab-chromium vs brwslab-chromium-stealth
./build/evalbench --compare-stealth

# Test specific tools
./build/evalbench --tools curl,brwslab-chromium-stealth

# Keep browser open for visual inspection (10 seconds)
./build/evalbench --dwell 10s --tools brwslab-chromium-stealth

# JSON output
./build/evalbench --json
```

### Tools

| Tool | Description |
|------|-------------|
| `curl` | Standard `curl` subprocess |
| `curl-impersonate-chrome` | curl-impersonate with Chrome TLS/JA3 |
| `curl-impersonate-ff` | curl-impersonate with Firefox TLS/JA3 |
| `brwslab-native` | Go native engine |
| `brwslab-chromium` | Chrome without stealth patches |
| `brwslab-chromium-stealth` | Chrome with full stealth |
| `brwslab-spoof-chrome` | TLS spoofing for Chrome profile |
| `brwslab-spoof-firefox` | TLS spoofing for Firefox profile |

### Built-in Targets

| Target | URL | Protection |
|--------|-----|------------|
| `coles-avocado` | coles.com.au product page | Incapsula |
| `httpbin-get` | httpbin.org/get | None (control) |
| `wikipedia` | en.wikipedia.org/wiki/Avocado | None (control) |
| `linkedin-ben-ebsworth` | linkedin.com/in/... | LinkedIn (heavy) |

### Output

For each tool/target combination, `evalbench` reports:
- Success / Blocked / Error
- HTTP status code
- Duration
- Body size
- Blocker identification (if detected)

---

## 3. `labd` + `brwslab` — Local Fingerprint Lab

For controlled, repeatable testing without hitting live sites.

### Start the lab

```bash
go run ./cmd/lab/server/labd --http-port 8080 --https-port 8443
```

The lab captures complete browser signatures across:
- TLS (JA3 / JA4 fingerprints)
- HTTP/2 (settings, frames, priority)
- HTTP (headers, ordering, encoding)

### Test against the lab

```bash
# Use brwslab CLI
go run ./cmd/lab/cli/brwslab --help

# Or run eval_e2e smoke test
go run ./cmd/ml/bench/eval_e2e
```

### Endpoints

| Endpoint | Purpose |
|----------|---------|
| `GET /health` | Lab health check |
| `GET /capture/json` | Raw fingerprint JSON |
| `POST /api/stealth-test` | Shield scoring |
| `GET /proxy.pac` | Proxy auto-config |

---

## 4. Adding a New Engine

### For `benchmark` (recommended)

1. Implement `engine.Engine` interface:
   ```go
   type Engine interface {
       Name() string
       Capabilities() Capabilities
       Do(ctx context.Context, req *Request) (*Response, error)
       Close() error
   }
   ```

2. Register in package `init()`:
   ```go
   func init() {
       engine.Register("myengine", New)
   }
   ```

3. Add blank import to `cmd/ml/bench/benchmark/main.go`:
   ```go
   _ "github.com/skunkworq/stealth/brws/browser/engine/myengine"
   ```

4. Rebuild and run:
   ```bash
   ./build/benchmark engines          # should list "myengine"
   ./build/benchmark --suite all      # will test it automatically
   ```

### For `evalbench`

`evalbench` requires manual wiring. Add a new `case` in `testTool()` and implement a `runMyEngine()` function:

```go
// In cmd/ml/bench/evalbench/main.go
func testTool(tool string, target TestTarget) TestResult {
    switch tool {
    // ... existing cases ...
    case "myengine":
        return runMyEngine(target, start)
    }
}

func runMyEngine(target TestTarget, start time.Time) TestResult {
    // Implementation
}
```

Also add it to `resolveTools()` if it should be included in `--tools all`.

---

## 5. Understanding Results

### Success Criteria

A request is considered **successful** if:
- HTTP status is 200–299
- Response body contains the expected substring for that target

A request is considered **blocked** if:
- HTTP status is 403, 429, or 503
- Response contains known block-page markers (CAPTCHA, challenge, "Access Denied")
- Body is missing the expected content

### Fingerprint Consistency Score

The `fingerprint` suite measures whether the same engine produces identical fingerprints across multiple requests. A score of 100% means the fingerprint is perfectly stable. Lower scores indicate entropy that could flag the client as suspicious.

### Shield Detection Metrics

The `shield` subcommand reports:
- **Accuracy** — overall correctness
- **Precision** — of detected bots, how many were actual bots
- **Recall** — of all bots, how many were detected
- **F1** — harmonic mean of precision and recall
- **Per-vector coverage** — which fingerprint vectors (TLS, HTTP/2, headers, JS) contributed to detection

---

## 6. CI Integration

All benchmark tools support JSON output for CI pipelines:

```bash
./build/benchmark --suite all --format json --output benchmark.json
./build/benchmark shield --json > shield.json
./build/evalbench --json > evalbench.json
```

Example GitHub Actions step:

```yaml
- name: Run stealth benchmarks
  run: |
    go build -o build/benchmark ./cmd/ml/bench/benchmark
    ./build/benchmark --suite endpoints --format json --output benchmark.json
- name: Upload results
  uses: actions/upload-artifact@v4
  with:
    name: benchmark-results
    path: benchmark.json
```

---

## See Also

- [`docs/architecture/ARCHITECTURE_PERFORMANCE.md`](../architecture/ARCHITECTURE_PERFORMANCE.md) — Semantic extraction performance
- [`docs/analysis/BENCHMARK_RESULTS.md`](../analysis/BENCHMARK_RESULTS.md) — Historical benchmark data
- [`docs/analysis/EVALUATION_REPORT.md`](../analysis/EVALUATION_REPORT.md) — Evaluation methodology
