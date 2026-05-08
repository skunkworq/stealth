# Original Design Brief — Historical Context

> **Note:** This document was the original design brief that launched the project. It articulates an ethical stance focused on "authorized automation and compatibility testing" rather than bot evasion. The actual implementation has evolved significantly beyond this brief to include stealth, anti-detection, challenge-solving, and behavioral evasion capabilities. This file is preserved for historical context. For the current system, see [`README.md`](README.md) and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

**Expert**: Browser networking / transport engineer (TLS, HTTP/2/3, client fingerprinting)
**Objective**: Give you a from-scratch design for a Go CLI + library that achieves *browser-grade fidelity for legitimate testing* and provides deep fingerprint observability, without turning it into a “human-impersonation / bot-evasion” kit.
**Assumptions**: You’re inspired by `curl-impersonate`, you understand TLS/HTTP fingerprinting exists, and your end goal is “looks like a real browser” at the network layer; you’re willing to run real browser engines locally/remote when you actually need true parity.

I’m not going to help you build a tool whose goal is “indistinguishable from a human user” or “spoofing so traffic 100% looks like a real browser,” because that’s basically a spec for evading bot detection and access controls at scale. Humans love calling that “browser emulation,” but the internet mostly experiences it as “someone is trying to sneak past defenses.”

What I *can* do: design a Go-based CLI + library that (1) uses **real browser networking stacks** when you need true browser parity, (2) gives you **instrumentation and fingerprint diffs** so you can see exactly what a server/CDN/WAF would see, and (3) supports **authorized** automation and compatibility testing.

---

## What “real browser traffic” actually means

When people say “make it look like Chrome,” they usually mean multiple layers at once:

1. **TLS ClientHello fingerprint**

   * ClientHello parameters (TLS versions, cipher suite list + order, signature algorithms, supported groups, extension set + order, GREASE behavior, ALPN, and more) differ materially across clients and TLS libraries. ([lwt hiker][1])
   * Fingerprints like **JA3** are derived from a subset of ClientHello features and are widely used. ([lwt hiker][1])
   * Modern browsers change behavior over time. Chrome even shipped a feature that *permutes TLS extension order*, which makes JA3 unstable connection-to-connection. ([fastly.com][2])

2. **HTTP/2 “handshake” and framing fingerprint**

   * HTTP/2 clients are fingerprintable via their initial SETTINGS choices, ordering, flow-control behaviors (e.g., WINDOW_UPDATE), stream priority behaviors, and pseudo-header ordering. ([lwt hiker][3])
   * This is used by commercial anti-bot / anti-DDoS systems to classify clients early, before sending meaningful content. ([lwt hiker][3])

3. **HTTP/1.1 and HTTP/2 header “shape”**

   * Header set, casing, ordering, compression behavior, Accept-Encoding patterns, Client Hints (`Sec-CH-UA*`)… these are easy to “copy,” so serious systems don’t rely only on these.

4. **HTTP/3 / QUIC**

   * QUIC transport parameters and packetization can be fingerprinted too. Not in your links directly, but it’s part of the current reality, and a pure-Go stack won’t match Chrome/Apple stacks byte-for-byte.

5. **JavaScript + device fingerprinting**

   * Canvas/WebGL, fonts, audio, timing jitter, storage, navigator properties, extensions, screen metrics, timezone/locale consistency, and automation artifacts. A pure HTTP client does none of this. So “100% real user” is already dead on arrival unless you run an actual browser.

6. **Behavioral signals**

   * Request pacing, navigation sequences, caching behavior, cookie churn, interaction events, and “human messiness.” Cloudflare explicitly combines fingerprints with aggregated and inter-request signals and ML models. ([The Cloudflare Blog][4])

So: network spoofing alone is not “indistinguishable.” It’s “you match a subset of signals until the next browser/WAF update.”

---

## Design philosophy that actually works in 2026

If you want traffic that *is* browser traffic, the most reliable method is embarrassingly simple: **use a real browser engine’s network stack**. That’s why `curl-impersonate` had to patch curl and swap TLS implementations (BoringSSL/NSS) and adjust HTTP/2 settings, etc. ([GitHub][5])

In Go, you have two realistic paths:

### Path A: “Truthful fidelity”

Run real browsers (Chromium/Firefox/WebKit) and treat them as engines behind a Go CLI/library. This gives you:

* Authentic TLS/HTTP2/HTTP3 behavior (because it’s literally the browser)
* Real cookie jar, cache, service workers (if you allow)
* JS execution and client-side fingerprint surfaces (the stuff bots fail at)

### Path B: “Native Go transport with visibility”

Use Go’s `net/http` plus controlled knobs, but accept it will *not* be byte-identical to browsers across TLS/HTTP2/QUIC. Instead, focus on:

* Correctness, stability, performance
* Fingerprint measurement + diffing so you can *see* where you differ

The sane tool provides both, explicitly.

---

## Proposed project: `brwslab` (CLI) + `brws` (Go library)

### Non-goals

* “Indistinguishable from a human user”
* “Bypass WAF/bot management”
* Shipping “Chrome-perfect” TLS/HTTP2 spoof profiles

### Goals

* Make it easy to run requests through **real browsers** or **native Go**
* Capture and compare **what a server can fingerprint**
* Provide deterministic, testable, observable behavior for QA/security research

---

## CLI UX

### Core commands

1. `brwslab fetch <url>`

   * Makes a request via an engine (`chromium`, `firefox`, `webkit`, `native`)
   * Outputs: status, headers, body (optionally), plus trace

2. `brwslab session`

   * `session new --engine=chromium --profile-dir=...`
   * `session run <script>` (authorized test flows: navigate, click, wait, etc.)
   * `session export-cookies`, `session import-cookies`

3. `brwslab fingerprint`

   * Runs a request against a controlled “lab server” endpoint and prints:

     * TLS fingerprint summary (JA3/JA4-like fields, not just a hash)
     * HTTP/2 fingerprint summary (SETTINGS presence/order, pseudo-header order, priority usage)
   * Also prints a “diff vs baseline browser build X” (baseline comes from your own captured dataset)

4. `brwslab diff`

   * `diff --engine=native --engine=chromium --url=https://…`
   * Compares: protocol negotiation, headers, redirects, cookie behavior, timing stats, caching behavior

5. `brwslab trace`

   * Produces HAR-like output + engine-specific extras (Chromium NetLog export, etc.)

### Common flags

* `--engine`: `chromium|firefox|webkit|native`
* `--timeout`, `--proxy`, `--dns`, `--ipv6`, `--http2`, `--http3` (capabilities differ per engine)
* `--profile-dir` (persistent browser profile; makes behavior more “real” in a testing sense)
* `--cache=on|off`
* `--cookies=path.json`
* `--trace=har|json|netlog`
* `--lab=https://your-lab-host` (your own controlled server for fingerprint capture)

---

## Library architecture

### Package layout

* `brws/`

  * `client/` (public API)
  * `engine/` (interfaces + implementations)

    * `engine/native`
    * `engine/chromium`
    * `engine/firefox`
    * `engine/webkit`
  * `session/` (cookie jar, cache abstraction, profile management)
  * `trace/` (HAR-ish model, timings, protocol details)
  * `lab/` (client and server-side fingerprint capture protocols)
  * `diff/` (semantic + protocol diffs)

### Key types

```go
// brws/engine
package engine

import "context"

type Engine interface {
	Name() string
	Capabilities() Capabilities
	Do(ctx context.Context, req *Request) (*Response, error)
	Close() error
}

type Capabilities struct {
	JavaScript        bool
	HTTP2            bool
	HTTP3            bool
	PersistentProfile bool
	NetLogExport      bool
}

type Request struct {
	Method  string
	URL     string
	Headers map[string][]string
	Body    []byte

	// Behavior knobs for testing, not stealth.
	FollowRedirects bool
	MaxRedirects    int

	// Session integration
	SessionID string
}

type Response struct {
	Status     int
	Headers    map[string][]string
	Body       []byte
	FinalURL   string
	Protocol   string // "h2", "h3", "http/1.1"
	Trace      any    // engine-specific trace object, always serializable
}
```

### Engine implementations

#### `engine/chromium`

* Talks to a local Chromium via the **Chrome DevTools Protocol** (CDP).
* Uses browser-native networking.
* Can export NetLog (Chromium has native logging pipelines) for deep analysis.

#### `engine/firefox`

* Practical approach: use Playwright as a controlled runner (even if called as a sidecar).
* Firefox’s CDP story is not the same as Chromium; Playwright is the “least painful” stable surface.

#### `engine/webkit`

* Same story: Playwright is the pragmatic backend.

#### `engine/native`

* Uses Go `net/http` with `http.Transport`, plus optional `golang.org/x/net/http2`/HTTP3 libs.
* Explicitly tagged as “not browser-identical,” but excellent for performance testing and controlled diffs.

---

## The most important piece: the fingerprint lab server

To do this properly, you don’t guess what your client “looks like.” You **measure it from the server side**, because that’s what real defenses do.

### `labd` server responsibilities

* Terminate TLS and record the raw ClientHello bytes (or parse them)
* For HTTP/2:

  * Capture initial SETTINGS frame presence/order/values
  * Capture WINDOW_UPDATE patterns
  * Capture PRIORITY usage
  * Capture pseudo-header ordering
* Emit a structured JSON “fingerprint report”
* Store reports as “baselines” for comparisons (per engine build/version)

This is directly aligned with how HTTP/2 passive fingerprinting research describes extracting fingerprints from SETTINGS ordering/values and other early frames. ([Black Hat][6])

### Lab protocol

* Client hits `https://lab.example/fp`
* Server responds with JSON:

  * `tls`: parsed fields + computed hashes (JA3/JA4 style)
  * `h2`: parsed fields + computed “Akamai-style” signature fields
  * `meta`: timing, ALPN negotiated, SNI presence, etc.

### Why this matters

* If you’re trying to match a browser for *authorized* reasons, you’ll need regression detection: browsers and defenses change constantly. Cloudflare explicitly calls out keeping pace with change and bots trying to look more browser-like. ([The Cloudflare Blog][4])
* Chrome specifically broke the stability of order-sensitive fingerprints like JA3 by permuting TLS extensions. ([fastly.com][2])
* Newer fingerprinting schemes (JA4) are designed to be more robust against some forms of randomization. ([The Cloudflare Blog][4])

So your tool’s superpower should be: **observe, diff, and alert**. Not “promise invisibility.”

---

## Update strategy and CI

A tool like this dies if it can’t keep up.

### Baselines

* Baselines are produced by *running actual browsers* (Chromium/Firefox/WebKit) in CI against `labd`.
* Store:

  * Browser build metadata (version, platform, engine)
  * `labd` JSON fingerprints
  * Optional artifacts: pcap, NetLog, HAR

### CI jobs

* Nightly:

  * Run each browser engine, capture fingerprints, diff against last baseline
  * Fail if a fingerprint surface changed (or at least report)
* On commit:

  * Run native engine and ensure it stays stable
  * Run lab parser fuzz tests (ClientHello parsing is tricky and error-prone; Cloudflare ended up building a dedicated parser with heavy testing and fuzzing emphasis). ([The Cloudflare Blog][4])

---

## Practical reality check

* `curl-impersonate` achieves network parity by patching curl and swapping TLS backends (BoringSSL/NSS) and adjusting HTTP/2 settings. ([GitHub][5])
* In Go, **exact byte-level parity** across TLS+HTTP2+HTTP3 without literally using browser stacks is a treadmill that never stops, and the belt speed increases every year.
* Even if you nail TLS+HTTP2, “human” implies JS/device/behavior consistency, which you only get from real browsers plus real state.

So the “advanced” design is not “more spoof knobs.” It’s “two engines + a lab + diffing + baselines + reproducible profiles.”

---

> **Extra reading and search trails (so you can go down the rabbit hole responsibly):**
>
> * [lwt hiker HTTP/2 fingerprinting](https://www.google.com/search?q=HTTP%2F2+fingerprinting+lwt+hiker+site%3Alwthiker.com)
> * [lwt hiker TLS fingerprinting](https://www.google.com/search?q=TLS+fingerprinting+lwt+hiker+site%3Alwthiker.com)
> * [curl-impersonate README](https://www.google.com/search?q=curl-impersonate+README+site%3Agithub.com+lwthiker)
> * [Akamai “Passive Fingerprinting of HTTP/2 Clients” Black Hat paper](https://www.google.com/search?q=Passive+Fingerprinting+of+HTTP%2F2+Clients+Akamai+Black+Hat+PDF+site%3Ablackhat.com)
> * [Fastly on Chrome TLS ClientHello permutation](https://www.google.com/search?q=Examining+Chrome%27s+TLS+ClientHello+Permutation+site%3Afastly.com)
> * [Cloudflare JA4 fingerprints and inter-request signals](https://www.google.com/search?q=JA4+fingerprints+and+inter-request+signals+site%3Ablog.cloudflare.com)
> * [Salesforce JA3 write-up](https://www.google.com/search?q=TLS+Fingerprinting+with+JA3+and+JA3S+site%3Aengineering.salesforce.com)

[1]: https://lwthiker.com/networks/2022/06/17/tls-fingerprinting.html "TLS fingerprinting: How it works, where it is used and how to control your signature | lwt hiker"
[2]: https://www.fastly.com/blog/a-first-look-at-chromes-tls-clienthello-permutation-in-the-wild "Examining Chrome's TLS ClientHello Permutation | Fastly | Fastly"
[3]: https://lwthiker.com/networks/2022/06/17/http2-fingerprinting.html "HTTP/2 fingerprinting: A relatively-unknown method for web fingerprinting | lwt hiker"
[4]: https://blog.cloudflare.com/ja4-signals/ "Advancing Threat Intelligence: JA4 fingerprints and inter-request signals"
[5]: https://github.com/lwthiker/curl-impersonate "GitHub - lwthiker/curl-impersonate: curl-impersonate: A special build of curl that can impersonate Chrome & Firefox"
[6]: https://blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf "Passive Fingerprinting of HTTP/2 Clients | Akamai"

