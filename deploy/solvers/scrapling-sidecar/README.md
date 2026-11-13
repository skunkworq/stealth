# Scrapling fetch sidecar

A fetch service for the crawler's escalation chain. It speaks the solver
JSON protocol, so the crawler can use Scrapling as a tier after the local
browser.

## Protocol

```
POST /v1/fetch
{"url": "https://example.com", "method": "GET", "headers": {...},
 "timeout_ms": 30000, "wait_ms": 0, "solve": true}

→ 200 {"status": 200, "url": "https://example.com/", "html": "<html>…",
       "headers": {...}, "solver": "scrapling", "elapsed_ms": 1234}
```

`GET /health` answers `{"status": "ok", "solver": "scrapling"}`.

Any service that speaks this protocol can be a tier — browser-use is the
obvious second one. The Go client is
`brws/engine/solver.HTTPSolver`.

## Running it

```sh
docker build -t brandbrain-scrapling-sidecar deploy/solvers/scrapling-sidecar
docker run --rm -p 8000:8000 brandbrain-scrapling-sidecar
```

Then point the crawler at it:

```sh
DISCOVERY_SCRAPLING_URL=http://localhost:8000
```

The sidecar uses Scrapling's `StealthyFetcher`, which spoofs the TLS
fingerprint and drives a real browser — the point of the tier is the wall
class a plain client cannot pass.

> The upstream `pyd4vinci/scrapling` image's system python cannot import
> Scrapling (`typing_extensions` is missing from it); its `uv` environment
> can. The Dockerfile therefore runs the server under `uv run`.

## Where it fits

The chain is SEQUENTIAL — escalation is a decision, not a race:

```
plain HTTP → stealth browser → flaresolverr → scrapling → browser-use
```

Each tier is tried only when the previous one answered with a wall
(401/403/429/503, or a body matching a known challenge signature). The
tier that served the page is recorded on the crawl result.
