# pybrwslab

Python wrapper for the [**brwslab**](https://github.com/skunkworq/stealth) Go toolkit — browser-grade network fidelity, semantic web extraction, and stealth browser automation.

## Prerequisites

1. **Build the Go binaries** from the project root:

```bash
cd ..
make build
# Binaries appear in build/ — add that directory to your PATH
export PATH="$PWD/build:$PATH"
```

2. **Install the Python package**:

```bash
cd python
pip install -e .
```

## Quick Start

### Fetch a page with stealth

```python
from pybrwslab import Brwslab

br = Brwslab()
result = br.fetch(
    "https://example.com",
    engine="chromium-stealth",
    proxy="http://proxy:8080",
)
print(result.status)      # 200
print(result.body[:500])  # HTML body
print(result.protocol)    # "h2"
```

### Extract semantic tree

```python
from pybrwslab import Semantic

sem = Semantic()
tree = sem.extract("https://example.com", format="json")
print(tree.title)
print(f"Nodes: {len(tree.root_nodes)}")

# Serialized text for LLM context
text = sem.extract_text("https://example.com")
```

### Run the fingerprint lab

```python
from pybrwslab import Labd

lab = Labd()
proc = lab.start(http_port=8080, https_port=8443, proxy_port=8081)

# Point a browser at http://localhost:8080 and capture fingerprints
fp = lab.capture_json("http://localhost:8080")
print(fp["tls"]["ja3"])

lab.stop(proc)
```

### Stealth spider / fetch

```python
from pybrwslab import Stealth

st = Stealth()
result = st.fetch("https://example.com", engine="chromium-stealth", json_output=True)

# Start lab server
proc = st.lab_start(http_port=8080, chrome=True)
# ...
st.stop(proc)
```

## API Overview

| Class | Binary | Purpose |
|-------|--------|---------|
| `Brwslab` | `brwslab` | Network fingerprinting, fetch, session management |
| `Stealth` | `stealth` | Spider framework, fetch, lab server |
| `Semantic` | `semantic` | Semantic tree extraction with LLM compression |
| `Labd` | `labd` | Fingerprint capture lab server |

### `Brwslab.fetch(...)`

```python
def fetch(
    url: str,
    *,
    engine: str = "native",
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str = "",
    proxy: str = "",
    timeout: str = "30s",
    follow_redirects: bool = True,
    session: str = "",
    output_format: str = "json",
) -> FetchResult
```

### `Semantic.extract(...)`

```python
def extract(
    url: str,
    *,
    format: str = "json",          # "tree" | "json" | "serialized" | "stats"
    engine: str = "native",
    stealth: bool = True,
    cache: str = "",
    no_cache: bool = False,
    api_key: str = "",
    compress_model: str = "openai/gpt-oss-120b",
    initial_budget: int = 5000,
    max_budget: int = 128000,
) -> SemanticTree | CompressionStats | str
```

### `Labd.start(...)`

```python
def start(
    *,
    http_port: int = 8080,
    https_port: int = 8443,
    proxy_port: int = 8081,
    tls_cert: str = "",
    tls_key: str = "",
    store_dir: str = "",
    chrome: bool = False,
    verbose: bool = False,
) -> subprocess.Popen[str]
```

## Error Handling

All wrappers raise `BrwslabError` on CLI failure:

```python
from pybrwslab import Brwslab, BrwslabError

br = Brwslab()
try:
    br.fetch("https://example.com", engine="chromium")
except BrwslabError as exc:
    print(f"Failed (code {exc.returncode}): {exc.stderr}")
```

## Development

```bash
cd python
pip install -e ".[dev]"
pytest
mypy pybrwslab
ruff check pybrwslab
```

## License

MIT — same as the parent brwslab project.
