# brws/research

Out-of-band packages for experimentation, data collection, and offline analysis. **Nothing here is imported by the production layers** (`browser`, `stealth`, `content`, `crawl`, `fingerprint`). Code graduates from here to production once it is stable and has been validated against real targets.

## Directory map

```
brws/research/
├── bench/
│   ├── fingerprint/   engine & detection benchmarks against live/mock endpoints
│   └── understand/    SemanticTree pipeline performance benchmarks
├── captcha/
│   ├── ml/            CNN + vision-LLM CAPTCHA solver prototypes
│   └── training/      training type re-exports; trace data in training/traces/
├── detection/
│   └── tracing/       request tracing, solve metrics, bot-detection lab server
├── evasion/
│   ├── cloudflare/    local Cloudflare challenge emulator (JS, Turnstile, Managed)
│   └── recaptcha/     local reCAPTCHA v2/v3 challenge emulator
├── fingerprint/
│   ├── capture/       full fingerprint capture lab server + REST API
│   └── training/      SQLite-backed episode collector + JSON/CSV export
└── rl/
    └── adaptive/      per-domain RL strategy storage and DOM element tracker
```

---

## bench/fingerprint

Package `fingerprintbench`. Measures how well each engine avoids detection across endpoint protection tiers, tests fingerprint consistency, capability gaps, and performance. Run via `make bench`.

### Suite types

```go
type SuiteType string
const (
    SuiteEndpoints    SuiteType = "endpoints"    // request success/block rates per engine
    SuiteCapabilities SuiteType = "capabilities" // JS, HTTP/2, headless-signal leakage
    SuiteFingerprint  SuiteType = "fingerprint"  // TLS + header consistency across runs
    SuitePerformance  SuiteType = "performance"  // page load latency (p95/p99)
    SuiteAll          SuiteType = "all"
)
```

### Key types

```go
type SuiteConfig struct {
    Type         SuiteType
    Engines      []string      // engine names; defaults to all registered engines
    Categories   []string      // endpoint categories to filter
    Endpoints    []Endpoint    // explicit endpoint list (overrides Categories)
    Iterations   int           // default 3
    Timeout      time.Duration // default 30s
    OutputFormat string        // "json" | "table"
    OutputPath   string
    Verbose      bool
    Parallel     bool
    MaxParallel  int           // default 4
}

type SuiteResult struct {
    Timestamp          time.Time
    Duration           time.Duration
    Config             SuiteConfig
    EndpointResults    []EndpointBenchmarkResult
    CapabilityReport   *CapabilityReport
    FingerprintReports map[string]*ConsistencyReport // keyed by engine name
    PerformanceResults []PerformanceResult
    Summary            SuiteSummary
}

type EndpointBenchmarkResult struct {
    EngineName string
    Endpoint   Endpoint
    Success    bool
    StatusCode int
    Duration   time.Duration
    BodySize   int
    Protocol   string
    Blocked    bool
    Blocker    string        // e.g. "cloudflare"
    Evidence   string
    RetryCount int
}

type PerformanceResult struct {
    EngineName string
    TestName   string
    Iterations int
    TotalTime, AvgTime, MinTime, MaxTime, P95Time, P99Time time.Duration
}

type SuiteSummary struct {
    TotalTests, PassedTests, FailedTests, BlockedTests, SkippedTests int
    ByEngine   map[string]EngineSummary
    ByCategory map[string]CategorySummary
}
```

### Entry point

```go
func NewSuiteRunner(config SuiteConfig) *SuiteRunner
func (sr *SuiteRunner) Run(ctx context.Context) (*SuiteResult, error)
func (sr *SuiteRunner) PrintResults(result *SuiteResult) error
```

### Shield evaluation (`shield.go`)

Evaluates the production `StealthDetector` against a labelled set of request profiles grouped into four categories: `bare_bot`, `basic_bot`, `stealth`, `advanced_stealth`.

```go
type ShieldReport struct {
    TotalProfiles, CorrectCount    int
    Accuracy, Precision, Recall    float64
    F1Score                        float64
    TruePositives, FalseNegatives  int
    TrueNegatives, FalsePositives  int
    ByCategory     map[string]CategoryStats   // "bare_bot" → {Total, Caught, Rate}
    VectorCoverage map[string]VectorStats     // "tls" → {Fires, TotalTests, FireRate, AvgScore}
    Results        []ShieldResult
}

type ShieldResult struct {
    Profile, Category string
    ShouldCatch       bool
    BotScore          float64
    IsBot             bool
    Correct           bool   // detection == expectation
    VectorScores      map[string]float64
    Indicators        []string
}

func RunShieldEvaluation(cfg *ShieldSuiteConfig) *ShieldReport
func PrintReport(report *ShieldReport)
func ExportReportJSON(report *ShieldReport) ([]byte, error)
```

Detection fires at `score > 0.3` for a vector. Overall `IsBot` threshold follows `constants.DefaultThresholdBot`.

### Tool comparison (`tool_comparison.go`)

Evaluates the shield against real-world tool profiles: python-requests, Scrapy, Playwright (default headless), Puppeteer (default), curl-impersonate, nodriver, Scrapling StealthyFetcher, Scrapling DynamicFetcher, nodriver-stealthified, Scrapling-stealthified, playwright-stealth, curl-impersonate-stealthified, and four internal sword profiles (`our_stealth_sword`, `armed`, `browser`, `broken`).

```go
type ToolCategory string
const (
    CategoryBareHTTP        ToolCategory = "bare_http"
    CategoryBrowserDefault  ToolCategory = "browser_default"
    CategoryBrowserStealth  ToolCategory = "browser_stealth"
    CategoryHTTPImpersonate ToolCategory = "http_impersonate"
)

type ToolComparisonReport struct {
    Timestamp    time.Time
    ShieldVer    string               // e.g. "v4-round4"
    Config       ToolComparisonConfig
    Results      []ToolResult
    Ranking      []RankEntry          // sorted by EvasionRate desc, then AvgScore asc
    VectorMatrix VectorToolMatrix     // matrix[vector][tool] = max score across scenarios
    CaptchaResults []CaptchaToolResult
}

type RankEntry struct {
    Rank        int
    ToolName    string
    Category    ToolCategory
    EvasionRate float64
    AvgScore    float64
}

func RunToolComparison(cfg *ToolComparisonConfig) *ToolComparisonReport
func PrintComparisonReport(report *ToolComparisonReport)
func ExportComparisonJSON(report *ToolComparisonReport) ([]byte, error)
```

### CAPTCHA benchmark (`tool_comparison.go — RunCaptchaBenchmark`)

Generates text CAPTCHAs with reduced noise (1 noise line, 15 dots, no wave/rotate), benchmarks `TemplateSolver` accuracy, and validates that synthetic behavioral event streams score below 0.5 on the `CaptchaTracer` bot scorer.

The behavioral event generator (`benchCaptchaSolver.GenerateHumanEvents`) produces realistic streams using:
- **Cubic Bézier mouse paths** with smoothstep `t` parameter
- **Multi-modal interval distribution** with four modes: fast (5–20ms), normal (20–60ms), slow (60–150ms), pause (150–400ms)
- **Directional tremor bias**: micro-tremors distributed around a preferred angle with wrapped-normal jitter to avoid uniform tremor-angle detection
- **Log-normal keystroke delays** (mean 120ms, σ 55ms)
- **Sub-pixel click jitter** (~0.8px radius) to avoid integer-coordinate detection
- **Interleaved event stream** to avoid sequential event ordering flags

```go
func RunCaptchaBenchmark(numCaptchas int) []CaptchaToolResult

type CaptchaToolResult struct {
    ToolName           string
    CaptchaSolveRate   float64
    BehavioralPassRate float64
    EndToEndPassRate   float64
    Attempts           int
}
```

---

## bench/understand

Package `understandbench`. Measures token reduction, latency, and accuracy of the HTML→`SemanticTree` pipeline.

```go
type Suite struct {
    Pages     []BenchPage    // URLs or local HTML fixtures
    LLMClient *llm.Client    // optional; nil = heuristic-only mode
}

type Result struct {
    Page           BenchPage
    RawTokens      int
    CompressedTokens int
    CompressionRatio float64
    LLMLatencyMs   int64
    AccuracyScore  float64    // relevance of extracted vs expected fields
    Error          error
}

type Summary struct {
    Pages          int
    AvgCompression float64
    AvgLLMLatency  time.Duration
    P95LLMLatency  time.Duration
    TotalTokensSaved int
}
```

---

## captcha/ml

Package `captchaml`. Prototype CAPTCHA solvers. Graduates to `brws/stealth/captcha/` once validated.

### Dense model (`model.go`)

Input: 2400-float64 grayscale pixel vector (e.g. 60×40 image flattened). Architecture: `[2400 → 512 → 256 → 128]` dense layers with ReLU + `ClassificationHead` (128 → 36 logits, softmax).

```go
var DefaultModelConfig = ModelConfig{
    InputDim:     2400,
    HiddenDims:   []int{512, 256, 128},
    OutputDim:    128,
    NumClasses:   36,   // A-Z + 0-9
    UseBatchNorm: true,
    Dropout:      0.2,
    Activation:   "relu",
}

func NewModel(config *ModelConfig) *Model
func (m *Model) Forward(input []float64) []float64        // returns softmax probabilities
func (m *Model) Backward(target []int, lr float64)        // SGD backprop
func (m *Model) Predict(input []float64) (class int, conf float64)
```

Backprop computes cross-entropy gradient against the label distribution, then propagates gradient through all `Layer` instances in reverse order.

### CNN model (`model.go`)

Convolutional backbone: three `Conv2DLayer` + `BatchNormLayer` pairs with channel sizes `[32, 64, 128]`, stride 1, padding 1, followed by global flatten and `ClassificationHead`. Supports residual connections via `ResNetBlock` (shortcut `Conv2DLayer` when channel dims differ).

```go
func NewCNNModel(config *ModelConfig) *CNNModel
func (m *CNNModel) Forward(input [][][]float64) []float64
func (m *CNNModel) Predict(input [][][]float64) (class int, conf float64)

func NewResNetBlock(inputChannels, outputChannels int) *ResNetBlock
func (r *ResNetBlock) Forward(x [][][]float64) [][][]float64
```

`Conv2DLayer.forward` derives kernel dimensions from the flattened weight storage (`Weights[outCh][inCh][kernelH*kernelW]`). `BatchNormLayer.forward` normalizes per-channel using stored `Mean`, `Variance`, `Gamma`, `Beta` with `Epsilon = 0.001`.

### Trainer (`trainer.go`)

```go
type TrainerConfig struct {
    Epochs          int     // default 100
    BatchSize       int     // default 32
    LearningRate    float64 // default 0.001
    Momentum        float64 // default 0.9
    WeightDecay     float64 // default 0.0001
    ValidationSplit float64 // default 0.2
    EarlyStopping   bool    // default true
    Patience        int     // default 10 epochs
    CheckpointDir   string
    LogInterval     int     // default every 10 epochs
}

func NewTrainer(model *Model, config *TrainerConfig) *Trainer
func (t *Trainer) Train(data *TrainingData) error
func (t *Trainer) GetMetrics() *TrainingMetrics
```

LR scheduling via `LearningRateScheduler`:

| `decayType` | Formula |
|---|---|
| `"step"` | `lr × decay^⌊epoch/stepSize⌋` |
| `"exponential"` | `lr × decay^epoch` |
| `"cosine"` | `lr × 0.5 × (1 + cos(π × epoch / stepSize))` |
| `"plateau"` | fixed `lr` (caller manages reduction) |

`TrainingMetrics` records per-epoch: `TrainLoss`, `TrainAcc`, `ValLoss`, `ValAcc`, `EpochTimes`, `LearningRates`. `GetBestEpoch()` returns epoch index with minimum `ValLoss`.

`DataAugmenter` applies rotation, per-pixel noise (`±0.01 × (i%10 - 5)`), and crop to 3× the training set.

### Vision solver (`vision_solver.go`)

Stateless solver that base64-encodes a CAPTCHA image and sends it to a vision LLM (wrapping `brws/llm/completions.LLM`). Graduates to production when accuracy exceeds the ML model baseline on real CAPTCHAs.

---

## captcha/training

Package `training`. Re-exports canonical training types from `brws/stealth/captcha` and `brws/stealth/challenge` so the fingerprint capture server and the training pipeline agree on schema without a circular import.

Turnstile session recordings live in `traces/sess_<operator>_<unix_ms>/`:
- `session.json` — session metadata
- `turnstile_rec_<variant>_<n>.json` — individual solve recording with full event stream

---

## detection/tracing

Package `tracing`. Records detailed per-request detection traces during live challenge interactions and serves an in-browser human challenge recording lab.

### TracingDetector

Embeds `detection.StealthDetector` and adds a per-request `DetectionTrace` with granular `CheckResult` breakdowns for seven signal categories.

```go
func NewTracingDetector() *TracingDetector

func (td *TracingDetector) AnalyzeWithTrace(req *http.Request, tls *tls.ConnectionState) *DetectionTrace

type DetectionTrace struct {
    RequestID    string
    Timestamp    time.Time
    FinalScore   float64           // mean of all CheckResult.Score values
    IsBot        bool              // score >= constants.DefaultThresholdBot
    IsStealth    bool              // score >= constants.DefaultThresholdSuspicious
    AllChecks    []CheckResult
    FailedChecks []CheckResult
    Warnings     []string
    RawHeaders   map[string]string
    Summary      string
}

type CheckResult struct {
    CheckName string  // e.g. "User-Agent-Clean"
    Category  string  // "tls"|"http"|"navigator"|"canvas"|"behavioral"|"timing"|"consistency"
    Passed    bool
    Score     float64 // contribution to FinalScore when failed
    Details   string
    RawValue  string
    Severity  string  // "critical"|"high"|"medium"|"low"|"info"
}
```

Signal categories and example checks:

| Category | Checks |
|---|---|
| `tls` | TLS version (1.3 preferred), cipher suite, SNI presence |
| `http` | UA presence, automation keywords, Accept, Accept-Language, Client Hints presence and consistency, header count ≥ 8 |
| `navigator` | `webdriver`, `chrome.runtime`, plugins count, automation property patterns |
| `canvas` | randomization keywords, hash presence, software renderer (`swiftshader`, `llvmpipe`) |
| `behavioral` | mouse variance, typing variance, linearity (>0.95), event count |
| `timing` | TTFB = 0, load time < 50ms |
| `consistency` | platform UA↔Sec-CH-UA-Platform, complete Client Hints triple, header diversity, Accept q-values |

```go
func (td *TracingDetector) PrintTrace(trace *DetectionTrace)
```

### TraceLabServer

HTTP server serving an interactive CAPTCHA challenge page that captures every mouse, keyboard, and scroll event from a human operator. Stores traces to disk and feeds `SolveMetricsTracker`.

```go
func NewTraceLabServer(dataDir string) *TraceLabServer
func (s *TraceLabServer) MountRoutes(mux *http.ServeMux)
```

**Routes:**

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/trace/lab?type=rotate` | Serve the interactive challenge HTML page |
| `POST` | `/api/trace/start` | Start a recording session; returns `session_id`, `recording_id` |
| `POST` | `/api/trace/record` | Append a batch of `CaptchaEvent` to the active recording |
| `POST` | `/api/trace/complete` | Finalize a recording; returns metrics and trace fingerprint |
| `GET` | `/api/trace/status` | Library summary + metrics report |
| `POST` | `/api/trace/end` | End the session and flush all recordings to `traces/<session_id>/` |

The lab page supports five challenge types: `rotate` (dial to target angle), `slide` (position slider to target px), `drag` (drag handle minimum distance), `orient3d` (3D cube with arrow keys), `orientlr` (left/right-only cube). Events are flushed every 2 seconds via `setInterval`.

### SolveMetricsTracker

```go
func NewSolveMetricsTracker() *SolveMetricsTracker
func (t *SolveMetricsTracker) RecordFromValidation(
    challengeType, variant, solver string,
    solved bool, durationMs int64, eventCount int,
    anomalyFlags []string, botScore float64,
)
func (t *SolveMetricsTracker) Report() map[string]any  // per-challenge-type success rates
```

Anomaly detection flags include: `uniform_tremor_angles`, `fixed_timing_intervals`, `sequential_event_ordering`, `integer_coordinate_precision`, `missing_behavioral_signal`.

---

## evasion/cloudflare

Package `cloudflare`. Local Cloudflare challenge emulator for solver development without hitting production. Mount via `cc.MountRoutes(mux)` in tests.

### TestServer

```go
func NewTestServer() *TestServer
func (ts *TestServer) MountRoutes(mux *http.ServeMux)
func (ts *TestServer) GetDetections() []DetectionRecord
func (ts *TestServer) Reset()

type TestServer struct {
    Server     *httptest.Server
    URL        string
    Detections []DetectionRecord
    UseTLS     bool
}

type DetectionRecord struct {
    Timestamp     time.Time
    RequestID     string
    IsBot         bool
    Score         float64
    Indicators    []detection.Indicator
    TLS           *detection.TLSAnalysis
    HTTP          *detection.HTTPAnalysis
    VectorResults []detection.VectorResult
    Request       *RequestInfo
    Response      *ResponseInfo
}
```

Each request runs through `detection.NewAnalyzer()` + `detection.NewVectorMap()`. Request info captures method, URL, headers + header order, remote address, TLS version/cipher/SNI/groups/signature-algs/ALPN.

### Challenge simulation

`lab_cloudflare.go` emulates four Cloudflare challenge types with associated timing constraints:

| Challenge | Serve delay | Min solve time | Max solve time |
|---|---|---|---|
| JS challenge | 100ms | 4s | 8s |
| Managed challenge | 200ms | 6s | 12s |
| Turnstile | 150ms | 2s | 10s |
| Under-Attack-Mode (IUAM) | 5s delay page | 5s | 15s |

Cookies: `__cf_bm` (30-minute TTL, HttpOnly, SameSite=None), `cf_clearance` (1-hour TTL). Rate limiting returns 429 after configurable threshold with `Retry-After` header. `__cf_bm` token format: `<rand32>.<unix_ts>.<base64-hmac>`.

### Turnstile visual proof (`turnstile_visual.go`)

Validates proof objects for the three visual interaction types:

| Type | Acceptance criterion |
|---|---|
| `rotate` | `|final_angle - target_angle| ≤ tolerance_deg` |
| `drag` | `completion_ratio ≥ 0.85` |
| `precision` | distance from click to target `≤ target_radius` |

```go
type TurnstileVisualProof struct {
    Type        string  // "rotate" | "drag" | "precision"
    FinalAngle  float64
    TargetAngle float64
    Tolerance   float64
    CompletionRatio float64
    ClickX, ClickY   float64
    TargetX, TargetY float64
    TargetRadius     float64
    DurationMs  int64
    EventCount  int
}

func ValidateVisualProof(proof *TurnstileVisualProof) (bool, string)
```

### reCAPTCHA v3 assessment (`v3_assess.go`)

Scores invisible requests by five features: User-Agent quality, header completeness, request timing deviation, behavioral signal presence, and navigation history. Returns `{token, score, action, challenge_ts, hostname, error_codes}`.

---

## evasion/recaptcha

Package `recaptcha`. Local reCAPTCHA v2/v3 emulator for solver development.

### v2 widget (`recaptcha_widget.go`)

Three-phase flow:
1. **Checkbox** — check triggers bot score eval; score ≥ 0.5 → passes immediately
2. **Image challenge** — serves 3×3 image grid; `POST /verify` with clicked tiles
3. **Token issuance** — `POST /token` with `g-recaptcha-response`

```go
type WidgetState struct {
    SessionID   string
    Phase       string    // "checkbox" | "image" | "complete"
    ImageGrid   [][]int   // 3x3 solution matrix
    Score       float64
    Attempts    int
    CreatedAt   time.Time
    ExpiresAt   time.Time // 2 minutes
}

func NewRecaptchaWidget() *RecaptchaWidget
func (w *RecaptchaWidget) MountRoutes(mux *http.ServeMux)
// Routes: GET /v2/challenge, POST /v2/check, POST /v2/verify, POST /v2/token
```

### v3 behavioral scoring (`recaptcha_v3.go`)

Scores eight signal dimensions: UA legitimacy, Accept-Language presence, page-load timing realism, mouse event count and variance, navigation history depth, Sec-Fetch-Dest/Mode, Connection header, behavioral event entropy. Weighted sum yields `[0.0, 1.0]` score (higher = more human).

```go
func NewRecaptchaV3() *RecaptchaV3
func (r *RecaptchaV3) MountRoutes(mux *http.ServeMux)
// Routes: GET /v3/challenge, POST /v3/submit, GET /v3/assess
```

---

## fingerprint/capture

Package `capture`. Full fingerprint capture lab server. Requires `libpcap` for raw TLS handshake capture (`sudo apt-get install libpcap-dev`).

### EnhancedServer

Top-level HTTP server wiring all capture, ML, CAPTCHA, reCAPTCHA, and training endpoints.

```go
func NewEnhancedServer(cfg *ServerConfig) *EnhancedServer
func (s *EnhancedServer) Start() error
func (s *EnhancedServer) MountRoutes(mux *http.ServeMux)
```

### HTTP routes

**Fingerprint API** (`fingerprint_api.go`):

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/fingerprint/submit` | Store a `CompleteFingerprint`; returns ID |
| `GET` | `/api/fingerprint/:id` | Retrieve stored fingerprint |
| `POST` | `/api/fingerprint/compare` | Diff two fingerprints; returns `FingerprintDiff` |
| `GET` | `/api/fingerprint/list` | List all stored fingerprints |

**ML API** (`ml_api.go`, `ml_evaluate_fast.go`):

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/ml/evaluate` | Run `StealthDetector` against a submitted fingerprint; returns bot score + vector breakdown |
| `GET` | `/api/ml/fast` | Synthetic detection eval without browser launch (pure header analysis) |

**CAPTCHA API** (`captcha_api.go`, `training_api.go`):

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/captcha/challenge` | Serve a CAPTCHA image for labelling |
| `POST` | `/api/captcha/train` | Submit human-solved CAPTCHA for training data collection |

**Shield API** (`shield_api.go`):

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/shield/score` | Bot score + per-vector breakdown for the current request |

**reCAPTCHA v3** (`recaptcha_v3_api.go`): mirrors evasion emulator routes under `/api/recaptcha/`.

**TLS capture** (`tls_capture.go`): stores and retrieves `ClientHello` records with JA3/JA4 hashes.

### BrowserControl

```go
func NewBrowserControl(cfg *BrowserConfig) *BrowserControl
func (bc *BrowserControl) Launch(ctx context.Context) error
func (bc *BrowserControl) Navigate(url string) (*CompleteFingerprint, error)
func (bc *BrowserControl) Close()
```

Drives Chrome via CDP: launches with custom flags, intercepts network events, extracts JS fingerprint via injected script, and assembles a `CompleteFingerprint` (TLS + HTTP/2 + navigator + canvas + screen + plugins + timing).

### RawCapture

```go
func NewRawCapture(iface string) (*RawCapture, error)
func (rc *RawCapture) Start() error
func (rc *RawCapture) Stop() error
func (rc *RawCapture) GetClientHellos() []*ClientHello
```

Captures TLS `ClientHello` messages directly from a network interface via `libpcap` — no browser required.

### Trainer (automated)

```go
func NewTrainer(cfg *TrainerConfig) *Trainer
func (t *Trainer) Run(ctx context.Context, urls []string) error
```

Launches Chrome, navigates each URL in sequence, captures the full fingerprint after page load, and stores episodes via `fingerprint/training.Collector`.

### Export

```go
// export/exporter.go
func ExportJSON(episodes []TrainingEpisode, path string) error
func ExportCSV(episodes []TrainingEpisode, path string) error
// also writes a manifest.json with schema version, count, and date range
```

---

## fingerprint/training

Package `training`. Persists RL training episodes to SQLite and exports them for offline model training.

### TrainingEpisode

```go
type TrainingEpisode struct {
    EpisodeID     string
    Timestamp     time.Time
    SessionID     string
    TargetURL     string
    EngineName    string
    StealthConfig StealthConfigSnapshot
    Detection     DetectionSnapshot
    FSMState      FSMSnapshot
    Captcha       *CaptchaSnapshot      // nil if no CAPTCHA
    Behavioral    *BehavioralSnapshot   // nil if no behavioral data
    Outcome       RequestOutcome
    BotScore      float64
    Reward        float64
    ModelVersion  string
}

type StealthConfigSnapshot struct {
    RemoveWebDriver, CanvasNoise, WebGLSpoof, ClientHints,
    FakeScreen, FakeTimezone, RandomUA, HardwareSync, NetworkSync,
    PluginsSync, GeometrySync, VideoSync, PermissionsSync, TimezoneSync bool
    WebRTCMode     string
    CanvasNoiseStr float64
}

type DetectionSnapshot struct {
    WebdriverExposed, CanvasDetected, ClientHintsIssues, IsomorphicIssues,
    HardwareMismatch, NetworkMismatch, PluginsDetected, GeometryMismatch,
    VideoDetected, PermissionsMismatch, TimezoneMismatch bool
    OverallScore float64
}

type FSMSnapshot struct {
    CurrentState    string
    TransitionCount int
    RetryCount      int
    ChallengeCount  int
}
```

### 18-dimensional feature vector

```
[0-10]  Detection flags (webdriver, canvas, client_hints, isomorphic,
         hardware, network, plugins, geometry, video, permissions, timezone)
[11-13] CAPTCHA (presented, solved, difficulty)
[14]    mouse_velocity / 2000 → [0, 1]
[15]    typing_speed / 500   → [0, 1]
[16]    straightness          ∈ [0, 1]
[17]    captcha_solve_ms / 30000 → [0, 1]
```

```go
func ToFeatureVector(ep *TrainingEpisode) []float64
```

### Collector (SQLite)

```go
func NewCollector(dbPath string) (*Collector, error)
func (c *Collector) RecordEpisode(ctx context.Context, ep *TrainingEpisode) error
func (c *Collector) Query(filters EpisodeFilters) ([]TrainingEpisode, error)
func (c *Collector) Stats() (*CollectionStats, error)
func (c *Collector) Close() error

type EpisodeFilters struct {
    EngineName            string
    MinBotScore, MaxBotScore float64
    Outcome               string  // "success" | "blocked" | "challenged"
    Limit, Offset         int
}

type CollectionStats struct {
    TotalEpisodes        int
    ByEngine, ByOutcome  map[string]int
    AvgBotScore, AvgReward float64
    DateRange            [2]string
}
```

**SQLite schema:**

```sql
CREATE TABLE episodes (
    episode_id    TEXT PRIMARY KEY,
    timestamp     TEXT NOT NULL,
    session_id    TEXT NOT NULL,
    target_url    TEXT NOT NULL,
    engine_name   TEXT NOT NULL,
    stealth_config TEXT NOT NULL,   -- JSON
    detection     TEXT NOT NULL,    -- JSON
    fsm_state     TEXT NOT NULL,    -- JSON
    captcha       TEXT,             -- JSON, nullable
    behavioral    TEXT,             -- JSON, nullable
    outcome       TEXT NOT NULL,    -- JSON
    bot_score     REAL NOT NULL,
    reward        REAL NOT NULL,
    model_version TEXT NOT NULL,
    feature_vector TEXT             -- JSON float64 array
);
-- Indexes: engine_name, bot_score, timestamp
```

Open with WAL mode and 5s busy timeout: `dbPath + "?_journal=WAL&_busy_timeout=5000"`.

### Export

```go
func ExportJSONL(c *Collector, filters EpisodeFilters, path string) error  // JSON Lines
func ExportCSV(c *Collector, filters EpisodeFilters, path string) error
// Both write a manifest.json alongside the data file.
```

Session data is in `session-001/`: `capture_01_<host>.json` (raw fingerprint), `header_patterns.json`, `training_report.json`.

---

## rl/adaptive

Package `adaptive`. Persists per-domain DOM element profiles and similarity-based lookup to back the RL training loop in `brws/ml`.

### ElementTracker (in-memory)

```go
func NewElementTracker() *ElementTracker

func (t *ElementTracker) Track(
    domain, selector, tag, text string,
    attrs map[string]string, path string,
) string  // returns UUID

func (t *ElementTracker) FindSimilar(
    domain, tag, text string,
    attrs map[string]string, path string,
) []ElementProfile

type ElementProfile struct {
    ID, Domain, Selector, Tag, Text string
    Attributes                      map[string]string
    Path, ParentTag, GrandparentTag string
    SiblingCount                    int
}
```

Similarity scoring weights (total weight = sum of contributing terms):

| Signal | Weight |
|---|---|
| Tag match | 3 |
| Parent tag match | 2 |
| Text similarity (LCS-based) | 2 |
| Attribute key-value match | 1 per matched attr |

`FindSimilar` returns all profiles with `score == bestScore` when `bestScore > 0.5` (ties included), else only the single best.

Text similarity: exact → 1.0; substring containment → `min(len)/max(len)`; otherwise `LCS(s1,s2)/max(len)` (DP table).

### Storage (SQLite)

```go
func NewStorage(cfg StorageConfig) (*Storage, error)
func (s *Storage) SaveProfile(domain string, profile ElementProfile) error
func (s *Storage) LoadProfiles(domain string) ([]ElementProfile, error)
func (s *Storage) FindSimilar(domain, tag, text string, attrs map[string]string, path string) []ElementProfile
func (s *Storage) GetTracker() *ElementTracker
func (s *Storage) Close() error
```

**SQLite schema:**

```sql
CREATE TABLE element_profiles (
    id              TEXT PRIMARY KEY,
    domain          TEXT NOT NULL,
    selector        TEXT,
    tag             TEXT NOT NULL,
    text_content    TEXT,
    attributes      TEXT,            -- JSON
    path            TEXT,
    sibling_count   INTEGER,
    parent_tag      TEXT,
    grandparent_tag TEXT,
    created_at      INTEGER DEFAULT (strftime('%s', 'now'))
);
-- Indexes: domain, tag, selector
```

### AdaptiveSelector

Convenience wrapper combining tracker + domain + base selector:

```go
func NewAdaptiveSelector(domain, selector string) *AdaptiveSelector
func (a *AdaptiveSelector) AutoSave(enable bool) *AdaptiveSelector
func (a *AdaptiveSelector) TrackElement(tag, text string, attrs map[string]string, path string) string
func (a *AdaptiveSelector) FindAdaptive(tag, text string, attrs map[string]string, path string) []ElementProfile
```

### Python training scripts (`rl/`)

| Script | Purpose |
|---|---|
| `train_rl_agent.py` | Trains the FSM RL policy (`models/fsm_rl_policy.pt`) using stored episodes |
| `train_shield_sword.py` | Adversarial shield-vs-sword training (`models/shield_sword_policy.pt`) |
