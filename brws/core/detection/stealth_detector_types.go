package detection

import (
	"net/http"
	"time"
)

// analyserEntry describes a single pluggable analysis step in AnalyzeRequest.
// enabled points into DetectorConfig; nil means always run.
// guard is an optional per-request gate (e.g., protocol check); nil means no gate.
// requireScore, when true, skips the vector when its score is zero.
// category, when non-empty, records the result in the adaptive-scorer input map.
type analyserEntry struct {
	category     VectorCategory
	enabled      *bool
	guard        func(*http.Request) bool
	analyze      func(*http.Request) *DetectionVector
	onResult     func(*StealthDetection, *DetectionVector)
	requireScore bool
}

// DetectorConfig holds configuration thresholds and feature toggles for the
// stealth detection engine.
type DetectorConfig struct {
	ThresholdBot          float64 `json:"threshold_bot"`
	ThresholdSuspicious   float64 `json:"threshold_suspicious"`
	EnableTLSAnalysis     bool    `json:"enable_tls_analysis"`
	EnableNavigatorCheck  bool    `json:"enable_navigator_check"`
	EnableTimingCheck     bool    `json:"enable_timing_check"`
	EnableCanvasCheck     bool    `json:"enable_canvas_check"`
	EnableBehavioralCheck bool    `json:"enable_behavioral_check"`
	EnableWebGLCheck      bool    `json:"enable_webgl_check"`
	EnableIPCheck         bool    `json:"enable_ip_check"`
	EnableAutomationCheck bool    `json:"enable_automation_check"`
	EnableHeadlessCheck   bool    `json:"enable_headless_check"`
	EnableWebRTCCheck     bool    `json:"enable_webrtc_check"`
	EnableHTTP2Check      bool    `json:"enable_http2_check"`
	EnableFontCheck       bool    `json:"enable_font_check"`
	EnableScreenCheck     bool    `json:"enable_screen_check"`
	EnablePluginCheck     bool    `json:"enable_plugin_check"`
	EnableAudioCheck      bool    `json:"enable_audio_check"`
	EnableAdaptiveScoring bool    `json:"enable_adaptive_scoring"`
}

// StealthDetection represents a complete detection result for a single request,
// including all analysis vectors and confidence scores.
type StealthDetection struct {
	Timestamp      time.Time            `json:"timestamp"`
	RequestID      string               `json:"request_id"`
	ClientIP       string               `json:"client_ip"`
	Score          float64              `json:"score"`
	IsBot          bool                 `json:"is_bot"`
	IsStealth      bool                 `json:"is_stealth"`
	Confidence     float64              `json:"confidence"`
	Vectors        []DetectionVector    `json:"vectors"`
	Indicators     []StealthIndicator   `json:"indicators"`
	TLSFingerprint *TLSFingerprintInfo  `json:"tls_fingerprint,omitempty"`
	HTTPHeaders    *HTTPFingerprintInfo `json:"http_headers,omitempty"`
	NavigatorData  *NavigatorCheckInfo  `json:"navigator_data,omitempty"`
	CanvasData     *CanvasCheckInfo     `json:"canvas_data,omitempty"`
	TimingData     *TimingCheckInfo     `json:"timing_data,omitempty"`
	BehavioralData *BehavioralCheckInfo `json:"behavioral_data,omitempty"`
	IsomorphicData *IsomorphicCheckInfo `json:"isomorphic_data,omitempty"`
}

// IsomorphicCheckInfo contains cross-validation results comparing different
// fingerprinting layers for consistency.
type IsomorphicCheckInfo struct {
	PlatformMismatch   bool     `json:"platform_mismatch"`
	ExecutionMismatch  bool     `json:"execution_mismatch"`
	SuspiciousPatterns []string `json:"suspicious_patterns"`
}

// DetectionVector represents a single detection category with its score,
// weight, and associated indicators.
type DetectionVector struct {
	Name         string        `json:"name"`
	Category     string        `json:"category"`
	Score        float64       `json:"score"`
	Confidence   float64       `json:"confidence,omitempty"`
	Weight       float64       `json:"weight"`
	Detected     bool          `json:"detected"`
	Description  string        `json:"description"`
	Indicators   []string      `json:"indicators"`
	CheckReports []CheckReport `json:"check_reports,omitempty"`
}

// StealthIndicator represents a specific indicator of automation with severity
// and descriptive message.
type StealthIndicator struct {
	Vector   string  `json:"vector"`
	Name     string  `json:"name"`
	Severity float64 `json:"severity"`
	Message  string  `json:"message"`
	RawData  string  `json:"raw_data,omitempty"`
}

// TLSFingerprintInfo contains detailed TLS connection fingerprinting data
// including JA3/JA4 hashes and cipher suite analysis.
type TLSFingerprintInfo struct {
	JA4             string   `json:"ja4"`
	JA3             string   `json:"ja3"`
	TLSVersion      string   `json:"tls_version"`
	CipherSuite     string   `json:"cipher_suite"`
	CipherCount     int      `json:"cipher_count"`
	ExtensionCount  int      `json:"extension_count"`
	HasGREASE       bool     `json:"has_grease"`
	HasALPS         bool     `json:"has_alps"`
	ALPN            string   `json:"alpn"`
	SNI             string   `json:"sni"`
	SupportedGroups []string `json:"supported_groups"`
	SignatureAlgs   []string `json:"signature_algs"`
	CipherOrder     string   `json:"cipher_order"`
	KnownChromeJA4  string   `json:"known_chrome_ja4,omitempty"`
	IsKnownJA4      bool     `json:"is_known_ja4"`
	Anomalies       []string `json:"anomalies"`
}

// HTTPFingerprintInfo contains HTTP header analysis data for browser fingerprinting
// including User-Agent parsing and Client Hints validation.
type HTTPFingerprintInfo struct {
	UserAgent              string   `json:"user_agent"`
	Platform               string   `json:"platform"`
	BrowserVersion         string   `json:"browser_version"`
	Accept                 string   `json:"accept"`
	AcceptLanguage         string   `json:"accept_language"`
	AcceptEncoding         string   `json:"accept_encoding"`
	HeaderOrder            []string `json:"header_order"`
	HeaderCount            int      `json:"header_count"`
	SecCHUA                string   `json:"sec_ch_ua"`
	SecCHUAMobile          string   `json:"sec_ch_ua_mobile"`
	SecCHUAPlatform        string   `json:"sec_ch_ua_platform"`
	SecCHUAFullVersion     string   `json:"sec_ch_ua_full_version"`
	SecCHUAFullVersionList string   `json:"sec_ch_ua_full_version_list"`
	SecCHUAArch            string   `json:"sec_ch_ua_arch"`
	SecCHUABitness         string   `json:"sec_ch_ua_bitness"`
	SecCHUAModel           string   `json:"sec_ch_ua_model"`
	SecFetchDest           string   `json:"sec_fetch_dest"`
	SecFetchMode           string   `json:"sec_fetch_mode"`
	SecFetchSite           string   `json:"sec_fetch_site"`
	SecFetchUser           string   `json:"sec_fetch_user"`
	UpgradeInsecure        string   `json:"upgrade_insecure_requests"`
	ClientHintsConsistent  bool     `json:"client_hints_consistent"`
	MissingHeaders         []string `json:"missing_headers"`
	SuspiciousHeaders      []string `json:"suspicious_headers"`
}

// NavigatorCheckInfo contains JavaScript navigator object properties used
// to detect automation frameworks and inconsistencies.
type NavigatorCheckInfo struct {
	Webdriver           bool     `json:"webdriver"`
	Languages           string   `json:"languages"`
	Platform            string   `json:"platform"`
	Vendor              string   `json:"vendor"`
	UserAgent           string   `json:"user_agent"`
	HardwareConcurrency int      `json:"hardware_concurrency"`
	DeviceMemory        int      `json:"device_memory"`
	MaxTouchPoints      int      `json:"max_touch_points"`
	CookieEnabled       bool     `json:"cookie_enabled"`
	DoNotTrack          string   `json:"do_not_track"`
	PDFViewerEnabled    bool     `json:"pdf_viewer_enabled"`
	PluginsLength       int      `json:"plugins_length"`
	AppVersion          string   `json:"app_version"`
	ProductSub          string   `json:"product_sub"`
	VendorSub           string   `json:"vendor_sub"`
	ChromeRuntime       bool     `json:"chrome_runtime"`
	Permissions         string   `json:"permissions"`
	PresentationAPI     bool     `json:"presentation_api"`
	WebdriverDetected   bool     `json:"webdriver_detected"`
	AutomationDetected  bool     `json:"automation_detected"`
	PropertyCount       int      `json:"property_count"`
	MissingProps        []string `json:"missing_props"`
	InconsistentProps   []string `json:"inconsistent_props"`
	ConnectionRTT       float64  `json:"connection_rtt"`
	ConnectionDownlink  float64  `json:"connection_downlink"`
	ScreenColorDepth    int      `json:"screen_color_depth"`
	ScreenInnerWidth    int      `json:"screen_inner_width"`
	ScreenOuterWidth    int      `json:"screen_outer_width"`
	Timezone            string   `json:"timezone"`
	VideoCanPlayMp4     string   `json:"video_can_play_mp4"`
	NotificationsPrompt string   `json:"notifications_prompt"`
}

// CanvasCheckInfo contains Canvas and WebGL fingerprinting data for detecting
// randomization and software renderers.
type CanvasCheckInfo struct {
	CanvasFingerprint   string   `json:"canvas_fingerprint"`
	CanvasHash          string   `json:"canvas_hash"`
	CanvasDataURL       string   `json:"canvas_data_url"`
	WebGLVendor         string   `json:"webgl_vendor"`
	WebGLRenderer       string   `json:"webgl_renderer"`
	WebGLVersion        string   `json:"webgl_version"`
	WebGL2Supported     bool     `json:"webgl2_supported"`
	UnmaskedVendor      string   `json:"unmasked_vendor"`
	UnmaskedRenderer    string   `json:"unmasked_renderer"`
	TooManyFingerprints bool     `json:"too_many_fingerprints"`
	RandomizedCanvas    bool     `json:"randomized_canvas"`
	RandomizedWebGL     bool     `json:"randomized_webgl"`
	SuspiciousPatterns  []string `json:"suspicious_patterns"`
}

// TimingCheckInfo contains navigation timing data used to detect automated
// browsing patterns and impossible timing sequences.
type TimingCheckInfo struct {
	NavigationStart       int      `json:"navigation_start"`
	UnloadEventStart      int      `json:"unload_event_start"`
	RedirectStart         int      `json:"redirect_start"`
	RedirectEnd           int      `json:"redirect_end"`
	FetchStart            int      `json:"fetch_start"`
	DomainLookupStart     int      `json:"domain_lookup_start"`
	ConnectStart          int      `json:"connect_start"`
	SecureConnectionStart int      `json:"secure_connection_start"`
	RequestStart          int      `json:"request_start"`
	ResponseStart         int      `json:"response_start"`
	TransferSize          int      `json:"transfer_size"`
	EncodedBodySize       int      `json:"encoded_body_size"`
	DecodedBodySize       int      `json:"decoded_body_size"`
	TTFB                  int      `json:"ttfb"`
	LoadEventEnd          int      `json:"load_event_end"`
	ZeroTTFB              bool     `json:"zero_ttfb"`
	PerfectTiming         bool     `json:"perfect_timing"`
	SuspiciousGaps        []string `json:"suspicious_gaps"`
}

// BehavioralCheckInfo contains user interaction metrics for detecting
// mechanical mouse movements and typing patterns.
type BehavioralCheckInfo struct {
	MouseEvents        int      `json:"mouse_events"`
	MouseSpeedAvg      float64  `json:"mouse_speed_avg"`
	MouseSpeedStdDev   float64  `json:"mouse_speed_stddev"`
	MousePathLength    float64  `json:"mouse_path_length"`
	ScrollEvents       int      `json:"scroll_events"`
	ScrollDepth        float64  `json:"scroll_depth"`
	TypingEvents       int      `json:"typing_events"`
	TypingSpeedAvg     float64  `json:"typing_speed_avg"`
	TypingSpeedStdDev  float64  `json:"typing_speed_stddev"`
	TotalEvents        int      `json:"total_events"`
	EventTimings       []int64  `json:"event_timings"`
	TooPerfect         bool     `json:"too_perfect"`
	ZeroVariance       bool     `json:"zero_variance"`
	SuspiciousPatterns []string `json:"suspicious_patterns"`
}

// StealthBaseline represents known-good browser fingerprint data for comparison
// against detected fingerprints.
type StealthBaseline struct {
	Browser        string   `json:"browser"`
	JA4            string   `json:"ja4"`
	UserAgent      string   `json:"user_agent"`
	Platform       string   `json:"platform"`
	NavigatorProps []string `json:"navigator_props"`
}

//nolint:unused
var knownJA4Signatures = map[string]string{
	"t13d": "Chrome 120+ macOS",
	"t13c": "Chrome 120+ Windows",
	"t13b": "Chrome 120+ Linux",
	"q20d": "Firefox 120+",
	"r20a": "Safari 17+",
}
