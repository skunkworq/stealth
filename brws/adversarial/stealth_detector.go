package adversarial

import (
	"bytes"
	"compress/zlib"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/stealth/brwslab/brws/constants"
)

// StealthDetector analyzes HTTP requests to detect stealth browser automation
// by examining TLS fingerprints, HTTP headers, navigator properties, canvas fingerprints,
// timing patterns, and behavioral biometrics.
type StealthDetector struct {
	mu              sync.RWMutex
	detections      []StealthDetection
	baselines       map[string]*StealthBaseline
	config          *DetectorConfig
	adaptiveScorer  *AdaptiveScorer
	advancedDet     *AdvancedDetection
}

// DetectorConfig holds configuration thresholds and feature toggles for the
// stealth detection engine.
type DetectorConfig struct {
	ThresholdBot           float64 `json:"threshold_bot"`
	ThresholdSuspicious    float64 `json:"threshold_suspicious"`
	EnableTLSAnalysis      bool    `json:"enable_tls_analysis"`
	EnableNavigatorCheck   bool    `json:"enable_navigator_check"`
	EnableTimingCheck      bool    `json:"enable_timing_check"`
	EnableCanvasCheck      bool    `json:"enable_canvas_check"`
	EnableBehavioralCheck  bool    `json:"enable_behavioral_check"`
	EnableWebGLCheck       bool    `json:"enable_webgl_check"`
	EnableIPCheck          bool    `json:"enable_ip_check"`
	EnableAutomationCheck  bool    `json:"enable_automation_check"`
	EnableHeadlessCheck    bool    `json:"enable_headless_check"`
	EnableWebRTCCheck      bool    `json:"enable_webrtc_check"`
	EnableHTTP2Check       bool    `json:"enable_http2_check"`
	EnableFontCheck        bool    `json:"enable_font_check"`
	EnableScreenCheck      bool    `json:"enable_screen_check"`
	EnablePluginCheck      bool    `json:"enable_plugin_check"`
	EnableAudioCheck       bool    `json:"enable_audio_check"`
	EnableAdaptiveScoring  bool    `json:"enable_adaptive_scoring"`
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
	UserAgent             string   `json:"user_agent"`
	Platform              string   `json:"platform"`
	BrowserVersion        string   `json:"browser_version"`
	Accept                string   `json:"accept"`
	AcceptLanguage        string   `json:"accept_language"`
	AcceptEncoding        string   `json:"accept_encoding"`
	HeaderOrder           []string `json:"header_order"`
	HeaderCount           int      `json:"header_count"`
	SecCHUA               string   `json:"sec_ch_ua"`
	SecCHUAMobile         string   `json:"sec_ch_ua_mobile"`
	SecCHUAPlatform       string   `json:"sec_ch_ua_platform"`
	SecCHUAFullVersion    string   `json:"sec_ch_ua_full_version"`
	SecCHUAArch           string   `json:"sec_ch_ua_arch"`
	SecCHUABitness        string   `json:"sec_ch_ua_bitness"`
	SecCHUAModel          string   `json:"sec_ch_ua_model"`
	SecFetchDest          string   `json:"sec_fetch_dest"`
	SecFetchMode          string   `json:"sec_fetch_mode"`
	SecFetchSite          string   `json:"sec_fetch_site"`
	SecFetchUser          string   `json:"sec_fetch_user"`
	UpgradeInsecure       string   `json:"upgrade_insecure_requests"`
	ClientHintsConsistent bool     `json:"client_hints_consistent"`
	MissingHeaders        []string `json:"missing_headers"`
	SuspiciousHeaders     []string `json:"suspicious_headers"`
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

// NewStealthDetector creates and initializes a new StealthDetector with default
// configuration settings.
func NewStealthDetector() *StealthDetector {
	return &StealthDetector{
		detections: make([]StealthDetection, 0),
		baselines:  make(map[string]*StealthBaseline),
		config: &DetectorConfig{
			ThresholdBot:          0.35,
			ThresholdSuspicious:   0.25,
			EnableTLSAnalysis:     true,
			EnableNavigatorCheck:  true,
			EnableTimingCheck:     true,
			EnableCanvasCheck:     true,
			EnableBehavioralCheck: true,
			EnableWebGLCheck:      true,
			EnableIPCheck:         true,
			EnableAutomationCheck: true,
			EnableHeadlessCheck:   true,
			EnableWebRTCCheck:     true,
			EnableHTTP2Check:      true,
			EnableFontCheck:       true,
			EnableScreenCheck:     true,
			EnablePluginCheck:     true,
			EnableAudioCheck:      true,
			EnableAdaptiveScoring: true,
		},
		adaptiveScorer: NewAdaptiveScorer(nil),
		advancedDet:    NewAdvancedDetection(),
	}
}

// AnalyzeRequest performs comprehensive stealth detection analysis on an HTTP request,
// examining TLS state, headers, and embedded fingerprint data.
func (sd *StealthDetector) AnalyzeRequest(req *http.Request, tlsConn *tls.ConnectionState) *StealthDetection {
	// Early return if request is nil
	if req == nil {
		return &StealthDetection{
			Timestamp:  time.Now(),
			RequestID:  generateRequestID(),
			ClientIP:   "unknown",
			Vectors:    make([]DetectionVector, 0),
			Indicators: make([]StealthIndicator, 0),
		}
	}

	detection := StealthDetection{
		Timestamp:  time.Now(),
		RequestID:  generateRequestID(),
		ClientIP:   getClientIP(req),
		Vectors:    make([]DetectionVector, 0),
		Indicators: make([]StealthIndicator, 0),
	}

	var totalScore float64
	var totalWeight float64

	// Collect VectorResults for adaptive scoring
	vectorResults := make(map[VectorCategory]*VectorResult)

	// 1. TLS Fingerprint Analysis
	if sd.config.EnableTLSAnalysis && tlsConn != nil {
		tlsInfo := sd.analyzeTLSFingerprint(tlsConn)
		detection.TLSFingerprint = tlsInfo
		tlsVec := sd.tlsInfoToVector(tlsInfo)
		detection.Vectors = append(detection.Vectors, tlsVec)
		totalScore += tlsVec.Score * tlsVec.Weight
		totalWeight += tlsVec.Weight
		vectorResults[VectorTLS] = &VectorResult{Score: tlsVec.Score, Detected: tlsVec.Detected}
	}

	// 2. HTTP Header Analysis
	httpInfo := sd.analyzeHTTPHeaders(req)
	detection.HTTPHeaders = httpInfo
	httpVec := sd.httpInfoToVector(httpInfo)
	detection.Vectors = append(detection.Vectors, httpVec)
	totalScore += httpVec.Score * httpVec.Weight
	totalWeight += httpVec.Weight
	vectorResults[VectorHTTP] = &VectorResult{Score: httpVec.Score, Detected: httpVec.Detected}

	// 3. Navigator Properties Analysis (from injected scripts)
	if sd.config.EnableNavigatorCheck {
		navVec := sd.analyzeNavigatorData(req)
		if navVec != nil {
			detection.NavigatorData = &NavigatorCheckInfo{}
			detection.Vectors = append(detection.Vectors, *navVec)
			totalScore += navVec.Score * navVec.Weight
			totalWeight += navVec.Weight
			vectorResults[VectorNavigator] = &VectorResult{Score: navVec.Score, Detected: navVec.Detected}
		}
	}

	// 4. Canvas/WebGL Analysis
	if sd.config.EnableCanvasCheck {
		canvasVec := sd.analyzeCanvasData(req)
		if canvasVec != nil {
			detection.CanvasData = &CanvasCheckInfo{}
			detection.Vectors = append(detection.Vectors, *canvasVec)
			totalScore += canvasVec.Score * canvasVec.Weight
			totalWeight += canvasVec.Weight
			vectorResults[VectorCanvas] = &VectorResult{Score: canvasVec.Score, Detected: canvasVec.Detected}
		}
	}

	// 4b. WebGL Deep Analysis
	if sd.config.EnableWebGLCheck {
		webglVec := sd.analyzeWebGLData(req)
		if webglVec != nil {
			detection.Vectors = append(detection.Vectors, *webglVec)
			totalScore += webglVec.Score * webglVec.Weight
			totalWeight += webglVec.Weight
			vectorResults[VectorWebGL] = &VectorResult{Score: webglVec.Score, Detected: webglVec.Detected}
		}
	}

	// 5. Timing Analysis (enhanced with deep TimingAnalyzer)
	if sd.config.EnableTimingCheck {
		timingVec := sd.analyzeTimingData(req)
		if timingVec != nil {
			detection.TimingData = &TimingCheckInfo{}
			detection.Vectors = append(detection.Vectors, *timingVec)
			totalScore += timingVec.Score * timingVec.Weight
			totalWeight += timingVec.Weight
			vectorResults[VectorTiming] = &VectorResult{Score: timingVec.Score, Detected: timingVec.Detected}
		}
	}

	// 6. Behavioral Analysis
	if sd.config.EnableBehavioralCheck {
		behavVec := sd.analyzeBehavioralData(req)
		if behavVec != nil {
			detection.BehavioralData = &BehavioralCheckInfo{}
			detection.Vectors = append(detection.Vectors, *behavVec)
			totalScore += behavVec.Score * behavVec.Weight
			totalWeight += behavVec.Weight
			vectorResults[VectorBehavioral] = &VectorResult{Score: behavVec.Score, Detected: behavVec.Detected}
		}
	}

	// 7. Isomorphic Cross-Validation
	isomorphicVec := sd.analyzeIsomorphicAnomalies(req, httpInfo)
	if isomorphicVec != nil {
		if isomorphicVec.Score > 0 {
			detection.IsomorphicData = &IsomorphicCheckInfo{
				PlatformMismatch:   true,
				SuspiciousPatterns: isomorphicVec.Indicators,
			}
			detection.Vectors = append(detection.Vectors, *isomorphicVec)
			totalScore += isomorphicVec.Score * isomorphicVec.Weight
			totalWeight += isomorphicVec.Weight
			vectorResults[VectorIsomorphic] = &VectorResult{Score: isomorphicVec.Score, Detected: isomorphicVec.Detected}
		}
	}

	// 8. Hardware Execution Parity
	hardwareVec := sd.analyzeHardwareExecution(req)
	if hardwareVec != nil {
		if hardwareVec.Score > 0 {
			detection.Vectors = append(detection.Vectors, *hardwareVec)
			totalScore += hardwareVec.Score * hardwareVec.Weight
			totalWeight += hardwareVec.Weight
		}
	}

	// 9. IP Classification (from advanced_detection.go)
	if sd.config.EnableIPCheck {
		ipVec := sd.analyzeIPClassification(req)
		if ipVec != nil && ipVec.Score > 0 {
			detection.Vectors = append(detection.Vectors, *ipVec)
			totalScore += ipVec.Score * ipVec.Weight
			totalWeight += ipVec.Weight
		}
	}

	// 10. Automation Deep Analysis (from advanced_detection.go)
	if sd.config.EnableAutomationCheck {
		autoVec := sd.analyzeAutomationSignals(req)
		if autoVec != nil && autoVec.Score > 0 {
			detection.Vectors = append(detection.Vectors, *autoVec)
			totalScore += autoVec.Score * autoVec.Weight
			totalWeight += autoVec.Weight
			vectorResults[VectorAutomation] = &VectorResult{Score: autoVec.Score, Detected: autoVec.Detected}
		}
	}

	// 11. Headless Detection (from advanced_detection.go)
	if sd.config.EnableHeadlessCheck {
		headlessVec := sd.analyzeHeadlessSignals(req)
		if headlessVec != nil && headlessVec.Score > 0 {
			detection.Vectors = append(detection.Vectors, *headlessVec)
			totalScore += headlessVec.Score * headlessVec.Weight
			totalWeight += headlessVec.Weight
			vectorResults[VectorHeadless] = &VectorResult{Score: headlessVec.Score, Detected: headlessVec.Detected}
		}
	}

	// 12. WebRTC Analysis (from advanced_detection.go)
	if sd.config.EnableWebRTCCheck {
		webrtcVec := sd.analyzeWebRTCData(req)
		if webrtcVec != nil && webrtcVec.Score > 0 {
			detection.Vectors = append(detection.Vectors, *webrtcVec)
			totalScore += webrtcVec.Score * webrtcVec.Weight
			totalWeight += webrtcVec.Weight
			vectorResults[VectorWebRTC] = &VectorResult{Score: webrtcVec.Score, Detected: webrtcVec.Detected}
		}
	}

	// 13. HTTP/2 Pseudo-Header Order (from advanced_detection.go)
	if sd.config.EnableHTTP2Check && req.Proto == "HTTP/2.0" {
		http2Vec := sd.analyzeHTTP2Signals(req)
		if http2Vec != nil && http2Vec.Score > 0 {
			detection.Vectors = append(detection.Vectors, *http2Vec)
			totalScore += http2Vec.Score * http2Vec.Weight
			totalWeight += http2Vec.Weight
			vectorResults[VectorHTTP2] = &VectorResult{Score: http2Vec.Score, Detected: http2Vec.Detected}
		}
	}

	// 14. Font Analysis
	if sd.config.EnableFontCheck {
		fontVec := sd.analyzeFontData(req)
		if fontVec != nil && fontVec.Score > 0 {
			detection.Vectors = append(detection.Vectors, *fontVec)
			totalScore += fontVec.Score * fontVec.Weight
			totalWeight += fontVec.Weight
			vectorResults[VectorFont] = &VectorResult{Score: fontVec.Score, Detected: fontVec.Detected}
		}
	}

	// 15. Screen Analysis
	if sd.config.EnableScreenCheck {
		screenVec := sd.analyzeScreenData(req)
		if screenVec != nil && screenVec.Score > 0 {
			detection.Vectors = append(detection.Vectors, *screenVec)
			totalScore += screenVec.Score * screenVec.Weight
			totalWeight += screenVec.Weight
			vectorResults[VectorScreen] = &VectorResult{Score: screenVec.Score, Detected: screenVec.Detected}
		}
	}

	// 16. Plugin Analysis
	if sd.config.EnablePluginCheck {
		pluginVec := sd.analyzePluginData(req)
		if pluginVec != nil && pluginVec.Score > 0 {
			detection.Vectors = append(detection.Vectors, *pluginVec)
			totalScore += pluginVec.Score * pluginVec.Weight
			totalWeight += pluginVec.Weight
			vectorResults[VectorPlugin] = &VectorResult{Score: pluginVec.Score, Detected: pluginVec.Detected}
		}
	}

	// 17. Audio Analysis
	if sd.config.EnableAudioCheck {
		audioVec := sd.analyzeAudioData(req)
		if audioVec != nil && audioVec.Score > 0 {
			detection.Vectors = append(detection.Vectors, *audioVec)
			totalScore += audioVec.Score * audioVec.Weight
			totalWeight += audioVec.Weight
			vectorResults[VectorAudio] = &VectorResult{Score: audioVec.Score, Detected: audioVec.Detected}
		}
	}

	// 18. Fingerprint Coverage Check (detects HTTP impersonation tools)
	fpVec := sd.analyzeFingerprintCoverage(req)
	if fpVec != nil && fpVec.Score > 0 {
		detection.Vectors = append(detection.Vectors, *fpVec)
		totalScore += fpVec.Score * fpVec.Weight
		totalWeight += fpVec.Weight
		vectorResults[VectorFingerprintCoverage] = &VectorResult{Score: fpVec.Score, Detected: fpVec.Detected}
	}

	// 19. Cross-Vector Temporal/Spatial Consistency
	crossVec := sd.analyzeCrossVectorConsistency(req)
	if crossVec != nil && crossVec.Score > 0 {
		detection.Vectors = append(detection.Vectors, *crossVec)
		totalScore += crossVec.Score * crossVec.Weight
		totalWeight += crossVec.Weight
		vectorResults[VectorCrossVector] = &VectorResult{Score: crossVec.Score, Detected: crossVec.Detected}
	}

	// Calculate final score
	if sd.config.EnableAdaptiveScoring && sd.adaptiveScorer != nil && len(vectorResults) > 0 {
		ensemble := sd.adaptiveScorer.ScoreResults(vectorResults)
		detection.Score = ensemble.FinalScore
	} else if totalWeight > 0 {
		detection.Score = totalScore / totalWeight
	}

	detection.Confidence = detection.Score
	detection.IsBot = detection.Score >= sd.config.ThresholdBot

	// Determine if it's specifically our stealth browser
	detection.IsStealth = sd.detectStealthBrowser(&detection)

	sd.mu.Lock()
	sd.detections = append(sd.detections, detection)
	sd.mu.Unlock()

	return &detection
}

// RecordBypassOutcome records an outcome for adaptive weight adjustment.
func (sd *StealthDetector) RecordBypassOutcome(category VectorCategory, score float64, bypassed bool) {
	if sd.adaptiveScorer != nil {
		sd.adaptiveScorer.RecordOutcome(BypassRecord{
			Timestamp: time.Now(),
			Category:  category,
			Score:     score,
			Bypassed:  bypassed,
		})
	}
}

// advancedChecksToVector converts AdvancedCheckResult slices into a DetectionVector.
func advancedChecksToVector(checks []AdvancedCheckResult, name, category string, weight float64) *DetectionVector {
	if len(checks) == 0 {
		return nil
	}

	vec := &DetectionVector{
		Name:        name,
		Category:    category,
		Weight:      weight,
		Description: fmt.Sprintf("Advanced %s analysis", category),
		Indicators:  make([]string, 0),
	}

	for _, c := range checks {
		if c.Score > 0 {
			vec.Score += c.Score
			vec.Indicators = append(vec.Indicators, fmt.Sprintf("%s: %s", c.CheckName, c.Details))
		}
	}

	// Average across checks to keep in [0,1]
	if len(checks) > 0 {
		vec.Score /= float64(len(checks))
	}
	if vec.Score > 1.0 {
		vec.Score = 1.0
	}

	vec.Detected = vec.Score > 0.3
	return vec
}

// analyzeWebGLData performs deep WebGL analysis using the WebGLAnalyzer.
func (sd *StealthDetector) analyzeWebGLData(req *http.Request) *DetectionVector {
	webglHeader := req.Header.Get(constants.HeaderWebGLData)
	if webglHeader == "" {
		return nil
	}

	var data WebGLData
	if err := json.Unmarshal([]byte(webglHeader), &data); err != nil {
		return nil
	}

	analyzer := NewWebGLAnalyzer()
	result := analyzer.Analyze(&data)

	indicators := make([]string, 0, len(result.Indicators))
	for _, ind := range result.Indicators {
		indicators = append(indicators, ind.Check)
	}

	return &DetectionVector{
		Name:        "WebGL Deep Analysis",
		Category:    string(VectorWebGL),
		Score:       result.Score,
		Weight:      constants.WeightWebGL,
		Detected:    result.Detected,
		Description: "Deep WebGL renderer and platform consistency analysis",
		Indicators:  indicators,
	}
}

// analyzeIPClassification checks client IP for datacenter/VPN classification.
func (sd *StealthDetector) analyzeIPClassification(req *http.Request) *DetectionVector {
	clientIP := getClientIP(req)
	if clientIP == "" || clientIP == "unknown" {
		return nil
	}

	checks := sd.advancedDet.AnalyzeIP(clientIP)
	return advancedChecksToVector(checks, "IP Classification", "ip", constants.WeightIP)
}

// analyzeAutomationSignals performs deep automation tool detection.
func (sd *StealthDetector) analyzeAutomationSignals(req *http.Request) *DetectionVector {
	checks := sd.advancedDet.AnalyzeAutomation(req)
	return advancedChecksToVector(checks, "Automation Detection", "automation", constants.WeightAutomation)
}

// analyzeHeadlessSignals detects headless browser indicators.
func (sd *StealthDetector) analyzeHeadlessSignals(req *http.Request) *DetectionVector {
	checks := sd.advancedDet.AnalyzeHeadless(req)
	return advancedChecksToVector(checks, "Headless Detection", "headless", constants.WeightHeadless)
}

// analyzeWebRTCData checks for WebRTC leak indicators and spoofing.
func (sd *StealthDetector) analyzeWebRTCData(req *http.Request) *DetectionVector {
	webrtcHeader := req.Header.Get(constants.HeaderWebRTCData)
	if webrtcHeader == "" {
		return nil
	}

	var data WebRTCData
	if err := json.Unmarshal([]byte(webrtcHeader), &data); err != nil {
		return nil
	}

	// Set the request source IP for mismatch detection
	data.RequestSourceIP = getClientIP(req)

	checks := sd.advancedDet.AnalyzeWebRTC(&data)
	return advancedChecksToVector(checks, "WebRTC Analysis", string(VectorWebRTC), constants.WeightWebRTC)
}

// analyzeHTTP2Signals checks HTTP/2 pseudo-header ordering.
func (sd *StealthDetector) analyzeHTTP2Signals(req *http.Request) *DetectionVector {
	checks := sd.advancedDet.AnalyzeHTTP2(req, req.Proto)
	return advancedChecksToVector(checks, "HTTP/2 Analysis", string(VectorHTTP2), constants.WeightHTTP2)
}

// analyzeFontData performs font enumeration analysis.
func (sd *StealthDetector) analyzeFontData(req *http.Request) *DetectionVector {
	fontHeader := req.Header.Get(constants.HeaderFontData)
	if fontHeader == "" {
		return nil
	}

	var data FontData
	if err := json.Unmarshal([]byte(fontHeader), &data); err != nil {
		return nil
	}

	analyzer := NewFontAnalyzer()
	result := analyzer.Analyze(&data)

	indicators := make([]string, 0, len(result.Indicators))
	for _, ind := range result.Indicators {
		indicators = append(indicators, ind.Check)
	}

	return &DetectionVector{
		Name:        "Font Analysis",
		Category:    string(VectorFont),
		Score:       result.Score,
		Weight:      constants.WeightFont,
		Detected:    result.Detected,
		Description: "Font enumeration and platform consistency analysis",
		Indicators:  indicators,
	}
}

// analyzeScreenData performs screen geometry analysis.
func (sd *StealthDetector) analyzeScreenData(req *http.Request) *DetectionVector {
	screenHeader := req.Header.Get(constants.HeaderScreenData)
	if screenHeader == "" {
		return nil
	}

	var data ScreenData
	if err := json.Unmarshal([]byte(screenHeader), &data); err != nil {
		return nil
	}

	analyzer := NewScreenAnalyzer()
	result := analyzer.Analyze(&data)

	indicators := make([]string, 0, len(result.Indicators))
	for _, ind := range result.Indicators {
		indicators = append(indicators, ind.Check)
	}

	return &DetectionVector{
		Name:        "Screen Analysis",
		Category:    string(VectorScreen),
		Score:       result.Score,
		Weight:      constants.WeightScreen,
		Detected:    result.Detected,
		Description: "Screen geometry and display configuration analysis",
		Indicators:  indicators,
	}
}

// analyzePluginData performs plugin enumeration analysis.
func (sd *StealthDetector) analyzePluginData(req *http.Request) *DetectionVector {
	pluginHeader := req.Header.Get(constants.HeaderPluginData)
	if pluginHeader == "" {
		return nil
	}

	var data PluginData
	if err := json.Unmarshal([]byte(pluginHeader), &data); err != nil {
		return nil
	}

	// Extract browser info for context
	ua := req.Header.Get("User-Agent")
	data.UserAgent = ua

	analyzer := NewPluginAnalyzer()
	result := analyzer.Analyze(&data)

	indicators := make([]string, 0, len(result.Indicators))
	for _, ind := range result.Indicators {
		indicators = append(indicators, ind.Check)
	}

	return &DetectionVector{
		Name:        "Plugin Analysis",
		Category:    string(VectorPlugin),
		Score:       result.Score,
		Weight:      constants.WeightPlugin,
		Detected:    result.Detected,
		Description: "Browser plugin enumeration and consistency analysis",
		Indicators:  indicators,
	}
}

// analyzeAudioData checks for AudioContext fingerprint data.
// If the header is entirely missing, returns a high score since real browsers
// always have AudioContext available. If present, delegates to AudioAnalyzer.
func (sd *StealthDetector) analyzeAudioData(req *http.Request) *DetectionVector {
	audioHeader := req.Header.Get(constants.HeaderAudioData)
	if audioHeader == "" {
		// Only penalize if other JS-sourced fingerprint headers are present,
		// proving the client has a JS context but omitted audio data.
		if hasJSFingerprintHeaders(req) {
			return &DetectionVector{
				Name:        "Audio Analysis",
				Category:    string(VectorAudio),
				Score:       0.45,
				Weight:      constants.WeightAudio,
				Detected:    true,
				Description: "AudioContext fingerprint missing (client has JS context but no AudioContext)",
				Indicators:  []string{"missing_audio_data"},
			}
		}
		return nil
	}

	var data AudioData
	if err := json.Unmarshal([]byte(audioHeader), &data); err != nil {
		return nil
	}

	analyzer := NewAudioAnalyzer()
	result := analyzer.Analyze(&data)

	indicators := make([]string, 0, len(result.Indicators))
	for _, ind := range result.Indicators {
		indicators = append(indicators, ind.Check)
	}

	return &DetectionVector{
		Name:        "Audio Analysis",
		Category:    string(VectorAudio),
		Score:       result.Score,
		Weight:      constants.WeightAudio,
		Detected:    result.Detected,
		Description: "AudioContext fingerprint analysis",
		Indicators:  indicators,
	}
}

func (sd *StealthDetector) analyzeTLSFingerprint(tlsConn *tls.ConnectionState) *TLSFingerprintInfo {
	info := &TLSFingerprintInfo{
		TLSVersion:  fmt.Sprintf("0x%04x", tlsConn.Version),
		CipherSuite: fmt.Sprintf("0x%04x", tlsConn.CipherSuite),
		Anomalies:   make([]string, 0),
	}

	// Check for known JA4 (simplified - real implementation would parse ClientHello)
	info.JA4 = "unknown"

	// Detect anomalies
	if info.TLSVersion != "0x0304" && info.TLSVersion != "0x0303" {
		info.Anomalies = append(info.Anomalies, fmt.Sprintf("Unusual TLS version: %s", info.TLSVersion))
	}

	// Check cipher suite
	if strings.Contains(info.CipherSuite, "00ff") {
		info.Anomalies = append(info.Anomalies, "GREASE cipher suite detected")
	}

	vec := DetectionVector{
		Name:        "TLS Fingerprint",
		Category:    "tls",
		Weight:      constants.WeightTLS,
		Description: "Analyzes TLS handshake for browser identification",
	}

	if len(info.Anomalies) > 0 {
		vec.Score = 0.3
		vec.Detected = true
		vec.Indicators = info.Anomalies
	}

	return info
}

func (sd *StealthDetector) analyzeHTTPHeaders(req *http.Request) *HTTPFingerprintInfo {
	info := &HTTPFingerprintInfo{
		UserAgent:          req.Header.Get("User-Agent"),
		Accept:             req.Header.Get("Accept"),
		AcceptLanguage:     req.Header.Get("Accept-Language"),
		AcceptEncoding:     req.Header.Get("Accept-Encoding"),
		SecCHUA:            req.Header.Get("Sec-Ch-Ua"),
		SecCHUAMobile:      req.Header.Get("Sec-Ch-Ua-Mobile"),
		SecCHUAPlatform:    req.Header.Get("Sec-Ch-Ua-Platform"),
		SecCHUAFullVersion: req.Header.Get("Sec-Ch-Ua-Full-Version"),
		SecCHUAArch:        req.Header.Get("Sec-Ch-Ua-Arch"),
		SecCHUABitness:     req.Header.Get("Sec-Ch-Ua-Bitness"),
		SecCHUAModel:       req.Header.Get("Sec-Ch-Ua-Model"),
		SecFetchDest:       req.Header.Get("Sec-Fetch-Dest"),
		SecFetchMode:       req.Header.Get("Sec-Fetch-Mode"),
		SecFetchSite:       req.Header.Get("Sec-Fetch-Site"),
		SecFetchUser:       req.Header.Get("Sec-Fetch-User"),
		UpgradeInsecure:    req.Header.Get("Upgrade-Insecure-Requests"),
		HeaderCount:        len(req.Header),
		HeaderOrder:        make([]string, 0),
		MissingHeaders:     make([]string, 0),
		SuspiciousHeaders:  make([]string, 0),
	}

	for k := range req.Header {
		info.HeaderOrder = append(info.HeaderOrder, k)
	}

	// Parse User-Agent
	if info.UserAgent != "" {
		info.Platform = extractPlatform(info.UserAgent)
		info.BrowserVersion = extractBrowserVersion(info.UserAgent)
	}

	// Check for suspicious User-Agent strings
	if info.UserAgent == "" {
		info.SuspiciousHeaders = append(info.SuspiciousHeaders, "missing_user_agent")
	} else {
		uaLower := strings.ToLower(info.UserAgent)
		suspiciousPatterns := []string{"curl", "wget", "python", "scrapy", "bot", "spider", "headless", "selenium", "automation", "phantomjs", "go-http-client"}
		for _, pat := range suspiciousPatterns {
			if strings.Contains(uaLower, pat) {
				info.SuspiciousHeaders = append(info.SuspiciousHeaders, fmt.Sprintf("suspicious_ua_%s", pat))
				break
			}
		}
	}

	// Check for missing headers
	requiredHeaders := []string{"Accept", "Accept-Language"}
	for _, h := range requiredHeaders {
		if req.Header.Get(h) == "" {
			info.MissingHeaders = append(info.MissingHeaders, h)
		}
	}

	// Check Accept header format — bots often use simple "*/*" or omit quality values
	if accept := info.Accept; accept != "" {
		if accept == "*/*" {
			info.SuspiciousHeaders = append(info.SuspiciousHeaders, "generic_accept_header")
		}
	}

	// Check header count — real browsers send 8+ headers
	if info.HeaderCount < 5 {
		info.SuspiciousHeaders = append(info.SuspiciousHeaders, "too_few_headers")
	}

	// Check Sec-Fetch-* headers — Chrome/Edge always send these on navigation
	isChromeUA := strings.Contains(strings.ToLower(info.UserAgent), "chrome")
	if isChromeUA {
		if info.SecFetchDest == "" || info.SecFetchMode == "" || info.SecFetchSite == "" {
			info.MissingHeaders = append(info.MissingHeaders, "Sec-Fetch-*")
		}
	}

	// Check Client Hints consistency
	info.ClientHintsConsistent = sd.checkClientHintsConsistency(info)

	if !info.ClientHintsConsistent {
		info.SuspiciousHeaders = append(info.SuspiciousHeaders, "inconsistent_client_hints")
	}

	// Check for missing Client Hints (Chrome should always send these; Firefox never does)
	if isChromeUA && (info.SecCHUA == "" || info.SecCHUAPlatform == "") {
		info.MissingHeaders = append(info.MissingHeaders, "Sec-Ch-Ua*")
	}

	// Check for webdriver header (simple boolean flag from stealth bypass tools)
	if req.Header.Get("X-Navigator-Webdriver") == "true" {
		info.SuspiciousHeaders = append(info.SuspiciousHeaders, "webdriver_exposed")
	}

	return info
}

func (sd *StealthDetector) checkClientHintsConsistency(info *HTTPFingerprintInfo) bool {
	if info.SecCHUA == "" || info.SecCHUAPlatform == "" {
		return true // Can't determine inconsistency without both
	}

	uaLower := strings.ToLower(info.UserAgent)
	platformLower := strings.ToLower(info.SecCHUAPlatform)

	// Check Windows
	if strings.Contains(uaLower, "windows") && !strings.Contains(platformLower, "windows") {
		return false
	}

	// Check macOS
	if strings.Contains(uaLower, "mac") && !strings.Contains(platformLower, "mac") {
		return false
	}

	// Check Linux
	if strings.Contains(uaLower, "linux") && !strings.Contains(platformLower, "linux") {
		return false
	}

	// Check Not_A Brand with Linux (common stealth indicator)
	if strings.Contains(info.SecCHUA, "Not_A Brand") && strings.Contains(platformLower, "linux") {
		return false
	}

	return true
}

func (sd *StealthDetector) analyzeNavigatorData(req *http.Request) *DetectionVector {
	// Check for navigator data that might be passed as custom headers
	// In real implementation, this would come from injected JS
	navHeader := req.Header.Get(constants.HeaderNavigatorData)
	if navHeader == "" {
		return nil
	}

	vec := &DetectionVector{
		Name:        "Navigator Properties",
		Category:    "navigator",
		Weight:      0.2,
		Description: "Analyzes navigator object properties for automation detection",
	}

	var navData map[string]interface{}
	if err := json.Unmarshal([]byte(navHeader), &navData); err != nil {
		return nil
	}

	log.Printf("NAV_DATA JSON: %+v", navData)

	indicators := make([]string, 0)

	// Check webdriver (naive boolean leak)
	if webdriver, ok := navData["webdriver"].(bool); ok && webdriver {
		indicators = append(indicators, "webdriver=true")
		vec.Score += 0.5
	}

	// Phase 10: Check stringification leak (Nodriver toString bypass failure)
	if wdStr, ok := navData["webdriverString"].(string); ok {
		if !strings.Contains(wdStr, "[native code]") {
			indicators = append(indicators, "inconsistent_webdriver_stringification")
			vec.Score += 0.6
		}
	} else {
		// If they patched the object but forgot the toString proxy
		indicators = append(indicators, "missing_webdriver_toString")
		vec.Score += 0.3
	}

	// Check chrome object (only for Chrome UAs — Firefox doesn't have chrome.*)
	reqUA := req.Header.Get("User-Agent")
	isChromeNav := strings.Contains(strings.ToLower(reqUA), "chrome")
	if isChromeNav {
		if _, ok := navData["chrome"]; !ok {
			indicators = append(indicators, "missing_chrome_runtime")
			vec.Score += 0.2
		}

		// P11: chrome.app API shape — real Chrome always has chrome.app with
		// isInstalled (bool), InstallState, RunningState. Missing or empty = bot.
		if chromeApp, ok := navData["chrome_app"].(map[string]interface{}); ok {
			if _, hasInstalled := chromeApp["isInstalled"]; !hasInstalled {
				indicators = append(indicators, "chrome_app_missing_isInstalled")
				vec.Score += 0.15
			}
			if _, hasInstallState := chromeApp["InstallState"]; !hasInstallState {
				indicators = append(indicators, "chrome_app_missing_InstallState")
				vec.Score += 0.10
			}
			if _, hasRunningState := chromeApp["RunningState"]; !hasRunningState {
				indicators = append(indicators, "chrome_app_missing_RunningState")
				vec.Score += 0.10
			}
		} else {
			// chrome.app entirely missing — strong signal for headless/automated
			indicators = append(indicators, "missing_chrome_app")
			vec.Score += 0.25
		}

		// P11: chrome.csi — real Chrome exposes chrome.csi() returning timing data.
		// Missing = headless or poorly spoofed.
		if _, hasCsi := navData["chrome_csi"]; !hasCsi {
			indicators = append(indicators, "missing_chrome_csi")
			vec.Score += 0.15
		}

		// P11: performance.memory — Chrome-only API exposing JS heap statistics.
		// Real Chrome always has jsHeapSizeLimit, totalJSHeapSize, usedJSHeapSize.
		if perfMem, ok := navData["performance_memory"].(map[string]interface{}); ok {
			if _, hasLimit := perfMem["jsHeapSizeLimit"]; !hasLimit {
				indicators = append(indicators, "performance_memory_missing_limit")
				vec.Score += 0.10
			}
			if _, hasTotal := perfMem["totalJSHeapSize"]; !hasTotal {
				indicators = append(indicators, "performance_memory_missing_total")
				vec.Score += 0.10
			}
			// Sanity check: usedJSHeapSize <= totalJSHeapSize <= jsHeapSizeLimit
			used, _ := perfMem["usedJSHeapSize"].(float64)
			total, _ := perfMem["totalJSHeapSize"].(float64)
			limit, _ := perfMem["jsHeapSizeLimit"].(float64)
			if used > 0 && total > 0 && used > total {
				indicators = append(indicators, "performance_memory_used_exceeds_total")
				vec.Score += 0.20
			}
			if total > 0 && limit > 0 && total > limit {
				indicators = append(indicators, "performance_memory_total_exceeds_limit")
				vec.Score += 0.20
			}
		} else {
			indicators = append(indicators, "missing_performance_memory")
			vec.Score += 0.15
		}
	}

	// Check for suspicious permissions
	if perm, ok := navData["permissions"].(string); ok {
		if strings.Contains(perm, "prompt") {
			indicators = append(indicators, "unusual_permissions")
			vec.Score += 0.1
		}
	}

	// Check automation flags
	automationFlags := []string{"__webdriver_script_fn__", "__selenium_unwrapped", "callSelenium"}
	for _, flag := range automationFlags {
		if _, ok := navData[flag]; ok {
			indicators = append(indicators, fmt.Sprintf("automation_flag: %s", flag))
			vec.Score += 0.6
		}
	}

	// Check for missing navigator.languages — real browsers always populate this
	// non-optional property. Its absence signals synthetic navigator data.
	if _, hasLangs := navData["languages"]; !hasLangs {
		indicators = append(indicators, "missing_navigator_languages")
		vec.Score += 0.5
	}

	// Check for missing navigator.productSub — Chrome always reports "20030107",
	// Firefox always reports "20100101". Its absence is a strong synthetic signal.
	if _, hasProductSub := navData["productSub"]; !hasProductSub {
		indicators = append(indicators, "missing_navigator_productSub")
		vec.Score += 0.3
	}

	// Check for missing navigator.maxTouchPoints — real desktop browsers always
	// report maxTouchPoints: 0. Its absence compounds with other missing fields.
	if _, hasMaxTouch := navData["maxTouchPoints"]; !hasMaxTouch {
		indicators = append(indicators, "missing_navigator_maxTouchPoints")
		vec.Score += 0.2
	}

	// Check for missing/inconsistent navigator.appVersion. Real browsers always
	// have appVersion = UA minus "Mozilla/" prefix. Missing = synthetic; inconsistent = spoofed.
	ua, _ := navData["userAgent"].(string)
	if appVer, hasAppVer := navData["appVersion"].(string); !hasAppVer {
		indicators = append(indicators, "missing_navigator_appVersion")
		vec.Score += 0.45
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        "missing_app_version",
			Fired:       true,
			Weight:      0.45,
			Score:       0.45,
			Field:       "appVersion",
			Actual:      "",
			Expected:    "UA minus 'Mozilla/' prefix",
			Severity:    "high",
			Description: "navigator.appVersion is missing (real browsers always populate it)",
		})
	} else if ua != "" && strings.HasPrefix(ua, "Mozilla/") {
		expectedAppVer := ua[len("Mozilla/"):]
		if appVer != expectedAppVer {
			indicators = append(indicators, "inconsistent_navigator_appVersion")
			vec.Score += 0.40
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "inconsistent_app_version",
				Fired:       true,
				Weight:      0.40,
				Score:       0.40,
				Field:       "appVersion",
				Actual:      appVer,
				Expected:    expectedAppVer,
				Severity:    "high",
				Description: "navigator.appVersion does not match UA minus 'Mozilla/' prefix",
			})
		}
	}

	// Phase 16: Comprehensive Spoofing Checks
	indicators = sd.analyzeNetworkInformation(navData, vec, indicators)
	indicators = sd.analyzePluginsArray(navData, vec, indicators)
	indicators = sd.analyzeScreenGeometry(navData, vec, indicators)
	indicators = sd.analyzeVideoElement(navData, vec, indicators)
	indicators = sd.analyzePermissionsAPI(navData, vec, indicators)
	indicators = sd.analyzeTimezoneParity(navData, vec, indicators, req)

	// Check for missing timezone. Real browsers always have
	// Intl.DateTimeFormat().resolvedOptions().timeZone available (e.g., "America/New_York").
	// Its absence in navigator data signals synthetic generation.
	if _, hasTZ := navData["timezone"]; !hasTZ {
		indicators = append(indicators, "missing_timezone")
		vec.Score += 0.15
	}

	vec.Indicators = indicators
	vec.Detected = vec.Score > 0.3

	return vec
}

func (sd *StealthDetector) analyzeNetworkInformation(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	var rtt float64
	var hasRTT bool

	if conn, ok := navData["connection"].(map[string]interface{}); ok {
		rtt, hasRTT = conn["rtt"].(float64)
		downlink, _ := conn["downlink"].(float64)

		if rtt == 50 && downlink == 10 {
			indicators = append(indicators, "spoofed_network_api_detected")
			vec.Score += 0.4
		}

		// Chrome's navigator.connection always includes effectiveType ("4g", "3g", etc.).
		// Its absence signals synthetic connection data.
		if _, hasEffType := conn["effectiveType"].(string); !hasEffType {
			indicators = append(indicators, "missing_connection_effectiveType")
			vec.Score += 0.30
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "missing_connection_effective_type",
				Fired:       true,
				Weight:      0.30,
				Score:       0.30,
				Field:       "effectiveType",
				Actual:      "",
				Expected:    "4g",
				Severity:    "medium",
				Description: "navigator.connection.effectiveType is missing (Chrome always includes it)",
			})
		}
	} else if r, ok := navData["connection_rtt"].(float64); ok {
		rtt = r
		hasRTT = true
		downlink, _ := navData["connection_downlink"].(float64)
		if rtt == 50 && downlink == 10 {
			indicators = append(indicators, "spoofed_network_api_detected")
			vec.Score += 0.4
		}
	}

	// Chrome quantizes NavigationTiming RTT to multiples of 25ms.
	// Non-quantized values indicate synthetic generation.
	if hasRTT && rtt > 0 && int(rtt)%25 != 0 {
		indicators = append(indicators, fmt.Sprintf("non_quantized_rtt: %.0fms (not multiple of 25)", rtt))
		vec.Score += 0.3
	}

	// RTT/Downlink anticorrelation check. Low RTT implies fast connection (high
	// downlink), and high RTT implies slow connection (low downlink). Independently
	// generated values often produce improbable combinations.
	if hasRTT {
		downlink := 0.0
		hasDownlink := false
		if conn, ok := navData["connection"].(map[string]interface{}); ok {
			downlink, hasDownlink = conn["downlink"].(float64)
		} else if dl, ok := navData["connection_downlink"].(float64); ok {
			downlink = dl
			hasDownlink = true
		}
		if hasDownlink {
			if rtt <= 50 && downlink < 3.0 {
				indicators = append(indicators, fmt.Sprintf("rtt_downlink_anticorrelated: rtt=%.0f downlink=%.1f (low RTT should have high downlink)", rtt, downlink))
				vec.Score += 0.35
			}
			if rtt >= 150 && downlink > 8.0 {
				indicators = append(indicators, fmt.Sprintf("rtt_downlink_anticorrelated: rtt=%.0f downlink=%.1f (high RTT should have low downlink)", rtt, downlink))
				vec.Score += 0.35
			}
		}
	}

	return indicators
}

func (sd *StealthDetector) analyzePluginsArray(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	if plugins, ok := navData["plugins"].([]interface{}); ok {
		if len(plugins) == 5 {
			isIntArray := true
			for _, p := range plugins {
				if _, isNum := p.(float64); !isNum {
					isIntArray = false
					break
				}
			}
			if isIntArray {
				indicators = append(indicators, "spoofed_plugins_array_detected")
				vec.Score += 0.5
			}
		}
	} else if length, ok := navData["plugins_length"].(float64); ok {
		if length == 5 && navData["plugins_is_array"] == true {
			indicators = append(indicators, "spoofed_plugins_array_detected")
			vec.Score += 0.5
		}
	}
	return indicators
}

func (sd *StealthDetector) analyzeScreenGeometry(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	var colorDepth, innerWidth, outerWidth float64
	if screen, ok := navData["screen"].(map[string]interface{}); ok {
		colorDepth, _ = screen["colorDepth"].(float64)
		innerWidth, _ = navData["innerWidth"].(float64)
		outerWidth, _ = navData["outerWidth"].(float64)
	} else if cd, ok := navData["screen_color_depth"].(float64); ok {
		colorDepth = cd
		innerWidth, _ = navData["screen_inner_width"].(float64)
		outerWidth, _ = navData["screen_outer_width"].(float64)
	}

	if colorDepth == 24 {
		if innerWidth > 0 && outerWidth > 0 && innerWidth == outerWidth {
			indicators = append(indicators, "impossible_window_geometry_detected")
			vec.Score += 0.4
		}
	}
	return indicators
}

func (sd *StealthDetector) analyzeVideoElement(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	if video, ok := navData["video_can_play_mp4"].(string); ok {
		if video == "probably" {
			indicators = append(indicators, "spoofed_video_element_detected")
			vec.Score += 0.3
		}
	}
	return indicators
}

func (sd *StealthDetector) analyzeTimezoneParity(navData map[string]interface{}, vec *DetectionVector, indicators []string, _ *http.Request) []string {
	if tz, ok := navData["timezone"].(string); ok {
		if offset, ok := navData["timezone_offset"].(float64); ok {
			if tz == "America/New_York" && offset != 300 {
				indicators = append(indicators, "timezone_offset_mismatch")
				vec.Score += 0.4
			}
		}
	}
	return indicators
}

func (sd *StealthDetector) analyzePermissionsAPI(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	if perm, ok := navData["notifications_prompt"].(string); ok {
		if perm == "default" && navData["permissions_is_proxy"] == true {
			indicators = append(indicators, "spoofed_permissions_api_detected")
			vec.Score += 0.6
		}
	}
	return indicators
}

func (sd *StealthDetector) analyzeCanvasData(req *http.Request) *DetectionVector {
	canvasHeader := req.Header.Get(constants.HeaderCanvasFingerprint)
	if canvasHeader == "" {
		if hasJSFingerprintHeaders(req) {
			return &DetectionVector{
				Name:        "Canvas/WebGL Fingerprint",
				Category:    string(VectorCanvas),
				Score:       0.35,
				Weight:      constants.WeightCanvas,
				Detected:    true,
				Description: "Canvas fingerprint data missing (client has JS context but no canvas toDataURL output)",
				Indicators:  []string{"missing_canvas_data"},
			}
		}
		return nil
	}

	vec := &DetectionVector{
		Name:        "Canvas/WebGL Fingerprint",
		Category:    "canvas",
		Weight:      constants.WeightTLS,
		Description: "Analyzes canvas and WebGL fingerprints for randomization",
	}

	indicators := make([]string, 0)

	// Check if canvas hash changes (randomization)
	if strings.Contains(canvasHeader, "randomized") {
		indicators = append(indicators, "canvas_randomization_detected")
		vec.Score += 0.4
	}

	// Check for suspicious WebGL fingerprints
	if strings.Contains(canvasHeader, "swiftshader") {
		indicators = append(indicators, "software_renderer")
		vec.Score += 0.2
	}

	// Check for masked WebGL
	if strings.Contains(canvasHeader, "google") || strings.Contains(canvasHeader, "intel") {
		// These are common real browser fingerprints - no action needed
		_ = canvasHeader
	} else if strings.Contains(canvasHeader, "unknown") {
		indicators = append(indicators, "masked_webgl")
		vec.Score += 0.3
	}

	// Check for bare hex hash format — real canvas fingerprints are data URLs,
	// JSON with metadata, or have library prefixes. A bare 32-128 char hex string
	// strongly suggests synthetic generation (e.g., fmt.Sprintf("%x", sha256hash)).
	if isBareHexHash(canvasHeader) {
		indicators = append(indicators, "synthetic_canvas_hash_format")
		vec.Score += 0.5
	}

	// Check for too-short canvas data URL payload. Real canvas toDataURL() produces
	// a PNG image of a rendered scene — typically 5KB-50KB (7000-70000 base64 chars).
	// A payload under 200 base64 chars is impossible for a real rendered canvas.
	if strings.HasPrefix(canvasHeader, "data:image/png;base64,") {
		payload := canvasHeader[len("data:image/png;base64,"):]
		if len(payload) < 200 {
			indicators = append(indicators, fmt.Sprintf("canvas_payload_too_short: %d chars (min 200 expected)", len(payload)))
			vec.Score += 0.5
		}

		// Check PNG magic header. Real toDataURL() produces an actual PNG whose
		// first 8 bytes are \x89PNG\r\n\x1a\n. In base64, this always starts with "iVBOR".
		// Random bytes produce random base64 prefixes — a strong synthetic signal.
		if len(payload) >= 200 && !strings.HasPrefix(payload, "iVBOR") {
			indicators = append(indicators, "canvas_png_magic_header_missing")
			vec.Score += 0.55
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:     "canvas_png_magic_header",
				Fired:    true,
				Weight:   0.55,
				Score:    0.55,
				Field:    "canvas_base64_prefix",
				Actual:   safePrefix(payload, 5),
				Expected: "iVBOR",
				Severity: "high",
				Description: "Canvas data URL does not start with PNG magic bytes (iVBOR)",
			})
		}

		// Check IDAT chunk structure. Real PNGs have: 8 sig + 25 IHDR = 33, then
		// IDAT chunk at offset 33 (4 bytes length + 4 bytes "IDAT" type at offset 37).
		// If the base64 decodes to valid PNG signature but lacks IDAT at byte 37-40,
		// it's synthetic random bytes stuffed after a valid header.
		if len(payload) >= 200 && strings.HasPrefix(payload, "iVBOR") {
			if decoded, err := base64.StdEncoding.DecodeString(payload); err == nil && len(decoded) > 40 {
				if string(decoded[37:41]) != "IDAT" {
					indicators = append(indicators, "canvas_missing_idat_chunk")
					vec.Score += 0.40
				} else {
					// IDAT exists — validate its data is valid zlib/DEFLATE.
					// Real canvas toDataURL() produces DEFLATE-compressed image data.
					// Synthetic generators stuff random bytes into IDAT, which won't
					// decompress. This is a very strong signal of synthetic generation.
					idatLen := int(decoded[33])<<24 | int(decoded[34])<<16 | int(decoded[35])<<8 | int(decoded[36])
					if idatLen > 0 && len(decoded) >= 41+idatLen {
						idatData := decoded[41 : 41+idatLen]
						r, zlibErr := zlib.NewReader(bytes.NewReader(idatData))
						if zlibErr != nil {
							indicators = append(indicators, "canvas_idat_not_deflate")
							vec.Score += 0.55
						} else {
							_, readErr := io.ReadAll(r)
							_ = r.Close()
							if readErr != nil {
								indicators = append(indicators, "canvas_idat_corrupt_deflate")
								vec.Score += 0.50
							}
						}
					}
				}
			}
		}
	}

	vec.Indicators = indicators
	vec.Detected = vec.Score > 0.3

	return vec
}

// safePrefix returns the first n characters of s, or s if shorter.
func safePrefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// isBareHexHash returns true if the string is a bare hexadecimal hash (32-128 chars
// of only [0-9a-fA-F]). Real canvas fingerprints use data URLs, JSON, or library prefixes.
func isBareHexHash(s string) bool {
	if len(s) < 32 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func (sd *StealthDetector) analyzeTimingData(req *http.Request) *DetectionVector {
	// Check for timing data passed via headers (from injected scripts)
	timingHeader := req.Header.Get(constants.HeaderTimingData)
	if timingHeader == "" {
		if hasJSFingerprintHeaders(req) {
			return &DetectionVector{
				Name:        "Timing Anomalies",
				Category:    string(VectorTiming),
				Score:       0.40,
				Weight:      constants.WeightTiming,
				Detected:    true,
				Description: "Resource timing data missing (client has JS context but no Performance API entries)",
				Indicators:  []string{"missing_timing_data"},
			}
		}
		return nil
	}

	vec := &DetectionVector{
		Name:        "Timing Anomalies",
		Category:    "timing",
		Weight:      constants.WeightTiming,
		Description: "Analyzes timing patterns for automation detection",
	}

	indicators := make([]string, 0)

	var timing map[string]interface{}
	if err := json.Unmarshal([]byte(timingHeader), &timing); err != nil {
		return nil
	}

	// Try deep analysis with TimingAnalyzer if entries are present
	if entriesRaw, ok := timing["entries"].([]interface{}); ok && len(entriesRaw) >= 2 {
		seq := &RequestTimingSequence{Entries: make([]RequestTimingEntry, 0, len(entriesRaw))}
		for _, e := range entriesRaw {
			if em, ok := e.(map[string]interface{}); ok {
				entry := RequestTimingEntry{}
				if ts, ok := em["timestamp_ms"].(float64); ok {
					entry.Timestamp = int64(ts)
				}
				if url, ok := em["url"].(string); ok {
					entry.URL = url
				}
				if ct, ok := em["content_type"].(string); ok {
					entry.ContentType = ct
				}
				if ref, ok := em["referrer"].(string); ok {
					entry.Referrer = ref
				}
				if dur, ok := em["duration_ms"].(float64); ok {
					entry.Duration = int64(dur)
				}
				seq.Entries = append(seq.Entries, entry)
			}
		}

		if len(seq.Entries) >= 2 {
			analyzer := NewTimingAnalyzer(nil)
			result := analyzer.Analyze(seq)
			vec.Score = result.Score
			for _, ind := range result.Indicators {
				indicators = append(indicators, ind.Check)
			}
			vec.Indicators = indicators
			vec.Detected = result.Detected
			return vec
		}
	}

	// Fallback: legacy TTFB check
	if ttfb, ok := timing["ttfb"].(float64); ok && ttfb == 0 {
		indicators = append(indicators, "zero_ttfb")
		vec.Score += 0.4
	}

	// Check for perfect navigation timing
	if navStart, ok := timing["navigationStart"].(float64); ok {
		if loadEnd, ok := timing["loadEventEnd"].(float64); ok && loadEnd > 0 {
			totalTime := loadEnd - navStart
			if totalTime < 100 {
				indicators = append(indicators, "too_fast_load")
				vec.Score += 0.3
			}
		}
	}

	vec.Indicators = indicators
	vec.Detected = vec.Score > 0.3

	return vec
}

func (sd *StealthDetector) analyzeBehavioralData(req *http.Request) *DetectionVector {
	behavHeader := req.Header.Get(constants.HeaderBehavioralData)
	if behavHeader == "" {
		// Only penalize if other JS-sourced fingerprint headers are present,
		// proving the client has a JS context but omitted behavioral data.
		if hasJSFingerprintHeaders(req) {
			return &DetectionVector{
				Name:        "Behavioral Patterns",
				Category:    string(VectorBehavioral),
				Score:       0.50,
				Weight:      constants.WeightBehavioral,
				Detected:    true,
				Description: "Behavioral data missing (client has JS context but no mouse/keyboard events)",
				Indicators:  []string{"missing_behavioral_data"},
			}
		}
		return nil
	}

	vec := &DetectionVector{
		Name:        "Behavioral Patterns",
		Category:    "behavioral",
		Weight:      constants.WeightBehavioral,
		Description: "Analyzes user interaction patterns for automation",
	}

	indicators := make([]string, 0)

	var behav map[string]interface{}
	if err := json.Unmarshal([]byte(behavHeader), &behav); err != nil {
		return nil
	}

	// Try enhanced analysis with the BehavioralAnalyzer if detailed event data is available
	enhanced := sd.tryEnhancedBehavioralAnalysis(behav)
	if enhanced != nil {
		for _, ind := range enhanced.Indicators {
			indicators = append(indicators, ind.Check)
		}
		vec.Score = enhanced.Score
	} else {
		// Fallback: basic checks for legacy format
		if mouseStdDev, ok := behav["mouseStdDev"].(float64); ok && mouseStdDev == 0 {
			indicators = append(indicators, "zero_mouse_variance")
			vec.Score += 0.4
		}
		if typingStdDev, ok := behav["typingStdDev"].(float64); ok && typingStdDev == 0 {
			indicators = append(indicators, "zero_typing_variance")
			vec.Score += 0.3
		}
		if eventTimingDev, ok := behav["eventTimingStdDev"].(float64); ok && eventTimingDev == 0 {
			indicators = append(indicators, "perfect_event_pacing")
			vec.Score += 0.4
		}
		if mouseEvents, ok := behav["mouseEvents"].(float64); ok && mouseEvents < 5 {
			indicators = append(indicators, "too_few_mouse_events")
			vec.Score += 0.2
		}
		if _, ok := behav["mousePathLength"].(float64); ok {
			if straightness, ok := behav["mouseStraightness"].(float64); ok && straightness > 0.95 {
				indicators = append(indicators, "linear_mouse_movement")
				vec.Score += 0.3
			}
		}
	}

	if vec.Score > 1.0 {
		vec.Score = 1.0
	}

	vec.Indicators = indicators
	vec.Detected = vec.Score > 0.3

	return vec
}

// tryEnhancedBehavioralAnalysis attempts to use the BehavioralAnalyzer with
// detailed event data (timestamps, positions, velocities). Returns nil if
// the data format doesn't include these enhanced fields.
func (sd *StealthDetector) tryEnhancedBehavioralAnalysis(behav map[string]interface{}) *VectorResult {
	events := &EnhancedBehavioralEvents{}
	hasEnhanced := false

	// Extract mouse timestamps
	if ts, ok := behav["mouseTimestamps"].([]interface{}); ok && len(ts) > 0 {
		for _, t := range ts {
			if v, ok := t.(float64); ok {
				events.MouseTimestamps = append(events.MouseTimestamps, int64(v))
			}
		}
		hasEnhanced = true
	}

	// Extract typing timestamps
	if ts, ok := behav["typingTimestamps"].([]interface{}); ok && len(ts) > 0 {
		for _, t := range ts {
			if v, ok := t.(float64); ok {
				events.TypingTimestamps = append(events.TypingTimestamps, int64(v))
			}
		}
		hasEnhanced = true
	}

	// Extract mouse positions
	if pos, ok := behav["mousePositions"].([]interface{}); ok && len(pos) > 0 {
		for _, p := range pos {
			if pt, ok := p.(map[string]interface{}); ok {
				x, _ := pt["x"].(float64)
				y, _ := pt["y"].(float64)
				events.MousePositions = append(events.MousePositions, Position{X: x, Y: y})
			}
		}
		hasEnhanced = true
	}

	// Extract mouse velocities
	if vel, ok := behav["mouseVelocities"].([]interface{}); ok && len(vel) > 0 {
		for _, v := range vel {
			if f, ok := v.(float64); ok {
				events.MouseVelocities = append(events.MouseVelocities, f)
			}
		}
		hasEnhanced = true
	}

	// Extract click timestamps
	if ts, ok := behav["clickTimestamps"].([]interface{}); ok && len(ts) > 0 {
		for _, t := range ts {
			if v, ok := t.(float64); ok {
				events.ClickTimestamps = append(events.ClickTimestamps, int64(v))
			}
		}
		hasEnhanced = true
	}

	// Extract click positions
	if pos, ok := behav["clickPositions"].([]interface{}); ok && len(pos) > 0 {
		for _, p := range pos {
			if pt, ok := p.(map[string]interface{}); ok {
				x, _ := pt["x"].(float64)
				y, _ := pt["y"].(float64)
				events.ClickPositions = append(events.ClickPositions, Position{X: x, Y: y})
			}
		}
		hasEnhanced = true
	}

	// Extract scroll deltas
	if deltas, ok := behav["scrollDeltas"].([]interface{}); ok && len(deltas) > 0 {
		for _, d := range deltas {
			if v, ok := d.(float64); ok {
				events.ScrollDeltas = append(events.ScrollDeltas, v)
			}
		}
		hasEnhanced = true
	}

	// Extract scroll timestamps (needed for Check 13: sequential event ordering)
	if ts, ok := behav["scrollTimestamps"].([]interface{}); ok && len(ts) > 0 {
		for _, t := range ts {
			if v, ok := t.(float64); ok {
				events.ScrollTimestamps = append(events.ScrollTimestamps, int64(v))
			}
		}
		hasEnhanced = true
	}

	if !hasEnhanced {
		return nil
	}

	analyzer := NewBehavioralAnalyzer(nil)
	return analyzer.Analyze(events)
}

func (sd *StealthDetector) analyzeIsomorphicAnomalies(req *http.Request, httpInfo *HTTPFingerprintInfo) *DetectionVector {
	if httpInfo == nil {
		return nil
	}

	vec := &DetectionVector{
		Name:        "Isomorphic Cross-Validation",
		Category:    "isomorphic",
		Weight:      0.5, // High penalty for failing isomorphic parity
		Description: "Cross-checks multiple layers (HTTP, Navigator, WebGL) for OS and execution environment parity",
	}

	indicators := make([]string, 0)

	// Get Navigator Data
	var navData map[string]interface{}
	if navHeader := req.Header.Get(constants.HeaderNavigatorData); navHeader != "" {
		_ = json.Unmarshal([]byte(navHeader), &navData)
	}

	// Get Canvas/WebGL Data
	var canvasData map[string]interface{}
	if canvasHeader := req.Header.Get(constants.HeaderCanvasFingerprint); canvasHeader != "" {
		_ = json.Unmarshal([]byte(canvasHeader), &canvasData)
	}

	// Cross-check: Platform vs WebGL Renderer
	httpPlatform := strings.ToLower(httpInfo.Platform)
	if httpInfo.SecCHUAPlatform != "" {
		httpPlatform = strings.ToLower(httpInfo.SecCHUAPlatform)
	}

	if canvasData != nil {
		if unmaskedRenderer, ok := canvasData["unmaskedRenderer"].(string); ok {
			renderer := strings.ToLower(unmaskedRenderer)

			isMac := strings.Contains(httpPlatform, "mac") || strings.Contains(httpPlatform, "darwin")
			isWindows := strings.Contains(httpPlatform, "win")

			// Detect Windows GPU (Direct3D/D3D) on claimed macOS HTTP
			if isMac && (strings.Contains(renderer, "direct3d") || strings.Contains(renderer, "d3d") || strings.Contains(renderer, "angle (nvidia")) {
				if !strings.Contains(renderer, "apple") {
					indicators = append(indicators, "platform_mismatch: macos_http_with_windows_gpu")
					vec.Score += 0.9 // Extremely suspicious Frankenstein bot
				}
			}

			// Detect Apple GPU on claimed Windows HTTP
			if isWindows && (strings.Contains(renderer, "apple m") || strings.Contains(renderer, "apple gpu")) {
				indicators = append(indicators, "platform_mismatch: windows_http_with_apple_gpu")
				vec.Score += 0.9 // Extremely suspicious Frankenstein bot
			}
		}
	}

	// Cross-check: Navigator Platform vs HTTP Platform
	if navData != nil {
		if navPlatform, ok := navData["platform"].(string); ok {
			navPlatLow := strings.ToLower(navPlatform)
			isMacHTTP := strings.Contains(httpPlatform, "mac") || strings.Contains(httpPlatform, "darwin")
			isWinHTTP := strings.Contains(httpPlatform, "win")

			isMacNav := strings.Contains(navPlatLow, "mac")
			isWinNav := strings.Contains(navPlatLow, "win")

			if (isMacHTTP && !isMacNav) || (isWinHTTP && !isWinNav) {
				indicators = append(indicators, "platform_mismatch: http_vs_navigator_platform")
				vec.Score += 0.8
			}
		}

		// Cross-check: Accept-Language HTTP Header vs navigator.languages
		if langs, ok := navData["languages"].([]interface{}); ok {
			if len(langs) > 0 {
				primaryNavLang, _ := langs[0].(string)
				httpLang := strings.ToLower(httpInfo.AcceptLanguage)
				if primaryNavLang != "" {
					primaryNavLang = strings.ToLower(strings.Split(primaryNavLang, "-")[0])
					if httpLang != "" && !strings.Contains(httpLang, primaryNavLang) {
						indicators = append(indicators, "locale_mismatch: http_accept_language_vs_navigator_languages")
						vec.Score += 0.7
					}
				}
			}
		}

		// Cross-check: Deep HTTP Parity (User-Agent vs Sec-Ch-Ua)
		if navUA, ok := navData["userAgent"].(string); ok {
			httpUA := strings.ToLower(httpInfo.UserAgent)
			navUALower := strings.ToLower(navUA)

			if httpUA != "" && httpUA != navUALower {
				indicators = append(indicators, "user_agent_mismatch: http_ua_vs_navigator_ua")
				vec.Score += 0.8
			}

			// If Sec-Ch-Ua says "Google Chrome" but UA says "Firefox"
			secChUa := strings.ToLower(httpInfo.SecCHUA)
			if secChUa != "" {
				if strings.Contains(secChUa, "chrome") && !strings.Contains(httpUA, "chrome") {
					indicators = append(indicators, "brand_mismatch: sec-ch-ua_chrome_vs_ua_non_chrome")
					vec.Score += 0.9
				}
			}
		}

		// Cross-check: Sec-Ch-Ua version vs User-Agent Chrome version.
		// Both should report the same Chrome major version. A mismatch indicates
		// synthetic header generation. Firefox is exempt (no Sec-Ch-Ua).
		if httpInfo.SecCHUA != "" {
			secChUaVersionRe := regexp.MustCompile(`"Google Chrome";v="(\d+)"`)
			uaVersionRe := regexp.MustCompile(`Chrome/(\d+)`)

			secChMatch := secChUaVersionRe.FindStringSubmatch(httpInfo.SecCHUA)
			uaMatch := uaVersionRe.FindStringSubmatch(httpInfo.UserAgent)

			if len(secChMatch) > 1 && len(uaMatch) > 1 {
				if secChMatch[1] != uaMatch[1] {
					indicators = append(indicators, fmt.Sprintf("sec_ch_ua_version_mismatch: Sec-Ch-Ua=%s UA=%s", secChMatch[1], uaMatch[1]))
					vec.Score += 0.40
				}
			}
		}

		// Cross-check: Screen dimensions (X-Screen-Data) vs Navigator screen properties
		// Real browsers derive both from the same window object, so outer_width and
		// screen_outer_width must match. Independent random generation produces mismatches.
		if screenHeader := req.Header.Get(constants.HeaderScreenData); screenHeader != "" {
			var screenData map[string]interface{}
			if json.Unmarshal([]byte(screenHeader), &screenData) == nil {
				if screenOuter, ok := screenData["outer_width"].(float64); ok {
					if navOuter, ok := navData["screen_outer_width"].(float64); ok {
						diff := screenOuter - navOuter
						if diff < 0 {
							diff = -diff
						}
						if diff > 5 {
							indicators = append(indicators, fmt.Sprintf("screen_nav_outer_width_mismatch: screen=%d nav=%d", int(screenOuter), int(navOuter)))
							vec.Score += 0.7
						}
					}
				}
				if screenInner, ok := screenData["inner_width"].(float64); ok {
					if navInner, ok := navData["screen_inner_width"].(float64); ok {
						diff := screenInner - navInner
						if diff < 0 {
							diff = -diff
						}
						if diff > 5 {
							indicators = append(indicators, fmt.Sprintf("screen_nav_inner_width_mismatch: screen=%d nav=%d", int(screenInner), int(navInner)))
							vec.Score += 0.5
						}
					}
				}

				// Cross-check: color_depth in X-Screen-Data vs screen_color_depth in X-Navigator-Data.
				// Real browsers derive both from the same screen object, so they must match.
				if screenColorDepth, ok := screenData["color_depth"].(float64); ok {
					if navColorDepth, ok := navData["screen_color_depth"].(float64); ok {
						if int(screenColorDepth) != int(navColorDepth) {
							indicators = append(indicators, fmt.Sprintf("screen_nav_color_depth_mismatch: screen=%d nav=%d", int(screenColorDepth), int(navColorDepth)))
							vec.Score += 0.65
						}
					}
				}
			}
		}
	}

	vec.Indicators = indicators
	if vec.Score > 1.0 {
		vec.Score = 1.0
	}
	vec.Detected = vec.Score > 0.0

	return vec
}

func (sd *StealthDetector) analyzeHardwareExecution(req *http.Request) *DetectionVector {
	navHeader := req.Header.Get(constants.HeaderNavigatorData)
	if navHeader == "" {
		return nil
	}

	vec := &DetectionVector{
		Name:        "Hardware Execution Fingerprinting",
		Category:    "hardware",
		Weight:      0.4,
		Description: "Analyzes navigator hardware properties for impossible configurations",
	}

	var navData map[string]interface{}
	if err := json.Unmarshal([]byte(navHeader), &navData); err != nil {
		return nil
	}

	indicators := make([]string, 0)

	// Cross-check: hardwareConcurrency vs deviceMemory
	cores, okCores := navData["hardwareConcurrency"].(float64)
	memory, okMem := navData["deviceMemory"].(float64)

	if okCores && okMem {
		// E.g., 16+ cores but only 0, 1, or 2GB of RAM is an impossible modern configuration
		if cores >= 16 && memory <= 2 {
			indicators = append(indicators, "impossible_hardware: high_concurrency_low_memory")
			vec.Score += 0.8
		}

		// Unusually low memory for desktop browsers
		if memory <= 0 {
			indicators = append(indicators, "impossible_hardware: zero_memory")
			vec.Score += 0.5
		}
	}

	vec.Indicators = indicators
	vec.Detected = vec.Score > 0.0

	return vec
}

func (sd *StealthDetector) detectStealthBrowser(detection *StealthDetection) bool {
	stealthIndicators := 0

	for _, vec := range detection.Vectors {
		// Check for specific stealth browser patterns
		for _, ind := range vec.Indicators {
			stealthPatterns := []string{
				"webdriver=true",
				"missing_chrome_runtime",
				"canvas_randomization",
				"zero_mouse_variance",
				"zero_typing_variance",
				"linear_mouse_movement",
				"inconsistent_client_hints",
			}

			for _, pattern := range stealthPatterns {
				if strings.Contains(ind, pattern) {
					stealthIndicators++
				}
			}
		}
	}

	// Multiple stealth indicators = likely our browser
	return stealthIndicators >= 2
}

// GetDetections returns a copy of all detection records collected by the detector.
func (sd *StealthDetector) GetDetections() []StealthDetection {
	sd.mu.RLock()
	defer sd.mu.RUnlock()
	return sd.detections
}

// AddDetection adds a new detection record to the detector's history.
func (sd *StealthDetector) AddDetection(detection StealthDetection) {
	sd.mu.Lock()
	defer sd.mu.Unlock()
	sd.detections = append(sd.detections, detection)
}

func extractPlatform(ua string) string {
	if strings.Contains(ua, "Windows") {
		return "Windows"
	}
	if strings.Contains(ua, "Mac") {
		return "macOS"
	}
	if strings.Contains(ua, "Linux") {
		return "Linux"
	}
	if strings.Contains(ua, "Android") {
		return "Android"
	}
	if strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPad") {
		return "iOS"
	}
	return "Unknown"
}

func extractBrowserVersion(ua string) string {
	re := regexp.MustCompile(`Chrome/(\d+)`)
	matches := re.FindStringSubmatch(ua)
	if len(matches) > 1 {
		return matches[1]
	}
	re = regexp.MustCompile(`Firefox/(\d+)`)
	matches = re.FindStringSubmatch(ua)
	if len(matches) > 1 {
		return matches[1]
	}
	re = regexp.MustCompile(`Safari/(\d+)`)
	matches = re.FindStringSubmatch(ua)
	if len(matches) > 1 {
		return matches[1]
	}
	return "Unknown"
}

// hasJSFingerprintHeaders returns true if the request contains at least one
// X-* fingerprint header that proves the client has a JS execution context.
// Used to gate missing-data penalties: if a client sends some JS-sourced
// fingerprint data but omits others (e.g. behavioral, timing), that's suspicious.
// Pure HTTP clients (like curl-impersonate) that send zero X-* headers won't
// trigger these penalties.
// analyzeFingerprintCoverage uses graduated scoring based on JS fingerprint header coverage.
// - 0 headers with Client Hints → 0.50 (HTTP impersonation, e.g., curl-impersonate)
// - 1-5 headers → 0.30 * (1 - ratio) (partial: cherry-picked headers)
// - 6-9 headers → 0.00 (normal partial coverage)
// - All 10 headers → 0.10 (suspiciously complete — real pages rarely collect all 10
//   on first load; WebRTC needs permission, Audio needs AudioContext)
func (sd *StealthDetector) analyzeFingerprintCoverage(req *http.Request) *DetectionVector {
	secChUa := req.Header.Get("Sec-Ch-Ua")
	if secChUa == "" {
		return nil
	}

	allJSHeaders := []string{
		constants.HeaderNavigatorData,
		constants.HeaderWebGLData,
		constants.HeaderPluginData,
		constants.HeaderScreenData,
		constants.HeaderFontData,
		constants.HeaderWebRTCData,
		constants.HeaderBehavioralData,
		constants.HeaderTimingData,
		constants.HeaderAudioData,
		constants.HeaderCanvasFingerprint,
	}

	presentCount := 0
	for _, h := range allJSHeaders {
		if req.Header.Get(h) != "" {
			presentCount++
		}
	}

	totalHeaders := len(allJSHeaders)
	vec := &DetectionVector{
		Name:        "Fingerprint Coverage",
		Category:    string(VectorFingerprintCoverage),
		Weight:      1.0,
		Description: "Graduated fingerprint header coverage analysis",
		Indicators:  make([]string, 0),
	}

	switch {
	case presentCount == 0:
		// Pure HTTP impersonator — no JS context at all
		vec.Score = 0.50
		vec.Detected = true
		vec.Indicators = append(vec.Indicators, "http_impersonation_no_js_context")

	case presentCount <= 5:
		// Partial coverage — some cherry-picked headers
		ratio := float64(presentCount) / float64(totalHeaders)
		vec.Score = 0.30 * (1.0 - ratio)
		vec.Detected = vec.Score > 0.15
		vec.Indicators = append(vec.Indicators, fmt.Sprintf("partial_js_coverage_%d_of_%d", presentCount, totalHeaders))

	case presentCount == totalHeaders:
		// Suspiciously complete — real pages rarely collect all 10 simultaneously.
		// WebRTC needs getUserMedia permission, Audio needs AudioContext creation,
		// Canvas needs explicit toDataURL call — unlikely all on first page load.
		vec.Score = 0.10
		vec.Detected = false
		vec.Indicators = append(vec.Indicators, "suspiciously_complete_js_coverage")

	default:
		// 6-9 headers = normal partial coverage
		return nil
	}

	return vec
}

// analyzeCrossVectorConsistency checks temporal and spatial consistency between
// independently generated fingerprint vectors. Two sub-checks:
// 1. Behavioral timestamps should start AFTER page load completion (from timing data).
// 2. Mouse positions should be within the claimed screen dimensions.
func (sd *StealthDetector) analyzeCrossVectorConsistency(req *http.Request) *DetectionVector {
	vec := &DetectionVector{
		Name:        "Cross-Vector Consistency",
		Category:    string(VectorCrossVector),
		Weight:      1.0,
		Description: "Temporal and spatial consistency between independent fingerprint vectors",
		Indicators:  make([]string, 0),
	}

	// Sub-check 1: Behavioral timestamps vs page load timing.
	// In a real browser, user events START AFTER the page loads.
	// The sword generates behavioral timestamps from 0, which precede page load.
	behavHeader := req.Header.Get(constants.HeaderBehavioralData)
	timingHeader := req.Header.Get(constants.HeaderTimingData)

	if behavHeader != "" && timingHeader != "" {
		var behav map[string]interface{}
		var timing map[string]interface{}

		if err := json.Unmarshal([]byte(behavHeader), &behav); err == nil {
			if err := json.Unmarshal([]byte(timingHeader), &timing); err == nil {
				// Get earliest behavioral timestamp
				earliestBehavTs := int64(-1)
				if mouseTs, ok := behav["mouseTimestamps"].([]interface{}); ok && len(mouseTs) > 0 {
					if v, ok := mouseTs[0].(float64); ok {
						earliestBehavTs = int64(v)
					}
				}

				// Get page load completion time from timing data.
				// Look for loadEventEnd in the timing entries.
				pageLoadEnd := int64(0)
				if entries, ok := timing["entries"].([]interface{}); ok {
					for _, entry := range entries {
						if e, ok := entry.(map[string]interface{}); ok {
							if end, ok := e["responseEnd"].(float64); ok {
								if int64(end) > pageLoadEnd {
									pageLoadEnd = int64(end)
								}
							}
						}
					}
				}
				// Also check top-level loadEventEnd
				if le, ok := timing["loadEventEnd"].(float64); ok && int64(le) > pageLoadEnd {
					pageLoadEnd = int64(le)
				}

				// If behavioral timestamps start before or at 0, or before page load end,
				// this is a strong signal of synthetic generation.
				if earliestBehavTs >= 0 && earliestBehavTs < 1_000_000_000_000 {
					vec.Score += 0.35
					vec.Indicators = append(vec.Indicators, fmt.Sprintf(
						"behavioral_before_epoch: first_mouse_ts=%d (sub-epoch)", earliestBehavTs))
				} else if pageLoadEnd > 0 && earliestBehavTs >= 0 && earliestBehavTs < pageLoadEnd {
					vec.Score += 0.35
					vec.Indicators = append(vec.Indicators, fmt.Sprintf(
						"behavioral_before_page_load: mouse_start=%d < page_load_end=%d", earliestBehavTs, pageLoadEnd))
				}
			}
		}
	}

	// Sub-check 2: Mouse positions vs claimed screen dimensions.
	if behavHeader != "" {
		screenHeader := req.Header.Get(constants.HeaderScreenData)
		if screenHeader != "" {
			var behav map[string]interface{}
			var screen map[string]interface{}

			if err := json.Unmarshal([]byte(behavHeader), &behav); err == nil {
				if err := json.Unmarshal([]byte(screenHeader), &screen); err == nil {
					screenW := 0.0
					screenH := 0.0
					if w, ok := screen["width"].(float64); ok {
						screenW = w
					}
					if h, ok := screen["height"].(float64); ok {
						screenH = h
					}

					if screenW > 0 && screenH > 0 {
						if positions, ok := behav["mousePositions"].([]interface{}); ok {
							for _, p := range positions {
								if pt, ok := p.(map[string]interface{}); ok {
									x, _ := pt["x"].(float64)
									y, _ := pt["y"].(float64)
									if x > screenW || y > screenH || x < 0 || y < 0 {
										vec.Score += 0.30
										vec.Indicators = append(vec.Indicators, fmt.Sprintf(
											"mouse_outside_viewport: pos(%.0f,%.0f) exceeds screen(%v×%v)",
											x, y, screenW, screenH))
										break // One violation is enough
									}
								}
							}
						}
					}
				}
			}
		}
	}

	if vec.Score == 0 {
		return nil
	}

	if vec.Score > 1.0 {
		vec.Score = 1.0
	}
	vec.Detected = vec.Score > 0.25

	return vec
}

func hasJSFingerprintHeaders(req *http.Request) bool {
	jsHeaders := []string{
		constants.HeaderNavigatorData,
		constants.HeaderWebGLData,
		constants.HeaderPluginData,
		constants.HeaderScreenData,
		constants.HeaderFontData,
		constants.HeaderWebRTCData,
	}
	for _, h := range jsHeaders {
		if req.Header.Get(h) != "" {
			return true
		}
	}
	return false
}

func getClientIP(req *http.Request) string {
	// Check for forwarded headers
	if forwarded := req.Header.Get("X-Forwarded-For"); forwarded != "" {
		return strings.Split(forwarded, ",")[0]
	}
	if realIP := req.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}
	// Fall back to remote addr
	if idx := strings.LastIndex(req.RemoteAddr, ":"); idx > 0 {
		return req.RemoteAddr[:idx]
	}
	return req.RemoteAddr
}

// AdvancedStealthServer combines a StealthDetector with a TestServer to provide
// HTTP request handling with integrated stealth detection capabilities.
type AdvancedStealthServer struct {
	*StealthDetector

	Server               *TestServer
	CaptchaShield        *CaptchaShield
	Tracer               *CaptchaTracer
	RecaptchaWidget      *ReCaptchaWidget
	CloudflareChallenger *CloudflareChallenger

	// CaptchaMode controls which captcha flow HandleRequest uses for suspicious
	// requests (score 0.20–0.60). Values: "recaptcha_v2" (default), "inline".
	CaptchaMode string

	// Session tokens for post-captcha-solve access
	captchaSecret []byte
	solvedTokens  map[string]time.Time // token -> expiry
	tokenMu       sync.RWMutex

	// V3 assessment ring buffer
	v3Assessments   []*V3AssessmentRecord
	v3AssessmentsMu sync.RWMutex
	v3MaxRecords    int
	OnV3Assessment  func(record *V3AssessmentRecord) // callback for WebSocket broadcast
}

// NewAdvancedStealthServer creates and initializes a new AdvancedStealthServer
// with default detector and test server configurations.
func NewAdvancedStealthServer() *AdvancedStealthServer {
	detector := NewStealthDetector()
	testServer := NewTestServer()
	tracer := NewCaptchaTracer()

	// Generate a random secret for HMAC tokens
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(time.Now().UnixNano()>>uint(i*8)) ^ byte(i*37+13) //nolint:gosec,mnd
	}

	shield := NewCaptchaShield(nil, nil, tracer)
	widget := NewReCaptchaWidget(shield)
	cfChallenger := NewCloudflareChallenger(tracer, nil)

	as := &AdvancedStealthServer{
		StealthDetector:      detector,
		Server:               testServer,
		CaptchaShield:        shield,
		Tracer:               tracer,
		RecaptchaWidget:      widget,
		CloudflareChallenger: cfChallenger,
		CaptchaMode:          "recaptcha_v2",
		captchaSecret:   secret,
		solvedTokens:    make(map[string]time.Time),
		v3Assessments:   make([]*V3AssessmentRecord, 0, 100),
		v3MaxRecords:    100,
	}

	// Bridge reCAPTCHA v2 tokens into the server's solvedTokens so that
	// HandleRequest's validateCaptchaToken recognizes v2-issued tokens.
	widget.SetTokenCallback(func(token string, expiry time.Time) {
		as.tokenMu.Lock()
		as.solvedTokens[token] = expiry
		as.tokenMu.Unlock()
	})

	return as
}

// generateCaptchaToken creates an HMAC-SHA256 session token for post-solve access.
func (as *AdvancedStealthServer) generateCaptchaToken(challengeID string) (string, string) {
	expiry := time.Now().Add(5 * time.Minute)
	data := fmt.Sprintf("%s|%d", challengeID, expiry.UnixMilli())

	mac := hmac.New(sha256.New, as.captchaSecret)
	mac.Write([]byte(data))
	token := base64.URLEncoding.EncodeToString(mac.Sum(nil))

	as.tokenMu.Lock()
	as.solvedTokens[token] = expiry
	as.tokenMu.Unlock()

	return token, expiry.Format(time.RFC3339)
}

// validateCaptchaToken checks if a token is valid and not expired.
func (as *AdvancedStealthServer) validateCaptchaToken(token string) bool {
	if token == "" {
		return false
	}
	as.tokenMu.RLock()
	expiry, ok := as.solvedTokens[token]
	as.tokenMu.RUnlock()

	if !ok {
		return false
	}
	return time.Now().Before(expiry)
}

// storeV3Assessment appends a record to the ring buffer, evicting the oldest if at capacity.
func (as *AdvancedStealthServer) storeV3Assessment(record *V3AssessmentRecord) {
	as.v3AssessmentsMu.Lock()
	defer as.v3AssessmentsMu.Unlock()
	if len(as.v3Assessments) >= as.v3MaxRecords {
		as.v3Assessments = as.v3Assessments[1:]
	}
	as.v3Assessments = append(as.v3Assessments, record)
}

// GetV3Assessments returns a copy of the v3 assessment ring buffer.
func (as *AdvancedStealthServer) GetV3Assessments() []*V3AssessmentRecord {
	as.v3AssessmentsMu.RLock()
	defer as.v3AssessmentsMu.RUnlock()
	out := make([]*V3AssessmentRecord, len(as.v3Assessments))
	copy(out, as.v3Assessments)
	return out
}

// selectCaptchaTypeFromScore selects the CAPTCHA type based on the WAF detection score.
func selectCaptchaTypeFromScore(score float64) string {
	switch {
	case score >= 0.80:
		return "cloudflare_managed"
	case score >= 0.60:
		return "cloudflare_js"
	case score >= 0.35:
		return "hcaptcha"
	default:
		return "text"
	}
}

// HandleCaptchaVerify verifies a submitted CAPTCHA solution.
func (as *AdvancedStealthServer) HandleCaptchaVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ChallengeID string         `json:"challenge_id"`
		Solution    string         `json:"solution"`
		Answer      string         `json:"answer"` // Keep for backward compatibility
		IsExpert    bool           `json:"is_expert"`
		Events      []CaptchaEvent `json:"events"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	// Support both naming conventions
	solution := req.Solution
	if solution == "" {
		solution = req.Answer
	}

	// Add events to tracer if provided
	if len(req.Events) > 0 {
		for _, ev := range req.Events {
			_ = as.CaptchaShield.RecordEvent(req.ChallengeID, ev)
		}
	}

	solved, metrics := as.CaptchaShield.ValidateChallenge(req.ChallengeID, solution)

	botScore := 0.0
	var behavioralBreakdown map[string]interface{}
	trace, _ := as.CaptchaShield.tracer.GetTrace(req.ChallengeID)
	if trace != nil {
		var analysisResult *VectorResult
		botScore, analysisResult = as.CaptchaShield.tracer.CalculateBotScoreDetailed(trace)

		// Build behavioral breakdown for observability
		behavioralBreakdown = map[string]interface{}{
			"analyzer_score":  analysisResult.Score,
			"checks_detected": analysisResult.Detected,
		}
		for _, ind := range analysisResult.Indicators {
			behavioralBreakdown[ind.Check] = ind.Value
		}

		log.Printf("CAPTCHA_SOLVE_METRICS challenge_id=%s correct=%v bot_score=%.2f solve_time_ms=%d indicators=%d",
			req.ChallengeID, solved, botScore, metrics.SolveTimeMs, len(analysisResult.Indicators))
		for _, ind := range analysisResult.Indicators {
			log.Printf("  %s=%s (weight=%.2f)", ind.Check, ind.Value, ind.Weight)
		}
	}

	mlFeatures := map[string]float64{
		"mouse_velocity": 0,
		"typing_speed":   0,
	}
	if trace != nil && trace.Metrics != nil {
		mlFeatures["mouse_velocity"] = trace.Metrics.MouseVelocity
		mlFeatures["typing_speed"] = trace.Metrics.TypingSpeed
	}

	// If the answer is correct but the behavioral bot score is too high, reject
	if solved && botScore >= 0.5 {
		solved = false
	}

	w.Header().Set("Content-Type", "application/json")

	// Generate session token on successful solve
	var captchaToken string
	var tokenExpiresAt string
	if solved && as.captchaSecret != nil {
		captchaToken, tokenExpiresAt = as.generateCaptchaToken(req.ChallengeID)
	}

	// For expert training tracks, we always return 200 even if solve failed
	// so the UI can show the analysis.
	if req.IsExpert {
		w.WriteHeader(http.StatusOK)
		//nolint:errchkjson // Dynamic response requires interface{}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"solved":               solved,
			"message":              "Expert track recorded",
			"solve_time_ms":        metrics.SolveTimeMs,
			"attempts":             metrics.AttemptCount,
			"bot_score":            botScore,
			"ml_features":          mlFeatures,
			"behavioral_breakdown": behavioralBreakdown,
		})
		return
	}

	if solved {
		resp := map[string]interface{}{
			"solved":        true,
			"message":       "CAPTCHA solved successfully",
			"solve_time_ms": metrics.SolveTimeMs,
			"attempts":      metrics.AttemptCount,
			"bot_score":     botScore,
		}
		if captchaToken != "" {
			resp["captcha_token"] = captchaToken
			resp["token_expires_at"] = tokenExpiresAt
		}
		if behavioralBreakdown != nil {
			resp["behavioral_breakdown"] = behavioralBreakdown
		}
		w.WriteHeader(http.StatusOK)
		//nolint:errchkjson // Dynamic response requires interface{}
		_ = json.NewEncoder(w).Encode(resp)
	} else {
		resp := map[string]interface{}{
			"solved":  false,
			"message": "Incorrect CAPTCHA solution",
		}
		if behavioralBreakdown != nil {
			resp["bot_score"] = botScore
			resp["behavioral_breakdown"] = behavioralBreakdown
		}
		w.WriteHeader(http.StatusForbidden)
		//nolint:errchkjson // Dynamic response requires interface{}
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// HandleRequest processes an HTTP request through stealth detection and returns
// the detection results as JSON with appropriate HTTP status codes.
func (as *AdvancedStealthServer) HandleRequest(w http.ResponseWriter, r *http.Request) {
	var tlsConn *tls.ConnectionState
	if r.TLS != nil {
		tlsConn = r.TLS
	}

	detection := as.AnalyzeRequest(r, tlsConn)

	// Check for valid captcha session token — reduce effective score
	captchaToken := r.Header.Get("X-Captcha-Token")
	if as.validateCaptchaToken(captchaToken) {
		detection.Score -= 0.15
		if detection.Score < 0 {
			detection.Score = 0
		}
		detection.IsBot = detection.Score > 0.60
	}

	// Add detection to test server's records
	as.Server.mu.Lock()
	record := DetectionRecord{
		Timestamp:  detection.Timestamp,
		RequestID:  detection.RequestID,
		IsBot:      detection.IsBot,
		Score:      detection.Score,
		Indicators: make([]Indicator, 0),
	}
	for _, ind := range detection.Indicators {
		record.Indicators = append(record.Indicators, Indicator{
			Category: ind.Vector,
			Name:     ind.Name,
			Severity: ind.Severity,
			Message:  ind.Message,
		})
	}
	as.Server.Detections = append(as.Server.Detections, record)
	as.Server.mu.Unlock()

	// Return detection results
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Bot-Score", fmt.Sprintf("%.2f", detection.Score))
	w.Header().Set("X-Is-Bot", fmt.Sprintf("%v", detection.IsBot))
	w.Header().Set("X-Is-Stealth", fmt.Sprintf("%v", detection.IsStealth))

	response := map[string]interface{}{
		"request_id": detection.RequestID,
		"is_bot":     detection.IsBot,
		"is_stealth": detection.IsStealth,
		"score":      detection.Score,
		"confidence": detection.Confidence,
		"vectors":    detection.Vectors,
		"indicators": detection.Indicators,
	}

	// Phase 17: Graduated CAPTCHA response based on bot score
	const captchaThresholdLow = 0.20
	const captchaThresholdHigh = 0.60

	if detection.Score > captchaThresholdHigh && detection.IsBot {
		// Hard block — confirmed bot with very high score
		response["detection_type"] = "blocked"
		response["message"] = "Bot detected"
		w.Header().Set("X-Datadome", "1")
		w.WriteHeader(http.StatusForbidden)
	} else if detection.Score > captchaThresholdLow {
		// Suspicious — issue CAPTCHA challenge. Mode selects the flow.
		captchaMode := as.CaptchaMode
		if captchaMode == "" {
			captchaMode = "recaptcha_v2"
		}

		switch captchaMode {
		case "recaptcha_v2":
			// Redirect client to the reCAPTCHA v2 widget flow (init → checkbox → verify).
			// No inline captcha image; the client follows the 5-step v2 API.
			response["detection_type"] = "recaptcha_v2"
			response["init_url"] = "/api/recaptcha/init"
			response["site_key"] = as.RecaptchaWidget.GetSiteKey()
			response["message"] = "reCAPTCHA v2 challenge required"
			log.Printf("RECAPTCHA_V2_REDIRECT score=%.2f request_id=%s", detection.Score, detection.RequestID)
			w.Header().Set("X-Captcha-Required", "1")
			w.Header().Set("X-Captcha-Type", "recaptcha-v2")
			w.WriteHeader(http.StatusOK)

		default: // "inline" — preserve the original CreateChallenge inline behavior
			captchaType := selectCaptchaTypeFromScore(detection.Score)
			challenge, err := as.CaptchaShield.CreateChallenge(detection.RequestID, nil, captchaType)
			if err != nil {
				log.Printf("CAPTCHA_GENERATION_FAILED: %v", err)
				w.WriteHeader(http.StatusOK)
			} else {
				response["detection_type"] = "captcha"
				challengeData := make(map[string]interface{})
				for k, v := range challenge.Challenge {
					if k != "text" {
						challengeData[k] = v
					}
				}
				response["captcha"] = map[string]interface{}{
					"challenge_id":   challenge.ID,
					"type":           challenge.Type,
					"captcha_id":     challenge.CaptchaID,
					"challenge_data": challengeData,
				}
				response["message"] = "CAPTCHA challenge required"
				log.Printf("CAPTCHA_CHALLENGE_ISSUED type=%s challenge_id=%s score=%.2f", challenge.Type, challenge.ID, detection.Score)
				w.Header().Set("X-Captcha-Required", "1")
				w.Header().Set("X-Captcha-Type", challenge.Type)
				w.Header().Set("X-Captcha-Id", challenge.ID)
				w.WriteHeader(http.StatusOK)
			}
		}
	} else {
		// Clean pass
		w.WriteHeader(http.StatusOK)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, `{"error": "encode failed"}`, http.StatusInternalServerError)
	}
}

func (sd *StealthDetector) tlsInfoToVector(info *TLSFingerprintInfo) DetectionVector {
	vec := DetectionVector{
		Name:        "TLS Fingerprint",
		Category:    "tls",
		Weight:      constants.WeightTLS,
		Description: "Analyzes TLS handshake for browser identification",
		Indicators:  info.Anomalies,
	}

	if len(info.Anomalies) > 0 {
		vec.Score = 0.3
		vec.Detected = true
	}

	return vec
}

func (sd *StealthDetector) httpInfoToVector(info *HTTPFingerprintInfo) DetectionVector {
	vec := DetectionVector{
		Name:        "HTTP Headers",
		Category:    "http",
		Weight:      constants.WeightHTTP,
		Description: "Analyzes HTTP headers for browser fingerprint consistency",
	}

	indicators := make([]string, 0)
	indicators = append(indicators, info.MissingHeaders...)
	indicators = append(indicators, info.SuspiciousHeaders...)
	vec.Indicators = indicators

	// Score missing headers
	vec.Score = float64(len(info.MissingHeaders)) * constants.SeverityLow

	// Score suspicious headers with severity-based weights
	for _, s := range info.SuspiciousHeaders {
		switch {
		case strings.HasPrefix(s, "suspicious_ua_"):
			vec.Score += constants.SeverityHigh // 0.35 — strong bot signal
		case s == "missing_user_agent":
			vec.Score += constants.SeverityHigh
		case s == "webdriver_exposed":
			vec.Score += constants.SeverityHigh
		case s == "too_few_headers":
			vec.Score += constants.SeverityMedium // 0.25
		case s == "generic_accept_header":
			vec.Score += constants.SeverityLow // 0.15
		default:
			vec.Score += 0.2
		}
	}

	if vec.Score > 1.0 {
		vec.Score = 1.0
	}

	vec.Detected = vec.Score > 0.3

	return vec
}

//nolint:unused
var chromeHeaderOrder = []string{
	":method", ":authority", ":path", "accept", "accept-encoding",
	"accept-language", "cache-control", "content-type", "content-length",
	"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
	"sec-ch-ua-arch", "sec-ch-ua-bitness", "sec-ch-ua-full-version",
	"sec-ch-ua-model", "sec-ch-ua-platform-version", "sec-ch-ua-wow64",
	"sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
	"upgrade-insecure-requests", "user-agent",
}

//nolint:unused
var goHeaderOrder = []string{
	"accept-encoding", "user-agent", "accept",
}

//nolint:unused
var automationScriptPatterns = []string{
	"window.cdc_adoQpoas",
	"window.selendroid",
	"window.__webdriver",
	"window.__selenium_unwrapped",
	"navigator.webdriver",
	"navigator.__webdriver_script",
	"_selenium",
	"callSelenium",
	"_Selenium_IDE_Recorder",
	"__webdriver_script_fn",
}

//nolint:unused
func (sd *StealthDetector) analyzeHeaderOrder(req *http.Request) *DetectionVector {
	vec := &DetectionVector{
		Name:        "Header Order",
		Category:    "http_order",
		Weight:      constants.WeightTLS,
		Description: "Analyzes HTTP header ordering for browser fingerprint",
	}

	order := make([]string, 0)
	for k := range req.Header {
		order = append(order, strings.ToLower(k))
	}

	// Score based on deviation from Chrome order
	score := 0.0
	indicators := make([]string, 0)

	// Check for Go's typical header order (very short)
	if len(order) < 5 {
		score += 0.4
		indicators = append(indicators, "too_few_headers")
	}

	// Check if order matches Go's typical order
	isGoOrder := false
	for _, goHeader := range goHeaderOrder {
		if len(order) > 0 && strings.Contains(order[0], goHeader) {
			isGoOrder = true
			break
		}
	}

	if isGoOrder {
		score += 0.5
		indicators = append(indicators, "go_header_order")
	}

	// Check for Chrome-specific headers missing
	missingChromeHeaders := 0
	for _, ch := range []string{"sec-ch-ua", "sec-fetch-dest", "upgrade-insecure-requests"} {
		found := false
		for _, h := range order {
			if strings.Contains(h, ch) {
				found = true
				break
			}
		}
		if !found {
			missingChromeHeaders++
		}
	}

	if missingChromeHeaders > 1 {
		score += 0.2 * float64(missingChromeHeaders)
		indicators = append(indicators, "missing_chrome_headers")
	}

	vec.Score = score
	vec.Detected = score > 0.2
	vec.Indicators = indicators

	return vec
}

//nolint:unused
func (sd *StealthDetector) analyzeAutomationScripts(req *http.Request) *DetectionVector {
	vec := &DetectionVector{
		Name:        "Automation Scripts",
		Category:    "automation_scripts",
		Weight:      0.2,
		Description: "Detects automation framework scripts and injection patterns",
	}

	indicators := make([]string, 0)
	score := 0.0

	// Check navigator data for automation patterns
	navHeader := req.Header.Get(constants.HeaderNavigatorData)
	if navHeader != "" {
		var navData map[string]interface{}
		if err := json.Unmarshal([]byte(navHeader), &navData); err == nil {
			// Check for common automation script globals
			for _, pattern := range automationScriptPatterns {
				if _, ok := navData[pattern]; ok {
					indicators = append(indicators, fmt.Sprintf("automation_script:%s", pattern))
					score += 0.5
				}
			}

			// Check for webdriver
			if v, ok := navData["webdriver"].(bool); ok && v {
				indicators = append(indicators, "webdriver_flag")
				score += 0.6
			}

			// Check for puppeteer specific
			if v, ok := navData["puppeteer"].(bool); ok && v {
				indicators = append(indicators, "puppeteer_detected")
				score += 0.7
			}

			// Check for CDP
			if v, ok := navData["__ CDP_CONNECTION"].(bool); ok && v {
				indicators = append(indicators, "cdp_connection")
				score += 0.5
			}
		}
	}

	// Check User-Agent for automation keywords
	ua := req.Header.Get("User-Agent")
	if ua != "" {
		uaLower := strings.ToLower(ua)
		automationUA := []string{"selenium", "webdriver", "puppeteer", "playwright", "chromedriver", "geckodriver"}
		for _, a := range automationUA {
			if strings.Contains(uaLower, a) {
				indicators = append(indicators, fmt.Sprintf("ua_contains:%s", a))
				score += 0.4
			}
		}
	}

	// Check for missing typical browser properties
	navHeader2 := req.Header.Get("X-Navigator-Data")
	if navHeader2 != "" {
		var navData map[string]interface{}
		if err := json.Unmarshal([]byte(navHeader2), &navData); err == nil {
			// Count navigator properties
			propCount := len(navData)
			if propCount < 12 {
				indicators = append(indicators, fmt.Sprintf("few_navigator_props:%d", propCount))
				score += 0.2
			}

			// Check for chrome runtime (should exist in real Chrome)
			if _, ok := navData["chrome"]; !ok {
				indicators = append(indicators, "missing_chrome_runtime")
				score += 0.3
			}

			// Check for plugins (should have some in real browser)
			if plugins, ok := navData["plugins"].([]interface{}); ok && len(plugins) == 0 {
				indicators = append(indicators, "zero_plugins")
				score += 0.2
			}
		}
	}

	vec.Score = score
	vec.Detected = score > 0.2
	vec.Indicators = indicators

	return vec
}

//nolint:unused
func (sd *StealthDetector) analyzeGenericFingerprint(req *http.Request) *DetectionVector {
	vec := &DetectionVector{
		Name:        "Generic Fingerprint",
		Category:    "generic_fp",
		Weight:      0.2,
		Description: "Detects generic/constant fingerprint patterns typical of spoofing",
	}

	indicators := make([]string, 0)
	score := 0.0

	// Check canvas fingerprinting
	canvasHeader := req.Header.Get(constants.HeaderCanvasFingerprint)
	if canvasHeader != "" {
		if strings.Contains(canvasHeader, "randomized") || strings.Contains(canvasHeader, "noise") {
			indicators = append(indicators, "canvas_noise")
			score += 0.4
		}
		if strings.Contains(canvasHeader, "hash:") {
			// Check for suspicious constant hashes
			indicators = append(indicators, "canvas_hash_detected")
			score += 0.2
		}
	}

	// Check behavioral patterns
	behavHeader := req.Header.Get(constants.HeaderBehavioralData)
	if behavHeader != "" {
		var behav map[string]interface{}
		if err := json.Unmarshal([]byte(behavHeader), &behav); err == nil {
			// Check for zero variance
			if v, ok := behav["mouseStdDev"].(float64); ok && v == 0 {
				indicators = append(indicators, "zero_mouse_variance")
				score += 0.4
			}
			if v, ok := behav["typingStdDev"].(float64); ok && v == 0 {
				indicators = append(indicators, "zero_typing_variance")
				score += 0.3
			}
			// Check for perfect linearity
			if v, ok := behav["mouseStraightness"].(float64); ok && v > 0.95 {
				indicators = append(indicators, "perfect_linear_movement")
				score += 0.3
			}
			// Check for suspiciously low event counts
			if v, ok := behav["mouseEvents"].(float64); ok && v < 3 {
				indicators = append(indicators, "too_few_events")
				score += 0.2
			}
		}
	}

	// Check timing anomalies
	timingHeader := req.Header.Get(constants.HeaderTimingData)
	if timingHeader != "" {
		var timing map[string]interface{}
		if err := json.Unmarshal([]byte(timingHeader), &timing); err == nil {
			if v, ok := timing["ttfb"].(float64); ok && v == 0 {
				indicators = append(indicators, "zero_ttfb")
				score += 0.3
			}
		}
	}

	// Check for generic spoofing patterns (multiple techniques)
	spoofCount := 0
	if canvasHeader != "" {
		spoofCount++
	}
	if behavHeader != "" {
		spoofCount++
	}
	if timingHeader != "" {
		spoofCount++
	}

	if spoofCount >= 2 {
		indicators = append(indicators, "multiple_spoofing_techniques")
		score += 0.2
	}

	vec.Score = score
	vec.Detected = score > 0.2
	vec.Indicators = indicators

	return vec
}

//nolint:unused
func (sd *StealthDetector) detectOurStealthBrowser(detection *StealthDetection) bool {
	stealthScore := 0.0
	reasons := make([]string, 0)

	for _, vec := range detection.Vectors {
		switch vec.Name {
		case "Navigator Properties":
			if strings.Contains(strings.Join(vec.Indicators, ","), "webdriver") {
				stealthScore += 0.4
				_ = append(reasons, "webdriver_flag")
			}
		case "Behavioral Patterns":
			if strings.Contains(strings.Join(vec.Indicators, ","), "zero") {
				stealthScore += 0.4
				_ = append(reasons, "zero_variance")
			}
		case "Canvas/WebGL Fingerprint":
			if strings.Contains(strings.Join(vec.Indicators, ","), "random") {
				stealthScore += 0.3
				_ = append(reasons, "canvas_randomization")
			}
		case "HTTP Headers":
			if len(vec.Indicators) > 2 {
				stealthScore += 0.2
				reasons = append(reasons, "multiple_header_issues")
			}
		}
	}

	return stealthScore >= 0.5
}
