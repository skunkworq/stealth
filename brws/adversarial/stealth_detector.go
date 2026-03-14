package adversarial

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/skunkworq/stealth/brws/constants"
)

// StealthDetector analyzes HTTP requests to detect stealth browser automation
// by examining TLS fingerprints, HTTP headers, navigator properties, canvas fingerprints,
// timing patterns, and behavioral biometrics.
type StealthDetector struct {
	mu               sync.RWMutex
	detections       []StealthDetection
	baselines        map[string]*StealthBaseline
	config           *DetectorConfig
	adaptiveScorer   *AdaptiveScorer
	advancedDet      *AdvancedDetection
	navAnalyzer      *NavigatorAnalyzer
	isoAnalyzer      *IsomorphicAnalyzer
	behavAnalyzer    *BehavioralAnalyzer
	timingAnalyzer   *TimingAnalyzer
	graphicsAnalyzer *GraphicsAnalyzer
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
		adaptiveScorer:   NewAdaptiveScorer(nil),
		advancedDet:      NewAdvancedDetection(),
		navAnalyzer:      NewNavigatorAnalyzer(),
		isoAnalyzer:      NewIsomorphicAnalyzer(),
		behavAnalyzer:    NewBehavioralAnalyzer(nil),
		timingAnalyzer:   NewTimingAnalyzer(nil),
		graphicsAnalyzer: NewGraphicsAnalyzer(),
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

	// Phase 3: Cross-check TLS against User-Agent
	if detection.TLSFingerprint != nil && httpInfo != nil {
		ua := strings.ToLower(httpInfo.UserAgent)
		isBrowser := strings.Contains(ua, "chrome") || strings.Contains(ua, "firefox") || strings.Contains(ua, "safari")

		// If UA claims to be a browser but TLS lacks GREASE, it's a strong indicator of Go/spoofing
		if isBrowser && !detection.TLSFingerprint.HasGREASE {
			detection.TLSFingerprint.Anomalies = append(detection.TLSFingerprint.Anomalies, "tls_go_fingerprint: browser_ua_with_go_tls")

			// Update the TLS vector score and indicators
			for i, v := range detection.Vectors {
				if v.Category == "tls" {
					detection.Vectors[i].Score = 0.50
					detection.Vectors[i].Detected = true
					detection.Vectors[i].Indicators = detection.TLSFingerprint.Anomalies

					// Re-calculate totals
					totalScore += 0.50*v.Weight - v.Score*v.Weight
					vectorResults[VectorTLS].Score = 0.50
					vectorResults[VectorTLS].Detected = true
				}
			}
		}
	}

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

	// Phase 57: Collect indicators from all vectors for the flat indicator list
	for i := range detection.Vectors {
		detection.Vectors[i].Confidence = calculateVectorConfidence(&detection.Vectors[i])
	}

	for _, v := range detection.Vectors {
		for _, indName := range v.Indicators {
			detection.Indicators = append(detection.Indicators, StealthIndicator{
				Vector:   v.Name,
				Name:     indName,
				Severity: v.Score, // Use vector score as indicator severity proxy
				Message:  fmt.Sprintf("%s indicator: %s", v.Name, indName),
			})
		}
	}

	// Calculate final score
	if sd.config.EnableAdaptiveScoring && sd.adaptiveScorer != nil && len(vectorResults) > 0 {
		ensemble := sd.adaptiveScorer.ScoreResults(vectorResults)
		detection.Score = ensemble.FinalScore
	} else if totalWeight > 0 {
		detection.Score = totalScore / totalWeight
	}

	detection.IsBot = detection.Score >= sd.config.ThresholdBot
	detection.Confidence = calculateDetectionConfidence(&detection)

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
	return sd.graphicsAnalyzer.AnalyzeWebGL(req)
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
	var data PluginData

	if pluginHeader != "" {
		if err := json.Unmarshal([]byte(pluginHeader), &data); err != nil {
			return nil
		}
	} else {
		// Fallback to X-Navigator-Data if X-Plugin-Data is missing (common in some tests/older emitters)
		navHeader := req.Header.Get(constants.HeaderNavigatorData)
		if navHeader == "" {
			return nil
		}
		var navMap map[string]interface{}
		if err := json.Unmarshal([]byte(navHeader), &navMap); err != nil {
			return nil
		}
		if plugins, ok := navMap["plugins"].([]interface{}); ok {
			for _, p := range plugins {
				if pm, ok := p.(map[string]interface{}); ok {
					entry := PluginEntry{
						Name:     fmt.Sprint(pm["name"]),
						Filename: fmt.Sprint(pm["filename"]),
					}
					if mt, ok := pm["mimeTypes"].([]interface{}); ok {
						for _, m := range mt {
							entry.MimeTypes = append(entry.MimeTypes, fmt.Sprint(m))
						}
					}
					data.Plugins = append(data.Plugins, entry)
				}
			}
			data.PluginCount = len(data.Plugins)
		} else {
			return nil
		}
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

	// Check for GREASE - standard Go crypto/tls DOES NOT use GREASE
	// Modern browsers (Chrome, Firefox, Safari) ALL use GREASE.

	// Check cipher suite for GREASE (0x0a0a, 0x1a1a, etc.)
	if (tlsConn.CipherSuite & 0x0f0f) == 0x0a0a {
		info.HasGREASE = true
	}

	// We can't strictly flag here because we don't have the UA.
	// We will perform the cross-check in AnalyzeRequest.

	return info
}

func (sd *StealthDetector) analyzeHTTPHeaders(req *http.Request) *HTTPFingerprintInfo {
	ua := req.Header.Get("User-Agent")
	accept := req.Header.Get("Accept")
	if ua == "" || accept == "" {
		// bot indicators
	}
	info := &HTTPFingerprintInfo{
		UserAgent:              ua,
		Accept:                 accept,
		AcceptLanguage:         req.Header.Get("Accept-Language"),
		AcceptEncoding:         req.Header.Get("Accept-Encoding"),
		SecCHUA:                req.Header.Get("Sec-Ch-Ua"),
		SecCHUAMobile:          req.Header.Get("Sec-Ch-Ua-Mobile"),
		SecCHUAPlatform:        req.Header.Get("Sec-Ch-Ua-Platform"),
		SecCHUAFullVersion:     req.Header.Get("Sec-Ch-Ua-Full-Version"),
		SecCHUAFullVersionList: req.Header.Get("Sec-Ch-Ua-Full-Version-List"),
		SecCHUAArch:            req.Header.Get("Sec-Ch-Ua-Arch"),
		SecCHUABitness:         req.Header.Get("Sec-Ch-Ua-Bitness"),
		SecCHUAModel:           req.Header.Get("Sec-Ch-Ua-Model"),
		SecFetchDest:           req.Header.Get("Sec-Fetch-Dest"),
		SecFetchMode:           req.Header.Get("Sec-Fetch-Mode"),
		SecFetchSite:           req.Header.Get("Sec-Fetch-Site"),
		SecFetchUser:           req.Header.Get("Sec-Fetch-User"),
		UpgradeInsecure:        req.Header.Get("Upgrade-Insecure-Requests"),
		HeaderCount:            len(req.Header),
		HeaderOrder:            make([]string, 0),
		MissingHeaders:         make([]string, 0),
		SuspiciousHeaders:      make([]string, 0),
	}

	// If a simulated header order is provided (used for testing/evasion simulation), use it.
	// Otherwise, use the map iteration order (which is a detection indicator for Go-based requests).
	if orderStr := req.Header.Get("X-Stealth-Header-Order"); orderStr != "" {
		info.HeaderOrder = strings.Split(orderStr, ",")
		// Remove the simulation header from the count and order to be clean
		info.HeaderCount--
	} else {
		for k := range req.Header {
			info.HeaderOrder = append(info.HeaderOrder, k)
		}
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
	isFirefoxUA := strings.Contains(strings.ToLower(info.UserAgent), "firefox")
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
		if info.SecFetchDest == "document" && info.SecFetchMode == "navigate" {
			info.SuspiciousHeaders = append(info.SuspiciousHeaders, "chrome_navigation_missing_client_hints")
		}
	}

	// Check for webdriver header (simple boolean flag from stealth bypass tools)
	if req.Header.Get("X-Navigator-Webdriver") == "true" {
		info.SuspiciousHeaders = append(info.SuspiciousHeaders, "webdriver_exposed")
	}

	// Check for proxy/CDN IP identification headers in a browser request.
	// Real browsers NEVER send X-Forwarded-For, X-Real-IP, True-Client-IP,
	// CF-Connecting-IP, or X-Client-IP — these are added by reverse proxies,
	// CDNs, and load balancers. A request with a browser UA that also carries
	// these headers is either coming through infrastructure (in which case
	// a single header is normal) or is a spoofing tool stuffing multiple headers
	// to impersonate infrastructure context. Multiple IP headers is a strong
	// signal of synthetic generation.
	if isChromeUA || isFirefoxUA {
		ipSpoofHeaders := []string{"X-Forwarded-For", "X-Real-Ip", "X-Client-Ip", "True-Client-Ip", "Cf-Connecting-Ip"}
		ipHeaderCount := 0
		for _, h := range ipSpoofHeaders {
			if req.Header.Get(h) != "" {
				ipHeaderCount++
			}
		}
		if ipHeaderCount >= 3 {
			info.SuspiciousHeaders = append(info.SuspiciousHeaders, fmt.Sprintf("browser_with_multiple_proxy_ip_headers_%d", ipHeaderCount))
		}
	}

	// Firefox should not present Chromium-style request priority metadata on a
	// synthetic top-level HTTP/1.x navigation without deeper browser context.
	if isFirefoxUA && req.Header.Get("Priority") != "" &&
		info.SecFetchDest == "document" && info.SecFetchMode == "navigate" &&
		(req.ProtoMajor <= 1 || req.Proto == "") && !hasJSFingerprintHeaders(req) {
		info.SuspiciousHeaders = append(info.SuspiciousHeaders, "firefox_navigation_priority_header")
		if strings.Contains(req.Header.Get("Priority"), ", i") {
			info.SuspiciousHeaders = append(info.SuspiciousHeaders, "firefox_chromium_priority_signature")
		}
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
	return sd.navAnalyzer.Analyze(req)
}

func (sd *StealthDetector) analyzeCanvasData(req *http.Request) *DetectionVector {
	return sd.graphicsAnalyzer.AnalyzeCanvas(req)
}

func (sd *StealthDetector) analyzeTimingData(req *http.Request) *DetectionVector {
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

	var timingData map[string]interface{}
	if err := json.Unmarshal([]byte(timingHeader), &timingData); err != nil {
		return nil
	}

	seq := NewRequestTimingSequenceFromMap(timingData)
	result := sd.timingAnalyzer.Analyze(seq)

	vec := &DetectionVector{
		Name:        "Timing Anomalies",
		Category:    "timing",
		Weight:      constants.WeightTiming,
		Description: "Analyzes timing patterns for automation detection",
		Score:       result.Score,
		Detected:    result.Detected,
	}

	for _, ind := range result.Indicators {
		vec.Indicators = append(vec.Indicators, ind.Check)
	}

	return vec
}

func (sd *StealthDetector) analyzeBehavioralData(req *http.Request) *DetectionVector {
	behavHeader := req.Header.Get(constants.HeaderBehavioralData)
	if behavHeader == "" {
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

	var behav map[string]interface{}
	if err := json.Unmarshal([]byte(behavHeader), &behav); err != nil {
		return nil
	}

	events := NewEnhancedBehavioralEventsFromMap(behav)
	result := sd.behavAnalyzer.Analyze(events)

	vec := &DetectionVector{
		Name:        "Behavioral Patterns",
		Category:    "behavioral",
		Weight:      constants.WeightBehavioral,
		Description: "Analyzes user interaction patterns for automation",
		Score:       result.Score,
		Detected:    result.Detected,
	}

	for _, ind := range result.Indicators {
		vec.Indicators = append(vec.Indicators, ind.Check)
	}

	return vec
}

func (sd *StealthDetector) analyzeIsomorphicAnomalies(req *http.Request, httpInfo *HTTPFingerprintInfo) *DetectionVector {
	return sd.isoAnalyzer.Analyze(req, httpInfo)
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
//   - 0 headers with Client Hints → 0.50 (HTTP impersonation, e.g., curl-impersonate)
//   - 1-5 headers → 0.30 * (1 - ratio) (partial: cherry-picked headers)
//   - 6-9 headers → 0.00 (normal partial coverage)
//   - Dense 8-10 header bundle on initial navigation → strong detection
//   - All 10 headers → 0.10 baseline suspicious completeness unless provenance is impossible
func (sd *StealthDetector) analyzeFingerprintCoverage(req *http.Request) *DetectionVector {
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

	secChUa := req.Header.Get("Sec-Ch-Ua")
	if secChUa == "" && presentCount < 8 {
		return nil
	}

	totalHeaders := len(allJSHeaders)
	vec := &DetectionVector{
		Name:         "Fingerprint Coverage",
		Category:     string(VectorFingerprintCoverage),
		Weight:       1.0,
		Description:  "Graduated fingerprint header coverage analysis",
		Indicators:   make([]string, 0),
		CheckReports: make([]CheckReport, 0),
	}

	switch {
	case presentCount == 0:
		// Pure HTTP impersonator — no JS context at all
		vec.Score = 0.50
		vec.Detected = true
		vec.Indicators = append(vec.Indicators, "http_impersonation_no_js_context")
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        "http_impersonation_no_js_context",
			Fired:       true,
			Weight:      constants.SeverityHigh,
			Score:       vec.Score,
			Field:       "X-*-Fingerprint-Headers",
			Actual:      fmt.Sprintf("%d of %d present", presentCount, totalHeaders),
			Expected:    "at least one coherent JS/runtime fingerprint surface",
			Severity:    "high",
			Description: "The request claims a browser navigation context but exposes no JS-derived runtime fingerprint data.",
		})
		if isRichChromiumNavigationWithoutRuntimeState(req) {
			vec.Score = 0.65
			vec.Indicators = append(vec.Indicators, "rich_chromium_headers_without_runtime_state")
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "rich_chromium_headers_without_runtime_state",
				Fired:       true,
				Weight:      constants.SeverityHigh,
				Score:       vec.Score,
				Field:       "Sec-Ch-Ua/Accept/Accept-Encoding",
				Actual:      "rich Chromium navigation bundle with 0 runtime surfaces",
				Expected:    "runtime surfaces consistent with a rich Chromium navigation bundle",
				Severity:    "high",
				Description: "The request sends a high-fidelity Chromium navigation header set, but still exposes no navigator, timing, canvas, or behavioral runtime state.",
			})
		}

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
		// 6-9 headers = normal partial coverage unless the bundle is impossibly dense
		// for an initial top-level navigation.
		if presentCount < 8 {
			return nil
		}
		vec.Score = 0.08
		vec.Detected = false
		vec.Indicators = append(vec.Indicators, fmt.Sprintf("dense_js_coverage_%d_of_%d", presentCount, totalHeaders))
	}

	if isInitialNavigationDenseRuntimeBundle(req, presentCount) {
		vec.Score = 0.82
		vec.Detected = true
		vec.Indicators = append(vec.Indicators, "pre_request_full_runtime_bundle")
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        "pre_request_full_runtime_bundle",
			Fired:       true,
			Weight:      constants.SeverityHigh,
			Score:       vec.Score,
			Field:       "X-*-Fingerprint-Headers",
			Actual:      fmt.Sprintf("%d of %d runtime headers on initial navigation", presentCount, totalHeaders),
			Expected:    "sparse or no JS/runtime headers before the page executes client-side probes",
			Severity:    "high",
			Description: "A first-party top-level navigation arrived with a dense runtime bundle that would normally require client-side execution after the document response.",
		})

		postLoadHeaders := countPresentHeaders(req, []string{
			constants.HeaderBehavioralData,
			constants.HeaderTimingData,
			constants.HeaderCanvasFingerprint,
			constants.HeaderAudioData,
			constants.HeaderWebRTCData,
		})
		if postLoadHeaders >= 3 {
			vec.Indicators = append(vec.Indicators, "post_load_telemetry_on_initial_navigation")
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "post_load_telemetry_on_initial_navigation",
				Fired:       true,
				Weight:      constants.SeverityHigh,
				Score:       vec.Score,
				Field:       "X-Behavioral-Data/X-Timing-Data/X-Canvas-Fingerprint/X-Audio-Data/X-WebRTC-Data",
				Actual:      fmt.Sprintf("%d post-load telemetry surfaces attached to initial navigation", postLoadHeaders),
				Expected:    "post-load telemetry should be submitted after the document has executed, not on the first navigation request",
				Severity:    "high",
				Description: "The request includes multiple telemetry surfaces that require user interaction, rendering, timing collection, or permission-gated APIs before they can exist.",
			})
		}
	}

	return vec
}

func isInitialNavigationDenseRuntimeBundle(req *http.Request, presentCount int) bool {
	if req == nil || presentCount < 8 || !isInitialTopLevelNavigation(req) {
		return false
	}

	postLoadHeaders := countPresentHeaders(req, []string{
		constants.HeaderBehavioralData,
		constants.HeaderTimingData,
		constants.HeaderCanvasFingerprint,
		constants.HeaderAudioData,
		constants.HeaderWebRTCData,
	})
	if postLoadHeaders < 3 {
		return false
	}

	permissionGatedHeaders := countPresentHeaders(req, []string{
		constants.HeaderAudioData,
		constants.HeaderWebRTCData,
		constants.HeaderBehavioralData,
	})

	return permissionGatedHeaders >= 2 || req.Header.Get(constants.HeaderTimingData) != ""
}

func isInitialTopLevelNavigation(req *http.Request) bool {
	if req == nil {
		return false
	}

	return req.Header.Get("Sec-Fetch-Dest") == "document" &&
		req.Header.Get("Sec-Fetch-Mode") == "navigate" &&
		req.Header.Get("Sec-Fetch-Site") == "none" &&
		req.Header.Get("Sec-Fetch-User") == "?1" &&
		req.Header.Get("Referer") == ""
}

func countPresentHeaders(req *http.Request, headers []string) int {
	count := 0
	for _, header := range headers {
		if req.Header.Get(header) != "" {
			count++
		}
	}
	return count
}

func totalHeaderValueBytes(req *http.Request, headers []string) int {
	total := 0
	for _, header := range headers {
		total += len(req.Header.Get(header))
	}
	return total
}

func isRichChromiumNavigationWithoutRuntimeState(req *http.Request) bool {
	uaLower := strings.ToLower(req.Header.Get("User-Agent"))
	secChLower := strings.ToLower(req.Header.Get("Sec-Ch-Ua"))
	if !strings.Contains(uaLower, "chrome") && !strings.Contains(secChLower, "chrom") {
		return false
	}

	if req.Header.Get("Sec-Fetch-Dest") != "document" ||
		req.Header.Get("Sec-Fetch-Mode") != "navigate" ||
		req.Header.Get("Upgrade-Insecure-Requests") != "1" {
		return false
	}

	richSignals := 0
	if strings.Contains(req.Header.Get("Accept"), "application/signed-exchange") {
		richSignals++
	}
	if strings.Contains(req.Header.Get("Accept-Encoding"), "zstd") {
		richSignals++
	}
	if req.Header.Get("Sec-Ch-Ua-Full-Version-List") != "" {
		richSignals++
	}
	if req.Header.Get("Sec-Ch-Ua-Arch") != "" || req.Header.Get("Sec-Ch-Ua-Bitness") != "" {
		richSignals++
	}
	if req.Header.Get("Priority") != "" {
		richSignals++
	}

	return richSignals >= 2
}

// analyzeCrossVectorConsistency checks temporal and spatial consistency between
// independently generated fingerprint vectors. Two sub-checks:
// 1. Behavioral timestamps should start AFTER page load completion (from timing data).
// 2. Mouse positions should be within the claimed screen dimensions.
// 3. Same-origin telemetry submissions should have coherent request provenance.
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

	// Sub-check 3: Same-site telemetry provenance.
	// A same-site analytics POST should target a sibling origin (for example
	// app.example.com -> metrics.example.com). If the request claims same-site
	// while Origin/URL point at the exact same origin, or it hides multiple
	// post-load runtime surfaces in custom headers behind a thin analytics body,
	// that fetch metadata is internally inconsistent and much more likely to be
	// generated by a request spoofer than a browser.
	if isNoneContextTelemetryFetch(req) {
		runtimeHeaderCount := countPresentHeaders(req, []string{
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
		})
		postLoadHeaderCount := countPresentHeaders(req, []string{
			constants.HeaderBehavioralData,
			constants.HeaderTimingData,
			constants.HeaderCanvasFingerprint,
			constants.HeaderAudioData,
			constants.HeaderWebRTCData,
		})

		bodySnapshot, bodyErr := snapshotRequestBody(req)
		bodyText := strings.TrimSpace(string(bodySnapshot))
		bodyTooSmall := bodyErr == nil && len(bodySnapshot) > 0 && len(bodySnapshot) < 512
		missingRuntimePayload := bodyErr == nil && len(bodySnapshot) > 0 && !bodyContainsRuntimePayload(bodyText)

		if req.Method == http.MethodPost && runtimeHeaderCount >= 4 {
			vec.Score += 0.80
			vec.Indicators = append(vec.Indicators, fmt.Sprintf(
				"none_context_runtime_bundle: %d runtime/%d post_load headers",
				runtimeHeaderCount, postLoadHeaderCount))

			if postLoadHeaderCount >= 3 {
				vec.Score += 0.18
				vec.Indicators = append(vec.Indicators, fmt.Sprintf(
					"none_context_postload_headers_present: %d runtime/%d post_load headers",
					runtimeHeaderCount, postLoadHeaderCount))
			}

			if isOriginSameAsRequestURL(req) {
				vec.Score += 0.14
				vec.Indicators = append(vec.Indicators, "none_context_first_party_origin_claim")
			}

			if bodyErr == nil && len(bodySnapshot) > 0 {
				if bodyTooSmall {
					vec.Score += 0.24
					vec.Indicators = append(vec.Indicators, fmt.Sprintf(
						"none_context_body_too_small_for_claimed_runtime: %d bytes", len(bodySnapshot)))
				}

				if missingRuntimePayload {
					vec.Score += 0.26
					vec.Indicators = append(vec.Indicators, "none_context_body_missing_runtime_payload")
				}
			}
		}
	}

	if isSameSiteTelemetryFetch(req) {
		mode := req.Header.Get("Sec-Fetch-Mode")
		runtimeHeaderCount := countPresentHeaders(req, []string{
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
		})
		postLoadHeaderCount := countPresentHeaders(req, []string{
			constants.HeaderBehavioralData,
			constants.HeaderTimingData,
			constants.HeaderCanvasFingerprint,
			constants.HeaderAudioData,
			constants.HeaderWebRTCData,
		})

		bodySnapshot, bodyErr := snapshotRequestBody(req)
		bodyText := strings.TrimSpace(string(bodySnapshot))
		bodyTooSmall := bodyErr == nil && len(bodySnapshot) > 0 && len(bodySnapshot) < 512
		missingRuntimePayload := bodyErr == nil && len(bodySnapshot) > 0 && !bodyContainsRuntimePayload(bodyText)
		hasRuntimeBody := bodyErr == nil && len(bodySnapshot) >= 512 && bodyContainsRuntimePayload(bodyText)
		sameOriginClaim := false
		requiredRuntimeHeaders := 4

		if req.Method == http.MethodPost && mode == "same-origin" && runtimeHeaderCount >= 3 {
			requiredRuntimeHeaders = 3
			vec.Score += 0.78
			vec.Indicators = append(vec.Indicators, fmt.Sprintf(
				"same_site_same_origin_mode_mismatch: %d runtime/%d post_load headers",
				runtimeHeaderCount, postLoadHeaderCount))
		}

		if req.Method == http.MethodPost && runtimeHeaderCount >= requiredRuntimeHeaders {
			if isOriginSameAsRequestURL(req) {
				vec.Score += 0.70
				vec.Indicators = append(vec.Indicators, "same_site_claim_on_same_origin_post")
				sameOriginClaim = true
			}

			if isRefererSameAsRequestURL(req) {
				vec.Score += 0.22
				vec.Indicators = append(vec.Indicators, "same_site_telemetry_self_referer")
				sameOriginClaim = true
			}
		}

		if req.Method == http.MethodPost && runtimeHeaderCount >= 6 && hasRuntimeBody {
			if sameOriginClaim && postLoadHeaderCount >= 3 {
				vec.Score += 0.30
				vec.Indicators = append(vec.Indicators, fmt.Sprintf(
					"telemetry_runtime_duplicated_in_body_and_headers: %d runtime/%d post_load headers",
					runtimeHeaderCount, postLoadHeaderCount))
			}
		}

		if req.Method == http.MethodPost && runtimeHeaderCount >= requiredRuntimeHeaders && bodyErr == nil && len(bodySnapshot) > 0 {
			if postLoadHeaderCount >= 3 && (bodyTooSmall || missingRuntimePayload) {
				vec.Score += 0.24
				vec.Indicators = append(vec.Indicators, fmt.Sprintf(
					"same_site_runtime_hidden_in_headers: %d runtime/%d post_load headers",
					runtimeHeaderCount, postLoadHeaderCount))
			}

			if bodyTooSmall {
				vec.Score += 0.42
				vec.Indicators = append(vec.Indicators, fmt.Sprintf(
					"same_site_body_too_small_for_claimed_runtime: %d bytes", len(bodySnapshot)))
			}

			if missingRuntimePayload {
				vec.Score += 0.34
				vec.Indicators = append(vec.Indicators, "same_site_body_missing_runtime_payload")
			}
		}

		// Sub-check 3b: Same-site POST with few runtime headers and browser UA.
		// Catches both zero-header and cherry-picked header patterns:
		//   - 0 headers: synthetic beacon (no runtime context at all)
		//   - 1-2 headers: cherry-picked to dodge both zero-header and >= 3 gates
		// For 1-2 headers: check if ONLY post-load headers (Behavioral, Timing)
		// are present without any JS fingerprint headers (Navigator, WebGL, etc.).
		// Real SDKs that collect behavioral/timing data also collect navigator.
		if req.Method == http.MethodPost && runtimeHeaderCount <= 2 {
			ua := strings.ToLower(req.Header.Get("User-Agent"))
			isBrowserUA := strings.Contains(ua, "chrome") || strings.Contains(ua, "firefox") || strings.Contains(ua, "safari")
			jsFingerprintCount := countPresentHeaders(req, []string{
				constants.HeaderNavigatorData,
				constants.HeaderWebGLData,
				constants.HeaderPluginData,
				constants.HeaderScreenData,
				constants.HeaderFontData,
				constants.HeaderWebRTCData,
			})

			if isBrowserUA {
				largeTelemetryBody := len(bodySnapshot) >= 1024
				siblingOriginClaim := req.Header.Get("Origin") != "" && !isOriginSameAsRequestURL(req)
				missingReferer := req.Referer() == ""

				if runtimeHeaderCount == 0 && bodyErr == nil && len(bodySnapshot) > 0 {
					if !bodyContainsRuntimePayload(bodyText) {
						vec.Score += 0.42
						vec.Indicators = append(vec.Indicators, fmt.Sprintf(
							"same_site_synthetic_beacon: browser_ua body_size=%d no_runtime_in_body_or_headers",
							len(bodySnapshot)))
					} else {
						vec.Score += 0.42
						vec.Indicators = append(vec.Indicators, fmt.Sprintf(
							"same_site_runtime_data_migration: browser_ua body_size=%d runtime_in_body_but_zero_headers",
							len(bodySnapshot)))
					}

					if largeTelemetryBody && siblingOriginClaim {
						vec.Score += 0.18
						vec.Indicators = append(vec.Indicators, fmt.Sprintf(
							"same_site_sibling_origin_zero_header_post: body_size=%d",
							len(bodySnapshot)))
					}

					if largeTelemetryBody && missingReferer {
						vec.Score += 0.12
						vec.Indicators = append(vec.Indicators, "same_site_zero_header_missing_referer")
					}
				} else if runtimeHeaderCount > 0 && runtimeHeaderCount <= 2 && jsFingerprintCount == 0 {
					// Cherry-picked post-load headers without JS fingerprints.
					// Behavioral + Timing without Navigator = selective header
					// evasion to dodge both zero-header and >= 3-header gates.
					// Score 0.50 needed to survive adaptive scorer dilution
					// (single-vector at 0.35 → final ≈ 0.28, below threshold).
					vec.Score += 0.50
					vec.Indicators = append(vec.Indicators, fmt.Sprintf(
						"same_site_cherry_picked_postload_headers: %d runtime_headers but 0 js_fingerprint_headers",
						runtimeHeaderCount))
				}
			}
		}
	}

	// Sub-check 4: Cross-site telemetry provenance.
	// Third-party analytics beacons should originate from a different origin than
	// the request target. If a request claims cross-site while Origin/URL still
	// point at the same origin, or if it hides a dense runtime bundle in headers
	// behind a tiny analytics body, the fetch metadata is inconsistent.
	if isCrossSiteTelemetryFetch(req) {
		mode := req.Header.Get("Sec-Fetch-Mode")
		runtimeHeaderCount := countPresentHeaders(req, []string{
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
		})
		postLoadHeaderCount := countPresentHeaders(req, []string{
			constants.HeaderBehavioralData,
			constants.HeaderTimingData,
			constants.HeaderCanvasFingerprint,
			constants.HeaderAudioData,
			constants.HeaderWebRTCData,
		})

		bodySnapshot, bodyErr := snapshotRequestBody(req)
		bodyText := strings.TrimSpace(string(bodySnapshot))
		bodyTooSmall := bodyErr == nil && len(bodySnapshot) > 0 && len(bodySnapshot) < 512
		missingRuntimePayload := bodyErr == nil && len(bodySnapshot) > 0 && !bodyContainsRuntimePayload(bodyText)
		crossSiteClaim := false
		requiredRuntimeHeaders := 4

		if req.Method == http.MethodPost && mode == "same-origin" && runtimeHeaderCount >= 3 {
			requiredRuntimeHeaders = 3
			vec.Score += 0.80
			vec.Indicators = append(vec.Indicators, fmt.Sprintf(
				"cross_site_same_origin_mode_mismatch: %d runtime/%d post_load headers",
				runtimeHeaderCount, postLoadHeaderCount))
		}

		if req.Method == http.MethodPost && runtimeHeaderCount >= requiredRuntimeHeaders {
			if isOriginSameAsRequestURL(req) {
				vec.Score += 0.72
				vec.Indicators = append(vec.Indicators, "cross_site_claim_on_same_origin_post")
				crossSiteClaim = true
			}

			if isRefererSameAsRequestURL(req) {
				vec.Score += 0.22
				vec.Indicators = append(vec.Indicators, "cross_site_telemetry_self_referer")
				crossSiteClaim = true
			}
		}

		if req.Method == http.MethodPost && runtimeHeaderCount >= requiredRuntimeHeaders && bodyErr == nil && len(bodySnapshot) > 0 {
			if postLoadHeaderCount >= 3 && (bodyTooSmall || missingRuntimePayload) {
				vec.Score += 0.28
				vec.Indicators = append(vec.Indicators, fmt.Sprintf(
					"cross_site_runtime_hidden_in_headers: %d runtime/%d post_load headers",
					runtimeHeaderCount, postLoadHeaderCount))
			}

			if bodyTooSmall {
				vec.Score += 0.42
				vec.Indicators = append(vec.Indicators, fmt.Sprintf(
					"cross_site_body_too_small_for_claimed_runtime: %d bytes", len(bodySnapshot)))
			}

			if missingRuntimePayload {
				vec.Score += 0.34
				vec.Indicators = append(vec.Indicators, "cross_site_body_missing_runtime_payload")
			}

			if crossSiteClaim && postLoadHeaderCount >= 3 {
				vec.Score += 0.20
				vec.Indicators = append(vec.Indicators, fmt.Sprintf(
					"cross_site_runtime_with_first_party_origin: %d runtime/%d post_load headers",
					runtimeHeaderCount, postLoadHeaderCount))
			}
		}
	}

	// Sub-check 5: no-cors telemetry/beacon provenance.
	// Browser no-cors beacons can be legitimate, but they cannot carry runtime
	// bundles in arbitrary custom X-* headers. When a POST claims to be a
	// no-cors analytics/beacon request yet still ships many runtime surfaces in
	// headers, optionally with a non-safelisted content type and a thin body, it
	// is much more likely to be synthetic request generation than in-page JS.
	if isNoCORSTelemetryFetch(req) {
		runtimeHeaderCount := countPresentHeaders(req, []string{
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
		})
		postLoadHeaderCount := countPresentHeaders(req, []string{
			constants.HeaderBehavioralData,
			constants.HeaderTimingData,
			constants.HeaderCanvasFingerprint,
			constants.HeaderAudioData,
			constants.HeaderWebRTCData,
		})
		bodySnapshot, bodyErr := snapshotRequestBody(req)
		bodyText := strings.TrimSpace(string(bodySnapshot))
		bodyTooSmall := bodyErr == nil && len(bodySnapshot) > 0 && len(bodySnapshot) < 512
		missingRuntimePayload := bodyErr == nil && len(bodySnapshot) > 0 && !bodyContainsRuntimePayload(bodyText)
		contentType := req.Header.Get("Content-Type")

		if req.Method == http.MethodPost && runtimeHeaderCount >= 5 {
			vec.Score += 0.72
			vec.Indicators = append(vec.Indicators, fmt.Sprintf(
				"nocors_impossible_custom_runtime_headers: %d runtime/%d post_load headers",
				runtimeHeaderCount, postLoadHeaderCount))

			if postLoadHeaderCount >= 3 {
				vec.Score += 0.18
				vec.Indicators = append(vec.Indicators, fmt.Sprintf(
					"nocors_postload_headers_present: %d runtime/%d post_load headers",
					runtimeHeaderCount, postLoadHeaderCount))
			}

			if !isNoCORSSafelistedContentType(contentType) {
				vec.Score += 0.40
				vec.Indicators = append(vec.Indicators, fmt.Sprintf(
					"nocors_non_safelisted_content_type: %s", contentType))
			}

			if isOriginSameAsRequestURL(req) {
				vec.Score += 0.12
				vec.Indicators = append(vec.Indicators, "nocors_same_origin_beacon")
			}

			if bodyErr == nil && len(bodySnapshot) > 0 {
				if bodyTooSmall {
					vec.Score += 0.26
					vec.Indicators = append(vec.Indicators, fmt.Sprintf(
						"nocors_body_too_small_for_claimed_runtime: %d bytes", len(bodySnapshot)))
				}

				if missingRuntimePayload {
					vec.Score += 0.22
					vec.Indicators = append(vec.Indicators, "nocors_body_missing_runtime_payload")
				}
			}
		}
	}

	// Sub-check 6: document navigation submissions with runtime telemetry.
	// A browser form/navigation POST can legitimately carry Origin, cookies, and
	// a form body, but it cannot attach client-side runtime telemetry in custom
	// X-* headers. If a document navigation carries multiple runtime surfaces, it
	// is almost certainly synthetic request generation rather than a real form
	// submission, regardless of whether the fetch metadata claims same-origin,
	// same-site, or cross-site.
	if isDocumentNavigationSubmission(req) {
		runtimeHeaderCount := countPresentHeaders(req, []string{
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
		})
		postLoadHeaderCount := countPresentHeaders(req, []string{
			constants.HeaderBehavioralData,
			constants.HeaderTimingData,
			constants.HeaderCanvasFingerprint,
			constants.HeaderAudioData,
			constants.HeaderWebRTCData,
		})
		bodySnapshot, bodyErr := snapshotRequestBody(req)
		bodyText := strings.TrimSpace(string(bodySnapshot))

		if runtimeHeaderCount >= 4 {
			vec.Score += 0.78
			vec.Indicators = append(vec.Indicators, fmt.Sprintf(
				"document_navigation_impossible_runtime_headers: %d runtime/%d post_load headers",
				runtimeHeaderCount, postLoadHeaderCount))

			if postLoadHeaderCount >= 3 {
				vec.Score += 0.20
				vec.Indicators = append(vec.Indicators, fmt.Sprintf(
					"document_navigation_postload_headers_present: %d runtime/%d post_load headers",
					runtimeHeaderCount, postLoadHeaderCount))
			}

			if bodyErr == nil && len(bodySnapshot) > 0 && !bodyContainsRuntimePayload(bodyText) {
				vec.Score += 0.18
				vec.Indicators = append(vec.Indicators, "document_navigation_body_missing_runtime_payload")
			}
		}
	}

	// Sub-check 7: Same-origin telemetry provenance.
	// A same-origin fetch/XHR can legitimately submit post-load telemetry, but if
	// the payload is stuffed into headers on a GET request, points its Referer at
	// the exact telemetry URL, and carries many runtime surfaces without a body,
	// it is much more likely to be synthetic request generation than in-page JS.
	if isSameOriginTelemetryFetch(req) {
		runtimeHeaderCount := countPresentHeaders(req, []string{
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
		})
		postLoadHeaderCount := countPresentHeaders(req, []string{
			constants.HeaderBehavioralData,
			constants.HeaderTimingData,
			constants.HeaderCanvasFingerprint,
			constants.HeaderAudioData,
			constants.HeaderWebRTCData,
		})
		postLoadHeaderBytes := totalHeaderValueBytes(req, []string{
			constants.HeaderBehavioralData,
			constants.HeaderTimingData,
			constants.HeaderCanvasFingerprint,
			constants.HeaderAudioData,
			constants.HeaderWebRTCData,
		})
		behaviorHeaderBytes := len(req.Header.Get(constants.HeaderBehavioralData))
		timingHeaderBytes := len(req.Header.Get(constants.HeaderTimingData))

		if req.Method == http.MethodPost && postLoadHeaderBytes >= 1536 {
			vec.Score += 0.36
			vec.Indicators = append(vec.Indicators, fmt.Sprintf(
				"telemetry_postload_blob_in_headers: %d bytes across %d post_load headers",
				postLoadHeaderBytes, postLoadHeaderCount))

			if timingHeaderBytes >= 1024 {
				vec.Score += 0.22
				vec.Indicators = append(vec.Indicators, fmt.Sprintf(
					"telemetry_timing_blob_in_headers: %d bytes", timingHeaderBytes))
			}

			if behaviorHeaderBytes >= 1024 {
				vec.Score += 0.10
				vec.Indicators = append(vec.Indicators, "telemetry_behavioral_payload_in_headers")
			}

			bodySnapshot, bodyErr := snapshotRequestBody(req)
			if bodyErr == nil && len(bodySnapshot) > 0 {
				if strings.Contains(strings.ToLower(req.Header.Get("Content-Type")), "application/json") && !json.Valid(bodySnapshot) {
					vec.Score += 0.55
					vec.Indicators = append(vec.Indicators, "telemetry_invalid_json_body")
				}
				if postLoadHeaderBytes > len(bodySnapshot)*4 {
					vec.Score += 0.18
					vec.Indicators = append(vec.Indicators, fmt.Sprintf(
						"telemetry_header_body_imbalance: %d header bytes vs %d body bytes",
						postLoadHeaderBytes, len(bodySnapshot)))
				}
			}
		}

		if req.Method == http.MethodPost && postLoadHeaderCount >= 3 && postLoadHeaderBytes >= 2048 {
			vec.Score += 0.44
			vec.Indicators = append(vec.Indicators, fmt.Sprintf(
				"telemetry_bulk_payload_in_headers: %d bytes across %d post_load headers",
				postLoadHeaderBytes, postLoadHeaderCount))
		}

		if runtimeHeaderCount >= 6 && postLoadHeaderCount >= 3 {
			if req.Method == http.MethodPost {
				vec.Score += 0.42
				vec.Indicators = append(vec.Indicators, fmt.Sprintf(
					"telemetry_header_surface_overload: %d runtime/%d post_load headers",
					runtimeHeaderCount, postLoadHeaderCount))
			}

			if req.Method == http.MethodGet {
				vec.Score += 0.30
				vec.Indicators = append(vec.Indicators, fmt.Sprintf(
					"telemetry_payload_on_get_request: %d runtime headers", runtimeHeaderCount))
			}

			if isRefererSameAsRequestURL(req) {
				vec.Score += 0.40
				vec.Indicators = append(vec.Indicators, "telemetry_self_referer")
			}

			if req.Header.Get("Content-Type") == "" && req.ContentLength <= 0 {
				vec.Score += 0.30
				vec.Indicators = append(vec.Indicators, fmt.Sprintf(
					"telemetry_stuffed_into_headers: %d runtime/%d post_load headers without body",
					runtimeHeaderCount, postLoadHeaderCount))
			}

			if req.Method == http.MethodPost {
				vec.Score += 0.20
				vec.Indicators = append(vec.Indicators, fmt.Sprintf(
					"telemetry_runtime_hidden_in_headers: %d runtime/%d post_load headers",
					runtimeHeaderCount, postLoadHeaderCount))

				bodySnapshot, bodyErr := snapshotRequestBody(req)
				bodyText := strings.TrimSpace(string(bodySnapshot))
				if bodyErr != nil || len(bodySnapshot) == 0 {
					vec.Score += 0.30
					vec.Indicators = append(vec.Indicators, "telemetry_post_missing_body_payload")
				} else {
					if len(bodySnapshot) < 256 {
						vec.Score += 0.22
						vec.Indicators = append(vec.Indicators, fmt.Sprintf(
							"telemetry_body_too_small_for_claimed_runtime: %d bytes", len(bodySnapshot)))
					}
					if !bodyContainsRuntimePayload(bodyText) {
						vec.Score += 0.22
						vec.Indicators = append(vec.Indicators, "telemetry_body_missing_runtime_payload")
					}
				}
			}
		}
	}

	// Sub-check 8: Fetch metadata provenance inconsistency.
	// Real browsers set Sec-Fetch-Site automatically based on the relationship
	// between the page origin and the request URL. If a request claims cross-site
	// but Origin matches the request URL host, the provenance is fabricated —
	// a real browser would have set same-origin instead.
	// This check fires regardless of runtime header count because it's a pure
	// logical impossibility, not a runtime data analysis.
	if req.Header.Get("Sec-Fetch-Site") == "cross-site" && isOriginSameAsRequestURL(req) {
		vec.Score += 0.50
		vec.Indicators = append(vec.Indicators, "cross_site_provenance_lie: origin_matches_request_url")
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        "cross_site_provenance_lie",
			Fired:       true,
			Weight:      constants.SeverityHigh,
			Score:       0.50,
			Field:       "Sec-Fetch-Site + Origin",
			Actual:      fmt.Sprintf("Sec-Fetch-Site=cross-site but Origin=%s matches request host", req.Header.Get("Origin")),
			Expected:    "cross-site requests must originate from a different host",
			Severity:    "high",
			Description: "The request claims cross-site provenance but its Origin header matches the request URL host, which is impossible in a real browser.",
		})
	}

	// Sub-check 9: Cross-site browser POST with zero runtime context.
	// Real cross-site analytics beacons (Sentry, FullStory, GA) carry SDK metadata
	// and runtime telemetry in their bodies. A cross-site POST with a browser UA,
	// zero runtime headers, a small body (< 512 bytes), and a CORS-safe Content-Type
	// matches the pattern of a synthetic beacon. The text/plain;charset=UTF-8
	// Content-Type is a CORS "simple request" optimization that avoids preflights —
	// commonly used by Sentry but always with a much larger envelope body.
	if isCrossSiteTelemetryFetch(req) && req.Method == http.MethodPost {
		runtimeHeaderCount := countPresentHeaders(req, []string{
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
		})

		if runtimeHeaderCount <= 2 {
			ua := strings.ToLower(req.Header.Get("User-Agent"))
			isBrowserUA := strings.Contains(ua, "chrome") || strings.Contains(ua, "firefox") || strings.Contains(ua, "safari")
			jsFingerprintCount := countPresentHeaders(req, []string{
				constants.HeaderNavigatorData,
				constants.HeaderWebGLData,
				constants.HeaderPluginData,
				constants.HeaderScreenData,
				constants.HeaderFontData,
				constants.HeaderWebRTCData,
			})

			if isBrowserUA {
				if runtimeHeaderCount == 0 {
					bodySnapshot, bodyErr := snapshotRequestBody(req)
					bodyText := strings.TrimSpace(string(bodySnapshot))
					if bodyErr == nil && len(bodySnapshot) > 0 {
						if !bodyContainsRuntimePayload(bodyText) {
							vec.Score += 0.35
							vec.Indicators = append(vec.Indicators, fmt.Sprintf(
								"cross_site_synthetic_beacon: browser_ua body_size=%d no_runtime_in_body_or_headers",
								len(bodySnapshot)))
						} else {
							vec.Score += 0.35
							vec.Indicators = append(vec.Indicators, fmt.Sprintf(
								"cross_site_runtime_data_migration: browser_ua body_size=%d runtime_in_body_but_zero_headers",
								len(bodySnapshot)))
						}
					}
				} else if runtimeHeaderCount > 0 && jsFingerprintCount == 0 {
					// Cherry-picked post-load headers on cross-site POST.
					vec.Score += 0.50
					vec.Indicators = append(vec.Indicators, fmt.Sprintf(
						"cross_site_cherry_picked_postload_headers: %d runtime_headers but 0 js_fingerprint_headers",
						runtimeHeaderCount))
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

func isSameOriginTelemetryFetch(req *http.Request) bool {
	if req == nil {
		return false
	}

	mode := req.Header.Get("Sec-Fetch-Mode")
	return req.Header.Get("Sec-Fetch-Dest") == "empty" &&
		(mode == "cors" || mode == "same-origin") &&
		req.Header.Get("Sec-Fetch-Site") == "same-origin"
}

func isNoneContextTelemetryFetch(req *http.Request) bool {
	if req == nil {
		return false
	}

	mode := req.Header.Get("Sec-Fetch-Mode")
	return req.Header.Get("Sec-Fetch-Dest") == "empty" &&
		(mode == "cors" || mode == "same-origin") &&
		req.Header.Get("Sec-Fetch-Site") == "none"
}

func isNoCORSTelemetryFetch(req *http.Request) bool {
	if req == nil {
		return false
	}

	return req.Header.Get("Sec-Fetch-Dest") == "empty" &&
		req.Header.Get("Sec-Fetch-Mode") == "no-cors"
}

func isDocumentNavigationSubmission(req *http.Request) bool {
	if req == nil {
		return false
	}

	return req.Method == http.MethodPost &&
		req.Header.Get("Sec-Fetch-Dest") == "document" &&
		req.Header.Get("Sec-Fetch-Mode") == "navigate" &&
		req.Header.Get("Sec-Fetch-User") == "?1"
}

func isSameSiteTelemetryFetch(req *http.Request) bool {
	if req == nil {
		return false
	}

	mode := req.Header.Get("Sec-Fetch-Mode")
	return req.Header.Get("Sec-Fetch-Dest") == "empty" &&
		(mode == "cors" || mode == "same-origin") &&
		req.Header.Get("Sec-Fetch-Site") == "same-site"
}

func isCrossSiteTelemetryFetch(req *http.Request) bool {
	if req == nil {
		return false
	}

	mode := req.Header.Get("Sec-Fetch-Mode")
	return req.Header.Get("Sec-Fetch-Dest") == "empty" &&
		(mode == "cors" || mode == "same-origin") &&
		req.Header.Get("Sec-Fetch-Site") == "cross-site"
}

func isRefererSameAsRequestURL(req *http.Request) bool {
	if req == nil || req.URL == nil {
		return false
	}

	referer := req.Referer()
	if referer == "" {
		return false
	}

	refURL, err := url.Parse(referer)
	if err != nil {
		return false
	}

	return urlsEqualSansFragment(refURL, req.URL)
}

func isOriginSameAsRequestURL(req *http.Request) bool {
	if req == nil || req.URL == nil {
		return false
	}

	origin := req.Header.Get("Origin")
	if origin == "" {
		return false
	}

	originURL, err := url.Parse(origin)
	if err != nil {
		return false
	}

	return strings.EqualFold(originURL.Scheme, req.URL.Scheme) &&
		strings.EqualFold(originURL.Host, req.URL.Host)
}

func isNoCORSSafelistedContentType(contentType string) bool {
	baseContentType := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	if baseContentType == "" {
		return true
	}

	switch baseContentType {
	case "application/x-www-form-urlencoded", "multipart/form-data", "text/plain":
		return true
	default:
		return false
	}
}

func urlsEqualSansFragment(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}

	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Host, b.Host) &&
		strings.TrimRight(a.EscapedPath(), "/") == strings.TrimRight(b.EscapedPath(), "/") &&
		a.RawQuery == b.RawQuery
}

func snapshotRequestBody(req *http.Request) ([]byte, error) {
	if req == nil || req.Body == nil {
		return nil, nil
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	return body, nil
}

// bodyContainsRuntimePayload checks whether the body contains genuine browser
// runtime data, not just superficial keyword references. For JSON bodies, it
// requires runtime keywords to appear as standalone JSON object keys (e.g.
// "navigator": {...}) rather than as prefixes in compound measurement labels
// (e.g. "navigator_entropy": {"value": 5.23}). This prevents keyword-stuffing
// attacks where a synthetic beacon includes runtime words without actual data.
func bodyContainsRuntimePayload(body string) bool {
	if body == "" {
		return false
	}

	runtimeKeywords := []string{
		"navigator", "webgl", "canvas", "timing", "behavior", "audio",
		"webrtc", "plugins", "screen", "fonts",
	}

	// Try JSON-aware check first: parse the body and look for runtime keywords
	// as exact JSON keys at any level of the object hierarchy.
	body = strings.TrimSpace(body)
	if len(body) > 0 && body[0] == '{' {
		var parsed map[string]json.RawMessage
		if json.Unmarshal([]byte(body), &parsed) == nil {
			if jsonContainsRuntimeKeys(parsed, runtimeKeywords, 0) {
				return true
			}
			// If we successfully parsed JSON but found no standalone runtime
			// keys, the body is keyword-stuffing — return false.
			return false
		}
	}

	// Non-JSON body: fall back to substring matching.
	lower := strings.ToLower(body)
	for _, keyword := range runtimeKeywords {
		if strings.Contains(lower, keyword) {
			return true
		}
	}

	return false
}

// jsonContainsRuntimeKeys recursively searches a JSON object for keys that
// exactly match runtime keywords. Compound keys like "navigator_entropy" do
// NOT match "navigator" — only exact key matches count.
func jsonContainsRuntimeKeys(obj map[string]json.RawMessage, keywords []string, depth int) bool {
	if depth > 3 {
		return false // limit recursion
	}
	for key, val := range obj {
		lowerKey := strings.ToLower(key)
		for _, kw := range keywords {
			if lowerKey == kw {
				return true
			}
		}
		// Recurse into nested objects
		var nested map[string]json.RawMessage
		if json.Unmarshal(val, &nested) == nil {
			if jsonContainsRuntimeKeys(nested, keywords, depth+1) {
				return true
			}
		}
	}
	return false
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
		captchaSecret:        secret,
		solvedTokens:         make(map[string]time.Time),
		v3Assessments:        make([]*V3AssessmentRecord, 0, 100),
		v3MaxRecords:         100,
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
	vec.CheckReports = make([]CheckReport, 0, len(indicators))

	// Score missing headers
	for _, missing := range info.MissingHeaders {
		weight := scoreForHTTPIndicator(missing)
		vec.Score += weight
		vec.CheckReports = append(vec.CheckReports, buildHTTPCheckReport(missing, weight, info))
	}

	// Score suspicious headers with severity-based weights
	for _, s := range info.SuspiciousHeaders {
		weight := scoreForHTTPIndicator(s)
		vec.Score += weight
		vec.CheckReports = append(vec.CheckReports, buildHTTPCheckReport(s, weight, info))
	}

	if vec.Score > 1.0 {
		vec.Score = 1.0
	}

	vec.Detected = vec.Score > 0.3

	return vec
}

func scoreForHTTPIndicator(indicator string) float64 {
	switch {
	case strings.HasPrefix(indicator, "suspicious_ua_"):
		return constants.SeverityHigh
	case indicator == "missing_user_agent":
		return constants.SeverityHigh
	case indicator == "webdriver_exposed":
		return constants.SeverityHigh
	case indicator == "chrome_navigation_missing_client_hints":
		return constants.SeverityHigh
	case indicator == "firefox_navigation_priority_header":
		return constants.SeverityHigh
	case indicator == "firefox_chromium_priority_signature":
		return constants.SeverityHigh
	case indicator == "Sec-Ch-Ua*":
		return constants.SeverityHigh
	case strings.HasPrefix(indicator, "browser_with_multiple_proxy_ip_headers"):
		return 0.40 // Stronger than SeverityHigh — 3+ proxy IP headers from a browser is definitive
	case indicator == "Sec-Fetch-*":
		return constants.SeverityMedium
	case indicator == "too_few_headers":
		return constants.SeverityMedium
	case indicator == "generic_accept_header":
		return constants.SeverityLow
	case indicator == "Accept":
		return constants.SeverityLow
	case indicator == "Accept-Language":
		return constants.SeverityLow
	default:
		return 0.2
	}
}

func buildHTTPCheckReport(indicator string, weight float64, info *HTTPFingerprintInfo) CheckReport {
	report := CheckReport{
		Name:        indicator,
		Fired:       true,
		Weight:      weight,
		Score:       weight,
		Severity:    severityFromScore(weight),
		Description: "HTTP fingerprint anomaly",
	}

	switch indicator {
	case "Accept":
		report.Field = "Accept"
		report.Actual = info.Accept
		report.Expected = "non-empty browser accept header"
		report.Description = "The request is missing the standard Accept header used by browsers."
	case "Accept-Language":
		report.Field = "Accept-Language"
		report.Actual = info.AcceptLanguage
		report.Expected = "locale-aware browser language header"
		report.Description = "The request is missing Accept-Language, which is unusual for real browsers."
	case "Sec-Fetch-*":
		report.Field = "Sec-Fetch-*"
		report.Actual = strings.Join([]string{info.SecFetchDest, info.SecFetchMode, info.SecFetchSite}, "|")
		report.Expected = "document|navigate|none-style navigation metadata"
		report.Description = "Chrome-class browsers should include coherent Sec-Fetch navigation metadata."
	case "Sec-Ch-Ua*":
		report.Field = "Sec-CH-UA"
		report.Actual = strings.Join([]string{info.SecCHUA, info.SecCHUAPlatform, info.SecCHUAMobile}, "|")
		report.Expected = "Chrome-class client hints present"
		report.Description = "The request claims a Chromium browser but omits required client hints."
	case "chrome_navigation_missing_client_hints":
		report.Field = "User-Agent/Sec-CH-UA"
		report.Actual = info.UserAgent
		report.Expected = "Chrome navigation with client hints"
		report.Description = "A Chromium navigation without client hints is strongly indicative of spoofed headers."
	case "firefox_navigation_priority_header":
		report.Field = "Priority"
		report.Actual = "present"
		report.Expected = "absent for simple Firefox-style top-level navigation"
		report.Description = "The Firefox-style request carries Chromium-like priority metadata without other browser context."
	case "firefox_chromium_priority_signature":
		report.Field = "Priority"
		report.Actual = "contains ', i'"
		report.Expected = "Firefox-style request without Chromium incremental priority signature"
		report.Description = "The Priority header uses a Chromium-style incremental scheduling signature on a Firefox-claimed request."
	case "generic_accept_header":
		report.Field = "Accept"
		report.Actual = info.Accept
		report.Expected = "browser navigation accept header with negotiated content types"
		report.Description = "A generic */* Accept header is common in bots and uncommon on top-level browser navigations."
	case "too_few_headers":
		report.Field = "header_count"
		report.Actual = fmt.Sprintf("%d", info.HeaderCount)
		report.Expected = ">= 5"
		report.Description = "The request includes too few headers for a normal browser navigation."
	case "missing_user_agent":
		report.Field = "User-Agent"
		report.Actual = info.UserAgent
		report.Expected = "browser user agent"
		report.Description = "Missing User-Agent is a strong automation signal."
	case "webdriver_exposed":
		report.Field = "X-Navigator-Webdriver"
		report.Actual = "true"
		report.Expected = "absent or false"
		report.Description = "The request directly exposes navigator.webdriver."
	default:
		if strings.HasPrefix(indicator, "suspicious_ua_") {
			report.Field = "User-Agent"
			report.Actual = info.UserAgent
			report.Expected = "browser user agent without automation keywords"
			report.Description = "The User-Agent contains automation-specific keywords."
		}
	}

	return report
}

func calculateVectorConfidence(vec *DetectionVector) float64 {
	if vec == nil || vec.Score <= 0 {
		return 0
	}

	firedChecks := 0
	highSeverityChecks := 0
	severitySum := 0.0
	maxCheckWeight := 0.0
	distinctFields := make(map[string]struct{})

	if len(vec.CheckReports) > 0 {
		for _, check := range vec.CheckReports {
			if !check.Fired {
				continue
			}
			firedChecks++
			if check.Weight > maxCheckWeight {
				maxCheckWeight = check.Weight
			}
			if check.Field != "" {
				distinctFields[check.Field] = struct{}{}
			}

			switch strings.ToLower(check.Severity) {
			case "critical":
				severitySum += 1.0
				highSeverityChecks++
			case "high":
				severitySum += 0.85
				highSeverityChecks++
			case "medium":
				severitySum += 0.60
			default:
				severitySum += 0.35
			}
		}
	} else {
		firedChecks = len(vec.Indicators)
		maxCheckWeight = vec.Score
		switch severityFromScore(vec.Score) {
		case "critical":
			severitySum = 1.0
			highSeverityChecks = 1
		case "high":
			severitySum = 0.85
			highSeverityChecks = 1
		case "medium":
			severitySum = 0.60
		default:
			severitySum = 0.35
		}
	}

	if maxCheckWeight == 0 {
		maxCheckWeight = vec.Weight
	}
	if firedChecks == 0 {
		firedChecks = len(vec.Indicators)
	}

	evidenceRatio := minFloat(1.0, float64(firedChecks)/3.0)
	severityRatio := minFloat(1.0, severitySum/maxFloat(1.0, float64(firedChecks)))
	weightRatio := minFloat(1.0, maxFloat(vec.Weight, maxCheckWeight))

	confidence := 0.45*vec.Score + 0.20*evidenceRatio + 0.15*severityRatio + 0.10*weightRatio
	if vec.Detected {
		confidence += 0.10
	}
	if len(distinctFields) >= 2 || firedChecks >= 2 {
		confidence += 0.10
	}
	if highSeverityChecks >= 2 {
		confidence += 0.07
	}
	if isHighSignalCategory(vec.Category) && vec.Score >= constants.SeverityHigh {
		confidence += 0.10
	} else if isHighSignalCategory(vec.Category) && vec.Score >= constants.SeverityMedium {
		confidence += 0.05
	}
	if firedChecks == 1 && isHighSignalCategory(vec.Category) && vec.Score >= 0.45 {
		confidence += 0.08
	}

	return minFloat(1.0, confidence)
}

func calculateDetectionConfidence(detection *StealthDetection) float64 {
	if detection == nil {
		return 0
	}

	activeVectors := 0
	strongVectors := 0
	totalVectorConfidence := 0.0
	maxVectorConfidence := 0.0
	corroboratingCategories := make(map[string]struct{})

	for _, vec := range detection.Vectors {
		if vec.Score <= 0 {
			continue
		}
		activeVectors++
		totalVectorConfidence += vec.Confidence
		if vec.Confidence > maxVectorConfidence {
			maxVectorConfidence = vec.Confidence
		}
		if vec.Confidence >= 0.75 || vec.Score >= 0.50 {
			strongVectors++
			corroboratingCategories[vec.Category] = struct{}{}
		}
	}

	if activeVectors == 0 {
		return minFloat(1.0, detection.Score)
	}

	avgVectorConfidence := totalVectorConfidence / float64(activeVectors)
	confidence := 0.45*detection.Score + 0.35*avgVectorConfidence + 0.20*maxVectorConfidence

	if detection.IsBot {
		if len(corroboratingCategories) >= 2 {
			confidence += 0.10
		}
		if strongVectors >= 2 {
			confidence += 0.08
		}
		if maxVectorConfidence >= 0.85 {
			confidence += 0.12
		} else if maxVectorConfidence >= 0.70 {
			confidence += 0.10
		}
		if activeVectors >= 3 {
			confidence += 0.05
		}
		if activeVectors == 1 && detection.Score >= 0.45 {
			confidence += 0.08
		}
		if detection.Score >= 0.45 {
			confidence += 0.08
		}
	} else {
		maxAllowed := detection.Score + 0.05
		if activeVectors > 1 {
			maxAllowed += 0.05
		}
		confidence = minFloat(confidence, maxAllowed)
	}

	return minFloat(1.0, confidence)
}

func isHighSignalCategory(category string) bool {
	switch category {
	case string(VectorHTTP), string(VectorTLS), string(VectorNavigator), string(VectorIsomorphic),
		string(VectorAutomation), string(VectorBehavioral), string(VectorCrossVector),
		string(VectorFingerprintCoverage):
		return true
	default:
		return false
	}
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
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
