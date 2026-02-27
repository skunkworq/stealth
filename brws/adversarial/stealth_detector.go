package adversarial

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/stealth/brwslab/brws/constants"
)

type StealthDetector struct {
	mu         sync.RWMutex
	detections []StealthDetection
	baselines  map[string]*StealthBaseline
	config     *DetectorConfig
}

type DetectorConfig struct {
	ThresholdBot          float64 `json:"threshold_bot"`
	ThresholdSuspicious   float64 `json:"threshold_suspicious"`
	EnableTLSAnalysis     bool    `json:"enable_tls_analysis"`
	EnableNavigatorCheck  bool    `json:"enable_navigator_check"`
	EnableTimingCheck     bool    `json:"enable_timing_check"`
	EnableCanvasCheck     bool    `json:"enable_canvas_check"`
	EnableBehavioralCheck bool    `json:"enable_behavioral_check"`
}

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

type IsomorphicCheckInfo struct {
	PlatformMismatch   bool     `json:"platform_mismatch"`
	ExecutionMismatch  bool     `json:"execution_mismatch"`
	SuspiciousPatterns []string `json:"suspicious_patterns"`
}

type DetectionVector struct {
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Score       float64  `json:"score"`
	Weight      float64  `json:"weight"`
	Detected    bool     `json:"detected"`
	Description string   `json:"description"`
	Indicators  []string `json:"indicators"`
}

type StealthIndicator struct {
	Vector   string  `json:"vector"`
	Name     string  `json:"name"`
	Severity float64 `json:"severity"`
	Message  string  `json:"message"`
	RawData  string  `json:"raw_data,omitempty"`
}

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
}

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

type StealthBaseline struct {
	Browser        string   `json:"browser"`
	JA4            string   `json:"ja4"`
	UserAgent      string   `json:"user_agent"`
	Platform       string   `json:"platform"`
	NavigatorProps []string `json:"navigator_props"`
}

var knownJA4Signatures = map[string]string{
	"t13d": "Chrome 120+ macOS",
	"t13c": "Chrome 120+ Windows",
	"t13b": "Chrome 120+ Linux",
	"q20d": "Firefox 120+",
	"r20a": "Safari 17+",
}

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
		},
	}
}

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

	// 1. TLS Fingerprint Analysis
	if sd.config.EnableTLSAnalysis && tlsConn != nil {
		tlsInfo := sd.analyzeTLSFingerprint(tlsConn)
		detection.TLSFingerprint = tlsInfo
		tlsVec := sd.tlsInfoToVector(tlsInfo)
		detection.Vectors = append(detection.Vectors, tlsVec)
		totalScore += tlsVec.Score * tlsVec.Weight
		totalWeight += tlsVec.Weight
	}

	// 2. HTTP Header Analysis
	httpInfo := sd.analyzeHTTPHeaders(req)
	detection.HTTPHeaders = httpInfo
	httpVec := sd.httpInfoToVector(httpInfo)
	detection.Vectors = append(detection.Vectors, httpVec)
	totalScore += httpVec.Score * httpVec.Weight
	totalWeight += httpVec.Weight

	// 3. Navigator Properties Analysis (from injected scripts)
	if sd.config.EnableNavigatorCheck {
		navVec := sd.analyzeNavigatorData(req)
		if navVec != nil {
			detection.NavigatorData = &NavigatorCheckInfo{}
			detection.Vectors = append(detection.Vectors, *navVec)
			totalScore += navVec.Score * navVec.Weight
			totalWeight += navVec.Weight
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
		}
	}

	// 5. Timing Analysis
	if sd.config.EnableTimingCheck {
		timingVec := sd.analyzeTimingData(req)
		if timingVec != nil {
			detection.TimingData = &TimingCheckInfo{}
			detection.Vectors = append(detection.Vectors, *timingVec)
			totalScore += timingVec.Score * timingVec.Weight
			totalWeight += timingVec.Weight
			totalWeight += timingVec.Weight
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
		}
	}

	// 7. Isomorphic Cross-Validation
	isomorphicVec := sd.analyzeIsomorphicAnomalies(req, httpInfo)
	if isomorphicVec != nil {
		// Mirror it into the struct for ML Tracing transparency
		if isomorphicVec.Score > 0 {
			detection.IsomorphicData = &IsomorphicCheckInfo{
				PlatformMismatch:   true,
				SuspiciousPatterns: isomorphicVec.Indicators,
			}
			// Only append the vector and dilute the weight if there actually are Franken-anomalies
			// This transforms it into an aggressive penalty without artificially inflating the base benign denominator
			detection.Vectors = append(detection.Vectors, *isomorphicVec)
			totalScore += isomorphicVec.Score * isomorphicVec.Weight
			totalWeight += isomorphicVec.Weight
		}
	}

	// Calculate final score
	if totalWeight > 0 {
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

	// Check for missing headers
	requiredHeaders := []string{"Accept", "Accept-Language"}
	for _, h := range requiredHeaders {
		if req.Header.Get(h) == "" {
			info.MissingHeaders = append(info.MissingHeaders, h)
		}
	}

	// Check Client Hints consistency
	info.ClientHintsConsistent = sd.checkClientHintsConsistency(info)

	if !info.ClientHintsConsistent {
		info.SuspiciousHeaders = append(info.SuspiciousHeaders, "inconsistent_client_hints")
	}

	// Check for missing Client Hints
	if info.SecCHUA == "" || info.SecCHUAPlatform == "" {
		info.MissingHeaders = append(info.MissingHeaders, "Sec-Ch-Ua*")
	}

	vec := DetectionVector{
		Name:        "HTTP Headers",
		Category:    "http",
		Weight:      constants.WeightHTTP,
		Description: "Analyzes HTTP headers for browser fingerprint consistency",
	}

	vec.Score = float64(len(info.MissingHeaders)) * constants.SeverityLow
	if len(info.SuspiciousHeaders) > 0 {
		vec.Score += float64(len(info.SuspiciousHeaders)) * 0.2
	}

	if vec.Score > 0 {
		vec.Detected = true
		vec.Indicators = append(info.MissingHeaders, info.SuspiciousHeaders...)
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

	// Check chrome.runtime
	if _, ok := navData["chrome"]; !ok {
		indicators = append(indicators, "missing_chrome_runtime")
		vec.Score += 0.2
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

	vec.Indicators = indicators
	vec.Detected = vec.Score > 0.3

	return vec
}

func (sd *StealthDetector) analyzeCanvasData(req *http.Request) *DetectionVector {
	canvasHeader := req.Header.Get(constants.HeaderCanvasFingerprint)
	if canvasHeader == "" {
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
		// These are common real browser fingerprints
	} else if strings.Contains(canvasHeader, "unknown") {
		indicators = append(indicators, "masked_webgl")
		vec.Score += 0.3
	}

	vec.Indicators = indicators
	vec.Detected = vec.Score > 0.3

	return vec
}

func (sd *StealthDetector) analyzeTimingData(req *http.Request) *DetectionVector {
	// Check for timing data passed via headers (from injected scripts)
	timingHeader := req.Header.Get(constants.HeaderTimingData)
	if timingHeader == "" {
		return nil
	}

	vec := &DetectionVector{
		Name:        "Timing Anomalies",
		Category:    "timing",
		Weight:      constants.WeightTLS,
		Description: "Analyzes timing patterns for automation detection",
	}

	indicators := make([]string, 0)

	var timing map[string]interface{}
	if err := json.Unmarshal([]byte(timingHeader), &timing); err != nil {
		return nil
	}

	// Check for zero TTFB
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
		return nil
	}

	vec := &DetectionVector{
		Name:        "Behavioral Patterns",
		Category:    "behavioral",
		Weight:      0.2,
		Description: "Analyzes user interaction patterns for automation",
	}

	indicators := make([]string, 0)

	var behav map[string]interface{}
	if err := json.Unmarshal([]byte(behavHeader), &behav); err != nil {
		return nil
	}

	// Check for zero variance (mechanical movement)
	if mouseStdDev, ok := behav["mouseStdDev"].(float64); ok && mouseStdDev == 0 {
		indicators = append(indicators, "zero_mouse_variance")
		vec.Score += 0.4
	}

	// Check for perfect typing (no human pacing)
	if typingStdDev, ok := behav["typingStdDev"].(float64); ok && typingStdDev == 0 {
		indicators = append(indicators, "zero_typing_variance")
		vec.Score += 0.3
	}

	// Check for perfectly static delays between overall events
	if eventTimingDev, ok := behav["eventTimingStdDev"].(float64); ok && eventTimingDev == 0 {
		indicators = append(indicators, "perfect_event_pacing")
		vec.Score += 0.4
	}

	// Check for suspiciously few events
	if mouseEvents, ok := behav["mouseEvents"].(float64); ok && mouseEvents < 5 {
		indicators = append(indicators, "too_few_mouse_events")
		vec.Score += 0.2
	}

	// Check for linear movement (no randomness)
	if _, ok := behav["mousePathLength"].(float64); ok {
		if straightness, ok := behav["mouseStraightness"].(float64); ok && straightness > 0.95 {
			indicators = append(indicators, "linear_mouse_movement")
			vec.Score += 0.3
		}
	}

	vec.Indicators = indicators
	vec.Detected = vec.Score > 0.3

	return vec
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
			isMacHttp := strings.Contains(httpPlatform, "mac") || strings.Contains(httpPlatform, "darwin")
			isWinHttp := strings.Contains(httpPlatform, "win")
			
			isMacNav := strings.Contains(navPlatLow, "mac")
			isWinNav := strings.Contains(navPlatLow, "win")
			
			if (isMacHttp && !isMacNav) || (isWinHttp && !isWinNav) {
				indicators = append(indicators, "platform_mismatch: http_vs_navigator_platform")
				vec.Score += 0.8
			}
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

func (sd *StealthDetector) GetDetections() []StealthDetection {
	sd.mu.RLock()
	defer sd.mu.RUnlock()
	return sd.detections
}

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

type AdvancedStealthServer struct {
	*StealthDetector

	Server *TestServer
}

func NewAdvancedStealthServer() *AdvancedStealthServer {
	detector := NewStealthDetector()
	testServer := NewTestServer()

	return &AdvancedStealthServer{
		StealthDetector: detector,
		Server:          testServer,
	}
}

func (as *AdvancedStealthServer) HandleRequest(w http.ResponseWriter, r *http.Request) {
	var tlsConn *tls.ConnectionState
	if r.TLS != nil {
		tlsConn = r.TLS
	}

	detection := as.AnalyzeRequest(r, tlsConn)

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

	if detection.IsBot || detection.IsStealth {
		response["detection_type"] = "stealth"

		// Phase 10: Inject explicit Adversarial Shield headers to organically trigger
		// the FSM Client Adapting sequence for validation
		w.Header().Set("X-Datadome", "1")
		w.WriteHeader(http.StatusForbidden)

		if detection.IsStealth {
			response["message"] = "Stealth browser automation detected"
		} else {
			response["message"] = "Bot detected"
		}
	} else {
		// Only write 200 OK if we passed the shield
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

	vec.Score = float64(len(info.MissingHeaders)) * constants.SeverityLow
	if len(info.SuspiciousHeaders) > 0 {
		vec.Score += float64(len(info.SuspiciousHeaders)) * 0.2
	}

	vec.Detected = vec.Score > 0

	return vec
}

var chromeHeaderOrder = []string{
	":method", ":authority", ":path", "accept", "accept-encoding",
	"accept-language", "cache-control", "content-type", "content-length",
	"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
	"sec-ch-ua-arch", "sec-ch-ua-bitness", "sec-ch-ua-full-version",
	"sec-ch-ua-model", "sec-ch-ua-platform-version", "sec-ch-ua-wow64",
	"sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
	"upgrade-insecure-requests", "user-agent",
}

var goHeaderOrder = []string{
	"accept-encoding", "user-agent", "accept",
}

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
