package detection

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/skunkworq/stealth/brws/core/constants"
	"github.com/skunkworq/stealth/brws/core/types"
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
	navAnalyzer      *navigatorAnalyzer
	isoAnalyzer      *IsomorphicAnalyzer
	behavAnalyzer    *BehavioralAnalyzer
	timingAnalyzer   *TimingAnalyzer
	graphicsAnalyzer *graphicsAnalyzer
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
		navAnalyzer:      newNavigatorAnalyzer(),
		isoAnalyzer:      NewIsomorphicAnalyzer(),
		behavAnalyzer:    NewBehavioralAnalyzer(nil),
		timingAnalyzer:   NewTimingAnalyzer(nil),
		graphicsAnalyzer: newGraphicsAnalyzer(),
	}
}

// AnalyzeRequest performs comprehensive stealth detection analysis on an HTTP request,
// examining TLS state, headers, and embedded fingerprint data.
func (sd *StealthDetector) AnalyzeRequest(req *http.Request, tlsConn *tls.ConnectionState) *StealthDetection {
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
	vectorResults := make(map[VectorCategory]*VectorResult)

	// TLS fingerprint analysis has a unique signature (takes tlsConn, not *http.Request).
	if sd.config.EnableTLSAnalysis && tlsConn != nil {
		tlsInfo := sd.analyzeTLSFingerprint(tlsConn)
		detection.TLSFingerprint = tlsInfo
		tlsVec := sd.tlsInfoToVector(tlsInfo)
		detection.Vectors = append(detection.Vectors, tlsVec)
		totalScore += tlsVec.Score * tlsVec.Weight
		totalWeight += tlsVec.Weight
		vectorResults[VectorTLS] = &VectorResult{Score: tlsVec.Score, Detected: tlsVec.Detected}
	}

	// HTTP header analysis always runs; its result feeds the TLS cross-check and isomorphic analysis.
	httpInfo := sd.analyzeHTTPHeaders(req)
	detection.HTTPHeaders = httpInfo

	// TLS × User-Agent cross-check: browser UA without GREASE is a strong spoofing signal.
	if detection.TLSFingerprint != nil && httpInfo != nil {
		ua := strings.ToLower(httpInfo.UserAgent)
		isBrowser := strings.Contains(ua, "chrome") || strings.Contains(ua, "firefox") || strings.Contains(ua, "safari")
		if isBrowser && !detection.TLSFingerprint.HasGREASE {
			detection.TLSFingerprint.Anomalies = append(detection.TLSFingerprint.Anomalies, "tls_go_fingerprint: browser_ua_with_go_tls")
			for i, v := range detection.Vectors {
				if v.Category == "tls" {
					detection.Vectors[i].Score = 0.50
					detection.Vectors[i].Detected = true
					detection.Vectors[i].Indicators = detection.TLSFingerprint.Anomalies
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

	// All remaining analysers are dispatched via a uniform loop.
	// Entries with enabled == nil or requireScore == false follow relaxed inclusion rules
	// that match the original per-step logic (see analyserEntry doc).
	entries := []analyserEntry{
		{category: VectorNavigator, enabled: &sd.config.EnableNavigatorCheck,
			analyze:  sd.analyzeNavigatorData,
			onResult: func(d *StealthDetection, _ *DetectionVector) { d.NavigatorData = &NavigatorCheckInfo{} }},
		{category: VectorCanvas, enabled: &sd.config.EnableCanvasCheck,
			analyze:  sd.analyzeCanvasData,
			onResult: func(d *StealthDetection, _ *DetectionVector) { d.CanvasData = &CanvasCheckInfo{} }},
		{category: VectorWebGL, enabled: &sd.config.EnableWebGLCheck,
			analyze: sd.analyzeWebGLData},
		{category: VectorTiming, enabled: &sd.config.EnableTimingCheck,
			analyze:  sd.analyzeTimingData,
			onResult: func(d *StealthDetection, _ *DetectionVector) { d.TimingData = &TimingCheckInfo{} }},
		{category: VectorBehavioral, enabled: &sd.config.EnableBehavioralCheck,
			analyze:  sd.analyzeBehavioralData,
			onResult: func(d *StealthDetection, _ *DetectionVector) { d.BehavioralData = &BehavioralCheckInfo{} }},
		// Isomorphic needs httpInfo from above; requireScore mirrors original "if score > 0" guard.
		{category: VectorIsomorphic, requireScore: true,
			analyze: func(r *http.Request) *DetectionVector { return sd.analyzeIsomorphicAnomalies(r, httpInfo) },
			onResult: func(d *StealthDetection, v *DetectionVector) {
				d.IsomorphicData = &IsomorphicCheckInfo{PlatformMismatch: true, SuspiciousPatterns: v.Indicators}
			}},
		// Hardware and IP have no named VectorCategory (empty → skipped in vectorResults map).
		{requireScore: true, analyze: sd.analyzeHardwareExecution},
		{enabled: &sd.config.EnableIPCheck, requireScore: true, analyze: sd.analyzeIPClassification},
		{category: VectorAutomation, enabled: &sd.config.EnableAutomationCheck, requireScore: true,
			analyze: sd.analyzeAutomationSignals},
		{category: VectorHeadless, enabled: &sd.config.EnableHeadlessCheck, requireScore: true,
			analyze: sd.analyzeHeadlessSignals},
		{category: VectorWebRTC, enabled: &sd.config.EnableWebRTCCheck, requireScore: true,
			analyze: sd.analyzeWebRTCData},
		// HTTP/2 also requires the request to be HTTP/2.
		{category: VectorHTTP2, enabled: &sd.config.EnableHTTP2Check, requireScore: true,
			guard:   func(r *http.Request) bool { return r.Proto == "HTTP/2.0" },
			analyze: sd.analyzeHTTP2Signals},
		{category: VectorFont, enabled: &sd.config.EnableFontCheck, requireScore: true,
			analyze: sd.analyzeFontData},
		{category: VectorScreen, enabled: &sd.config.EnableScreenCheck, requireScore: true,
			analyze: sd.analyzeScreenData},
		{category: VectorPlugin, enabled: &sd.config.EnablePluginCheck, requireScore: true,
			analyze: sd.analyzePluginData},
		{category: VectorAudio, enabled: &sd.config.EnableAudioCheck, requireScore: true,
			analyze: sd.analyzeAudioData},
		{category: VectorFingerprintCoverage, requireScore: true, analyze: sd.analyzeFingerprintCoverage},
		{category: VectorCrossVector, requireScore: true, analyze: sd.analyzeCrossVectorConsistency},
	}

	for _, e := range entries {
		if e.enabled != nil && !*e.enabled {
			continue
		}
		if e.guard != nil && !e.guard(req) {
			continue
		}
		vec := e.analyze(req)
		if vec == nil || (e.requireScore && vec.Score == 0) {
			continue
		}
		if e.onResult != nil {
			e.onResult(&detection, vec)
		}
		detection.Vectors = append(detection.Vectors, *vec)
		totalScore += vec.Score * vec.Weight
		totalWeight += vec.Weight
		if e.category != "" {
			vectorResults[e.category] = &VectorResult{Score: vec.Score, Detected: vec.Detected}
		}
	}

	for i := range detection.Vectors {
		detection.Vectors[i].Confidence = calculateVectorConfidence(&detection.Vectors[i])
	}
	for _, v := range detection.Vectors {
		for _, indName := range v.Indicators {
			detection.Indicators = append(detection.Indicators, StealthIndicator{
				Vector:   v.Name,
				Name:     indName,
				Severity: v.Score,
				Message:  fmt.Sprintf("%s indicator: %s", v.Name, indName),
			})
		}
	}

	if sd.config.EnableAdaptiveScoring && sd.adaptiveScorer != nil && len(vectorResults) > 0 {
		ensemble := sd.adaptiveScorer.ScoreResults(vectorResults)
		detection.Score = ensemble.FinalScore
	} else if totalWeight > 0 {
		detection.Score = totalScore / totalWeight
	}

	detection.IsBot = detection.Score >= sd.config.ThresholdBot
	detection.Confidence = calculateDetectionConfidence(&detection)
	detection.IsStealth = sd.detectStealthBrowser(&detection)

	sd.mu.Lock()
	sd.detections = append(sd.detections, detection)
	sd.mu.Unlock()

	return &detection
}

// AnalyzeRequestWithTLS performs comprehensive stealth detection with deep TLS
// fingerprint analysis from a parsed ClientHello. Use this when you have access
// to the raw TLS handshake data (e.g., via CapturingListener).
func (sd *StealthDetector) AnalyzeRequestWithTLS(req *http.Request, tlsFP *types.TLSFingerprint) *StealthDetection {
	// Run standard analysis without TLS connection state
	detection := sd.AnalyzeRequest(req, nil)

	if tlsFP == nil {
		return detection
	}

	// Determine claimed browser from UA
	claimedBrowser := ""
	if req != nil {
		ua := strings.ToLower(req.Header.Get("User-Agent"))
		if strings.Contains(ua, "chrome") {
			claimedBrowser = "chrome"
		} else if strings.Contains(ua, "firefox") {
			claimedBrowser = "firefox"
		}
	}

	// Run deep TLS analysis
	deepAnalysis := AnalyzeTLSDeep(tlsFP, claimedBrowser)
	if deepAnalysis == nil {
		return detection
	}

	// Build TLS vector from deep analysis
	tlsVec := DetectionVector{
		Name:        "TLS Fingerprint (Deep)",
		Category:    "tls",
		Weight:      constants.WeightTLS,
		Description: "Deep TLS ClientHello analysis against browser baselines",
		Score:       deepAnalysis.BotScore,
		Detected:    deepAnalysis.BotScore >= 0.35,
		Indicators:  deepAnalysis.Indicators,
	}

	// Store TLS info
	detection.TLSFingerprint = &TLSFingerprintInfo{
		JA4:        tlsFP.JA4,
		JA3:        tlsFP.JA3String,
		TLSVersion: fmt.Sprintf("0x%04x", tlsFP.Version),
		HasGREASE:  len(tlsFP.GREASE) > 0,
		HasALPS:    hasExtension(tlsFP, 0x44cd),
		Anomalies:  deepAnalysis.Anomalies,
	}

	// Replace or add TLS vector
	replaced := false
	for i, v := range detection.Vectors {
		if v.Category == "tls" {
			detection.Vectors[i] = tlsVec
			replaced = true
			break
		}
	}
	if !replaced {
		detection.Vectors = append(detection.Vectors, tlsVec)
	}

	// Re-run adaptive scoring with new TLS vector
	if sd.config.EnableAdaptiveScoring && sd.adaptiveScorer != nil {
		vectorResults := make(map[VectorCategory]*VectorResult)
		for _, v := range detection.Vectors {
			cat := categoryFromString(v.Category)
			vectorResults[cat] = &VectorResult{Score: v.Score, Detected: v.Detected}
		}

		adaptiveResult := sd.adaptiveScorer.ScoreResults(vectorResults)
		detection.Score = adaptiveResult.FinalScore
		detection.IsBot = adaptiveResult.FinalScore >= sd.config.ThresholdBot
		detection.IsStealth = sd.detectStealthBrowser(detection)
		detection.Confidence = calculateDetectionConfidence(detection)
	}

	return detection
}

// categoryFromString converts a category string back to VectorCategory.
func categoryFromString(s string) VectorCategory {
	switch s {
	case "tls":
		return VectorTLS
	case "http":
		return VectorHTTP
	case "navigator":
		return VectorNavigator
	case "canvas":
		return VectorCanvas
	case "timing":
		return VectorTiming
	case "behavioral":
		return VectorBehavioral
	case "webgl":
		return VectorWebGL
	default:
		return VectorHTTP
	}
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

	return &DetectionVector{
		Name:        "Font Analysis",
		Category:    string(VectorFont),
		Score:       result.Score,
		Weight:      constants.WeightFont,
		Detected:    result.Detected,
		Description: "Font enumeration and platform consistency analysis",
		Indicators:  indicatorChecks(result.Indicators),
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

	return &DetectionVector{
		Name:        "Screen Analysis",
		Category:    string(VectorScreen),
		Score:       result.Score,
		Weight:      constants.WeightScreen,
		Detected:    result.Detected,
		Description: "Screen geometry and display configuration analysis",
		Indicators:  indicatorChecks(result.Indicators),
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

	return &DetectionVector{
		Name:        "Plugin Analysis",
		Category:    string(VectorPlugin),
		Score:       result.Score,
		Weight:      constants.WeightPlugin,
		Detected:    result.Detected,
		Description: "Browser plugin enumeration and consistency analysis",
		Indicators:  indicatorChecks(result.Indicators),
	}
}

// analyzeAudioData checks for AudioContext fingerprint data.
// If the header is entirely missing, returns a high score since real browsers
// always have AudioContext available. If present, delegates to audioAnalyzer.
func (sd *StealthDetector) analyzeAudioData(req *http.Request) *DetectionVector {
	audioHeader := req.Header.Get(constants.HeaderAudioData)
	if audioHeader == "" {
		// Only penalize if other JS-sourced fingerprint headers are present,
		// proving the client has a JS context but omitted audio data.
		if hasJSFingerprintHeaders(req) {
			return missingHeaderVector("Audio Analysis", string(VectorAudio), "missing_audio_data",
				0.45, constants.WeightAudio, "AudioContext fingerprint missing (client has JS context but no AudioContext)")
		}
		return nil
	}

	var data audioData
	if err := json.Unmarshal([]byte(audioHeader), &data); err != nil {
		return nil
	}

	analyzer := newAudioAnalyzer()
	result := analyzer.Analyze(&data)

	return &DetectionVector{
		Name:        "Audio Analysis",
		Category:    string(VectorAudio),
		Score:       result.Score,
		Weight:      constants.WeightAudio,
		Detected:    result.Detected,
		Description: "AudioContext fingerprint analysis",
		Indicators:  indicatorChecks(result.Indicators),
	}
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
			return missingHeaderVector("Timing Anomalies", string(VectorTiming), "missing_timing_data",
				0.40, constants.WeightTiming, "Resource timing data missing (client has JS context but no Performance API entries)")
		}
		return nil
	}

	var timingData map[string]interface{}
	if err := json.Unmarshal([]byte(timingHeader), &timingData); err != nil {
		return nil
	}

	seq := NewRequestTimingSequenceFromMap(timingData)
	result := sd.timingAnalyzer.Analyze(seq)

	return &DetectionVector{
		Name:        "Timing Anomalies",
		Category:    "timing",
		Weight:      constants.WeightTiming,
		Description: "Analyzes timing patterns for automation detection",
		Score:       result.Score,
		Detected:    result.Detected,
		Indicators:  indicatorChecks(result.Indicators),
	}
}

func (sd *StealthDetector) analyzeBehavioralData(req *http.Request) *DetectionVector {
	behavHeader := req.Header.Get(constants.HeaderBehavioralData)
	if behavHeader == "" {
		if hasJSFingerprintHeaders(req) {
			return missingHeaderVector("Behavioral Patterns", string(VectorBehavioral), "missing_behavioral_data",
				0.50, constants.WeightBehavioral, "Behavioral data missing (client has JS context but no mouse/keyboard events)")
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
		Indicators:  indicatorChecks(result.Indicators),
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

	ctx := newCrossVecCtx(req)

	checks := []func(*http.Request, crossVecCtx) crossVecResult{
		sd.cvCheckBehavioralTiming,
		sd.cvCheckMouseViewport,
		sd.cvCheckNoneContextProvenance,
		sd.cvCheckSameSiteProvenance,
		sd.cvCheckCrossSiteProvenance,
		sd.cvCheckNoCORSProvenance,
		sd.cvCheckDocumentNavigation,
		sd.cvCheckSameOriginTelemetry,
		sd.cvCheckFetchMetadataConsistency,
		sd.cvCheckCrossSiteBrowserPost,
		sd.cvCheckExoticDest,
	}
	for _, fn := range checks {
		r := fn(req, ctx)
		vec.Score += r.score
		vec.Indicators = append(vec.Indicators, r.indicators...)
		vec.CheckReports = append(vec.CheckReports, r.reports...)
	}
	// Catch-all only fires when no gate-specific check has scored ≥ 0.35.
	if vec.Score < 0.35 {
		r := sd.cvCheckZeroHeaderCatchAll(req, ctx)
		vec.Score += r.score
		vec.Indicators = append(vec.Indicators, r.indicators...)
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

func isDocumentNavigation(req *http.Request) bool {
	if req == nil {
		return false
	}

	return req.Header.Get("Sec-Fetch-Dest") == "document" &&
		req.Header.Get("Sec-Fetch-Mode") == "navigate"
}

func isDocumentNavigationSubmission(req *http.Request) bool {
	if req == nil {
		return false
	}

	return req.Method == http.MethodPost &&
		isDocumentNavigation(req) &&
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

// isSiblingSubdomainOrigin returns true when the Origin header shares the same
// base domain as the request URL but is NOT the same host (i.e., it's a
// sibling or child subdomain). Synthetic beacons often construct sibling
// origins like "app.example.com" when targeting "api.example.com".
func isSiblingSubdomainOrigin(req *http.Request) bool {
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
	originHost := strings.ToLower(strings.Split(originURL.Host, ":")[0])
	reqHost := strings.ToLower(strings.Split(req.URL.Host, ":")[0])
	if originHost == reqHost {
		return false // same host, not sibling
	}
	// Check shared base domain (last two labels).
	originParts := strings.Split(originHost, ".")
	reqParts := strings.Split(reqHost, ".")
	if len(originParts) < 2 || len(reqParts) < 2 {
		return false
	}
	originBase := originParts[len(originParts)-2] + "." + originParts[len(originParts)-1]
	reqBase := reqParts[len(reqParts)-2] + "." + reqParts[len(reqParts)-1]
	return originBase == reqBase
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

func normalizedURLPath(u *url.URL) string {
	if u == nil {
		return ""
	}
	if u.Path != "" {
		return strings.ToLower(u.Path)
	}
	return "/"
}

func normalizedURLHost(u *url.URL) string {
	if u == nil {
		return ""
	}

	return strings.ToLower(strings.Split(u.Host, ":")[0])
}

func looksLikeTelemetryEndpointPath(u *url.URL) bool {
	path := normalizedURLPath(u)
	if path == "" {
		return false
	}

	telemetryMarkers := []string{
		"/api/telemetry",
		"/api/ml/",
		"/collect",
		"/beacon",
		"/metrics",
		"/track",
		"/events",
		"/trap",
	}

	for _, marker := range telemetryMarkers {
		if strings.Contains(path, marker) {
			return true
		}
	}

	return false
}

func looksLikeAPIHostname(u *url.URL) bool {
	host := normalizedURLHost(u)
	if host == "" {
		return false
	}

	prefixes := []string{
		"api.",
		"metrics.",
		"telemetry.",
		"events.",
		"collect.",
		"track.",
		"beacon.",
	}

	for _, prefix := range prefixes {
		if strings.HasPrefix(host, prefix) {
			return true
		}
	}

	return false
}

// looksLikeEncodedPayload checks whether a query string contains base64 or
// percent-encoded blobs that suggest fingerprint data smuggling. It looks for:
//   - Long base64-like runs (>64 chars of [A-Za-z0-9+/=])
//   - Dense percent-encoding (>30% of characters are %XX sequences)
func looksLikeEncodedPayload(query string) bool {
	// Check for base64-like runs: contiguous [A-Za-z0-9+/=] longer than 64 chars
	run := 0
	for _, c := range query {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' {
			run++
			if run > 64 {
				return true
			}
		} else {
			run = 0
		}
	}

	// Check for dense percent-encoding
	pctCount := strings.Count(query, "%")
	if len(query) > 32 && float64(pctCount*3)/float64(len(query)) > 0.30 {
		return true
	}

	return false
}

func ghostHeadersInDeclaredOrder(req *http.Request, candidates []string) []string {
	if req == nil {
		return nil
	}

	declared := declaredHeaderOrder(req)
	if len(declared) == 0 {
		return nil
	}

	ghosts := make([]string, 0)
	for _, candidate := range candidates {
		lowerCandidate := strings.ToLower(candidate)
		declaredPresent := false
		for _, header := range declared {
			if strings.TrimSpace(header) == lowerCandidate {
				declaredPresent = true
				break
			}
		}
		if declaredPresent && req.Header.Get(candidate) == "" {
			ghosts = append(ghosts, lowerCandidate)
		}
	}

	return ghosts
}

func declaredHeaderOrder(req *http.Request) []string {
	if req == nil {
		return nil
	}

	order := req.Header.Get("X-Stealth-Header-Order")
	if order == "" {
		return nil
	}

	parts := strings.Split(strings.ToLower(order), ",")
	normalized := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		normalized = append(normalized, trimmed)
	}

	return normalized
}

func headerOrderIndex(order []string, header string) int {
	lowerHeader := strings.ToLower(header)
	for i, current := range order {
		if current == lowerHeader {
			return i
		}
	}

	return -1
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

// indicatorChecks extracts the Check string from each VectorIndicator.
// Used by all analyzer methods that delegate to a typed analyzer and need to
// map result.Indicators → []string for DetectionVector.Indicators.
func indicatorChecks(inds []VectorIndicator) []string {
	out := make([]string, 0, len(inds))
	for _, ind := range inds {
		out = append(out, ind.Check)
	}
	return out
}

// missingHeaderVector returns a DetectionVector for a JS-context header that
// is absent when other JS-sourced headers are present, proving the client
// has a JS execution context but deliberately omitted this data.
func missingHeaderVector(name, category, indicatorKey string, score, weight float64, description string) *DetectionVector {
	return &DetectionVector{
		Name:        name,
		Category:    category,
		Score:       score,
		Weight:      weight,
		Detected:    true,
		Description: description,
		Indicators:  []string{indicatorKey},
	}
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
