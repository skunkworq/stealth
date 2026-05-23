package detection

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
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
