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
	navAnalyzer      *NavigatorAnalyzer
	isoAnalyzer      *IsomorphicAnalyzer
	behavAnalyzer    *BehavioralAnalyzer
	timingAnalyzer   *TimingAnalyzer
	graphicsAnalyzer *GraphicsAnalyzer
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

		// Sub-check 2b: None-context POST with zero runtime headers and browser UA.
		// A POST with Sec-Fetch-Site: none means no referrer context — the request
		// appears to come from a bookmarklet, extension, or ServiceWorker. Combined
		// with zero runtime headers and a browser UA, this is the shape of synthetic
		// beacon generation that strips provenance to evade gate-specific checks.
		if req.Method == http.MethodPost && runtimeHeaderCount >= 1 && runtimeHeaderCount <= 3 {
			// Mid-range none-context POST: 1-3 runtime headers with site=none.
			// A POST from no referrer context (bookmarklet, extension, SW) with a
			// partial set of runtime headers is the shape of adaptive evasion —
			// the F-series strategies send 2-3 post-load headers with site=none to
			// slip between the >=4 and ==0 gates. Real browser extensions that POST
			// telemetry either send the full runtime set or none at all.
			ua := strings.ToLower(req.Header.Get("User-Agent"))
			isBrowserUA := strings.Contains(ua, "chrome") || strings.Contains(ua, "firefox") || strings.Contains(ua, "safari")
			hasSecChUa := req.Header.Get("Sec-Ch-Ua") != ""

			if isBrowserUA && !hasSecChUa {
				vec.Score += 0.62
				vec.Indicators = append(vec.Indicators, fmt.Sprintf(
					"none_context_post_mid_range_headers: %d runtime/%d post_load headers on none-context POST",
					runtimeHeaderCount, postLoadHeaderCount))
			}
		}

		if req.Method == http.MethodPost && runtimeHeaderCount == 0 {
			ua := strings.ToLower(req.Header.Get("User-Agent"))
			isBrowserUA := strings.Contains(ua, "chrome") || strings.Contains(ua, "firefox") || strings.Contains(ua, "safari")

			if isBrowserUA {
				vec.Score += 0.38
				vec.Indicators = append(vec.Indicators, "none_context_zero_header_synthetic_beacon")

				if req.Header.Get("Origin") == "" {
					vec.Score += 0.15
					vec.Indicators = append(vec.Indicators, "none_context_post_missing_origin")
				}

				if bodyErr == nil && len(bodySnapshot) > 0 {
					if bodyTooSmall && missingRuntimePayload {
						vec.Score += 0.12
						vec.Indicators = append(vec.Indicators, fmt.Sprintf(
							"none_context_small_body_no_runtime: %d bytes", len(bodySnapshot)))
					}
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
		telemetryTarget := looksLikeTelemetryEndpointPath(req.URL)
		apiLikeHost := looksLikeAPIHostname(req.URL)
		jsFingerprintCount := countPresentHeaders(req, []string{
			constants.HeaderNavigatorData,
			constants.HeaderWebGLData,
			constants.HeaderPluginData,
			constants.HeaderScreenData,
			constants.HeaderFontData,
			constants.HeaderWebRTCData,
		})

		// Post-load cherry-pick on same-site telemetry GET
		if req.Method == http.MethodGet && jsFingerprintCount == 0 && postLoadHeaderCount >= 1 && (telemetryTarget || apiLikeHost) {
			vec.Score += 0.68
			vec.Indicators = append(vec.Indicators, fmt.Sprintf(
				"same_site_postload_cherry_pick: %d post_load/%d jsFP headers on telemetry GET",
				postLoadHeaderCount, jsFingerprintCount))
		}

		if req.Method == http.MethodGet && mode == "cors" && runtimeHeaderCount >= 6 {
			vec.Score += 0.78
			vec.Indicators = append(vec.Indicators, fmt.Sprintf(
				"same_site_get_runtime_bundle: %d runtime/%d post_load headers",
				runtimeHeaderCount, postLoadHeaderCount))

			if bodyErr == nil && len(bodySnapshot) > 0 {
				vec.Score += 0.26
				vec.Indicators = append(vec.Indicators, fmt.Sprintf(
					"same_site_get_with_body: %d bytes",
					len(bodySnapshot)))
			}

			if req.Header.Get("Content-Type") != "" {
				vec.Score += 0.18
				vec.Indicators = append(vec.Indicators, fmt.Sprintf(
					"same_site_get_with_content_type: %s",
					req.Header.Get("Content-Type")))
			}
		}

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

		if req.Method == http.MethodPost && mode == "cors" && req.Header.Get("Sec-Fetch-User") == "?1" {
			vec.Score += 0.24
			vec.Indicators = append(vec.Indicators, "same_site_xhr_with_user_activation")
		}

		if req.Method == http.MethodPost && runtimeHeaderCount >= 6 && hasRuntimeBody {
			if sameOriginClaim && postLoadHeaderCount >= 3 {
				vec.Score += 0.30
				vec.Indicators = append(vec.Indicators, fmt.Sprintf(
					"telemetry_runtime_duplicated_in_body_and_headers: %d runtime/%d post_load headers",
					runtimeHeaderCount, postLoadHeaderCount))
			}

			if !sameOriginClaim && runtimeHeaderCount >= 8 && postLoadHeaderCount >= 3 {
				vec.Score += 0.72
				vec.Indicators = append(vec.Indicators, fmt.Sprintf(
					"same_site_dense_runtime_body_header_duplication: %d runtime/%d post_load headers",
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
		if req.Method == http.MethodPost && runtimeHeaderCount <= 3 {
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
				} else if runtimeHeaderCount > 0 && runtimeHeaderCount <= 3 && jsFingerprintCount == 0 {
					// Cherry-picked post-load headers without JS fingerprints.
					// 1-3 post-load headers (Behavioral, Timing, Audio) without any
					// JS fingerprint headers (Navigator, WebGL, etc.) is selective
					// header evasion. Widened from <=2 to <=3 to catch F-series
					// 3-header POST strategies that exploit the gap between the
					// <=2 cherry-pick and >=4 general gates.
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
		telemetryTarget := looksLikeTelemetryEndpointPath(req.URL)
		apiLikeHost := looksLikeAPIHostname(req.URL)
		jsFingerprintCount := countPresentHeaders(req, []string{
			constants.HeaderNavigatorData,
			constants.HeaderWebGLData,
			constants.HeaderPluginData,
			constants.HeaderScreenData,
			constants.HeaderFontData,
			constants.HeaderWebRTCData,
		})

		if req.Method == http.MethodGet && runtimeHeaderCount >= 5 && (telemetryTarget || apiLikeHost) {
			vec.Score += 0.74
			vec.Indicators = append(vec.Indicators, fmt.Sprintf(
				"cross_site_get_runtime_bundle: %d runtime/%d post_load headers",
				runtimeHeaderCount, postLoadHeaderCount))

			if postLoadHeaderCount >= 2 {
				vec.Score += 0.16
				vec.Indicators = append(vec.Indicators, fmt.Sprintf(
					"cross_site_get_postload_runtime_headers: %d post_load headers",
					postLoadHeaderCount))
			}

			if jsFingerprintCount >= 2 && postLoadHeaderCount >= 2 {
				vec.Score += 0.12
				vec.Indicators = append(vec.Indicators, "cross_site_get_mixed_runtime_surfaces")
			}
		}

		// Post-load cherry-pick: telemetry GET with post-load headers but zero jsFP headers.
		// Real in-page JS that collects Timing/Behavioral/Audio/Canvas would also collect
		// Navigator/WebGL/Font — having ONLY post-load data is synthetic header selection.
		if req.Method == http.MethodGet && jsFingerprintCount == 0 && postLoadHeaderCount >= 1 && (telemetryTarget || apiLikeHost) {
			vec.Score += 0.68
			vec.Indicators = append(vec.Indicators, fmt.Sprintf(
				"cross_site_postload_cherry_pick: %d post_load/%d jsFP headers on telemetry GET",
				postLoadHeaderCount, jsFingerprintCount))
		}

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
		telemetryTarget := looksLikeTelemetryEndpointPath(req.URL)
		apiLikeHost := looksLikeAPIHostname(req.URL)
		jsFingerprintCount := countPresentHeaders(req, []string{
			constants.HeaderNavigatorData,
			constants.HeaderWebGLData,
			constants.HeaderPluginData,
			constants.HeaderScreenData,
			constants.HeaderFontData,
			constants.HeaderWebRTCData,
		})

		if req.Method == http.MethodGet && runtimeHeaderCount >= 5 && (telemetryTarget || apiLikeHost) {
			vec.Score += 0.76
			vec.Indicators = append(vec.Indicators, fmt.Sprintf(
				"nocors_get_runtime_bundle: %d runtime/%d post_load headers",
				runtimeHeaderCount, postLoadHeaderCount))

			if postLoadHeaderCount >= 2 {
				vec.Score += 0.16
				vec.Indicators = append(vec.Indicators, fmt.Sprintf(
					"nocors_get_postload_runtime_headers: %d post_load headers",
					postLoadHeaderCount))
			}

			if jsFingerprintCount >= 2 && postLoadHeaderCount >= 2 {
				vec.Score += 0.12
				vec.Indicators = append(vec.Indicators, "nocors_get_mixed_runtime_surfaces")
			}
		}

		// Post-load cherry-pick on no-cors telemetry GET
		if req.Method == http.MethodGet && jsFingerprintCount == 0 && postLoadHeaderCount >= 1 && (telemetryTarget || apiLikeHost) {
			vec.Score += 0.70
			vec.Indicators = append(vec.Indicators, fmt.Sprintf(
				"nocors_postload_cherry_pick: %d post_load/%d jsFP headers on telemetry GET",
				postLoadHeaderCount, jsFingerprintCount))
		}

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
		} else if req.Method == http.MethodPost && runtimeHeaderCount >= 1 && runtimeHeaderCount <= 4 {
			// Mid-range no-cors POST: 1-4 runtime headers on a no-cors POST.
			// No-cors mode restricts custom headers — browsers cannot add X-* headers
			// on no-cors requests. The presence of 1-4 runtime headers on a no-cors POST
			// is structurally impossible in a real browser, making this a strong signal
			// of programmatic request generation that forgot to switch to cors mode.
			ua := strings.ToLower(req.Header.Get("User-Agent"))
			isBrowserUA := strings.Contains(ua, "chrome") || strings.Contains(ua, "firefox") || strings.Contains(ua, "safari")
			hasSecChUa := req.Header.Get("Sec-Ch-Ua") != ""

			if isBrowserUA && !hasSecChUa {
				vec.Score += 0.68
				vec.Indicators = append(vec.Indicators, fmt.Sprintf(
					"nocors_post_mid_range_runtime_headers: %d runtime/%d post_load headers on no-cors POST",
					runtimeHeaderCount, postLoadHeaderCount))
			}
		} else if req.Method == http.MethodPost && runtimeHeaderCount == 0 {
			// Zero-header no-cors POST: synthetic sendBeacon pattern.
			ua := strings.ToLower(req.Header.Get("User-Agent"))
			isBrowserUA := strings.Contains(ua, "chrome") || strings.Contains(ua, "firefox") || strings.Contains(ua, "safari")
			hasAccept := req.Header.Get("Accept") != ""
			hasAcceptEncoding := req.Header.Get("Accept-Encoding") != ""
			fetchSite := strings.ToLower(req.Header.Get("Sec-Fetch-Site"))
			hasProvenance := fetchSite == "same-site" || fetchSite == "cross-site" || fetchSite == "same-origin"
			// Real Chrome always sends Sec-Ch-Ua on fetches. Presence indicates a
			// genuine browser, not synthetic beacon generation with identity stripping.
			hasSecChUa := req.Header.Get("Sec-Ch-Ua") != ""

			if isBrowserUA && hasProvenance && !hasSecChUa {
				// Base: no-cors zero-header beacon with browser UA and same-site claim.
				vec.Score += 0.38
				vec.Indicators = append(vec.Indicators, "nocors_zero_header_synthetic_beacon")

				// Amplifier: Accept or Accept-Encoding present — real sendBeacon
				// discards responses and never sets these.
				if hasAccept {
					vec.Score += 0.20
					vec.Indicators = append(vec.Indicators, fmt.Sprintf(
						"nocors_beacon_has_accept: %s", req.Header.Get("Accept")))
				}
				if hasAcceptEncoding {
					vec.Score += 0.15
					vec.Indicators = append(vec.Indicators, fmt.Sprintf(
						"nocors_beacon_has_accept_encoding: %s", req.Header.Get("Accept-Encoding")))
				}

				// Amplifier: CORS-safelisted content type — sendBeacon is restricted
				// to text/plain, application/x-www-form-urlencoded, multipart/form-data.
				if isNoCORSSafelistedContentType(contentType) {
					vec.Score += 0.10
					vec.Indicators = append(vec.Indicators, "nocors_beacon_safelisted_content_type")
				}

				// Amplifier: small body without runtime payload keywords.
				if bodyTooSmall && missingRuntimePayload {
					vec.Score += 0.12
					vec.Indicators = append(vec.Indicators, fmt.Sprintf(
						"nocors_beacon_small_body_no_runtime: %d bytes", len(bodySnapshot)))
				}

				// Amplifier: Origin from sibling subdomain — synthetic beacons often
				// construct a plausible-looking sibling origin.
				if isSiblingSubdomainOrigin(req) {
					vec.Score += 0.10
					vec.Indicators = append(vec.Indicators, "nocors_beacon_sibling_origin")
				}
			}
		}
	}

	// Sub-check 6: document navigations with synthetic telemetry context.
	// Real top-level navigations can carry Referer, cookies, and normal browser
	// navigation metadata, but they cannot attach client-side runtime telemetry in
	// custom X-* headers. Separately, a same-origin document navigation to an
	// API/telemetry endpoint without user activation is suspicious because it
	// looks like a fetch/beacon request masquerading as a page load.
	if isDocumentNavigation(req) {
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
		uaLower := strings.ToLower(req.Header.Get("User-Agent"))
		isBrowserUA := strings.Contains(uaLower, "chrome") || strings.Contains(uaLower, "firefox") || strings.Contains(uaLower, "safari")
		telemetryTarget := looksLikeTelemetryEndpointPath(req.URL)
		apiLikeHost := looksLikeAPIHostname(req.URL)

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

		// Sub-check 6b: ANY runtime X-* headers on a document navigation.
		// Real top-level navigations (typing a URL, clicking a link, submitting a
		// form) NEVER carry custom X-Canvas-Fingerprint, X-Timing-Data, X-Behavioral-Data
		// or X-Audio-Data headers. These headers are injected by client-side JS after
		// page load. Their presence on a dest=document GET is structurally impossible
		// regardless of the target URL, making this a URL-independent bot signal.
		if req.Method == http.MethodGet &&
			runtimeHeaderCount >= 1 && runtimeHeaderCount <= 3 &&
			isBrowserUA {
			vec.Score += 0.55
			vec.Indicators = append(vec.Indicators, fmt.Sprintf(
				"document_navigation_synthetic_runtime_headers: %d runtime headers on page load",
				runtimeHeaderCount))

			if postLoadHeaderCount >= 1 {
				vec.Score += 0.20
				vec.Indicators = append(vec.Indicators, fmt.Sprintf(
					"document_navigation_postload_on_navigation: %d post-load headers present",
					postLoadHeaderCount))
			}
		}

		// Sub-check 6c: Suspicious query string on document navigation.
		// Real navigations may have short query params (utm_source, page=2, q=search),
		// but large encoded payloads (>512 bytes) or base64 blobs in query strings
		// indicate fingerprint data smuggling via URL parameters.
		if req.Method == http.MethodGet && isBrowserUA && req.URL != nil {
			queryLen := len(req.URL.RawQuery)
			if queryLen > 512 {
				vec.Score += 0.45
				vec.Indicators = append(vec.Indicators, fmt.Sprintf(
					"document_navigation_suspicious_query_string: %d bytes in query params",
					queryLen))
			}
			if queryLen > 0 && looksLikeEncodedPayload(req.URL.RawQuery) {
				vec.Score += 0.35
				vec.Indicators = append(vec.Indicators, "document_navigation_encoded_query_payload")
			}
		}

		if req.Method == http.MethodGet &&
			runtimeHeaderCount <= 3 &&
			isBrowserUA &&
			(telemetryTarget || apiLikeHost) {
			acceptLower := strings.ToLower(req.Header.Get("Accept"))
			vec.Score += 0.40
			vec.Indicators = append(vec.Indicators, fmt.Sprintf(
				"document_navigation_to_telemetry_target: %s",
				normalizedURLPath(req.URL)))

			if telemetryTarget {
				vec.Score += 0.10
				vec.Indicators = append(vec.Indicators, "document_navigation_non_page_endpoint")
			}

			if apiLikeHost {
				vec.Score += 0.20
				vec.Indicators = append(vec.Indicators, fmt.Sprintf(
					"document_navigation_api_hostname: %s",
					normalizedURLHost(req.URL)))
			}

			if req.Header.Get("Sec-Fetch-Site") != "same-origin" {
				vec.Score += 0.22
				vec.Indicators = append(vec.Indicators, fmt.Sprintf(
					"document_navigation_non_same_origin_target: site=%s",
					req.Header.Get("Sec-Fetch-Site")))
			}

			if req.Referer() == "" {
				vec.Score += 0.18
				vec.Indicators = append(vec.Indicators, "document_navigation_missing_referer_to_telemetry_target")
			}

			if strings.Contains(acceptLower, "text/html") {
				vec.Score += 0.16
				vec.Indicators = append(vec.Indicators, "document_navigation_html_accept_to_telemetry_target")
			}

			if req.Header.Get("Upgrade-Insecure-Requests") == "1" {
				vec.Score += 0.12
				vec.Indicators = append(vec.Indicators, "document_navigation_upgrade_insecure_requests_to_telemetry_target")
			}

			if req.Header.Get("Sec-Fetch-User") == "?1" {
				vec.Score += 0.12
				vec.Indicators = append(vec.Indicators, "document_navigation_user_activation_to_telemetry_target")
			}

			if runtimeHeaderCount >= 1 {
				vec.Score += 0.14
				vec.Indicators = append(vec.Indicators, fmt.Sprintf(
					"document_navigation_runtime_headers_on_telemetry_target: %d runtime headers",
					runtimeHeaderCount))
			}
		}

		if req.Method == http.MethodGet &&
			runtimeHeaderCount == 0 &&
			isBrowserUA &&
			req.Header.Get("Sec-Fetch-Site") == "same-origin" &&
			req.Referer() != "" {
			ghostHeaders := ghostHeadersInDeclaredOrder(req, []string{"Content-Type", "Origin"})
			if len(ghostHeaders) > 0 {
				vec.Score += 0.44
				vec.Indicators = append(vec.Indicators, fmt.Sprintf(
					"document_navigation_header_order_ghost_headers: %s",
					strings.Join(ghostHeaders, ",")))
			}

			if looksLikeTelemetryEndpointPath(req.URL) {
				vec.Score += 0.52
				vec.Indicators = append(vec.Indicators, fmt.Sprintf(
					"document_navigation_to_telemetry_endpoint: %s",
					normalizedURLPath(req.URL)))
			}

			if req.Header.Get("Sec-Fetch-User") == "" {
				vec.Score += 0.18
				vec.Indicators = append(vec.Indicators, "document_navigation_missing_user_activation")
			}

			if req.Header.Get("Upgrade-Insecure-Requests") == "" {
				vec.Score += 0.12
				vec.Indicators = append(vec.Indicators, "document_navigation_missing_upgrade_insecure_requests")
			}

			if req.ProtoMajor == 1 && req.Header.Get("Connection") == "" {
				vec.Score += 0.20
				vec.Indicators = append(vec.Indicators, "document_navigation_missing_connection_header")
			}

			if strings.Contains(uaLower, "firefox") {
				acceptLower := strings.ToLower(req.Header.Get("Accept"))
				if !strings.Contains(acceptLower, "image/avif") || !strings.Contains(acceptLower, "image/webp") {
					vec.Score += 0.28
					vec.Indicators = append(vec.Indicators, "document_navigation_firefox_accept_missing_image_codecs")
				}
			}

			order := declaredHeaderOrder(req)
			upgradeIdx := headerOrderIndex(order, "upgrade-insecure-requests")
			uaIdx := headerOrderIndex(order, "user-agent")
			acceptIdx := headerOrderIndex(order, "accept")
			acceptLangIdx := headerOrderIndex(order, "accept-language")
			if upgradeIdx != -1 &&
				((uaIdx != -1 && upgradeIdx < uaIdx) ||
					(acceptIdx != -1 && upgradeIdx < acceptIdx) ||
					(acceptLangIdx != -1 && upgradeIdx < acceptLangIdx)) {
				vec.Score += 0.24
				vec.Indicators = append(vec.Indicators, fmt.Sprintf(
					"document_navigation_improbable_header_order: upgrade-insecure-requests@%d",
					upgradeIdx))
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
		telemetryTarget := looksLikeTelemetryEndpointPath(req.URL)
		apiLikeHost := looksLikeAPIHostname(req.URL)
		jsFingerprintCount := countPresentHeaders(req, []string{
			constants.HeaderNavigatorData,
			constants.HeaderWebGLData,
			constants.HeaderPluginData,
			constants.HeaderScreenData,
			constants.HeaderFontData,
			constants.HeaderWebRTCData,
		})

		if req.Method == http.MethodGet && runtimeHeaderCount >= 5 && (telemetryTarget || apiLikeHost) {
			vec.Score += 0.70
			vec.Indicators = append(vec.Indicators, fmt.Sprintf(
				"same_origin_get_runtime_bundle: %d runtime/%d post_load headers",
				runtimeHeaderCount, postLoadHeaderCount))

			if postLoadHeaderCount >= 2 {
				vec.Score += 0.16
				vec.Indicators = append(vec.Indicators, fmt.Sprintf(
					"same_origin_get_postload_runtime_headers: %d post_load headers",
					postLoadHeaderCount))
			}

			if jsFingerprintCount >= 2 && postLoadHeaderCount >= 2 {
				vec.Score += 0.10
				vec.Indicators = append(vec.Indicators, "same_origin_get_mixed_runtime_surfaces")
			}
		}

		// Post-load cherry-pick on same-origin telemetry GET
		if req.Method == http.MethodGet && jsFingerprintCount == 0 && postLoadHeaderCount >= 1 && (telemetryTarget || apiLikeHost) {
			vec.Score += 0.66
			vec.Indicators = append(vec.Indicators, fmt.Sprintf(
				"same_origin_postload_cherry_pick: %d post_load/%d jsFP headers on telemetry GET",
				postLoadHeaderCount, jsFingerprintCount))
		}

		// Same-origin POST cherry-pick: post-load headers without JS fingerprints.
		// Mirrors the same-site/cross-site cherry-pick gates. A same-origin POST
		// with 1-3 post-load headers (Behavioral, Timing, Audio) but zero JS
		// fingerprint headers (Navigator, WebGL, etc.) is the shape of adaptive
		// evasion that truncates headers to stay under the byte-based gates.
		// Real analytics POSTs from browser JS either send the full runtime set
		// or send the data in the body, not in selective headers.
		if req.Method == http.MethodPost && postLoadHeaderCount >= 1 && postLoadHeaderCount <= 4 && jsFingerprintCount == 0 && (telemetryTarget || apiLikeHost) {
			ua := strings.ToLower(req.Header.Get("User-Agent"))
			isBrowserUA := strings.Contains(ua, "chrome") || strings.Contains(ua, "firefox") || strings.Contains(ua, "safari")
			hasSecChUa := req.Header.Get("Sec-Ch-Ua") != ""

			if isBrowserUA && !hasSecChUa {
				vec.Score += 0.58
				vec.Indicators = append(vec.Indicators, fmt.Sprintf(
					"same_origin_post_cherry_picked_postload: %d post_load/%d jsFP headers on telemetry POST",
					postLoadHeaderCount, jsFingerprintCount))
			}
		}

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

		if runtimeHeaderCount <= 4 {
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
					// Widened from <=2 to <=4 to catch F-series 3-header POST
					// strategies that slip between the old <=2 and >=4 gates.
					vec.Score += 0.50
					vec.Indicators = append(vec.Indicators, fmt.Sprintf(
						"cross_site_cherry_picked_postload_headers: %d runtime_headers but 0 js_fingerprint_headers",
						runtimeHeaderCount))
				}
			}
		}
	}

	// Sub-check 10: Exotic dest sub-resource to telemetry/API target.
	// Real sub-resource loads (iframe, script, image, style, worker) fetch page
	// assets — HTML pages, JS bundles, images, CSS files. They do NOT target
	// telemetry/API endpoints (/collect, /beacon, /metrics, /track, /events, etc.)
	// or API-prefixed hostnames (api.*, metrics.*, telemetry.*, etc.).
	//
	// A request with dest=iframe/script/image/style/worker targeting a telemetry
	// endpoint is structurally impossible in normal browsing — it indicates the
	// sword is using exotic dest values to bypass the dest=empty and dest=document
	// gates.
	{
		dest := strings.ToLower(req.Header.Get("Sec-Fetch-Dest"))
		// Any dest that is NOT "empty", "document", or "" is a sub-resource load.
		// Real sub-resource loads fetch page assets, NOT telemetry/API endpoints.
		isExoticDest := dest != "" && dest != "empty" && dest != "document"
		if isExoticDest && req.URL != nil {
			telemetryTarget := looksLikeTelemetryEndpointPath(req.URL)
			apiLikeHost := looksLikeAPIHostname(req.URL)

			if telemetryTarget || apiLikeHost {
				vec.Score += 0.45
				vec.Indicators = append(vec.Indicators, fmt.Sprintf(
					"exotic_dest_to_telemetry_target: dest=%s url=%s",
					dest, normalizedURLPath(req.URL)))

				if telemetryTarget {
					vec.Score += 0.10
					vec.Indicators = append(vec.Indicators, "exotic_dest_telemetry_endpoint_path")
				}

				if apiLikeHost {
					vec.Score += 0.15
					vec.Indicators = append(vec.Indicators, fmt.Sprintf(
						"exotic_dest_api_hostname: %s", normalizedURLHost(req.URL)))
				}

				// Amplifier: zero runtime headers — real sub-resource loads are
				// triggered by browser parsing, not by telemetry JS. But the
				// combination of exotic dest + telemetry target + zero runtime is
				// a strong indicator of strategy rotation.
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
				if runtimeHeaderCount == 0 {
					vec.Score += 0.10
					vec.Indicators = append(vec.Indicators, "exotic_dest_zero_runtime_headers")
				}

				// Amplifier: no Sec-Ch-Ua — Chrome always sends it on sub-resource
				// fetches. Its absence with a browser UA means identity stripping.
				ua := strings.ToLower(req.Header.Get("User-Agent"))
				hasSecChUa := req.Header.Get("Sec-Ch-Ua") != ""
				if !hasSecChUa && (strings.Contains(ua, "chrome") || strings.Contains(ua, "firefox")) {
					vec.Score += 0.08
					vec.Indicators = append(vec.Indicators, "exotic_dest_no_sec_ch_ua")
				}
			}
		}
	}

	// Sub-check 8: Unified zero-header fetch catch-all.
	// After gate-specific checks, catch any fetch-like request (GET or POST) with
	// browser UA, zero runtime headers, Sec-Fetch-Dest: empty, and no Sec-Ch-Ua.
	// This prevents the sword from:
	//   - Rotating through site/mode combinations to find uncovered gates
	//   - Switching from POST to GET to bypass POST-specific sub-checks
	//   - Migrating runtime data from headers to body
	//
	// The structural invariant: a request from the stealth proxy's context ALWAYS
	// has X-* runtime headers attached by injected page JS. A fetch-like request
	// (dest=empty, mode=cors) with zero runtime headers and browser UA either:
	//   a) Comes from synthetic request generation (no injected JS context), or
	//   b) Deliberately stripped the headers to evade detection
	// Both are strong bot signals.
	if vec.Score < 0.35 && (req.Method == http.MethodPost || req.Method == http.MethodGet) {
		dest := req.Header.Get("Sec-Fetch-Dest")
		if dest == "empty" || dest == "" {
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

			if runtimeHeaderCount == 0 {
				ua := strings.ToLower(req.Header.Get("User-Agent"))
				isBrowserUA := strings.Contains(ua, "chrome") || strings.Contains(ua, "firefox") || strings.Contains(ua, "safari")
				hasSecChUa := req.Header.Get("Sec-Ch-Ua") != ""

				if isBrowserUA && !hasSecChUa {
					mode := req.Header.Get("Sec-Fetch-Mode")
					site := req.Header.Get("Sec-Fetch-Site")

					if req.Method == http.MethodPost {
						// POST path: check body patterns.
						bodySnapshot, bodyErr := snapshotRequestBody(req)
						bodyText := strings.TrimSpace(string(bodySnapshot))

						if bodyErr == nil && len(bodySnapshot) > 0 {
							hasRuntimeInBody := bodyContainsRuntimePayload(bodyText)

							if hasRuntimeInBody {
								vec.Score += 0.52
								vec.Indicators = append(vec.Indicators, fmt.Sprintf(
									"zero_header_runtime_data_migration: dest=%s mode=%s site=%s body=%d",
									dest, mode, site, len(bodySnapshot)))
							} else {
								vec.Score += 0.52
								vec.Indicators = append(vec.Indicators, fmt.Sprintf(
									"zero_header_browser_post_catchall: dest=%s mode=%s site=%s body=%d",
									dest, mode, site, len(bodySnapshot)))
							}

							if req.Header.Get("Accept") == "" {
								vec.Score += 0.10
								vec.Indicators = append(vec.Indicators, "zero_header_post_no_accept")
							}
						}
					} else if req.Method == http.MethodGet {
						// GET path: no body to analyze, but the structural pattern
						// is equally suspicious. A cors/same-origin GET with browser
						// UA and zero runtime headers models a tracking pixel or
						// analytics API call without injected JS context.
						vec.Score += 0.48
						vec.Indicators = append(vec.Indicators, fmt.Sprintf(
							"zero_header_browser_get_catchall: dest=%s mode=%s site=%s",
							dest, mode, site))
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
