// Package types provides common types used across the stealth detection system.
package types

import (
	"time"
)

// DetectionVector represents a single detection category with its score,
// weight, and associated indicators.
type DetectionVector struct {
	Name         string         `json:"name"`
	Category     VectorCategory `json:"category"`
	Score        float64        `json:"score"`
	Weight       float64        `json:"weight"`
	Detected     bool           `json:"detected"`
	Description  string         `json:"description"`
	Indicators   []string       `json:"indicators"`
	CheckReports []CheckReport  `json:"check_reports,omitempty"`
}

// VectorCategory categorizes different types of detection vectors.
type VectorCategory string

const (
	VectorTLS         VectorCategory = "tls"
	VectorHTTP        VectorCategory = "http"
	VectorNavigator   VectorCategory = "navigator"
	VectorCanvas      VectorCategory = "canvas"
	VectorTiming      VectorCategory = "timing"
	VectorBehavioral  VectorCategory = "behavioral"
	VectorIsomorphic  VectorCategory = "isomorphic"
	VectorHardware    VectorCategory = "hardware"
	VectorWebRTC      VectorCategory = "webrtc"
	VectorHTTP2       VectorCategory = "http2"
	VectorFont        VectorCategory = "font"
	VectorScreen      VectorCategory = "screen"
	VectorPlugin      VectorCategory = "plugin"
	VectorAudio       VectorCategory = "audio"
	VectorFingerprint VectorCategory = "fingerprint"
	VectorCrossVector VectorCategory = "cross_vector"
	VectorIP          VectorCategory = "ip"
	VectorAutomation  VectorCategory = "automation"
	VectorHeadless    VectorCategory = "headless"
)

// CheckReport represents a single check result.
type CheckReport struct {
	Name        string  `json:"name"`
	Passed      bool    `json:"passed"`
	Score       float64 `json:"score"`
	Weight      float64 `json:"weight"`
	Description string  `json:"description"`
}

// StealthIndicator represents a specific automation indicator found during detection.
type StealthIndicator struct {
	Category    string  `json:"category"`
	Indicator   string  `json:"indicator"`
	Confidence  float64 `json:"confidence"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
}

// DetectionResult represents the outcome of a detection operation.
type DetectionResult struct {
	Timestamp  time.Time          `json:"timestamp"`
	Score      float64            `json:"score"`
	Detected   bool               `json:"detected"`
	Confidence float64            `json:"confidence"`
	Category   VectorCategory     `json:"category"`
	Vectors    []DetectionVector  `json:"vectors"`
	Indicators []StealthIndicator `json:"indicators"`
	Metadata   map[string]any     `json:"metadata,omitempty"`
}

// ThresholdConfig defines configurable thresholds for detection.
type ThresholdConfig struct {
	Bot        float64 `json:"bot_threshold"`
	Suspicious float64 `json:"suspicious_threshold"`
	Legitimate float64 `json:"legitimate_threshold"`
}

// DefaultThresholdConfig returns sensible default thresholds.
func DefaultThresholdConfig() ThresholdConfig {
	return ThresholdConfig{
		Bot:        0.7,
		Suspicious: 0.4,
		Legitimate: 0.2,
	}
}

// IsBot returns true if the score exceeds the bot threshold.
func (t ThresholdConfig) IsBot(score float64) bool {
	return score >= t.Bot
}

// IsSuspicious returns true if the score is in the suspicious range.
func (t ThresholdConfig) IsSuspicious(score float64) bool {
	return score >= t.Suspicious && score < t.Bot
}

// IsLegitimate returns true if the score indicates legitimate traffic.
func (t ThresholdConfig) IsLegitimate(score float64) bool {
	return score < t.Suspicious
}

// Classify returns a string classification of the score.
func (t ThresholdConfig) Classify(score float64) string {
	switch {
	case t.IsBot(score):
		return "bot"
	case t.IsSuspicious(score):
		return "suspicious"
	default:
		return "legitimate"
	}
}

// VectorBuilder helps construct DetectionVector instances.
type VectorBuilder struct {
	name        string
	category    VectorCategory
	weight      float64
	description string
	indicators  []string
	reports     []CheckReport
}

// NewVectorBuilder creates a new VectorBuilder.
func NewVectorBuilder(name string, category VectorCategory, weight float64) *VectorBuilder {
	return &VectorBuilder{
		name:     name,
		category: category,
		weight:   weight,
	}
}

// WithDescription sets the description.
func (b *VectorBuilder) WithDescription(desc string) *VectorBuilder {
	b.description = desc
	return b
}

// AddIndicator adds an indicator.
func (b *VectorBuilder) AddIndicator(indicator string) *VectorBuilder {
	b.indicators = append(b.indicators, indicator)
	return b
}

// AddCheckReport adds a check report.
func (b *VectorBuilder) AddCheckReport(report CheckReport) *VectorBuilder {
	b.reports = append(b.reports, report)
	return b
}

// Build constructs the DetectionVector.
func (b *VectorBuilder) Build(score float64, detected bool) DetectionVector {
	return DetectionVector{
		Name:         b.name,
		Category:     b.category,
		Score:        score,
		Weight:       b.weight,
		Detected:     detected,
		Description:  b.description,
		Indicators:   b.indicators,
		CheckReports: b.reports,
	}
}

// AnalysisConfig defines which detection vectors are enabled.
type AnalysisConfig struct {
	EnableTLSAnalysis     bool `json:"enable_tls_analysis"`
	EnableHTTPAnalysis    bool `json:"enable_http_analysis"`
	EnableNavigatorCheck  bool `json:"enable_navigator_check"`
	EnableTimingCheck     bool `json:"enable_timing_check"`
	EnableCanvasCheck     bool `json:"enable_canvas_check"`
	EnableBehavioralCheck bool `json:"enable_behavioral_check"`
	EnableWebGLCheck      bool `json:"enable_webgl_check"`
	EnableIPCheck         bool `json:"enable_ip_check"`
	EnableAutomationCheck bool `json:"enable_automation_check"`
	EnableHeadlessCheck   bool `json:"enable_headless_check"`
	EnableWebRTCCheck     bool `json:"enable_webrtc_check"`
	EnableHTTP2Check      bool `json:"enable_http2_check"`
	EnableFontCheck       bool `json:"enable_font_check"`
	EnableScreenCheck     bool `json:"enable_screen_check"`
	EnablePluginCheck     bool `json:"enable_plugin_check"`
	EnableAudioCheck      bool `json:"enable_audio_check"`
	EnableAdaptiveScoring bool `json:"enable_adaptive_scoring"`
}

// DefaultAnalysisConfig returns a config with all analyses enabled.
func DefaultAnalysisConfig() AnalysisConfig {
	return AnalysisConfig{
		EnableTLSAnalysis:     true,
		EnableHTTPAnalysis:    true,
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
	}
}
