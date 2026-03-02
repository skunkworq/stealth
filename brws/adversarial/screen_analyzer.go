package adversarial

import (
	"fmt"
	"math"
)

// ScreenData holds screen geometry data for analysis.
type ScreenData struct {
	Width       int     `json:"width"`
	Height      int     `json:"height"`
	AvailWidth  int     `json:"avail_width"`
	AvailHeight int     `json:"avail_height"`
	ColorDepth  int     `json:"color_depth"`
	PixelRatio  float64 `json:"pixel_ratio"`
	OuterWidth  int     `json:"outer_width"`
	OuterHeight int     `json:"outer_height"`
	InnerWidth  int     `json:"inner_width"`
	InnerHeight int     `json:"inner_height"`
}

// ScreenAnalyzer validates screen geometry for headless/bot detection.
type ScreenAnalyzer struct {
	validColorDepths map[int]bool
	knownResolutions map[[2]int]bool
}

// NewScreenAnalyzer creates a new ScreenAnalyzer with known display configurations.
func NewScreenAnalyzer() *ScreenAnalyzer {
	return &ScreenAnalyzer{
		validColorDepths: map[int]bool{
			24: true, 30: true, 32: true, 48: true,
		},
		knownResolutions: map[[2]int]bool{
			{1920, 1080}: true, {2560, 1440}: true, {3840, 2160}: true,
			{1366, 768}: true, {1440, 900}: true, {1536, 864}: true,
			{1680, 1050}: true, {1280, 720}: true, {1280, 800}: true,
			{1600, 900}: true, {2560, 1600}: true, {3440, 1440}: true,
			{1280, 1024}: true, {1024, 768}: true, {1920, 1200}: true,
			{2880, 1800}: true, {3072, 1920}: true, // Retina
		},
	}
}

// Analyze runs the full screen analysis suite.
func (sa *ScreenAnalyzer) Analyze(data *ScreenData) *VectorResult {
	result := &VectorResult{
		Vector:     "Screen Analysis",
		Category:   VectorScreen,
		Detected:   false,
		Score:      0,
		Indicators: make([]VectorIndicator, 0),
	}

	if data == nil {
		return result
	}

	// Check 1: No browser chrome (outerWidth == innerWidth or outerHeight == innerHeight)
	if data.OuterWidth > 0 && data.InnerWidth > 0 && data.OuterWidth == data.InnerWidth {
		weight := 0.40
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "no_browser_chrome",
			Message: fmt.Sprintf("outerWidth (%d) == innerWidth (%d) — no browser chrome", data.OuterWidth, data.InnerWidth),
			Weight:  weight,
			Field:   "outer_width",
			Value:   fmt.Sprintf("%d==%d", data.OuterWidth, data.InnerWidth),
		})
		result.Score += weight
	}
	if data.OuterHeight > 0 && data.InnerHeight > 0 && data.OuterHeight == data.InnerHeight {
		weight := 0.40
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "no_browser_chrome",
			Message: fmt.Sprintf("outerHeight (%d) == innerHeight (%d) — no browser chrome", data.OuterHeight, data.InnerHeight),
			Weight:  weight,
			Field:   "outer_height",
			Value:   fmt.Sprintf("%d==%d", data.OuterHeight, data.InnerHeight),
		})
		// Only add if we haven't already added for width
		if data.OuterWidth == 0 || data.InnerWidth == 0 || data.OuterWidth != data.InnerWidth {
			result.Score += weight
		}
	}

	// Check 2: Invalid color depth
	if data.ColorDepth > 0 && !sa.validColorDepths[data.ColorDepth] {
		weight := 0.25
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "invalid_color_depth",
			Message: fmt.Sprintf("Unusual color depth: %d (expected 24, 30, 32, or 48)", data.ColorDepth),
			Weight:  weight,
			Field:   "color_depth",
			Value:   fmt.Sprintf("%d", data.ColorDepth),
		})
		result.Score += weight
	}

	// Check 3: Suspicious pixel ratio
	if data.PixelRatio == 0 || data.PixelRatio > 4 {
		weight := 0.20
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "suspicious_pixel_ratio",
			Message: fmt.Sprintf("Suspicious devicePixelRatio: %.2f (expected 1-4)", data.PixelRatio),
			Weight:  weight,
			Field:   "pixel_ratio",
			Value:   fmt.Sprintf("%.2f", data.PixelRatio),
		})
		result.Score += weight
	}

	// Check 4: No taskbar (avail_height == height means no OS chrome)
	if data.Height > 0 && data.AvailHeight > 0 && data.AvailHeight == data.Height {
		weight := 0.25
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "no_taskbar",
			Message: fmt.Sprintf("avail_height (%d) == height (%d) — no OS chrome/taskbar", data.AvailHeight, data.Height),
			Weight:  weight,
			Field:   "avail_height",
			Value:   fmt.Sprintf("%d==%d", data.AvailHeight, data.Height),
		})
		result.Score += weight
	}

	// Check 5: Non-standard resolution
	if data.Width > 0 && data.Height > 0 {
		if !sa.knownResolutions[[2]int{data.Width, data.Height}] {
			weight := 0.15
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "non_standard_resolution",
				Message: fmt.Sprintf("Non-standard resolution: %dx%d", data.Width, data.Height),
				Weight:  weight,
				Field:   "resolution",
				Value:   fmt.Sprintf("%dx%d", data.Width, data.Height),
			})
			result.Score += weight
		}
	}

	result.Score = math.Min(1.0, result.Score)
	result.Detected = result.Score > 0.3

	return result
}
