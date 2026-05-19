package detection

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
	AvailLeft   int     `json:"avail_left"`
	AvailTop    int     `json:"avail_top"`
	ColorDepth  int     `json:"color_depth"`
	PixelRatio  float64 `json:"pixel_ratio"`
	OuterWidth  int     `json:"outer_width"`
	OuterHeight int     `json:"outer_height"`
	InnerWidth  int     `json:"inner_width"`
	InnerHeight int     `json:"inner_height"`

	// P11: Screen orientation API
	OrientationType  string `json:"orientation_type,omitempty"`
	OrientationAngle int    `json:"orientation_angle,omitempty"`

	// Phase 64: Screen.isExtended API
	IsExtended *bool `json:"is_extended,omitempty"`

	// Phase 86: Screen orientation locking
	HasOrientationLock *bool `json:"has_orientation_lock,omitempty"`
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

	sa.checkScreenIsExtended(data, result, nil)
	sa.checkAvailGeometryConsistency(data, result, nil)
	sa.checkOrientationLock(data, result, nil)

	// Check 1: No browser chrome (outerWidth == innerWidth or outerHeight == innerHeight)
	// Ignore for mobile where full screen is standard.
	isMobile := false
	if data.Width < 1200 && data.Height < 1200 { // heuristic
		isMobile = true
	}

	if !isMobile && data.OuterWidth > 0 && data.InnerWidth > 0 && data.OuterWidth == data.InnerWidth {
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

	// Check 3b: Non-quantized DPR (Phase 36)
	// Real OS scaling factors only use values from the standard set.
	// An arbitrary float (e.g. 1.371) is a strong indicator of synthetic spoofing.
	standardDPRs := []float64{1.0, 1.25, 1.5, 1.75, 2.0, 2.5, 2.625, 3.0, 3.5, 4.0}
	if data.PixelRatio > 0 {
		isStandard := false
		for _, std := range standardDPRs {
			if math.Abs(data.PixelRatio-std) < 0.01 {
				isStandard = true
				break
			}
		}
		if !isStandard {
			weight := 0.30
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "non_quantized_dpr",
				Message: fmt.Sprintf("devicePixelRatio %.4f is not a standard OS scaling factor (expected 1.0/1.25/1.5/1.75/2.0/2.5/3.0)", data.PixelRatio),
				Weight:  weight,
				Field:   "pixel_ratio",
				Value:   fmt.Sprintf("%.4f", data.PixelRatio),
			})
			result.Score += weight
		}
	}

	// Check 4: Taskbar/OS Chrome gap (Phase 35)
	// Real OS always has some chrome (taskbar, menu bar). Mac menu is ~25px,
	// Windows taskbar is ~40px. A gap of 0 means full screen (rare for regular browsing)
	// or headless browser. A gap > 150px is also improbable for standard desktops.
	if !isMobile && data.Height > 0 && data.AvailHeight > 0 {
		gap := data.Height - data.AvailHeight
		if gap == 0 {
			weight := 0.30
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "no_taskbar_gap",
				Message: fmt.Sprintf("avail_height (%d) == height (%d) — no OS chrome/taskbar", data.AvailHeight, data.Height),
				Weight:  weight,
				Field:   "avail_height",
				Value:   fmt.Sprintf("%d==%d", data.AvailHeight, data.Height),
			})
			result.Score += weight
		} else if gap < 24 || gap > 150 {
			weight := 0.25
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "suspicious_taskbar_gap",
				Message: fmt.Sprintf("Improbable taskbar height gap: %dpx (expected 24-150px)", gap),
				Weight:  weight,
				Field:   "avail_height_gap",
				Value:   fmt.Sprintf("%dpx", gap),
			})
			result.Score += weight
		}
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

	// Check 6: P11 — Missing screen orientation. Real browsers always expose
	// screen.orientation.type ("landscape-primary"|"portrait-primary") and angle (0|90|180|270).
	// Missing or invalid type signals headless/synthetic.
	validOrientations := map[string]bool{
		"landscape-primary":   true,
		"landscape-secondary": true,
		"portrait-primary":    true,
		"portrait-secondary":  true,
	}
	if data.OrientationType == "" {
		weight := 0.15
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "missing_screen_orientation",
			Message: "screen.orientation.type is missing — real browsers always expose it",
			Weight:  weight,
			Field:   "orientation_type",
			Value:   "empty",
		})
		result.Score += weight
	} else if !validOrientations[data.OrientationType] {
		weight := 0.20
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "invalid_screen_orientation",
			Message: fmt.Sprintf("screen.orientation.type '%s' is not valid", data.OrientationType),
			Weight:  weight,
			Field:   "orientation_type",
			Value:   data.OrientationType,
		})
		result.Score += weight
	}

	// Check 7: P11 — Orientation/geometry mismatch. Desktop landscape should have width > height.
	if data.OrientationType == "landscape-primary" && data.Width > 0 && data.Height > 0 && data.Width < data.Height {
		weight := 0.25
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "screen_orientation_mismatch",
			Message: fmt.Sprintf("landscape-primary but width(%d) < height(%d)", data.Width, data.Height),
			Weight:  weight,
			Field:   "orientation_type",
			Value:   fmt.Sprintf("%s with %dx%d", data.OrientationType, data.Width, data.Height),
		})
		result.Score += weight
	}

	result.Score = math.Min(1.0, result.Score)
	result.Detected = result.Score > 0.3

	return result
}

func (sa *ScreenAnalyzer) checkScreenIsExtended(data *ScreenData, result *VectorResult, indicators []string) []string {
	// Modern desktop browsers always expose screen.isExtended.
	// If it's missing (pointer is nil), it's a strong indicator of a synthetic/headless environment.
	if data.IsExtended == nil {
		weight := 0.25
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "screen_is_extended_missing",
			Message: "window.screen.isExtended is missing — real modern browsers always expose it",
			Weight:  weight,
			Field:   "is_extended",
			Value:   "undefined",
		})
		result.Score += weight
	}
	return indicators
}

func (sa *ScreenAnalyzer) checkAvailGeometryConsistency(data *ScreenData, result *VectorResult, indicators []string) []string {
	// Phase 79: availLeft/availTop should be 0 if not extended, or reasonably consistent if it is.
	// Many simple bots/headless environments report availLeft=0, availTop=0 regardless.
	// Some bots might accidentally set availLeft/Top while isExtended is false.
	isExt := false
	if data.IsExtended != nil {
		isExt = *data.IsExtended
	}

	if !isExt && (data.AvailLeft != 0 || data.AvailTop != 0) {
		weight := 0.35
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "screen_avail_geometry_mismatch",
			Message: fmt.Sprintf("Screen not extended but availLeft=%d, availTop=%d", data.AvailLeft, data.AvailTop),
			Weight:  weight,
			Field:   "avail_left",
			Value:   fmt.Sprintf("%d,%d", data.AvailLeft, data.AvailTop),
		})
		result.Score += weight
		indicators = append(indicators, "screen_avail_geometry_mismatch")
	}
	return indicators
}

func (sa *ScreenAnalyzer) checkOrientationLock(data *ScreenData, result *VectorResult, indicators []string) []string {
	// Phase 86: Screen orientation locking is usually available on mobile but not desktop.
	if data.HasOrientationLock == nil {
		if data.OrientationType != "" {
			weight := 0.20
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "missing_orientation_lock",
				Message: "screen.orientation.lock/unlock are missing but orientation.type is present",
				Weight:  weight,
				Field:   "has_orientation_lock",
				Value:   "undefined",
			})
			result.Score += weight
			indicators = append(indicators, "missing_orientation_lock")
		}
	} else if !*data.HasOrientationLock {
		weight := 0.25
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "missing_orientation_lock",
			Message: "screen.orientation.lock/unlock explicitly false on mobile profile",
			Weight:  weight,
			Field:   "has_orientation_lock",
			Value:   "false",
		})
		result.Score += weight
		indicators = append(indicators, "missing_orientation_lock")
	}

	return indicators
}
