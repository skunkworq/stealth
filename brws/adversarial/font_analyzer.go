package adversarial

import (
	"fmt"
	"math"
	"strings"
)

// FontData holds font enumeration data for analysis.
type FontData struct {
	Fonts     []string `json:"fonts"`
	FontCount int      `json:"font_count"`
	Platform  string   `json:"platform"`
}

// FontAnalyzer validates font enumeration data for headless/bot detection.
type FontAnalyzer struct {
	platformFonts map[string][]string
	webSafeFonts  map[string]bool
}

// NewFontAnalyzer creates a new FontAnalyzer with known platform font mappings.
func NewFontAnalyzer() *FontAnalyzer {
	return &FontAnalyzer{
		platformFonts: map[string][]string{
			"windows": {"Segoe UI", "Calibri", "Consolas", "Tahoma", "Verdana"},
			"macos":   {"SF Pro", "Helvetica Neue", "Menlo", "Monaco", "Lucida Grande"},
			"linux":   {"Ubuntu", "DejaVu Sans", "Liberation Sans", "Noto Sans", "Cantarell"},
		},
		webSafeFonts: map[string]bool{
			"arial":           true,
			"times new roman": true,
			"courier new":     true,
			"georgia":         true,
			"verdana":         true,
			"trebuchet ms":    true,
			"impact":          true,
			"comic sans ms":   true,
			"serif":           true,
			"sans-serif":      true,
			"monospace":       true,
		},
	}
}

// Analyze runs the full font analysis suite.
func (fa *FontAnalyzer) Analyze(data *FontData) *VectorResult {
	result := &VectorResult{
		Vector:     "Font Analysis",
		Category:   VectorFont,
		Detected:   false,
		Score:      0,
		Indicators: make([]VectorIndicator, 0),
	}

	if data == nil {
		return result
	}

	// Check 1: Too few fonts (headless browsers enumerate very few)
	if len(data.Fonts) < 20 {
		weight := 0.35
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "too_few_fonts",
			Message: fmt.Sprintf("Only %d fonts detected (expected 20+ on desktop)", len(data.Fonts)),
			Weight:  weight,
			Field:   "font_count",
			Value:   fmt.Sprintf("%d", len(data.Fonts)),
		})
		result.Score += weight
	}

	// Check 2: Missing platform-specific fonts
	platform := strings.ToLower(data.Platform)
	for p, fonts := range fa.platformFonts {
		if strings.Contains(platform, p) {
			foundPlatformFont := false
			for _, expected := range fonts {
				expectedLower := strings.ToLower(expected)
				for _, actual := range data.Fonts {
					if strings.Contains(strings.ToLower(actual), expectedLower) {
						foundPlatformFont = true
						break
					}
				}
				if foundPlatformFont {
					break
				}
			}
			if !foundPlatformFont && len(data.Fonts) > 0 {
				weight := 0.30
				result.Indicators = append(result.Indicators, VectorIndicator{
					Check:   "missing_platform_fonts",
					Message: fmt.Sprintf("No %s-specific fonts found on claimed %s platform", p, data.Platform),
					Weight:  weight,
					Field:   "platform",
					Value:   data.Platform,
				})
				result.Score += weight
			}
			break
		}
	}

	// Check 3: Count mismatch between reported count and actual font list
	if data.FontCount > 0 && data.FontCount != len(data.Fonts) {
		weight := 0.20
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "count_mismatch",
			Message: fmt.Sprintf("Reported font_count=%d but fonts array has %d entries", data.FontCount, len(data.Fonts)),
			Weight:  weight,
			Field:   "font_count",
			Value:   fmt.Sprintf("%d vs %d", data.FontCount, len(data.Fonts)),
		})
		result.Score += weight
	}

	// Check 4: Only generic/web-safe fonts (no platform-specific ones)
	if len(data.Fonts) > 0 {
		allGeneric := true
		for _, font := range data.Fonts {
			if !fa.webSafeFonts[strings.ToLower(font)] {
				allGeneric = false
				break
			}
		}
		if allGeneric {
			weight := 0.25
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "generic_fonts_only",
				Message: "All fonts are web-safe/generic — no platform-specific fonts",
				Weight:  weight,
				Field:   "fonts",
				Value:   "web-safe only",
			})
			result.Score += weight
		}
	}

	result.Score = math.Min(1.0, result.Score)
	result.Detected = result.Score > 0.3

	return result
}
