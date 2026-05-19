package detection

import "testing"

func TestFontAnalyzer_TooFewFonts(t *testing.T) {
	fa := NewFontAnalyzer()
	result := fa.Analyze(&FontData{
		Fonts:     []string{"Arial", "Times New Roman", "Courier New"},
		FontCount: 3,
		Platform:  "linux",
	})

	if !result.Detected {
		t.Errorf("expected detection for too few fonts, got score=%.3f", result.Score)
	}
	assertIndicatorPresent(t, result, "too_few_fonts")
}

func TestFontAnalyzer_MissingPlatformFonts(t *testing.T) {
	fa := NewFontAnalyzer()

	// Windows platform but no Windows-specific fonts (Segoe UI, Calibri, Consolas, Tahoma, Verdana)
	result := fa.Analyze(&FontData{
		Fonts: []string{
			"Arial", "Times New Roman", "Courier New", "Georgia",
			"Trebuchet MS", "Impact", "Comic Sans MS", "Palatino Linotype",
			"Lucida Console", "Lucida Sans Unicode", "MS Gothic", "MS Mincho",
			"MS PGothic", "MS PMincho", "MS Sans Serif", "MS Serif",
			"MS UI Gothic", "MV Boli", "Marlett", "Symbol",
		},
		FontCount: 20,
		Platform:  "windows",
	})

	// Should flag missing platform fonts (no Segoe UI, Calibri, Consolas, Tahoma, Verdana)
	assertIndicatorPresent(t, result, "missing_platform_fonts")
}

func TestFontAnalyzer_CountMismatch(t *testing.T) {
	fa := NewFontAnalyzer()
	result := fa.Analyze(&FontData{
		Fonts: []string{
			"Arial", "Times New Roman", "Courier New", "Georgia", "Verdana",
			"Trebuchet MS", "Impact", "Comic Sans MS", "Palatino Linotype",
			"Segoe UI", "Calibri", "Consolas", "Tahoma", "Lucida Console",
			"Lucida Sans Unicode", "MS Gothic", "MS Mincho", "MS PGothic",
			"MS PMincho", "MS Sans Serif", "MS Serif", "MS UI Gothic",
		},
		FontCount: 50, // Reported 50 but only 22 fonts
		Platform:  "windows",
	})

	assertIndicatorPresent(t, result, "count_mismatch")
}

func TestFontAnalyzer_GenericFontsOnly(t *testing.T) {
	fa := NewFontAnalyzer()
	result := fa.Analyze(&FontData{
		Fonts:     []string{"Arial", "Times New Roman", "Courier New", "Georgia", "Verdana", "Serif", "Sans-Serif", "Monospace"},
		FontCount: 8,
		Platform:  "windows",
	})

	assertIndicatorPresent(t, result, "generic_fonts_only")
}

func TestFontAnalyzer_ValidDesktop(t *testing.T) {
	fa := NewFontAnalyzer()
	fonts := make([]string, 0, 30)
	// Include platform fonts + generic fonts
	platformFonts := []string{
		"Segoe UI", "Calibri", "Consolas", "Tahoma", "Verdana",
		"Arial", "Times New Roman", "Courier New", "Georgia",
		"Trebuchet MS", "Impact", "Comic Sans MS", "Palatino Linotype",
		"Lucida Console", "Lucida Sans Unicode", "MS Gothic", "MS Mincho",
		"MS PGothic", "MS PMincho", "MS Sans Serif", "MS Serif",
		"MS UI Gothic", "MV Boli", "Marlett", "Symbol", "Wingdings",
	}
	fonts = append(fonts, platformFonts...)

	result := fa.Analyze(&FontData{
		Fonts:     fonts,
		FontCount: len(fonts),
		Platform:  "windows",
	})

	if result.Detected {
		t.Errorf("valid Windows desktop should not be detected, score=%.3f, indicators=%v", result.Score, indicatorNames(result))
	}
}

func TestFontAnalyzer_Nil(t *testing.T) {
	fa := NewFontAnalyzer()
	result := fa.Analyze(nil)
	if result.Detected {
		t.Error("nil data should not be detected")
	}
}

func assertIndicatorPresent(t *testing.T, result *VectorResult, check string) {
	t.Helper()
	for _, ind := range result.Indicators {
		if ind.Check == check {
			return
		}
	}
	t.Errorf("expected indicator %q not found in %v", check, indicatorNames(result))
}

func indicatorNames(result *VectorResult) []string {
	names := make([]string, 0, len(result.Indicators))
	for _, ind := range result.Indicators {
		names = append(names, ind.Check)
	}
	return names
}
