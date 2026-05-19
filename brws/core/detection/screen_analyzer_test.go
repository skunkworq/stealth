package detection

import "testing"

func ptr[T any](v T) *T {
	return &v
}

func TestScreenAnalyzer_NoBrowserChrome(t *testing.T) {
	sa := NewScreenAnalyzer()
	result := sa.Analyze(&ScreenData{
		Width:       1920,
		Height:      1080,
		AvailWidth:  1920,
		AvailHeight: 1040,
		ColorDepth:  24,
		PixelRatio:  1.0,
		OuterWidth:  1920,
		OuterHeight: 1080,
		InnerWidth:  1920, // Same as outer = headless
		InnerHeight: 1080, // Same as outer = headless
	})

	if !result.Detected {
		t.Errorf("expected detection for no browser chrome, got score=%.3f", result.Score)
	}
	assertIndicatorPresent(t, result, "no_browser_chrome")
}

func TestScreenAnalyzer_InvalidColorDepth(t *testing.T) {
	sa := NewScreenAnalyzer()
	result := sa.Analyze(&ScreenData{
		Width:       1920,
		Height:      1080,
		AvailWidth:  1920,
		AvailHeight: 1040,
		ColorDepth:  16, // Invalid
		PixelRatio:  1.0,
		OuterWidth:  1920,
		OuterHeight: 1080,
		InnerWidth:  1900,
		InnerHeight: 1000,
	})

	assertIndicatorPresent(t, result, "invalid_color_depth")
}

func TestScreenAnalyzer_SuspiciousPixelRatio(t *testing.T) {
	sa := NewScreenAnalyzer()
	result := sa.Analyze(&ScreenData{
		Width:       1920,
		Height:      1080,
		AvailWidth:  1920,
		AvailHeight: 1040,
		ColorDepth:  24,
		PixelRatio:  0, // Zero = suspicious
		OuterWidth:  1920,
		OuterHeight: 1080,
		InnerWidth:  1900,
		InnerHeight: 1000,
	})

	assertIndicatorPresent(t, result, "suspicious_pixel_ratio")
}

func TestScreenAnalyzer_NoTaskbar(t *testing.T) {
	sa := NewScreenAnalyzer()
	result := sa.Analyze(&ScreenData{
		Width:       1920,
		Height:      1080,
		AvailWidth:  1920,
		AvailHeight: 1080, // Same as height = no taskbar
		ColorDepth:  24,
		PixelRatio:  1.0,
		OuterWidth:  1920,
		OuterHeight: 1080,
		InnerWidth:  1900,
		InnerHeight: 1000,
	})

	assertIndicatorPresent(t, result, "no_taskbar_gap")
}

func TestScreenAnalyzer_ValidGeometry(t *testing.T) {
	sa := NewScreenAnalyzer()
	result := sa.Analyze(&ScreenData{
		Width:              1920,
		Height:             1080,
		AvailWidth:         1920,
		AvailHeight:        1040,
		ColorDepth:         24,
		PixelRatio:         1.0,
		OuterWidth:         1920,
		OuterHeight:        1040,
		InnerWidth:         1900,
		InnerHeight:        950,
		OrientationType:    "landscape-primary",
		OrientationAngle:   0,
		IsExtended:         ptr(false),
		HasOrientationLock: ptr(false),
	})

	if result.Detected {
		t.Errorf("valid geometry should not be detected, score=%.3f, indicators=%v", result.Score, indicatorNames(result))
	}
}

func TestScreenAnalyzer_HeadlessCombined(t *testing.T) {
	sa := NewScreenAnalyzer()
	result := sa.Analyze(&ScreenData{
		Width:       800,
		Height:      600,
		AvailWidth:  800,
		AvailHeight: 600, // No taskbar
		ColorDepth:  24,
		PixelRatio:  1.0,
		OuterWidth:  800,
		OuterHeight: 600,
		InnerWidth:  800, // No browser chrome
		InnerHeight: 600, // No browser chrome
	})

	if !result.Detected {
		t.Errorf("headless combined should be detected, got score=%.3f", result.Score)
	}
	if result.Score < 0.5 {
		t.Errorf("headless combined score too low: %.3f", result.Score)
	}
}

func TestScreenAnalyzer_Nil(t *testing.T) {
	sa := NewScreenAnalyzer()
	result := sa.Analyze(nil)
	if result.Detected {
		t.Error("nil data should not be detected")
	}
}

// --- P11 Screen Orientation Tests ---

func TestScreenAnalyzer_MissingOrientation(t *testing.T) {
	sa := NewScreenAnalyzer()
	result := sa.Analyze(&ScreenData{
		Width:       1920,
		Height:      1080,
		AvailWidth:  1920,
		AvailHeight: 1040,
		ColorDepth:  24,
		PixelRatio:  1.0,
		OuterWidth:  1920,
		OuterHeight: 1040,
		InnerWidth:  1900,
		InnerHeight: 950,
		// OrientationType missing = headless
	})

	assertIndicatorPresent(t, result, "missing_screen_orientation")
}

func TestScreenAnalyzer_InvalidOrientation(t *testing.T) {
	sa := NewScreenAnalyzer()
	result := sa.Analyze(&ScreenData{
		Width:            1920,
		Height:           1080,
		AvailWidth:       1920,
		AvailHeight:      1040,
		ColorDepth:       24,
		PixelRatio:       1.0,
		OuterWidth:       1920,
		OuterHeight:      1040,
		InnerWidth:       1900,
		InnerHeight:      950,
		OrientationType:  "invalid-type",
		OrientationAngle: 0,
	})

	assertIndicatorPresent(t, result, "invalid_screen_orientation")
}

func TestScreenAnalyzer_OrientationGeometryMismatch(t *testing.T) {
	sa := NewScreenAnalyzer()
	// landscape-primary but height > width
	result := sa.Analyze(&ScreenData{
		Width:            600,
		Height:           800,
		AvailWidth:       600,
		AvailHeight:      760,
		ColorDepth:       24,
		PixelRatio:       1.0,
		OuterWidth:       600,
		OuterHeight:      760,
		InnerWidth:       580,
		InnerHeight:      700,
		OrientationType:  "landscape-primary",
		OrientationAngle: 0,
	})

	assertIndicatorPresent(t, result, "screen_orientation_mismatch")
}

func TestScreenAnalyzer_ValidOrientation(t *testing.T) {
	sa := NewScreenAnalyzer()
	result := sa.Analyze(&ScreenData{
		Width:              1920,
		Height:             1080,
		AvailWidth:         1920,
		AvailHeight:        1040,
		ColorDepth:         24,
		PixelRatio:         1.0,
		OuterWidth:         1920,
		OuterHeight:        1040,
		InnerWidth:         1900,
		InnerHeight:        950,
		OrientationType:    "landscape-primary",
		OrientationAngle:   0,
		IsExtended:         ptr(false),
		HasOrientationLock: ptr(false),
	})

	for _, ind := range result.Indicators {
		if ind.Check == "missing_screen_orientation" || ind.Check == "invalid_screen_orientation" || ind.Check == "screen_orientation_mismatch" {
			t.Errorf("valid orientation should not trigger %s", ind.Check)
		}
	}
	if result.Detected {
		t.Errorf("valid screen with orientation should not be detected, score=%.3f", result.Score)
	}
}
