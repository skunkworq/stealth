package challenge

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/skunkworq/stealth/brws/core/constants"
)

func TestWebGLVendorGPUKeywords(t *testing.T) {
	wa := NewWebGLAnalyzer()

	tests := []struct {
		name       string
		vendor     string
		wantDetect bool
	}{
		{"clean_google", "Google Inc.", false},
		{"clean_mozilla", "Mozilla", false},
		{"clean_apple", "Apple", false},
		{"clean_intel", "Intel Inc.", false},
		{"gpu_nvidia_parens", "Google Inc. (NVIDIA)", true},
		{"gpu_apple_parens", "Google Inc. (Apple)", true},
		{"gpu_radeon", "AMD Radeon", true},
		{"gpu_geforce", "NVIDIA GeForce", true},
		{"gpu_apple_m", "Apple M2", true},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &WebGLData{
				Vendor:   tt.vendor,
				Renderer: "NVIDIA GeForce RTX 4070",
				Platform: "Win32",
			}

			result := wa.Analyze(data)
			found := false
			for _, ind := range result.Indicators {
				if ind.Check == "gpu_keywords_in_masked_vendor" {
					found = true
					break
				}
			}
			if found != tt.wantDetect {
				t.Errorf("vendor=%q: got detected=%v, want %v (score=%.3f)", tt.vendor, found, tt.wantDetect, result.Score)
			}
		})
	}
}

func TestRTTQuantization(t *testing.T) {
	detector := NewStealthDetector()

	tests := []struct {
		name       string
		rtt        int
		wantDetect bool
	}{
		{"quantized_75", 75, false},
		{"quantized_100", 100, false},
		{"quantized_125", 125, false},
		{"quantized_150", 150, false},
		{"non_quantized_87", 87, true},
		{"non_quantized_110", 110, true},
		{"non_quantized_133", 133, true},
		{"non_quantized_76", 76, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://test/", nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			req.Header.Set("Accept-Encoding", "gzip, deflate, br")

			navData := map[string]interface{}{
				"platform":  "Win32",
				"userAgent": req.Header.Get("User-Agent"),
				"connection": map[string]interface{}{
					"rtt":      tt.rtt,
					"downlink": 5.5,
				},
			}
			navJSON, _ := json.Marshal(navData)
			req.Header.Set(constants.HeaderNavigatorData, string(navJSON))

			result := detector.AnalyzeRequest(req, nil)

			found := false
			for _, v := range result.Vectors {
				for _, ind := range v.Indicators {
					if len(ind) > 18 && ind[:18] == "non_quantized_rtt:" {
						found = true
						break
					}
				}
			}
			if found != tt.wantDetect {
				t.Errorf("rtt=%d: got detected=%v, want %v", tt.rtt, found, tt.wantDetect)
				for _, v := range result.Vectors {
					if len(v.Indicators) > 0 {
						t.Logf("  vector %s: indicators=%v", v.Name, v.Indicators)
					}
				}
			}
		})
	}
}

func TestCanvasHashFormat(t *testing.T) {
	detector := NewStealthDetector()

	tests := []struct {
		name       string
		canvas     string
		wantDetect bool
	}{
		{"bare_sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", true},
		{"bare_md5", "d41d8cd98f00b204e9800998ecf8427e", true},
		{"data_url", "data:image/png;base64,iVBORw0KGgo=", false},
		{"json_format", `{"hash":"abc123","width":300}`, false},
		{"short_string", "abc123", false},
		{"with_prefix", "canvas:e3b0c44298fc1c149afbf4c8996fb924", false},
		{"randomized", "randomized-abc123def456", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://test/", nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
			req.Header.Set("Accept", "text/html")
			req.Header.Set("Accept-Language", "en-US")
			req.Header.Set("Accept-Encoding", "gzip")
			req.Header.Set(constants.HeaderCanvasFingerprint, tt.canvas)

			result := detector.AnalyzeRequest(req, nil)

			found := false
			for _, v := range result.Vectors {
				for _, ind := range v.Indicators {
					if ind == "synthetic_canvas_hash_format" {
						found = true
						break
					}
				}
			}
			if found != tt.wantDetect {
				t.Errorf("canvas=%q: got detected=%v, want %v", tt.name, found, tt.wantDetect)
			}
		})
	}
}

func TestScreenNavigatorCrossCheck(t *testing.T) {
	detector := NewStealthDetector()

	tests := []struct {
		name           string
		screenOuter    int
		screenInner    int
		navOuter       int
		navInner       int
		wantOuterMatch bool // true = no mismatch indicator expected
		wantInnerMatch bool
	}{
		{"matched", 1920, 1903, 1920, 1903, true, true},
		{"outer_mismatch", 1920, 1903, 2560, 2543, false, false},
		{"inner_mismatch_only", 1920, 1903, 1920, 1400, true, false},
		{"close_enough", 1920, 1903, 1922, 1905, true, true}, // within 5px tolerance
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://test/", nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			req.Header.Set("Accept-Encoding", "gzip, deflate, br")
			req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134"`)
			req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
			req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

			screenData := map[string]interface{}{
				"width":        tt.screenOuter,
				"height":       1080,
				"avail_width":  tt.screenOuter,
				"avail_height": 1040,
				"color_depth":  24,
				"pixel_ratio":  1.0,
				"outer_width":  tt.screenOuter,
				"outer_height": 1040,
				"inner_width":  tt.screenInner,
				"inner_height": 969,
			}
			screenJSON, _ := json.Marshal(screenData)
			req.Header.Set(constants.HeaderScreenData, string(screenJSON))

			navData := map[string]interface{}{
				"platform":           "Win32",
				"userAgent":          req.Header.Get("User-Agent"),
				"screen_outer_width": tt.navOuter,
				"screen_inner_width": tt.navInner,
			}
			navJSON, _ := json.Marshal(navData)
			req.Header.Set(constants.HeaderNavigatorData, string(navJSON))

			result := detector.AnalyzeRequest(req, nil)

			outerMismatchFound := false
			innerMismatchFound := false
			for _, v := range result.Vectors {
				for _, ind := range v.Indicators {
					if len(ind) > 30 && ind[:30] == "screen_nav_outer_width_mismatc" {
						outerMismatchFound = true
					}
					if len(ind) > 30 && ind[:30] == "screen_nav_inner_width_mismatc" {
						innerMismatchFound = true
					}
				}
			}

			if outerMismatchFound == tt.wantOuterMatch {
				t.Errorf("outer: got mismatch=%v, want match=%v", outerMismatchFound, tt.wantOuterMatch)
			}
			if innerMismatchFound == tt.wantInnerMatch {
				t.Errorf("inner: got mismatch=%v, want match=%v", innerMismatchFound, tt.wantInnerMatch)
			}
		})
	}
}

func TestColorDepthCrossCheck(t *testing.T) {
	detector := NewStealthDetector()

	tests := []struct {
		name       string
		screenCD   int
		navCD      int
		wantDetect bool
	}{
		{"matched_24", 24, 24, false},
		{"matched_32", 32, 32, false},
		{"mismatch_32_vs_24", 32, 24, true},
		{"mismatch_24_vs_30", 24, 30, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://test/", nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			req.Header.Set("Accept-Encoding", "gzip, deflate, br")
			req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134"`)
			req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
			req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

			screenData := map[string]interface{}{
				"width":        1920,
				"height":       1080,
				"avail_width":  1920,
				"avail_height": 1040,
				"color_depth":  tt.screenCD,
				"pixel_ratio":  1.0,
				"outer_width":  1920,
				"outer_height": 1040,
				"inner_width":  1903,
				"inner_height": 969,
			}
			screenJSON, _ := json.Marshal(screenData)
			req.Header.Set(constants.HeaderScreenData, string(screenJSON))

			navData := map[string]interface{}{
				"platform":           "Win32",
				"userAgent":          req.Header.Get("User-Agent"),
				"screen_color_depth": tt.navCD,
				"screen_outer_width": 1920,
				"screen_inner_width": 1903,
			}
			navJSON, _ := json.Marshal(navData)
			req.Header.Set(constants.HeaderNavigatorData, string(navJSON))

			result := detector.AnalyzeRequest(req, nil)

			found := false
			for _, v := range result.Vectors {
				for _, ind := range v.Indicators {
					if len(ind) > 30 && ind[:30] == "screen_nav_color_depth_mismatc" {
						found = true
					}
				}
			}
			if found != tt.wantDetect {
				t.Errorf("screenCD=%d navCD=%d: got detected=%v, want %v", tt.screenCD, tt.navCD, found, tt.wantDetect)
			}
		})
	}
}

func TestCanvasPayloadLength(t *testing.T) {
	detector := NewStealthDetector()

	tests := []struct {
		name       string
		canvas     string
		wantDetect bool
	}{
		{"short_44_chars", "data:image/png;base64,dGVzdGluZzEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNA==", true},
		{"realistic_10k", "data:image/png;base64," + strings.Repeat("ABCD", 2600), false},
		{"bare_hash_not_data_url", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", false}, // different check
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://test/", nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
			req.Header.Set("Accept", "text/html")
			req.Header.Set("Accept-Language", "en-US")
			req.Header.Set("Accept-Encoding", "gzip")
			req.Header.Set(constants.HeaderCanvasFingerprint, tt.canvas)

			result := detector.AnalyzeRequest(req, nil)

			found := false
			for _, v := range result.Vectors {
				for _, ind := range v.Indicators {
					if len(ind) >= 24 && ind[:24] == "canvas_payload_too_short" {
						found = true
						break
					}
				}
			}
			if found != tt.wantDetect {
				t.Errorf("canvas=%q: got detected=%v, want %v", tt.name, found, tt.wantDetect)
			}
		})
	}
}

func TestMissingProductSub(t *testing.T) {
	detector := NewStealthDetector()

	tests := []struct {
		name       string
		navData    map[string]interface{}
		wantDetect bool
	}{
		{
			"present_chrome",
			map[string]interface{}{
				"platform":   "Win32",
				"userAgent":  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
				"productSub": "20030107",
				"languages":  []string{"en-US", "en"},
			},
			false,
		},
		{
			"present_firefox",
			map[string]interface{}{
				"platform":   "Win32",
				"userAgent":  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
				"productSub": "20100101",
				"languages":  []string{"en-US", "en"},
			},
			false,
		},
		{
			"absent",
			map[string]interface{}{
				"platform":  "Win32",
				"userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
				"languages": []string{"en-US", "en"},
			},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://test/", nil)
			req.Header.Set("User-Agent", tt.navData["userAgent"].(string))
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			req.Header.Set("Accept-Encoding", "gzip, deflate, br")

			navJSON, _ := json.Marshal(tt.navData)
			req.Header.Set(constants.HeaderNavigatorData, string(navJSON))

			result := detector.AnalyzeRequest(req, nil)

			found := false
			for _, v := range result.Vectors {
				for _, ind := range v.Indicators {
					if ind == "missing_navigator_productSub" {
						found = true
						break
					}
				}
			}
			if found != tt.wantDetect {
				t.Errorf("%s: got detected=%v, want %v", tt.name, found, tt.wantDetect)
			}
		})
	}
}

func TestMissingMaxTouchPoints(t *testing.T) {
	detector := NewStealthDetector()

	tests := []struct {
		name       string
		navData    map[string]interface{}
		wantDetect bool
	}{
		{
			"present_zero",
			map[string]interface{}{
				"platform":       "Win32",
				"userAgent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
				"maxTouchPoints": 0,
				"languages":      []string{"en-US", "en"},
			},
			false,
		},
		{
			"absent",
			map[string]interface{}{
				"platform":  "Win32",
				"userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
				"languages": []string{"en-US", "en"},
			},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://test/", nil)
			req.Header.Set("User-Agent", tt.navData["userAgent"].(string))
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			req.Header.Set("Accept-Encoding", "gzip, deflate, br")

			navJSON, _ := json.Marshal(tt.navData)
			req.Header.Set(constants.HeaderNavigatorData, string(navJSON))

			result := detector.AnalyzeRequest(req, nil)

			found := false
			for _, v := range result.Vectors {
				for _, ind := range v.Indicators {
					if ind == "missing_navigator_maxTouchPoints" {
						found = true
						break
					}
				}
			}
			if found != tt.wantDetect {
				t.Errorf("%s: got detected=%v, want %v", tt.name, found, tt.wantDetect)
			}
		})
	}
}

func TestWebGLMissingShadingVersion(t *testing.T) {
	wa := NewWebGLAnalyzer()

	tests := []struct {
		name       string
		shading    string
		wantDetect bool
	}{
		{"present", "WebGL GLSL ES 3.00", false},
		{"present_100", "WebGL GLSL ES 1.00", false},
		{"empty_string", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &WebGLData{
				Vendor:         "Google Inc.",
				Renderer:       "NVIDIA GeForce RTX 4070",
				ShadingVersion: tt.shading,
				Platform:       "Win32",
			}

			result := wa.Analyze(data)
			found := false
			for _, ind := range result.Indicators {
				if ind.Check == "missing_shading_version" {
					found = true
					break
				}
			}
			if found != tt.wantDetect {
				t.Errorf("shading=%q: got detected=%v, want %v (score=%.3f)", tt.shading, found, tt.wantDetect, result.Score)
			}
		})
	}
}

// === Round 3 Shield Check Tests ===

func TestCanvasPNGMagicHeader(t *testing.T) {
	detector := NewStealthDetector()

	// Real PNG base64 starts with "iVBOR" (from \x89PNG\r\n\x1a\n)
	realPNGPrefix := "iVBORw0KGgoAAAANSUhEUgAA"
	randomPrefix := "ABCDEFGHIJKLMNOPQRSTUVWX"

	tests := []struct {
		name       string
		canvas     string
		wantDetect bool
	}{
		{"real_png_prefix", "data:image/png;base64," + realPNGPrefix + strings.Repeat("AAAA", 100), false},
		{"random_prefix", "data:image/png;base64," + randomPrefix + strings.Repeat("AAAA", 100), true},
		{"too_short_payload", "data:image/png;base64,iVBORshort", false},                         // handled by too_short check, not magic check
		{"bare_hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", false}, // different check
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://test/", nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
			req.Header.Set("Accept", "text/html")
			req.Header.Set("Accept-Language", "en-US")
			req.Header.Set("Accept-Encoding", "gzip")
			req.Header.Set(constants.HeaderCanvasFingerprint, tt.canvas)

			result := detector.AnalyzeRequest(req, nil)

			found := false
			for _, v := range result.Vectors {
				for _, ind := range v.Indicators {
					if ind == "canvas_png_magic_header_missing" {
						found = true
						break
					}
				}
			}
			if found != tt.wantDetect {
				t.Errorf("canvas=%q: got detected=%v, want %v", tt.name, found, tt.wantDetect)
			}
		})
	}
}

func TestMissingAppVersion(t *testing.T) {
	detector := NewStealthDetector()

	tests := []struct {
		name       string
		navData    map[string]interface{}
		wantInd    string // which indicator to look for
		wantDetect bool
	}{
		{
			"absent",
			map[string]interface{}{
				"platform":  "Win32",
				"userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
				"languages": []string{"en-US", "en"},
			},
			"missing_navigator_appVersion",
			true,
		},
		{
			"present_correct",
			map[string]interface{}{
				"platform":   "Win32",
				"userAgent":  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
				"appVersion": "5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
				"languages":  []string{"en-US", "en"},
			},
			"missing_navigator_appVersion",
			false,
		},
		{
			"present_inconsistent",
			map[string]interface{}{
				"platform":   "Win32",
				"userAgent":  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
				"appVersion": "5.0 (Macintosh; Intel Mac OS X 10_15_7)",
				"languages":  []string{"en-US", "en"},
			},
			"inconsistent_navigator_appVersion",
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://test/", nil)
			req.Header.Set("User-Agent", tt.navData["userAgent"].(string))
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			req.Header.Set("Accept-Encoding", "gzip, deflate, br")

			navJSON, _ := json.Marshal(tt.navData)
			req.Header.Set(constants.HeaderNavigatorData, string(navJSON))

			result := detector.AnalyzeRequest(req, nil)

			found := false
			for _, v := range result.Vectors {
				for _, ind := range v.Indicators {
					if ind == tt.wantInd {
						found = true
						break
					}
				}
			}
			if found != tt.wantDetect {
				t.Errorf("%s: got detected=%v for '%s', want %v", tt.name, found, tt.wantInd, tt.wantDetect)
			}
		})
	}
}

func TestWebGLMissingMaxTextureSize(t *testing.T) {
	wa := NewWebGLAnalyzer()

	tests := []struct {
		name       string
		maxTex     int
		wantDetect bool
	}{
		{"zero_missing", 0, true},
		{"realistic_16384", 16384, false},
		{"realistic_8192", 8192, false},
		{"realistic_4096", 4096, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &WebGLData{
				Vendor:         "Google Inc.",
				Renderer:       "NVIDIA GeForce RTX 4070",
				ShadingVersion: "WebGL GLSL ES 3.00",
				Platform:       "Win32",
				MaxTextureSize: tt.maxTex,
			}

			result := wa.Analyze(data)
			found := false
			for _, ind := range result.Indicators {
				if ind.Check == "missing_max_texture_size" {
					found = true
					break
				}
			}
			if found != tt.wantDetect {
				t.Errorf("maxTextureSize=%d: got detected=%v, want %v (score=%.3f)", tt.maxTex, found, tt.wantDetect, result.Score)
			}
		})
	}
}

func TestMissingConnectionEffectiveType(t *testing.T) {
	detector := NewStealthDetector()

	tests := []struct {
		name       string
		navData    map[string]interface{}
		wantDetect bool
	}{
		{
			"absent",
			map[string]interface{}{
				"platform":  "Win32",
				"userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
				"languages": []string{"en-US", "en"},
				"connection": map[string]interface{}{
					"rtt":      75,
					"downlink": 5.5,
				},
			},
			true,
		},
		{
			"present_4g",
			map[string]interface{}{
				"platform":  "Win32",
				"userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
				"languages": []string{"en-US", "en"},
				"connection": map[string]interface{}{
					"rtt":           75,
					"downlink":      5.5,
					"effectiveType": "4g",
				},
			},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://test/", nil)
			req.Header.Set("User-Agent", tt.navData["userAgent"].(string))
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			req.Header.Set("Accept-Encoding", "gzip, deflate, br")

			navJSON, _ := json.Marshal(tt.navData)
			req.Header.Set(constants.HeaderNavigatorData, string(navJSON))

			result := detector.AnalyzeRequest(req, nil)

			found := false
			for _, v := range result.Vectors {
				for _, ind := range v.Indicators {
					if ind == "missing_connection_effectiveType" {
						found = true
						break
					}
				}
			}
			if found != tt.wantDetect {
				t.Errorf("%s: got detected=%v, want %v", tt.name, found, tt.wantDetect)
			}
		})
	}
}

func TestTooFewTimingEntries(t *testing.T) {
	ta := NewTimingAnalyzer(nil)

	tests := []struct {
		name       string
		entryCount int
		wantDetect bool
	}{
		{"5_entries", 5, true},
		{"8_entries", 8, true},
		{"10_entries", 10, false},
		{"15_entries", 15, false},
		{"20_entries", 20, false},
	}

	baseURL := "https://example.com"
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seq := &RequestTimingSequence{Entries: make([]RequestTimingEntry, 0, tt.entryCount)}

			// Generate entries in correct order with variable intervals
			contentTypes := []string{
				"text/html",
				"text/css", "text/css",
				"application/javascript", "application/javascript", "application/javascript",
				"image/png", "image/jpeg", "image/webp", "image/svg+xml",
				"font/woff2", "font/woff2",
				"application/javascript", // deferred JS
				"image/png", "image/jpeg",
				"font/woff2",
				"application/javascript", // async JS
				"image/png", "image/jpeg", "image/webp",
			}

			var ts int64
			for i := 0; i < tt.entryCount && i < len(contentTypes); i++ {
				referrer := ""
				if i > 0 {
					referrer = baseURL
				}
				seq.Entries = append(seq.Entries, RequestTimingEntry{
					Timestamp:   ts,
					ContentType: contentTypes[i],
					Referrer:    referrer,
				})
				ts += 100 + int64(i*50) // variable intervals
			}

			result := ta.Analyze(seq)
			found := false
			for _, ind := range result.Indicators {
				if ind.Check == "too_few_timing_entries" {
					found = true
					break
				}
			}
			if found != tt.wantDetect {
				t.Errorf("entries=%d: got detected=%v, want %v (score=%.3f)", tt.entryCount, found, tt.wantDetect, result.Score)
			}
		})
	}
}

// === Round 4 Shield Check Tests ===

func TestWebGLMissingExtensions(t *testing.T) {
	wa := NewWebGLAnalyzer()

	tests := []struct {
		name       string
		extensions []string
		wantDetect bool
	}{
		{"nil_extensions", nil, true},
		{"empty_extensions", []string{}, true},
		{"few_extensions_10", make([]string, 10), true},
		{"sufficient_extensions_20", make([]string, 20), true},
		{"plenty_extensions_30", make([]string, 30), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fill test extension arrays with valid names
			for i := range tt.extensions {
				tt.extensions[i] = fmt.Sprintf("EXT_test_%d", i)
			}

			data := &WebGLData{
				Vendor:         "Google Inc.",
				Renderer:       "NVIDIA GeForce RTX 4070",
				ShadingVersion: "WebGL GLSL ES 3.00",
				Platform:       "Win32",
				MaxTextureSize: 16384,
				Extensions:     tt.extensions,
			}

			result := wa.Analyze(data)

			found := false
			for _, ind := range result.Indicators {
				if ind.Check == "missing_webgl_extensions" || ind.Check == "insufficient_webgl_extensions" {
					found = true
					break
				}
			}

			if found != tt.wantDetect {
				t.Errorf("extensions=%d: got detected=%v, want %v (score=%.3f)", len(tt.extensions), found, tt.wantDetect, result.Score)
			}
		})
	}
}

func TestMissingAudioData(t *testing.T) {
	detector := NewStealthDetector()

	tests := []struct {
		name       string
		hasAudio   bool
		wantDetect bool
	}{
		{"absent", false, true},
		{"present_valid", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://test/", nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			req.Header.Set("Accept-Encoding", "gzip, deflate, br")
			// Include a JS fingerprint header so the audio missing-data penalty is gated on
			req.Header.Set(constants.HeaderNavigatorData, `{"webdriver":false,"platform":"Win32"}`)

			if tt.hasAudio {
				audioData := map[string]interface{}{
					"sample_rate":       48000,
					"channel_count":     2,
					"max_channel_count": 2,
					"base_latency":      0.01,
					"output_latency":    0.0,
					"state":             "suspended",
				}
				audioJSON, _ := json.Marshal(audioData)
				req.Header.Set(constants.HeaderAudioData, string(audioJSON))
			}

			result := detector.AnalyzeRequest(req, nil)

			found := false
			for _, v := range result.Vectors {
				for _, ind := range v.Indicators {
					if ind == "missing_audio_data" {
						found = true
						break
					}
				}
			}
			if found != tt.wantDetect {
				t.Errorf("%s: got detected=%v, want %v", tt.name, found, tt.wantDetect)
			}
		})
	}
}

func TestCanvasIDATChunk(t *testing.T) {
	detector := NewStealthDetector()

	// Build a valid PNG with IDAT at byte 37
	validPNG := make([]byte, 200)
	// PNG signature
	copy(validPNG, []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A})
	// IHDR chunk (25 bytes: 4 len + 4 "IHDR" + 13 data + 4 CRC)
	copy(validPNG[8:], []byte{0x00, 0x00, 0x00, 0x0D}) // length 13
	copy(validPNG[12:], []byte("IHDR"))
	// 13 bytes of IHDR data + 4 bytes CRC = at offset 33
	// IDAT at offset 33: 4 len + 4 "IDAT"
	copy(validPNG[33:], []byte{0x00, 0x00, 0x00, 0x50}) // length
	copy(validPNG[37:], []byte("IDAT"))

	// Build invalid PNG - has PNG magic + IHDR but random bytes where IDAT should be
	invalidPNG := make([]byte, 200)
	copy(invalidPNG, []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A})
	copy(invalidPNG[8:], []byte{0x00, 0x00, 0x00, 0x0D})
	copy(invalidPNG[12:], []byte("IHDR"))
	copy(invalidPNG[37:], []byte("XXXX")) // not IDAT

	tests := []struct {
		name       string
		pngBytes   []byte
		wantDetect bool
	}{
		{"valid_idat", validPNG, false},
		{"invalid_idat", invalidPNG, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://test/", nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
			req.Header.Set("Accept", "text/html")
			req.Header.Set("Accept-Language", "en-US")
			req.Header.Set("Accept-Encoding", "gzip")

			// Pad to make base64 >= 200 chars
			padded := make([]byte, 300)
			copy(padded, tt.pngBytes)

			import_b64 := "data:image/png;base64," + base64Encode(padded)
			req.Header.Set(constants.HeaderCanvasFingerprint, import_b64)

			result := detector.AnalyzeRequest(req, nil)

			found := false
			for _, v := range result.Vectors {
				for _, ind := range v.Indicators {
					if ind == "canvas_missing_idat_chunk" {
						found = true
						break
					}
				}
			}
			if found != tt.wantDetect {
				t.Errorf("%s: got detected=%v, want %v", tt.name, found, tt.wantDetect)
			}
		})
	}
}

func TestRTTDownlinkCorrelation(t *testing.T) {
	detector := NewStealthDetector()

	tests := []struct {
		name       string
		rtt        int
		downlink   float64
		wantDetect bool
	}{
		{"correlated_low_rtt_high_dl", 25, 8.0, false},
		{"correlated_mid_rtt_mid_dl", 100, 5.0, false},
		{"correlated_high_rtt_low_dl", 175, 3.0, false},
		{"anticorrelated_low_rtt_low_dl", 25, 1.5, true},
		{"anticorrelated_high_rtt_high_dl", 175, 9.0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://test/", nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			req.Header.Set("Accept-Encoding", "gzip, deflate, br")

			navData := map[string]interface{}{
				"platform":  "Win32",
				"userAgent": req.Header.Get("User-Agent"),
				"languages": []string{"en-US", "en"},
				"connection": map[string]interface{}{
					"rtt":           tt.rtt,
					"downlink":      tt.downlink,
					"effectiveType": "4g",
				},
			}
			navJSON, _ := json.Marshal(navData)
			req.Header.Set(constants.HeaderNavigatorData, string(navJSON))

			result := detector.AnalyzeRequest(req, nil)

			found := false
			for _, v := range result.Vectors {
				for _, ind := range v.Indicators {
					if strings.HasPrefix(ind, "rtt_downlink_anticorrelated") {
						found = true
						break
					}
				}
			}
			if found != tt.wantDetect {
				t.Errorf("rtt=%d downlink=%.1f: got detected=%v, want %v", tt.rtt, tt.downlink, found, tt.wantDetect)
			}
		})
	}
}

func TestMissingScrollEvents(t *testing.T) {
	analyzer := NewBehavioralAnalyzer(nil)

	baseMouseTimestamps := []int64{
		1709500000000, 1709500000032, 1709500000078, 1709500000131,
		1709500000192, 1709500000284, 1709500000367, 1709500000445,
		1709500000591, 1709500000680, 1709500000712, 1709500000799,
	}
	baseMousePositions := []Position{
		{X: 100, Y: 200},
		{X: 101.2, Y: 200.8},
		{X: 102.5, Y: 199.3},
		{X: 115, Y: 190},
		{X: 135, Y: 178},
		{X: 160, Y: 175},
		{X: 161.5, Y: 175.8},
		{X: 190, Y: 182},
		{X: 210, Y: 195},
		{X: 205, Y: 200},
		{X: 195, Y: 210},
		{X: 196.2, Y: 209.5},
	}
	baseTypingTimestamps := []int64{
		1709500001000, 1709500001087, 1709500001243, 1709500002000, 1709500002200, 1709500002800,
	}
	baseScrollTimestamps := []int64{
		1709500000800, 1709500000855, 1709500002655, 1709500004555, 1709500004620, 1709500005320,
	}
	baseScrollDeltas := []float64{350, 320, 300, 100, 120, 80}

	tests := []struct {
		name          string
		mouseCount    int
		typingCount   int
		includeScroll bool
		wantDetect    bool
	}{
		{"with_scrolls", 12, 6, true, false},
		{"no_scrolls_with_activity", 12, 6, false, false},
		{"no_scrolls_low_mouse", 5, 6, false, false},
		{"no_scrolls_no_typing", 12, 0, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			events := &EnhancedBehavioralEvents{}

			events.MouseTimestamps = append(events.MouseTimestamps, baseMouseTimestamps[:tt.mouseCount]...)
			events.MousePositions = append(events.MousePositions, baseMousePositions[:tt.mouseCount]...)

			if tt.typingCount > 0 {
				events.TypingTimestamps = append(events.TypingTimestamps, baseTypingTimestamps[:tt.typingCount]...)
			}

			if tt.includeScroll {
				events.ScrollTimestamps = append(events.ScrollTimestamps, baseScrollTimestamps...)
				events.ScrollDeltas = append(events.ScrollDeltas, baseScrollDeltas...)
			}

			result := analyzer.Analyze(events)
			if result.Detected != tt.wantDetect {
				t.Errorf("%s: got detected=%v, want %v (score=%.3f indicators=%v)", tt.name, result.Detected, tt.wantDetect, result.Score, indicatorNames(result))
			}
		})
	}
}

func TestSecChUaVersionMismatch(t *testing.T) {
	detector := NewStealthDetector()

	tests := []struct {
		name       string
		secChUa    string
		userAgent  string
		wantDetect bool
	}{
		{
			"matching_134",
			`"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`,
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
			false,
		},
		{
			"mismatch_133_vs_134",
			`"Chromium";v="133", "Google Chrome";v="133", "Not-A.Brand";v="99"`,
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
			true,
		},
		{
			"firefox_no_sec_ch_ua",
			"",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
			false, // Firefox exempt — no Sec-Ch-Ua
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://test/", nil)
			req.Header.Set("User-Agent", tt.userAgent)
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			req.Header.Set("Accept-Encoding", "gzip, deflate, br")

			if tt.secChUa != "" {
				req.Header.Set("Sec-Ch-Ua", tt.secChUa)
				req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
				req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
			}

			// Need navigator data for isomorphic check to trigger
			navData := map[string]interface{}{
				"platform":  "Win32",
				"userAgent": tt.userAgent,
				"languages": []string{"en-US", "en"},
			}
			navJSON, _ := json.Marshal(navData)
			req.Header.Set(constants.HeaderNavigatorData, string(navJSON))

			result := detector.AnalyzeRequest(req, nil)

			found := false
			for _, v := range result.Vectors {
				for _, ind := range v.Indicators {
					if strings.HasPrefix(ind, "sec_ch_ua_version_mismatch") {
						found = true
						break
					}
				}
			}
			if found != tt.wantDetect {
				t.Errorf("%s: got detected=%v, want %v", tt.name, found, tt.wantDetect)
			}
		})
	}
}

// base64Encode is a test helper for encoding bytes to base64 for canvas tests.
func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func TestIsBareHexHash(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", true}, // SHA-256
		{"d41d8cd98f00b204e9800998ecf8427e", true},                                 // MD5
		{"AABBCCDD00112233445566778899aabb", true},                                 // mixed case
		{"abc", false},                       // too short
		{"data:image/png;base64,abc", false}, // not hex
		{`{"hash":"abc"}`, false},            // JSON
		{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", false}, // too long (>128)
		{"", false}, // empty
	}

	for _, tt := range tests {
		name := tt.input
		if len(name) > 20 {
			name = name[:20] + "..."
		}
		t.Run(fmt.Sprintf("%s_want_%v", name, tt.want), func(t *testing.T) {
			got := isBareHexHash(tt.input)
			if got != tt.want {
				t.Errorf("isBareHexHash(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// --- P11: Chrome API Surface Tests ---

func TestP11_MissingChromeApp(t *testing.T) {
	sd := NewStealthDetector()

	navJSON := `{"webdriver":false,"webdriverString":"function () { [native code] }","platform":"Win32","vendor":"Google Inc.","userAgent":"Mozilla/5.0 Chrome/134.0.0.0","appVersion":"5.0 Chrome/134.0.0.0","hardwareConcurrency":8,"deviceMemory":16,"cookieEnabled":true,"pdfViewerEnabled":true,"connection":{"rtt":50,"downlink":8.5,"effectiveType":"4g"},"languages":["en-US","en"],"screen_color_depth":24,"screen_inner_width":1903,"screen_outer_width":1920,"productSub":"20030107","maxTouchPoints":0,"chrome":{},"timezone":"America/New_York"}`

	req, _ := http.NewRequest("GET", "http://test/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/134.0.0.0")
	req.Header.Set(constants.HeaderNavigatorData, navJSON)

	result := sd.analyzeNavigatorData(req)
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	found := false
	for _, ind := range result.Indicators {
		if ind == "missing_chrome_app" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'missing_chrome_app' indicator, got: %v", result.Indicators)
	}
}

func TestP11_ChromeAppIncomplete(t *testing.T) {
	sd := NewStealthDetector()

	// chrome.app present but missing isInstalled
	navJSON := `{"webdriver":false,"webdriverString":"function () { [native code] }","platform":"Win32","vendor":"Google Inc.","userAgent":"Mozilla/5.0 Chrome/134.0.0.0","appVersion":"5.0 Chrome/134.0.0.0","hardwareConcurrency":8,"deviceMemory":16,"cookieEnabled":true,"pdfViewerEnabled":true,"connection":{"rtt":50,"downlink":8.5,"effectiveType":"4g"},"languages":["en-US","en"],"screen_color_depth":24,"screen_inner_width":1903,"screen_outer_width":1920,"productSub":"20030107","maxTouchPoints":0,"chrome":{},"chrome_app":{},"timezone":"America/New_York"}`

	req, _ := http.NewRequest("GET", "http://test/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/134.0.0.0")
	req.Header.Set(constants.HeaderNavigatorData, navJSON)

	result := sd.analyzeNavigatorData(req)
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	checks := map[string]bool{
		"chrome_app_missing_isInstalled":  false,
		"chrome_app_missing_InstallState": false,
		"chrome_app_missing_RunningState": false,
	}
	for _, ind := range result.Indicators {
		if _, ok := checks[ind]; ok {
			checks[ind] = true
		}
	}
	for check, found := range checks {
		if !found {
			t.Errorf("expected '%s' indicator", check)
		}
	}
}

func TestP11_MissingChromeCsi(t *testing.T) {
	sd := NewStealthDetector()

	navJSON := `{"webdriver":false,"webdriverString":"function () { [native code] }","platform":"Win32","vendor":"Google Inc.","userAgent":"Mozilla/5.0 Chrome/134.0.0.0","appVersion":"5.0 Chrome/134.0.0.0","hardwareConcurrency":8,"deviceMemory":16,"cookieEnabled":true,"pdfViewerEnabled":true,"connection":{"rtt":50,"downlink":8.5,"effectiveType":"4g"},"languages":["en-US","en"],"screen_color_depth":24,"screen_inner_width":1903,"screen_outer_width":1920,"productSub":"20030107","maxTouchPoints":0,"chrome":{},"chrome_app":{"isInstalled":false,"InstallState":{},"RunningState":{}},"timezone":"America/New_York"}`

	req, _ := http.NewRequest("GET", "http://test/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/134.0.0.0")
	req.Header.Set(constants.HeaderNavigatorData, navJSON)

	result := sd.analyzeNavigatorData(req)
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	found := false
	for _, ind := range result.Indicators {
		if ind == "missing_chrome_csi" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'missing_chrome_csi' indicator, got: %v", result.Indicators)
	}
}

func TestP11_MissingPerformanceMemory(t *testing.T) {
	sd := NewStealthDetector()

	navJSON := `{"webdriver":false,"webdriverString":"function () { [native code] }","platform":"Win32","vendor":"Google Inc.","userAgent":"Mozilla/5.0 Chrome/134.0.0.0","appVersion":"5.0 Chrome/134.0.0.0","hardwareConcurrency":8,"deviceMemory":16,"cookieEnabled":true,"pdfViewerEnabled":true,"connection":{"rtt":50,"downlink":8.5,"effectiveType":"4g"},"languages":["en-US","en"],"screen_color_depth":24,"screen_inner_width":1903,"screen_outer_width":1920,"productSub":"20030107","maxTouchPoints":0,"chrome":{},"chrome_app":{"isInstalled":false,"InstallState":{},"RunningState":{}},"chrome_csi":{"pageT":2000},"timezone":"America/New_York"}`

	req, _ := http.NewRequest("GET", "http://test/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/134.0.0.0")
	req.Header.Set(constants.HeaderNavigatorData, navJSON)

	result := sd.analyzeNavigatorData(req)
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	found := false
	for _, ind := range result.Indicators {
		if ind == "missing_performance_memory" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'missing_performance_memory' indicator, got: %v", result.Indicators)
	}
}

func TestP11_PerformanceMemoryInvalid(t *testing.T) {
	sd := NewStealthDetector()

	// usedJSHeapSize > totalJSHeapSize = impossible
	navJSON := `{"webdriver":false,"webdriverString":"function () { [native code] }","platform":"Win32","vendor":"Google Inc.","userAgent":"Mozilla/5.0 Chrome/134.0.0.0","appVersion":"5.0 Chrome/134.0.0.0","hardwareConcurrency":8,"deviceMemory":16,"cookieEnabled":true,"pdfViewerEnabled":true,"connection":{"rtt":50,"downlink":8.5,"effectiveType":"4g"},"languages":["en-US","en"],"screen_color_depth":24,"screen_inner_width":1903,"screen_outer_width":1920,"productSub":"20030107","maxTouchPoints":0,"chrome":{},"chrome_app":{"isInstalled":false,"InstallState":{},"RunningState":{}},"chrome_csi":{"pageT":2000},"performance_memory":{"jsHeapSizeLimit":4294705152,"totalJSHeapSize":35000000,"usedJSHeapSize":99000000},"timezone":"America/New_York"}`

	req, _ := http.NewRequest("GET", "http://test/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/134.0.0.0")
	req.Header.Set(constants.HeaderNavigatorData, navJSON)

	result := sd.analyzeNavigatorData(req)
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	found := false
	for _, ind := range result.Indicators {
		if ind == "performance_memory_used_exceeds_total" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'performance_memory_used_exceeds_total' indicator, got: %v", result.Indicators)
	}
}

func TestP11_ValidChromeAPIs(t *testing.T) {
	sd := NewStealthDetector()

	// All P11 Chrome APIs present and valid
	navJSON := `{"webdriver":false,"webdriverString":"function () { [native code] }","platform":"Win32","vendor":"Google Inc.","userAgent":"Mozilla/5.0 Chrome/134.0.0.0","appVersion":"5.0 Chrome/134.0.0.0","hardwareConcurrency":8,"deviceMemory":16,"cookieEnabled":true,"pdfViewerEnabled":true,"connection":{"rtt":50,"downlink":8.5,"effectiveType":"4g"},"languages":["en-US","en"],"screen_color_depth":24,"screen_inner_width":1903,"screen_outer_width":1920,"productSub":"20030107","maxTouchPoints":0,"chrome":{},"chrome_app":{"isInstalled":false,"InstallState":{"DISABLED":"disabled"},"RunningState":{"RUNNING":"running"}},"chrome_csi":{"pageT":2000,"startE":1709500000000},"performance_memory":{"jsHeapSizeLimit":4294705152,"totalJSHeapSize":35000000,"usedJSHeapSize":20000000},"timezone":"America/New_York"}`

	req, _ := http.NewRequest("GET", "http://test/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/134.0.0.0")
	req.Header.Set(constants.HeaderNavigatorData, navJSON)

	result := sd.analyzeNavigatorData(req)
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	p11Checks := []string{
		"missing_chrome_app", "chrome_app_missing_isInstalled",
		"missing_chrome_csi", "missing_performance_memory",
		"performance_memory_used_exceeds_total", "performance_memory_total_exceeds_limit",
	}
	for _, check := range p11Checks {
		for _, ind := range result.Indicators {
			if ind == check {
				t.Errorf("valid Chrome APIs should not trigger '%s'", check)
			}
		}
	}
}

func TestP11_FirefoxNoChromAPIs(t *testing.T) {
	sd := NewStealthDetector()

	// Firefox UA should NOT trigger Chrome-specific P11 checks
	navJSON := `{"webdriver":false,"webdriverString":"function () { [native code] }","platform":"Win32","vendor":"","userAgent":"Mozilla/5.0 Firefox/128.0","appVersion":"5.0 Firefox/128.0","hardwareConcurrency":8,"deviceMemory":16,"cookieEnabled":true,"pdfViewerEnabled":false,"connection":{"rtt":50,"downlink":8.5,"effectiveType":"4g"},"languages":["en-US","en"],"screen_color_depth":24,"screen_inner_width":1903,"screen_outer_width":1920,"productSub":"20100101","maxTouchPoints":0,"timezone":"America/New_York"}`

	req, _ := http.NewRequest("GET", "http://test/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 Firefox/128.0")
	req.Header.Set(constants.HeaderNavigatorData, navJSON)

	result := sd.analyzeNavigatorData(req)
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	chromeChecks := []string{
		"missing_chrome_runtime", "missing_chrome_app", "missing_chrome_csi",
		"missing_performance_memory",
	}
	for _, check := range chromeChecks {
		for _, ind := range result.Indicators {
			if ind == check {
				t.Errorf("Firefox should not trigger Chrome-specific check '%s'", check)
			}
		}
	}
}

func TestMediaQueryHover(t *testing.T) {
	detector := NewStealthDetector()

	tests := []struct {
		name       string
		ua         string
		navData    map[string]interface{}
		wantDetect bool
		wantInd    string
	}{
		{
			"desktop_hover_correct",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
			map[string]interface{}{
				"media_query_hover": "hover",
			},
			false,
			"",
		},
		{
			"desktop_hover_none",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
			map[string]interface{}{
				"media_query_hover": "none",
			},
			true,
			"none_media_query_hover",
		},
		{
			"desktop_hover_missing",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
			map[string]interface{}{},
			true,
			"missing_media_query_hover",
		},
		{
			"mobile_hover_none_allowed",
			"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
			map[string]interface{}{
				"media_query_hover": "none",
			},
			false,
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://test/", nil)
			req.Header.Set("User-Agent", tt.ua)

			navJSON, _ := json.Marshal(tt.navData)
			req.Header.Set(constants.HeaderNavigatorData, string(navJSON))

			result := detector.AnalyzeRequest(req, nil)

			found := false
			for _, v := range result.Vectors {
				for _, ind := range v.Indicators {
					if ind == tt.wantInd {
						found = true
						break
					}
				}
			}
			if found != tt.wantDetect {
				t.Errorf("%s: got detected=%v for '%s', want %v", tt.name, found, tt.wantInd, tt.wantDetect)
			}
		})
	}
}

func TestGPUCoreCoherence(t *testing.T) {
	sd := NewStealthDetector()

	tests := []struct {
		name       string
		renderer   string
		cores      int
		wantDetect bool
	}{
		{"apple_m2_8_cores", "Apple M2", 8, false},
		{"apple_m2_4_cores", "Apple M2", 4, true},
		{"rtx_4090_12_cores", "NVIDIA GeForce RTX 4090", 12, false},
		{"rtx_4090_4_cores", "NVIDIA GeForce RTX 4090", 4, true},
		{"intel_uhd_4_cores", "Intel UHD Graphics 630", 4, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://test/", nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")

			navData := map[string]interface{}{
				"hardwareConcurrency": float64(tt.cores),
			}
			navBytes, _ := json.Marshal(navData)
			req.Header.Set(constants.HeaderNavigatorData, string(navBytes))

			webglData := map[string]interface{}{
				"unmasked_renderer": tt.renderer,
			}
			webglBytes, _ := json.Marshal(webglData)
			req.Header.Set(constants.HeaderWebGLData, string(webglBytes))

			detection := sd.AnalyzeRequest(req, nil)

			found := false
			for _, vec := range detection.Vectors {
				if vec.Category == "isomorphic" {
					for _, ind := range vec.Indicators {
						if strings.HasPrefix(ind, "hardware_core_mismatch") {
							found = true
						}
					}
				}
			}

			if found != tt.wantDetect {
				t.Errorf("got detect=%v, want %v", found, tt.wantDetect)
			}
		})
	}
}

func TestPhase51Gaps(t *testing.T) {
	detector := NewStealthDetector()
	detector.config.EnableNavigatorCheck = true

	tests := []struct {
		name       string
		ua         string
		navData    map[string]interface{}
		wantDetect string
	}{
		{
			name: "Pointer None on Desktop",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			navData: map[string]interface{}{
				"media_query_pointer": "none",
			},
			wantDetect: "pointer_mismatch",
		},
		{
			name: "Any Pointer Coarse on Desktop",
			ua:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			navData: map[string]interface{}{
				"media_query_any_pointer": "coarse",
			},
			wantDetect: "any_pointer_mismatch",
		},
		{
			name: "Suspicious Plugin Filename on Chrome",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			navData: map[string]interface{}{
				"plugins": []interface{}{
					map[string]interface{}{
						"name":     "PDF Viewer",
						"filename": "pdf-viewer.dll", // Suspicious, should be internal-pdf-viewer
					},
				},
			},
			wantDetect: "suspicious_plugin_filename",
		},
		{
			name: "Valid Chrome Interaction & Plugins",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			navData: map[string]interface{}{
				"media_query_pointer":     "fine",
				"media_query_any_pointer": "fine",
				"plugins": []interface{}{
					map[string]interface{}{
						"name":     "PDF Viewer",
						"filename": "internal-pdf-viewer",
					},
				},
			},
			wantDetect: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "https://example.com/", nil)
			req.Header.Set("User-Agent", tt.ua)

			navJSON, _ := json.Marshal(tt.navData)
			req.Header.Set(constants.HeaderNavigatorData, string(navJSON))

			detection := detector.AnalyzeRequest(req, nil)
			found := false
			for _, vec := range detection.Vectors {
				for _, ind := range vec.Indicators {
					if strings.Contains(ind, tt.wantDetect) && tt.wantDetect != "" {
						found = true
						break
					}
				}
			}

			if tt.wantDetect == "" {
				if found {
					t.Errorf("expected no detection, but found %v", detection.Indicators)
				}
			} else {
				if !found {
					t.Errorf("did not find indicator %s in %v", tt.wantDetect, detection.Indicators)
				}
			}
		})
	}
}

func TestPhase52Gaps(t *testing.T) {
	detector := NewStealthDetector()
	detector.config.EnableNavigatorCheck = true

	tests := []struct {
		name       string
		ua         string
		navData    map[string]interface{}
		wantDetect string
	}{
		{
			name: "Missing WebGPU on Chrome",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
			navData: map[string]interface{}{
				"gpu_present": false,
			},
			wantDetect: "missing_webgpu",
		},
		{
			name: "Permissions Query Mismatch",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			navData: map[string]interface{}{
				"Notification_permission":         "default",
				"permissions_notifications_state": "denied",
			},
			wantDetect: "permissions_query_mismatch",
		},
		{
			name: "Valid Chrome 113 with WebGPU",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
			navData: map[string]interface{}{
				"gpu_present":                     true,
				"Notification_permission":         "default",
				"permissions_notifications_state": "default",
			},
			wantDetect: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "https://example.com/", nil)
			req.Header.Set("User-Agent", tt.ua)

			navJSON, _ := json.Marshal(tt.navData)
			req.Header.Set(constants.HeaderNavigatorData, string(navJSON))

			detection := detector.AnalyzeRequest(req, nil)
			found := false
			for _, vec := range detection.Vectors {
				for _, ind := range vec.Indicators {
					if strings.Contains(ind, tt.wantDetect) && tt.wantDetect != "" {
						found = true
						break
					}
				}
			}

			if tt.wantDetect == "" {
				if len(detection.Indicators) > 0 {
					// Filter for the new indicators we care about
					for _, ind := range detection.Indicators {
						if strings.Contains(ind.Name, "missing_webgpu") || strings.Contains(ind.Name, "permissions_query_mismatch") {
							t.Errorf("unexpected check fired: %s", ind.Name)
						}
					}
				}
			} else {
				if !found {
					t.Errorf("did not find indicator %s in %v", tt.wantDetect, detection.Indicators)
				}
			}
		})
	}
}

func TestPhase53Gaps(t *testing.T) {
	detector := NewStealthDetector()
	detector.config.EnableNavigatorCheck = true

	tests := []struct {
		name       string
		audioData  map[string]interface{}
		navData    map[string]interface{}
		wantDetect string
	}{
		{
			name: "Zero Audio Base Latency",
			audioData: map[string]interface{}{
				"base_latency": 0.0,
			},
			wantDetect: "audio_zero_base_latency",
		},
		{
			name: "Missing Audio Base Latency",
			audioData: map[string]interface{}{
				"output_latency": 0.005,
				// base_latency missing
			},
			wantDetect: "missing_audio_base_latency",
		},
		{
			name: "Screen Orientation Mismatch (Landscape dims, Portrait orientation)",
			navData: map[string]interface{}{
				"screen_inner_width":  1920,
				"screen_inner_height": 1080,
				"screen_orientation":  "portrait-primary",
			},
			wantDetect: "screen_orientation_mismatch",
		},
		{
			name: "Screen Orientation Mismatch (Portrait dims, Landscape orientation)",
			navData: map[string]interface{}{
				"screen_inner_width":  1080,
				"screen_inner_height": 1920,
				"screen_orientation":  "landscape-primary",
			},
			wantDetect: "screen_orientation_mismatch",
		},
		{
			name: "Valid Phase 53 Interaction",
			audioData: map[string]interface{}{
				"base_latency": 0.002,
			},
			navData: map[string]interface{}{
				"screen_inner_width":  1920,
				"screen_inner_height": 1080,
				"screen_orientation":  "landscape-primary",
			},
			wantDetect: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "https://example.com/", nil)

			if tt.audioData != nil {
				audioJSON, _ := json.Marshal(tt.audioData)
				req.Header.Set(constants.HeaderAudioData, string(audioJSON))
			}

			if tt.navData != nil {
				navJSON, _ := json.Marshal(tt.navData)
				req.Header.Set(constants.HeaderNavigatorData, string(navJSON))
			} else {
				req.Header.Set(constants.HeaderNavigatorData, "{}")
			}

			detection := detector.AnalyzeRequest(req, nil)
			found := false
			for _, vec := range detection.Vectors {
				for _, ind := range vec.Indicators {
					if strings.Contains(ind, tt.wantDetect) && tt.wantDetect != "" {
						found = true
						break
					}
				}
			}

			if tt.wantDetect == "" {
				if len(detection.Indicators) > 0 {
					for _, ind := range detection.Indicators {
						if strings.Contains(ind.Name, "audio_zero_base_latency") ||
							strings.Contains(ind.Name, "missing_audio_base_latency") ||
							strings.Contains(ind.Name, "screen_orientation_mismatch") {
							t.Errorf("unexpected check fired: %s", ind.Name)
						}
					}
				}
			} else {
				if !found {
					t.Errorf("did not find indicator %s in %v", tt.wantDetect, detection.Indicators)
				}
			}
		})
	}
}

func TestPhase54Gaps(t *testing.T) {
	detector := NewStealthDetector()
	detector.config.EnableNavigatorCheck = true

	tests := []struct {
		name       string
		navData    map[string]interface{}
		wantDetect string
	}{
		{
			name: "Suspicious Battery Status (Static 100% Charging)",
			navData: map[string]interface{}{
				"battery_status": map[string]interface{}{
					"level":           1.0,
					"charging":        true,
					"chargingTime":    0.0,
					"dischargingTime": 1e308,
				},
			},
			wantDetect: "suspicious_battery_status",
		},
		{
			name: "Low Storage Quota",
			navData: map[string]interface{}{
				"storage_quota": 512 * 1024.0, // 512KB
			},
			wantDetect: "low_storage_quota",
		},
		{
			name:    "Missing Storage Quota",
			navData: map[string]interface{}{
				// storage_quota missing
			},
			wantDetect: "missing_storage_quota",
		},
		{
			name: "Valid Phase 54 Interaction",
			navData: map[string]interface{}{
				"battery_status": map[string]interface{}{
					"level":           0.75,
					"charging":        false,
					"chargingTime":    0.0,
					"dischargingTime": 12000.0,
				},
				"storage_quota": 500 * 1024 * 1024 * 1024.0, // 500GB
			},
			wantDetect: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "https://example.com/", nil)

			if tt.navData != nil {
				navJSON, _ := json.Marshal(tt.navData)
				req.Header.Set(constants.HeaderNavigatorData, string(navJSON))
			} else {
				req.Header.Set(constants.HeaderNavigatorData, "{}")
			}

			detection := detector.AnalyzeRequest(req, nil)
			found := false
			for _, vec := range detection.Vectors {
				for _, ind := range vec.Indicators {
					if strings.Contains(ind, tt.wantDetect) && tt.wantDetect != "" {
						found = true
						break
					}
				}
			}

			if tt.wantDetect == "" {
				if len(detection.Indicators) > 0 {
					for _, ind := range detection.Indicators {
						if strings.Contains(ind.Name, "suspicious_battery_status") ||
							strings.Contains(ind.Name, "low_storage_quota") ||
							strings.Contains(ind.Name, "missing_storage_quota") {
							t.Errorf("unexpected check fired: %s", ind.Name)
						}
					}
				}
			} else {
				if !found {
					t.Errorf("did not find indicator %s in %v", tt.wantDetect, detection.Indicators)
				}
			}
		})
	}
}

func TestPhase55Gaps(t *testing.T) {
	detector := NewStealthDetector()
	detector.config.EnableNavigatorCheck = true

	tests := []struct {
		name       string
		navData    map[string]interface{}
		wantDetect string
	}{
		{
			name: "Empty Media Devices",
			navData: map[string]interface{}{
				"media_devices": []interface{}{},
			},
			wantDetect: "empty_media_devices",
		},
		{
			name: "Suspicious Media Device ID (Empty)",
			navData: map[string]interface{}{
				"media_devices": []interface{}{
					map[string]interface{}{
						"deviceId": "",
						"kind":     "audioinput",
						"label":    "Internal Microphone",
						"groupId":  "some-group",
					},
				},
			},
			wantDetect: "",
		},
		{
			name: "Non-standard Media Device ID Format",
			navData: map[string]interface{}{
				"media_devices": []interface{}{
					map[string]interface{}{
						"deviceId": "short-id",
						"kind":     "audioinput",
						"label":    "Internal Microphone",
						"groupId":  "some-group-id-which-is-also-short",
					},
				},
			},
			wantDetect: "non_standard_media_device_id_format",
		},
		{
			name: "Valid Media Devices",
			navData: map[string]interface{}{
				"media_devices": []interface{}{
					map[string]interface{}{
						"deviceId": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
						"kind":     "audioinput",
						"label":    "Internal Microphone",
						"groupId":  "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
					},
				},
			},
			wantDetect: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "https://example.com/", nil)

			navJSON, _ := json.Marshal(tt.navData)
			req.Header.Set(constants.HeaderNavigatorData, string(navJSON))

			detection := detector.AnalyzeRequest(req, nil)
			found := false
			for _, vec := range detection.Vectors {
				for _, ind := range vec.Indicators {
					if strings.Contains(ind, tt.wantDetect) && tt.wantDetect != "" {
						found = true
						break
					}
				}
			}

			if tt.wantDetect == "" {
				if len(detection.Indicators) > 0 {
					for _, ind := range detection.Indicators {
						if strings.Contains(ind.Name, "empty_media_devices") ||
							strings.Contains(ind.Name, "suspicious_media_device_id") ||
							strings.Contains(ind.Name, "non_standard_media_device_id_format") {
							t.Errorf("unexpected check fired: %s", ind.Name)
						}
					}
				}
			} else {
				if !found {
					t.Errorf("did not find indicator %s in %v", tt.wantDetect, detection.Indicators)
				}
			}
		})
	}
}

func TestPhase56Gaps(t *testing.T) {
	detector := NewStealthDetector()
	detector.config.EnableNavigatorCheck = true

	tests := []struct {
		name       string
		ua         string
		navData    map[string]interface{}
		wantDetect string
	}{
		{
			name: "Missing WebRTC (Chrome Desktop)",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
			navData: map[string]interface{}{
				"webrtc_data": nil,
			},
			wantDetect: "missing_webrtc",
		},
		{
			name: "Empty ICE Candidates",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
			navData: map[string]interface{}{
				"webrtc_data": map[string]interface{}{
					"ice_candidates": []interface{}{},
				},
			},
			wantDetect: "empty_ice_candidates",
		},
		{
			name: "Suspicious ICE Format",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
			navData: map[string]interface{}{
				"webrtc_data": map[string]interface{}{
					"ice_candidates": []interface{}{
						"192.168.1.1", // missing prefix
					},
				},
			},
			wantDetect: "suspicious_ice_format",
		},
		{
			name: "Valid WebRTC",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
			navData: map[string]interface{}{
				"webrtc_data": map[string]interface{}{
					"ice_candidates": []interface{}{
						"candidate:0 1 UDP 2122252543 12345678-1234-4321-abcd-1234567890ab.local 58349 typ host",
					},
				},
			},
			wantDetect: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "https://example.com/", nil)
			req.Header.Set("User-Agent", tt.ua)

			navJSON, _ := json.Marshal(tt.navData)
			req.Header.Set(constants.HeaderNavigatorData, string(navJSON))

			detection := detector.AnalyzeRequest(req, nil)
			found := false
			for _, vec := range detection.Vectors {
				for _, ind := range vec.Indicators {
					if strings.Contains(ind, tt.wantDetect) && tt.wantDetect != "" {
						found = true
						break
					}
				}
			}

			if tt.wantDetect == "" {
				if len(detection.Indicators) > 0 {
					for _, ind := range detection.Indicators {
						if strings.Contains(ind.Name, "missing_webrtc") ||
							strings.Contains(ind.Name, "empty_ice_candidates") ||
							strings.Contains(ind.Name, "suspicious_ice_format") {
							t.Errorf("unexpected check fired: %s", ind.Name)
						}
					}
				}
			} else {
				if !found {
					t.Errorf("did not find indicator %s in %v", tt.wantDetect, detection.Indicators)
				}
			}
		})
	}
}

func TestPhase57Gaps(t *testing.T) {
	detector := NewStealthDetector()
	detector.config.EnableCanvasCheck = true

	// Helper to create a valid base64 PNG with specific uncompressed IDAT content
	createCanvas := func(rawPixels []byte) string {
		var idatBuf bytes.Buffer
		zlibW := zlib.NewWriter(&idatBuf)
		zlibW.Write(rawPixels)
		zlibW.Close()
		idatData := idatBuf.Bytes()

		png := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}

		// IHDR: 13 bytes data + 4 bytes "IHDR"
		png = append(png, 0x00, 0x00, 0x00, 0x0D) // IHDR length
		png = append(png, 0x49, 0x48, 0x44, 0x52)
		png = append(png, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x00, 0x00, 0xC8, 0x08, 0x06, 0x00, 0x00, 0x00)
		png = append(png, 0x00, 0x00, 0x00, 0x00) // CRC dummy

		// IDAT: len(idatData) data + 4 bytes "IDAT"
		size := uint32(len(idatData))
		png = append(png, byte(size>>24), byte(size>>16), byte(size>>8), byte(size))
		png = append(png, 0x49, 0x44, 0x41, 0x54)
		png = append(png, idatData...)
		png = append(png, 0x00, 0x00, 0x00, 0x00) // CRC dummy

		return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
	}

	tests := []struct {
		name       string
		pixels     []byte
		wantDetect string
	}{
		{
			name: "High Entropy Noise",
			pixels: func() []byte {
				p := make([]byte, 16384)
				for i := range p {
					p[i] = byte(i % 256)
				}
				return p
			}(),
			wantDetect: "canvas_idat_high_entropy",
		},
		{
			name: "Spatial Inconsistency (Modulo Noise)",
			pixels: func() []byte {
				p := make([]byte, 16384)
				for i := range p {
					if i%100 == 0 {
						p[i] = byte(i % 256) // Random-ish byte to break compression
					} else if i%17 == 0 {
						p[i] = 128
					} else {
						p[i] = 255
					}
				}
				return p
			}(),
			wantDetect: "canvas_spatial_inconsistency",
		},
		{
			name: "Valid Correlated Noise",
			pixels: func() []byte {
				p := make([]byte, 16384)
				for i := 0; i < 16384; i += 100 {
					val := byte(i / 10)
					for j := 0; j < 100 && i+j < 16384; j++ {
						p[i+j] = val
					}
				}
				return p
			}(),
			wantDetect: "",
		},
		{
			name: "Plain White Canvas",
			pixels: func() []byte {
				p := make([]byte, 16384)
				for i := range p {
					p[i] = 255
				}
				return p
			}(),
			wantDetect: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "https://example.com/", nil)
			req.Header.Set(constants.HeaderCanvasFingerprint, createCanvas(tt.pixels))

			detection := detector.AnalyzeRequest(req, nil)
			found := false
			for _, ind := range detection.Indicators {
				if strings.Contains(ind.Name, tt.wantDetect) && tt.wantDetect != "" {
					found = true
					break
				}
			}

			if tt.wantDetect == "" {
				if len(detection.Indicators) > 0 {
					for _, ind := range detection.Indicators {
						if strings.Contains(ind.Name, "canvas_idat_high_entropy") ||
							strings.Contains(ind.Name, "canvas_spatial_inconsistency") {
							t.Errorf("unexpected check fired: %s", ind.Name)
						}
					}
				}
			} else {
				if !found {
					t.Errorf("did not find indicator %s", tt.wantDetect)
				}
			}
		})
	}
}
