package adversarial

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"strings"

	"github.com/skunkworq/stealth/brws/constants"
)

// GraphicsAnalyzer handles analysis and validation of Canvas and WebGL fingerprints.
type GraphicsAnalyzer struct {
	webglAnalyzer *WebGLAnalyzer
}

// NewGraphicsAnalyzer creates a new GraphicsAnalyzer.
func NewGraphicsAnalyzer() *GraphicsAnalyzer {
	return &GraphicsAnalyzer{
		webglAnalyzer: NewWebGLAnalyzer(),
	}
}

// AnalyzeCanvas performs analysis of canvas fingerprint data.
func (ga *GraphicsAnalyzer) AnalyzeCanvas(req *http.Request) *DetectionVector {
	canvasHeader := req.Header.Get(constants.HeaderCanvasFingerprint)
	if canvasHeader == "" {
		if hasJSFingerprintHeaders(req) {
			return &DetectionVector{
				Name:        "Canvas/WebGL Fingerprint",
				Category:    string(VectorCanvas),
				Score:       0.35,
				Weight:      constants.WeightCanvas,
				Detected:    true,
				Description: "Canvas fingerprint data missing (client has JS context but no canvas toDataURL output)",
				Indicators:  []string{"missing_canvas_data"},
			}
		}
		return nil
	}

	vec := &DetectionVector{
		Name:        "Canvas/WebGL Fingerprint",
		Category:    "canvas",
		Weight:      constants.WeightTLS,
		Description: "Analyzes canvas and WebGL fingerprints for randomization",
	}

	indicators := make([]string, 0)

	// Check if canvas hash changes (randomization)
	if strings.Contains(canvasHeader, "randomized") {
		indicators = append(indicators, "canvas_randomization_detected")
		vec.Score += 0.4
	}

	// Check for suspicious WebGL fingerprints
	if strings.Contains(canvasHeader, "swiftshader") {
		indicators = append(indicators, "software_renderer")
		vec.Score += 0.2
	}

	// Check for masked WebGL
	if strings.Contains(canvasHeader, "google") || strings.Contains(canvasHeader, "intel") {
		// These are common real browser fingerprints - no action needed
	} else if strings.Contains(canvasHeader, "unknown") {
		indicators = append(indicators, "masked_webgl")
		vec.Score += 0.3
	}

	// Check for bare hex hash format
	if isBareHexHash(canvasHeader) {
		indicators = append(indicators, "synthetic_canvas_hash_format")
		vec.Score += 0.5
	}

	// Check for too-short canvas data URL payload
	if strings.HasPrefix(canvasHeader, "data:image/png;base64,") {
		payload := canvasHeader[len("data:image/png;base64,"):]
		if len(payload) < 200 {
			indicators = append(indicators, "canvas_payload_too_short")
			vec.Score += 0.5
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "canvas_payload_too_short",
				Fired:       true,
				Weight:      0.5,
				Score:       0.5,
				Field:       "canvas_payload_length",
				Actual:      fmt.Sprintf("%d", len(payload)),
				Expected:    ">= 200",
				Severity:    "high",
				Description: fmt.Sprintf("Canvas payload too short: %d chars (min 200 expected)", len(payload)),
			})
		}

		// Check PNG magic header
		if len(payload) >= 200 && !strings.HasPrefix(payload, "iVBOR") {
			indicators = append(indicators, "canvas_png_magic_header_missing")
			vec.Score += 0.55
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "canvas_png_magic_header",
				Fired:       true,
				Weight:      0.55,
				Score:       0.55,
				Field:       "canvas_base64_prefix",
				Actual:      safePrefix(payload, 5),
				Expected:    "iVBOR",
				Severity:    "high",
				Description: "Canvas data URL does not start with PNG magic bytes (iVBOR)",
			})
		}

		// Check IDAT chunk structure
		if len(payload) >= 200 && strings.HasPrefix(payload, "iVBOR") {
			if decoded, err := base64.StdEncoding.DecodeString(payload); err == nil && len(decoded) > 40 {
				// Robust IDAT search (try all chunks until we find valid pixels)
				var rawPixels []byte
				var entropy float64
				foundIDAT := false
				for i := 4; i < len(decoded)-8; i++ {
					if string(decoded[i:i+4]) == "IDAT" {
						foundIDAT = true
						length := binary.BigEndian.Uint32(decoded[i-4 : i])
						if i+4+int(length) <= len(decoded) {
							idatData := decoded[i+4 : i+4+int(length)]
							if len(idatData) > 0 {
								r, zlibErr := zlib.NewReader(bytes.NewReader(idatData))
								if zlibErr == nil {
									pixels, readErr := io.ReadAll(r)
									_ = r.Close()
									if readErr == nil && len(pixels) > 0 {
										rawPixels = pixels
										// Calculate entropy for this chunk
										counts := make(map[byte]int)
										for _, b := range rawPixels {
											counts[b]++
										}
										chunkEntropy := 0.0
										for _, c := range counts {
											p := float64(c) / float64(len(rawPixels))
											chunkEntropy -= p * math.Log2(p)
										}
										entropy = chunkEntropy
										break // Found valid data
									}
								}
							}
						}
					}
				}

				if !foundIDAT {
					indicators = append(indicators, "canvas_missing_idat_chunk")
					vec.Score += 0.40
				} else if len(rawPixels) == 0 {
					// Found IDAT tag but couldn't decompress - suspicious but less certain than missing entirely
					indicators = append(indicators, "canvas_malformed_idat_chunk")
					vec.Score += 0.20
				} else {
					// Canvas IDAT Entropy/Spatial Analysis
					if entropy > 7.9 {
						indicators = append(indicators, "canvas_idat_high_entropy")
						vec.Score += 0.45
						vec.CheckReports = append(vec.CheckReports, CheckReport{
							Name:        "canvas_idat_high_entropy",
							Fired:       true,
							Weight:      0.45,
							Score:       0.45,
							Field:       "canvas_entropy",
							Actual:      fmt.Sprintf("%.2f", entropy),
							Expected:    "< 7.9",
							Severity:    "medium",
							Description: fmt.Sprintf("Canvas IDAT high entropy: %.2f (synthetic noise)", entropy),
						})
					}

					// 2. Spatial Consistency Check (Phase 57)
					if len(rawPixels) > 2 {
						totalDiff := 0.0
						for i := 1; i < len(rawPixels); i++ {
							diff := math.Abs(float64(rawPixels[i]) - float64(rawPixels[i-1]))
							totalDiff += diff
						}
						avgDiff := totalDiff / float64(len(rawPixels)-1)

						if avgDiff > 10.0 {
							indicators = append(indicators, "canvas_spatial_inconsistency")
							vec.Score += 0.35
							vec.CheckReports = append(vec.CheckReports, CheckReport{
								Name:        "canvas_spatial_inconsistency",
								Fired:       true,
								Weight:      0.35,
								Score:       0.35,
								Field:       "canvas_spatial_variance",
								Actual:      fmt.Sprintf("%.2f", avgDiff),
								Expected:    "< 10.0",
								Severity:    "medium",
								Description: fmt.Sprintf("Canvas IDAT spatial inconsistency: %.2f (uncorrelated noise)", avgDiff),
							})
						}
					}
				}
			}
		}
	}

	indicators = ga.checkOffscreenCanvas(req, vec, indicators)
	indicators = ga.checkOffscreenCanvasMetrics(req, vec, indicators)
	log.Printf("ANALYZE_CANVAS: score=%.2f indicators=%v", vec.Score, indicators)

	vec.Indicators = indicators
	if vec.Score > 1.0 {
		vec.Score = 1.0
	}
	vec.Detected = vec.Score > 0.3
	return vec
}

func (ga *GraphicsAnalyzer) checkOffscreenCanvas(req *http.Request, vec *DetectionVector, indicators []string) []string {
	navHeader := req.Header.Get(constants.HeaderNavigatorData)
	if navHeader == "" {
		return indicators
	}

	var navData map[string]interface{}
	if err := json.Unmarshal([]byte(navHeader), &navData); err != nil {
		return indicators
	}

	ua := req.Header.Get("User-Agent")
	uaLower := strings.ToLower(ua)
	isChrome := strings.Contains(uaLower, "chrome")
	isFirefox := strings.Contains(uaLower, "firefox")

	// OffscreenCanvas is standard in modern Chrome (69+) and Firefox (105+)
	if isChrome || isFirefox {
		offscreenAvail, ok := navData["offscreen_canvas_available"].(bool)
		if ok && !offscreenAvail {
			indicators = append(indicators, "missing_offscreen_canvas")
			vec.Score += 0.35
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "missing_offscreen_canvas",
				Fired:       true,
				Weight:      0.35,
				Score:       0.35,
				Field:       "OffscreenCanvas",
				Actual:      "false/missing",
				Expected:    "true",
				Severity:    "high",
				Description: "OffscreenCanvas API is missing, which is standard in modern browsers. Common in headless or outdated bot environments.",
			})
		}
	}

	return indicators
}

func (ga *GraphicsAnalyzer) checkOffscreenCanvasMetrics(req *http.Request, vec *DetectionVector, indicators []string) []string {
	navHeader := req.Header.Get(constants.HeaderNavigatorData)
	if navHeader == "" {
		return indicators
	}

	var navData map[string]interface{}
	if err := json.Unmarshal([]byte(navHeader), &navData); err != nil {
		return indicators
	}

	// offscreen_canvas_text_metrics: { "width": 123.45 }
	// main_canvas_text_metrics: { "width": 123.45 }
	offscreen, hasOffscreen := navData["offscreen_canvas_text_metrics"].(map[string]interface{})
	main, hasMain := navData["main_canvas_text_metrics"].(map[string]interface{})

	if hasOffscreen && hasMain {
		offWidth, _ := offscreen["width"].(float64)
		mainWidth, _ := main["width"].(float64)

		diff := math.Abs(offWidth - mainWidth)
		if diff > 0.1 {
			indicators = append(indicators, "offscreen_canvas_metrics_mismatch")
			vec.Score += 0.45
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "offscreen_canvas_metrics_mismatch",
				Fired:       true,
				Weight:      0.45,
				Score:       0.45,
				Field:       "OffscreenCanvas vs Canvas text metrics",
				Actual:      fmt.Sprintf("offscreen=%.2f main=%.2f", offWidth, mainWidth),
				Expected:    "exact match",
				Severity:    "high",
				Description: "The font metrics (e.g., text width) on OffscreenCanvas do not match the main Canvas, indicating inconsistent font rendering or stubbing.",
			})
		}
	}

	return indicators
}

// AnalyzeWebGL performs deep WebGL analysis.
func (ga *GraphicsAnalyzer) AnalyzeWebGL(req *http.Request) *DetectionVector {
	webglHeader := req.Header.Get(constants.HeaderWebGLData)
	if webglHeader == "" {
		return nil
	}

	var data WebGLData
	if err := json.Unmarshal([]byte(webglHeader), &data); err != nil {
		return nil
	}

	result := ga.webglAnalyzer.Analyze(&data)

	indicators := make([]string, 0, len(result.Indicators))
	for _, ind := range result.Indicators {
		indicators = append(indicators, ind.Check)
	}

	return &DetectionVector{
		Name:        "WebGL Deep Analysis",
		Category:    string(VectorWebGL),
		Score:       result.Score,
		Weight:      constants.WeightWebGL,
		Detected:    result.Detected,
		Description: "Deep WebGL renderer and platform consistency analysis",
		Indicators:  indicators,
	}
}

// safePrefix returns the first n characters of s, or s if shorter.
func safePrefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// isBareHexHash returns true if the string is a bare hexadecimal hash (32-128 chars
// of only [0-9a-fA-F]). Real canvas fingerprints use data URLs, JSON, or library prefixes.
func isBareHexHash(s string) bool {
	if len(s) < 32 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}
