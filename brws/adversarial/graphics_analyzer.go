package adversarial

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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
			indicators = append(indicators, fmt.Sprintf("canvas_payload_too_short: %d chars (min 200 expected)", len(payload)))
			vec.Score += 0.5
		}

		// Check PNG magic header
		if len(payload) >= 200 && !strings.HasPrefix(payload, "iVBOR") {
			indicators = append(indicators, "canvas_png_magic_header_missing")
			vec.Score += 0.55
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:     "canvas_png_magic_header",
				Fired:    true,
				Weight:   0.55,
				Score:    0.55,
				Field:    "canvas_base64_prefix",
				Actual:   safePrefix(payload, 5),
				Expected: "iVBOR",
				Severity: "high",
				Description: "Canvas data URL does not start with PNG magic bytes (iVBOR)",
			})
		}

		// Check IDAT chunk structure
		if len(payload) >= 200 && strings.HasPrefix(payload, "iVBOR") {
			if decoded, err := base64.StdEncoding.DecodeString(payload); err == nil && len(decoded) > 40 {
				if string(decoded[37:41]) != "IDAT" {
					indicators = append(indicators, "canvas_missing_idat_chunk")
					vec.Score += 0.40
				} else {
					// IDAT exists — validate its data is valid zlib/DEFLATE
					idatLen := int(decoded[33])<<24 | int(decoded[34])<<16 | int(decoded[35])<<8 | int(decoded[36])
					if idatLen > 0 && len(decoded) >= 41+idatLen {
						idatData := decoded[41 : 41+idatLen]
						r, zlibErr := zlib.NewReader(bytes.NewReader(idatData))
						if zlibErr != nil {
							indicators = append(indicators, "canvas_idat_not_deflate")
							vec.Score += 0.55
						} else {
							_, readErr := io.ReadAll(r)
							_ = r.Close()
							if readErr != nil {
								indicators = append(indicators, "canvas_idat_corrupt_deflate")
								vec.Score += 0.50
							} else {
								// Canvas IDAT Entropy Threshold
								r2, _ := zlib.NewReader(bytes.NewReader(idatData))
								rawPixels, _ := io.ReadAll(r2)
								_ = r2.Close()
								if len(rawPixels) > 0 {
									counts := make(map[byte]int)
									for _, b := range rawPixels {
										counts[b]++
									}
									entropy := 0.0
									for _, c := range counts {
										p := float64(c) / float64(len(rawPixels))
										entropy -= p * math.Log2(p)
									}
									if entropy > 7.9 {
										indicators = append(indicators, fmt.Sprintf("canvas_idat_high_entropy: %.2f (synthetic noise)", entropy))
										vec.Score += 0.45
									}
								}
							}
						}
					}
				}
			}
		}
	}

	vec.Indicators = indicators
	if vec.Score > 1.0 {
		vec.Score = 1.0
	}
	vec.Detected = vec.Score > 0.3
	return vec
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
