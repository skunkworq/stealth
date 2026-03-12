package adversarial

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// WebGLData holds WebGL fingerprinting data for analysis.
type WebGLData struct {
	Vendor            string                           `json:"vendor"`
	Renderer          string                           `json:"renderer"`
	UnmaskedVendor    string                           `json:"unmasked_vendor"`
	UnmaskedRenderer  string                           `json:"unmasked_renderer"`
	Version           string                           `json:"version"`
	ShadingVersion    string                           `json:"shading_version"`
	WebGL2Supported   bool                             `json:"webgl2_supported"`
	MaxTextureSize    int                              `json:"max_texture_size"`
	MaxViewportWidth  int                              `json:"max_viewport_width"`
	MaxViewportHeight int                              `json:"max_viewport_height"`
	Platform          string                           `json:"platform"`
	Extensions        []string                         `json:"webgl_extensions"`
	ShaderPrecision   map[string]ShaderPrecisionFormat `json:"shader_precision"`
	ContextAttributes map[string]interface{}           `json:"context_attributes"`
}

// ShaderPrecisionFormat matches the WebGLShaderPrecisionFormat interface.
type ShaderPrecisionFormat struct {
	RangeMin  int `json:"range_min"`
	RangeMax  int `json:"range_max"`
	Precision int `json:"precision"`
}

// WebGLAnalyzer validates WebGL parameters for consistency and spoofing detection.
type WebGLAnalyzer struct {
	platformGPUMap map[string][]string
}

// NewWebGLAnalyzer creates a new WebGLAnalyzer with known platform-GPU mappings.
func NewWebGLAnalyzer() *WebGLAnalyzer {
	return &WebGLAnalyzer{
		platformGPUMap: map[string][]string{
			"Win32": {
				"NVIDIA", "GeForce", "Quadro", "RTX", "GTX",
				"AMD", "Radeon", "RX",
				"Intel", "UHD", "Iris", "HD Graphics",
			},
			"MacIntel": {
				"Apple", "Apple GPU", "Apple M1", "Apple M2", "Apple M3", "Apple M4",
				"AMD Radeon", "Intel",
			},
			"Linux x86_64": {
				"NVIDIA", "GeForce", "Quadro", "RTX", "GTX",
				"AMD", "Radeon",
				"Intel", "Mesa", "llvmpipe", "Gallium",
			},
			"Linux aarch64": {
				"Mali", "Adreno", "PowerVR", "Vivante",
			},
		},
	}
}

// Analyze runs the full WebGL analysis suite.
func (wa *WebGLAnalyzer) Analyze(data *WebGLData) *VectorResult {
	result := &VectorResult{
		Vector:     "WebGL Analysis",
		Category:   VectorWebGL,
		Detected:   false,
		Score:      0,
		Indicators: make([]VectorIndicator, 0),
	}

	if data == nil {
		return result
	}

	// Check 1: Renderer vs platform mismatch
	mismatchScore := wa.validateRendererVsPlatform(data.Renderer, data.UnmaskedRenderer, data.Platform)
	if mismatchScore > 0 {
		weight := 0.40
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "renderer_platform_mismatch",
			Message: fmt.Sprintf("GPU renderer '%s' inconsistent with platform '%s'", data.Renderer, data.Platform),
			Weight:  weight,
			Field:   "renderer",
			Value:   data.Renderer,
		})
		result.Score += weight * mismatchScore
	}

	// Check 2: Software renderer detection
	softScore := wa.detectSoftwareRenderer(data.Renderer)
	if softScore > 0 {
		weight := 0.35
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "software_renderer",
			Message: fmt.Sprintf("Software renderer detected: %s", data.Renderer),
			Weight:  weight,
			Field:   "renderer",
			Value:   data.Renderer,
		})
		result.Score += weight * softScore
	}

	// Check 3: Masked vs unmasked renderer mismatch (spoofing indicator)
	spoofScore := wa.detectSpoofedRenderer(data)
	if spoofScore > 0 {
		weight := 0.50
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "spoofed_renderer",
			Message: fmt.Sprintf("Masked renderer differs from unmasked: '%s' vs '%s'", data.Renderer, data.UnmaskedRenderer),
			Weight:  weight,
			Field:   "unmasked_renderer",
			Value:   data.UnmaskedRenderer,
		})
		result.Score += weight * spoofScore
	}

	// Check 4: Missing WebGL2 on modern GPU
	if !data.WebGL2Supported && isModernGPU(data.Renderer) {
		weight := 0.20
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "missing_webgl2_modern_gpu",
			Message: fmt.Sprintf("Claims modern GPU '%s' but missing WebGL2 support", data.Renderer),
			Weight:  weight,
			Field:   "webgl2_supported",
			Value:   "false",
		})
		result.Score += weight
	}

	// Check 5: Missing MAX_TEXTURE_SIZE
	// Every real GPU reports MAX_TEXTURE_SIZE (4096–32768). The WebGLData struct
	// has the field — a value of 0 signals synthetic data.
	if data.MaxTextureSize == 0 {
		weight := 0.35
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "missing_max_texture_size",
			Message: "WebGL MAX_TEXTURE_SIZE is 0 (every real GPU reports 4096–32768)",
			Weight:  weight,
			Field:   "max_texture_size",
			Value:   "0",
		})
		result.Score += weight
	}

	// Check 6: Missing SHADING_LANGUAGE_VERSION (was Check 5)
	// Real browsers always report SHADING_LANGUAGE_VERSION (e.g. "WebGL GLSL ES 3.00").
	// The WebGLData struct has the field — an empty string signals synthetic data.
	if data.ShadingVersion == "" {
		weight := 0.40
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "missing_shading_version",
			Message: "WebGL SHADING_LANGUAGE_VERSION is empty (real browsers always report this)",
			Weight:  weight,
			Field:   "shading_version",
			Value:   "",
		})
		result.Score += weight
	}

	// Check 7: Missing MAX_VIEWPORT_DIMS (Phase 36)
	// Real GPUs expose maximum viewport dimensions, which are always large (typically equal to MAX_TEXTURE_SIZE).
	// A missing attribute (0) indicates synthetic generation.
	if data.MaxViewportWidth == 0 || data.MaxViewportHeight == 0 {
		weight := 0.30
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "missing_webgl_viewport_dims",
			Message: "WebGL MAX_VIEWPORT_DIMS is missing (0)",
			Weight:  weight,
			Field:   "max_viewport_dims",
			Value:   fmt.Sprintf("%dx%d", data.MaxViewportWidth, data.MaxViewportHeight),
		})
		result.Score += weight
	}

	// Check 8: GPU keywords in masked vendor field (was Check 6)
	// Real Chrome's getParameter(gl.VENDOR) returns only "Google Inc." — GPU names
	// only appear in UNMASKED_VENDOR_WEBGL. Presence of GPU keywords in the masked
	// vendor is a strong signal of synthetic fingerprints.
	if gpuScore := wa.detectGPUKeywordsInMaskedVendor(data.Vendor); gpuScore > 0 {
		weight := 0.50
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "gpu_keywords_in_masked_vendor",
			Message: fmt.Sprintf("Masked vendor '%s' contains GPU keywords (real browsers use generic values)", data.Vendor),
			Weight:  weight,
			Field:   "vendor",
			Value:   data.Vendor,
		})
		result.Score += weight * gpuScore
	}

	// Check 8: Missing or insufficient WebGL extensions
	// Real browsers report 20-50+ WebGL extensions. A nil/empty list or fewer than
	// expected extensions strongly signals synthetic data or a headless environment.
	if len(data.Extensions) == 0 {
		weight := 0.40
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "missing_webgl_extensions",
			Message: "No WebGL extensions reported (real browsers report 25-50+)",
			Weight:  weight,
			Field:   "extensions",
			Value:   "0",
		})
		result.Score += weight
	} else {
		// Minimum expected extensions based on platform.
		// Chrome on Windows typically has >= 30. Mac/Linux >= 27.
		minExpected := 27
		if data.Platform == "Win32" {
			minExpected = 30
		}
		if len(data.Extensions) < minExpected {
			weight := 0.35
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "insufficient_webgl_extensions",
				Message: fmt.Sprintf("Too few WebGL extensions for %s: %d (expected %d+)", data.Platform, len(data.Extensions), minExpected),
				Weight:  weight,
				Field:   "extensions",
				Value:   fmt.Sprintf("%d", len(data.Extensions)),
			})
			result.Score += weight
		}
	}

	// Check 9: WebGL parameter vs Renderer consistency (MAX_TEXTURE_SIZE)
	paramScore := wa.validateWebGLParameters(data)
	if paramScore > 0 {
		weight := 0.45
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "webgl_parameter_mismatch",
			Message: fmt.Sprintf("MAX_TEXTURE_SIZE (%d) is too low for GPU renderer '%s'", data.MaxTextureSize, data.Renderer),
			Weight:  weight,
			Field:   "max_texture_size",
			Value:   fmt.Sprintf("%d", data.MaxTextureSize),
		})
		result.Score += weight * paramScore
	}

	// Check 10: Missing common draft extensions
	draftScore := wa.checkDraftExtensions(data.Extensions)
	if draftScore > 0 {
		weight := 0.25
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "missing_webgl_draft_extensions",
			Message: "Common WebGL draft extensions (e.g. EXT_disjoint_timer_query_webgl2) are missing",
			Weight:  weight,
			Field:   "extensions",
			Value:   fmt.Sprintf("%d", len(data.Extensions)),
		})
		result.Score += weight * draftScore
	}

	// Check 11: Shader Precision Validation (Phase 71)
	precisionScore := wa.validateShaderPrecision(data)
	if precisionScore > 0 {
		weight := 0.45
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "webgl_shader_precision_mismatch",
			Message: "WebGL shader precision values are inconsistent with the reported GPU renderer",
			Weight:  weight,
			Field:   "shader_precision",
			Value:   "mismatch",
		})
		result.Score += weight * precisionScore
	}

	// Check 12: Advanced Context Attributes (Phase 89)
	attrScore := wa.checkWebGLContextAttributes(data)
	if attrScore > 0 {
		weight := 0.35
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "webgl_context_attributes_mismatch",
			Message: "WebGL context attributes (antialias, depth, etc.) are suspicious or missing",
			Weight:  weight,
			Field:   "context_attributes",
			Value:   "mismatch",
		})
		result.Score += weight * attrScore
	}

	result.Score = math.Min(1.0, result.Score)
	result.Detected = result.Score > 0.3

	return result
}

// validateRendererVsPlatform checks if the GPU renderer is plausible for the platform.
func (wa *WebGLAnalyzer) validateRendererVsPlatform(renderer, unmasked, platform string) float64 {
	if (renderer == "" && unmasked == "") || platform == "" {
		return 0
	}

	gpuList, ok := wa.platformGPUMap[platform]
	if !ok {
		return 0 // Unknown platform, can't validate
	}

	renderers := []string{renderer, unmasked}
	for _, r := range renderers {
		if r == "" {
			continue
		}
		rendererLower := strings.ToLower(r)
		match := false
		for _, gpu := range gpuList {
			if strings.Contains(rendererLower, strings.ToLower(gpu)) {
				match = true
				break
			}
		}
		if !match {
			// No match — e.g., Apple GPU claimed on Win32, or NVIDIA on Mac (modern)
			// But careful: older Macs DID have NVIDIA. However, for "MacIntel" it's usually Intel/AMD/Apple.
			return 1.0
		}
	}

	return 0
}

// detectSoftwareRenderer identifies software renderers commonly found in headless.
func (wa *WebGLAnalyzer) detectSoftwareRenderer(renderer string) float64 {
	rendererLower := strings.ToLower(renderer)

	softwareRenderers := []string{
		"swiftshader",
		"llvmpipe",
		"softpipe",
		"mesa software",
		"software rasterizer",
		"microsoft basic render",
	}

	for _, sr := range softwareRenderers {
		if strings.Contains(rendererLower, sr) {
			return 1.0
		}
	}

	return 0
}

// detectSpoofedRenderer checks if the masked renderer differs from the unmasked one.
func (wa *WebGLAnalyzer) detectSpoofedRenderer(data *WebGLData) float64 {
	if data.UnmaskedRenderer == "" || data.Renderer == "" {
		return 0
	}

	// If both are set and different, this indicates GPU string manipulation
	if data.Renderer != data.UnmaskedRenderer {
		// Check if the unmasked renderer reveals a software renderer
		if wa.detectSoftwareRenderer(data.UnmaskedRenderer) > 0 {
			return 1.0 // Unmasked is software, masked is something else = spoofed
		}

		// Different but both look like real GPUs could be a driver difference
		return 0.5
	}

	return 0
}

// detectGPUKeywordsInMaskedVendor checks if the masked gl.VENDOR string contains
// GPU-specific keywords. Real browsers return generic values like "Google Inc.",
// "Mozilla", "Apple", or "Intel Inc." — GPU names only appear in UNMASKED_VENDOR.
func (wa *WebGLAnalyzer) detectGPUKeywordsInMaskedVendor(vendor string) float64 {
	if vendor == "" {
		return 0
	}

	// Known clean masked vendor values — exact matches pass
	cleanVendors := []string{
		"Google Inc.",
		"Mozilla",
		"Apple",
		"Intel Inc.",
		"Intel",
		"Brian Paul", // Mesa software
		"Mesa",
	}
	for _, clean := range cleanVendors {
		if vendor == clean {
			return 0
		}
	}

	// Check for GPU keywords that shouldn't be in masked vendor
	vendorLower := strings.ToLower(vendor)
	gpuKeywords := []string{
		"nvidia", "radeon", "geforce", "apple m",
		"amd", "rtx", "gtx", "quadro",
		"rx ", "mali", "adreno", "powervr",
	}
	for _, kw := range gpuKeywords {
		if strings.Contains(vendorLower, kw) {
			return 1.0
		}
	}

	// Parenthetical qualifiers like "(NVIDIA)" or "(Apple)" are the ANGLE
	// unmasked vendor pattern — they never appear in the masked gl.VENDOR.
	if strings.Contains(vendor, "(") {
		return 1.0
	}

	return 0
}

// isModernGPU checks if the renderer string indicates a GPU released after ~2020.
func isModernGPU(renderer string) bool {
	r := strings.ToLower(renderer)
	modernGPUs := []string{
		"rtx 30", "rtx 40", "rtx 50",
		"rx 6", "rx 7",
		"apple m1", "apple m2", "apple m3", "apple m4",
		"iris xe", "uhd 7",
		"geforce 40", "geforce 30",
	}
	for _, g := range modernGPUs {
		if strings.Contains(r, g) {
			return true
		}
	}
	return false
}

func (wa *WebGLAnalyzer) validateWebGLParameters(data *WebGLData) float64 {
	if data.MaxTextureSize == 0 || data.Renderer == "" {
		return 0
	}

	r := strings.ToLower(data.Renderer)

	// Profiles for high-end GPUs that should definitely have >= 16384
	highEndKeywords := []string{
		"rtx 30", "rtx 40", "rtx 50",
		"rx 6", "rx 7",
		"apple m1", "apple m2", "apple m3", "apple m4",
		"iris xe", "geforce 40", "geforce 30",
	}

	isHighEnd := false
	for _, kw := range highEndKeywords {
		if strings.Contains(r, kw) {
			isHighEnd = true
			break
		}
	}

	if isHighEnd && data.MaxTextureSize < 16384 {
		// RT 4090 reporting 4096 or 8192 is a clear spoofing indicator.
		return 1.0
	}

	// Mid-range or Older but still should be >= 8192
	if data.MaxTextureSize < 8192 && !strings.Contains(r, "intel") {
		// Most discrete GPUs since 2012 support 16384; 8192 is a very safe floor.
		return 0.5
	}

	return 0
}

func (wa *WebGLAnalyzer) checkDraftExtensions(extensions []string) float64 {
	if len(extensions) == 0 {
		return 0
	}

	// Draft extensions often missing in basic spoofers but present in real browsers
	draftExts := []string{
		"EXT_disjoint_timer_query_webgl2",
		"WEBGL_debug_renderer_info",
		"WEBGL_debug_shaders",
	}

	missingCount := 0
	extMap := make(map[string]bool)
	for _, e := range extensions {
		extMap[e] = true
	}

	for _, de := range draftExts {
		if !extMap[de] {
			missingCount++
		}
	}

	if missingCount >= 2 {
		return 1.0
	} else if missingCount == 1 {
		return 0.5
	}

	return 0
}

func (wa *WebGLAnalyzer) validateShaderPrecision(data *WebGLData) float64 {
	if data.ShaderPrecision == nil || len(data.ShaderPrecision) == 0 {
		// If missing entirely, could be an old telemetry format or a simplified spoofer
		return 0.3
	}

	r := strings.ToLower(data.Renderer)

	// High-float precision is a common check.
	// Key format: "FRAGMENT_SHADER_HIGH_FLOAT"
	highFloat, ok := data.ShaderPrecision["FRAGMENT_SHADER_HIGH_FLOAT"]
	if !ok {
		return 0.5
	}

	// Software renderers (e.g. SwiftShader) often report specific fixed values.
	// SwiftShader: rangeMin: 127, rangeMax: 127, precision: 23 (often seen in Headless Chrome)
	if highFloat.RangeMin == 127 && highFloat.RangeMax == 127 {
		if !strings.Contains(r, "swiftshader") && !strings.Contains(r, "llvmpipe") {
			// Discrete GPUs (NVIDIA/AMD/Apple) never report 127/127 for High Float.
			// NVIDIA typically has 127/127 for range but precision is 23 or higher.
			// Actually, standard IEEE 754 float32 is 127/127/23.
			// However, real GPUs often report differently in WebGL.
		}
	}

	// Apple M1/M2/M3: Fragmment High Float is usually 127/127/23.
	// NVIDIA: 127/127/23 is also common.
	// The most suspicious thing is "missing" or "static" values across all types.

	// Check for "Static Spoofer" (Everything is the same)
	vals := []string{}
	for k, v := range data.ShaderPrecision {
		vals = append(vals, fmt.Sprintf("%s:%d,%d,%d", k, v.RangeMin, v.RangeMax, v.Precision))
	}
	sort.Strings(vals)

	// If it's a very short list (fewer than 6 - Low/Med/High for Vert/Frag), it's likely synthetic.
	if len(data.ShaderPrecision) < 6 {
		return 1.0
	}

	return 0
}

// checkWebGLContextAttributes validates parameters like antialias, depth, stencil, etc.
func (wa *WebGLAnalyzer) checkWebGLContextAttributes(data *WebGLData) float64 {
	if data.ContextAttributes == nil || len(data.ContextAttributes) == 0 {
		return 0.5 // Missing attributes is suspicious
	}

	attrs := data.ContextAttributes

	// Common defaults and patterns
	// antialias is usually true on real hardware (Windows/Mac)
	antialias, hasAntialias := attrs["antialias"].(bool)
	depth, hasDepth := attrs["depth"].(bool)
	stencil, hasStencil := attrs["stencil"].(bool)

	score := 0.0

	if hasAntialias && !antialias {
		// Headless/SwiftShader sometimes has antialias false by default
		if !strings.Contains(strings.ToLower(data.Renderer), "intel") {
			score += 0.3
		}
	}

	// depth and stencil are almost always true in real browsers
	if hasDepth && !depth {
		score += 0.4
	}
	if hasStencil && !stencil {
		score += 0.3
	}

	// desynchronized is a modern performance attribute, missing or false is okay but
	// if it exists and is true on a very old reported renderer, it's a mismatch.
	if desync, ok := attrs["desynchronized"].(bool); ok && desync {
		if strings.Contains(strings.ToLower(data.Renderer), "gtx 6") ||
			strings.Contains(strings.ToLower(data.Renderer), "radeon hd") {
			score += 0.5
		}
	}

	return math.Min(1.0, score)
}
