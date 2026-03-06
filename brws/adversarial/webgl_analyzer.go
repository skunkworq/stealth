package adversarial

import (
	"fmt"
	"math"
	"strings"
)

// WebGLData holds WebGL fingerprinting data for analysis.
type WebGLData struct {
	Vendor            string   `json:"vendor"`
	Renderer          string   `json:"renderer"`
	UnmaskedVendor    string   `json:"unmasked_vendor"`
	UnmaskedRenderer  string   `json:"unmasked_renderer"`
	Version           string   `json:"version"`
	ShadingVersion    string   `json:"shading_version"`
	WebGL2Supported   bool     `json:"webgl2_supported"`
	MaxTextureSize    int      `json:"max_texture_size"`
	MaxViewportWidth  int      `json:"max_viewport_width"`
	MaxViewportHeight int      `json:"max_viewport_height"`
	Platform          string   `json:"platform"`
	Extensions        []string `json:"webgl_extensions"`
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
	mismatchScore := wa.validateRendererVsPlatform(data.Renderer, data.Platform)
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

	result.Score = math.Min(1.0, result.Score)
	result.Detected = result.Score > 0.3

	return result
}

// validateRendererVsPlatform checks if the GPU renderer is plausible for the platform.
func (wa *WebGLAnalyzer) validateRendererVsPlatform(renderer, platform string) float64 {
	if renderer == "" || platform == "" {
		return 0
	}

	gpuList, ok := wa.platformGPUMap[platform]
	if !ok {
		return 0 // Unknown platform, can't validate
	}

	rendererLower := strings.ToLower(renderer)
	for _, gpu := range gpuList {
		if strings.Contains(rendererLower, strings.ToLower(gpu)) {
			return 0 // Match found
		}
	}

	// No match — e.g., Apple GPU claimed on Win32
	return 1.0
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
		"Brian Paul",   // Mesa software
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
