package behavior

import (
	"encoding/json"
	"strings"

	"github.com/skunkworq/stealth/brws/stealth/challenge"
)

// generateWebGL creates the X-WebGL-Data header JSON.
// Picks a random renderer from the profile's options; unmasked == masked (no spoofing).
func (rg *RequestGenerator) generateWebGL(renderer string) string {
	exts := rg.profile.WebGLExtensions
	if rg.config.EvadeWebGLCount {
		genericExts := []string{
			"WEBGL_depth_texture", "WEBGL_draw_buffers",
			"OES_element_index_uint", "OES_standard_derivatives",
			"EXT_sRGB", "EXT_frag_depth", "EXT_shader_texture_lod",
			"EXT_color_buffer_half_float", "EXT_color_buffer_float",
			"EXT_disjoint_timer_query", "EXT_blend_minmax",
			"WEBGL_color_buffer_float", "OES_texture_float_linear",
			"OES_texture_half_float_linear", "WEBGL_compressed_texture_s3tc",
			"WEBGL_compressed_texture_etc", "WEBGL_compressed_texture_astc",
			"EXT_texture_filter_anisotropic", "OES_vertex_array_object",
			"KHR_parallel_shader_compile", "WEBGL_multi_draw",
			"WEBGL_lose_context", "WEBGL_debug_renderer_info",
			"WEBGL_compressed_texture_pvrtc",
			"WEBGL_compressed_texture_s3tc_srgb",
			"WEBGL_draw_instanced_base_vertex_base_instance",
			"WEBGL_multi_draw_instanced_base_vertex_base_instance",
			"EXT_disjoint_timer_query_webgl2",
			"EXT_float_blend",
			"EXT_texture_compression_bptc",
			"EXT_texture_compression_rgtc",
			"KHR_parallel_shader_compile",
			"OES_draw_buffers_indexed",
			"WEBGL_blend_equation_advanced_coherent",
			"WEBGL_debug_renderer_info",
			"WEBGL_debug_shaders",
		}

		exts = append([]string(nil), exts...) // clone
		for i := 0; i < len(genericExts); i++ {
			found := false
			for _, e := range exts {
				if e == genericExts[i] {
					found = true
					break
				}
			}
			if !found {
				exts = append(exts, genericExts[i])
			}
		}
	} else {
		// Default bot behavior: strip some extensions to trigger the check
		if len(exts) > 10 {
			exts = exts[:10]
		}
	}

	maxTextureSize := rg.profile.WebGLMaxTextureSize
	if !rg.config.EvadeWebGLParameters && rg.rng.Intn(10) < 3 {
		// Deliberately use a small value (like 4096 or 8192) to match standard headless defaults
		maxTextureSize = 4096 * (1 + rg.rng.Intn(2)) // 4096 or 8192
	}

	// Phase 81: WebGL Renderer Deep Consistency
	// Use the profile's own renderer for consistency — the same renderer is passed to
	// generateNavigator for hardware coherence, so overriding here would cause a mismatch
	// between WebGL unmasked_renderer and navigator hardwareConcurrency.
	finalRenderer := renderer
	unmaskedRenderer := renderer
	if rg.config.ForceDetections && !rg.config.EvadeWebGLRendererDeep {
		// Simulate mismatch: NVIDIA on Mac (only if evasion not active)
		os := strings.ToLower(rg.profile.Platform)
		if strings.Contains(os, "mac") || strings.Contains(os, "darwin") {
			finalRenderer = "NVIDIA GeForce RTX 3080"
			unmaskedRenderer = "NVIDIA GeForce RTX 3080"
		}
	}

	data := map[string]interface{}{
		"vendor":              rg.profile.WebGLVendor,
		"renderer":            finalRenderer,
		"unmasked_vendor":     rg.profile.WebGLUnmaskedVendor,
		"unmasked_renderer":   unmaskedRenderer,
		"version":             rg.profile.WebGLVersion,
		"shading_version":     rg.profile.WebGLShadingVersion,
		"platform":            rg.profile.WebGLPlatform,
		"webgl2_supported":    true,
		"max_texture_size":    maxTextureSize,
		"max_viewport_width":  maxTextureSize,
		"max_viewport_height": maxTextureSize,
		"webgl_extensions":    exts,
	}

	if rg.config.EvadeWebGLAttributesDeep {
		data["context_attributes"] = map[string]interface{}{
			"alpha":                        true,
			"antialias":                    true,
			"depth":                        true,
			"desynchronized":               false,
			"failIfMajorPerformanceCaveat": false,
			"powerPreference":              "default",
			"preserveDrawingBuffer":        false,
			"stencil":                      true,
		}
	} else if rg.config.ForceDetections {
		// Bot-like: missing or unusual attributes
		if rg.rng.Intn(2) == 0 {
			data["context_attributes"] = map[string]interface{}{
				"antialias": false,
				"depth":     false,
				"stencil":   false,
			}
		}
	}

	if rg.config.EvadeWebGLShaderPrecision {
		// Realistic shader precision for modern GPUs (NVIDIA/Apple/AMD)
		// Usually Low/Med/High for both Vertex and Fragment shaders.
		data["shader_precision"] = map[string]interface{}{
			"VERTEX_SHADER_LOW_FLOAT":      map[string]int{"range_min": 127, "range_max": 127, "precision": 23},
			"VERTEX_SHADER_MEDIUM_FLOAT":   map[string]int{"range_min": 127, "range_max": 127, "precision": 23},
			"VERTEX_SHADER_HIGH_FLOAT":     map[string]int{"range_min": 127, "range_max": 127, "precision": 23},
			"FRAGMENT_SHADER_LOW_FLOAT":    map[string]int{"range_min": 127, "range_max": 127, "precision": 23},
			"FRAGMENT_SHADER_MEDIUM_FLOAT": map[string]int{"range_min": 127, "range_max": 127, "precision": 23},
			"FRAGMENT_SHADER_HIGH_FLOAT":   map[string]int{"range_min": 127, "range_max": 127, "precision": 23},
			"VERTEX_SHADER_LOW_INT":        map[string]int{"range_min": 31, "range_max": 30, "precision": 0},
			"VERTEX_SHADER_MEDIUM_INT":     map[string]int{"range_min": 31, "range_max": 30, "precision": 0},
			"VERTEX_SHADER_HIGH_INT":       map[string]int{"range_min": 31, "range_max": 30, "precision": 0},
			"FRAGMENT_SHADER_LOW_INT":      map[string]int{"range_min": 31, "range_max": 30, "precision": 0},
			"FRAGMENT_SHADER_MEDIUM_INT":   map[string]int{"range_min": 31, "range_max": 30, "precision": 0},
			"FRAGMENT_SHADER_HIGH_INT":     map[string]int{"range_min": 31, "range_max": 30, "precision": 0},
		}
	} else if rg.config.ForceDetections || rg.rng.Intn(10) < 3 {
		// Bot-like: missing or incomplete shader precision
		if rg.rng.Intn(2) == 0 {
			data["shader_precision"] = map[string]interface{}{} // empty
		} else {
			// incomplete
			data["shader_precision"] = map[string]interface{}{
				"FRAGMENT_SHADER_HIGH_FLOAT": map[string]int{"range_min": 127, "range_max": 127, "precision": 23},
			}
		}
	}

	if rg.config.EvadeWebGLViewport {
		data["max_viewport_width"] = rg.profile.WebGLMaxTextureSize
		data["max_viewport_height"] = rg.profile.WebGLMaxTextureSize
	}

	b, _ := json.Marshal(data)
	return string(b)
}

// generateCanvas creates the X-Canvas-Fingerprint header.
// Returns a stable SHA-256 hash with no suspicious substrings.
func (rg *RequestGenerator) generateCanvas() string {
	return rg.canvasHash
}

// generateAudio creates the X-Audio-Data header JSON.
func (rg *RequestGenerator) generateAudio() string {
	p := rg.profile
	latency := p.AudioBaseLatency
	state := "running"

	if rg.config.EvadeAudioContextDeep {
		// Provide realistic latency (not exactly 0.0)
		latency = 0.001 + rg.rng.Float64()*0.005
		state = "running"
	} else if rg.config.ForceDetections {
		// Static/improbable state and latency
		latency = 0.0
		state = "closed"
	}

	offlineHash := "2c3245f3"
	attack := 0.003
	release := 0.25

	if rg.config.EvadeAudioGraphDeep {
		// defaults are realistic
	} else if rg.config.ForceDetections {
		offlineHash = "0"
		attack = 0.0
		release = 0.0
	}

	data := map[string]interface{}{
		"sample_rate":             p.AudioSampleRate,
		"channel_count":           p.AudioChannelCount,
		"max_channel_count":       p.AudioMaxChannelCount,
		"base_latency":            latency,
		"output_latency":          0.005 + rg.rng.Float64()*0.035,
		"state":                   state,
		"audio_worklet_available": true,
		"offline_context_hash":    offlineHash,
		"compressor_attack":       attack,
		"compressor_release":      release,
	}

	if !rg.config.EvadeAudioBaseLatency && rg.rng.Intn(10) < 3 {
		data["base_latency"] = 0.0
	}

	b, _ := json.Marshal(data)
	return string(b)
}

// generateFonts creates the X-Font-Data header JSON.
// Includes 22+ fonts with platform-specific fonts. Count matches array length.
func (rg *RequestGenerator) generateFonts() string {
	fonts := make([]string, len(rg.profile.Fonts))
	copy(fonts, rg.profile.Fonts)

	data := map[string]interface{}{
		"fonts":      fonts,
		"font_count": len(fonts),
		"platform":   rg.profile.FontPlatform,
	}

	b, _ := json.Marshal(data)
	return string(b)
}

// generateScreen creates the X-Screen-Data header JSON.
// Uses the shared resolution, scrollbar width, and color depth for consistency with navigator data.
func (rg *RequestGenerator) generateScreen(dims sharedDimensions) string {
	w := dims.resolution[0]
	h := dims.resolution[1]
	aw := dims.resolution[0]
	ah := dims.resolution[1]
	innerWidth := dims.innerWidth
	innerHeight := dims.innerHeight
	dpr := dims.pixelRatio

	isMobile := rg.profile.Platform == "android" || rg.profile.Platform == "ios"

	scr := &challenge.ScreenData{
		Width:       w,
		Height:      h,
		AvailWidth:  aw,
		AvailHeight: ah,
		AvailLeft:   0,
		AvailTop:    0,
		ColorDepth:  24,
		PixelRatio:  dpr,
		InnerWidth:  innerWidth,
		InnerHeight: innerHeight,
		OuterWidth:  dims.outerWidth,
		OuterHeight: dims.outerHeight,
	}

	if rg.profile.Platform == "macos" {
		scr.AvailTop = 25 // menu bar
		scr.AvailHeight = h - 25
	} else if rg.profile.Platform == "windows" || rg.profile.Platform == "linux" {
		scr.AvailHeight = h - 40 // taskbar
	} else if isMobile {
		// Mobile: availHeight might be slightly less due to status bar, or same for full screen
		scr.OuterHeight = scr.Height
		scr.OuterWidth = scr.Width
	}

	// Orientation
	scr.OrientationType = "landscape-primary"
	scr.OrientationAngle = 0
	if h > w {
		scr.OrientationType = "portrait-primary"
	}

	// Phase 86: Screen orientation locking
	if rg.config.EvadeOrientationDeep {
		hasLock := true
		scr.HasOrientationLock = &hasLock
	} else if rg.config.ForceDetections {
		hasLock := false
		scr.HasOrientationLock = &hasLock
	} else {
		// Default to true for standard profiles to avoid noise
		hasLock := true
		scr.HasOrientationLock = &hasLock
	}

	data := map[string]interface{}{
		"width":                scr.Width,
		"height":               scr.Height,
		"avail_width":          scr.AvailWidth,
		"avail_height":         scr.AvailHeight,
		"avail_left":           scr.AvailLeft,
		"avail_top":            scr.AvailTop,
		"color_depth":          scr.ColorDepth,
		"pixel_ratio":          scr.PixelRatio,
		"outer_width":          scr.OuterWidth,
		"outer_height":         scr.OuterHeight,
		"inner_width":          scr.InnerWidth,
		"inner_height":         scr.InnerHeight,
		"orientation_type":     scr.OrientationType,
		"orientation_angle":    scr.OrientationAngle,
		"has_orientation_lock": scr.HasOrientationLock,
	}

	// Phase 64
	isExt := false
	if rg.config != nil && rg.profile.Browser == "chrome" {
		isExt = true
	}
	data["is_extended"] = isExt

	// Phase 79: Screen Geometry
	// This logic is now mostly handled by the scr struct initialization and OS-specific adjustments.
	// The ForceDetections for availLeft/availTop mismatch is kept for specific bot-like simulation.
	if rg.config != nil && !rg.config.EvadeScreenGeometryDeep && rg.config.ForceDetections {
		// Simulate mismatch: non-extended but has offsets (common in some bot managers)
		data["avail_left"] = 1920
		data["is_extended"] = false
	}

	// If not evading, randomly omit is_extended to trigger the sword (30% chance)
	if !rg.config.EvadeScreenIsExtended && (rg.config.ForceDetections || rg.rng.Intn(10) < 3) {
		delete(data, "is_extended")
	}

	b, _ := json.Marshal(data)
	return string(b)
}

func (rg *RequestGenerator) generateScreenOrientation(dims sharedDimensions) string {
	width := dims.resolution[0]
	height := dims.resolution[1]
	if width < height {
		return "portrait-primary"
	}
	return "landscape-primary"
}
