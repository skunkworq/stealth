package behavior

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"math"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/skunkworq/stealth/brws/constants"
)

// RequestGeneratorConfig controls the full request generation.
type RequestGeneratorConfig struct {
	Profile            *BrowserProfile  // Browser identity to emulate
	EventConfig        *GeneratorConfig // Config for behavioral event generation (optional)
	SpoofLocalIPs        bool             // Whether to spoof local LAN IPs
	EvadeCanvasEntropy   bool             // Phase 32: Generate low entropy IDAT chunks
	EvadeWebGLCount         bool             // Phase 34: Ensure sufficient WebGL extensions
	EvadeScreenHeightGap    bool             // Phase 35: Ensure screen/availHeight gap is 30-50px
	EvadeWebGLViewport      bool             // Phase 36: Append max viewport dimensions based on max texture size
	EvadeDeviceMemoryClamp  bool             // Phase 38: Cap deviceMemory at 8
	EvadeConnectionSaveData bool             // Phase 39: Inject saveData: false into connection
	EvadeScreenOrientation  bool             // Phase 40: Ensure screen orientation matches aspect ratio
	EvadeNavigatorKeyboard  bool             // Phase 41: Inject mock keyboard API for Chrome
	EvadeHardwareConcurrency bool            // Phase 42: Ensure hardwareConcurrency is even
	EvadeNetworkQuantization bool            // Phase 43: Quantize RTT/downlink values
}

// RequestGenerator produces complete, internally-consistent stealth HTTP requests
// with all fingerprint headers that the shield's StealthDetector checks.
type RequestGenerator struct {
	config     *RequestGeneratorConfig
	eventGen   *EventGenerator
	profile    *BrowserProfile
	rng        *rand.Rand
	canvasHash string // stable per instance
	targetURL  string // target URL for timing referrer chain
}

// NewRequestGenerator creates a new RequestGenerator. If config is nil, a random
// profile from the defaults is selected.
func NewRequestGenerator(config *RequestGeneratorConfig) *RequestGenerator {
	if config == nil {
		config = &RequestGeneratorConfig{}
	}
	if config.Profile == nil {
		profiles := DefaultProfiles()
		//nolint:gosec
		config.Profile = profiles[rand.Intn(len(profiles))]
	}

	//nolint:gosec
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	// Generate a stable canvas hash for this instance as a data URL.
	// Real canvas toDataURL() produces a PNG of a rendered scene (5KB-50KB).
	// We construct a valid PNG structure:
	//   8 bytes: PNG signature (\x89PNG\r\n\x1a\n)
	//  25 bytes: IHDR chunk (4 len + 4 "IHDR" + 13 data + 4 CRC)
	//   N bytes: IDAT chunk (4 len + 4 "IDAT" + data + 4 CRC)
	//  12 bytes: IEND chunk (4 len + 4 "IEND" + 4 CRC)
	// This ensures bytes 37-40 == "IDAT" to pass the IDAT structure check.
	seed := fmt.Sprintf("canvas-%d-%s", rng.Int63(), config.Profile.Name)
	hash := sha256.Sum256([]byte(seed))
	//nolint:gosec
	canvasRng := rand.New(rand.NewSource(int64(hash[0])<<56 | int64(hash[1])<<48 | int64(hash[2])<<40 | int64(hash[3])<<32 | int64(hash[4])<<24 | int64(hash[5])<<16 | int64(hash[6])<<8 | int64(hash[7])))

	// PNG signature (8 bytes)
	pngSignature := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}

	// IHDR chunk: 4 bytes length (13) + 4 bytes "IHDR" + 13 bytes data + 4 bytes CRC = 25 bytes
	ihdrChunk := []byte{
		0x00, 0x00, 0x00, 0x0D, // length = 13
		0x49, 0x48, 0x44, 0x52, // "IHDR"
		0x00, 0x00, 0x01, 0x2C, // width = 300
		0x00, 0x00, 0x00, 0xC8, // height = 200
		0x08,                   // bit depth = 8
		0x06,                   // color type = RGBA
		0x00, 0x00, 0x00,       // compression, filter, interlace
		0x00, 0x00, 0x00, 0x00, // CRC (filled below)
	}
	// Compute CRC32 over chunk type + data (bytes 4..20 of ihdrChunk)
	ihdrCRC := crc32.NewIEEE()
	ihdrCRC.Write(ihdrChunk[4:21])
	binary.BigEndian.PutUint32(ihdrChunk[21:25], ihdrCRC.Sum32())

	// IDAT chunk: zlib-compressed pixel data (valid DEFLATE stream)
	var idatBuf bytes.Buffer
	zlibW := zlib.NewWriter(&idatBuf)
	rawPixels := make([]byte, 8100)
	if config.EvadeCanvasEntropy {
		// Real canvases have low entropy (<6.0) because they have a solid background
		// and simple shapes/text. We fill with white and sprinkle a unique 32-byte
		// fingerprint pattern to ensure uniqueness without raising average entropy.
		pattern := make([]byte, 32)
		for i := 0; i < 32; i++ {
			pattern[i] = byte(canvasRng.Intn(256))
		}
		for i := range rawPixels {
			if i%17 == 0 {
				rawPixels[i] = pattern[i%32]
			} else {
				rawPixels[i] = 255 // White background
			}
		}
	} else {
		// High entropy noise (gets caught by Phase 32 check)
		for i := range rawPixels {
			rawPixels[i] = byte(canvasRng.Intn(256))
		}
	}
	_, _ = zlibW.Write(rawPixels)
	_ = zlibW.Close()
	idatData := idatBuf.Bytes()
	idatDataSize := len(idatData)
	idatChunk := make([]byte, 0, 4+4+idatDataSize+4)
	idatChunk = append(idatChunk,
		byte(idatDataSize>>24), byte(idatDataSize>>16),
		byte(idatDataSize>>8), byte(idatDataSize), // length
	)
	idatChunk = append(idatChunk, 0x49, 0x44, 0x41, 0x54) // "IDAT"
	idatChunk = append(idatChunk, idatData...)
	idatChunk = append(idatChunk, 0x00, 0x00, 0x00, 0x00) // CRC (filled below)
	// Compute CRC32 over chunk type + data (bytes 4 to end-4 of idatChunk)
	idatCRC := crc32.NewIEEE()
	idatCRC.Write(idatChunk[4 : len(idatChunk)-4])
	binary.BigEndian.PutUint32(idatChunk[len(idatChunk)-4:], idatCRC.Sum32())

	// IEND chunk: 4 bytes length (0) + 4 bytes "IEND" + 4 bytes CRC = 12 bytes
	iendChunk := []byte{
		0x00, 0x00, 0x00, 0x00, // length = 0
		0x49, 0x45, 0x4E, 0x44, // "IEND"
		0xAE, 0x42, 0x60, 0x82, // standard IEND CRC
	}

	canvasBytes := make([]byte, 0, len(pngSignature)+len(ihdrChunk)+len(idatChunk)+len(iendChunk))
	canvasBytes = append(canvasBytes, pngSignature...)
	canvasBytes = append(canvasBytes, ihdrChunk...)
	canvasBytes = append(canvasBytes, idatChunk...)
	canvasBytes = append(canvasBytes, iendChunk...)
	canvasHash := fmt.Sprintf("data:image/png;base64,%s", base64.StdEncoding.EncodeToString(canvasBytes))

	return &RequestGenerator{
		config:     config,
		eventGen:   NewEventGenerator(config.EventConfig),
		profile:    config.Profile,
		rng:        rng,
		canvasHash: canvasHash,
	}
}

// SetTargetURL sets the target URL used for timing referrer chains.
func (rg *RequestGenerator) SetTargetURL(url string) {
	rg.targetURL = url
}

// GenerateRequest creates a complete HTTP request with all stealth headers set.
func (rg *RequestGenerator) GenerateRequest(targetURL string) *http.Request {
	rg.SetTargetURL(targetURL)
	req, _ := http.NewRequest("GET", targetURL, nil)
	headers := rg.GenerateHeaders()
	for k, vals := range headers {
		for _, v := range vals {
			req.Header.Set(k, v)
		}
	}

	// Dynamic IP Spoofing
	if rg.config != nil && rg.config.SpoofLocalIPs {
		ip := randomLocalIP()
		req.Header.Set("X-Forwarded-For", ip)
		req.Header.Set("X-Real-IP", ip)
		req.Header.Set("X-Client-IP", ip)
		req.Header.Set("True-Client-IP", ip)
		req.Header.Set("CF-Connecting-IP", ip)
	}

	return req
}

// randomLocalIP generates a random private IP address.
func randomLocalIP() string {
	// Pick one of the 3 private IP ranges
	rangeType := rand.Intn(3)
	switch rangeType {
	case 0:
		// 10.0.0.0/8
		return fmt.Sprintf("10.%d.%d.%d", rand.Intn(256), rand.Intn(256), rand.Intn(256))
	case 1:
		// 172.16.0.0/12
		return fmt.Sprintf("172.%d.%d.%d", 16+rand.Intn(16), rand.Intn(256), rand.Intn(256))
	default:
		// 192.168.0.0/16
		return fmt.Sprintf("192.168.%d.%d", rand.Intn(256), rand.Intn(256))
	}
}

// sharedDimensions holds resolution, scrollbar width, and color depth picked once
// per request so that generateScreen and generateNavigator produce consistent values.
type sharedDimensions struct {
	resolution   [2]int
	scrollbarW   int
	colorDepth   int
}

// GenerateHeaders creates the full set of HTTP headers including all fingerprint
// data headers. Each call produces unique timing and behavioral data.
func (rg *RequestGenerator) GenerateHeaders() http.Header {
	h := make(http.Header)

	// Pick resolution, scrollbar width, and color depth ONCE for consistency across headers
	dims := sharedDimensions{
		resolution: rg.profile.Resolutions[rg.rng.Intn(len(rg.profile.Resolutions))],
		scrollbarW: 15 + rg.rng.Intn(3), // 15-17px
		colorDepth: rg.profile.ColorDepths[rg.rng.Intn(len(rg.profile.ColorDepths))],
	}

	// Standard HTTP headers
	rg.setHTTPHeaders(h)

	// Fingerprint data headers
	h.Set(constants.HeaderWebGLData, rg.generateWebGL())
	h.Set(constants.HeaderFontData, rg.generateFonts())
	h.Set(constants.HeaderScreenData, rg.generateScreen(dims))
	h.Set(constants.HeaderPluginData, rg.generatePlugins())
	h.Set(constants.HeaderTimingData, rg.generateTiming())
	h.Set(constants.HeaderBehavioralData, rg.generateBehavioral())
	h.Set(constants.HeaderNavigatorData, rg.generateNavigator(dims))
	h.Set(constants.HeaderCanvasFingerprint, rg.generateCanvas())
	h.Set(constants.HeaderAudioData, rg.generateAudio())

	return h
}

// setHTTPHeaders sets standard browser headers and Client Hints from the profile.
func (rg *RequestGenerator) setHTTPHeaders(h http.Header) {
	h.Set("User-Agent", rg.profile.UserAgent)
	h.Set("Accept", rg.profile.Accept)
	h.Set("Accept-Language", rg.profile.AcceptLanguage)
	h.Set("Accept-Encoding", rg.profile.AcceptEncoding)
	h.Set("Connection", "keep-alive")
	h.Set("Upgrade-Insecure-Requests", "1")
	h.Set("Cache-Control", "max-age=0")

	// Sec-Fetch headers
	h.Set("Sec-Fetch-Dest", rg.profile.SecFetchDest)
	h.Set("Sec-Fetch-Mode", rg.profile.SecFetchMode)
	h.Set("Sec-Fetch-Site", rg.profile.SecFetchSite)
	h.Set("Sec-Fetch-User", rg.profile.SecFetchUser)

	// Client Hints (Chrome only)
	if rg.profile.SecChUa != "" {
		h.Set("Sec-Ch-Ua", rg.profile.SecChUa)
		h.Set("Sec-Ch-Ua-Platform", rg.profile.SecChUaPlatform)
		h.Set("Sec-Ch-Ua-Mobile", rg.profile.SecChUaMobile)
	}
}

// generateWebGL creates the X-WebGL-Data header JSON.
// Picks a random renderer from the profile's options; unmasked == masked (no spoofing).
func (rg *RequestGenerator) generateWebGL() string {
	renderer := rg.profile.WebGLRenderers[rg.rng.Intn(len(rg.profile.WebGLRenderers))]

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

	data := map[string]interface{}{
		"vendor":            rg.profile.WebGLVendor,
		"renderer":          renderer,
		"unmasked_vendor":   rg.profile.WebGLUnmaskedVendor,
		"unmasked_renderer": renderer, // Must match renderer to avoid spoofed_renderer check
		"version":           rg.profile.WebGLVersion,
		"shading_version":   rg.profile.WebGLShadingVersion,
		"platform":          rg.profile.WebGLPlatform,
		"webgl2_supported":  true,
		"max_texture_size":  rg.profile.WebGLMaxTextureSize,
		"webgl_extensions":  exts,
	}

	if rg.config.EvadeWebGLViewport {
		data["max_viewport_width"] = rg.profile.WebGLMaxTextureSize
		data["max_viewport_height"] = rg.profile.WebGLMaxTextureSize
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
	colorDepth := dims.colorDepth
	pixelRatio := rg.profile.PixelRatios[rg.rng.Intn(len(rg.profile.PixelRatios))]

	width, height := dims.resolution[0], dims.resolution[1]

	// Phase 30 evasion: high-DPI (2x+) only on 1920px+ displays
	if pixelRatio >= 2.0 && width < 1920 {
		pixelRatio = 1.0
	}

	// Taskbar takes 32-48px typically, but wait, the sword requires 24-150px gap.
	var taskbarHeight int
	if rg.config.EvadeScreenHeightGap {
		taskbarHeight = 30 + rg.rng.Intn(20) // 30-50px gap
	} else {
		// Default bot behavior: either 0 or a massive gap
		if rg.rng.Float64() < 0.5 {
			taskbarHeight = 0 // Full screen
		} else {
			taskbarHeight = 200 + rg.rng.Intn(100) // 200-300px
		}
	}
	availHeight := height - taskbarHeight

	// Browser chrome: outer uses avail dimensions, inner is smaller
	outerWidth := width
	outerHeight := availHeight

	// Browser toolbar + tabs take 60-90px from height
	chromeHeight := 60 + rg.rng.Intn(31)
	innerHeight := outerHeight - chromeHeight

	// Scrollbar width shared with navigator
	innerWidth := outerWidth - dims.scrollbarW

	// P11: Screen orientation — desktops are always landscape-primary at angle 0
	orientationType := "landscape-primary"
	if rg.config.EvadeScreenOrientation && width < height {
		orientationType = "portrait-primary"
	}
	orientationAngle := 0

	// Phase 40 Evasion: respect config if we want to force something else?
	// Actually the loop usually wants us to fix it if it's broken.
	// We'll just make it dynamic by default or if toggle is on.
	if rg.config.EvadeScreenOrientation {
		// already dynamic above
	}

	data := map[string]interface{}{
		"width":             width,
		"height":            height,
		"avail_width":       width,
		"avail_height":      availHeight,
		"color_depth":       colorDepth,
		"pixel_ratio":       pixelRatio,
		"outer_width":       outerWidth,
		"outer_height":      outerHeight,
		"inner_width":       innerWidth,
		"inner_height":      innerHeight,
		"orientation": map[string]interface{}{
			"type":  orientationType,
			"angle": orientationAngle,
		},
	}
	// backward compat for old sword versions if any
	data["orientation_type"] = orientationType
	data["orientation_angle"] = orientationAngle

	b, _ := json.Marshal(data)
	return string(b)
}

// generatePlugins creates the X-Plugin-Data header JSON.
// Chrome profiles get 5 PDF plugins with MIME types; Firefox gets empty.
func (rg *RequestGenerator) generatePlugins() string {
	plugins := make([]map[string]interface{}, 0, len(rg.profile.Plugins))
	for _, p := range rg.profile.Plugins {
		entry := map[string]interface{}{
			"name":     p.Name,
			"filename": p.Filename,
		}
		if len(p.MimeTypes) > 0 {
			entry["mimeTypes"] = p.MimeTypes
		}
		plugins = append(plugins, entry)
	}

	data := map[string]interface{}{
		"plugins":      plugins,
		"plugin_count": len(plugins),
	}

	b, _ := json.Marshal(data)
	return string(b)
}

// generateTiming creates the X-Timing-Data header JSON.
// Generates 18 entries in correct loading order (HTML → CSS → JS → Images → Fonts → deferred)
// with variable intervals and proper referrer chain to pass the too_few_timing_entries check.
func (rg *RequestGenerator) generateTiming() string {
	baseURL := "https://example.com"
	if rg.targetURL != "" {
		baseURL = rg.targetURL
	}

	type entry struct {
		TimestampMs int64  `json:"timestamp_ms"`
		ContentType string `json:"content_type"`
		Referrer    string `json:"referrer"`
		URL         string `json:"url,omitempty"`
		DurationMs  int64  `json:"duration_ms,omitempty"`
	}

	// Resources in correct loading order with 18 entries.
	// Follows strict priority: HTML(1) → CSS(3) → JS(4) → Images(5) → Fonts(3) → XHR(2)
	// The timing analyzer validates: text/html(0) < text/css(1) < application/javascript(2) < image/*(3) < font/*(4).
	// No later-priority resources may precede earlier-priority ones.
	resources := []struct {
		contentType string
		hasReferrer bool
		minGap      int64
		maxGap      int64
		path        string
	}{
		{"text/html", false, 0, 0, "/"},
		{"text/css", true, 80, 200, "/assets/css/main.css"},
		{"text/css", true, 30, 100, "/assets/css/vendor.css"},
		{"text/css", true, 20, 80, "/assets/css/theme.css"},
		{"application/javascript", true, 60, 180, "/assets/js/runtime.js"},
		{"application/javascript", true, 40, 120, "/assets/js/vendor.js"},
		{"application/javascript", true, 30, 100, "/assets/js/app.js"},
		{"application/javascript", true, 20, 80, "/assets/js/analytics.js"},
		{"image/png", true, 150, 500, "/assets/img/logo.png"},
		{"image/jpeg", true, 80, 300, "/assets/img/hero.jpg"},
		{"image/webp", true, 60, 250, "/assets/img/banner.webp"},
		{"image/svg+xml", true, 40, 150, "/assets/img/icons.svg"},
		{"image/png", true, 50, 200, "/assets/img/bg.png"},
		{"font/woff2", true, 100, 400, "/assets/fonts/inter-regular.woff2"},
		{"font/woff2", true, 50, 200, "/assets/fonts/inter-bold.woff2"},
		{"font/woff2", true, 30, 150, "/assets/fonts/icons.woff2"},
		{"application/json", true, 200, 800, "/api/v1/init"},
		{"application/json", true, 100, 400, "/api/v1/config"},
	}

	entries := make([]entry, 0, len(resources))
	var ts int64

	for i, res := range resources {
		referrer := ""
		if res.hasReferrer {
			referrer = baseURL
		}

		e := entry{
			TimestampMs: ts,
			ContentType: res.contentType,
			Referrer:    referrer,
			URL:         baseURL + res.path,
		}

		// Real PerformanceResourceTiming.duration is always > 0.
		// Duration varies by resource type and network conditions.
		switch {
		case strings.HasPrefix(res.contentType, "text/html"):
			e.DurationMs = 200 + int64(rg.rng.Intn(300)) // 200-500ms
		case strings.HasPrefix(res.contentType, "text/css"):
			e.DurationMs = 30 + int64(rg.rng.Intn(70)) // 30-100ms
		case strings.HasPrefix(res.contentType, "application/javascript"):
			e.DurationMs = 50 + int64(rg.rng.Intn(100)) // 50-150ms
		case strings.HasPrefix(res.contentType, "image/"):
			e.DurationMs = 80 + int64(rg.rng.Intn(220)) // 80-300ms
		case strings.HasPrefix(res.contentType, "font/"):
			e.DurationMs = 50 + int64(rg.rng.Intn(150)) // 50-200ms
		default:
			e.DurationMs = 100 + int64(rg.rng.Intn(300)) // 100-400ms (XHR/fetch)
		}
		entries = append(entries, e)

		if i < len(resources)-1 {
			next := resources[i+1]
			interval := next.minGap + int64(rg.rng.Intn(int(next.maxGap-next.minGap+1)))
			ts += interval
		}
	}

	navStart := time.Now().UnixMilli() - ts
	ttfb := float64(10 + rg.rng.Intn(100))
	loadEventEnd := float64(ts)

	data := map[string]interface{}{
		"entries":         entries,
		"ttfb":            ttfb,
		"navigationStart": float64(navStart),
		"loadEventEnd":    loadEventEnd + float64(navStart),
	}

	b, _ := json.Marshal(data)
	return string(b)
}

// generateBehavioral creates the X-Behavioral-Data header JSON.
// Delegates to the EventGenerator for human-like mouse/typing data.
func (rg *RequestGenerator) generateBehavioral() string {
	eventData := rg.eventGen.Generate()
	jsonStr, _ := rg.eventGen.ToJSON(eventData)
	return jsonStr
}

// generateNavigator creates the X-Navigator-Data header JSON.
// Uses shared resolution and scrollbar width for consistency with screen data.
func (rg *RequestGenerator) generateNavigator(dims sharedDimensions) string {
	p := rg.profile

	concurrency, memory := rg.generateHardwareSpecs()
	rtt, downlink := rg.generateNetworkInfo()

	// navigator.appVersion = UA minus "Mozilla/" prefix
	appVersion := p.UserAgent
	if strings.HasPrefix(p.UserAgent, "Mozilla/") {
		appVersion = p.UserAgent[len("Mozilla/"):]
	}

	outerWidth := dims.resolution[0]
	innerWidth := outerWidth - dims.scrollbarW

	connObj := map[string]interface{}{
		"rtt":           rtt,
		"downlink":      downlink,
		"effectiveType": "4g",
	}

	if rg.config.EvadeConnectionSaveData && p.Browser == "chrome" {
		connObj["saveData"] = false
	}

	data := map[string]interface{}{
		"webdriver":              false,
		"webdriverString":        "function () { [native code] }",
		"platform":               p.NavPlatform,
		"vendor":                 p.NavVendor,
		"userAgent":              p.UserAgent,
		"appVersion":             appVersion,
		"hardwareConcurrency":   concurrency,
		"deviceMemory":           memory,
		"cookieEnabled":          true,
		"pdfViewerEnabled":       true,
		"connection":             connObj,
		"languages":              p.Languages,
		"screen_color_depth":      dims.colorDepth,
		"screen_inner_width":      innerWidth,
		"screen_outer_width":      outerWidth,
		"productSub":              p.ProductSub,
		"maxTouchPoints":          0,
		"Notification_permission": "default",
	}

	if rg.config.EvadeNavigatorKeyboard && p.Browser == "chrome" {
		data["keyboard"] = map[string]interface{}{}
	}

	if p.Timezone != "" {
		data["timezone"] = p.Timezone
	}

	if p.Browser == "chrome" {
		rg.addChromeRuntimeData(data)
	}

	b, _ := json.Marshal(data)
	return string(b)
}

func (rg *RequestGenerator) generateHardwareSpecs() (concurrency, memory int) {
	type hwPair struct{ memory, cores int }
	hardwarePairs := []hwPair{
		{4, 4}, {4, 8},
		{8, 4}, {8, 8},
		{16, 8}, {16, 12},
		{32, 8}, {32, 12}, {32, 16},
	}
	hw := hardwarePairs[rg.rng.Intn(len(hardwarePairs))]
	concurrency = hw.cores
	if !rg.config.EvadeHardwareConcurrency && rg.rng.Intn(10) < 3 {
		oddCores := []int{3, 7, 13, 15}
		concurrency = oddCores[rg.rng.Intn(len(oddCores))]
	} else if rg.config.EvadeHardwareConcurrency && concurrency%2 != 0 {
		concurrency = (concurrency / 2) * 2
		if concurrency == 0 {
			concurrency = 2
		}
	}
	memory = hw.memory
	if rg.config.EvadeDeviceMemoryClamp && memory > 8 {
		memory = 8
	}
	return
}

func (rg *RequestGenerator) generateNetworkInfo() (rtt, downlink float64) {
	if rg.config.EvadeNetworkQuantization {
		quantizedRTTs := []int{25, 50, 75, 100, 125, 150, 175, 200}
		rttInt := quantizedRTTs[rg.rng.Intn(len(quantizedRTTs))]
		rtt = float64(rttInt)
		switch {
		case rttInt <= 50:
			downlink = 5.0 + rg.rng.Float64()*5.0
		case rttInt <= 100:
			downlink = 3.0 + rg.rng.Float64()*5.0
		default:
			downlink = 1.5 + rg.rng.Float64()*4.5
		}
		downlink = math.Round(downlink*10) / 10
		if rttInt == 50 && downlink == 10.0 {
			downlink = 9.5
		}
	} else {
		rtt = 30 + rg.rng.Float64()*170
		if int(rtt)%25 == 0 {
			rtt += 1
		}
		downlink = 1.0 + rg.rng.Float64()*9.0
		if math.Round(downlink*10) == downlink*10 {
			downlink += 0.00342
		}
	}
	return
}

func (rg *RequestGenerator) addChromeRuntimeData(data map[string]interface{}) {
	data["chrome"] = map[string]interface{}{}
	data["chrome_app"] = map[string]interface{}{
		"isInstalled":  false,
		"InstallState": map[string]interface{}{"DISABLED": "disabled", "INSTALLED": "installed", "NOT_INSTALLED": "not_installed"},
		"RunningState": map[string]interface{}{"CANNOT_RUN": "cannot_run", "READY_TO_RUN": "ready_to_run", "RUNNING": "running"},
	}

	nowSec := float64(time.Now().UnixMilli()) / 1000.0
	requestTime := nowSec - 2.0 - rg.rng.Float64()*1.0
	pageT := int64((nowSec - requestTime) * 1000)
	data["chrome_csi"] = map[string]interface{}{
		"onloadT": pageT + int64(200+rg.rng.Intn(500)),
		"pageT":   pageT,
		"startE":  int64(requestTime * 1000),
		"tran":    15,
	}

	rg.addChromeLoadTimes(data, requestTime)
	rg.addPerformanceMemory(data)
}

func (rg *RequestGenerator) addChromeLoadTimes(data map[string]interface{}, requestTime float64) {
	startLoadTime := requestTime + 0.1 + rg.rng.Float64()*0.3
	commitLoadTime := startLoadTime + 0.3 + rg.rng.Float64()*0.5
	firstPaintTime := commitLoadTime + 0.1 + rg.rng.Float64()*0.3
	finishDocLoadTime := firstPaintTime + 0.2 + rg.rng.Float64()*0.3
	finishLoadTime := finishDocLoadTime + 0.1 + rg.rng.Float64()*0.2
	data["chrome_loadTimes"] = map[string]interface{}{
		"commitLoadTime":                commitLoadTime,
		"connectionInfo":                "h2",
		"finishDocumentLoadTime":        finishDocLoadTime,
		"finishLoadTime":                finishLoadTime,
		"firstPaintAfterLoadTime":       0,
		"firstPaintTime":                firstPaintTime,
		"navigationType":                "Other",
		"npnNegotiatedProtocol":         "h2",
		"requestTime":                   requestTime,
		"startLoadTime":                 startLoadTime,
		"wasAlternateProtocolAvailable": false,
		"wasFetchedViaSpdy":             true,
		"wasNpnNegotiated":              true,
	}
}

func (rg *RequestGenerator) addPerformanceMemory(data map[string]interface{}) {
	jsHeapLimit := 4294705152
	totalHeap := 20*1024*1024 + rg.rng.Intn(60*1024*1024)
	usedHeap := int(float64(totalHeap) * (0.3 + rg.rng.Float64()*0.5))
	data["performance_memory"] = map[string]interface{}{
		"jsHeapSizeLimit": jsHeapLimit,
		"totalJSHeapSize": totalHeap,
		"usedJSHeapSize":  usedHeap,
	}
}

// generateCanvas creates the X-Canvas-Fingerprint header.
// Returns a stable SHA-256 hash with no suspicious substrings.
func (rg *RequestGenerator) generateCanvas() string {
	return rg.canvasHash
}

// generateAudio creates the X-Audio-Data header JSON.
func (rg *RequestGenerator) generateAudio() string {
	p := rg.profile
	data := map[string]interface{}{
		"sample_rate":       p.AudioSampleRate,
		"channel_count":     p.AudioChannelCount,
		"max_channel_count": p.AudioMaxChannelCount,
		"base_latency":      p.AudioBaseLatency,
		"output_latency":    0.005 + rg.rng.Float64()*0.035, // 0.005-0.04s (real hardware latency)
		"state":             "running", // active AudioContext state
	}

	b, _ := json.Marshal(data)
	return string(b)
}
