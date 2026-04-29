package behavior

// BrowserProfile holds all fingerprint data for a consistent browser identity.
// Every field across HTTP headers, WebGL, fonts, plugins, screen, and navigator
// must be internally consistent (e.g. Windows UA ↔ Win32 platform ↔ Segoe UI fonts).
type BrowserProfile struct {
	Name     string
	Platform string // "windows", "macos", "linux"
	Browser  string // "chrome", "firefox"

	// Standard HTTP headers
	UserAgent      string
	Accept         string
	AcceptLanguage string
	AcceptEncoding string

	// Client Hints (Chrome only; empty for Firefox)
	SecChUa                string
	SecChUaPlatform        string
	SecChUaMobile          string
	SecChUaFullVersionList string // Phase 96: high-entropy version list
	SecChUaArch            string // Phase 96: high-entropy architecture
	SecChUaBitness         string // Phase 96: high-entropy bitness

	// Sec-Fetch headers
	SecFetchDest string
	SecFetchMode string
	SecFetchSite string
	SecFetchUser string

	// WebGL
	WebGLVendor         string
	WebGLUnmaskedVendor string
	WebGLVersion        string
	WebGLPlatform       string   // "Win32", "MacIntel", "Linux x86_64"
	WebGLRenderers      []string // random choice per request

	// Fonts
	Fonts        []string
	FontPlatform string // "windows", "macos", "linux"

	// Plugins
	Plugins []PluginInfo

	// Screen
	Resolutions [][2]int
	ColorDepths []int
	PixelRatios []float64

	// Navigator
	NavPlatform         string
	NavVendor           string
	Languages           []string // navigator.languages (e.g. ["en-US", "en"])
	HardwareConcurrency []int
	DeviceMemory        []int
	ProductSub          string // Chrome: "20030107", Firefox: "20100101"

	// WebGL shading language version
	WebGLShadingVersion string // e.g. "WebGL GLSL ES 3.00"

	// WebGL max texture size (every real GPU reports 4096-32768)
	WebGLMaxTextureSize int // e.g. 16384

	// WebGL extensions (real browsers report 20-50+)
	WebGLExtensions []string

	// Audio context
	AudioSampleRate      int     // e.g. 48000
	AudioBaseLatency     float64 // e.g. 0.01
	AudioChannelCount    int     // typically 2 (stereo)
	AudioMaxChannelCount int     // typically 2
	AudioState           string  // "suspended", "running"

	// Timezone (IANA timezone string, e.g. "America/New_York")
	Timezone string

	// Phase 58: MaxTouchPoints
	MaxTouchPoints int
}

// PluginInfo represents a browser plugin entry.
type PluginInfo struct {
	Name      string   `json:"name"`
	Filename  string   `json:"filename"`
	MimeTypes []string `json:"mimeTypes,omitempty"`
}

// chromePDFPlugins returns the standard Chrome PDF plugins.
// Each plugin includes its MIME type array matching real Chrome behavior.
func chromePDFPlugins() []PluginInfo {
	pdfMime := []string{"application/pdf"}
	return []PluginInfo{
		{Name: "PDF Viewer", Filename: "internal-pdf-viewer", MimeTypes: pdfMime},
		{Name: "Chrome PDF Viewer", Filename: "internal-pdf-viewer", MimeTypes: pdfMime},
		{Name: "Chromium PDF Viewer", Filename: "internal-pdf-viewer", MimeTypes: pdfMime},
		{Name: "Microsoft Edge PDF Viewer", Filename: "internal-pdf-viewer", MimeTypes: pdfMime},
		{Name: "WebKit built-in PDF", Filename: "internal-pdf-viewer", MimeTypes: pdfMime},
	}
}

// webSafeFonts returns fonts common to all platforms.
func webSafeFonts() []string {
	return []string{
		"Arial", "Times New Roman", "Courier New", "Georgia", "Verdana",
		"Trebuchet MS", "Impact", "Comic Sans MS", "Palatino Linotype",
		"Lucida Console", "Lucida Sans Unicode",
	}
}

// chromeWindowsExtensions returns WebGL extensions typical for Chrome on Windows (ANGLE).
func chromeWindowsExtensions() []string {
	return []string{
		"ANGLE_instanced_arrays", "EXT_blend_minmax", "EXT_color_buffer_half_float",
		"EXT_disjoint_timer_query", "EXT_float_blend", "EXT_frag_depth",
		"EXT_shader_texture_lod", "EXT_texture_compression_bptc",
		"EXT_texture_compression_rgtc", "EXT_texture_filter_anisotropic",
		"GOOGLE_GENERATE_MIPMAP_HINT", "KHR_parallel_shader_compile",
		"OES_element_index_uint", "OES_fbo_render_mipmap",
		"OES_standard_derivatives", "OES_texture_float",
		"OES_texture_float_linear", "OES_texture_half_float",
		"OES_texture_half_float_linear", "OES_vertex_array_object",
		"WEBGL_color_buffer_float", "WEBGL_compressed_texture_s3tc",
		"WEBGL_compressed_texture_s3tc_srgb", "WEBGL_debug_renderer_info",
		"WEBGL_debug_shaders", "WEBGL_depth_texture",
		"WEBGL_draw_buffers", "WEBGL_lose_context",
		"WEBGL_multi_draw",
	}
}

// chromeMacOSExtensions returns WebGL extensions typical for Chrome on macOS (Apple GPU).
func chromeMacOSExtensions() []string {
	return []string{
		"ANGLE_instanced_arrays", "EXT_blend_minmax", "EXT_color_buffer_half_float",
		"EXT_disjoint_timer_query", "EXT_float_blend", "EXT_frag_depth",
		"EXT_shader_texture_lod", "EXT_texture_filter_anisotropic",
		"GOOGLE_GENERATE_MIPMAP_HINT", "KHR_parallel_shader_compile",
		"OES_element_index_uint", "OES_fbo_render_mipmap",
		"OES_standard_derivatives", "OES_texture_float",
		"OES_texture_float_linear", "OES_texture_half_float",
		"OES_texture_half_float_linear", "OES_vertex_array_object",
		"WEBGL_color_buffer_float", "WEBGL_compressed_texture_s3tc",
		"WEBGL_debug_renderer_info", "WEBGL_debug_shaders",
		"WEBGL_depth_texture", "WEBGL_draw_buffers",
		"WEBGL_lose_context", "WEBGL_multi_draw",
	}
}

// chromeLinuxExtensions returns WebGL extensions typical for Chrome on Linux (Mesa).
func chromeLinuxExtensions() []string {
	return []string{
		"ANGLE_instanced_arrays", "EXT_blend_minmax", "EXT_color_buffer_half_float",
		"EXT_disjoint_timer_query", "EXT_float_blend", "EXT_frag_depth",
		"EXT_shader_texture_lod", "EXT_texture_compression_rgtc",
		"EXT_texture_filter_anisotropic", "GOOGLE_GENERATE_MIPMAP_HINT",
		"KHR_parallel_shader_compile", "OES_element_index_uint",
		"OES_fbo_render_mipmap", "OES_standard_derivatives",
		"OES_texture_float", "OES_texture_float_linear",
		"OES_texture_half_float", "OES_texture_half_float_linear",
		"OES_vertex_array_object", "WEBGL_color_buffer_float",
		"WEBGL_compressed_texture_s3tc", "WEBGL_debug_renderer_info",
		"WEBGL_debug_shaders", "WEBGL_depth_texture",
		"WEBGL_draw_buffers", "WEBGL_lose_context",
	}
}

// firefoxExtensions returns WebGL extensions typical for Firefox (MOZ prefixed).
func firefoxExtensions() []string {
	return []string{
		"ANGLE_instanced_arrays", "EXT_blend_minmax", "EXT_color_buffer_half_float",
		"EXT_disjoint_timer_query", "EXT_float_blend", "EXT_frag_depth",
		"EXT_shader_texture_lod", "EXT_texture_filter_anisotropic",
		"MOZ_debug_get", "OES_element_index_uint",
		"OES_fbo_render_mipmap", "OES_standard_derivatives",
		"OES_texture_float", "OES_texture_float_linear",
		"OES_texture_half_float", "OES_texture_half_float_linear",
		"OES_vertex_array_object", "WEBGL_color_buffer_float",
		"WEBGL_compressed_texture_s3tc", "WEBGL_debug_renderer_info",
		"WEBGL_debug_shaders", "WEBGL_depth_texture",
		"WEBGL_draw_buffers", "WEBGL_lose_context",
	}
}

// DefaultProfiles returns the 4 pre-defined browser profiles.
func DefaultProfiles() []*BrowserProfile {
	return []*BrowserProfile{
		ChromeWindowsProfile(),
		ChromeMacOSProfile(),
		ChromeLinuxProfile(),
		FirefoxWindowsProfile(),
	}
}

// ChromeWindowsProfile returns a Chrome 146 on Windows 10 profile.
func ChromeWindowsProfile() *BrowserProfile {
	return &BrowserProfile{
		Name:     "Chrome 146 Windows",
		Platform: "windows",
		Browser:  "chrome",

		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		Accept:         "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		AcceptLanguage: "en-US,en;q=0.9",
		AcceptEncoding: "gzip, deflate, br, zstd",

		SecChUa:                `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`,
		SecChUaPlatform:        `"Windows"`,
		SecChUaMobile:          "?0",
		SecChUaFullVersionList: `"Chromium";v="146.0.7735.6", "Not-A.Brand";v="24.0.0.0", "Google Chrome";v="146.0.7735.6"`,
		SecChUaArch:            `"x86"`,
		SecChUaBitness:         `"64"`,

		SecFetchDest: "document",
		SecFetchMode: "navigate",
		SecFetchSite: "none",
		SecFetchUser: "?1",

		WebGLVendor:         "Google Inc.",
		WebGLUnmaskedVendor: "Google Inc. (NVIDIA)",
		WebGLVersion:        "WebGL 2.0",
		WebGLPlatform:       "Win32",
		WebGLRenderers: []string{
			"NVIDIA GeForce RTX 4070",
			"NVIDIA GeForce RTX 3060",
			"AMD Radeon RX 6700 XT",
			"Intel UHD Graphics 770",
			"Intel Iris Xe Graphics",
		},

		Fonts: append(webSafeFonts(),
			"Segoe UI", "Calibri", "Consolas", "Tahoma",
			"MS Gothic", "MS Mincho", "MS PGothic", "MS PMincho",
			"MS Sans Serif", "MS Serif", "MS UI Gothic",
		),
		FontPlatform: "windows",

		Plugins: chromePDFPlugins(),

		Resolutions: [][2]int{
			{1920, 1080}, {2560, 1440}, {1366, 768}, {1536, 864}, {1680, 1050},
		},
		ColorDepths: []int{24, 32},
		PixelRatios: []float64{1.0, 1.25, 1.5},

		NavPlatform:         "Win32",
		NavVendor:           "Google Inc.",
		Languages:           []string{"en-US", "en"},
		HardwareConcurrency: []int{4, 8, 12, 16},
		DeviceMemory:        []int{8, 16, 32},
		ProductSub:          "20030107",

		WebGLShadingVersion: "WebGL GLSL ES 3.00",
		WebGLMaxTextureSize: 16384,

		WebGLExtensions: chromeWindowsExtensions(),

		AudioSampleRate:      48000,
		AudioBaseLatency:     0.01,
		AudioChannelCount:    2,
		AudioMaxChannelCount: 2,
		AudioState:           "suspended",

		Timezone: "America/New_York",
	}
}

// ChromeMacOSProfile returns a Chrome 146 on macOS 14 profile.
func ChromeMacOSProfile() *BrowserProfile {
	return &BrowserProfile{
		Name:     "Chrome 146 macOS",
		Platform: "macos",
		Browser:  "chrome",

		UserAgent:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		Accept:         "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		AcceptLanguage: "en-US,en;q=0.9",
		AcceptEncoding: "gzip, deflate, br, zstd",

		SecChUa:                `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`,
		SecChUaPlatform:        `"macOS"`,
		SecChUaMobile:          "?0",
		SecChUaFullVersionList: `"Chromium";v="146.0.7735.6", "Not-A.Brand";v="24.0.0.0", "Google Chrome";v="146.0.7735.6"`,
		SecChUaArch:            `"arm"`,
		SecChUaBitness:         `"64"`,

		SecFetchDest: "document",
		SecFetchMode: "navigate",
		SecFetchSite: "none",
		SecFetchUser: "?1",

		WebGLVendor:         "Google Inc.",
		WebGLUnmaskedVendor: "Google Inc. (Apple)",
		WebGLVersion:        "WebGL 2.0",
		WebGLPlatform:       "MacIntel",
		WebGLRenderers: []string{
			"Apple M1",
			"Apple M2",
			"Apple M3",
			"Apple M1 Pro",
			"Apple M2 Pro",
		},

		Fonts: append(webSafeFonts(),
			"SF Pro", "Helvetica Neue", "Menlo", "Monaco", "Lucida Grande",
			"Avenir", "Avenir Next", "Futura", "Optima", "Didot",
			"American Typewriter",
		),
		FontPlatform: "macos",

		Plugins: chromePDFPlugins(),

		Resolutions: [][2]int{
			{1440, 900}, {2560, 1600}, {1680, 1050}, {1920, 1080}, {2880, 1800},
		},
		ColorDepths: []int{24, 30},
		PixelRatios: []float64{1.0, 2.0},

		NavPlatform:         "MacIntel",
		NavVendor:           "Google Inc.",
		Languages:           []string{"en-US", "en"},
		HardwareConcurrency: []int{8, 10, 12},
		DeviceMemory:        []int{8, 16, 24},
		ProductSub:          "20030107",

		WebGLShadingVersion: "WebGL GLSL ES 3.00",
		WebGLMaxTextureSize: 16384,

		WebGLExtensions: chromeMacOSExtensions(),

		AudioSampleRate:      48000,
		AudioBaseLatency:     0.01,
		AudioChannelCount:    2,
		AudioMaxChannelCount: 2,
		AudioState:           "suspended",

		Timezone:       "America/Los_Angeles",
		MaxTouchPoints: 0,
	}
}

// ChromeLinuxProfile returns a Chrome 146 on Linux profile.
func ChromeLinuxProfile() *BrowserProfile {
	return &BrowserProfile{
		Name:     "Chrome 146 Linux",
		Platform: "linux",
		Browser:  "chrome",

		UserAgent:      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		Accept:         "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		AcceptLanguage: "en-US,en;q=0.9",
		AcceptEncoding: "gzip, deflate, br, zstd",

		SecChUa:                `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`,
		SecChUaPlatform:        `"Linux"`,
		SecChUaMobile:          "?0",
		SecChUaFullVersionList: `"Chromium";v="146.0.7735.6", "Not-A.Brand";v="24.0.0.0", "Google Chrome";v="146.0.7735.6"`,
		SecChUaArch:            `"x86"`,
		SecChUaBitness:         `"64"`,

		SecFetchDest: "document",
		SecFetchMode: "navigate",
		SecFetchSite: "none",
		SecFetchUser: "?1",

		WebGLVendor:         "Google Inc.",
		WebGLUnmaskedVendor: "Google Inc. (NVIDIA)",
		WebGLVersion:        "WebGL 2.0",
		WebGLPlatform:       "Linux x86_64",
		WebGLRenderers: []string{
			"NVIDIA GeForce RTX 3060",
			"NVIDIA GeForce GTX 1660",
			"AMD Radeon RX 6600",
			"Mesa Intel HD Graphics 630",
		},

		Fonts: append(webSafeFonts(),
			"Ubuntu", "DejaVu Sans", "Liberation Sans", "Noto Sans", "Cantarell",
			"DejaVu Serif", "Liberation Mono", "Noto Serif", "DejaVu Sans Mono",
			"Droid Sans", "FreeSans",
		),
		FontPlatform: "linux",

		Plugins: chromePDFPlugins(),

		Resolutions: [][2]int{
			{1920, 1080}, {2560, 1440}, {1366, 768}, {3840, 2160},
		},
		ColorDepths: []int{24, 32},
		PixelRatios: []float64{1.0, 1.25, 2.0},

		NavPlatform:         "Linux x86_64",
		NavVendor:           "Google Inc.",
		Languages:           []string{"en-US", "en"},
		HardwareConcurrency: []int{4, 8, 12, 16},
		DeviceMemory:        []int{8, 16, 32},
		ProductSub:          "20030107",

		WebGLShadingVersion: "WebGL GLSL ES 3.00",
		WebGLMaxTextureSize: 16384,

		WebGLExtensions: chromeLinuxExtensions(),

		AudioSampleRate:      48000,
		AudioBaseLatency:     0.01,
		AudioChannelCount:    2,
		AudioMaxChannelCount: 2,
		AudioState:           "suspended",

		Timezone:       "America/Chicago",
		MaxTouchPoints: 0,
	}
}

// FirefoxWindowsProfile returns a Firefox 128 on Windows profile.
func FirefoxWindowsProfile() *BrowserProfile {
	return &BrowserProfile{
		Name:     "Firefox 128 Windows",
		Platform: "windows",
		Browser:  "firefox",

		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
		Accept:         "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		AcceptLanguage: "en-US,en;q=0.5",
		AcceptEncoding: "gzip, deflate, br, zstd",

		// Firefox does not send Client Hints
		SecChUa:         "",
		SecChUaPlatform: "",
		SecChUaMobile:   "",

		SecFetchDest: "document",
		SecFetchMode: "navigate",
		SecFetchSite: "none",
		SecFetchUser: "?1",

		WebGLVendor:         "Mozilla",
		WebGLUnmaskedVendor: "Mozilla",
		WebGLVersion:        "WebGL 2.0",
		WebGLPlatform:       "Win32",
		WebGLRenderers: []string{
			"NVIDIA GeForce RTX 4070",
			"NVIDIA GeForce RTX 3060",
			"AMD Radeon RX 6700 XT",
			"Intel UHD Graphics 770",
		},

		Fonts: append(webSafeFonts(),
			"Segoe UI", "Calibri", "Consolas", "Tahoma",
			"MS Gothic", "MS Mincho", "MS PGothic", "MS PMincho",
			"MS Sans Serif", "MS Serif", "MS UI Gothic",
		),
		FontPlatform: "windows",

		// Firefox has no plugins
		Plugins: nil,

		Resolutions: [][2]int{
			{1920, 1080}, {2560, 1440}, {1366, 768}, {1536, 864},
		},
		ColorDepths: []int{24, 32},
		PixelRatios: []float64{1.0, 1.25, 1.5},

		NavPlatform:         "Win32",
		NavVendor:           "",
		Languages:           []string{"en-US", "en"},
		HardwareConcurrency: []int{4, 8, 12, 16},
		DeviceMemory:        []int{8, 16, 32},
		ProductSub:          "20100101",

		WebGLShadingVersion: "WebGL GLSL ES 3.00",
		WebGLMaxTextureSize: 16384,

		WebGLExtensions: firefoxExtensions(),

		AudioSampleRate:      44100,
		AudioBaseLatency:     0.01,
		AudioChannelCount:    2,
		AudioMaxChannelCount: 2,
		AudioState:           "suspended",

		Timezone: "America/New_York",
	}
}

func AndroidPixelProfile() *BrowserProfile {
	return &BrowserProfile{
		Name:                   "Android Pixel 7",
		Platform:               "android",
		Browser:                "chrome",
		UserAgent:              "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36",
		Accept:                 "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		AcceptLanguage:         "en-US,en;q=0.9",
		AcceptEncoding:         "gzip, deflate, br",
		SecChUa:                `"Chromium";v="116", "Not)A;Brand";v="24", "Google Chrome";v="116"`,
		SecChUaPlatform:        `"Android"`,
		SecChUaMobile:          "?1",
		SecChUaFullVersionList: `"Chromium";v="116.0.5845.163", "Not)A;Brand";v="24.0.0.0", "Google Chrome";v="116.0.5845.163"`,
		SecChUaArch:            `""`,
		SecChUaBitness:         `""`,
		SecFetchDest:           "document",
		SecFetchMode:           "navigate",
		SecFetchSite:           "none",
		SecFetchUser:           "?1",
		WebGLVendor:            "Google Inc. (Google)",
		WebGLUnmaskedVendor:    "Google Inc. (Google)",
		WebGLVersion:           "WebGL 2.0",
		WebGLPlatform:          "linux",
		WebGLRenderers: []string{
			"Adreno (TM) 730",
		},
		Fonts: []string{
			"Roboto", "Droid Sans", "Droid Serif", "monospace",
			"Noto Sans", "Noto Serif", "Inter", "sans-serif-thin",
			"sans-serif-light", "sans-serif-medium", "sans-serif-black",
			"sans-serif-condensed", "sans-serif-condensed-light",
		},
		FontPlatform: "android",
		Resolutions: [][2]int{
			{412, 915}, // Pixel 7 logical resolution
		},
		ColorDepths:          []int{24},
		PixelRatios:          []float64{2.625},
		NavPlatform:          "Linux armv8l",
		NavVendor:            "Google Inc.",
		Languages:            []string{"en-US", "en"},
		HardwareConcurrency:  []int{8},
		DeviceMemory:         []int{8},
		ProductSub:           "20030107",
		WebGLShadingVersion:  "WebGL GLSL ES 3.00",
		WebGLMaxTextureSize:  16384,
		WebGLExtensions:      chromeLinuxExtensions(),
		AudioSampleRate:      48000,
		AudioBaseLatency:     0.012,
		AudioChannelCount:    2,
		AudioMaxChannelCount: 2,
		AudioState:           "suspended",
		Timezone:             "America/Los_Angeles",
	}
}
