package behavior

import (
	"crypto/sha256"
	"fmt"
	"math/rand"
)

// CanvasFingerprint contains canvas rendering characteristics.
type CanvasFingerprint struct {
	Hash             string   `json:"hash"`
	UnmaskedRenderer string   `json:"unmaskedRenderer"`
	UnmaskedVendor   string   `json:"unmaskedVendor"`
	Renderer         string   `json:"renderer"`
	Vendor           string   `json:"vendor"`
	MaxTextureSize   int      `json:"maxTextureSize"`
	MaxViewportDims  [2]int   `json:"maxViewportDims"`
	ShadingLanguage  string   `json:"shadingLanguageVersion"`
	Antialiasing     bool     `json:"antialiasing"`
	Extensions       []string `json:"extensions"`
}

// AudioFingerprint contains AudioContext characteristics.
type AudioFingerprint struct {
	SampleRate      float64 `json:"sampleRate"`
	ChannelCount    int     `json:"channelCount"`
	MaxChannelCount int     `json:"maxChannelCount"`
	State           string  `json:"state"`
	BaseLatency     float64 `json:"baseLatency"`
	OutputLatency   float64 `json:"outputLatency"`
	// DynamicsCompressor output hash — key fingerprinting signal.
	CompressorHash string `json:"compressorHash"`
}

// WebGLFingerprint contains WebGL rendering characteristics.
type WebGLFingerprint struct {
	Vendor              string   `json:"vendor"`
	Renderer            string   `json:"renderer"`
	UnmaskedVendor      string   `json:"unmasked_vendor"`
	UnmaskedRenderer    string   `json:"unmasked_renderer"`
	Version             string   `json:"version"`
	ShadingVersion      string   `json:"shading_version"`
	MaxTextureSize      int      `json:"max_texture_size"`
	MaxRenderbufferSize int      `json:"max_renderbuffer_size"`
	Extensions          []string `json:"extensions"`
}

// PlatformFingerprints holds platform-consistent canvas and audio data.
type PlatformFingerprints struct {
	Canvas CanvasFingerprint `json:"canvas"`
	Audio  AudioFingerprint  `json:"audio"`
	WebGL  WebGLFingerprint  `json:"webgl"`
}

// GPU profile represents a realistic GPU configuration for a platform.
type gpuProfile struct {
	unmaskedRenderer string
	unmaskedVendor   string
	renderer         string
	vendor           string
	maxTextureSize   int
	maxViewportDims  [2]int
	maxRenderbuffer  int
}

var windowsGPUs = []gpuProfile{
	{
		unmaskedRenderer: "ANGLE (NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0)",
		unmaskedVendor:   "Google Inc. (NVIDIA)",
		renderer:         "ANGLE (NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0)",
		vendor:           "Google Inc. (NVIDIA)",
		maxTextureSize:   16384,
		maxViewportDims:  [2]int{32768, 32768},
		maxRenderbuffer:  16384,
	},
	{
		unmaskedRenderer: "ANGLE (Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0)",
		unmaskedVendor:   "Google Inc. (Intel)",
		renderer:         "ANGLE (Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0)",
		vendor:           "Google Inc. (Intel)",
		maxTextureSize:   16384,
		maxViewportDims:  [2]int{16384, 16384},
		maxRenderbuffer:  16384,
	},
	{
		unmaskedRenderer: "ANGLE (AMD Radeon RX 580 Direct3D11 vs_5_0 ps_5_0)",
		unmaskedVendor:   "Google Inc. (AMD)",
		renderer:         "ANGLE (AMD Radeon RX 580 Direct3D11 vs_5_0 ps_5_0)",
		vendor:           "Google Inc. (AMD)",
		maxTextureSize:   16384,
		maxViewportDims:  [2]int{16384, 16384},
		maxRenderbuffer:  16384,
	},
	{
		unmaskedRenderer: "ANGLE (NVIDIA GeForce RTX 4070 Direct3D11 vs_5_0 ps_5_0)",
		unmaskedVendor:   "Google Inc. (NVIDIA)",
		renderer:         "ANGLE (NVIDIA GeForce RTX 4070 Direct3D11 vs_5_0 ps_5_0)",
		vendor:           "Google Inc. (NVIDIA)",
		maxTextureSize:   32768,
		maxViewportDims:  [2]int{32768, 32768},
		maxRenderbuffer:  32768,
	},
}

var macGPUs = []gpuProfile{
	{
		unmaskedRenderer: "Apple M1",
		unmaskedVendor:   "Apple",
		renderer:         "Apple GPU",
		vendor:           "Apple",
		maxTextureSize:   16384,
		maxViewportDims:  [2]int{16384, 16384},
		maxRenderbuffer:  16384,
	},
	{
		unmaskedRenderer: "Apple M2",
		unmaskedVendor:   "Apple",
		renderer:         "Apple GPU",
		vendor:           "Apple",
		maxTextureSize:   16384,
		maxViewportDims:  [2]int{16384, 16384},
		maxRenderbuffer:  16384,
	},
	{
		unmaskedRenderer: "Apple M3",
		unmaskedVendor:   "Apple",
		renderer:         "Apple GPU",
		vendor:           "Apple",
		maxTextureSize:   16384,
		maxViewportDims:  [2]int{16384, 16384},
		maxRenderbuffer:  16384,
	},
	{
		unmaskedRenderer: "Apple GPU",
		unmaskedVendor:   "Apple",
		renderer:         "Apple GPU",
		vendor:           "Apple",
		maxTextureSize:   16384,
		maxViewportDims:  [2]int{16384, 16384},
		maxRenderbuffer:  16384,
	},
	{
		unmaskedRenderer: "Intel(R) Iris(TM) Plus Graphics",
		unmaskedVendor:   "Intel Inc.",
		renderer:         "Intel(R) Iris(TM) Plus Graphics OpenGL Engine",
		vendor:           "Intel Inc.",
		maxTextureSize:   16384,
		maxViewportDims:  [2]int{16384, 16384},
		maxRenderbuffer:  16384,
	},
}

var linuxGPUs = []gpuProfile{
	{
		unmaskedRenderer: "Mesa Intel(R) UHD Graphics 630",
		unmaskedVendor:   "Intel",
		renderer:         "Mesa Intel(R) UHD Graphics 630 (CFL GT2)",
		vendor:           "Intel",
		maxTextureSize:   16384,
		maxViewportDims:  [2]int{16384, 16384},
		maxRenderbuffer:  16384,
	},
	{
		unmaskedRenderer: "NVIDIA GeForce RTX 3060/PCIe/SSE2",
		unmaskedVendor:   "NVIDIA Corporation",
		renderer:         "NVIDIA GeForce RTX 3060/PCIe/SSE2",
		vendor:           "NVIDIA Corporation",
		maxTextureSize:   32768,
		maxViewportDims:  [2]int{32768, 32768},
		maxRenderbuffer:  32768,
	},
	{
		unmaskedRenderer: "Mesa AMD Radeon RX 580",
		unmaskedVendor:   "AMD",
		renderer:         "AMD Radeon RX 580 (polaris10, LLVM 15.0.7, DRM 3.49, 6.1.0-18-amd64)",
		vendor:           "AMD",
		maxTextureSize:   16384,
		maxViewportDims:  [2]int{16384, 16384},
		maxRenderbuffer:  16384,
	},
}

// Extension lists are defined in profiles.go as functions:
//   chromeWindowsExtensions(), chromeMacOSExtensions(),
//   chromeLinuxExtensions(), firefoxExtensions().

// GeneratePlatformFingerprints creates canvas/audio/webgl data consistent with
// the given platform and browser. The seed parameter enables deterministic
// generation for tests and reproducible sessions.
func GeneratePlatformFingerprints(platform, browser string, seed int64) *PlatformFingerprints {
	//nolint:gosec // G404: math/rand is intentional for non-cryptographic use
	rng := rand.New(rand.NewSource(seed))

	gpu := selectGPU(platform, rng)
	extensions := selectExtensions(platform, browser)

	canvas := generateCanvasFingerprint(gpu, extensions, rng)
	audio := generateAudioFingerprint(browser, rng)
	webgl := generateWebGLFingerprint(gpu, platform, browser, extensions, rng)

	return &PlatformFingerprints{
		Canvas: canvas,
		Audio:  audio,
		WebGL:  webgl,
	}
}

func selectGPU(platform string, rng *rand.Rand) gpuProfile {
	switch normalizePlatform(platform) {
	case "windows":
		return windowsGPUs[rng.Intn(len(windowsGPUs))]
	case "macos":
		return macGPUs[rng.Intn(len(macGPUs))]
	case "linux":
		return linuxGPUs[rng.Intn(len(linuxGPUs))]
	default:
		// Default to Windows as the most common desktop platform.
		return windowsGPUs[rng.Intn(len(windowsGPUs))]
	}
}

func selectExtensions(platform, browser string) []string {
	browser = normalizeBrowser(browser)
	if browser == "firefox" {
		return firefoxExtensions()
	}
	switch normalizePlatform(platform) {
	case "windows":
		return chromeWindowsExtensions()
	case "macos":
		return chromeMacOSExtensions()
	case "linux":
		return chromeLinuxExtensions()
	default:
		return chromeWindowsExtensions()
	}
}

func generateCanvasFingerprint(gpu gpuProfile, extensions []string, rng *rand.Rand) CanvasFingerprint {
	// Generate a deterministic-looking hash from the GPU profile.
	hashInput := fmt.Sprintf("%s:%s:%d", gpu.unmaskedRenderer, gpu.unmaskedVendor, rng.Int63())
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(hashInput)))[:32]

	shadingLang := "WebGL GLSL ES 1.0"
	if gpu.maxTextureSize >= 32768 {
		shadingLang = "WebGL GLSL ES 3.00"
	}

	return CanvasFingerprint{
		Hash:             hash,
		UnmaskedRenderer: gpu.unmaskedRenderer,
		UnmaskedVendor:   gpu.unmaskedVendor,
		Renderer:         gpu.renderer,
		Vendor:           gpu.vendor,
		MaxTextureSize:   gpu.maxTextureSize,
		MaxViewportDims:  gpu.maxViewportDims,
		ShadingLanguage:  shadingLang,
		Antialiasing:     true,
		Extensions:       extensions,
	}
}

func generateAudioFingerprint(browser string, rng *rand.Rand) AudioFingerprint {
	browser = normalizeBrowser(browser)

	var sampleRate float64
	var baseLatency float64

	switch browser {
	case "chrome":
		sampleRate = 48000
		// Chrome base latency varies by audio hardware: typically 0.005333 to 0.01.
		baseLatency = 0.005333 + rng.Float64()*0.004667
	case "firefox":
		sampleRate = 44100
		baseLatency = 0.011610 + rng.Float64()*0.005
	case "safari":
		sampleRate = 44100
		baseLatency = 0.01 + rng.Float64()*0.005
	default:
		sampleRate = 48000
		baseLatency = 0.005333 + rng.Float64()*0.004667
	}

	// Output latency is always slightly above base latency.
	outputLatency := baseLatency + rng.Float64()*0.002

	// DynamicsCompressor hash — unique per audio stack configuration.
	compInput := fmt.Sprintf("audio:%s:%.0f:%d", browser, sampleRate, rng.Int63())
	compHash := fmt.Sprintf("%x", sha256.Sum256([]byte(compInput)))[:16]

	return AudioFingerprint{
		SampleRate:      sampleRate,
		ChannelCount:    2,
		MaxChannelCount: 2,
		State:           "suspended",
		BaseLatency:     roundFloat(baseLatency, 6),
		OutputLatency:   roundFloat(outputLatency, 6),
		CompressorHash:  compHash,
	}
}

func generateWebGLFingerprint(gpu gpuProfile, platform, browser string, extensions []string, rng *rand.Rand) WebGLFingerprint {
	version := "WebGL 1.0 (OpenGL ES 2.0 Chromium)"
	shadingVersion := "WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)"

	if normalizeBrowser(browser) == "firefox" {
		version = "WebGL 1.0"
		shadingVersion = "WebGL GLSL ES 1.0"
	}

	// Use the masked vendor/renderer for the top-level fields (these come from
	// getParameter(VENDOR/RENDERER)), and unmasked for the debug info extension.
	maskedVendor := "WebKit"
	maskedRenderer := "WebKit WebGL"
	if normalizeBrowser(browser) == "firefox" {
		maskedVendor = "Mozilla"
		maskedRenderer = "Mozilla"
	}

	_ = rng // rng available for future jitter

	return WebGLFingerprint{
		Vendor:              maskedVendor,
		Renderer:            maskedRenderer,
		UnmaskedVendor:      gpu.unmaskedVendor,
		UnmaskedRenderer:    gpu.unmaskedRenderer,
		Version:             version,
		ShadingVersion:      shadingVersion,
		MaxTextureSize:      gpu.maxTextureSize,
		MaxRenderbufferSize: gpu.maxRenderbuffer,
		Extensions:          extensions,
	}
}

func normalizePlatform(platform string) string {
	switch platform {
	case "windows", "Windows", "win", "Win", "win32", "Win32", "win64":
		return "windows"
	case "macos", "macOS", "mac", "Mac", "darwin", "Darwin", "MacIntel":
		return "macos"
	case "linux", "Linux", "x11":
		return "linux"
	default:
		return "windows"
	}
}

func normalizeBrowser(browser string) string {
	switch browser {
	case "chrome", "Chrome", "chromium", "Chromium":
		return "chrome"
	case "firefox", "Firefox":
		return "firefox"
	case "safari", "Safari":
		return "safari"
	default:
		return "chrome"
	}
}

func roundFloat(val float64, precision int) float64 {
	p := 1.0
	for i := 0; i < precision; i++ {
		p *= 10
	}
	return float64(int(val*p+0.5)) / p
}
