package behavior

import (
	"fmt"
	"math/rand"
	"regexp"
	"strings"
)

// NavigatorData generates a complete, cross-layer-consistent navigator fingerprint.
// All fields are coherent across HTTP headers, navigator properties, WebGL, fonts,
// screen, and behavioral layers — designed to pass all IsomorphicAnalyzer checks.
type NavigatorData struct {
	// Core navigator properties
	UserAgent string   `json:"userAgent"`
	Platform  string   `json:"platform"`  // "Win32", "MacIntel", "Linux x86_64"
	Language  string   `json:"language"`  // "en-US"
	Languages []string `json:"languages"` // ["en-US", "en"]

	// Hardware
	HardwareConcurrency int     `json:"hardwareConcurrency"` // Must match GPU expectations
	DeviceMemory        float64 `json:"deviceMemory"`        // 4, 8, 16 GB
	MaxTouchPoints      int     `json:"maxTouchPoints"`      // 0 for desktop

	// Client Hints UA Data
	UserAgentData *UAData `json:"userAgentData,omitempty"` // nil for Firefox/Safari

	// Media queries
	MediaQueryPointer    string `json:"media_query_pointer"`     // "fine" for desktop
	MediaQueryAnyPointer string `json:"media_query_any_pointer"` // "fine" for desktop

	// Intl
	IntlLocale string `json:"intl_locale"` // Must match language

	// Screen
	ScreenOuterWidth  int     `json:"screen_outer_width"`
	ScreenOuterHeight int     `json:"screen_outer_height"`
	ScreenInnerWidth  int     `json:"screen_inner_width"`
	ScreenInnerHeight int     `json:"screen_inner_height"`
	ScreenColorDepth  int     `json:"screen_color_depth"` // 24 or 30
	PixelRatio        float64 `json:"pixel_ratio"`        // 1.0, 1.25, 1.5, 2.0

	// Error stack format
	ErrorStack string `json:"errorStack"` // V8 format for Chrome, SpiderMonkey for Firefox

	// Font platform
	FontPlatform string `json:"font_platform"` // "windows", "macos", "linux"

	// Chrome-specific window.chrome object (Chromium browsers only)
	Chrome map[string]interface{} `json:"chrome,omitempty"`
}

// UAData holds navigator.userAgentData properties (Chromium only).
type UAData struct {
	Brands          []UABrand `json:"brands"`
	FullVersionList []UABrand `json:"fullVersionList,omitempty"`
	Mobile          bool      `json:"mobile"`
	Platform        string    `json:"platform"`     // "Windows", "macOS", "Linux"
	Architecture    string    `json:"architecture"` // "x86", "arm"
	Bitness         string    `json:"bitness"`      // "64"
}

// UABrand is a single brand/version pair from navigator.userAgentData.brands.
type UABrand struct {
	Brand   string `json:"brand"`
	Version string `json:"version"`
}

// NavigatorProfile provides input parameters for generating a consistent navigator fingerprint.
type NavigatorProfile struct {
	Browser         string // "chrome", "firefox"
	Version         string // e.g. "134"
	Platform        string // "windows", "macos", "linux"
	UserAgent       string // Full UA string
	SecCHUA         string // Sec-Ch-Ua header value (empty for Firefox)
	SecCHUAPlatform string // e.g. `"Windows"`, `"macOS"`, `"Linux"`
	AcceptLanguage  string // e.g. "en-US,en;q=0.9"

	// Optional high-entropy client hints
	SecCHUAFullVersionList string // e.g. `"Chromium";v="134.0.6998.35", ...`
	SecCHUAArch            string // e.g. `"x86"` or `"arm"`
	SecCHUABitness         string // e.g. `"64"`
}

// NavigatorProfileFromBrowserProfile creates a NavigatorProfile from an existing BrowserProfile.
func NavigatorProfileFromBrowserProfile(bp *BrowserProfile) NavigatorProfile {
	return NavigatorProfile{
		Browser:                bp.Browser,
		Platform:               bp.Platform,
		UserAgent:              bp.UserAgent,
		SecCHUA:                bp.SecChUa,
		SecCHUAPlatform:        bp.SecChUaPlatform,
		AcceptLanguage:         bp.AcceptLanguage,
		SecCHUAFullVersionList: bp.SecChUaFullVersionList,
		SecCHUAArch:            bp.SecChUaArch,
		SecCHUABitness:         bp.SecChUaBitness,
	}
}

// platformScreenConfig holds platform-specific screen defaults.
type platformScreenConfig struct {
	navPlatform    string
	fontPlatform   string
	outerWidth     int
	outerHeight    int
	innerWidth     int
	innerHeight    int
	colorDepth     int
	pixelRatio     float64
	minConcurrency int
	maxConcurrency int
	memories       []float64
}

var platformScreenConfigs = map[string]platformScreenConfig{
	"windows": {
		navPlatform:    "Win32",
		fontPlatform:   "windows",
		outerWidth:     1920,
		outerHeight:    1040,
		innerWidth:     1920,
		innerHeight:    969,
		colorDepth:     24,
		pixelRatio:     1.0,
		minConcurrency: 8,
		maxConcurrency: 16,
		memories:       []float64{8, 16, 32},
	},
	"macos": {
		navPlatform:    "MacIntel",
		fontPlatform:   "macos",
		outerWidth:     1440,
		outerHeight:    877,
		innerWidth:     1440,
		innerHeight:    789,
		colorDepth:     30,
		pixelRatio:     2.0,
		minConcurrency: 8,
		maxConcurrency: 16,
		memories:       []float64{8, 16, 24, 36},
	},
	"linux": {
		navPlatform:    "Linux x86_64",
		fontPlatform:   "linux",
		outerWidth:     1920,
		outerHeight:    1053,
		innerWidth:     1920,
		innerHeight:    969,
		colorDepth:     24,
		pixelRatio:     1.0,
		minConcurrency: 4,
		maxConcurrency: 16,
		memories:       []float64{4, 8, 16, 32},
	},
}

// GenerateNavigatorData creates a complete navigator fingerprint consistent
// with the given browser profile. All cross-layer checks pass.
func GenerateNavigatorData(profile NavigatorProfile, seed int64) *NavigatorData {
	if seed == 0 {
		seed = 42
	}
	//nolint:gosec
	rng := rand.New(rand.NewSource(seed))

	platform := strings.ToLower(profile.Platform)
	cfg, ok := platformScreenConfigs[platform]
	if !ok {
		cfg = platformScreenConfigs["windows"] // fallback
	}

	// Screen dimensions — macOS with DPR 2.0 must have width >= 1920
	// The logical resolution is 1440x900 but the physical is 2880x1800.
	// The DPR check looks at the screen data header's "width" field.
	// For macOS Retina: logical width is 1440, which is < 1920, so DPR 2.0 would
	// trigger the check. The shield uses the *screen data* width (which we set
	// in the test to match outerWidth). For macOS we use 1920 to be safe.
	outerWidth := cfg.outerWidth
	outerHeight := cfg.outerHeight
	innerWidth := cfg.innerWidth
	innerHeight := cfg.innerHeight
	pixelRatio := cfg.pixelRatio

	// For macOS Retina (DPR >= 2.0), ensure screen width >= 1920
	if platform == "macos" && pixelRatio >= 2.0 {
		outerWidth = 1920
		innerWidth = 1920
		outerHeight = 1040
		innerHeight = 969
	}

	// Hardware concurrency — must be >= 8 for Apple Silicon GPUs
	concurrency := cfg.minConcurrency + rng.Intn(cfg.maxConcurrency-cfg.minConcurrency+1)
	// Ensure even number (common in real hardware)
	if concurrency%2 != 0 {
		concurrency++
	}

	memory := cfg.memories[rng.Intn(len(cfg.memories))]

	// Language — extract primary language from AcceptLanguage
	primaryLang := "en-US"
	if profile.AcceptLanguage != "" {
		parts := strings.Split(profile.AcceptLanguage, ",")
		if len(parts) > 0 {
			lang := strings.TrimSpace(strings.Split(parts[0], ";")[0])
			if lang != "" {
				primaryLang = lang
			}
		}
	}

	// Build languages array from AcceptLanguage
	languages := []string{primaryLang}
	if profile.AcceptLanguage != "" {
		parts := strings.Split(profile.AcceptLanguage, ",")
		for i, part := range parts {
			if i == 0 {
				continue
			}
			lang := strings.TrimSpace(strings.Split(part, ";")[0])
			if lang != "" {
				languages = append(languages, lang)
			}
		}
	}

	// Error stack format
	errorStack := generateV8Stack(rng)
	if profile.Browser == "firefox" {
		errorStack = generateSpiderMonkeyStack(rng)
	}

	nav := &NavigatorData{
		UserAgent:            profile.UserAgent,
		Platform:             cfg.navPlatform,
		Language:             primaryLang,
		Languages:            languages,
		HardwareConcurrency:  concurrency,
		DeviceMemory:         memory,
		MaxTouchPoints:       0, // desktop always 0
		MediaQueryPointer:    "fine",
		MediaQueryAnyPointer: "fine",
		IntlLocale:           primaryLang,
		ScreenOuterWidth:     outerWidth,
		ScreenOuterHeight:    outerHeight,
		ScreenInnerWidth:     innerWidth,
		ScreenInnerHeight:    innerHeight,
		ScreenColorDepth:     cfg.colorDepth,
		PixelRatio:           pixelRatio,
		ErrorStack:           errorStack,
		FontPlatform:         cfg.fontPlatform,
	}

	// UA Data — Chrome/Chromium only, not Firefox
	if profile.Browser != "firefox" && profile.SecCHUA != "" {
		nav.UserAgentData = buildUAData(profile, rng)
	}

	// window.chrome object — present in all Chromium browsers
	if profile.Browser != "firefox" && profile.Browser != "safari" {
		nav.Chrome = map[string]interface{}{
			"runtime": map[string]interface{}{},
		}
	}

	return nav
}

// buildUAData parses the SecCHUA header and builds a consistent UAData struct.
func buildUAData(profile NavigatorProfile, rng *rand.Rand) *UAData {
	_ = rng // reserved for future randomization

	uad := &UAData{
		Mobile: false,
	}

	// Platform from SecCHUAPlatform (strip quotes)
	uad.Platform = strings.Trim(profile.SecCHUAPlatform, `"`)
	if uad.Platform == "" {
		switch strings.ToLower(profile.Platform) {
		case "windows":
			uad.Platform = "Windows"
		case "macos":
			uad.Platform = "macOS"
		case "linux":
			uad.Platform = "Linux"
		}
	}

	// Parse brands from SecCHUA: "Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"
	uad.Brands = parseBrands(profile.SecCHUA)

	// Full version list
	if profile.SecCHUAFullVersionList != "" {
		uad.FullVersionList = parseBrands(profile.SecCHUAFullVersionList)
	}

	// Architecture and bitness
	uad.Architecture = strings.Trim(profile.SecCHUAArch, `"`)
	if uad.Architecture == "" {
		uad.Architecture = "x86"
	}
	uad.Bitness = strings.Trim(profile.SecCHUABitness, `"`)
	if uad.Bitness == "" {
		uad.Bitness = "64"
	}

	return uad
}

// parseBrands extracts brand/version pairs from a Sec-Ch-Ua style string.
func parseBrands(header string) []UABrand {
	re := regexp.MustCompile(`"([^"]+)";v="([^"]+)"`)
	matches := re.FindAllStringSubmatch(header, -1)
	brands := make([]UABrand, 0, len(matches))
	for _, m := range matches {
		brands = append(brands, UABrand{
			Brand:   m[1],
			Version: m[2],
		})
	}
	return brands
}

// generateV8Stack creates a realistic V8 (Chrome/Edge) error stack trace.
func generateV8Stack(rng *rand.Rand) string {
	appJS := []string{"main.js", "app.js", "index.js", "bundle.js"}
	vendorJS := []string{"vendor.js", "react-dom.production.min.js", "lodash.min.js", "jquery.min.js"}

	app := appJS[rng.Intn(len(appJS))]
	vendor := vendorJS[rng.Intn(len(vendorJS))]

	return fmt.Sprintf("Error\n    at init (https://example.com/js/%s:%d:%d)\n    at async render (https://example.com/js/%s:%d:%d)\n    at dispatch (https://example.com/js/%s:%d:%d)\n    at https://example.com/js/%s:%d:%d",
		app, 10+rng.Intn(50), 5+rng.Intn(20),
		app, 60+rng.Intn(100), 5+rng.Intn(20),
		vendor, 200+rng.Intn(1000), 1+rng.Intn(80),
		vendor, 50+rng.Intn(200), 1+rng.Intn(80))
}

// generateSpiderMonkeyStack creates a realistic SpiderMonkey (Firefox) error stack trace.
func generateSpiderMonkeyStack(rng *rand.Rand) string {
	appJS := []string{"main.js", "app.js", "index.js", "bundle.js"}
	vendorJS := []string{"vendor.js", "react-dom.production.min.js", "lodash.min.js", "jquery.min.js"}

	app := appJS[rng.Intn(len(appJS))]
	vendor := vendorJS[rng.Intn(len(vendorJS))]

	return fmt.Sprintf("init@https://example.com/js/%s:%d:%d\nrender@https://example.com/js/%s:%d:%d\n@https://example.com/js/%s:%d:%d\n@https://example.com/js/%s:%d:%d",
		app, 10+rng.Intn(50), 5+rng.Intn(20),
		app, 60+rng.Intn(100), 5+rng.Intn(20),
		vendor, 200+rng.Intn(1000), 1+rng.Intn(80),
		vendor, 50+rng.Intn(200), 1+rng.Intn(80))
}
