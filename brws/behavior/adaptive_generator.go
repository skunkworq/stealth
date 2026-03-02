package behavior

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/stealth/brwslab/brws/adversarial"
	"github.com/stealth/brwslab/brws/constants"
)

// MutationFunc is a function that modifies the generator to fix a specific check.
type MutationFunc func(ag *AdaptiveRequestGenerator)

// RoundResult records the outcome of a single adaptation round.
type RoundResult struct {
	Round       int      `json:"round"`
	Score       float64  `json:"score"`
	IsBot       bool     `json:"is_bot"`
	FiredChecks []string `json:"fired_checks"`
	Applied     []string `json:"applied_mutations"`
}

// AdaptiveRequestGenerator wraps a RequestGenerator and consumes shield
// DetectionReports to learn what to fix, closing the adversarial feedback loop.
type AdaptiveRequestGenerator struct {
	mu         sync.Mutex
	base       *RequestGenerator
	config     *RequestGeneratorConfig
	mutations  map[string]MutationFunc
	lastReport *adversarial.DetectionReport
	history    []RoundResult
	applied    map[string]bool
	rng        *rand.Rand
}

// NewAdaptiveRequestGenerator creates an AdaptiveRequestGenerator with all known
// mutations registered. If config is nil, a random profile is selected.
func NewAdaptiveRequestGenerator(config *RequestGeneratorConfig) *AdaptiveRequestGenerator {
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

	ag := &AdaptiveRequestGenerator{
		base:      NewRequestGenerator(config),
		config:    config,
		mutations: make(map[string]MutationFunc),
		history:   make([]RoundResult, 0),
		applied:   make(map[string]bool),
		rng:       rng,
	}

	ag.registerMutations()
	return ag
}

// GenerateRequest creates a complete HTTP request via the base generator.
func (ag *AdaptiveRequestGenerator) GenerateRequest(targetURL string) *http.Request {
	ag.mu.Lock()
	defer ag.mu.Unlock()
	return ag.base.GenerateRequest(targetURL)
}

// ApplyFeedback iterates over fired checks in the report, applies matching
// mutations, and records a history entry.
func (ag *AdaptiveRequestGenerator) ApplyFeedback(report *adversarial.DetectionReport) {
	ag.mu.Lock()
	defer ag.mu.Unlock()

	ag.lastReport = report

	firedChecks := report.FiredCheckNames()
	appliedNow := make([]string, 0)

	for _, checkName := range firedChecks {
		if ag.applied[checkName] {
			continue
		}
		if mutation, ok := ag.mutations[checkName]; ok {
			mutation(ag)
			ag.applied[checkName] = true
			appliedNow = append(appliedNow, checkName)
		}
	}

	ag.history = append(ag.history, RoundResult{
		Round:       len(ag.history) + 1,
		Score:       report.TotalScore,
		IsBot:       report.IsBot,
		FiredChecks: firedChecks,
		Applied:     appliedNow,
	})
}

// EvasionRate returns the fraction of history rounds that achieved non-bot status.
func (ag *AdaptiveRequestGenerator) EvasionRate() float64 {
	ag.mu.Lock()
	defer ag.mu.Unlock()

	if len(ag.history) == 0 {
		return 0
	}

	evaded := 0
	for _, r := range ag.history {
		if !r.IsBot {
			evaded++
		}
	}
	return float64(evaded) / float64(len(ag.history))
}

// History returns a copy of the adaptation history.
func (ag *AdaptiveRequestGenerator) History() []RoundResult {
	ag.mu.Lock()
	defer ag.mu.Unlock()
	out := make([]RoundResult, len(ag.history))
	copy(out, ag.history)
	return out
}

// LastReport returns the most recent detection report.
func (ag *AdaptiveRequestGenerator) LastReport() *adversarial.DetectionReport {
	ag.mu.Lock()
	defer ag.mu.Unlock()
	return ag.lastReport
}

// registerMutations registers fix functions for all known shield checks.
func (ag *AdaptiveRequestGenerator) registerMutations() {
	// Round 3 checks
	ag.mutations["canvas_png_magic_header_missing"] = mutateCanvasPNGMagic
	ag.mutations["canvas_png_magic_header"] = mutateCanvasPNGMagic
	ag.mutations["missing_navigator_appVersion"] = mutateAddAppVersion
	ag.mutations["missing_app_version"] = mutateAddAppVersion
	ag.mutations["inconsistent_navigator_appVersion"] = mutateAddAppVersion
	ag.mutations["inconsistent_app_version"] = mutateAddAppVersion
	ag.mutations["missing_max_texture_size"] = mutateAddMaxTextureSize
	ag.mutations["missing_connection_effectiveType"] = mutateAddEffectiveType
	ag.mutations["missing_connection_effective_type"] = mutateAddEffectiveType
	ag.mutations["too_few_timing_entries"] = mutateExpandTimingEntries

	// Round 4 checks
	ag.mutations["missing_webgl_extensions"] = mutateAddWebGLExtensions
	ag.mutations["missing_audio_data"] = mutateAddAudioData
	ag.mutations["canvas_missing_idat_chunk"] = mutateCanvasIDATChunk
	ag.mutations["rtt_downlink_anticorrelated"] = mutateCorrelateRTTDownlink
	ag.mutations["missing_scroll_events"] = mutateAddScrollEvents
	ag.mutations["sec_ch_ua_version_mismatch"] = mutateFixVersionMismatch

	// Round 2 checks (legacy indicators)
	ag.mutations["synthetic_canvas_hash_format"] = mutateCanvasDataURL
	ag.mutations["canvas_payload_too_short"] = mutateCanvasDataURL
	ag.mutations["missing_navigator_languages"] = mutateAddLanguages
	ag.mutations["missing_navigator_productSub"] = mutateAddProductSub
	ag.mutations["missing_navigator_maxTouchPoints"] = mutateAddMaxTouchPoints
	ag.mutations["missing_shading_version"] = mutateAddShadingVersion
	ag.mutations["non_quantized_rtt"] = mutateQuantizeRTT
	ag.mutations["spoofed_network_api_detected"] = mutateFixNetworkAPI
	ag.mutations["missing_chrome_runtime"] = mutateAddChromeRuntime
	ag.mutations["missing_webdriver_toString"] = mutateAddWebdriverString
}

// rebuild reconstructs the base generator from the current config.
func (ag *AdaptiveRequestGenerator) rebuild() {
	ag.base = NewRequestGenerator(ag.config)
}

// --- Mutation functions ---

func mutateCanvasPNGMagic(ag *AdaptiveRequestGenerator) {
	// Rebuild with PNG-prefixed canvas (NewRequestGenerator now does this by default)
	ag.rebuild()
}

func mutateCanvasDataURL(ag *AdaptiveRequestGenerator) {
	ag.rebuild()
}

func mutateAddAppVersion(ag *AdaptiveRequestGenerator) {
	// The base generator now emits appVersion by default; rebuild to pick it up
	ag.rebuild()
}

func mutateAddMaxTextureSize(ag *AdaptiveRequestGenerator) {
	if ag.config.Profile.WebGLMaxTextureSize == 0 {
		ag.config.Profile.WebGLMaxTextureSize = 16384
	}
	ag.rebuild()
}

func mutateAddEffectiveType(ag *AdaptiveRequestGenerator) {
	// The base generator now emits effectiveType by default; rebuild
	ag.rebuild()
}

func mutateExpandTimingEntries(ag *AdaptiveRequestGenerator) {
	// The base generator now generates 18 entries by default; rebuild
	ag.rebuild()
}

func mutateAddLanguages(ag *AdaptiveRequestGenerator) {
	if len(ag.config.Profile.Languages) == 0 {
		ag.config.Profile.Languages = []string{"en-US", "en"}
	}
	ag.rebuild()
}

func mutateAddProductSub(ag *AdaptiveRequestGenerator) {
	if ag.config.Profile.ProductSub == "" {
		if ag.config.Profile.Browser == "firefox" {
			ag.config.Profile.ProductSub = "20100101"
		} else {
			ag.config.Profile.ProductSub = "20030107"
		}
	}
	ag.rebuild()
}

func mutateAddMaxTouchPoints(ag *AdaptiveRequestGenerator) {
	// maxTouchPoints is always emitted; rebuild
	ag.rebuild()
}

func mutateAddShadingVersion(ag *AdaptiveRequestGenerator) {
	if ag.config.Profile.WebGLShadingVersion == "" {
		ag.config.Profile.WebGLShadingVersion = "WebGL GLSL ES 3.00"
	}
	ag.rebuild()
}

func mutateQuantizeRTT(ag *AdaptiveRequestGenerator) {
	// RTT quantization is built into generateNavigator; rebuild
	ag.rebuild()
}

func mutateFixNetworkAPI(ag *AdaptiveRequestGenerator) {
	ag.rebuild()
}

func mutateAddChromeRuntime(ag *AdaptiveRequestGenerator) {
	ag.rebuild()
}

func mutateAddWebdriverString(ag *AdaptiveRequestGenerator) {
	ag.rebuild()
}

func mutateAddWebGLExtensions(ag *AdaptiveRequestGenerator) {
	if len(ag.config.Profile.WebGLExtensions) == 0 {
		ag.config.Profile.WebGLExtensions = chromeWindowsExtensions()
	}
	ag.rebuild()
}

func mutateAddAudioData(ag *AdaptiveRequestGenerator) {
	if ag.config.Profile.AudioSampleRate == 0 {
		ag.config.Profile.AudioSampleRate = 48000
		ag.config.Profile.AudioBaseLatency = 0.01
		ag.config.Profile.AudioChannelCount = 2
		ag.config.Profile.AudioMaxChannelCount = 2
		ag.config.Profile.AudioState = "suspended"
	}
	ag.rebuild()
}

func mutateCanvasIDATChunk(ag *AdaptiveRequestGenerator) {
	// NewRequestGenerator now produces proper IDAT chunk; rebuild
	ag.rebuild()
}

func mutateCorrelateRTTDownlink(ag *AdaptiveRequestGenerator) {
	// generateNavigator now correlates RTT/downlink; rebuild
	ag.rebuild()
}

func mutateAddScrollEvents(ag *AdaptiveRequestGenerator) {
	// EventGenerator.Generate() now produces scroll events; rebuild
	ag.rebuild()
}

func mutateFixVersionMismatch(ag *AdaptiveRequestGenerator) {
	ag.rebuild()
}

// --- Intentionally-broken generator for testing the feedback loop ---

// BrokenRequestGenerator generates requests with known defects for testing
// the adaptive feedback loop. It deliberately omits appVersion, effectiveType,
// max_texture_size, uses random canvas bytes, generates only 5 timing entries,
// omits audio data, omits scroll events, adds version mismatch, and uses
// anticorrelated RTT/downlink.
type BrokenRequestGenerator struct {
	profile *BrowserProfile
	rng     *rand.Rand
}

// NewBrokenRequestGenerator creates a generator with intentional defects.
func NewBrokenRequestGenerator(profile *BrowserProfile) *BrokenRequestGenerator {
	if profile == nil {
		profile = ChromeWindowsProfile()
	}
	//nolint:gosec
	return &BrokenRequestGenerator{
		profile: profile,
		rng:     rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// GenerateRequest creates a deliberately broken request.
func (bg *BrokenRequestGenerator) GenerateRequest(targetURL string) *http.Request {
	req, _ := http.NewRequest("GET", targetURL, nil)
	p := bg.profile

	// Standard HTTP headers (correct)
	req.Header.Set("User-Agent", p.UserAgent)
	req.Header.Set("Accept", p.Accept)
	req.Header.Set("Accept-Language", p.AcceptLanguage)
	req.Header.Set("Accept-Encoding", p.AcceptEncoding)
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", p.SecFetchDest)
	req.Header.Set("Sec-Fetch-Mode", p.SecFetchMode)
	req.Header.Set("Sec-Fetch-Site", p.SecFetchSite)
	req.Header.Set("Sec-Fetch-User", p.SecFetchUser)

	if p.SecChUa != "" {
		// BROKEN: Version mismatch — Sec-Ch-Ua says 133, UA says 134
		req.Header.Set("Sec-Ch-Ua", `"Chromium";v="133", "Google Chrome";v="133", "Not-A.Brand";v="99"`)
		req.Header.Set("Sec-Ch-Ua-Platform", p.SecChUaPlatform)
		req.Header.Set("Sec-Ch-Ua-Mobile", p.SecChUaMobile)
	}

	// BROKEN: WebGL without max_texture_size and without extensions
	renderer := p.WebGLRenderers[bg.rng.Intn(len(p.WebGLRenderers))]
	webgl := map[string]interface{}{
		"vendor":            p.WebGLVendor,
		"renderer":          renderer,
		"unmasked_vendor":   p.WebGLUnmaskedVendor,
		"unmasked_renderer": renderer,
		"version":           p.WebGLVersion,
		"shading_version":   p.WebGLShadingVersion,
		"platform":          p.WebGLPlatform,
		"webgl2_supported":  true,
		// max_texture_size intentionally omitted
		// extensions intentionally omitted
	}
	webglJSON, _ := json.Marshal(webgl)
	req.Header.Set(constants.HeaderWebGLData, string(webglJSON))

	// BROKEN: Navigator without appVersion and effectiveType
	dims := [2]int{1920, 1080}
	scrollW := 17
	nav := map[string]interface{}{
		"webdriver":            false,
		"webdriverString":      "function () { [native code] }",
		"platform":             p.NavPlatform,
		"vendor":               p.NavVendor,
		"userAgent":            p.UserAgent,
		"hardwareConcurrency":  8,
		"deviceMemory":         16,
		"cookieEnabled":        true,
		"pdfViewerEnabled":     p.Browser == "chrome",
		"connection": map[string]interface{}{
			"rtt":      25,
			"downlink": 1.5,
			// effectiveType intentionally omitted
			// BROKEN: anticorrelated — low RTT with low downlink
		},
		// appVersion intentionally omitted
		"languages":          p.Languages,
		"screen_color_depth": 24,
		"screen_inner_width": dims[0] - scrollW,
		"screen_outer_width": dims[0],
		"productSub":         p.ProductSub,
		"maxTouchPoints":     0,
	}
	if p.Browser == "chrome" {
		nav["chrome"] = map[string]interface{}{}
	}
	navJSON, _ := json.Marshal(nav)
	req.Header.Set(constants.HeaderNavigatorData, string(navJSON))

	// BROKEN: Canvas with random bytes (no PNG magic)
	canvasBytes := make([]byte, 8192)
	for i := range canvasBytes {
		canvasBytes[i] = byte(bg.rng.Intn(256))
	}
	req.Header.Set(constants.HeaderCanvasFingerprint,
		fmt.Sprintf("data:image/png;base64,%s", base64.StdEncoding.EncodeToString(canvasBytes)))

	// BROKEN: Only 5 timing entries
	type timingEntry struct {
		TimestampMs int64  `json:"timestamp_ms"`
		ContentType string `json:"content_type"`
		Referrer    string `json:"referrer"`
	}
	entries := []timingEntry{
		{0, "text/html", ""},
		{200, "text/css", "https://example.com"},
		{400, "application/javascript", "https://example.com"},
		{800, "image/png", "https://example.com"},
		{1200, "font/woff2", "https://example.com"},
	}
	timingJSON, _ := json.Marshal(map[string]interface{}{"entries": entries})
	req.Header.Set(constants.HeaderTimingData, string(timingJSON))

	// BROKEN: Behavioral data without scroll events
	eventGen := NewEventGenerator(nil)
	eventData := eventGen.Generate()
	eventData.ScrollTimestamps = nil // intentionally stripped
	eventData.ScrollDeltas = nil    // intentionally stripped
	behavJSON, _ := eventGen.ToJSON(eventData)
	req.Header.Set(constants.HeaderBehavioralData, behavJSON)

	// BROKEN: Audio data intentionally omitted (no HeaderAudioData set)

	// Correct font, screen, plugin data
	fonts := map[string]interface{}{"fonts": p.Fonts, "font_count": len(p.Fonts), "platform": p.FontPlatform}
	fontJSON, _ := json.Marshal(fonts)
	req.Header.Set(constants.HeaderFontData, string(fontJSON))

	pixelRatio := p.PixelRatios[bg.rng.Intn(len(p.PixelRatios))]
	screen := map[string]interface{}{
		"width": dims[0], "height": dims[1],
		"avail_width": dims[0], "avail_height": dims[1] - 40,
		"color_depth": 24, "pixel_ratio": pixelRatio,
		"outer_width": dims[0], "outer_height": dims[1] - 40,
		"inner_width": dims[0] - scrollW, "inner_height": dims[1] - 40 - 80,
	}
	screenJSON, _ := json.Marshal(screen)
	req.Header.Set(constants.HeaderScreenData, string(screenJSON))

	plugins := make([]map[string]string, 0, len(p.Plugins))
	for _, pl := range p.Plugins {
		plugins = append(plugins, map[string]string{"name": pl.Name, "filename": pl.Filename})
	}
	pluginJSON, _ := json.Marshal(map[string]interface{}{"plugins": plugins, "plugin_count": len(plugins)})
	req.Header.Set(constants.HeaderPluginData, string(pluginJSON))

	return req
}

// NewAdaptiveFromBroken creates an AdaptiveRequestGenerator that starts with
// a deliberately broken profile (missing appVersion, effectiveType, max_texture_size,
// wrong canvas, too few timing entries), then applies feedback to fix itself.
func NewAdaptiveFromBroken(profile *BrowserProfile) *AdaptiveRequestGenerator {
	if profile == nil {
		profile = ChromeWindowsProfile()
	}

	// Start with a broken profile: no max_texture_size
	brokenProfile := *profile
	brokenProfile.WebGLMaxTextureSize = 0

	config := &RequestGeneratorConfig{Profile: &brokenProfile}

	//nolint:gosec
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	ag := &AdaptiveRequestGenerator{
		config:    config,
		mutations: make(map[string]MutationFunc),
		history:   make([]RoundResult, 0),
		applied:   make(map[string]bool),
		rng:       rng,
	}

	// Build a deliberately broken base generator
	ag.base = newBrokenBaseGenerator(config, rng)

	ag.registerMutations()
	return ag
}

// newBrokenBaseGenerator creates a RequestGenerator that produces intentionally
// broken requests (no PNG magic, no appVersion, no effectiveType, 5 timing entries).
func newBrokenBaseGenerator(config *RequestGeneratorConfig, rng *rand.Rand) *RequestGenerator {
	if config.Profile == nil {
		config.Profile = ChromeWindowsProfile()
	}

	// Generate canvas without PNG magic (random bytes)
	seed := fmt.Sprintf("broken-canvas-%d", rng.Int63())
	hash := sha256.Sum256([]byte(seed))
	//nolint:gosec
	canvasRng := rand.New(rand.NewSource(int64(hash[0])<<56 | int64(hash[1])<<48 | int64(hash[2])<<40 | int64(hash[3])<<32))
	canvasBytes := make([]byte, 8192)
	for i := range canvasBytes {
		canvasBytes[i] = byte(canvasRng.Intn(256))
	}
	canvasHash := fmt.Sprintf("data:image/png;base64,%s", base64.StdEncoding.EncodeToString(canvasBytes))

	return &RequestGenerator{
		config:     config,
		eventGen:   NewEventGenerator(config.EventConfig),
		profile:    config.Profile,
		rng:        rng,
		canvasHash: canvasHash,
	}
}

// unusedImportGuard prevents "imported and not used" errors.
var _ = math.Min
var _ = strings.HasPrefix
