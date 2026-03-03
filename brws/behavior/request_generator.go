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

	"github.com/stealth/brwslab/brws/constants"
)

// RequestGeneratorConfig controls the full request generation.
type RequestGeneratorConfig struct {
	Profile   *BrowserProfile  // Browser identity to emulate
	EventConfig *GeneratorConfig // Config for behavioral event generation (optional)
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
	for i := range rawPixels {
		rawPixels[i] = byte(canvasRng.Intn(256))
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
	return req
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
		"extensions":        rg.profile.WebGLExtensions,
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

	// Taskbar takes 32-48px
	taskbarHeight := 32 + rg.rng.Intn(17) // 32-48
	availHeight := height - taskbarHeight

	// Browser chrome: outer uses avail dimensions, inner is smaller
	outerWidth := width
	outerHeight := availHeight

	// Browser toolbar + tabs take 60-90px from height
	chromeHeight := 60 + rg.rng.Intn(31)
	innerHeight := outerHeight - chromeHeight

	// Scrollbar width shared with navigator
	innerWidth := outerWidth - dims.scrollbarW

	data := map[string]interface{}{
		"width":        width,
		"height":       height,
		"avail_width":  width,
		"avail_height": availHeight,
		"color_depth":  colorDepth,
		"pixel_ratio":  pixelRatio,
		"outer_width":  outerWidth,
		"outer_height": outerHeight,
		"inner_width":  innerWidth,
		"inner_height": innerHeight,
	}

	b, _ := json.Marshal(data)
	return string(b)
}

// generatePlugins creates the X-Plugin-Data header JSON.
// Chrome profiles get 5 PDF plugins; Firefox gets empty (but won't trigger since
// the empty check only fires score > 0 check happens after).
func (rg *RequestGenerator) generatePlugins() string {
	plugins := make([]map[string]string, 0, len(rg.profile.Plugins))
	for _, p := range rg.profile.Plugins {
		plugins = append(plugins, map[string]string{
			"name":     p.Name,
			"filename": p.Filename,
		})
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
	}{
		{"text/html", false, 0, 0},
		{"text/css", true, 80, 200},
		{"text/css", true, 30, 100},
		{"text/css", true, 20, 80},
		{"application/javascript", true, 60, 180},
		{"application/javascript", true, 40, 120},
		{"application/javascript", true, 30, 100},
		{"application/javascript", true, 20, 80},
		{"image/png", true, 150, 500},
		{"image/jpeg", true, 80, 300},
		{"image/webp", true, 60, 250},
		{"image/svg+xml", true, 40, 150},
		{"image/png", true, 50, 200},
		{"font/woff2", true, 100, 400},
		{"font/woff2", true, 50, 200},
		{"font/woff2", true, 30, 150},
		{"application/json", true, 200, 800},  // XHR/fetch (priority -1, ignored by checker)
		{"application/json", true, 100, 400},  // XHR/fetch
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
		}
		entries = append(entries, e)

		if i < len(resources)-1 {
			next := resources[i+1]
			interval := next.minGap + int64(rg.rng.Intn(int(next.maxGap-next.minGap+1)))
			ts += interval
		}
	}

	data := map[string]interface{}{
		"entries": entries,
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

	// Pick hardware specs
	concurrency := p.HardwareConcurrency[rg.rng.Intn(len(p.HardwareConcurrency))]
	memory := p.DeviceMemory[rg.rng.Intn(len(p.DeviceMemory))]

	// Use shared resolution and scrollbar width (must match screen data)
	outerWidth := dims.resolution[0]
	innerWidth := outerWidth - dims.scrollbarW

	// Chrome quantizes RTT to 25ms multiples. Pick from realistic values,
	// avoiding rtt=50+downlink=10 combo (known spoof signature).
	// RTT and downlink must be correlated: low RTT → high downlink, high RTT → low downlink.
	quantizedRTTs := []int{25, 50, 75, 100, 125, 150, 175, 200}
	rtt := quantizedRTTs[rg.rng.Intn(len(quantizedRTTs))]
	var downlink float64
	switch {
	case rtt <= 50:
		downlink = 5.0 + rg.rng.Float64()*5.0 // 5.0-10.0
	case rtt <= 100:
		downlink = 3.0 + rg.rng.Float64()*5.0 // 3.0-8.0
	default:
		downlink = 1.5 + rg.rng.Float64()*4.5 // 1.5-6.0
	}
	downlink = math.Round(downlink*10) / 10
	// Avoid the exact rtt=50/downlink=10 spoof signature
	if rtt == 50 && downlink == 10.0 {
		downlink = 9.5
	}

	// navigator.appVersion = UA minus "Mozilla/" prefix
	appVersion := p.UserAgent
	if strings.HasPrefix(p.UserAgent, "Mozilla/") {
		appVersion = p.UserAgent[len("Mozilla/"):]
	}

	data := map[string]interface{}{
		"webdriver":       false,
		"webdriverString": "function () { [native code] }",
		"platform":        p.NavPlatform,
		"vendor":          p.NavVendor,
		"userAgent":       p.UserAgent,
		"appVersion":      appVersion,
		"hardwareConcurrency": concurrency,
		"deviceMemory":    memory,
		"cookieEnabled":   true,
		"pdfViewerEnabled": p.Browser == "chrome",
		"connection": map[string]interface{}{
			"rtt":           rtt,
			"downlink":      downlink,
			"effectiveType": "4g",
		},
		"languages":          p.Languages,
		"screen_color_depth": dims.colorDepth,
		"screen_inner_width": innerWidth,
		"screen_outer_width": outerWidth,
		"productSub":         p.ProductSub,
		"maxTouchPoints":     0,
	}

	// Timezone
	if p.Timezone != "" {
		data["timezone"] = p.Timezone
	}

	// Chrome-specific: add chrome runtime object and loadTimes
	if p.Browser == "chrome" {
		data["chrome"] = map[string]interface{}{}

		// chrome.loadTimes() — real Chrome returns timing data
		nowSec := float64(time.Now().UnixMilli()) / 1000.0
		requestTime := nowSec - 2.0 - rg.rng.Float64()*1.0
		startLoadTime := requestTime + 0.1 + rg.rng.Float64()*0.3
		commitLoadTime := startLoadTime + 0.3 + rg.rng.Float64()*0.5
		firstPaintTime := commitLoadTime + 0.1 + rg.rng.Float64()*0.3
		finishDocLoadTime := firstPaintTime + 0.2 + rg.rng.Float64()*0.3
		finishLoadTime := finishDocLoadTime + 0.1 + rg.rng.Float64()*0.2
		data["chrome_loadTimes"] = map[string]interface{}{
			"commitLoadTime":              commitLoadTime,
			"connectionInfo":              "h2",
			"finishDocumentLoadTime":      finishDocLoadTime,
			"finishLoadTime":              finishLoadTime,
			"firstPaintAfterLoadTime":     0,
			"firstPaintTime":              firstPaintTime,
			"navigationType":              "Other",
			"npnNegotiatedProtocol":       "h2",
			"requestTime":                 requestTime,
			"startLoadTime":               startLoadTime,
			"wasAlternateProtocolAvailable": false,
			"wasFetchedViaSpdy":           true,
			"wasNpnNegotiated":            true,
		}
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
	data := map[string]interface{}{
		"sample_rate":       p.AudioSampleRate,
		"channel_count":     p.AudioChannelCount,
		"max_channel_count": p.AudioMaxChannelCount,
		"base_latency":      p.AudioBaseLatency,
		"output_latency":    0.0,
		"state":             p.AudioState,
	}

	b, _ := json.Marshal(data)
	return string(b)
}
