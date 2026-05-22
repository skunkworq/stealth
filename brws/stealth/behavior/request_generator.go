package behavior

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/skunkworq/stealth/brws/core/constants"
	"github.com/skunkworq/stealth/brws/stealth/internal/netutil"
)

// RequestGeneratorConfig controls the full request generation.
type RequestGeneratorConfig struct {
	Profile                    *BrowserProfile  // Browser identity to emulate
	EventConfig                *GeneratorConfig // Config for behavioral event generation (optional)
	Seed                       int64            // Optional deterministic seed for reproducible request generation
	SpoofLocalIPs              bool             // Whether to spoof local LAN IPs
	EvadeCanvasEntropy         bool             // Phase 32: Generate low entropy IDAT chunks
	EvadeWebGLCount            bool             // Phase 34: Ensure sufficient WebGL extensions
	EvadeScreenHeightGap       bool             // Phase 35: Ensure screen/availHeight gap is 30-50px
	EvadeWebGLViewport         bool             // Phase 36: Append max viewport dimensions based on max texture size
	EvadeDeviceMemoryClamp     bool             // Phase 38: Cap deviceMemory at 8
	EvadeAudioBaseLatency      bool             // Phase 53: realistic base latency
	EvadeScreenOrientation     bool             // Phase 53: consistent screen orientation
	EvadeBatteryStatus         bool             // Phase 54: realistic battery level and state
	EvadeStorageQuota          bool             // Phase 54: realistic storage quota (e.g. > 1GB)
	EvadeConnectionSaveData    bool             // Phase 39: Inject saveData: false into connection
	EvadeNavigatorKeyboard     bool             // Phase 41: Inject mock keyboard API for Chrome
	EvadeHardwareConcurrency   bool             // Phase 42: Ensure hardwareConcurrency is even
	EvadeNetworkQuantization   bool             // Phase 43: Quantize RTT/downlink values
	EvadeDPRQuantization       bool             // Phase 44: Use standard OS DPR scaling values only
	EvadeErrorStackFormat      bool             // Phase 46: Generate engine-consistent Error.stack
	EvadeWebGLParameters       bool             // Phase 47: Ensure MAX_TEXTURE_SIZE matches Renderer
	EvadeLanguageConsistency   bool             // Phase 48: Ensure Accept-Language matches navigator.languages/Intl
	EvadeMediaQueryHover       bool             // Phase 49: Ensure media query hover/any-hover is "hover"
	EvadeTLSFingerprint        bool             // Phase 3: Use uTLS to match browser JA3/JA4
	EvadeHardwareCoherence     bool             // Phase 50: Ensure CPU cores match GPU (e.g. Apple M2 >= 8 cores)
	EvadePointerInteraction    bool             // Phase 51: Ensure pointer/any-pointer are "fine"
	EvadePluginFilenames       bool             // Phase 51: Ensure all Chrome PDF plugins use internal-pdf-viewer
	EvadeWebGPU                bool             // Phase 52: Ensure WebGPU is disabled or spoofed
	EvadePermissions           bool             // Phase 52: Ensure permissions API is spoofed
	EvadeMediaDevices          bool             // Phase 55: realistic media device enumeration
	EvadeWebRTC                bool             // Phase 56: realistic WebRTC ICE candidates
	EvadeCanvasNoise           bool             // Phase 57: spatially correlated canvas noise
	EvadeScreenIsExtended      bool             // Phase 64: ensure screen.isExtended is present
	EvadeNavigatorConnectivity bool             // Phase 65: ensure onLine and vibrate are present
	EvadeNavigatorHardware     bool             // Phase 66: ensure bluetooth and usb are present
	EvadeNavigatorModernAPIs   bool             // Phase 67: ensure clipboard and credentials are present
	EvadeNavigatorMediaAPIs    bool             // Phase 68: ensure mediaCapabilities and mediaSession are present
	EvadeHeaderOrder           bool             // Phase 69: ensure browser-consistent header order
	EvadeNavigatorWorkers      bool             // Phase 70: ensure serviceWorker and sharedWorker are present
	EvadeWebGLShaderPrecision  bool             // Phase 71: ensure realistic shader precision values
	EvadeTimingDeepAnalysis    bool             // Phase 72: ensure realistic byte counts and protocols in timing
	EvadePlugins               bool             // Phase 73: ensure realistic plugins and mimeTypes
	EvadePermissionsDeep       bool             // Phase 74: ensure deep permissions consistency (cam, mic, geo)
	EvadeClientHintsDeep       bool             // Phase 75: ensure deep client hints consistency (full version, arch)
	EvadeOffscreenCanvasDeep   bool             // Phase 76: ensure offscreen canvas metrics consistency
	EvadeGamepadAPI            bool             // Phase 77: ensure Gamepad API consistency
	EvadeHardwareHardening     bool             // Phase 78: ensure Bluetooth/USB API consistency
	EvadeScreenGeometryDeep    bool             // Phase 79: ensure screen.availLeft/Top consistency
	EvadeNavigatorPrototype    bool             // Phase 80: ensure Navigator prototype chain consistency
	EvadeWebGLRendererDeep     bool             // Phase 81: ensure WebGL renderer/OS consistency
	EvadeAudioContextDeep      bool             // Phase 82: ensure AudioContext state/latency consistency
	EvadePerformanceDeep       bool             // Phase 83: ensure performance.memory/navigation consistency
	EvadeTimingDeep            bool             // Phase 84: ensure navigation/resource timing consistency
	EvadeTouchDeep             bool             // Phase 85: ensure touch/pointer consistency
	EvadeOrientationDeep       bool             // Phase 86: ensure screen orientation hardening
	EvadeNetworkInfoDeep       bool             // Phase 87: ensure network info/effectiveType consistency
	EvadeStorageDeep           bool             // Phase 88: ensure storage quota/persistence consistency
	EvadeWebGLAttributesDeep   bool             // Phase 89: ensure WebGL context attributes consistency
	EvadePaintTimingDeep       bool             // Phase 90: ensure performance paint timing consistency
	EvadeWorkerCoherence       bool             // Phase 91: ensure consistency between main thread and workers
	EvadeIntrospectionDeep     bool             // Phase 92: ensure prototype integrity and proxy evasion
	EvadeAudioGraphDeep        bool             // Phase 93: ensure WebAudio graph correlation
	EvadeCanvasGeometryDeep    bool             // Phase 94: ensure canvas measureText geometry consistency
	EvadeMathPrecision         bool             // Phase 95: ensure floating point / math precision consistency
	EvadeUADataDeep            bool             // Phase 96: ensure navigator.userAgentData high-entropy correlation
	EvadeRequestProvenance     bool             // Phase 97: model request as same-origin telemetry submission, not initial navigation
	EvadeAcceptDestConsistency bool             // Phase 98: ensure Accept vs Sec-Fetch-Dest consistency
	EvasionStrategy            EvasionStrategy  // Adaptive strategy (overrides EvadeRequestProvenance if set)
	ForceDetections            bool             // Overrides random chance to always trigger checks (for tests)
}

// MaxEvasionConfig returns a RequestGeneratorConfig with ALL evasion phases enabled.
// This represents the sword's best attempt to evade the shield.
func MaxEvasionConfig(profile *BrowserProfile) *RequestGeneratorConfig {
	return &RequestGeneratorConfig{
		Profile:                    profile,
		SpoofLocalIPs:              false, // RealBrowserStrategy: real browsers never send proxy IP headers
		EvadeCanvasEntropy:         true,
		EvadeWebGLCount:            true,
		EvadeScreenHeightGap:       true,
		EvadeWebGLViewport:         true,
		EvadeDeviceMemoryClamp:     true,
		EvadeAudioBaseLatency:      true,
		EvadeScreenOrientation:     true,
		EvadeBatteryStatus:         true,
		EvadeStorageQuota:          true,
		EvadeConnectionSaveData:    true,
		EvadeNavigatorKeyboard:     true,
		EvadeHardwareConcurrency:   true,
		EvadeNetworkQuantization:   true,
		EvadeDPRQuantization:       true,
		EvadeErrorStackFormat:      true,
		EvadeWebGLParameters:       true,
		EvadeLanguageConsistency:   true,
		EvadeMediaQueryHover:       true,
		EvadeTLSFingerprint:        true,
		EvadeHardwareCoherence:     true,
		EvadePointerInteraction:    true,
		EvadePluginFilenames:       true,
		EvadeWebGPU:                true,
		EvadePermissions:           true,
		EvadeMediaDevices:          true,
		EvadeWebRTC:                true,
		EvadeCanvasNoise:           true,
		EvadeScreenIsExtended:      true,
		EvadeNavigatorConnectivity: true,
		EvadeNavigatorHardware:     true,
		EvadeNavigatorModernAPIs:   true,
		EvadeNavigatorMediaAPIs:    true,
		EvadeHeaderOrder:           true,
		EvadeNavigatorWorkers:      true,
		EvadeWebGLShaderPrecision:  true,
		EvadeTimingDeepAnalysis:    true,
		EvadePlugins:               true,
		EvadePermissionsDeep:       true,
		EvadeClientHintsDeep:       true,
		EvadeOffscreenCanvasDeep:   true,
		EvadeGamepadAPI:            true,
		EvadeHardwareHardening:     true,
		EvadeScreenGeometryDeep:    true,
		EvadeNavigatorPrototype:    true,
		EvadeWebGLRendererDeep:     true,
		EvadeAudioContextDeep:      true,
		EvadePerformanceDeep:       true,
		EvadeTimingDeep:            true,
		EvadeTouchDeep:             true,
		EvadeOrientationDeep:       true,
		EvadeNetworkInfoDeep:       true,
		EvadeStorageDeep:           true,
		EvadeWebGLAttributesDeep:   true,
		EvadePaintTimingDeep:       true,
		EvadeWorkerCoherence:       true,
		EvadeIntrospectionDeep:     true,
		EvadeAudioGraphDeep:        true,
		EvadeCanvasGeometryDeep:    true,
		EvadeMathPrecision:         true,
		EvadeUADataDeep:            true,
		EvadeRequestProvenance:     true,
		EvadeAcceptDestConsistency: true,
		EvasionStrategy:            &FirefoxInitNavStrategy{},
	}
}

// RequestGenerator produces complete, internally-consistent stealth HTTP requests
// with all fingerprint headers that the shield's StealthDetector checks.
type RequestGenerator struct {
	config       *RequestGeneratorConfig
	eventGen     *EventGenerator
	profile      *BrowserProfile
	rng          *rand.Rand
	canvasHash   string // stable per instance
	targetURL    string // target URL for timing referrer chain
	loadEventEnd int64  // stored from timing generation for behavioral coordination
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

	seed := config.Seed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}

	//nolint:gosec
	rng := rand.New(rand.NewSource(seed))

	// Generate a stable canvas hash for this instance as a data URL.
	// Real canvas toDataURL() produces a PNG of a rendered scene (5KB-50KB).
	// We construct a valid PNG structure:
	//   8 bytes: PNG signature (\x89PNG\r\n\x1a\n)
	//  25 bytes: IHDR chunk (4 len + 4 "IHDR" + 13 data + 4 CRC)
	//   N bytes: IDAT chunk (4 len + 4 "IDAT" + data + 4 CRC)
	//  12 bytes: IEND chunk (4 len + 4 "IEND" + 4 CRC)
	// This ensures bytes 37-40 == "IDAT" to pass the IDAT structure check.
	canvasSeed := fmt.Sprintf("canvas-%d-%s", rng.Int63(), config.Profile.Name)
	hash := sha256.Sum256([]byte(canvasSeed))
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
		0x08,             // bit depth = 8
		0x06,             // color type = RGBA
		0x00, 0x00, 0x00, // compression, filter, interlace
		0x00, 0x00, 0x00, 0x00, // CRC (filled below)
	}
	// Compute CRC32 over chunk type + data (bytes 4..20 of ihdrChunk)
	ihdrCRC := crc32.NewIEEE()
	ihdrCRC.Write(ihdrChunk[4:21])
	binary.BigEndian.PutUint32(ihdrChunk[21:25], ihdrCRC.Sum32())

	// IDAT chunk: zlib-compressed pixel data (valid DEFLATE stream)
	var idatBuf bytes.Buffer
	zlibW := zlib.NewWriter(&idatBuf)
	// Real canvas toDataURL() for a 300x150 default canvas produces 5KB-20KB base64.
	// Use 48000 bytes (200x60 RGBA) to ensure compressed output > 200 base64 chars
	// even with mostly-white data (passes canvas_payload_too_short check).
	rawPixels := make([]byte, 48000)
	if config.EvadeCanvasEntropy {
		// Real canvases have low entropy (<6.0) because they have a solid background
		// and simple shapes/text. We fill with white and sprinkle a unique 32-byte
		// fingerprint pattern to ensure uniqueness without raising average entropy.
		pattern := make([]byte, 32)
		for i := 0; i < 32; i++ {
			pattern[i] = byte(canvasRng.Intn(256))
		}

		if config.EvadeCanvasNoise {
			// Phase 57: Spatially correlated noise (Low-frequency)
			// Instead of a strict modulo (which looks synthetic), we use a "clumped" approach.
			for i := 0; i < len(rawPixels); i += 4 {
				if canvasRng.Float64() < 0.005 { // 0.5% chance of a "noise clump"
					val := pattern[canvasRng.Intn(32)]
					// Clump: same noise for 4 adjacent bytes (e.g. one RGBA pixel)
					for j := 0; j < 4 && i+j < len(rawPixels); j++ {
						rawPixels[i+j] = val
					}
				} else {
					// White background
					for j := 0; j < 4 && i+j < len(rawPixels); j++ {
						rawPixels[i+j] = 255
					}
				}
			}
		} else {
			// Phase 32 evasion: simple modulo (highly periodic/detectable by Phase 57 sword)
			for i := range rawPixels {
				if i%17 == 0 {
					rawPixels[i] = pattern[i%32]
				} else {
					rawPixels[i] = 255 // White background
				}
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

	if config.EventConfig == nil {
		config.EventConfig = DefaultGeneratorConfig()
	}
	if config.EventConfig.Seed == 0 && config.Seed != 0 {
		config.EventConfig.Seed = config.Seed + 1
	}
	config.EventConfig.BrowserEngine = config.Profile.Browser
	config.EventConfig.EvadeErrorStackFormat = config.EvadeErrorStackFormat

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
// Returns nil if targetURL cannot be parsed.
func (rg *RequestGenerator) GenerateRequest(targetURL string) *http.Request {
	rg.SetTargetURL(targetURL)
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return nil
	}

	if rg.config != nil && rg.config.EvadeHeaderOrder {
		// Browser-consistent header order
		orderedHeaders := rg.GenerateOrderedHeaders()
		orderKeys := make([]string, 0, len(orderedHeaders))
		for _, pair := range orderedHeaders {
			if pair.Key != "" {
				req.Header.Add(pair.Key, pair.Value)
				orderKeys = append(orderKeys, pair.Key)
			}
		}
		// Simulation header for our own StealthDetector/Analyzers to see the intended order
		req.Header.Set("X-Stealth-Header-Order", strings.Join(orderKeys, ","))
	} else {
		headers := rg.GenerateHeaders()
		for k, vals := range headers {
			for _, v := range vals {
				req.Header.Set(k, v)
			}
		}
	}

	// Adaptive evasion strategy (overrides Phase 97 if set)
	if rg.config != nil && rg.config.EvasionStrategy != nil {
		rg.config.EvasionStrategy.Apply(req, rg, targetURL)
	} else if rg.config != nil && rg.config.EvadeRequestProvenance {
		// Legacy Phase 97: Request Provenance Evasion
		rg.applyProvenanceEvasion(req, targetURL)
	}

	// Dynamic IP Spoofing
	if rg.config != nil && rg.config.SpoofLocalIPs {
		ip := netutil.RandomLocalIP()
		req.Header.Set("X-Forwarded-For", ip)
		req.Header.Set("X-Real-IP", ip)
		req.Header.Set("X-Client-IP", ip)
		req.Header.Set("True-Client-IP", ip)
		req.Header.Set("CF-Connecting-IP", ip)
	}

	return req
}

// applyProvenanceEvasion transforms the request from an initial top-level navigation
// into a same-origin telemetry submission (XHR/fetch). Real browser stealth flows
// work in two phases: (1) navigate to the page (document request, no runtime data),
// (2) page JS collects fingerprints and sends them via fetch to a telemetry endpoint.
// The shield's provenance check flags dense runtime bundles on initial navigation
// because JS telemetry can't exist before the page loads and executes probes.
func (rg *RequestGenerator) applyProvenanceEvasion(req *http.Request, targetURL string) {
	// Model this as a POST telemetry submission — real JS telemetry uses fetch()
	// with POST and a JSON body, not GET with data stuffed in headers.
	req.Method = http.MethodPost

	// Build a realistic telemetry beacon body that mirrors what real analytics
	// SDKs (Segment, Amplitude, Sentry) send: session metadata + summarized
	// runtime fingerprint signals. Body must be ≥256 bytes and contain runtime
	// keywords to pass the shield's body-content analysis.
	sessionID := fmt.Sprintf("%x", rg.rng.Uint64())
	pageLoadTs := time.Now().Add(-time.Duration(2000+rg.rng.Intn(5000)) * time.Millisecond).UnixMilli()
	ttfb := 80 + rg.rng.Intn(300)
	fcp := ttfb + 100 + rg.rng.Intn(400)
	lcp := fcp + 200 + rg.rng.Intn(800)
	bodyJSON := fmt.Sprintf(
		`{"sid":"%s","ts":%d,"page":"/","v":"1.4.2","seq":%d,`+
			`"navigator":{"lang":"%s","cores":%d,"mem":%d},`+
			`"timing":{"ttfb":%d,"fcp":%d,"lcp":%d},`+
			`"canvas":"%x","audio":"%x",`+
			`"webgl":{"vendor":"Google Inc.","renderer":"ANGLE"}}`,
		sessionID, pageLoadTs, 1+rg.rng.Intn(5),
		rg.profile.AcceptLanguage, rg.profile.HardwareConcurrency, rg.profile.DeviceMemory,
		ttfb, fcp, lcp,
		rg.rng.Uint64(), rg.rng.Uint64())
	body := []byte(bodyJSON)
	req.Header.Set("Content-Type", "application/json")
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))

	// Change Sec-Fetch headers from initial navigation to same-origin fetch.
	// same-origin mode (not cors) — this is a same-origin POST via fetch().
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "same-origin")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Del("Sec-Fetch-User") // only present on user-initiated navigation

	// Set Referer and Origin to the origin page (different from the telemetry endpoint).
	// Real pattern: page at / collects data, POSTs to /api/telemetry.
	if parsed, err := url.Parse(targetURL); err == nil {
		originPage := parsed.Scheme + "://" + parsed.Host + "/"
		req.Header.Set("Referer", originPage)
		req.Header.Set("Origin", parsed.Scheme+"://"+parsed.Host)
	}

	// Remove Upgrade-Insecure-Requests — only sent on document navigation
	req.Header.Del("Upgrade-Insecure-Requests")

	// Change Accept to XHR format (not document)
	req.Header.Set("Accept", "application/json, text/plain, */*")

	// Chrome 146: XHR/fetch requests use priority u=1 (not u=0 like navigation)
	if rg.profile.Browser == "chrome" {
		req.Header.Set("Priority", "u=1, i")
	}

	// Strip all "JS context" headers AND most "post-load" telemetry headers.
	// Phase 99: The shield now detects dense telemetry payloads in headers on
	// same-origin fetch (postLoadHeaderCount >= 3 triggers bulk_payload check).
	// Keep only Behavioral + Timing (2 post-load headers, below the >= 3 gate).
	// This achieves:
	// 1. hasJSFingerprintHeaders() = false → missing_* penalties skipped.
	// 2. postLoadHeaderCount = 2 < 3 → telemetry bulk payload check skipped.
	// 3. presentCount = 2 → coverage score 0.24 (below ensemble threshold).
	req.Header.Del(constants.HeaderNavigatorData)
	req.Header.Del(constants.HeaderWebGLData)
	req.Header.Del(constants.HeaderPluginData)
	req.Header.Del(constants.HeaderFontData)
	req.Header.Del(constants.HeaderScreenData)
	req.Header.Del(constants.HeaderWebRTCData)
	req.Header.Del(constants.HeaderCanvasFingerprint)
	req.Header.Del(constants.HeaderAudioData)

	// Note: Chrome sends low-entropy Client Hints (Sec-Ch-Ua, -Mobile, -Platform)
	// on ALL requests including fetch/XHR. Do NOT strip them — the shield detects
	// Chrome UA without Client Hints as a strong signal.

	// Update the X-Stealth-Header-Order if present, to reflect the new header set
	if order := req.Header.Get("X-Stealth-Header-Order"); order != "" {
		// Rebuild order without removed headers
		removedHeaders := map[string]bool{
			"Upgrade-Insecure-Requests":       true,
			"Sec-Fetch-User":                  true,
			constants.HeaderNavigatorData:     true,
			constants.HeaderWebGLData:         true,
			constants.HeaderPluginData:        true,
			constants.HeaderFontData:          true,
			constants.HeaderScreenData:        true,
			constants.HeaderWebRTCData:        true,
			constants.HeaderCanvasFingerprint: true,
			constants.HeaderAudioData:         true,
		}
		parts := strings.Split(order, ",")
		filtered := make([]string, 0, len(parts))
		for _, p := range parts {
			trimmed := strings.TrimSpace(p)
			if !removedHeaders[trimmed] {
				filtered = append(filtered, trimmed)
			}
		}
		// Add Origin, Referer, and Content-Type in browser-consistent positions
		final := make([]string, 0, len(filtered)+3)
		refererAdded := false
		for _, h := range filtered {
			// Content-Type goes before Accept in browser fetch order
			if h == "Accept" {
				final = append(final, "Content-Type")
			}
			final = append(final, h)
			if h == "Accept-Language" && !refererAdded {
				final = append(final, "Origin")
				final = append(final, "Referer")
				refererAdded = true
			}
		}
		if !refererAdded {
			final = append(final, "Origin")
			final = append(final, "Referer")
		}
		req.Header.Set("X-Stealth-Header-Order", strings.Join(final, ","))
	}
}

// headerPair holds a single header key/value in ordered-header generation.
type headerPair struct {
	Key   string
	Value string
}

// sharedDimensions holds resolution, scrollbar width, and color depth picked once
// per request so that generateScreen and generateNavigator produce consistent values.
type sharedDimensions struct {
	resolution  [2]int
	scrollbarW  int
	colorDepth  int
	pixelRatio  float64
	innerWidth  int
	innerHeight int
	outerWidth  int
	outerHeight int
	orientation string
}

// GenerateHeaders creates the full set of HTTP headers including all fingerprint
// data headers. Each call produces unique timing and behavioral data.
func (rg *RequestGenerator) GenerateHeaders() http.Header {
	h := make(http.Header)

	// Pick resolution, scrollbar width, color depth, and WebGL renderer ONCE for consistency across headers
	dims := rg.calculateSharedDimensions()
	renderer := rg.profile.WebGLRenderers[rg.rng.Intn(len(rg.profile.WebGLRenderers))]

	// Standard HTTP headers
	rg.setHTTPHeaders(h)

	// Fingerprint data headers
	h.Set(constants.HeaderWebGLData, rg.generateWebGL(renderer))
	h.Set(constants.HeaderFontData, rg.generateFonts())
	h.Set(constants.HeaderScreenData, rg.generateScreen(dims))
	h.Set(constants.HeaderPluginData, rg.generatePlugins())
	h.Set(constants.HeaderTimingData, rg.generateTiming())
	h.Set(constants.HeaderBehavioralData, rg.generateBehavioral())
	h.Set(constants.HeaderNavigatorData, rg.generateNavigator(dims, renderer))
	h.Set(constants.HeaderCanvasFingerprint, rg.generateCanvas())
	h.Set(constants.HeaderAudioData, rg.generateAudio())

	return h
}

func (rg *RequestGenerator) calculateSharedDimensions() sharedDimensions {
	p := rg.profile
	res := p.Resolutions[rg.rng.Intn(len(p.Resolutions))]
	pixelRatio := rg.getDPR()

	// screen.width/height are LOGICAL resolution
	width := res[0]
	height := res[1]

	isMobile := p.Platform == "android" || p.Platform == "ios"

	// Ensure DPR >= 2.0 is only used with wide screens on desktop.
	// The shield flags DPR >= 2.0 + width < 1920 as improbable on non-mobile.
	if !isMobile && pixelRatio >= 2.0 && width < 1920 {
		// Downgrade to 1.0 DPR for narrow screens
		pixelRatio = 1.0
	}

	scrollbarW := 0
	if !isMobile {
		scrollbarW = 12 + rg.rng.Intn(6) // 12-17px
	}

	// innerWidth/innerHeight are also logical
	innerWidth := width
	innerHeight := height

	if !isMobile {
		innerWidth -= scrollbarW
		innerHeight -= 40 + rg.rng.Intn(60) // top chrome
	}

	outerWidth := width
	outerHeight := height
	if !isMobile {
		// outerWidth/Height usually match screen width/height for maximized windows on desktop,
		// or slightly smaller for windowed.
	}

	orientation := "landscape-primary"
	if height > width {
		orientation = "portrait-primary"
	}

	return sharedDimensions{
		resolution:  res,
		scrollbarW:  scrollbarW,
		colorDepth:  24,
		pixelRatio:  pixelRatio,
		innerWidth:  innerWidth,
		innerHeight: innerHeight,
		outerWidth:  outerWidth,
		outerHeight: outerHeight,
		orientation: orientation,
	}
}

func (rg *RequestGenerator) getDPR() float64 {
	if rg.config.EvadeDPRQuantization {
		return rg.profile.PixelRatios[rg.rng.Intn(len(rg.profile.PixelRatios))]
	}
	return 1.0 + rg.rng.Float64()*0.9
}
