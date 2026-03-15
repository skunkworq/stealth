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
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/constants"
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
		EvasionStrategy:            &SendBeaconStrategy{},
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
func (rg *RequestGenerator) GenerateRequest(targetURL string) *http.Request {
	rg.SetTargetURL(targetURL)
	req, _ := http.NewRequest("GET", targetURL, nil)

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
		ip := randomLocalIP()
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

type headerPair struct {
	Key   string
	Value string
}

// GenerateOrderedHeaders produces headers in a deterministic order mimicking real browsers.
func (rg *RequestGenerator) GenerateOrderedHeaders() []headerPair {
	// Pick resolution and renderer once
	dims := rg.calculateSharedDimensions()
	renderer := rg.profile.WebGLRenderers[rg.rng.Intn(len(rg.profile.WebGLRenderers))]

	h := []headerPair{}

	// Helper to add if not empty
	add := func(k, v string) {
		if v != "" {
			h = append(h, headerPair{Key: k, Value: v})
		}
	}

	// Chrome 146 ordered headers.
	// The X-Stealth-Header-Order simulation header uses HTTP/1.1 title-case names.
	// The shield's header-order check expects User-Agent before Accept for Chrome,
	// and Sec-Ch-Ua before User-Agent, so we preserve that relative ordering.
	if rg.profile.SecChUa != "" {
		add("Sec-Ch-Ua", rg.profile.SecChUa)
		add("Sec-Ch-Ua-Mobile", rg.profile.SecChUaMobile)
		add("Sec-Ch-Ua-Platform", rg.profile.SecChUaPlatform)
		if (rg.config != nil && rg.config.EvadeUADataDeep) && rg.profile.SecChUaFullVersionList != "" {
			add("Sec-Ch-Ua-Full-Version-List", rg.profile.SecChUaFullVersionList)
			add("Sec-Ch-Ua-Arch", rg.profile.SecChUaArch)
			add("Sec-Ch-Ua-Bitness", rg.profile.SecChUaBitness)
		} else if (rg.config != nil && rg.config.EvadeClientHintsDeep) || (rg.config != nil && rg.config.ForceDetections) {
			re := regexp.MustCompile(`"([^"]+)";v="(\d+)"`)
			matches := re.FindAllStringSubmatch(rg.profile.SecChUa, -1)
			fullVersions := []string{}
			for _, m := range matches {
				fullVersions = append(fullVersions, fmt.Sprintf(`"%s";v="%s.0.6998.77"`, m[1], m[2]))
			}
			add("Sec-Ch-Ua-Full-Version-List", strings.Join(fullVersions, ", "))

			isArm := strings.Contains(strings.ToLower(rg.profile.UserAgent), "arm") ||
				(strings.Contains(strings.ToLower(rg.profile.UserAgent), "applewebkit") && strings.Contains(strings.ToLower(rg.profile.UserAgent), "macintosh"))
			arch := `"x86"`
			if isArm {
				arch = `"arm"`
			}
			add("Sec-Ch-Ua-Arch", arch)
			add("Sec-Ch-Ua-Bitness", `"64"`)
		}
	}
	add("Upgrade-Insecure-Requests", "1")
	add("User-Agent", rg.profile.UserAgent)
	add("Accept", rg.profile.Accept)
	if rg.profile.Browser == "chrome" {
		add("Priority", "u=0, i")
	}
	add("Sec-Fetch-Site", rg.profile.SecFetchSite)
	add("Sec-Fetch-Mode", rg.profile.SecFetchMode)
	add("Sec-Fetch-User", rg.profile.SecFetchUser)
	add("Sec-Fetch-Dest", rg.profile.SecFetchDest)
	add("Accept-Encoding", rg.profile.AcceptEncoding)
	add("Accept-Language", rg.profile.AcceptLanguage)

	// Stealth data headers
	add(constants.HeaderWebGLData, rg.generateWebGL(renderer))
	add(constants.HeaderFontData, rg.generateFonts())
	add(constants.HeaderScreenData, rg.generateScreen(dims))
	add(constants.HeaderPluginData, rg.generatePlugins())
	add(constants.HeaderTimingData, rg.generateTiming())
	add(constants.HeaderBehavioralData, rg.generateBehavioral())
	add(constants.HeaderNavigatorData, rg.generateNavigator(dims, renderer))
	add(constants.HeaderCanvasFingerprint, rg.generateCanvas())
	add(constants.HeaderAudioData, rg.generateAudio())

	return h
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

// setHTTPHeaders sets standard browser headers and Client Hints from the profile.
func (rg *RequestGenerator) setHTTPHeaders(h http.Header) {
	h.Set("User-Agent", rg.profile.UserAgent)
	h.Set("Accept", rg.profile.Accept)
	h.Set("Accept-Language", rg.profile.AcceptLanguage)
	h.Set("Accept-Encoding", rg.profile.AcceptEncoding)
	h.Set("Connection", "keep-alive")
	h.Set("Upgrade-Insecure-Requests", "1")
	h.Set("Cache-Control", "max-age=0")

	// Chrome 146 Priority header (RFC 9218)
	if rg.profile.Browser == "chrome" {
		h.Set("Priority", "u=0, i")
	}

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

		if rg.config != nil && (rg.config.EvadeUADataDeep || rg.config.EvadeClientHintsDeep) {
			// Phase 96/75: prioritize high-entropy Client Hints from profile
			if rg.profile.SecChUaFullVersionList != "" {
				h.Set("Sec-Ch-Ua-Full-Version-List", rg.profile.SecChUaFullVersionList)
			} else if rg.config.EvadeClientHintsDeep {
				// Fallback if list is missing but evasion requested
				re := regexp.MustCompile(`"([^"]+)";v="(\d+)"`)
				matches := re.FindAllStringSubmatch(rg.profile.SecChUa, -1)
				fullVersions := []string{}
				for _, m := range matches {
					fullVersions = append(fullVersions, fmt.Sprintf(`"%s";v="%s.0.6998.77"`, m[1], m[2]))
				}
				h.Set("Sec-Ch-Ua-Full-Version-List", strings.Join(fullVersions, ", "))
			}

			if rg.profile.SecChUaArch != "" {
				h.Set("Sec-Ch-Ua-Arch", rg.profile.SecChUaArch)
			} else if rg.config.EvadeClientHintsDeep {
				isArm := strings.Contains(strings.ToLower(rg.profile.UserAgent), "arm") ||
					(strings.Contains(strings.ToLower(rg.profile.UserAgent), "applewebkit") && strings.Contains(strings.ToLower(rg.profile.UserAgent), "macintosh"))
				if isArm {
					h.Set("Sec-Ch-Ua-Arch", `"arm"`)
				} else {
					h.Set("Sec-Ch-Ua-Arch", `"x86"`)
				}
			}

			if rg.profile.SecChUaBitness != "" {
				h.Set("Sec-Ch-Ua-Bitness", rg.profile.SecChUaBitness)
			} else if rg.config.EvadeClientHintsDeep {
				h.Set("Sec-Ch-Ua-Bitness", `"64"`)
			}
		} else if rg.config != nil && rg.config.ForceDetections {
			// Phase 75 Fallback/Forced Detection logic
			re := regexp.MustCompile(`"([^"]+)";v="(\d+)"`)
			matches := re.FindAllStringSubmatch(rg.profile.SecChUa, -1)
			fullVersions := []string{}
			for _, m := range matches {
				fullVersions = append(fullVersions, fmt.Sprintf(`"%s";v="%s.0.6998.77"`, m[1], m[2]))
			}
			h.Set("Sec-Ch-Ua-Full-Version-List", strings.Join(fullVersions, ", "))

			isArm := strings.Contains(strings.ToLower(rg.profile.UserAgent), "arm") ||
				(strings.Contains(strings.ToLower(rg.profile.UserAgent), "applewebkit") && strings.Contains(strings.ToLower(rg.profile.UserAgent), "macintosh"))
			arch := `"x86"`
			if isArm {
				arch = `"arm"`
			}
			h.Set("Sec-Ch-Ua-Arch", arch)
			h.Set("Sec-Ch-Ua-Bitness", `"64"`)
		}
	}
}

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

	scr := &adversarial.ScreenData{
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

// generatePlugins creates the X-Plugin-Data header JSON.
// Chrome profiles get 5 PDF plugins with MIME types; Firefox gets empty.
func (rg *RequestGenerator) generatePlugins() string {
	plugins := make([]map[string]interface{}, 0, len(rg.profile.Plugins))
	for _, p := range rg.profile.Plugins {
		filename := p.Filename
		if rg.config.EvadePluginFilenames && rg.profile.Browser == "chrome" && strings.Contains(strings.ToLower(p.Name), "pdf") {
			filename = "internal-pdf-viewer"
		}
		entry := map[string]interface{}{
			"name":     p.Name,
			"filename": filename,
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

	if !rg.config.EvadePlugins && !rg.config.EvadePluginFilenames && (rg.config.ForceDetections || rg.rng.Intn(10) < 3) {
		// Bot-like: empty plugins on Chrome
		if rg.profile.Browser == "chrome" {
			data["plugins"] = []interface{}{}
			data["plugin_count"] = 0
		}
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
		TimestampMs     int64   `json:"timestamp_ms"`
		ContentType     string  `json:"content_type"`
		Referrer        string  `json:"referrer"`
		URL             string  `json:"url,omitempty"`
		DurationMs      int64   `json:"duration_ms,omitempty"`
		TransferSize    float64 `json:"transfer_size,omitempty"`
		EncodedBodySize float64 `json:"encoded_body_size,omitempty"`
		DecodedBodySize float64 `json:"decoded_body_size,omitempty"`
		Protocol        string  `json:"next_hop_protocol,omitempty"`
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

	// Establish base timing
	tsRelative := int64(0)
	absStart := time.Now().UnixMilli() - 2000 // Start 2s ago

	for i, res := range resources {
		referrer := ""
		if res.hasReferrer {
			referrer = baseURL
		}

		e := entry{
			TimestampMs: absStart + tsRelative,
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
		case strings.Contains(res.contentType, "json"):
			e.DurationMs = 100 + int64(rg.rng.Intn(300)) // 100-400ms
		default:
			e.DurationMs = 50 + int64(rg.rng.Intn(100))
		}

		if rg.config.EvadeTimingDeepAnalysis {
			// Realistic byte counts and protocols
			decodedSize := int64(1024 + rg.rng.Intn(500000)) // 1KB - 501KB
			if strings.Contains(res.contentType, "image") {
				decodedSize = int64(10000 + rg.rng.Intn(2000000))
			} else if strings.Contains(res.contentType, "html") {
				decodedSize = int64(5000 + rg.rng.Intn(100000))
			}

			encodedSize := int64(float64(decodedSize) * (0.3 + rg.rng.Float64()*0.4))
			transferSize := encodedSize + int64(200+rg.rng.Intn(300))

			e.TransferSize = float64(transferSize)
			e.EncodedBodySize = float64(encodedSize)
			e.DecodedBodySize = float64(decodedSize)

			proto := "h2"
			if rg.rng.Float64() < 0.15 {
				proto = "h3"
			}
			e.Protocol = proto
		} else if rg.config.ForceDetections || rg.rng.Intn(10) < 3 {
			// Bot-like: missing or constant
			if rg.rng.Float64() < 0.5 {
				e.TransferSize = 0
				e.EncodedBodySize = 0
				e.Protocol = ""
			} else {
				e.TransferSize = 1234
				e.EncodedBodySize = 1200
				e.Protocol = "http/1.1"
			}
		} else {
			// Default healthy behavior
			e.Protocol = "h2"
			e.TransferSize = float64(1000 + rg.rng.Intn(5000))
			e.EncodedBodySize = e.TransferSize * 0.8
			e.DecodedBodySize = e.TransferSize * 1.5
		}

		entries = append(entries, e)

		if i < len(resources)-1 {
			next := resources[i+1]
			interval := next.minGap + int64(rg.rng.Intn(int(next.maxGap-next.minGap+1)))
			tsRelative += interval
		}
	}

	navStart := absStart - int64(100+rg.rng.Intn(200)) // navStart before first request
	loadEventEnd := absStart + tsRelative + 1000       // loadEnd after last request

	if rg.config.EvadeTimingDeep {
		// already good with absolute defaults above
	} else if rg.config.ForceDetections {
		// Simulate inconsistencies
		navStart = absStart + 100                  // AFTER first request (mismatch!)
		loadEventEnd = absStart + tsRelative - 100 // BEFORE last request finished (mismatch!)
	}

	// Phase 90: Paint Timing
	paintEntries := make([]map[string]interface{}, 0)
	if rg.config.EvadePaintTimingDeep {
		// Calculate when the first visual resource (CSS) finished loading
		// resources[0] is HTML, resources[1] is the first CSS
		firstCSSLoadEnd := resources[0].maxGap + resources[1].maxGap + entries[1].DurationMs

		fp := firstCSSLoadEnd - 20 - int64(rg.rng.Intn(30))
		fcp := firstCSSLoadEnd + 10 + int64(rg.rng.Intn(50))

		paintEntries = append(paintEntries, map[string]interface{}{
			"name":       "first-paint",
			"start_time": float64(fp),
		})
		paintEntries = append(paintEntries, map[string]interface{}{
			"name":       "first-contentful-paint",
			"start_time": float64(fcp),
		})
	} else if rg.config.ForceDetections {
		// Mismatch: FCP before FP or zero
		paintEntries = append(paintEntries, map[string]interface{}{
			"name":       "first-paint",
			"start_time": 0.0,
		})
	} else {
		// Healthy default paint markers — must be significantly after navigationStart
		// and usually after a few resources have started/finished.
		fp := 350.0 + float64(rg.rng.Intn(100))
		fcp := fp + 20.0 + float64(rg.rng.Intn(100))
		paintEntries = append(paintEntries, map[string]interface{}{
			"name":       "first-paint",
			"start_time": fp,
		})
		paintEntries = append(paintEntries, map[string]interface{}{
			"name":       "first-contentful-paint",
			"start_time": fcp,
		})
	}

	// Store loadEventEnd for behavioral timestamp coordination.
	rg.loadEventEnd = loadEventEnd

	data := map[string]interface{}{
		"entries":         entries,
		"ttfb":            float64(resources[0].maxGap + 50),
		"navigationStart": float64(navStart),
		"loadEventEnd":    float64(loadEventEnd),
		"paint_entries":   paintEntries,
	}

	jsonData, _ := json.Marshal(data)
	return string(jsonData)
}

// generateBehavioral creates the X-Behavioral-Data header JSON.
// Delegates to the EventGenerator for human-like mouse/typing data.
// When loadEventEnd is set (from timing generation), behavioral timestamps
// are offset to start after page load to avoid the behavioral_before_page_load check.
func (rg *RequestGenerator) generateBehavioral() string {
	eventData := rg.eventGen.Generate()

	// Coordinate behavioral timestamps with timing data:
	// behavioral events must start AFTER loadEventEnd.
	if rg.loadEventEnd > 0 && len(eventData.MouseTimestamps) > 0 {
		earliest := eventData.MouseTimestamps[0]
		for _, ts := range eventData.MouseTimestamps {
			if ts < earliest {
				earliest = ts
			}
		}
		// Offset so first behavioral event is 500-1500ms after page load
		offset := rg.loadEventEnd - earliest + 500 + int64(rg.rng.Intn(1000))
		for i := range eventData.MouseTimestamps {
			eventData.MouseTimestamps[i] += offset
		}
		for i := range eventData.TypingTimestamps {
			eventData.TypingTimestamps[i] += offset
		}
		for i := range eventData.ScrollTimestamps {
			eventData.ScrollTimestamps[i] += offset
		}
		for i := range eventData.ClickTimestamps {
			eventData.ClickTimestamps[i] += offset
		}
	}

	jsonStr, _ := rg.eventGen.ToJSON(eventData)
	return jsonStr
}

// generateNavigator creates the X-Navigator-Data header JSON.
// Uses shared resolution and scrollbar width for consistency with screen data.
func (rg *RequestGenerator) generateNavigator(dims sharedDimensions, renderer string) string {
	p := rg.profile

	concurrency, memory := rg.generateHardwareSpecsWithRenderer(renderer)
	rtt, downlink := rg.generateNetworkInfo()
	effType := "4g"

	if rg.config.EvadeNetworkInfoDeep {
		// Align network info with device/profile (mostly 4g for modern profiles)
		effType = "4g"
		if rtt > 100 {
			rtt = 25 + float64(rg.rng.Intn(3))*25 // 25, 50, 75ms
		}
		if downlink < 5.0 {
			downlink = 5.0 + rg.rng.Float64()*5.0
		}
	} else if rg.config.ForceDetections {
		// Simulate mismatch: high downlink but low effectiveType
		effType = "2g"
		downlink = 15.0
		rtt = 50.0
	}

	// navigator.appVersion = UA minus "Mozilla/" prefix
	appVersion := p.UserAgent
	if strings.HasPrefix(p.UserAgent, "Mozilla/") {
		appVersion = p.UserAgent[len("Mozilla/"):]
	}

	connObj := map[string]interface{}{
		"rtt":           rtt,
		"downlink":      downlink,
		"effectiveType": effType,
	}

	if (rg.config.EvadeConnectionSaveData || rg.config.EvadeNetworkInfoDeep) && p.Browser == "chrome" {
		connObj["saveData"] = false
	}

	maxTouch := 0
	if rg.profile.Platform == "android" || rg.profile.Platform == "ios" {
		maxTouch = 5
	}

	if rg.config.EvadeTouchDeep {
		// already good
	} else if rg.config.ForceDetections {
		// Simulate mismatch: mobile UA with 0 touch points
		if maxTouch > 0 {
			maxTouch = 0
		} else {
			// desktop with touch points
			maxTouch = 10
		}
	}

	data := map[string]interface{}{
		"webdriver":                       false,
		"webdriverString":                 "function () { [native code] }",
		"platform":                        p.NavPlatform,
		"vendor":                          p.NavVendor,
		"userAgent":                       p.UserAgent,
		"appVersion":                      appVersion,
		"hardwareConcurrency":             concurrency,
		"deviceMemory":                    memory,
		"cookieEnabled":                   true,
		"pdfViewerEnabled":                true,
		"connection":                      connObj,
		"languages":                       p.Languages,
		"language":                        p.Languages[0],
		"intl_locale":                     p.Languages[0],
		"screen_color_depth":              dims.colorDepth,
		"screen_inner_width":              dims.innerWidth,
		"screen_inner_height":             dims.innerHeight,
		"screen_outer_width":              dims.outerWidth,
		"screen_outer_height":             dims.outerHeight,
		"productSub":                      p.ProductSub,
		"maxTouchPoints":                  maxTouch,
		"Notification_permission":         "default",
		"gpu_present":                     true,
		"permissions_notifications_state": "default",
		"screen_orientation":              dims.orientation,
		"screen": map[string]interface{}{
			"orientation":          dims.orientation,
			"has_orientation_lock": hasLockValue(rg),
			"is_extended":          isExtendedValue(rg),
			"colorDepth":           float64(dims.colorDepth),
			"pixelDepth":           float64(dims.colorDepth),
		},
		"battery_status":             rg.generateBatteryStatus(),
		"storage_quota":              rg.generateStorageQuota(dims, float64(memory)),
		"media_devices":              rg.generateMediaDevices(),
		"webrtc_data":                rg.generateWebRTC(),
		"userAgentData":              rg.generateUserAgentData(),
		"userActivation":             map[string]interface{}{"hasBeenActive": false, "isActive": false},
		"keyboard":                   map[string]interface{}{},
		"scheduling":                 map[string]interface{}{"isInputPending": false},
		"locks":                      map[string]interface{}{},
		"intl_timezone":              rg.profile.Timezone,
		"timezone":                   rg.profile.Timezone,
		"audio_worklet_available":    true,
		"offscreen_canvas_available": true,
		"storage_persisted":          rg.config.EvadeStorageDeep,                      // true on modern Chrome
		"storage_usage":              float64(1024 * 1024 * (100 + rg.rng.Intn(900))), // 100MB - 1GB usage
		"onLine":                     true,
		"vibrate":                    true,
		"clipboard":                  map[string]interface{}{},
		"credentials":                map[string]interface{}{},
		"mediaCapabilities":          map[string]interface{}{},
		"mediaSession":               map[string]interface{}{},
		"getGamepads":                true, // Presence indicator
		"bluetooth":                  map[string]interface{}{"getAvailability": true},
		"usb":                        map[string]interface{}{"getDevices": true},
	}

	// Storage API availability flags (present in all modern browsers)
	data["hasLocalStorage"] = true
	data["hasSessionStorage"] = true
	data["hasIndexedDB"] = true

	// hasChrome flag for Chromium browsers
	if p.Browser == "chrome" || p.Browser == "edge" {
		data["hasChrome"] = true
	}

	rg.addMathPrecision(data)

	if rg.config != nil && rg.config.EvadeOffscreenCanvasDeep {
		// Realistic font metrics for a standard "16px sans-serif" space character or short string.
		// These values are typically stable across Chrome versions on the same OS.
		metrics := map[string]interface{}{
			"width": 9.6015625, // characteristic width for 16px Arial/sans-serif 'A'
		}
		data["main_canvas_text_metrics"] = metrics
		data["offscreen_canvas_text_metrics"] = metrics
	} else if rg.config != nil && rg.config.ForceDetections {
		// Simulate mismatch: main canvas is correct, offscreen is default/broken
		data["main_canvas_text_metrics"] = map[string]interface{}{"width": 9.6015625}
		data["offscreen_canvas_text_metrics"] = map[string]interface{}{"width": 0.0}
	}

	// Phase 77: Gamepad API
	if rg.config != nil && !rg.config.EvadeGamepadAPI && rg.config.ForceDetections {
		delete(data, "getGamepads")
		data["gamepad_api_stubbed"] = true
	}

	// Phase 78: Hardware API Hardening
	if rg.config != nil && !rg.config.EvadeHardwareHardening && rg.config.ForceDetections {
		data["bluetooth"] = map[string]interface{}{} // missing getAvailability
		data["usb"] = map[string]interface{}{}       // missing getDevices
	}

	// Phase 80: Navigator Prototype Hardening
	if rg.config != nil && !rg.config.EvadeNavigatorPrototype && rg.config.ForceDetections {
		data["navigator_prototype_stubbed"] = true
	}

	if rg.config != nil && rg.config.EvadePermissionsDeep {
		data["permissions_notifications_state"] = data["Notification_permission"]
		data["permissions_camera_state"] = "prompt"
		data["permissions_microphone_state"] = "prompt"
		data["permissions_geolocation_state"] = "prompt"
	}

	if rg.config != nil && rg.config.EvadePlugins && rg.profile.Browser == "chrome" {
		mimes := []string{}
		for _, p := range rg.profile.Plugins {
			mimes = append(mimes, p.MimeTypes...)
		}
		data["mimeTypes"] = mimes
	}

	if rg.config != nil && rg.config.EvadeNavigatorWorkers {
		data["serviceWorker"] = map[string]interface{}{}
		data["sharedWorker"] = map[string]interface{}{}
	}

	if !rg.config.EvadeWebGPU && rg.rng.Intn(10) < 3 {
		// Randomly simulate missing WebGPU support (common in headless/old bots)
		data["gpu_present"] = false
	}

	if !rg.config.EvadePermissions && !rg.config.EvadePermissionsDeep && (rg.config.ForceDetections || rg.rng.Intn(10) < 3) {
		// Randomly simulate permissions mismatch
		data["permissions_notifications_state"] = "denied" // Notification_permission defaults to "default"
	}

	if !rg.config.EvadeScreenOrientation && rg.rng.Intn(10) < 3 {
		// Randomly simulate orientation mismatch
		if strings.Contains(data["screen_orientation"].(string), "landscape") {
			data["screen_orientation"] = "portrait-primary"
		} else {
			data["screen_orientation"] = "landscape-primary"
		}
	}

	if !rg.config.EvadeBatteryStatus && rg.rng.Intn(10) < 3 {
		// Randomly simulate static "fully charged" battery mock
		data["battery_status"] = map[string]interface{}{
			"level":           1.0,
			"charging":        true,
			"chargingTime":    0.0,
			"dischargingTime": 1e308, // Infinity
		}
	}

	if rg.config.ForceDetections && !rg.config.EvadeStorageQuota {
		// Only force obviously bad quota data when a test explicitly asks for detections.
		data["storage_quota"] = 0.0
	}

	if !rg.config.EvadeMediaDevices && rg.rng.Intn(10) < 3 {
		// Randomly simulate empty media devices (common in headless/CI)
		data["media_devices"] = []interface{}{}
	}

	if !rg.config.EvadeWebRTC && rg.rng.Intn(10) < 3 {
		// Randomly simulate missing WebRTC or empty candidates
		if rg.rng.Float64() < 0.5 {
			delete(data, "webrtc_data")
		} else {
			data["webrtc_data"] = map[string]interface{}{
				"ice_candidates": []interface{}{},
			}
		}
	}

	// Phase 83: performance.navigation
	navType := 0
	if !rg.config.EvadePerformanceDeep && rg.config.ForceDetections {
		navType = 1 // simulate reload
	}
	data["performance_navigation"] = map[string]interface{}{
		"type": navType,
	}

	rg.addNavigatorMediaQueries(data)

	if rg.profile.Browser == "chrome" {
		rg.addChromeRuntimeData(data)
	}

	if !rg.config.EvadeNavigatorConnectivity && (rg.config.ForceDetections || rg.rng.Intn(10) < 3) {
		if rg.config.ForceDetections {
			delete(data, "onLine")
			delete(data, "vibrate")
		} else if rg.rng.Float64() < 0.5 {
			delete(data, "onLine")
		} else {
			delete(data, "vibrate")
		}
	}

	if !rg.config.EvadeNavigatorHardware && (rg.config.ForceDetections || rg.rng.Intn(10) < 3) {
		if rg.config.ForceDetections {
			delete(data, "bluetooth")
			delete(data, "usb")
		} else if rg.rng.Float64() < 0.5 {
			delete(data, "bluetooth")
		} else {
			delete(data, "usb")
		}
	}

	if !rg.config.EvadeNavigatorModernAPIs && (rg.config.ForceDetections || rg.rng.Intn(10) < 3) {
		if rg.config.ForceDetections {
			delete(data, "clipboard")
			delete(data, "credentials")
		} else if rg.rng.Float64() < 0.5 {
			delete(data, "clipboard")
		} else {
			delete(data, "credentials")
		}
	}

	if !rg.config.EvadeNavigatorMediaAPIs && (rg.config.ForceDetections || rg.rng.Intn(10) < 3) {
		if rg.config.ForceDetections {
			delete(data, "mediaCapabilities")
			delete(data, "mediaSession")
		} else if rg.rng.Float64() < 0.5 {
			delete(data, "mediaCapabilities")
		} else {
			delete(data, "mediaSession")
		}
	}

	// Phase 91: Worker Coherence
	if rg.config.EvadeWorkerCoherence {
		data["worker_navigator"] = map[string]interface{}{
			"userAgent":           rg.profile.UserAgent,
			"platform":            rg.profile.NavPlatform,
			"hardwareConcurrency": concurrency,
		}
	} else if rg.config.ForceDetections {
		// Mismatch: Worker has different UA/Platform (common in simple bots)
		data["worker_navigator"] = map[string]interface{}{
			"userAgent":           "BotWorker/1.0",
			"platform":            "Linux",
			"hardwareConcurrency": 2,
		}
	}

	// Phase 92: Runtime Introspection
	if rg.config.EvadeIntrospectionDeep {
		data["navigator_proxied"] = false
		data["toString_integrity_leaks"] = []interface{}{}
	} else if rg.config.ForceDetections {
		data["navigator_proxied"] = true
		data["toString_integrity_leaks"] = []interface{}{
			"Function.prototype.toString.call(navigator.plugins)",
		}
	}

	// Phase 94: Canvas measureText
	if rg.config.EvadeCanvasGeometryDeep {
		data["canvas_measure_text"] = map[string]interface{}{
			"i": 4.5,
			"W": 12.8,
		}
	} else if rg.config.ForceDetections {
		data["canvas_measure_text"] = map[string]interface{}{
			"i": 10.0,
			"W": 10.0, // simplified stub
		}
	}

	b, _ := json.Marshal(data)
	return string(b)
}

func hasLockValue(rg *RequestGenerator) *bool {
	hasLock := false
	if rg.profile.Platform == "android" || rg.profile.Platform == "ios" {
		hasLock = true
	}
	if rg.config.EvadeOrientationDeep {
		return &hasLock
	} else if rg.config.ForceDetections {
		if hasLock {
			lock := false
			return &lock
		}
	}
	// Default: provide the value
	return &hasLock
}

func isExtendedValue(rg *RequestGenerator) *bool {
	isExt := false
	if rg.config != nil && rg.profile.Browser == "chrome" {
		isExt = true
	}
	if rg.config != nil && !rg.config.EvadeScreenIsExtended && (rg.config.ForceDetections || rg.rng.Intn(10) < 3) {
		return nil
	}
	return &isExt
}

func (rg *RequestGenerator) addNavigatorMediaQueries(data map[string]interface{}) {
	hover := "hover"
	anyHover := "hover"
	pointer := "fine"
	anyPointer := "fine"

	isMobile := rg.profile.Platform == "android" || rg.profile.Platform == "ios"
	if isMobile {
		hover = "none"
		anyHover = "none"
		pointer = "coarse"
		anyPointer = "coarse"
	}

	if rg.config.EvadeMediaQueryHover {
		// already good with defaults
	} else if rg.config.ForceDetections {
		// possibly simulate mobile with hover or desktop with none
		if isMobile {
			hover = "hover"
		} else {
			hover = "none"
		}
	}

	if !rg.config.EvadePointerInteraction && !rg.config.EvadeTouchDeep {
		if rg.config.ForceDetections {
			if isMobile {
				// Mismatch: maxTouchPoints=0 but primary pointer=coarse
				pointer = "coarse"
			} else {
				// Mismatch: maxTouchPoints=5 but only fine pointers reported
				pointer = "fine"
				anyPointer = "fine"
			}
		} else if rg.rng.Intn(10) < 3 {
			// Randomly simulate non-standard pointer
			if isMobile {
				pointer = "fine"
			} else {
				pointer = "coarse"
			}
		}
	}

	data["media_query_hover"] = hover
	data["media_query_any_hover"] = anyHover
	data["media_query_pointer"] = pointer
	data["media_query_any_pointer"] = anyPointer
}

func (rg *RequestGenerator) generateHardwareSpecsWithRenderer(renderer string) (concurrency, memory int) {
	type hwPair struct{ memory, cores int }
	hardwarePairs := []hwPair{
		{4, 4},
		{4, 8},
		{8, 4},
		{8, 8},
		{16, 8},
		{16, 12},
		{32, 8},
		{32, 12},
		{32, 16},
	}

	rLow := strings.ToLower(renderer)

	// If profile has specific memory values, use them to filter pairs
	availableMem := make(map[int]bool)
	for _, m := range rg.profile.DeviceMemory {
		availableMem[m] = true
	}

	filtered := make([]hwPair, 0)
	for _, pair := range hardwarePairs {
		coherent := true

		// 1. Enforce profile memory constraints
		if len(availableMem) > 0 && !availableMem[pair.memory] {
			coherent = false
		}

		// 2. Coherence rules (only if evading)
		if rg.config != nil && rg.config.EvadeHardwareCoherence {
			isApple := strings.Contains(rLow, "apple m")
			highEndGPUs := []string{"rtx 30", "rtx 40", "rx 6", "rx 7"}
			isHighEnd := false
			for _, g := range highEndGPUs {
				if strings.Contains(rLow, g) {
					isHighEnd = true
					break
				}
			}

			if isApple && pair.cores < 8 {
				coherent = false
			}
			if isHighEnd && pair.cores < 6 {
				coherent = false
			}
		}

		if coherent {
			filtered = append(filtered, pair)
		}
	}

	if len(filtered) > 0 {
		hardwarePairs = filtered
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
	return concurrency, memory
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
	return rtt, downlink
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

func (rg *RequestGenerator) addMathPrecision(data map[string]interface{}) {
	// Phase 95: Floating Point / Math Precision Evasion
	sin1e15 := -0.8582732024756439
	cos1e15 := -0.5131970812354724

	// Real V8 values for 1e15:
	// Math.sin(1e15) = -0.8582732024756439
	// Math.cos(1e15) = -0.5131970812354724

	if !rg.config.EvadeMathPrecision && rg.config.ForceDetections {
		// Detection: stubbed math
		sin1e15 = 0.0
		cos1e15 = 0.0
	}

	data["math_precision"] = map[string]interface{}{
		"sin1e15": sin1e15,
		"cos1e15": cos1e15,
	}
}

func (rg *RequestGenerator) addPerformanceMemory(data map[string]interface{}) {
	deviceMem, _ := data["deviceMemory"].(int)
	if deviceMem == 0 {
		deviceMem = 8 // Default to 8GB if not set
	}

	// Standard Chrome heap limits (approximate bytes)
	// 4GB RAM -> ~2.1GB heap limit
	// 8GB+ RAM -> ~4.2GB heap limit
	jsHeapLimit := 4294705152 // Default for 8GB+
	if deviceMem <= 4 {
		jsHeapLimit = 2172641280
	}

	// Add a tiny bit of jitter to the limit (real browsers vary by a few bytes/KB)
	jsHeapLimit += rg.rng.Intn(1024) - 512

	totalHeap := 20*1024*1024 + rg.rng.Intn(60*1024*1024)
	usedHeap := int(float64(totalHeap) * (0.3 + rg.rng.Float64()*0.5))

	if !rg.config.EvadePerformanceDeep && rg.config.ForceDetections {
		// Simulate mismatch: small limit for large RAM
		jsHeapLimit = 1073741824
	}

	data["performance_memory"] = map[string]interface{}{
		"jsHeapSizeLimit": float64(jsHeapLimit),
		"totalJSHeapSize": float64(totalHeap),
		"usedJSHeapSize":  float64(usedHeap),
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

func (rg *RequestGenerator) generateScreenOrientation(dims sharedDimensions) string {
	width := dims.resolution[0]
	height := dims.resolution[1]
	if width < height {
		return "portrait-primary"
	}
	return "landscape-primary"
}

func (rg *RequestGenerator) generateBatteryStatus() map[string]interface{} {
	if rg.config != nil && rg.config.EvadeBatteryStatus {
		// Realistic battery status: almost never "exactly" 100% charging 0 time
		level := 0.2 + rg.rng.Float64()*0.75 // 20-95%
		charging := rg.rng.Float64() < 0.3
		chargingTime := 0.0
		dischargingTime := 1e308 // Infinity

		if charging {
			chargingTime = float64(rg.rng.Intn(3600)) // seconds to full
		} else {
			dischargingTime = float64(rg.rng.Intn(18000)) // seconds to empty
		}

		return map[string]interface{}{
			"level":           level,
			"charging":        charging,
			"chargingTime":    chargingTime,
			"dischargingTime": dischargingTime,
		}
	} else if rg.config != nil && rg.config.ForceDetections {
		// Simulate suspicious: 100% full, charging, 0 charging time, infinity discharging
		return map[string]interface{}{
			"level":           1.0,
			"charging":        true,
			"chargingTime":    0.0,
			"dischargingTime": 1e308, // JSON doesn't support math.Inf(1)
		}
	}

	// Default/Realism (un-evaded)
	return map[string]interface{}{
		"level":           1.0,
		"charging":        true,
		"chargingTime":    0.0,
		"dischargingTime": 1e308, // JSON doesn't support math.Inf(1)
	}
}

func (rg *RequestGenerator) generateStorageQuota(dims sharedDimensions, memory float64) float64 {
	// Based on Chromium logic: usually ~80% of total disk, but reported as a fraction of avail
	// For bots, we'll return a realistic value between 10GB and 500GB
	baseQuota := 10 * 1024 * 1024 * 1024 // 10GB

	if rg.config.EvadeStorageDeep || rg.config.EvadeStorageQuota {
		// Phase 88/54: Quota vs RAM
		// 8GB RAM -> > 10GB quota typically.
		// 4GB RAM -> > 5GB quota.
		if memory >= 8 {
			baseQuota = 20 * 1024 * 1024 * 1024
		} else if memory >= 4 {
			baseQuota = 8 * 1024 * 1024 * 1024
		}
	} else if rg.config.ForceDetections {
		// Low quota despite memory
		return 512 * 1024 * 1024 // 512MB
	}

	q := float64(baseQuota + rg.rng.Intn(480*1024*1024*1024))
	return q
}

func (rg *RequestGenerator) generateMediaDevices() []interface{} {
	devices := make([]interface{}, 0)

	genId := func() string {
		bytes := make([]byte, 32)
		rg.rng.Read(bytes)
		return fmt.Sprintf("%x", bytes)
	}

	groupId := genId()

	// If deep permissions evasion is enabled, we default to "prompt" state
	// which means devices should NOT have labels or deviceIds should be empty/mangled.
	showLabels := true
	if rg.config != nil && rg.config.EvadePermissionsDeep {
		showLabels = false
	}

	getLabel := func(defaultLabel string) string {
		if showLabels {
			return defaultLabel
		}
		return ""
	}

	getId := func() string {
		if showLabels {
			return genId()
		}
		// When permission is not granted, deviceId is usually an empty string or a generic hash
		// and label is empty.
		return ""
	}

	// 1. Audio Input (Microphone)
	devices = append(devices, map[string]interface{}{
		"deviceId": getId(),
		"kind":     "audioinput",
		"label":    getLabel("Internal Microphone"),
		"groupId":  groupId,
	})

	// 2. Audio Output (Speakers)
	devices = append(devices, map[string]interface{}{
		"deviceId": "default",
		"kind":     "audiooutput",
		"label":    getLabel("Default - Speakers"),
		"groupId":  groupId,
	})
	devices = append(devices, map[string]interface{}{
		"deviceId": getId(),
		"kind":     "audiooutput",
		"label":    getLabel("Built-in Output"),
		"groupId":  groupId,
	})

	// 3. Video Input (Camera)
	if rg.rng.Float64() < 0.8 {
		devices = append(devices, map[string]interface{}{
			"deviceId": getId(),
			"kind":     "videoinput",
			"label":    getLabel("FaceTime HD Camera"),
			"groupId":  genId(),
		})
	}

	return devices
}

func (rg *RequestGenerator) generateWebRTC() map[string]interface{} {
	candidates := make([]interface{}, 0)

	// Helper to generate a realistic local IPv4 (e.g. 192.168.1.X)
	genLocalIP := func() string {
		return fmt.Sprintf("192.168.1.%d", 2+rg.rng.Intn(250))
	}

	// Helper to generate a realistic mDNS IPv6 (e.g. xxxxxxxx-xxxx-4xxx-xxxx-xxxxxxxxxxxx.local)
	genMDNS := func() string {
		bytes := make([]byte, 16)
		rg.rng.Read(bytes)
		return fmt.Sprintf("%x-%x-%x-%x-%x.local", bytes[0:4], bytes[4:6], bytes[6:8], bytes[8:10], bytes[10:16])
	}

	// 1. Host Candidates (mDNS is common in modern browsers)
	candidates = append(candidates, fmt.Sprintf("candidate:0 1 UDP 2122252543 %s 58349 typ host", genMDNS()))

	if rg.rng.Float64() < 0.3 {
		// Occasionally add a real local IP (older styles or specific configs)
		candidates = append(candidates, fmt.Sprintf("candidate:1 1 UDP 2122252542 %s 58350 typ host", genLocalIP()))
	}

	// 2. Server Reflexive (STUN) - usually not present in static request snapshots but good for completeness
	// For this analyzer, we'll stick to host candidates which are more common in initial SDP.

	return map[string]interface{}{
		"ice_candidates": candidates,
	}
}

func (rg *RequestGenerator) generateUserAgentData() map[string]interface{} {
	// Dynamically extract brands and versions from the profile's SecChUa
	// Format: "Chromium";v="116", "Not)A;Brand";v="24", "Google Chrome";v="116"
	uaData := map[string]interface{}{
		"mobile":   rg.profile.SecChUaMobile == "?1",
		"platform": rg.profile.Platform,
	}

	rawUA := rg.profile.SecChUa
	if rawUA == "" {
		// Default fallback for Chrome if not specified (though it should be)
		uaData["brands"] = []map[string]interface{}{
			{"brand": "Chromium", "version": "134"},
			{"brand": "Google Chrome", "version": "134"},
			{"brand": "Not-A.Brand", "version": "99"},
		}
		uaData["uaFullVersion"] = "134.0.0.0"
		return uaData
	}

	// Simple parser for Sec-Ch-Ua string
	brands := []map[string]interface{}{}
	fullVersion := "134.0.0.0" // Default major version
	parts := strings.Split(rawUA, ",")
	for _, part := range parts {
		// Look for brand and version: "Brand";v="Version"
		re := regexp.MustCompile(`"([^"]+)";v="(\d+)"`)
		matches := re.FindStringSubmatch(strings.TrimSpace(part))
		if len(matches) > 2 {
			brand := matches[1]
			version := matches[2]
			brands = append(brands, map[string]interface{}{
				"brand":   brand,
				"version": version,
			})
			// Use the first non-generic version as the full version base
			if brand != "Not-A.Brand" && brand != "Chromium" {
				fullVersion = fmt.Sprintf("%s.0.0.0", version)
			}
		}
	}

	uaData["brands"] = brands
	uaData["uaFullVersion"] = fullVersion

	if rg.config != nil && rg.config.EvadeUADataDeep {
		// Phase 96: Deep Evasion using high-entropy profile fields
		if rg.profile.SecChUaFullVersionList != "" {
			fullBrands := []map[string]interface{}{}
			parts := strings.Split(rg.profile.SecChUaFullVersionList, ",")
			for _, part := range parts {
				re := regexp.MustCompile(`"([^"]+)";v="([^"]+)"`)
				matches := re.FindStringSubmatch(strings.TrimSpace(part))
				if len(matches) > 2 {
					fullBrands = append(fullBrands, map[string]interface{}{
						"brand":   matches[1],
						"version": matches[2],
					})
				}
			}
			uaData["fullVersionList"] = fullBrands
			// Update fullVersion to match the primary brand in fullVersionList
			if len(fullBrands) > 0 {
				uaData["uaFullVersion"] = fullBrands[0]["version"]
			}
		}

		if rg.profile.SecChUaArch != "" {
			uaData["architecture"] = strings.Trim(rg.profile.SecChUaArch, "\"")
		}
		if rg.profile.SecChUaBitness != "" {
			uaData["bitness"] = strings.Trim(rg.profile.SecChUaBitness, "\"")
		}
	} else if rg.config != nil && rg.config.EvadeClientHintsDeep {
		// Fallback to Phase 75 logic if deep evasion is off
		fullBrands := []map[string]interface{}{}
		for _, b := range brands {
			name := b["brand"].(string)
			v := b["version"].(string)
			fullV := fmt.Sprintf("%s.0.6998.77", v)
			fullBrands = append(fullBrands, map[string]interface{}{
				"brand":   name,
				"version": fullV,
			})
		}
		uaData["fullVersionList"] = fullBrands

		arch := "x86"
		if strings.Contains(strings.ToLower(rg.profile.UserAgent), "arm") ||
			(strings.Contains(strings.ToLower(rg.profile.UserAgent), "macintosh") && rg.profile.Platform == "macos") {
			arch = "arm"
		}
		uaData["architecture"] = arch
		uaData["bitness"] = "64"
	} else if rg.config != nil && rg.config.ForceDetections {
		// Simulate mismatch: JS returns a different version than headers
		uaData["fullVersionList"] = []map[string]interface{}{
			{"brand": "Google Chrome", "version": "99.9.9.9"},
		}
		uaData["architecture"] = "pdp-11"
		uaData["bitness"] = "16"
	}

	return uaData
}
