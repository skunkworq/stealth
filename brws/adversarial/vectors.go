// Package adversarial provides detection vectors and fingerprinting analysis.
package adversarial

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/stealth/brwslab/brws/constants"
	"github.com/stealth/brwslab/brws/types"
)

// VectorCategory represents the category of a detection vector.
type VectorCategory string

const (
	// VectorTLS is the TLS fingerprinting category.
	VectorTLS VectorCategory = "tls"
	// VectorHTTP is the HTTP fingerprinting category.
	VectorHTTP VectorCategory = "http"
	// VectorHTTP2 is the HTTP/2 fingerprinting category.
	VectorHTTP2 VectorCategory = "http2"
	// VectorBehavioral is the behavioral fingerprinting category.
	VectorBehavioral VectorCategory = "behavioral"
	// VectorWebGL is the WebGL fingerprinting category.
	VectorWebGL VectorCategory = "webgl"
	// VectorCanvas is the canvas fingerprinting category.
	VectorCanvas VectorCategory = "canvas"
	// VectorFont is the font fingerprinting category.
	VectorFont VectorCategory = "font"
	// VectorScreen is the screen fingerprinting category.
	VectorScreen VectorCategory = "screen"
	// VectorNavigator is the navigator fingerprinting category.
	VectorNavigator VectorCategory = "navigator"
	// VectorTiming is the timing fingerprinting category.
	VectorTiming VectorCategory = "timing"
	// VectorPlugin is the plugin fingerprinting category.
	VectorPlugin VectorCategory = "plugin"
	// VectorWebRTC is the WebRTC fingerprinting category.
	VectorWebRTC VectorCategory = "webrtc"
	// VectorIsomorphic is the cross-vector consistency category.
	VectorIsomorphic VectorCategory = "isomorphic"
	// VectorAudio is the AudioContext fingerprinting category.
	VectorAudio VectorCategory = "audio"
	// VectorAutomation is the automation tool detection category.
	VectorAutomation VectorCategory = "automation"
	// VectorHeadless is the headless browser detection category.
	VectorHeadless VectorCategory = "headless"
	// VectorFingerprintCoverage detects Chrome Client Hints with zero JS fingerprint data.
	VectorFingerprintCoverage VectorCategory = "fingerprint_coverage"
	// VectorCrossVector detects temporal/spatial inconsistencies across independent vectors.
	VectorCrossVector VectorCategory = "cross_vector"
)

// FingerprintVector represents a single fingerprinting detection vector.
type FingerprintVector struct {
	Category    VectorCategory     `json:"category"`
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Severity    float64            `json:"severity"`
	Patterns    []VectorPattern    `json:"patterns"`
	Thresholds  map[string]float64 `json:"thresholds"`
	Checks      []VectorCheck      `json:"checks"`
}

// VectorPattern defines a pattern to match in a detection vector.
type VectorPattern struct {
	Name      string  `json:"name"`
	Pattern   string  `json:"pattern"`
	Weight    float64 `json:"weight"`
	MatchType string  `json:"match_type"` // exact, regex, contains
}

// VectorCheck defines a single check within a detection vector.
type VectorCheck struct {
	Name     string      `json:"name"`
	Field    string      `json:"field"`
	Operator string      `json:"operator"` // eq, neq, gt, lt, contains, regex
	Value    interface{} `json:"value"`
	Weight   float64     `json:"weight"`
	Message  string      `json:"message"`
}

// VectorResult contains the results of a vector analysis.
type VectorResult struct {
	Vector     string            `json:"vector"`
	Category   VectorCategory    `json:"category"`
	Detected   bool              `json:"detected"`
	Score      float64           `json:"score"`
	Indicators []VectorIndicator `json:"indicators"`
}

// VectorIndicator represents a single detection indicator.
type VectorIndicator struct {
	Check   string  `json:"check"`
	Message string  `json:"message"`
	Weight  float64 `json:"weight"`
	Field   string  `json:"field"`
	Value   string  `json:"value"`
}

// VectorMap manages multiple detection vectors and their results.
type VectorMap struct {
	mu        sync.RWMutex
	vectors   map[string]*FingerprintVector
	results   []VectorResult
	baselines map[VectorCategory]*BaselineProfile
}

// BaselineProfile represents a baseline profile for fingerprint comparison.
type BaselineProfile struct {
	Category  VectorCategory     `json:"category"`
	TLS       *TLSBaseline       `json:"tls,omitempty"`
	HTTP      *HTTPBaseline      `json:"http,omitempty"`
	HTTP2     *HTTP2Baseline     `json:"http2,omitempty"`
	Navigator *NavigatorBaseline `json:"navigator,omitempty"`
	Screen    *ScreenBaseline    `json:"screen,omitempty"`
	Timing    *TimingBaseline    `json:"timing,omitempty"`
}

// TLSBaseline represents TLS-specific baseline data.
type TLSBaseline struct {
	JA4             string   `json:"ja4"`
	Version         string   `json:"version"`
	CipherSuites    []string `json:"cipher_suites"`
	Extensions      []string `json:"extensions"`
	SupportedGroups []string `json:"supported_groups"`
	SignatureAlgs   []string `json:"signature_algs"`
	ALPN            []string `json:"alpn"`
	HasGREASE       bool     `json:"has_grease"`
	HasALPS         bool     `json:"has_alps"`
}

// HTTPBaseline represents HTTP-specific baseline data.
type HTTPBaseline struct {
	UserAgent              string   `json:"user_agent"`
	Accept                 string   `json:"accept"`
	AcceptLanguage         string   `json:"accept_language"`
	AcceptEncoding         string   `json:"accept_encoding"`
	HeaderOrder            []string `json:"header_order"`
	SecCHUA                string   `json:"sec_ch_ua"`
	SecCHUAPlatform        string   `json:"sec_ch_ua_platform"`
	SecCHUAMobile          string   `json:"sec_ch_ua_mobile"`
	SecCHUAFullVersion     string   `json:"sec_ch_ua_full_version"`
	SecChUaArch            string   `json:"sec_ch_ua_arch"`
	SecChUaBitness         string   `json:"sec_ch_ua_bitness"`
	SecChUaModel           string   `json:"sec_ch_ua_model"`
	SecChUaPlatformVersion string   `json:"sec_ch_ua_platform_version"`
	SecChUaWow64           string   `json:"sec_ch_ua_wow64"`
}

// HTTP2Baseline represents HTTP/2-specific baseline data.
type HTTP2Baseline struct {
	Settings          map[string]uint32 `json:"settings"`
	SettingOrder      []string          `json:"setting_order"`
	UsesPseudoHeaders bool              `json:"uses_pseudo_headers"`
	PriorityWeight    bool              `json:"priority_weight"`
}

// NavigatorBaseline represents navigator-specific baseline data.
type NavigatorBaseline struct {
	UserAgent           string   `json:"user_agent"`
	Platform            string   `json:"platform"`
	Vendor              string   `json:"vendor"`
	Language            string   `json:"language"`
	Languages           []string `json:"languages"`
	HardwareConcurrency int      `json:"hardware_concurrency"`
	DeviceMemory        int      `json:"device_memory"`
	MaxTouchPoints      int      `json:"max_touch_points"`
	CookieEnabled       bool     `json:"cookie_enabled"`
	DoNotTrack          string   `json:"do_not_track"`
	PDFViewerEnabled    bool     `json:"pdf_viewer_enabled"`
	Webdriver           bool     `json:"webdriver"`
	Plugins             []string `json:"plugins"`
}

// ScreenBaseline represents screen-specific baseline data.
type ScreenBaseline struct {
	Width       int     `json:"width"`
	Height      int     `json:"height"`
	AvailWidth  int     `json:"avail_width"`
	AvailHeight int     `json:"avail_height"`
	ColorDepth  int     `json:"color_depth"`
	PixelRatio  float64 `json:"pixel_ratio"`
}

// TimingBaseline represents timing-specific baseline data.
type TimingBaseline struct {
	NavigationStart       int `json:"navigation_start"`
	UnloadEventStart      int `json:"unload_event_start"`
	RedirectStart         int `json:"redirect_start"`
	RedirectEnd           int `json:"redirect_end"`
	FetchStart            int `json:"fetch_start"`
	DomainLookupStart     int `json:"domain_lookup_start"`
	ConnectStart          int `json:"connect_start"`
	SecureConnectionStart int `json:"secure_connection_start"`
	RequestStart          int `json:"request_start"`
	ResponseStart         int `json:"response_start"`
	TransferSize          int `json:"transfer_size"`
	EncodedBodySize       int `json:"encoded_body_size"`
	DecodedBodySize       int `json:"decoded_body_size"`
	TTFB                  int `json:"ttfb"`
	LoadEventEnd          int `json:"load_event_end"`
}

// NewVectorMap creates a new VectorMap with default vectors initialized.
func NewVectorMap() *VectorMap {
	vm := &VectorMap{
		vectors:   make(map[string]*FingerprintVector),
		results:   make([]VectorResult, 0),
		baselines: make(map[VectorCategory]*BaselineProfile),
	}
	vm.initVectors()
	return vm
}

func (vm *VectorMap) initVectors() {
	vm.vectors[string(VectorTLS)] = &FingerprintVector{
		Category:    VectorTLS,
		Name:        "TLS Fingerprint",
		Description: "Analyzes TLS ClientHello for non-browser patterns",
		Severity:    0.8,
		Patterns: []VectorPattern{
			{Name: "chrome_tls_signature", Pattern: `ecdsa_secp256r1_sha256`, Weight: -0.1, MatchType: "contains"},
			{Name: "unusual_version", Pattern: "0303", Weight: 0.3, MatchType: "exact"},
			{Name: "missing_chacha", Pattern: "chacha20", Weight: 0.1, MatchType: "missing"},
			{Name: "suspicious_order", Pattern: "cipher_order", Weight: 0.2, MatchType: "custom"},
		},
		Thresholds: map[string]float64{
			"min_ciphers":      10,
			"min_extensions":   8,
			"max_grease_ratio": constants.DefaultGreaseRatio,
		},
		Checks: []VectorCheck{
			{Name: "cipher_count", Field: "cipher_count", Operator: "lt", Value: 10, Weight: 0.3, Message: "Too few cipher suites"},
			{Name: "extension_count", Field: "extension_count", Operator: "lt", Value: 8, Weight: 0.3, Message: "Too few extensions"},
			{Name: "no_alpn", Field: "alpn", Operator: "eq", Value: "", Weight: 0.2, Message: "Missing ALPN"},
			{Name: "no_grease", Field: "has_grease", Operator: "eq", Value: false, Weight: 0.1, Message: "No GREASE values"},
		},
	}

	vm.vectors[string(VectorHTTP)] = &FingerprintVector{
		Category:    VectorHTTP,
		Name:        "HTTP Fingerprint",
		Description: "Analyzes HTTP headers for bot detection",
		Severity:    0.7,
		Patterns: []VectorPattern{
			{Name: "missing_ua", Pattern: "User-Agent", Weight: 0.5, MatchType: "missing"},
			{Name: "suspicious_ua", Pattern: "(curl|wget|python|scrapy|bot|headless)", Weight: 0.5, MatchType: "regex"},
			{Name: "inconsistent_ch", Pattern: "Sec-Ch-Ua.*Platform", Weight: 0.3, MatchType: "custom"},
			{Name: "missing_accept", Pattern: "Accept", Weight: 0.3, MatchType: "missing"},
		},
		Thresholds: map[string]float64{
			"min_headers":      8,
			"max_duplicate_ws": 0,
		},
		Checks: []VectorCheck{
			{Name: "header_count", Field: "header_count", Operator: "lt", Value: 8, Weight: 0.3, Message: "Too few headers"},
			{Name: "missing_ua", Field: "user_agent", Operator: "eq", Value: "", Weight: 0.5, Message: "Missing User-Agent"},
			{Name: "missing_accept", Field: "accept", Operator: "eq", Value: "", Weight: 0.3, Message: "Missing Accept header"},
			{Name: "missing_accept_lang", Field: "accept_language", Operator: "eq", Value: "", Weight: 0.2, Message: "Missing Accept-Language"},
			{Name: "client_hints", Field: "has_client_hints", Operator: "eq", Value: false, Weight: 0.3, Message: "Missing Client Hints"},
		},
	}

	vm.vectors[string(VectorHTTP2)] = &FingerprintVector{
		Category:    VectorHTTP2,
		Name:        "HTTP/2 Fingerprint",
		Description: "Analyzes HTTP/2 connection patterns",
		Severity:    0.6,
		Patterns: []VectorPattern{
			{Name: "no_settings", Pattern: "SETTINGS", Weight: 0.4, MatchType: "missing"},
			{Name: "invalid_settings", Pattern: "settings", Weight: 0.3, MatchType: "custom"},
		},
		Thresholds: map[string]float64{
			"min_settings": 4,
		},
		Checks: []VectorCheck{
			{Name: "settings_count", Field: "settings_count", Operator: "lt", Value: 4, Weight: 0.4, Message: "Too few HTTP/2 settings"},
		},
	}

	vm.vectors[string(VectorBehavioral)] = &FingerprintVector{
		Category:    VectorBehavioral,
		Name:        "Behavioral Fingerprint",
		Description: "Analyzes user interaction patterns",
		Severity:    0.9,
		Patterns: []VectorPattern{
			{Name: "perfect_mouse", Pattern: "stddev=0", Weight: 0.4, MatchType: "contains"},
			{Name: "instant_scroll", Pattern: "scroll_time<50", Weight: 0.3, MatchType: "custom"},
			{Name: "mechanical_typing", Pattern: "keystroke_interval", Weight: 0.3, MatchType: "custom"},
		},
		Thresholds: map[string]float64{
			"min_mouse_events":  5,
			"min_scroll_events": 2,
			"max_mouse_speed":   2000,
			"min_typing_events": 5,
		},
		Checks: []VectorCheck{
			{Name: "mouse_events", Field: "mouse_events", Operator: "lt", Value: 5, Weight: 0.3, Message: "Too few mouse events"},
			{Name: "scroll_events", Field: "scroll_events", Operator: "lt", Value: 2, Weight: 0.2, Message: "Too few scroll events"},
			{Name: "mouse_variance", Field: "mouse_stddev", Operator: "eq", Value: 0, Weight: 0.4, Message: "Unnatural mouse movement"},
			{Name: "typing_pattern", Field: "typing_stddev", Operator: "eq", Value: 0, Weight: 0.3, Message: "Unnatural typing pattern"},
		},
	}

	vm.vectors[string(VectorNavigator)] = &FingerprintVector{
		Category:    VectorNavigator,
		Name:        "Navigator Fingerprint",
		Description: "Analyzes navigator object properties",
		Severity:    0.8,
		Patterns: []VectorPattern{
			{Name: "webdriver", Pattern: "webdriver", Weight: 0.5, MatchType: "contains"},
			{Name: "automation", Pattern: "automation", Weight: 0.5, MatchType: "contains"},
			{Name: "missing_props", Pattern: "navigator_props", Weight: 0.3, MatchType: "custom"},
		},
		Thresholds: map[string]float64{
			"min_props": 15,
		},
		Checks: []VectorCheck{
			{Name: "webdriver", Field: "webdriver", Operator: "eq", Value: true, Weight: 0.6, Message: "webdriver property detected"},
			{Name: "prop_count", Field: "prop_count", Operator: "lt", Value: 15, Weight: 0.3, Message: "Too few navigator properties"},
			{Name: "chrome_runtime", Field: "chrome_runtime", Operator: "exists", Value: false, Weight: 0.2, Message: "Missing Chrome runtime"},
		},
	}

	vm.vectors[string(VectorTiming)] = &FingerprintVector{
		Category:    VectorTiming,
		Name:        "Timing Fingerprint",
		Description: "Analyzes timing patterns",
		Severity:    0.5,
		Patterns: []VectorPattern{
			{Name: "instant_load", Pattern: "load_time=0", Weight: 0.4, MatchType: "contains"},
			{Name: "perfect_timing", Pattern: "timing", Weight: 0.2, MatchType: "custom"},
		},
		Thresholds: map[string]float64{
			"min_ttfb": 10,
		},
		Checks: []VectorCheck{
			{Name: "ttfb", Field: "ttfb", Operator: "eq", Value: 0, Weight: 0.4, Message: "Zero TTFB"},
			{Name: "navigation_timing", Field: "has_nav_timing", Operator: "eq", Value: false, Weight: 0.3, Message: "Missing Navigation Timing"},
		},
	}

	vm.vectors[string(VectorWebRTC)] = &FingerprintVector{
		Category:    VectorWebRTC,
		Name:        "WebRTC Fingerprint",
		Description: "Detects WebRTC-based IP leak vectors and spoofing artifacts",
		Severity:    0.9,
		Patterns: []VectorPattern{
			{Name: "rtc_disabled", Pattern: "RTCPeerConnection", Weight: 0.3, MatchType: "missing"},
			{Name: "rtc_no_candidates", Pattern: "icecandidate", Weight: 0.3, MatchType: "missing"},
			{Name: "rtc_ip_mismatch", Pattern: "ip_mismatch", Weight: 0.5, MatchType: "custom"},
		},
		Thresholds: map[string]float64{
			"max_ip_mismatch_score": 0.5,
		},
		Checks: []VectorCheck{
			{Name: "rtc_disabled", Field: "rtc_available", Operator: "eq", Value: false, Weight: 0.3, Message: "WebRTC completely disabled — may flag as non-standard browser"},
			{Name: "rtc_no_candidates", Field: "ice_candidate_count", Operator: "eq", Value: 0, Weight: 0.3, Message: "No ICE candidates generated"},
			{Name: "rtc_ip_mismatch", Field: "ip_mismatch", Operator: "eq", Value: true, Weight: 0.5, Message: "WebRTC IP does not match request source IP"},
			{Name: "rtc_proxy_constructor", Field: "constructor_proxied", Operator: "eq", Value: true, Weight: 0.2, Message: "RTCPeerConnection constructor appears proxied"},
		},
	}

	vm.vectors[string(VectorCanvas)] = &FingerprintVector{
		Category:    VectorCanvas,
		Name:        "Canvas Fingerprint",
		Description: "Detects canvas fingerprinting anomalies and spoofing",
		Severity:    0.7,
		Patterns: []VectorPattern{
			{Name: "canvas_inconsistent", Pattern: "multi_render_mismatch", Weight: 0.4, MatchType: "custom"},
			{Name: "canvas_prototype_modified", Pattern: "prototype_modified", Weight: 0.3, MatchType: "custom"},
			{Name: "canvas_software_renderer", Pattern: "SwiftShader", Weight: 0.3, MatchType: "contains"},
		},
		Thresholds: map[string]float64{
			"max_inconsistency_score": 0.5,
		},
		Checks: []VectorCheck{
			{Name: "canvas_inconsistent", Field: "multi_render_consistent", Operator: "eq", Value: false, Weight: 0.4, Message: "Canvas renders inconsistently across calls (noise injection detected)"},
			{Name: "canvas_prototype_modified", Field: "prototype_intact", Operator: "eq", Value: false, Weight: 0.3, Message: "Canvas prototype methods have been modified"},
			{Name: "canvas_software_renderer", Field: "renderer", Operator: "contains", Value: "SwiftShader", Weight: 0.3, Message: "Software renderer detected (common in headless)"},
		},
	}
}

// RegisterVector registers a new fingerprint vector.
func (vm *VectorMap) RegisterVector(vec *FingerprintVector) {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	vm.vectors[string(vec.Category)] = vec
}

// GetVector returns the fingerprint vector for the given category.
func (vm *VectorMap) GetVector(category VectorCategory) *FingerprintVector {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	return vm.vectors[string(category)]
}

// GetAllVectors returns all registered fingerprint vectors.
func (vm *VectorMap) GetAllVectors() []*FingerprintVector {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	vecs := make([]*FingerprintVector, 0, len(vm.vectors))
	for _, v := range vm.vectors {
		vecs = append(vecs, v)
	}
	return vecs
}

// AnalyzeTLS analyzes a TLS ClientHello using registered vectors.
func (vm *VectorMap) AnalyzeTLS(ch *tls.ClientHelloInfo) *VectorResult {
	vm.mu.RLock()
	vec := vm.vectors[string(VectorTLS)]
	vm.mu.RUnlock()

	result := &VectorResult{
		Vector:     vec.Name,
		Category:   vec.Category,
		Detected:   false,
		Score:      0,
		Indicators: make([]VectorIndicator, 0),
	}

	cipherCount := len(ch.CipherSuites)
	if cipherCount < 10 {
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "cipher_count",
			Message: fmt.Sprintf("Too few cipher suites: %d", cipherCount),
			Weight:  0.3,
			Field:   "cipher_count",
			Value:   strconv.Itoa(cipherCount),
		})
		result.Score += 0.3
	}

	hasGREASE := false
	for _, c := range ch.CipherSuites {
		if isGREASE(c) {
			hasGREASE = true
			break
		}
	}
	if !hasGREASE {
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "no_grease",
			Message: "No GREASE values in cipher suites",
			Weight:  0.1,
			Field:   "has_grease",
			Value:   "false",
		})
		result.Score += 0.1
	}

	// Skip ALPN check - requires lower-level TLS inspection

	result.Score = minFloat(1.0, result.Score)
	result.Detected = result.Score > 0.3

	return result
}

// AnalyzeHTTP analyzes an HTTP request using registered vectors.
func (vm *VectorMap) AnalyzeHTTP(req *http.Request) *VectorResult {
	vm.mu.RLock()
	vec := vm.vectors[string(VectorHTTP)]
	vm.mu.RUnlock()

	result := &VectorResult{
		Vector:     vec.Name,
		Category:   vec.Category,
		Detected:   false,
		Score:      0,
		Indicators: make([]VectorIndicator, 0),
	}

	ua := req.Header.Get("User-Agent")
	if ua == "" {
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "missing_ua",
			Message: "Missing User-Agent header",
			Weight:  0.5,
			Field:   "user_agent",
			Value:   "",
		})
		result.Score += 0.5
	} else {
		uaLower := strings.ToLower(ua)
		suspicious := []string{"curl", "wget", "python", "scrapy", "bot", "spider", "headless", "selenium", "automation"}
		for _, s := range suspicious {
			if strings.Contains(uaLower, s) {
				result.Indicators = append(result.Indicators, VectorIndicator{
					Check:   "suspicious_ua",
					Message: fmt.Sprintf("Suspicious User-Agent: contains '%s'", s),
					Weight:  0.5,
					Field:   "user_agent",
					Value:   ua,
				})
				result.Score += 0.5
				break
			}
		}
	}

	if req.Header.Get("Accept") == "" {
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "missing_accept",
			Message: "Missing Accept header",
			Weight:  0.3,
			Field:   "accept",
			Value:   "",
		})
		result.Score += 0.3
	}

	if req.Header.Get("Accept-Language") == "" {
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "missing_accept_lang",
			Message: "Missing Accept-Language header",
			Weight:  0.2,
			Field:   "accept_language",
			Value:   "",
		})
		result.Score += 0.2
	}

	chUa := req.Header.Get("Sec-Ch-Ua")
	chPlatform := req.Header.Get("Sec-Ch-Ua-Platform")
	if chUa == "" || chPlatform == "" {
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "client_hints",
			Message: "Missing Client Hints",
			Weight:  0.3,
			Field:   "has_client_hints",
			Value:   "false",
		})
		result.Score += 0.3
	} else if !clientHintsConsistent(chUa, chPlatform) {
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "inconsistent_ch",
			Message: "Inconsistent Client Hints (Sec-Ch-Ua vs Sec-Ch-Ua-Platform)",
			Weight:  0.3,
			Field:   "sec_ch_ua_platform",
			Value:   chPlatform,
		})
		result.Score += 0.3
	}

	result.Score = minFloat(1.0, result.Score)
	result.Detected = result.Score > 0.3

	return result
}

// AnalyzeBehavioral analyzes behavioral events using registered vectors.
func (vm *VectorMap) AnalyzeBehavioral(events *BehavioralEvents) *VectorResult {
	vm.mu.RLock()
	vec := vm.vectors[string(VectorBehavioral)]
	vm.mu.RUnlock()

	result := &VectorResult{
		Vector:     vec.Name,
		Category:   vec.Category,
		Detected:   false,
		Score:      0,
		Indicators: make([]VectorIndicator, 0),
	}

	if events.MouseEvents < 5 {
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "mouse_events",
			Message: fmt.Sprintf("Too few mouse events: %d", events.MouseEvents),
			Weight:  0.3,
			Field:   "mouse_events",
			Value:   strconv.Itoa(events.MouseEvents),
		})
		result.Score += 0.3
	}

	if events.ScrollEvents < 2 {
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "scroll_events",
			Message: fmt.Sprintf("Too few scroll events: %d", events.ScrollEvents),
			Weight:  0.2,
			Field:   "scroll_events",
			Value:   strconv.Itoa(events.ScrollEvents),
		})
		result.Score += 0.2
	}

	if events.MouseStdDev == 0 && events.MouseEvents > 10 {
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "mouse_variance",
			Message: "Unnatural mouse movement (zero variance)",
			Weight:  0.4,
			Field:   "mouse_stddev",
			Value:   "0",
		})
		result.Score += 0.4
	}

	if events.TypingStdDev == 0 && events.TypingEvents > 10 {
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "typing_pattern",
			Message: "Unnatural typing pattern (zero variance)",
			Weight:  0.3,
			Field:   "typing_stddev",
			Value:   "0",
		})
		result.Score += 0.3
	}

	result.Score = minFloat(1.0, result.Score)
	result.Detected = result.Score > 0.3

	return result
}

// AnalyzeNavigator analyzes navigator data using registered vectors.
func (vm *VectorMap) AnalyzeNavigator(nav *NavigatorData) *VectorResult {
	vm.mu.RLock()
	vec := vm.vectors[string(VectorNavigator)]
	vm.mu.RUnlock()

	result := &VectorResult{
		Vector:     vec.Name,
		Category:   vec.Category,
		Detected:   false,
		Score:      0,
		Indicators: make([]VectorIndicator, 0),
	}

	if nav.Webdriver {
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "webdriver",
			Message: "webdriver property is true",
			Weight:  0.6,
			Field:   "webdriver",
			Value:   "true",
		})
		result.Score += 0.6
	}

	if nav.PropCount < 15 {
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "prop_count",
			Message: fmt.Sprintf("Too few navigator properties: %d", nav.PropCount),
			Weight:  0.3,
			Field:   "prop_count",
			Value:   strconv.Itoa(nav.PropCount),
		})
		result.Score += 0.3
	}

	result.Score = minFloat(1.0, result.Score)
	result.Detected = result.Score > 0.3

	return result
}

// AnalyzeTiming analyzes timing data using registered vectors.
func (vm *VectorMap) AnalyzeTiming(timing *TimingData) *VectorResult {
	vm.mu.RLock()
	vec := vm.vectors[string(VectorTiming)]
	vm.mu.RUnlock()

	result := &VectorResult{
		Vector:     vec.Name,
		Category:   vec.Category,
		Detected:   false,
		Score:      0,
		Indicators: make([]VectorIndicator, 0),
	}

	if timing.TTFB == 0 && timing.TransferSize > 1000 {
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "ttfb",
			Message: "Zero TTFB with non-zero transfer size",
			Weight:  0.4,
			Field:   "ttfb",
			Value:   "0",
		})
		result.Score += 0.4
	}

	if !timing.HasNavTiming {
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "navigation_timing",
			Message: "Missing Navigation Timing API",
			Weight:  0.3,
			Field:   "has_nav_timing",
			Value:   "false",
		})
		result.Score += 0.3
	}

	result.Score = minFloat(1.0, result.Score)
	result.Detected = result.Score > 0.3

	return result
}

// AnalyzeComplete performs a complete analysis using all registered vectors.
func (vm *VectorMap) AnalyzeComplete(fp *types.CompleteFingerprint) []VectorResult {
	results := make([]VectorResult, 0)

	if fp.TLS != nil {
		tlsResult := vm.analyzeTLSFingerprint(fp.TLS)
		results = append(results, *tlsResult)
	}

	if fp.HTTP != nil {
		httpResult := vm.analyzeHTTPFingerprint(fp.HTTP)
		results = append(results, *httpResult)
	}

	return results
}

func (vm *VectorMap) analyzeTLSFingerprint(tls *types.TLSFingerprint) *VectorResult {
	result := &VectorResult{
		Vector:     "TLS Fingerprint",
		Category:   VectorTLS,
		Detected:   false,
		Score:      0,
		Indicators: make([]VectorIndicator, 0),
	}

	if tls.JA4 == "" || tls.JA4 == "unknown" {
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "invalid_ja4",
			Message: "Invalid or missing JA4",
			Weight:  0.4,
			Field:   "ja4",
			Value:   tls.JA4,
		})
		result.Score += 0.4
	}

	result.Score = minFloat(1.0, result.Score)
	result.Detected = result.Score > 0.3

	return result
}

func (vm *VectorMap) analyzeHTTPFingerprint(http *types.HTTPFingerprint) *VectorResult {
	result := &VectorResult{
		Vector:     "HTTP Fingerprint",
		Category:   VectorHTTP,
		Detected:   false,
		Score:      0,
		Indicators: make([]VectorIndicator, 0),
	}

	ua := http.UserAgent
	if ua == "" {
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "missing_ua",
			Message: "Missing User-Agent",
			Weight:  0.5,
			Field:   "user_agent",
			Value:   "",
		})
		result.Score += 0.5
	} else {
		uaLower := strings.ToLower(ua)
		if matched, _ := regexp.MatchString("(curl|wget|python|scrapy|bot|headless)", uaLower); matched {
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "suspicious_ua",
				Message: "Suspicious User-Agent detected",
				Weight:  0.5,
				Field:   "user_agent",
				Value:   ua,
			})
			result.Score += 0.5
		}
	}

	result.Score = minFloat(1.0, result.Score)
	result.Detected = result.Score > 0.3

	return result
}

// AddResult adds a result to the vector map.
func (vm *VectorMap) AddResult(result VectorResult) {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	vm.results = append(vm.results, result)
}

// GetResults returns all stored results.
func (vm *VectorMap) GetResults() []VectorResult {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	return vm.results
}

// GetResultsByCategory returns results filtered by category.
func (vm *VectorMap) GetResultsByCategory(category VectorCategory) []VectorResult {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	results := make([]VectorResult, 0)
	for _, r := range vm.results {
		if r.Category == category {
			results = append(results, r)
		}
	}
	return results
}

// LoadBaseline loads a baseline profile for the given category.
func (vm *VectorMap) LoadBaseline(category VectorCategory, profile *BaselineProfile) {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	vm.baselines[category] = profile
}

// GetBaseline returns the baseline profile for the given category.
func (vm *VectorMap) GetBaseline(category VectorCategory) *BaselineProfile {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	return vm.baselines[category]
}

// CompareToBaseline compares a fingerprint against the baseline for the category.
func (vm *VectorMap) CompareToBaseline(category VectorCategory, fp interface{}) *VectorResult {
	vm.mu.RLock()
	baseline := vm.baselines[category]
	vm.mu.RUnlock()

	result := &VectorResult{
		Category:   category,
		Detected:   false,
		Score:      0,
		Indicators: make([]VectorIndicator, 0),
	}

	if baseline == nil {
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "no_baseline",
			Message: "No baseline available",
			Weight:  0.5,
		})
		result.Score = 0.5
		return result
	}

	switch category {
	case VectorTLS:
		if tls, ok := fp.(*types.TLSFingerprint); ok {
			if baseline.TLS != nil {
				if tls.JA4 != baseline.TLS.JA4 {
					result.Indicators = append(result.Indicators, VectorIndicator{
						Check:   "ja4_mismatch",
						Message: fmt.Sprintf("JA4 mismatch: got %s, expected %s", tls.JA4, baseline.TLS.JA4),
						Weight:  0.4,
						Field:   "ja4",
						Value:   tls.JA4,
					})
					result.Score += 0.4
				}
			}
		}
	case VectorHTTP:
		if http, ok := fp.(*types.HTTPFingerprint); ok {
			if baseline.HTTP != nil {
				if http.UserAgent != baseline.HTTP.UserAgent {
					result.Indicators = append(result.Indicators, VectorIndicator{
						Check:   "ua_mismatch",
						Message: "User-Agent mismatch",
						Weight:  0.3,
						Field:   "user_agent",
						Value:   http.UserAgent,
					})
					result.Score += 0.3
				}
			}
		}
	case VectorHTTP2, VectorBehavioral, VectorWebGL, VectorCanvas, VectorFont, VectorScreen, VectorNavigator, VectorTiming, VectorPlugin, VectorWebRTC:
		// Not yet implemented
	}

	result.Score = minFloat(1.0, result.Score)
	result.Detected = result.Score > 0.3

	return result
}

// BehavioralEvents represents behavioral interaction data.
type BehavioralEvents struct {
	MouseEvents   int
	ScrollEvents  int
	TypingEvents  int
	MouseAvgSpeed float64
	MouseStdDev   float64
	TypingStdDev  float64
}

// NavigatorData represents navigator API data.
type NavigatorData struct {
	Webdriver           bool
	PropCount           int
	Platform            string
	Vendor              string
	Language            string
	Languages           []string
	HardwareConcurrency int
	DeviceMemory        int
}

// TimingData represents performance timing data.
type TimingData struct {
	TTFB         int
	TransferSize int
	HasNavTiming bool
	LoadTime     int
}

// DetectWithVectors detects automation using all registered vectors.
func DetectWithVectors(fp *types.CompleteFingerprint) ([]VectorResult, bool) {
	vm := NewVectorMap()
	results := vm.AnalyzeComplete(fp)

	var totalScore float64
	for _, r := range results {
		totalScore += r.Score
	}

	avgScore := totalScore / float64(len(results))
	detected := avgScore > 0.3

	return results, detected
}

// GenerateReport generates a text report of all vector analysis results.
func (vm *VectorMap) GenerateReport() string {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	var b strings.Builder
	b.WriteString("=== Fingerprint Vector Analysis Report ===\n\n")

	categories := []VectorCategory{VectorTLS, VectorHTTP, VectorHTTP2, VectorBehavioral, VectorNavigator, VectorTiming, VectorWebRTC, VectorCanvas}
	for _, cat := range categories {
		vec := vm.vectors[string(cat)]
		if vec == nil {
			continue
		}

		_, _ = fmt.Fprintf(&b, "## %s Vector\n", vec.Name)
		_, _ = fmt.Fprintf(&b, "Description: %s\n", vec.Description)
		_, _ = fmt.Fprintf(&b, "Severity: %.1f\n\n", vec.Severity)

		b.WriteString("Checks:\n")
		for _, check := range vec.Checks {
			_, _ = fmt.Fprintf(&b, "  - %s: %s\n", check.Name, check.Message)
		}

		b.WriteString("\n")
	}

	b.WriteString("## Results Summary\n")
	_, _ = fmt.Fprintf(&b, "Total vectors: %d\n", len(vm.results))

	var detectedCount int
	var totalScore float64
	for _, r := range vm.results {
		if r.Detected {
			detectedCount++
		}
		totalScore += r.Score
	}

	if len(vm.results) > 0 {
		_, _ = fmt.Fprintf(&b, "Detected: %d/%d\n", detectedCount, len(vm.results))
		_, _ = fmt.Fprintf(&b, "Average score: %.2f\n", totalScore/float64(len(vm.results)))
	}

	return b.String()
}

// WebRTCData represents WebRTC fingerprinting data collected from a browser session.
type WebRTCData struct {
	RTCAvailable       bool     `json:"rtc_available"`
	ICECandidateCount  int      `json:"ice_candidate_count"`
	LocalIPs           []string `json:"local_ips"`
	RequestSourceIP    string   `json:"request_source_ip"`
	ConstructorProxied bool     `json:"constructor_proxied"`
	RelayOnly          bool     `json:"relay_only"`
}

// CanvasData represents canvas fingerprinting data collected from a browser session.
type CanvasData struct {
	MultiRenderConsistent bool   `json:"multi_render_consistent"`
	PrototypeIntact       bool   `json:"prototype_intact"`
	Renderer              string `json:"renderer"`
	CanvasHash            string `json:"canvas_hash"`
}

// AnalyzeWebRTC analyzes WebRTC data for leak prevention and spoofing detection.
func (vm *VectorMap) AnalyzeWebRTC(data *WebRTCData) *VectorResult {
	vm.mu.RLock()
	vec := vm.vectors[string(VectorWebRTC)]
	vm.mu.RUnlock()

	result := &VectorResult{
		Vector:     vec.Name,
		Category:   vec.Category,
		Detected:   false,
		Score:      0,
		Indicators: make([]VectorIndicator, 0),
	}

	if !data.RTCAvailable {
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "rtc_disabled",
			Message: "WebRTC completely disabled",
			Weight:  0.3,
			Field:   "rtc_available",
			Value:   "false",
		})
		result.Score += 0.3
	}

	if data.ICECandidateCount == 0 && data.RTCAvailable {
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "rtc_no_candidates",
			Message: "WebRTC enabled but no ICE candidates generated",
			Weight:  0.3,
			Field:   "ice_candidate_count",
			Value:   "0",
		})
		result.Score += 0.3
	}

	// Check for IP mismatch between WebRTC local IPs and request source
	if data.RequestSourceIP != "" && len(data.LocalIPs) > 0 {
		mismatch := true
		for _, ip := range data.LocalIPs {
			if ip == data.RequestSourceIP {
				mismatch = false
				break
			}
		}
		if mismatch {
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "rtc_ip_mismatch",
				Message: "WebRTC local IP does not match request source IP",
				Weight:  0.5,
				Field:   "ip_mismatch",
				Value:   "true",
			})
			result.Score += 0.5
		}
	}

	if data.ConstructorProxied {
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "rtc_proxy_constructor",
			Message: "RTCPeerConnection constructor appears proxied",
			Weight:  0.2,
			Field:   "constructor_proxied",
			Value:   "true",
		})
		result.Score += 0.2
	}

	result.Score = minFloat(1.0, result.Score)
	result.Detected = result.Score > 0.3

	return result
}

// AnalyzeCanvas analyzes canvas fingerprint data for spoofing detection.
func (vm *VectorMap) AnalyzeCanvas(data *CanvasData) *VectorResult {
	vm.mu.RLock()
	vec := vm.vectors[string(VectorCanvas)]
	vm.mu.RUnlock()

	result := &VectorResult{
		Vector:     vec.Name,
		Category:   vec.Category,
		Detected:   false,
		Score:      0,
		Indicators: make([]VectorIndicator, 0),
	}

	if !data.MultiRenderConsistent {
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "canvas_inconsistent",
			Message: "Canvas renders inconsistently across calls (noise injection detected)",
			Weight:  0.4,
			Field:   "multi_render_consistent",
			Value:   "false",
		})
		result.Score += 0.4
	}

	if !data.PrototypeIntact {
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "canvas_prototype_modified",
			Message: "Canvas prototype methods have been modified",
			Weight:  0.3,
			Field:   "prototype_intact",
			Value:   "false",
		})
		result.Score += 0.3
	}

	if strings.Contains(data.Renderer, "SwiftShader") || strings.Contains(data.Renderer, "llvmpipe") {
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "canvas_software_renderer",
			Message: fmt.Sprintf("Software renderer detected: %s", data.Renderer),
			Weight:  0.3,
			Field:   "renderer",
			Value:   data.Renderer,
		})
		result.Score += 0.3
	}

	result.Score = minFloat(1.0, result.Score)
	result.Detected = result.Score > 0.3

	return result
}

// SortHeaderOrder returns headers sorted in a canonical order.
func SortHeaderOrder(headers http.Header) []string {
	order := make([]string, 0, len(headers))

	priority := map[string]int{
		":method":                   0,
		":authority":                1,
		":scheme":                   2,
		":path":                     3,
		"host":                      4,
		"content-type":              5,
		"content-length":            6,
		"user-agent":                7,
		"accept":                    8,
		"accept-language":           9,
		"accept-encoding":           10,
		"sec-ch-ua":                 11,
		"sec-ch-ua-mobile":          12,
		"sec-ch-ua-platform":        13,
		"sec-fetch-dest":            14,
		"sec-fetch-mode":            15,
		"sec-fetch-site":            16,
		"sec-fetch-user":            17,
		"upgrade-insecure-requests": 18,
	}

	for k := range headers {
		order = append(order, k)
	}

	sort.Slice(order, func(i, j int) bool {
		ki := strings.ToLower(order[i])
		kj := strings.ToLower(order[j])
		pi, okI := priority[ki]
		pj, okJ := priority[kj]

		if okI && okJ {
			return pi < pj
		}
		if okI {
			return true
		}
		if okJ {
			return false
		}
		return ki < kj
	})

	return order
}
