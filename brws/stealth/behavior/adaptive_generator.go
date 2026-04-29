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

	"github.com/skunkworq/stealth/brws/stealth/challenge"
	"github.com/skunkworq/stealth/brws/core/constants"
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
	lastReport *challenge.DetectionReport
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

	seed := config.Seed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}

	//nolint:gosec
	rng := rand.New(rand.NewSource(seed + 2))

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
func (ag *AdaptiveRequestGenerator) ApplyFeedback(report *challenge.DetectionReport) {
	ag.mu.Lock()
	defer ag.mu.Unlock()

	ag.lastReport = report

	firedChecks := report.FiredCheckNames()
	appliedNow := make([]string, 0)

	for _, checkName := range firedChecks {
		baseName := strings.Split(checkName, ":")[0]
		if ag.applied[baseName] {
			continue
		}
		if mutation, ok := ag.mutations[baseName]; ok {
			mutation(ag)
			ag.applied[baseName] = true
			appliedNow = append(appliedNow, baseName)
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
func (ag *AdaptiveRequestGenerator) LastReport() *challenge.DetectionReport {
	ag.mu.Lock()
	defer ag.mu.Unlock()
	return ag.lastReport
}

// GetConfig returns the underlying request generator configuration.
func (ag *AdaptiveRequestGenerator) GetConfig() *RequestGeneratorConfig {
	ag.mu.Lock()
	defer ag.mu.Unlock()
	return ag.config
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
	ag.mutations["mouse_interval_no_clustering"] = mutateAddMouseClustering
	ag.mutations["scroll_delta_no_momentum"] = mutateAddScrollMomentum
	ag.mutations["no_click_deceleration"] = mutateAddClickDeceleration
	ag.mutations["fitts_law_violation"] = mutateEvadeFittsLaw
	ag.mutations["mouse_velocity_lag3_anomaly"] = mutateEvadeMouseVelocityLag3
	ag.mutations["scroll_delta_interval_independence"] = mutateEvadeScrollSpearman
	ag.mutations["mouse_density_during_typing"] = mutateEvadeMouseTypingDensity

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

	// IP Based Checks
	ag.mutations["ip_datacenter"] = mutateSpoofLocalIP
	ag.mutations["ip_botnet"] = mutateSpoofLocalIP
	ag.mutations["ip_known_proxy"] = mutateSpoofLocalIP

	// Phase 20/21: PDF viewer and hardware coherence
	ag.mutations["pdfViewerEnabled_false_modern_browser"] = mutateFixPdfViewer
	ag.mutations["pdf_viewer_disabled"] = mutateFixPdfViewer
	ag.mutations["hardware_coherence_improbable"] = mutateFixHardwareCoherence
	ag.mutations["hardware_coherence_high_ram_low_cores"] = mutateFixHardwareCoherence
	ag.mutations["hardware_coherence_low_ram_high_cores"] = mutateFixHardwareCoherence

	// Phase 22/23: Timing duration and vendor consistency
	ag.mutations["timing_all_zero_duration"] = mutateFixTimingDuration
	ag.mutations["vendor_browser_mismatch"] = mutateFixVendorConsistency

	// Phase 24/25: LoadTimes ordering and audio output latency
	ag.mutations["chrome_loadtimes_ordering_violation"] = mutateFixLoadTimesOrdering
	ag.mutations["chrome_loadtimes_ordering"] = mutateFixLoadTimesOrdering
	ag.mutations["chrome_loadtimes_implausible_duration"] = mutateFixLoadTimesOrdering
	ag.mutations["missing_chrome_loadTimes"] = mutateFixLoadTimesOrdering
	ag.mutations["audio_zero_output_latency"] = mutateFixAudioOutputLatency

	// Phase 26/27: CSI/LoadTimes cross-check and timing URLs
	ag.mutations["csi_loadtimes_timing_mismatch"] = mutateFixCSILoadTimes
	ag.mutations["timing_all_entries_missing_url"] = mutateFixTimingURLs

	// Phase 28/29: Browser mode detection and evasion
	ag.mutations["network_effectivetype_rtt_mismatch"] = mutateFixNetworkCoherence
	ag.mutations["network_effectivetype_downlink_mismatch"] = mutateFixNetworkCoherence
	ag.mutations["missing_notification_permission"] = mutateFixNotificationPermission

	// Phase 30/31: DPR/resolution plausibility and font/nav platform
	ag.mutations["screen_dpr_resolution_improbable"] = mutateFixDPRResolution
	ag.mutations["font_nav_platform_mismatch"] = mutateFixFontPlatform

	// Phase 32: Canvas IDAT Entropy Threshold
	ag.mutations["canvas_idat_high_entropy"] = mutateFixCanvasEntropy

	// Phase 33: Click Dwell Time
	ag.mutations["missing_click_dwell_time"] = mutateEvadeClickDwellTime
	ag.mutations["instant_click_dwell"] = mutateEvadeClickDwellTime

	// Phase 34: WebGL Extension Count
	ag.mutations["insufficient_webgl_extensions"] = mutateFixWebGLCount
	ag.mutations["missing_webgl_extensions"] = mutateFixWebGLCount

	// Phase 35: Screen Taskbar Gap
	ag.mutations["no_taskbar_gap"] = mutateFixScreenHeightGap
	ag.mutations["suspicious_taskbar_gap"] = mutateFixScreenHeightGap

	// Phase 36: WebGL Viewport
	ag.mutations["missing_webgl_viewport_dims"] = mutateFixWebGLViewport

	// Phase 37: Mouse Ease-In
	ag.mutations["mouse_abrupt_start"] = mutateFixMouseEaseIn

	// Phase 38: Improbable Device Memory Limit
	ag.mutations["improbable_device_memory"] = mutateFixDeviceMemoryClamp

	// Phase 39: Missing Connection SaveData
	ag.mutations["missing_connection_saveData"] = mutateFixConnectionSaveData

	// Phase 40: Screen Orientation Mismatch
	ag.mutations["screen_orientation_mismatch"] = mutateFixScreenOrientation

	// Phase 41: Missing Navigator Keyboard
	ag.mutations["missing_navigator_keyboard"] = mutateFixNavigatorKeyboard

	// Phase 42: Improbable Hardware Concurrency
	ag.mutations["improbable_hardware_concurrency"] = mutateFixHardwareConcurrency

	// Phase 43: Non-Quantized Network Quality
	ag.mutations["non_quantized_network_rtt"] = mutateFixNetworkQuantization
	ag.mutations["non_quantized_network_downlink"] = mutateFixNetworkQuantization

	// Phase 44: Non-Quantized DPR
	ag.mutations["non_quantized_dpr"] = mutateFixDPRQuantization

	// Phase 46: Error Stack Trace Consistency
	ag.mutations["error_stack_mismatch"] = mutateFixErrorStackConsistency

	// Phase 47: WebGL Parameter Consistency
	ag.mutations["webgl_parameter_mismatch"] = mutateFixWebGLParameters

	// Phase 48: Language Consistency
	ag.mutations["language_mismatch"] = mutateFixLanguageConsistency

	// Phase 49: Media Query Hover
	ag.mutations["none_media_query_hover"] = mutateFixMediaQueryHover
	ag.mutations["missing_media_query_hover"] = mutateFixMediaQueryHover

	// Phase 3: TLS Fingerprint Validation
	ag.mutations["tls_go_fingerprint: browser_ua_with_go_tls"] = mutateFixTLSFingerprint

	// Phase 50: Hardware-Renderer Coherence
	ag.mutations["hardware_core_mismatch"] = mutateFixHardwareCoherence

	// Phase 51: Isomorphic Interaction & Plugin Hardening
	ag.mutations["pointer_mismatch"] = mutateFixPointerInteraction
	ag.mutations["any_pointer_mismatch"] = mutateFixPointerInteraction
	ag.mutations["suspicious_plugin_filename"] = mutateFixPluginFilenames
	ag.mutations["missing_webgpu"] = mutateFixWebGPU
	ag.mutations["permissions_query_mismatch"] = mutateFixPermissions

	// Phase 53: Audio & Orientation Hardening
	ag.mutations["audio_zero_base_latency"] = mutateFixAudioBaseLatency
	ag.mutations["missing_audio_base_latency"] = mutateFixAudioBaseLatency
	ag.mutations["screen_orientation_mismatch"] = mutateFixScreenOrientation
	ag.mutations["suspicious_battery_status"] = mutateFixBatteryStatus
	ag.mutations["missing_storage_quota"] = mutateFixStorageQuota
	ag.mutations["low_storage_quota"] = mutateFixStorageQuota
	ag.mutations["empty_media_devices"] = mutateFixMediaDevices
	ag.mutations["suspicious_media_device_id"] = mutateFixMediaDevices
	ag.mutations["non_standard_media_device_id_format"] = mutateFixMediaDevices
	ag.mutations["missing_media_device_kind"] = mutateFixMediaDevices
	ag.mutations["missing_webrtc"] = mutateFixWebRTC
	ag.mutations["empty_ice_candidates"] = mutateFixWebRTC
	ag.mutations["suspicious_ice_format"] = mutateFixWebRTC
	ag.mutations["canvas_spatial_inconsistency"] = mutateFixCanvasNoise

	// Phase 58: Modern Navigator
	ag.mutations["missing_navigator_userAgentData"] = mutateFixModernNavigator
	ag.mutations["inconsistent_userAgentData_platform"] = mutateFixModernNavigator
	ag.mutations["inconsistent_mobile_max_touch_points"] = mutateFixModernNavigator
	ag.mutations["missing_navigator_userActivation"] = mutateFixModernNavigator
	ag.mutations["missing_navigator_keyboard"] = mutateFixModernNavigator

	// Phase 59: Modern API Consistency
	ag.mutations["missing_navigator_scheduling"] = mutateFixModernNavigator
	ag.mutations["missing_navigator_locks"] = mutateFixModernNavigator
	ag.mutations["intl_timezone_mismatch"] = mutateFixModernNavigator

	// Phase 60: Memory & Stack Hardening
	ag.mutations["performance_memory_limit_too_low_for_ram"] = mutateFixMemoryAndStack
	ag.mutations["automation_leak_detected"] = mutateFixMemoryAndStack
	ag.mutations["error_stack_mismatch"] = mutateFixMemoryAndStack
	ag.mutations["error_stack_suspiciously_clean"] = mutateFixMemoryAndStack
	ag.mutations["error_stack_missing_async_context"] = mutateFixMemoryAndStack

	// Phase 61: WebAudio & AudioWorklet Hardening
	ag.mutations["missing_audio_worklet"] = mutateFixAudioAPIs
	ag.mutations["audio_max_channel_count_anomaly"] = mutateFixAudioAPIs

	// Phase 62: OffscreenCanvas & WebGL Hardening
	ag.mutations["missing_offscreen_canvas"] = mutateFixGraphicsAPIs
	ag.mutations["missing_webgl_draft_extensions"] = mutateFixGraphicsAPIs

	// Phase 63: Storage & Quota Management Hardening
	ag.mutations["missing_storage_usage"] = mutateFixStorageAPIs
	ag.mutations["low_storage_quota"] = mutateFixStorageAPIs
	ag.mutations["missing_storage_persistence"] = mutateFixStorageAPIs
	ag.mutations["zero_storage_usage"] = mutateFixStorageAPIs

	// Phase 64: Screen.isExtended Detection
	ag.mutations["missing_navigator_vibrate"] = mutateFixNavigatorConnectivity
	ag.mutations["missing_navigator_onLine"] = mutateFixNavigatorConnectivity
	ag.mutations["missing_navigator_bluetooth"] = mutateFixNavigatorHardware
	ag.mutations["missing_navigator_usb"] = mutateFixNavigatorHardware
	ag.mutations["missing_navigator_clipboard"] = mutateFixNavigatorModernAPIs
	ag.mutations["missing_navigator_credentials"] = mutateFixNavigatorModernAPIs
	ag.mutations["screen_is_extended_missing"] = mutateFixScreenIsExtended

	// Phase 68: Navigator Media APIs (Capabilities, Session)
	ag.mutations["missing_navigator_mediaCapabilities"] = mutateFixNavigatorMediaAPIs
	ag.mutations["missing_navigator_mediaSession"] = mutateFixNavigatorMediaAPIs

	// Phase 69: Crawlee Parity (UserAgentData & Header Order)
	ag.mutations["ua_data_consistency_mismatch"] = mutateFixUADataConsistency
	ag.mutations["suspicious_header_order"] = mutateFixHeaderOrder

	// Phase 70: Navigator Worker APIs (ServiceWorker, SharedWorker)
	ag.mutations["missing_navigator_serviceWorker"] = mutateFixNavigatorWorkers
	ag.mutations["missing_navigator_sharedWorker"] = mutateFixNavigatorWorkers

	// Phase 71: WebGL Shader Precision & Deep Extensions
	ag.mutations["webgl_shader_precision_mismatch"] = mutateFixWebGLShaderPrecision

	// Phase 72: Performance Timing Deep Analysis
	ag.mutations["timing_missing_byte_counts"] = mutateFixTimingDeepAnalysis
	ag.mutations["timing_inconsistent_protocols"] = mutateFixTimingDeepAnalysis

	// Phase 73: Navigator Plugins & MimeTypes Consistency
	ag.mutations["missing_navigator_plugins"] = mutateFixPlugins
	ag.mutations["empty_plugins"] = mutateFixPlugins
	ag.mutations["plugins_mimetype_mismatch"] = mutateFixPlugins

	// Phase 74: Permissions API Deep Consistency
	ag.mutations["permissions_query_mismatch"] = mutateFixPermissionsDeep
	ag.mutations["permissions_metadata_leak"] = mutateFixPermissionsDeep
	ag.mutations["permissions_media_mismatch"] = mutateFixPermissionsDeep

	// Phase 75: Client Hints Deep Consistency
	ag.mutations["ua_client_hints_mismatch"] = mutateFixClientHintsDeep

	// Phase 76: Graphics API Hardening (OffscreenCanvas)
	ag.mutations["offscreen_canvas_metrics_mismatch"] = mutateFixOffscreenCanvasDeep

	// Phase 77: Gamepad API Consistency
	ag.mutations["missing_navigator_getGamepads"] = mutateFixGamepadAPI
	ag.mutations["gamepad_api_stubbed"] = mutateFixGamepadAPI

	// Phase 78: Hardware API Hardening
	ag.mutations["bluetooth_api_stubbed"] = mutateFixHardwareHardening
	ag.mutations["usb_api_stubbed"] = mutateFixHardwareHardening
	ag.mutations["missing_navigator_bluetooth"] = mutateFixHardwareHardening
	ag.mutations["missing_navigator_usb"] = mutateFixHardwareHardening

	// Phase 79: Screen Geometry Consistency
	ag.mutations["screen_avail_geometry_mismatch"] = mutateFixScreenGeometryDeep

	// Phase 80: Navigator Prototype Hardening
	ag.mutations["navigator_prototype_mismatch"] = mutateFixNavigatorPrototype

	// Phase 81: WebGL Renderer Deep Consistency
	ag.mutations["renderer_platform_mismatch"] = mutateFixWebGLRendererDeep

	// Phase 82: AudioContext Hardening
	ag.mutations["audio_context_static_state"] = mutateFixAudioContextDeep
	ag.mutations["audio_latency_improbable"] = mutateFixAudioContextDeep

	// Phase 83: Performance.memory/navigation Hardening
	ag.mutations["performance_memory_limit_mismatch"] = mutateFixPerformanceDeep
	ag.mutations["performance_navigation_type_mismatch"] = mutateFixPerformanceDeep

	// Phase 84: Timing Consistency
	ag.mutations["timing_navigation_start_inconsistent"] = mutateFixTimingDeep
	ag.mutations["timing_load_event_inconsistent"] = mutateFixTimingDeep

	// Phase 85: Touch & Orientation Hardening
	ag.mutations["touch_pointer_mismatch"] = mutateFixTouchDeep
	ag.mutations["missing_orientation_lock"] = mutateFixOrientationDeep
	ag.mutations["network_high_downlink_low_efftype"] = mutateFixNetworkInfoDeep
	ag.mutations["suspicious_desktop_savedata"] = mutateFixNetworkInfoDeep
	ag.mutations["storage_quota_memory_mismatch"] = mutateFixStorageDeep
	ag.mutations["low_storage_quota"] = mutateFixStorageDeep

	// Phase 89: WebGL Advanced Context Attributes
	ag.mutations["webgl_context_attributes_mismatch"] = mutateFixWebGLAttributesDeep

	// Phase 90: Paint Timing
	ag.mutations["timing_paint_mismatch"] = mutateFixPaintTimingDeep

	// Phase 91: Worker Coherence
	ag.mutations["worker_userAgent_mismatch"] = mutateFixWorkerCoherence
	ag.mutations["worker_platform_mismatch"] = mutateFixWorkerCoherence
	ag.mutations["worker_hardwareConcurrency_mismatch"] = mutateFixWorkerCoherence

	// Phase 92: Runtime Introspection
	ag.mutations["navigator_proxy_detected"] = mutateFixIntrospectionDeep
	ag.mutations["native_function_toString_leak"] = mutateFixIntrospectionDeep

	// Phase 93: Audio Graph
	ag.mutations["missing_offline_audio_context"] = mutateFixAudioGraphDeep
	ag.mutations["suspicious_audio_compressor_params"] = mutateFixAudioGraphDeep

	// Phase 94: Canvas Geometry
	ag.mutations["canvas_measureText_fixed_width_stub"] = mutateFixCanvasGeometryDeep

	// Phase 95: Math Precision
	ag.mutations["math_precision_stubbed"] = mutateFixMathPrecision

	// Phase 96: UserAgentData
	ag.mutations["inconsistent_userAgentData_arch"] = mutateFixUADataDeep
	ag.mutations["inconsistent_userAgentData_bitness"] = mutateFixUADataDeep
	ag.mutations["inconsistent_userAgentData_fullVersionList"] = mutateFixUADataDeep

	// Phase 98: Accept vs Sec-Fetch-Dest
	ag.mutations["accept_dest_mismatch_missing_html"] = mutateFixAcceptDest
	ag.mutations["accept_dest_mismatch_static_document"] = mutateFixAcceptDest
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

func mutateFixPdfViewer(ag *AdaptiveRequestGenerator) {
	// generateNavigator now always sets pdfViewerEnabled=true; rebuild
	ag.rebuild()
}

func mutateFixHardwareCoherence(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeHardwareCoherence = true
	ag.config.EvadeHardwareConcurrency = true
	// generateNavigator now uses correlated hardware pairs; rebuild
	ag.rebuild()
}

func mutateFixTimingDuration(ag *AdaptiveRequestGenerator) {
	// generateTiming now populates realistic duration_ms per resource type; rebuild
	ag.rebuild()
}

func mutateFixVendorConsistency(ag *AdaptiveRequestGenerator) {
	// generateNavigator vendors already match browser profiles; rebuild
	ag.rebuild()
}

func mutateFixLoadTimesOrdering(ag *AdaptiveRequestGenerator) {
	// generateNavigator already produces correctly ordered chrome.loadTimes; rebuild
	ag.rebuild()
}

func mutateFixAudioOutputLatency(ag *AdaptiveRequestGenerator) {
	// generateAudio now produces non-zero output_latency; rebuild
	ag.rebuild()
}

func mutateFixCSILoadTimes(ag *AdaptiveRequestGenerator) {
	// generateNavigator derives csi.startE from loadTimes.requestTime; rebuild
	ag.rebuild()
}

func mutateFixTimingURLs(ag *AdaptiveRequestGenerator) {
	// generateTiming now includes resource URLs in all entries; rebuild
	ag.rebuild()
}

func mutateFixNetworkCoherence(ag *AdaptiveRequestGenerator) {
	// generateNavigator already limits RTT to 4g-compatible range; rebuild
	ag.rebuild()
}

func mutateFixNotificationPermission(ag *AdaptiveRequestGenerator) {
	// generateNavigator now includes Notification_permission="default"; rebuild
	ag.rebuild()
}

func mutateFixDPRResolution(ag *AdaptiveRequestGenerator) {
	// generateScreen now constrains DPR to 1.0 on <1920px displays; rebuild
	ag.rebuild()
}

func mutateFixFontPlatform(ag *AdaptiveRequestGenerator) {
	// Font platform is already consistent with navigator platform via profile; rebuild
	ag.rebuild()
}

func mutateAddScrollEvents(ag *AdaptiveRequestGenerator) {
	// EventGenerator.Generate() now produces scroll events; rebuild
	ag.rebuild()
}

func mutateFixVersionMismatch(ag *AdaptiveRequestGenerator) {
	ag.rebuild()
}

func mutateSpoofLocalIP(ag *AdaptiveRequestGenerator) {
	ag.config.SpoofLocalIPs = true
	ag.rebuild()
}

func mutateAddMouseClustering(ag *AdaptiveRequestGenerator) {
	if ag.config.EventConfig == nil {
		ag.config.EventConfig = DefaultGeneratorConfig()
	}
	ag.config.EventConfig.EvadeMouseClustering = true
	ag.rebuild()
}

func mutateAddScrollMomentum(ag *AdaptiveRequestGenerator) {
	if ag.config.EventConfig == nil {
		ag.config.EventConfig = DefaultGeneratorConfig()
	}
	ag.config.EventConfig.EvadeScrollMomentum = true
	ag.rebuild()
}

func mutateAddClickDeceleration(ag *AdaptiveRequestGenerator) {
	if ag.config.EventConfig == nil {
		ag.config.EventConfig = DefaultGeneratorConfig()
	}
	ag.config.EventConfig.EvadeClickDeceleration = true
	ag.rebuild()
}

func mutateEvadeFittsLaw(ag *AdaptiveRequestGenerator) {
	if ag.config.EventConfig == nil {
		ag.config.EventConfig = DefaultGeneratorConfig()
	}
	ag.config.EventConfig.EvadeFittsLaw = true
	ag.rebuild()
}

func mutateEvadeMouseVelocityLag3(ag *AdaptiveRequestGenerator) {
	if ag.config.EventConfig == nil {
		ag.config.EventConfig = DefaultGeneratorConfig()
	}
	ag.config.EventConfig.EvadeMouseVelocityLag3 = true
	ag.rebuild()
}

func mutateEvadeScrollSpearman(ag *AdaptiveRequestGenerator) {
	if ag.config.EventConfig == nil {
		ag.config.EventConfig = DefaultGeneratorConfig()
	}
	ag.config.EventConfig.EvadeScrollSpearman = true
	ag.rebuild()
}

func mutateFixCanvasEntropy(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeCanvasEntropy = true
	ag.rebuild()
}

func mutateEvadeClickDwellTime(ag *AdaptiveRequestGenerator) {
	ag.config.EventConfig.EvadeClickDwellTime = true
	ag.rebuild()
}

func mutateFixWebGLCount(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeWebGLCount = true
	ag.rebuild()
}

func mutateFixScreenHeightGap(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeScreenHeightGap = true
	ag.rebuild()
}

func mutateFixWebGLViewport(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeWebGLViewport = true
	ag.rebuild()
}

func mutateFixMouseEaseIn(ag *AdaptiveRequestGenerator) {
	if ag.config.EventConfig == nil {
		ag.config.EventConfig = DefaultGeneratorConfig()
	}
	ag.config.EventConfig.EvadeMouseEaseIn = true
	ag.rebuild()
}

func mutateFixDeviceMemoryClamp(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeDeviceMemoryClamp = true
	ag.rebuild()
}

func mutateFixConnectionSaveData(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeConnectionSaveData = true
	ag.rebuild()
}

func mutateFixScreenOrientation(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeScreenOrientation = true
	ag.rebuild()
}

func mutateFixBatteryStatus(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeBatteryStatus = true
	ag.rebuild()
}

func mutateFixStorageQuota(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeStorageQuota = true
	ag.rebuild()
}

func mutateFixNavigatorKeyboard(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeNavigatorKeyboard = true
	ag.rebuild()
}

func mutateFixHardwareConcurrency(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeHardwareConcurrency = true
	ag.rebuild()
}

func mutateFixPointerInteraction(ag *AdaptiveRequestGenerator) {
	ag.config.EvadePointerInteraction = true
	ag.rebuild()
}

func mutateFixPluginFilenames(ag *AdaptiveRequestGenerator) {
	ag.config.EvadePluginFilenames = true
	ag.rebuild()
}

func mutateFixNetworkQuantization(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeNetworkQuantization = true
	ag.rebuild()
}

func mutateFixWebGPU(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeWebGPU = true
	ag.rebuild()
}

func mutateFixPermissions(ag *AdaptiveRequestGenerator) {
	ag.config.EvadePermissions = true
	ag.rebuild()
}

func mutateFixAudioBaseLatency(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeAudioBaseLatency = true
	ag.rebuild()
}

func mutateFixMediaDevices(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeMediaDevices = true
	ag.rebuild()
}

func mutateFixWebRTC(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeWebRTC = true
	ag.rebuild()
}

func mutateFixCanvasNoise(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeCanvasEntropy = true
	ag.config.EvadeCanvasNoise = true
	ag.rebuild()
}

func mutateFixModernNavigator(ag *AdaptiveRequestGenerator) {
	// These are currently always-on in generateNavigator once implemented.
	// We call rebuild just to ensure the RequestGenerator is refreshed if needed,
	// though it's technically redundant for always-on features.
	ag.rebuild()
}

func mutateFixDPRQuantization(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeDPRQuantization = true
	ag.rebuild()
}

func mutateFixMemoryAndStack(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeErrorStackFormat = true
	// Memory plausibility is currently handled by always scaling in addPerformanceMemory,
	// but we call rebuild to ensure any config changes are picked up.
	ag.rebuild()
}

func mutateFixAudioAPIs(ag *AdaptiveRequestGenerator) {
	// These are currently always-on in generateAudio/generateNavigator once implemented.
	// We call rebuild just to ensure the RequestGenerator is refreshed.
	ag.rebuild()
}

func mutateFixGraphicsAPIs(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeWebGLCount = true
	ag.rebuild()
}

func mutateFixStorageAPIs(ag *AdaptiveRequestGenerator) {
	// These are currently always-on in generateNavigator once implemented.
	ag.rebuild()
}

func mutateFixScreenIsExtended(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeScreenIsExtended = true
	ag.rebuild()
}

func mutateFixNavigatorConnectivity(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeNavigatorConnectivity = true
	ag.rebuild()
}

func mutateFixNavigatorHardware(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeNavigatorHardware = true
	ag.rebuild()
}

func mutateFixNavigatorModernAPIs(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeNavigatorModernAPIs = true
	ag.rebuild()
}

func mutateFixNavigatorMediaAPIs(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeNavigatorMediaAPIs = true
	ag.rebuild()
}

func mutateFixUADataConsistency(ag *AdaptiveRequestGenerator) {
	// rebuilding is enough since generateUserAgentData is now dynamic
	ag.rebuild()
}

func mutateFixHeaderOrder(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeHeaderOrder = true
	ag.rebuild()
}

func mutateFixNavigatorWorkers(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeNavigatorWorkers = true
	ag.rebuild()
}

func mutateFixWebGLShaderPrecision(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeWebGLShaderPrecision = true
	ag.rebuild()
}

func mutateFixTimingDeepAnalysis(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeTimingDeepAnalysis = true
	ag.rebuild()
}

func mutateFixPlugins(ag *AdaptiveRequestGenerator) {
	ag.config.EvadePlugins = true
	ag.rebuild()
}

func mutateFixPermissionsDeep(ag *AdaptiveRequestGenerator) {
	ag.config.EvadePermissionsDeep = true
	ag.rebuild()
}

func mutateFixClientHintsDeep(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeClientHintsDeep = true
	ag.rebuild()
}

func mutateFixOffscreenCanvasDeep(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeOffscreenCanvasDeep = true
	ag.rebuild()
}

func mutateFixGamepadAPI(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeGamepadAPI = true
	ag.rebuild()
}

func mutateFixHardwareHardening(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeHardwareHardening = true
	ag.config.EvadeNavigatorHardware = true // Phase 66
	ag.rebuild()
}

func mutateFixScreenGeometryDeep(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeScreenGeometryDeep = true
	ag.rebuild()
}

func mutateFixNavigatorPrototype(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeNavigatorPrototype = true
	ag.rebuild()
}

func mutateFixWebGLRendererDeep(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeWebGLRendererDeep = true
	ag.rebuild()
}

func mutateFixAudioContextDeep(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeAudioContextDeep = true
	ag.rebuild()
}

func mutateFixPerformanceDeep(ag *AdaptiveRequestGenerator) {
	ag.config.EvadePerformanceDeep = true
	ag.rebuild()
}

func mutateFixTimingDeep(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeTimingDeep = true
	ag.rebuild()
}

func mutateFixTouchDeep(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeTouchDeep = true
	ag.rebuild()
}

func mutateFixOrientationDeep(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeOrientationDeep = true
	ag.rebuild()
}

func mutateFixErrorStackConsistency(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeErrorStackFormat = true
	ag.rebuild()
}

func mutateFixWebGLParameters(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeWebGLParameters = true
	ag.rebuild()
}

func mutateFixLanguageConsistency(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeLanguageConsistency = true
	ag.rebuild()
}

func mutateFixMediaQueryHover(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeMediaQueryHover = true
	ag.rebuild()
}

func mutateFixTLSFingerprint(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeTLSFingerprint = true
	ag.rebuild()
}

func mutateEvadeMouseTypingDensity(ag *AdaptiveRequestGenerator) {
	if ag.config.EventConfig == nil {
		ag.config.EventConfig = DefaultGeneratorConfig()
	}
	ag.config.EventConfig.EvadeMouseTypingDensity = true
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

	// BROKEN: WebGL with mismatching max_texture_size (4096 for high-end GPU) and without extensions
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
		"max_texture_size":  4096, // BROKEN: Low texture size for high-end renderer
		// extensions intentionally omitted
	}
	webglJSON, _ := json.Marshal(webgl)
	req.Header.Set(constants.HeaderWebGLData, string(webglJSON))

	// BROKEN: Navigator without appVersion and effectiveType
	dims := [2]int{1920, 1080}
	scrollW := 17
	nav := map[string]interface{}{
		"webdriver":           false,
		"webdriverString":     "function () { [native code] }",
		"platform":            p.NavPlatform,
		"vendor":              p.NavVendor,
		"userAgent":           p.UserAgent,
		"hardwareConcurrency": 8,
		"deviceMemory":        16,
		"cookieEnabled":       true,
		"pdfViewerEnabled":    p.Browser == "chrome",
		"connection": map[string]interface{}{
			"rtt":      25,
			"downlink": 1.5,
			// effectiveType intentionally omitted
			// BROKEN: anticorrelated — low RTT with low downlink
		},
		// appVersion intentionally omitted
		"languages":          p.Languages,
		"language":           "fr-FR", // BROKEN: mismatch with languages[0] (which is en-US)
		"intl_locale":        "fr-FR",
		"screen_color_depth": 24,
		"screen_inner_width": dims[0] - scrollW,
		"screen_outer_width": dims[0],
		"productSub":         p.ProductSub,
		"maxTouchPoints":     0,
		// onLine and vibrate intentionally omitted for Phase 65 detection
	}
	if p.Browser == "chrome" {
		nav["chrome"] = map[string]interface{}{}
	}
	// P11 signals
	nav["orientation_type"] = "landscape-primary"
	nav["orientation_angle"] = 0

	// Phase 64: Omit screen.isExtended to trigger the sword
	// (Already omitted by default in this broken generator)

	b, _ := json.Marshal(nav)
	req.Header.Set(constants.HeaderNavigatorData, string(b))

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

	// BROKEN: Behavioral data without scroll events AND with inconsistent error stack
	eventGen := NewEventGenerator(nil)
	eventData := eventGen.Generate()
	eventData.ScrollTimestamps = nil // intentionally stripped
	eventData.ScrollDeltas = nil     // intentionally stripped

	// BROKEN: Error stack mismatch (Firefox format on Chrome UA or vice-versa)
	if p.Browser == "chrome" {
		eventData.ErrorStack = "myApp@https://example.com/js/main.js:10:5" // Firefox format
	} else {
		eventData.ErrorStack = "Error\n    at myApp (https://example.com/js/main.js:10:5)" // Chrome format
	}

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

	seed := config.Seed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}

	//nolint:gosec
	rng := rand.New(rand.NewSource(seed + 2))

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

func mutateFixNetworkInfoDeep(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeNetworkInfoDeep = true
}

func mutateFixStorageDeep(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeStorageDeep = true
}

func mutateFixWebGLAttributesDeep(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeWebGLAttributesDeep = true
}

func mutateFixPaintTimingDeep(ag *AdaptiveRequestGenerator) {
	ag.config.EvadePaintTimingDeep = true
}

func mutateFixWorkerCoherence(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeWorkerCoherence = true
}

func mutateFixIntrospectionDeep(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeIntrospectionDeep = true
	ag.rebuild()
}

func mutateFixAudioGraphDeep(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeAudioGraphDeep = true
	ag.rebuild()
}

func mutateFixCanvasGeometryDeep(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeCanvasGeometryDeep = true
	ag.rebuild()
}

func mutateFixMathPrecision(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeMathPrecision = true
	ag.rebuild()
}

func mutateFixUADataDeep(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeUADataDeep = true
	ag.rebuild()
}

func mutateFixAcceptDest(ag *AdaptiveRequestGenerator) {
	ag.config.EvadeAcceptDestConsistency = true
	ag.rebuild()
}

// unusedImportGuard prevents "imported and not used" errors.
var (
	_ = math.Min
	_ = strings.HasPrefix
)
