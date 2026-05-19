package behavior

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

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
