package detection

import (
	"fmt"
	"strings"
)

func (na *NavigatorAnalyzer) checkKeyboardAPI(navData map[string]interface{}, vec *DetectionVector, indicators []string, reqUA string) []string {
	if strings.Contains(strings.ToLower(reqUA), "chrome") {
		if _, hasKeyboard := navData["keyboard"]; !hasKeyboard {
			indicators = append(indicators, "missing_navigator_keyboard")
			vec.Score += 0.25
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "missing_navigator_keyboard",
				Fired:       true,
				Weight:      0.25,
				Score:       0.25,
				Field:       "navigator.keyboard",
				Actual:      "absent",
				Expected:    "present (for Chrome)",
				Severity:    "medium",
				Description: "navigator.keyboard is missing. Modern Chromium browsers always include this object.",
			})
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkVendor(navData map[string]interface{}, vec *DetectionVector, indicators []string, reqUA string) []string {
	if vendor, hasVendor := navData["vendor"].(string); hasVendor {
		uaLower := strings.ToLower(reqUA)
		if strings.Contains(uaLower, "chrome") && vendor != "Google Inc." {
			indicators = append(indicators, fmt.Sprintf("vendor_browser_mismatch: chrome_ua_vendor=%q", vendor))
			vec.Score += 0.30
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "vendor_browser_mismatch",
				Fired:       true,
				Weight:      0.30,
				Score:       0.30,
				Field:       "vendor",
				Actual:      vendor,
				Expected:    "Google Inc. (for Chrome UA)",
				Severity:    "high",
				Description: "navigator.vendor does not match the browser type in UA",
			})
		} else if strings.Contains(uaLower, "firefox") && vendor != "" {
			indicators = append(indicators, fmt.Sprintf("vendor_browser_mismatch: firefox_ua_vendor=%q", vendor))
			vec.Score += 0.30
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "vendor_browser_mismatch",
				Fired:       true,
				Weight:      0.30,
				Score:       0.30,
				Field:       "vendor",
				Actual:      vendor,
				Expected:    "empty string (for Firefox UA)",
				Severity:    "high",
				Description: "navigator.vendor does not match the browser type in UA",
			})
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkNotificationPermission(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	if _, hasNotif := navData["Notification_permission"]; !hasNotif {
		indicators = append(indicators, "missing_notification_permission")
		vec.Score += 0.15
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        "missing_notification_permission",
			Fired:       true,
			Weight:      0.15,
			Score:       0.15,
			Field:       "Notification_permission",
			Actual:      "absent",
			Expected:    "'default', 'granted', or 'denied'",
			Severity:    "medium",
			Description: "Notification.permission missing — real browsers always expose this Web API",
		})
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkTimezone(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	if _, hasTZ := navData["timezone"]; !hasTZ {
		indicators = append(indicators, "missing_timezone")
		vec.Score += 0.15
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkTimezoneParity(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	if tz, ok := navData["timezone"].(string); ok {
		if offset, ok := navData["timezone_offset"].(float64); ok {
			if tz == "America/New_York" && offset != 300 {
				indicators = append(indicators, "timezone_offset_mismatch")
				vec.Score += 0.4
			}
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkPermissionsAPI(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	if perm, ok := navData["notifications_prompt"].(string); ok {
		if perm == "default" && navData["permissions_is_proxy"] == true {
			indicators = append(indicators, "spoofed_permissions_api_detected")
			vec.Score += 0.6
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkPermissionsExtended(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	// 1. Notification vs Query state
	notifPerm, hasNotifPerm := navData["Notification_permission"].(string)
	permState, hasPermState := navData["permissions_notifications_state"].(string)

	if hasNotifPerm && hasPermState {
		if notifPerm != permState {
			indicators = append(indicators, "permissions_query_mismatch")
			vec.Score += 0.45
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "permissions_query_mismatch",
				Fired:       true,
				Weight:      0.45,
				Score:       0.45,
				Field:       "Notification.permission vs permissions.query",
				Actual:      fmt.Sprintf("notif=%s query=%s", notifPerm, permState),
				Expected:    "matching states",
				Severity:    "high",
				Description: "The Notification permission state is inconsistent with the Permissions API query result.",
			})
		}
	}

	// 2. Headless/Bot Metadata Leak
	if isProxy, ok := navData["permissions_is_proxy"].(bool); ok && isProxy {
		indicators = append(indicators, "permissions_metadata_leak")
		vec.Score += 0.8
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        "permissions_metadata_leak",
			Fired:       true,
			Weight:      0.8,
			Score:       0.8,
			Field:       "permissions.query result",
			Actual:      "isProxy=true",
			Expected:    "no proxy indicators",
			Severity:    "critical",
			Description: "Permissions status object contains unexpected 'isProxy' property, indicating a shallow evasion script.",
		})
	}

	// 3. Multi-permission consistency (e.g., camera/mic)
	camState, hasCam := navData["permissions_camera_state"].(string)
	micState, hasMic := navData["permissions_microphone_state"].(string)

	devices, hasDevices := navData["media_devices"].([]interface{})
	if (hasCam && camState == "granted") || (hasMic && micState == "granted") {
		// If granted, we should have labeled devices
		hasLabels := false
		if hasDevices {
			for _, d := range devices {
				if dm, ok := d.(map[string]interface{}); ok {
					if label, ok := dm["label"].(string); ok && label != "" {
						hasLabels = true
						break
					}
				}
			}
		}
		if !hasLabels {
			indicators = append(indicators, "permissions_media_mismatch")
			vec.Score += 0.5
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "permissions_media_mismatch",
				Fired:       true,
				Weight:      0.5,
				Score:       0.5,
				Field:       "mediaDevice labels",
				Actual:      "no labels with granted permission",
				Expected:    "labels present when granted",
				Severity:    "high",
				Description: "Media device labels are missing despite camera/microphone permissions being granted, indicating spoofed permissions.",
			})
		}
	}

	// 4. Geolocation vs Timezone/IP (Simplified check for now)
	geoState, hasGeo := navData["permissions_geolocation_state"].(string)
	if hasGeo && geoState == "granted" {
		// In automated environments, granting geolocation without actual location providers usually looks fake
		// unless we see specific lat/long data (handled in a separate analyzer usually)
	}

	return indicators
}

func (na *NavigatorAnalyzer) checkMediaQueryHover(navData map[string]interface{}, vec *DetectionVector, indicators []string, reqUA string) []string {
	// Desktop browsers (Chrome, Firefox, Safari) in real environments always support hover.
	// Headless Chrome (even with --headless=new) sometimes defaults to (hover: none).
	uaLower := strings.ToLower(reqUA)
	isDesktop := (strings.Contains(uaLower, "macintosh") || strings.Contains(uaLower, "windows") || strings.Contains(uaLower, "linux")) &&
		!strings.Contains(uaLower, "android") && !strings.Contains(uaLower, "iphone") && !strings.Contains(uaLower, "ipad")

	if isDesktop {
		if hover, ok := navData["media_query_hover"].(string); ok {
			if hover == "none" {
				indicators = append(indicators, "none_media_query_hover")
				vec.Score += 0.40
				vec.CheckReports = append(vec.CheckReports, CheckReport{
					Name:        "media_query_hover_none",
					Fired:       true,
					Weight:      0.40,
					Score:       0.40,
					Field:       "media_query_hover",
					Actual:      "none",
					Expected:    "hover",
					Severity:    "high",
					Description: "Desktop User-Agent reports (hover: none) media query, indicating a headless/virtual environment.",
				})
			}
		} else {
			// Missing property is also suspicious for desktop UAs
			indicators = append(indicators, "missing_media_query_hover")
			vec.Score += 0.15
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkWebGPUSupport(navData map[string]interface{}, vec *DetectionVector, indicators []string, reqUA string) []string {
	isModernChrome := strings.Contains(strings.ToLower(reqUA), "chrome")
	// WebGPU (navigator.gpu) was added in Chrome 113.
	if isModernChrome {
		if gpu, hasGPU := navData["gpu_present"].(bool); hasGPU {
			if !gpu {
				indicators = append(indicators, "missing_webgpu")
				vec.Score += 0.35
				vec.CheckReports = append(vec.CheckReports, CheckReport{
					Name:        "missing_webgpu",
					Fired:       true,
					Weight:      0.35,
					Score:       0.35,
					Field:       "navigator.gpu",
					Actual:      "absent",
					Expected:    "present",
					Severity:    "medium",
					Description: "Modern Chrome browsers (113+) should expose the WebGPU API.",
				})
			}
		}
	}
	return indicators
}

// checkUserAgentData is kept in navigator_analyzer.go (requires *http.Request import).

func (na *NavigatorAnalyzer) checkUserActivation(navData map[string]interface{}, vec *DetectionVector, indicators []string, reqUA string) []string {
	isChrome := strings.Contains(strings.ToLower(reqUA), "chrome")
	if isChrome {
		if _, hasActivation := navData["userActivation"]; !hasActivation {
			indicators = append(indicators, "missing_navigator_userActivation")
			vec.Score += 0.25
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "missing_navigator_userActivation",
				Fired:       true,
				Weight:      0.25,
				Score:       0.25,
				Field:       "navigator.userActivation",
				Actual:      "absent",
				Expected:    "present",
				Severity:    "medium",
				Description: "Modern Chromium browsers expose navigator.userActivation to track user interaction state.",
			})
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkSchedulingAPI(navData map[string]interface{}, vec *DetectionVector, indicators []string, reqUA string) []string {
	isChrome := strings.Contains(strings.ToLower(reqUA), "chrome")
	if isChrome {
		if _, hasScheduling := navData["scheduling"]; !hasScheduling {
			indicators = append(indicators, "missing_navigator_scheduling")
			vec.Score += 0.25
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "missing_navigator_scheduling",
				Fired:       true,
				Weight:      0.25,
				Score:       0.25,
				Field:       "navigator.scheduling",
				Actual:      "absent",
				Expected:    "present",
				Severity:    "medium",
				Description: "Modern Chromium browsers expose navigator.scheduling for task prioritization and input pending checks.",
			})
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkLocksAPI(navData map[string]interface{}, vec *DetectionVector, indicators []string, reqUA string) []string {
	// Web Locks API is standard in modern browsers
	if _, hasLocks := navData["locks"]; !hasLocks {
		indicators = append(indicators, "missing_navigator_locks")
		vec.Score += 0.2
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        "missing_navigator_locks",
			Fired:       true,
			Weight:      0.2,
			Score:       0.2,
			Field:       "navigator.locks",
			Actual:      "absent",
			Expected:    "present",
			Severity:    "low",
			Description: "The Web Locks API (navigator.locks) is a standard modern browser API available in all major engines.",
		})
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkIntlConsistency(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	if intlTZ, ok := navData["intl_timezone"].(string); ok {
		if browserTZ, ok := navData["timezone"].(string); ok {
			if intlTZ != browserTZ {
				indicators = append(indicators, "intl_timezone_mismatch")
				vec.Score += 0.4
				vec.CheckReports = append(vec.CheckReports, CheckReport{
					Name:        "intl_timezone_mismatch",
					Fired:       true,
					Weight:      0.4,
					Score:       0.4,
					Field:       "Intl.DateTimeFormat().resolvedOptions().timeZone",
					Actual:      intlTZ,
					Expected:    browserTZ,
					Severity:    "medium",
					Description: "Intl API timezone reports a different value than the primary navigator timezone property.",
				})
			}
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkNavigatorModernAPIs(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	// Clipboard and Credentials are standard modern browser APIs.
	// Often missing in headless/restricted environments.
	apis := []string{"clipboard", "credentials"}
	for _, api := range apis {
		if _, ok := navData[api]; !ok {
			name := fmt.Sprintf("missing_navigator_%s", api)
			indicators = append(indicators, name)
			vec.Score += 0.20
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        name,
				Fired:       true,
				Weight:      0.20,
				Score:       0.20,
				Field:       "navigator." + api,
				Actual:      "absent",
				Expected:    "present",
				Severity:    "medium",
				Description: fmt.Sprintf("The Navigator.%s API is a standard browser feature and is often missing in simplified bot environments.", api),
			})
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkNavigatorMediaAPIs(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	// mediaCapabilities (Chrome 66+) and mediaSession (Chrome 73+) are standard modern browser APIs.
	apis := []string{"mediaCapabilities", "mediaSession"}
	for _, api := range apis {
		if _, ok := navData[api]; !ok {
			name := fmt.Sprintf("missing_navigator_%s", api)
			indicators = append(indicators, name)
			vec.Score += 0.20
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        name,
				Fired:       true,
				Weight:      0.20,
				Score:       0.20,
				Field:       "navigator." + api,
				Actual:      "absent",
				Expected:    "present",
				Severity:    "medium",
				Description: fmt.Sprintf("The Navigator.%s API is a standard browser feature and is often missing in simplified bot environments.", api),
			})
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkNavigatorWorkers(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	// serviceWorker and SharedWorker are standard modern browser APIs.
	// serviceWorker is usually available on secure contexts (which we assume here).
	apis := []string{"serviceWorker", "sharedWorker"}
	for _, api := range apis {
		if _, ok := navData[api]; !ok {
			name := fmt.Sprintf("missing_navigator_%s", api)
			indicators = append(indicators, name)
			vec.Score += 0.20
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        name,
				Fired:       true,
				Weight:      0.20,
				Score:       0.20,
				Field:       "navigator." + api,
				Actual:      "absent",
				Expected:    "present",
				Severity:    "medium",
				Description: fmt.Sprintf("The Navigator.%s API is a standard browser feature and is often missing in simplified bot environments.", api),
			})
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkNavigatorPrototype(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	// Phase 80: Navigator Prototype chain.
	if stubbed, ok := navData["navigator_prototype_stubbed"].(bool); ok && stubbed {
		name := "navigator_prototype_mismatch"
		indicators = append(indicators, name)
		vec.Score += 0.45
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        name,
			Fired:       true,
			Weight:      0.45,
			Score:       0.45,
			Field:       "navigator.__proto__",
			Actual:      "own properties",
			Expected:    "prototype properties",
			Severity:    "high",
			Description: "The Navigator object has own properties where getter/setter properties on the prototype are expected.",
		})
	}
	return indicators
}

// checkWorkerContextCoherence (Phase 91)
func (na *NavigatorAnalyzer) checkWorkerContextCoherence(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	workerRaw, ok := navData["worker_navigator"]
	if !ok {
		return indicators
	}
	workerData, ok := workerRaw.(map[string]interface{})
	if !ok {
		return indicators
	}

	checks := []struct {
		prop string
		name string
	}{
		{"userAgent", "worker_userAgent_mismatch"},
		{"platform", "worker_platform_mismatch"},
		{"hardwareConcurrency", "worker_hardwareConcurrency_mismatch"},
	}

	for _, c := range checks {
		mainVal := navData[c.prop]
		workerVal := workerData[c.prop]
		if mainVal != nil && workerVal != nil && mainVal != workerVal {
			name := c.name
			indicators = append(indicators, name)
			vec.Score += 0.35
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        name,
				Fired:       true,
				Weight:      0.35,
				Score:       0.35,
				Field:       "worker." + c.prop,
				Actual:      fmt.Sprintf("%v", workerVal),
				Expected:    fmt.Sprintf("%v", mainVal),
				Severity:    "medium",
				Description: fmt.Sprintf("Navigator properties in the Worker context do not match the main thread (mismatch on %s).", c.prop),
			})
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkNavigatorVibrate(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	if _, ok := navData["vibrate"]; !ok {
		name := "missing_navigator_vibrate"
		indicators = append(indicators, name)
		vec.Score += 0.20
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        name,
			Fired:       true,
			Weight:      0.20,
			Score:       0.20,
			Field:       "navigator.vibrate",
			Actual:      "absent",
			Expected:    "present",
			Severity:    "medium",
			Description: "The Navigator.vibrate() API is a standard browser feature and is often missing in simplified bot environments.",
		})
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkNavigatorHardwareAPIs(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	// Bluetooth and USB are part of the standard Chromium navigator object.
	apis := []string{"bluetooth", "usb"}
	for _, api := range apis {
		val, ok := navData[api]
		if !ok {
			name := fmt.Sprintf("missing_navigator_%s", api)
			indicators = append(indicators, name)
			vec.Score += 0.20
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        name,
				Fired:       true,
				Weight:      0.20,
				Score:       0.20,
				Field:       "navigator." + api,
				Actual:      "absent",
				Expected:    "present",
				Severity:    "medium",
				Description: fmt.Sprintf("The Navigator.%s API is a standard browser feature and is often missing in simplified bot environments.", api),
			})
		} else {
			// Check for shallow stubs (Phase 78)
			apiData, isMap := val.(map[string]interface{})
			if isMap {
				if api == "bluetooth" {
					if _, hasAvail := apiData["getAvailability"]; !hasAvail {
						name := "bluetooth_api_stubbed"
						indicators = append(indicators, name)
						vec.Score += 0.30
						vec.CheckReports = append(vec.CheckReports, CheckReport{
							Name:        name,
							Fired:       true,
							Weight:      0.30,
							Score:       0.30,
							Field:       "navigator.bluetooth.getAvailability",
							Actual:      "absent",
							Expected:    "present",
							Severity:    "medium",
							Description: "The Bluetooth API is stubbed without the getAvailability method.",
						})
					}
				} else if api == "usb" {
					if _, hasGetDevices := apiData["getDevices"]; !hasGetDevices {
						name := "usb_api_stubbed"
						indicators = append(indicators, name)
						vec.Score += 0.30
						vec.CheckReports = append(vec.CheckReports, CheckReport{
							Name:        name,
							Fired:       true,
							Weight:      0.30,
							Score:       0.30,
							Field:       "navigator.usb.getDevices",
							Actual:      "absent",
							Expected:    "present",
							Severity:    "medium",
							Description: "The USB API is stubbed without the getDevices method.",
						})
					}
				}
			}
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkGamepadAPI(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	// Gamepad API (Phase 77)
	if _, ok := navData["getGamepads"]; !ok {
		if len(navData) > 10 {
			name := "missing_navigator_getGamepads"
			indicators = append(indicators, name)
			vec.Score += 0.25
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        name,
				Fired:       true,
				Weight:      0.25,
				Score:       0.25,
				Field:       "navigator.getGamepads",
				Actual:      "absent",
				Expected:    "present",
				Severity:    "medium",
				Description: "The Gamepad API is missing, which is standard in modern browsers.",
			})
		}
	} else {
		if stubbed, ok := navData["gamepad_api_stubbed"].(bool); ok && stubbed {
			name := "gamepad_api_stubbed"
			indicators = append(indicators, name)
			vec.Score += 0.35
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        name,
				Fired:       true,
				Weight:      0.35,
				Score:       0.35,
				Field:       "navigator.getGamepads",
				Actual:      "stubbed",
				Expected:    "native",
				Severity:    "medium",
				Description: "The Gamepad API is detectably stubbed.",
			})
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkCanvasMeasureText(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	metrics, ok := navData["canvas_measure_text"].(map[string]interface{})
	if !ok {
		return indicators
	}

	// Basic check: 'i' and 'W' should have different widths in non-monospace fonts
	iWidth, okI := metrics["i"].(float64)
	wWidth, okW := metrics["W"].(float64)

	if okI && okW && iWidth == wWidth && iWidth > 0 {
		name := "canvas_measureText_fixed_width_stub"
		indicators = append(indicators, name)
		vec.Score += 0.50
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        name,
			Fired:       true,
			Weight:      0.50,
			Score:       0.50,
			Field:       "canvas.measureText",
			Actual:      fmt.Sprintf("i=%f, W=%f", iWidth, wWidth),
			Expected:    "i < W",
			Severity:    "high",
			Description: "Canvas measureText(text).width returns identical values for 'i' and 'W', indicating a simplified fixed-width stub.",
		})
	}

	return indicators
}

func (na *NavigatorAnalyzer) checkMathPrecision(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	mathProps, ok := navData["math_precision"].(map[string]interface{})
	if !ok {
		return indicators
	}

	// Example values for Math.sin(1e15) and Math.cos(1e15)
	// V8 (Chrome/Deno/Node): cos(1e15) = -0.9352358826620556
	// SpiderMonkey (Firefox): cos(1e15) = -0.9352358826620556
	// However, edge cases like Math.tan(1e15) or very large inputs can vary.
	// We'll check for "common" bot-stubbed or inconsistent values.

	sin1e15, _ := mathProps["sin1e15"].(float64)
	cos1e15, _ := mathProps["cos1e15"].(float64)

	// If these are exactly 0 or 1, or missing, it's a huge red flag
	if sin1e15 == 0 && cos1e15 == 0 {
		name := "math_precision_stubbed"
		indicators = append(indicators, name)
		vec.Score += 0.40
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        name,
			Fired:       true,
			Weight:      0.40,
			Score:       0.40,
			Field:       "Math.sin/cos",
			Actual:      "zero/stubbed",
			Expected:    "precise float",
			Severity:    "high",
			Description: "Math trigonometric functions return suspiciously clean or zeroed values, suggesting a naive JS engine stub.",
		})
	}

	return indicators
}

// hasLockValue is a helper used by checkLocksAPI (kept here alongside its caller).
//
//nolint:unused
func hasLockValue(navData map[string]interface{}, key string) bool {
	_, ok := navData[key]
	return ok
}

// isExtendedValue is a helper for extended checks.
//
//nolint:unused
func isExtendedValue(val interface{}) bool {
	if val == nil {
		return false
	}
	_, isMap := val.(map[string]interface{})
	return isMap
}

// addNavigatorMediaQueries is a helper for media query checks (placeholder for future extension).
//
//nolint:unused
func (na *NavigatorAnalyzer) addNavigatorMediaQueries(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	return indicators
}
