package detection

import (
	"fmt"
	"strings"
)

func (na *NavigatorAnalyzer) checkHardwareCoherence(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	if devMem, hasMem := navData["deviceMemory"].(float64); hasMem {
		if conc, hasConc := navData["hardwareConcurrency"].(float64); hasConc {
			memGB := int(devMem)
			cores := int(conc)
			if memGB >= 32 && cores <= 4 {
				indicators = append(indicators, fmt.Sprintf("hardware_coherence_improbable: %dGB_RAM_%d_cores", memGB, cores))
				vec.Score += 0.20
				vec.CheckReports = append(vec.CheckReports, CheckReport{
					Name:        "hardware_coherence_high_ram_low_cores",
					Fired:       true,
					Weight:      0.20,
					Score:       0.20,
					Field:       "deviceMemory+hardwareConcurrency",
					Actual:      fmt.Sprintf("%dGB/%dcores", memGB, cores),
					Expected:    "correlated RAM/core counts",
					Severity:    "medium",
					Description: "High RAM with very low core count is statistically improbable",
				})
			}
			if memGB <= 4 && cores >= 16 {
				indicators = append(indicators, fmt.Sprintf("hardware_coherence_improbable: %dGB_RAM_%d_cores", memGB, cores))
				vec.Score += 0.20
				vec.CheckReports = append(vec.CheckReports, CheckReport{
					Name:        "hardware_coherence_low_ram_high_cores",
					Fired:       true,
					Weight:      0.20,
					Score:       0.20,
					Field:       "deviceMemory+hardwareConcurrency",
					Actual:      fmt.Sprintf("%dGB/%dcores", memGB, cores),
					Expected:    "correlated RAM/core counts",
					Severity:    "medium",
					Description: "Low RAM with very high core count is statistically improbable",
				})
			}
			if cores > 1 && int(cores)%2 != 0 {
				indicators = append(indicators, fmt.Sprintf("improbable_hardware_concurrency: %d cores", int(cores)))
				vec.Score += 0.25
				vec.CheckReports = append(vec.CheckReports, CheckReport{
					Name:        "improbable_hardware_concurrency",
					Fired:       true,
					Weight:      0.25,
					Score:       0.25,
					Field:       "hardwareConcurrency",
					Actual:      fmt.Sprintf("%d", int(cores)),
					Expected:    "even core count",
					Severity:    "medium",
					Description: "Odd core count detected. Real hardware typically follows even power-of-two or common multi-core patterns.",
				})
			}
		}

		if devMem > 8.0 {
			indicators = append(indicators, fmt.Sprintf("improbable_device_memory: %.1f (expected <= 8)", devMem))
			vec.Score += 0.35
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "improbable_device_memory",
				Fired:       true,
				Weight:      0.35,
				Score:       0.35,
				Field:       "deviceMemory",
				Actual:      fmt.Sprintf("%.1f", devMem),
				Expected:    "<= 8",
				Severity:    "high",
				Description: "Reported deviceMemory > 8. Browsers intentionally cap this API to 8 to prevent high-entropy hardware fingerprinting.",
			})
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkMemoryPlausibility(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	perfMem, hasPerf := navData["performance_memory"].(map[string]interface{})
	deviceMem, _ := navData["deviceMemory"].(float64)

	if hasPerf {
		limit, _ := perfMem["jsHeapSizeLimit"].(float64)
		// Standard Chrome heap limits based on deviceMemory (GB):
		// 4GB -> ~2GB limit, 8GB+ -> ~4GB limit.
		// If limit is < 1GB or doesn't match expected scale, it's suspicious.
		if deviceMem >= 8 && limit < 3.5e9 {
			indicators = append(indicators, "performance_memory_limit_too_low_for_ram")
			vec.Score += 0.35
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "performance_memory_plausibility",
				Fired:       true,
				Weight:      0.35,
				Score:       0.35,
				Field:       "performance.memory.jsHeapSizeLimit",
				Actual:      fmt.Sprintf("%.0f", limit),
				Expected:    "> 3.5GB (for 8GB+ RAM)",
				Severity:    "high",
				Description: "The reported JS heap size limit is too low for the claimed device memory, suggesting a headless or restricted environment.",
			})
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkPluginsArray(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	if plugins, ok := navData["plugins"].([]interface{}); ok {
		if len(plugins) == 5 {
			isIntArray := true
			for _, p := range plugins {
				if _, isNum := p.(float64); !isNum {
					isIntArray = false
					break
				}
			}
			if isIntArray {
				indicators = append(indicators, "spoofed_plugins_array_detected")
				vec.Score += 0.5
			}
		}
	} else if length, ok := navData["plugins_length"].(float64); ok {
		if length == 5 && navData["plugins_is_array"] == true {
			indicators = append(indicators, "spoofed_plugins_array_detected")
			vec.Score += 0.5
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkScreenGeometry(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	var colorDepth, innerWidth, outerWidth float64
	if screen, ok := navData["screen"].(map[string]interface{}); ok {
		colorDepth, _ = screen["colorDepth"].(float64)
		innerWidth, _ = navData["innerWidth"].(float64)
		outerWidth, _ = navData["outerWidth"].(float64)
	} else if cd, ok := navData["screen_color_depth"].(float64); ok {
		colorDepth = cd
		innerWidth, _ = navData["screen_inner_width"].(float64)
		outerWidth, _ = navData["screen_outer_width"].(float64)
	}

	if colorDepth == 24 {
		if innerWidth > 0 && outerWidth > 0 && innerWidth == outerWidth {
			indicators = append(indicators, "impossible_window_geometry_detected")
			vec.Score += 0.4
		}
	}

	return indicators
}

func (na *NavigatorAnalyzer) checkBatteryStatus(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	battery, hasBattery := navData["battery_status"].(map[string]interface{})
	if !hasBattery {
		return indicators
	}

	level, _ := battery["level"].(float64)
	charging, _ := battery["charging"].(bool)
	chargingTime, _ := battery["chargingTime"].(float64)
	dischargingTime, _ := battery["dischargingTime"].(float64)

	// Suspicious static state: 100% level, charging, 0 charging time, infinity discharging
	// This is the default state for many headless/emulated battery mocks.
	if level == 1.0 && charging && chargingTime == 0 && dischargingTime > 1e10 {
		indicators = append(indicators, "suspicious_battery_status")
		vec.Score += 0.30
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        "suspicious_battery_status",
			Fired:       true,
			Weight:      0.30,
			Score:       0.30,
			Field:       "navigator.getBattery()",
			Actual:      fmt.Sprintf("level=%.1f charging=%v cTime=%.0f dTime=%.0f", level, charging, chargingTime, dischargingTime),
			Expected:    "variable battery state",
			Severity:    "medium",
			Description: "Static 100% charging battery state is a common headless bot signature.",
		})
	}

	return indicators
}

func (na *NavigatorAnalyzer) checkStorageQuota(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	quota, hasQuota := navData["storage_quota"].(float64)
	usage, hasUsage := navData["storage_usage"].(float64)

	if !hasQuota {
		indicators = append(indicators, "missing_storage_quota")
		vec.Score += 0.20
		return indicators
	}

	// 1. Quota Plausibility
	// Web browsers usually have a significant quota (GBs).
	// Zero or very low quota (e.g. < 1MB) is suspicious for desktop.
	if quota <= 1024*1024 {
		name := "low_storage_quota"
		indicators = append(indicators, name)
		vec.Score += 0.25
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        name,
			Fired:       true,
			Weight:      0.25,
			Score:       0.25,
			Field:       "navigator.storage.estimate().quota",
			Actual:      fmt.Sprintf("%.0f bytes", quota),
			Expected:    "> 1MB",
			Severity:    "medium",
			Description: "Storage quota is zero or suspiciously low, indicating restricted environment.",
		})
	}

	// 2. Usage Check
	if !hasUsage {
		indicators = append(indicators, "missing_storage_usage")
		vec.Score += 0.15
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        "missing_storage_usage",
			Fired:       true,
			Weight:      0.15,
			Score:       0.15,
			Field:       "navigator.storage.estimate().usage",
			Actual:      "absent",
			Expected:    "present",
			Severity:    "low",
			Description: "Storage usage metric is missing from the estimate reports.",
		})
	} else if usage == 0 {
		// Soft indicator: fresh profiles are often bots
		indicators = append(indicators, "zero_storage_usage")
		vec.Score += 0.10
	}

	return indicators
}

func (na *NavigatorAnalyzer) checkStoragePersistence(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	persisted, hasPersisted := navData["storage_persisted"].(bool)
	if !hasPersisted {
		indicators = append(indicators, "missing_storage_persistence")
		vec.Score += 0.15
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        "missing_storage_persistence",
			Fired:       true,
			Weight:      0.15,
			Score:       0.15,
			Field:       "navigator.storage.persisted()",
			Actual:      "absent",
			Expected:    "present",
			Severity:    "low",
			Description: "Storage persistence API response is missing.",
		})
	}
	_ = persisted // currently only checking presence
	return indicators
}

func (na *NavigatorAnalyzer) checkStorageQuotaCoherence(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	quota, hasQuota := navData["storage_quota"].(float64)
	deviceMem, hasMem := navData["deviceMemory"].(float64)

	if hasQuota && hasMem && deviceMem > 0 {
		// Phase 88: Quota vs RAM
		// On modern Chrome, quota is typically ~10% of disk, but linked to deviceMemory bucket.
		// 8GB RAM usually implies a machine with at least 128GB disk -> ~12GB+ quota.
		// If quota is very low (e.g. < 5GB) for high RAM (>= 8GB), it's suspicious.
		if deviceMem >= 8 && quota < 5.0*1024*1024*1024 {
			name := "storage_quota_memory_mismatch"
			indicators = append(indicators, name)
			vec.Score += 0.30
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        name,
				Fired:       true,
				Weight:      0.30,
				Score:       0.30,
				Field:       "navigator.storage.estimate().quota",
				Actual:      fmt.Sprintf("%.1f GB", quota/(1024*1024*1024)),
				Expected:    "> 5 GB (for 8GB+ RAM)",
				Severity:    "medium",
				Description: "Storage quota is unexpectedly low given the reported device memory.",
			})
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkMaxTouchPointsConsistency(navData map[string]interface{}, vec *DetectionVector, indicators []string, reqUA string) []string {
	maxTouch, hasMaxTouch := navData["maxTouchPoints"].(float64)
	if !hasMaxTouch {
		return indicators
	}

	uaLower := strings.ToLower(reqUA)
	isMobile := strings.Contains(uaLower, "mobile") || strings.Contains(uaLower, "android") || strings.Contains(uaLower, "iphone") || strings.Contains(uaLower, "ipad")

	if !isMobile && maxTouch > 0 {
		// Rare for desktop to have touch points unless it's a touch screen, but bots often spoof it.
		// We'll be conservative and flag high values (>0) on desktop as suspicious if other flags exist.
		indicators = append(indicators, "suspicious_desktop_max_touch_points")
		vec.Score += 0.20
	} else if isMobile && maxTouch == 0 {
		indicators = append(indicators, "inconsistent_mobile_max_touch_points")
		vec.Score += 0.45
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        "inconsistent_mobile_max_touch_points",
			Fired:       true,
			Weight:      0.45,
			Score:       0.45,
			Field:       "maxTouchPoints",
			Actual:      "0",
			Expected:    "> 0 (for mobile)",
			Severity:    "high",
			Description: "Mobile User-Agent reports 0 maxTouchPoints, which is impossible for modern touch devices.",
		})
	}

	return indicators
}

func (na *NavigatorAnalyzer) checkScreenOrientation(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	orientation, hasOrientation := navData["screen_orientation"].(string)
	if !hasOrientation {
		return indicators
	}

	innerWidth, _ := navData["screen_inner_width"].(float64)
	innerHeight, _ := navData["screen_inner_height"].(float64)

	if innerWidth > 0 && innerHeight > 0 {
		isLandscape := innerWidth > innerHeight
		isPortrait := innerHeight > innerWidth

		if isLandscape && strings.Contains(orientation, "portrait") {
			indicators = append(indicators, "screen_orientation_mismatch")
			vec.Score += 0.35
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "screen_orientation_mismatch",
				Fired:       true,
				Weight:      0.35,
				Score:       0.35,
				Field:       "screen_orientation vs aspect ratio",
				Actual:      fmt.Sprintf("orientation=%s dims=%.0fx%.0f", orientation, innerWidth, innerHeight),
				Expected:    "landscape-primary or landscape-secondary",
				Severity:    "medium",
				Description: "Screen orientation type does not match the window aspect ratio (landscape).",
			})
		} else if isPortrait && strings.Contains(orientation, "landscape") {
			indicators = append(indicators, "screen_orientation_mismatch")
			vec.Score += 0.35
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "screen_orientation_mismatch",
				Fired:       true,
				Weight:      0.35,
				Score:       0.35,
				Field:       "screen_orientation vs aspect ratio",
				Actual:      fmt.Sprintf("orientation=%s dims=%.0fx%.0f", orientation, innerWidth, innerHeight),
				Expected:    "portrait-primary or portrait-secondary",
				Severity:    "medium",
				Description: "Screen orientation type does not match the window aspect ratio (portrait).",
			})
		}
	}

	return indicators
}
