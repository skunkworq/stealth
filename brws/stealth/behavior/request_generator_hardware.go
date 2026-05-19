package behavior

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
)

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
