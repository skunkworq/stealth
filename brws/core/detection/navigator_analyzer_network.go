package detection

import (
	"fmt"
	"strings"
)

func (na *navigatorAnalyzer) checkNetworkCoherence(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	if conn, ok := navData["connection"].(map[string]interface{}); ok {
		effType, _ := conn["effectiveType"].(string)
		rtt, hasRTT := conn["rtt"].(float64)
		downlink, hasDown := conn["downlink"].(float64)

		if effType == "4g" && hasRTT && rtt > 200 {
			name := "network_effectivetype_rtt_mismatch"
			indicators = append(indicators, name)
			vec.Score += 0.20
		}

		if hasDown && downlink > 10.0 && (effType == "2g" || effType == "3g") {
			name := "network_high_downlink_low_efftype"
			indicators = append(indicators, fmt.Sprintf("%s: %s_downlink=%.1fMbps", name, effType, downlink))
			vec.Score += 0.25
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        name,
				Fired:       true,
				Weight:      0.25,
				Score:       0.25,
				Field:       "connection.downlink + connection.effectiveType",
				Actual:      fmt.Sprintf("%s downlink on %s", fmt.Sprintf("%.1fMbps", downlink), effType),
				Expected:    "Low downlink for 2g/3g",
				Severity:    "medium",
				Description: "Reported downlink is too high for the effective connection type.",
			})
		}

		// Phase 87: SaveData vs Platform
		saveData, hasSaveData := conn["saveData"].(bool)
		isDesktop := !strings.Contains(strings.ToLower(effType), "mobile")
		if hasSaveData && saveData && isDesktop && !strings.Contains(strings.ToLower(fmt.Sprint(navData["platform"])), "linux") {
			name := "suspicious_desktop_savedata"
			indicators = append(indicators, name)
			vec.Score += 0.15
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        name,
				Fired:       true,
				Weight:      0.15,
				Score:       0.15,
				Field:       "connection.saveData",
				Actual:      "true",
				Expected:    "false (on desktop)",
				Severity:    "low",
				Description: "SaveData is enabled on a desktop profile, which is suspicious.",
			})
		}
	}
	return indicators
}

func (na *navigatorAnalyzer) checkNetworkInformation(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	var rtt float64
	var hasRTT bool

	if conn, ok := navData["connection"].(map[string]interface{}); ok {
		rtt, hasRTT = conn["rtt"].(float64)
		downlink, _ := conn["downlink"].(float64)

		if rtt == 50 && downlink == 10 {
			indicators = append(indicators, "spoofed_network_api_detected")
			vec.Score += 0.4
		}

		if _, hasEffType := conn["effectiveType"].(string); !hasEffType {
			indicators = append(indicators, "missing_connection_effectiveType")
			vec.Score += 0.30
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "missing_connection_effective_type",
				Fired:       true,
				Weight:      0.30,
				Score:       0.30,
				Field:       "effectiveType",
				Actual:      "",
				Expected:    "4g",
				Severity:    "medium",
				Description: "navigator.connection.effectiveType is missing (Chrome always includes it)",
			})
		}

		ua, _ := navData["userAgent"].(string)
		isChrome := strings.Contains(strings.ToLower(ua), "chrome")
		if isChrome {
			if _, hasSaveData := conn["saveData"].(bool); !hasSaveData {
				indicators = append(indicators, "missing_connection_saveData")
				vec.Score += 0.30
				vec.CheckReports = append(vec.CheckReports, CheckReport{
					Name:        "missing_connection_saveData",
					Fired:       true,
					Weight:      0.30,
					Score:       0.30,
					Field:       "saveData",
					Actual:      "",
					Expected:    "true/false",
					Severity:    "medium",
					Description: "navigator.connection.saveData is missing. Chromium-based browsers always include this property.",
				})
			}
		}
	} else if r, ok := navData["connection_rtt"].(float64); ok {
		rtt = r
		hasRTT = true
		downlink, _ := navData["connection_downlink"].(float64)
		if rtt == 50 && downlink == 10 {
			indicators = append(indicators, "spoofed_network_api_detected")
			vec.Score += 0.4
		}
	}

	if hasRTT && rtt > 0 && int(rtt)%25 != 0 {
		indicators = append(indicators, fmt.Sprintf("non_quantized_rtt: %.0fms (not multiple of 25)", rtt))
		vec.Score += 0.3
	}

	if hasRTT {
		downlink := 0.0
		hasDownlink := false
		if conn, ok := navData["connection"].(map[string]interface{}); ok {
			downlink, hasDownlink = conn["downlink"].(float64)
		} else if dl, ok := navData["connection_downlink"].(float64); ok {
			downlink = dl
			hasDownlink = true
		}
		if hasDownlink {
			if rtt <= 50 && downlink < 3.0 {
				indicators = append(indicators, fmt.Sprintf("rtt_downlink_anticorrelated: rtt=%.0f downlink=%.1f (low RTT should have high downlink)", rtt, downlink))
				vec.Score += 0.35
			}
			if rtt >= 150 && downlink > 8.0 {
				indicators = append(indicators, fmt.Sprintf("rtt_downlink_anticorrelated: rtt=%.0f downlink=%.1f (high RTT should have low downlink)", rtt, downlink))
				vec.Score += 0.35
			}
		}
	}

	return indicators
}

func (na *navigatorAnalyzer) checkWebRTC(navData map[string]interface{}, vec *DetectionVector, indicators []string, reqUA string) []string {
	webrtc, ok := navData["webrtc_data"].(map[string]interface{})
	if !ok {
		// Chrome browsers (desktop) should always have WebRTC available.
		if strings.Contains(reqUA, "Chrome") && !strings.Contains(reqUA, "Mobile") {
			name := "missing_webrtc"
			indicators = append(indicators, name)
			vec.Score += 0.20
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        name,
				Fired:       true,
				Weight:      0.20,
				Score:       0.20,
				Field:       "RTCPeerConnection",
				Actual:      "missing webrtc_data",
				Expected:    "webrtc_data with ICE candidates",
				Severity:    "medium",
				Description: "Desktop Chrome environments should expose WebRTC metadata and candidate generation.",
			})
		}
		return indicators
	}

	iceCandidates, _ := webrtc["ice_candidates"].([]interface{})
	if len(iceCandidates) == 0 {
		indicators = append(indicators, "empty_ice_candidates")
		vec.Score += 0.25
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        "empty_ice_candidates",
			Fired:       true,
			Weight:      0.25,
			Score:       0.25,
			Field:       "RTCPeerConnection.onicecandidate",
			Actual:      "0 candidates",
			Expected:    "> 0 candidates (local/mDNS)",
			Severity:    "medium",
			Description: "Empty ICE candidates list is suspicious for a real browser environment.",
		})
	} else {
		// Check for suspicious candidate formats
		for _, c := range iceCandidates {
			cand, ok := c.(string)
			if !ok {
				continue
			}
			// Basic heuristic: ICE candidates usually have 'candidate:' prefix
			if !strings.HasPrefix(cand, "candidate:") {
				indicators = append(indicators, "suspicious_ice_format")
				vec.Score += 0.15
			}
		}
	}

	return indicators
}

func (na *navigatorAnalyzer) checkNavigatorConnectivity(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	if _, ok := navData["onLine"]; !ok {
		name := "missing_navigator_onLine"
		indicators = append(indicators, name)
		vec.Score += 0.15
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        name,
			Fired:       true,
			Weight:      0.15,
			Score:       0.15,
			Field:       "navigator.onLine",
			Actual:      "absent",
			Expected:    "present (true)",
			Severity:    "low",
			Description: "The Navigator.onLine property is missing, which is highly unusual for a connected browser session.",
		})
	}
	return indicators
}
