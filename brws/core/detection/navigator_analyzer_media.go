package detection

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/skunkworq/stealth/brws/core/constants"
)

func (na *navigatorAnalyzer) checkMediaDevices(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	devices, _ := navData["media_devices"].([]interface{})

	if len(devices) == 0 {
		indicators = append(indicators, "empty_media_devices")
		vec.Score += 0.25
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        "empty_media_devices",
			Fired:       true,
			Weight:      0.25,
			Score:       0.25,
			Field:       "navigator.mediaDevices.enumerateDevices()",
			Actual:      "0 devices",
			Expected:    "> 0 devices (mic/camera/speakers)",
			Severity:    "medium",
			Description: "Empty media devices list is highly suspicious for a real user device.",
		})
		return indicators
	}

	for _, d := range devices {
		device, ok := d.(map[string]interface{})
		if !ok {
			continue
		}

		deviceId, _ := device["deviceId"].(string)
		groupId, _ := device["groupId"].(string)
		kind, _ := device["kind"].(string)

		// deviceId is empty if permissions are not granted (prompt state)
		// but groupId is usually still present as a session-persistent identifier.
		if groupId == "" {
			indicators = append(indicators, "suspicious_media_device_id")
			vec.Score += 0.15
		}

		// Real browser deviceIds are usually 64-character hex strings (hashes)
		// but "default" is also used for the primary device.
		if len(deviceId) > 0 && deviceId != "default" && len(deviceId) != 64 {
			indicators = append(indicators, "non_standard_media_device_id_format")
			vec.Score += 0.10
		}

		if kind == "" {
			indicators = append(indicators, "missing_media_device_kind")
			vec.Score += 0.10
		}
	}

	return indicators
}

func (na *navigatorAnalyzer) checkAudioLatency(req *http.Request, vec *DetectionVector, indicators []string) []string {
	if audioHeader := req.Header.Get(constants.HeaderAudioData); audioHeader != "" {
		var audioData map[string]interface{}
		if err := json.Unmarshal([]byte(audioHeader), &audioData); err == nil {
			if outputLatency, hasOL := audioData["output_latency"].(float64); hasOL {
				if outputLatency == 0.0 {
					indicators = append(indicators, "audio_zero_output_latency")
					vec.Score += 0.20
					vec.CheckReports = append(vec.CheckReports, CheckReport{
						Name:        "audio_zero_output_latency",
						Fired:       true,
						Weight:      0.20,
						Score:       0.20,
						Field:       "output_latency",
						Actual:      "0.0",
						Expected:    "0.005-0.05 (real hardware latency)",
						Severity:    "medium",
						Description: "AudioContext.outputLatency=0 indicates no real audio hardware connection",
					})
				}
			}
		}
	}
	return indicators
}

func (na *navigatorAnalyzer) checkAudioBaseLatency(req *http.Request, vec *DetectionVector, indicators []string) []string {
	if audioHeader := req.Header.Get(constants.HeaderAudioData); audioHeader != "" {
		var audioData map[string]interface{}
		if err := json.Unmarshal([]byte(audioHeader), &audioData); err == nil {
			if baseLatency, hasBL := audioData["base_latency"].(float64); hasBL {
				if baseLatency == 0.0 {
					indicators = append(indicators, "audio_zero_base_latency")
					vec.Score += 0.20
					vec.CheckReports = append(vec.CheckReports, CheckReport{
						Name:        "audio_zero_base_latency",
						Fired:       true,
						Weight:      0.20,
						Score:       0.20,
						Field:       "base_latency",
						Actual:      "0.0",
						Expected:    "0.002-0.005",
						Severity:    "medium",
						Description: "AudioContext.baseLatency=0 is suspicious and common in headless environments.",
					})
				}
			} else {
				// Base latency is missing, which is also suspicious for modern browsers
				indicators = append(indicators, "missing_audio_base_latency")
				vec.Score += 0.15
			}
		}
	}
	return indicators
}

func (na *navigatorAnalyzer) checkAudioWorklet(navData map[string]interface{}, vec *DetectionVector, indicators []string, ua string) []string {
	// Only for modern browsers
	uaLower := strings.ToLower(ua)
	isChrome := strings.Contains(uaLower, "chrome")
	isFirefox := strings.Contains(uaLower, "firefox")

	if isChrome || isFirefox {
		awAvailable, ok := navData["audio_worklet_available"].(bool)
		// If it's explicitly false or missing in a modern browser navigator data (if reported there)
		if ok && !awAvailable {
			indicators = append(indicators, "missing_audio_worklet")
			vec.Score += 0.4
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "missing_audio_worklet",
				Fired:       true,
				Weight:      0.4,
				Score:       0.4,
				Field:       "audioWorklet",
				Actual:      "false/missing",
				Expected:    "true",
				Severity:    "high",
				Description: "BaseAudioContext.audioWorklet is missing, which is standard in modern browsers and often absent in restricted or older bot environments.",
			})
		}
	}
	return indicators
}

func (na *navigatorAnalyzer) checkPDFViewer(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	if pdfViewer, hasPdfViewer := navData["pdfViewerEnabled"]; hasPdfViewer {
		pdfBool, isBool := pdfViewer.(bool)
		if isBool && !pdfBool {
			indicators = append(indicators, "pdfViewerEnabled_false_modern_browser")
			vec.Score += 0.25
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "pdf_viewer_disabled",
				Fired:       true,
				Weight:      0.25,
				Score:       0.25,
				Field:       "pdfViewerEnabled",
				Actual:      "false",
				Expected:    "true (all modern browsers)",
				Severity:    "medium",
				Description: "navigator.pdfViewerEnabled=false is inconsistent with modern Chrome/Firefox UAs",
			})
		}
	}
	return indicators
}

func (na *navigatorAnalyzer) checkVideoElement(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	if video, ok := navData["video_can_play_mp4"].(string); ok {
		if video == "probably" {
			indicators = append(indicators, "spoofed_video_element_detected")
			vec.Score += 0.3
		}
	}
	return indicators
}
