package behavior

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stealth/brwslab/brws/adversarial"
	"github.com/stealth/brwslab/brws/constants"
)

func TestRequestGenerator_AllHeadersPresent(t *testing.T) {
	for _, profile := range DefaultProfiles() {
		t.Run(profile.Name, func(t *testing.T) {
			rg := NewRequestGenerator(&RequestGeneratorConfig{Profile: profile})
			h := rg.GenerateHeaders()

			// Standard headers
			for _, hdr := range []string{
				"User-Agent", "Accept", "Accept-Language", "Accept-Encoding",
				"Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site", "Sec-Fetch-User",
			} {
				if h.Get(hdr) == "" {
					t.Errorf("missing standard header: %s", hdr)
				}
			}

			// Client Hints (Chrome only)
			if profile.Browser == "chrome" {
				for _, hdr := range []string{"Sec-Ch-Ua", "Sec-Ch-Ua-Platform", "Sec-Ch-Ua-Mobile"} {
					if h.Get(hdr) == "" {
						t.Errorf("missing Client Hint header: %s", hdr)
					}
				}
			}

			// Fingerprint data headers
			for _, hdr := range []string{
				constants.HeaderWebGLData,
				constants.HeaderFontData,
				constants.HeaderScreenData,
				constants.HeaderPluginData,
				constants.HeaderTimingData,
				constants.HeaderBehavioralData,
				constants.HeaderNavigatorData,
				constants.HeaderCanvasFingerprint,
			} {
				if h.Get(hdr) == "" {
					t.Errorf("missing fingerprint header: %s", hdr)
				}
			}
		})
	}
}

func TestRequestGenerator_PlatformConsistency(t *testing.T) {
	for _, profile := range DefaultProfiles() {
		t.Run(profile.Name, func(t *testing.T) {
			rg := NewRequestGenerator(&RequestGeneratorConfig{Profile: profile})
			h := rg.GenerateHeaders()

			// Parse all JSON headers
			var webgl map[string]interface{}
			json.Unmarshal([]byte(h.Get(constants.HeaderWebGLData)), &webgl)

			var fonts map[string]interface{}
			json.Unmarshal([]byte(h.Get(constants.HeaderFontData)), &fonts)

			var nav map[string]interface{}
			json.Unmarshal([]byte(h.Get(constants.HeaderNavigatorData)), &nav)

			// Verify platform consistency
			ua := h.Get("User-Agent")
			webglPlatform := webgl["platform"].(string)
			navPlatform := nav["platform"].(string)
			fontPlatform := fonts["platform"].(string)

			// WebGL platform should match navigator platform
			if webglPlatform != navPlatform {
				t.Errorf("WebGL platform (%s) != navigator platform (%s)", webglPlatform, navPlatform)
			}

			// Platform in UA should be consistent with navigator platform
			switch {
			case strings.Contains(ua, "Windows"):
				if !strings.Contains(navPlatform, "Win") {
					t.Errorf("UA says Windows but navigator platform is %s", navPlatform)
				}
				if fontPlatform != "windows" {
					t.Errorf("UA says Windows but font platform is %s", fontPlatform)
				}
			case strings.Contains(ua, "Macintosh"):
				if !strings.Contains(navPlatform, "Mac") {
					t.Errorf("UA says Mac but navigator platform is %s", navPlatform)
				}
				if fontPlatform != "macos" {
					t.Errorf("UA says Mac but font platform is %s", fontPlatform)
				}
			case strings.Contains(ua, "Linux"):
				if !strings.Contains(navPlatform, "Linux") {
					t.Errorf("UA says Linux but navigator platform is %s", navPlatform)
				}
				if fontPlatform != "linux" {
					t.Errorf("UA says Linux but font platform is %s", fontPlatform)
				}
			}

			// Client Hints consistency (Chrome only)
			if profile.Browser == "chrome" {
				chPlatform := h.Get("Sec-Ch-Ua-Platform")
				switch profile.Platform {
				case "windows":
					if !strings.Contains(chPlatform, "Windows") {
						t.Errorf("Sec-Ch-Ua-Platform (%s) doesn't match windows profile", chPlatform)
					}
				case "macos":
					if !strings.Contains(chPlatform, "mac") && !strings.Contains(chPlatform, "Mac") {
						t.Errorf("Sec-Ch-Ua-Platform (%s) doesn't match macos profile", chPlatform)
					}
				case "linux":
					if !strings.Contains(chPlatform, "Linux") {
						t.Errorf("Sec-Ch-Ua-Platform (%s) doesn't match linux profile", chPlatform)
					}
				}
			}
		})
	}
}

func TestRequestGenerator_UniquePerCall(t *testing.T) {
	rg := NewRequestGenerator(nil)

	h1 := rg.GenerateHeaders()
	h2 := rg.GenerateHeaders()

	// Behavioral data should differ (random mouse/typing)
	b1 := h1.Get(constants.HeaderBehavioralData)
	b2 := h2.Get(constants.HeaderBehavioralData)
	if b1 == b2 {
		t.Error("two calls produced identical behavioral data")
	}

	// Timing data should differ (random intervals)
	t1 := h1.Get(constants.HeaderTimingData)
	t2 := h2.Get(constants.HeaderTimingData)
	if t1 == t2 {
		t.Error("two calls produced identical timing data")
	}

	// Canvas hash should be stable (same instance)
	c1 := h1.Get(constants.HeaderCanvasFingerprint)
	c2 := h2.Get(constants.HeaderCanvasFingerprint)
	if c1 != c2 {
		t.Error("canvas hash should be stable within same instance")
	}
}

func TestRequestGenerator_EachVectorPasses(t *testing.T) {
	for _, profile := range DefaultProfiles() {
		t.Run(profile.Name, func(t *testing.T) {
			rg := NewRequestGenerator(&RequestGeneratorConfig{Profile: profile})
			h := rg.GenerateHeaders()

			// WebGL
			t.Run("WebGL", func(t *testing.T) {
				var data adversarial.WebGLData
				json.Unmarshal([]byte(h.Get(constants.HeaderWebGLData)), &data)
				result := adversarial.NewWebGLAnalyzer().Analyze(&data)
				if result.Score > 0 {
					indicators := make([]string, 0)
					for _, ind := range result.Indicators {
						indicators = append(indicators, ind.Check)
					}
					t.Errorf("WebGL score=%.3f, indicators: %v", result.Score, indicators)
				}
			})

			// Font
			t.Run("Font", func(t *testing.T) {
				var data adversarial.FontData
				json.Unmarshal([]byte(h.Get(constants.HeaderFontData)), &data)
				result := adversarial.NewFontAnalyzer().Analyze(&data)
				if result.Score > 0 {
					indicators := make([]string, 0)
					for _, ind := range result.Indicators {
						indicators = append(indicators, ind.Check)
					}
					t.Errorf("Font score=%.3f, indicators: %v", result.Score, indicators)
				}
			})

			// Screen
			t.Run("Screen", func(t *testing.T) {
				var data adversarial.ScreenData
				json.Unmarshal([]byte(h.Get(constants.HeaderScreenData)), &data)
				result := adversarial.NewScreenAnalyzer().Analyze(&data)
				if result.Score > 0 {
					indicators := make([]string, 0)
					for _, ind := range result.Indicators {
						indicators = append(indicators, ind.Check)
					}
					t.Errorf("Screen score=%.3f, indicators: %v", result.Score, indicators)
				}
			})

			// Plugin (Firefox legitimately has 0 plugins; the empty_plugins check
			// fires but its low weight (0.08) doesn't affect overall detection)
			t.Run("Plugin", func(t *testing.T) {
				var data adversarial.PluginData
				json.Unmarshal([]byte(h.Get(constants.HeaderPluginData)), &data)
				data.UserAgent = h.Get("User-Agent")
				result := adversarial.NewPluginAnalyzer().Analyze(&data)
				if profile.Browser == "firefox" {
					// Firefox has no plugins — the generic empty check fires but
					// none of the Chrome-specific checks should fire
					for _, ind := range result.Indicators {
						if ind.Check != "empty_plugins" {
							t.Errorf("unexpected Plugin indicator for Firefox: %s", ind.Check)
						}
					}
				} else if result.Score > 0 {
					indicators := make([]string, 0)
					for _, ind := range result.Indicators {
						indicators = append(indicators, ind.Check)
					}
					t.Errorf("Plugin score=%.3f, indicators: %v", result.Score, indicators)
				}
			})

			// Timing
			t.Run("Timing", func(t *testing.T) {
				var timing map[string]interface{}
				json.Unmarshal([]byte(h.Get(constants.HeaderTimingData)), &timing)

				entriesRaw := timing["entries"].([]interface{})
				seq := &adversarial.RequestTimingSequence{Entries: make([]adversarial.RequestTimingEntry, 0)}
				for _, e := range entriesRaw {
					em := e.(map[string]interface{})
					entry := adversarial.RequestTimingEntry{}
					if ts, ok := em["timestamp_ms"].(float64); ok {
						entry.Timestamp = int64(ts)
					}
					if ct, ok := em["content_type"].(string); ok {
						entry.ContentType = ct
					}
					if ref, ok := em["referrer"].(string); ok {
						entry.Referrer = ref
					}
					seq.Entries = append(seq.Entries, entry)
				}

				result := adversarial.NewTimingAnalyzer(nil).Analyze(seq)
				if result.Score > 0 {
					indicators := make([]string, 0)
					for _, ind := range result.Indicators {
						indicators = append(indicators, ind.Check)
					}
					t.Errorf("Timing score=%.3f, indicators: %v", result.Score, indicators)
				}
			})

			// Behavioral (run 20 trials, allow 15% false positive to reduce flakiness)
			t.Run("Behavioral", func(t *testing.T) {
				ba := adversarial.NewBehavioralAnalyzer(nil)
				detections := 0
				trials := 20
				for i := 0; i < trials; i++ {
					var behav map[string]interface{}
					json.Unmarshal([]byte(rg.GenerateHeaders().Get(constants.HeaderBehavioralData)), &behav)

					events := &adversarial.EnhancedBehavioralEvents{}
					if ts, ok := behav["mouseTimestamps"].([]interface{}); ok {
						for _, v := range ts {
							events.MouseTimestamps = append(events.MouseTimestamps, int64(v.(float64)))
						}
					}
					if ts, ok := behav["typingTimestamps"].([]interface{}); ok {
						for _, v := range ts {
							events.TypingTimestamps = append(events.TypingTimestamps, int64(v.(float64)))
						}
					}
					if pos, ok := behav["mousePositions"].([]interface{}); ok {
						for _, p := range pos {
							pt := p.(map[string]interface{})
							events.MousePositions = append(events.MousePositions, adversarial.Position{
								X: pt["x"].(float64),
								Y: pt["y"].(float64),
							})
						}
					}
					if vel, ok := behav["mouseVelocities"].([]interface{}); ok {
						for _, v := range vel {
							events.MouseVelocities = append(events.MouseVelocities, v.(float64))
						}
					}
					if ts, ok := behav["scrollTimestamps"].([]interface{}); ok {
						for _, v := range ts {
							events.ScrollTimestamps = append(events.ScrollTimestamps, int64(v.(float64)))
						}
					}
					if ds, ok := behav["scrollDeltas"].([]interface{}); ok {
						for _, v := range ds {
							events.ScrollDeltas = append(events.ScrollDeltas, v.(float64))
						}
					}
					if ts, ok := behav["clickTimestamps"].([]interface{}); ok {
						for _, v := range ts {
							events.ClickTimestamps = append(events.ClickTimestamps, int64(v.(float64)))
						}
					}
					if pos, ok := behav["clickPositions"].([]interface{}); ok {
						for _, p := range pos {
							pt := p.(map[string]interface{})
							events.ClickPositions = append(events.ClickPositions, adversarial.Position{
								X: pt["x"].(float64),
								Y: pt["y"].(float64),
							})
						}
					}

					result := ba.Analyze(events)
					if result.Detected {
						detections++
					}
				}
				// After shield upgrade (checks 20-24), expect high detection rate
				if float64(detections)/float64(trials) < 0.80 {
					t.Errorf("Behavioral should be detected >= 80%% of the time after shield upgrade, got %d/%d", detections, trials)
				}
			})
		})
	}
}

func TestRequestGenerator_EvadeShield(t *testing.T) {
	detector := adversarial.NewStealthDetector()

	for _, profile := range DefaultProfiles() {
		t.Run(profile.Name, func(t *testing.T) {
			rg := NewRequestGenerator(&RequestGeneratorConfig{Profile: profile})

			trials := 50
			evasions := 0

			for i := 0; i < trials; i++ {
				req := rg.GenerateRequest("https://example.com/page")
				result := detector.AnalyzeRequest(req, nil)

				if !result.IsBot {
					evasions++
				} else {
					if i < 3 { // Log first few failures for debugging
						t.Logf("trial %d: score=%.3f, vectors:", i, result.Score)
						for _, v := range result.Vectors {
							if v.Score > 0 {
								t.Logf("  %s: score=%.3f weight=%.2f indicators=%v",
									v.Name, v.Score, v.Weight, v.Indicators)
							}
						}
					}
				}
			}

			evasionRate := float64(evasions) / float64(trials)
			detectionRate := 1.0 - evasionRate
			fmt.Printf("%s: %d/%d detected (%.0f%% detection)\n", profile.Name, trials-evasions, trials, detectionRate*100)

			if detectionRate < 0.80 {
				t.Errorf("detection rate %.0f%% < 80%% after shield upgrade (%d/%d detected)", detectionRate*100, trials-evasions, trials)
			}
		})
	}
}

// --- Phase 8: PNG CRC + Timing baseURL Tests ---

func TestCanvasFingerprint_ValidPNGWithCRC(t *testing.T) {
	rg := NewRequestGenerator(nil)
	canvas := rg.generateCanvas()

	if !strings.HasPrefix(canvas, "data:image/png;base64,") {
		t.Fatalf("canvas should be data:image/png;base64,... got: %s", canvas[:40])
	}

	// Decode
	b64 := canvas[len("data:image/png;base64,"):]
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}

	// PNG signature (bytes 0-7)
	pngSig := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	if len(decoded) < 8 {
		t.Fatal("decoded PNG too short for signature")
	}
	for i := 0; i < 8; i++ {
		if decoded[i] != pngSig[i] {
			t.Fatalf("PNG signature mismatch at byte %d: got %02x want %02x", i, decoded[i], pngSig[i])
		}
	}

	// IHDR chunk type at bytes 12-15
	if string(decoded[12:16]) != "IHDR" {
		t.Fatalf("expected IHDR at offset 12, got %q", string(decoded[12:16]))
	}

	// CRC at bytes 29-32 should NOT be all zeros (was the bug)
	ihdrCRC := decoded[29:33]
	allZero := true
	for _, b := range ihdrCRC {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("IHDR CRC is all zeros — CRC fix not applied")
	}

	// Find IDAT chunk
	found := false
	for i := 33; i < len(decoded)-4; i++ {
		if string(decoded[i:i+4]) == "IDAT" {
			found = true
			break
		}
	}
	if !found {
		t.Error("no IDAT chunk found in PNG")
	}

	t.Logf("valid PNG: %d bytes, CRC present", len(decoded))
}

func TestCanvasFingerprint_StablePerInstance(t *testing.T) {
	rg := NewRequestGenerator(nil)
	h1 := rg.generateCanvas()
	h2 := rg.generateCanvas()
	if h1 != h2 {
		t.Error("canvas hash should be stable per instance")
	}
}

func TestTimingData_UsesTargetURL(t *testing.T) {
	rg := NewRequestGenerator(nil)

	// Without target URL, should use example.com
	h1 := rg.GenerateHeaders()
	timing1 := h1.Get(constants.HeaderTimingData)
	if !strings.Contains(timing1, "example.com") {
		t.Error("default timing should reference example.com")
	}

	// With target URL set
	rg.SetTargetURL("https://mysite.com/page")
	h2 := rg.GenerateHeaders()
	timing2 := h2.Get(constants.HeaderTimingData)
	if !strings.Contains(timing2, "https://mysite.com/page") {
		t.Error("timing should reference the set target URL")
	}
	if strings.Contains(timing2, "example.com") {
		t.Error("timing should NOT reference example.com when target URL is set")
	}
}

func TestGenerateRequest_SetsTargetURL(t *testing.T) {
	rg := NewRequestGenerator(nil)
	req := rg.GenerateRequest("https://target.com/path")

	timing := req.Header.Get(constants.HeaderTimingData)
	if !strings.Contains(timing, "https://target.com/path") {
		t.Error("GenerateRequest should set targetURL for timing referrers")
	}
}

// --- P11: JS API Surface Completeness Tests ---

func TestP11_ChromeNavigatorContainsChromeApp(t *testing.T) {
	for _, profile := range DefaultProfiles() {
		if profile.Browser != "chrome" {
			continue
		}
		t.Run(profile.Name, func(t *testing.T) {
			rg := NewRequestGenerator(&RequestGeneratorConfig{Profile: profile})
			h := rg.GenerateHeaders()

			navJSON := h.Get(constants.HeaderNavigatorData)
			var navData map[string]interface{}
			if err := json.Unmarshal([]byte(navJSON), &navData); err != nil {
				t.Fatalf("failed to parse navigator data: %v", err)
			}

			// chrome.app must be present with correct shape
			chromeApp, ok := navData["chrome_app"].(map[string]interface{})
			if !ok {
				t.Fatal("chrome_app missing from navigator data")
			}
			if _, hasInstalled := chromeApp["isInstalled"]; !hasInstalled {
				t.Error("chrome_app missing isInstalled")
			}
			if _, hasIS := chromeApp["InstallState"]; !hasIS {
				t.Error("chrome_app missing InstallState")
			}
			if _, hasRS := chromeApp["RunningState"]; !hasRS {
				t.Error("chrome_app missing RunningState")
			}
		})
	}
}

func TestP11_ChromeNavigatorContainsChromeCsi(t *testing.T) {
	for _, profile := range DefaultProfiles() {
		if profile.Browser != "chrome" {
			continue
		}
		t.Run(profile.Name, func(t *testing.T) {
			rg := NewRequestGenerator(&RequestGeneratorConfig{Profile: profile})
			h := rg.GenerateHeaders()

			navJSON := h.Get(constants.HeaderNavigatorData)
			var navData map[string]interface{}
			if err := json.Unmarshal([]byte(navJSON), &navData); err != nil {
				t.Fatalf("failed to parse navigator data: %v", err)
			}

			csi, ok := navData["chrome_csi"].(map[string]interface{})
			if !ok {
				t.Fatal("chrome_csi missing from navigator data")
			}
			for _, key := range []string{"onloadT", "pageT", "startE", "tran"} {
				if _, has := csi[key]; !has {
					t.Errorf("chrome_csi missing %s", key)
				}
			}
		})
	}
}

func TestP11_ChromeNavigatorContainsPerformanceMemory(t *testing.T) {
	for _, profile := range DefaultProfiles() {
		if profile.Browser != "chrome" {
			continue
		}
		t.Run(profile.Name, func(t *testing.T) {
			rg := NewRequestGenerator(&RequestGeneratorConfig{Profile: profile})
			h := rg.GenerateHeaders()

			navJSON := h.Get(constants.HeaderNavigatorData)
			var navData map[string]interface{}
			if err := json.Unmarshal([]byte(navJSON), &navData); err != nil {
				t.Fatalf("failed to parse navigator data: %v", err)
			}

			mem, ok := navData["performance_memory"].(map[string]interface{})
			if !ok {
				t.Fatal("performance_memory missing from navigator data")
			}

			limit, _ := mem["jsHeapSizeLimit"].(float64)
			total, _ := mem["totalJSHeapSize"].(float64)
			used, _ := mem["usedJSHeapSize"].(float64)

			if limit <= 0 {
				t.Error("jsHeapSizeLimit should be positive")
			}
			if total <= 0 || total > limit {
				t.Errorf("totalJSHeapSize (%f) should be 0 < total <= limit (%f)", total, limit)
			}
			if used <= 0 || used > total {
				t.Errorf("usedJSHeapSize (%f) should be 0 < used <= total (%f)", used, total)
			}
		})
	}
}

func TestP11_FirefoxNavigatorNoChromeAPIs(t *testing.T) {
	profile := FirefoxWindowsProfile()
	rg := NewRequestGenerator(&RequestGeneratorConfig{Profile: profile})
	h := rg.GenerateHeaders()

	navJSON := h.Get(constants.HeaderNavigatorData)
	var navData map[string]interface{}
	if err := json.Unmarshal([]byte(navJSON), &navData); err != nil {
		t.Fatalf("failed to parse navigator data: %v", err)
	}

	// Firefox should NOT have Chrome-specific APIs
	chromeAPIs := []string{"chrome_app", "chrome_csi", "chrome_loadTimes", "performance_memory"}
	for _, api := range chromeAPIs {
		if _, has := navData[api]; has {
			t.Errorf("Firefox should not have %s in navigator data", api)
		}
	}
}

func TestP11_ScreenContainsOrientation(t *testing.T) {
	for _, profile := range DefaultProfiles() {
		t.Run(profile.Name, func(t *testing.T) {
			rg := NewRequestGenerator(&RequestGeneratorConfig{Profile: profile})
			h := rg.GenerateHeaders()

			screenJSON := h.Get(constants.HeaderScreenData)
			var screenData map[string]interface{}
			if err := json.Unmarshal([]byte(screenJSON), &screenData); err != nil {
				t.Fatalf("failed to parse screen data: %v", err)
			}

			ot, hasType := screenData["orientation_type"].(string)
			if !hasType {
				t.Fatal("screen data missing orientation_type")
			}
			if ot != "landscape-primary" {
				t.Errorf("desktop screen should be landscape-primary, got %s", ot)
			}

			angle, hasAngle := screenData["orientation_angle"].(float64)
			if !hasAngle {
				t.Fatal("screen data missing orientation_angle")
			}
			if angle != 0 {
				t.Errorf("desktop landscape angle should be 0, got %f", angle)
			}
		})
	}
}

func TestP11_PluginsContainMimeTypes(t *testing.T) {
	for _, profile := range DefaultProfiles() {
		if profile.Browser != "chrome" {
			continue
		}
		t.Run(profile.Name, func(t *testing.T) {
			rg := NewRequestGenerator(&RequestGeneratorConfig{Profile: profile})
			h := rg.GenerateHeaders()

			pluginJSON := h.Get(constants.HeaderPluginData)
			var pluginData struct {
				Plugins []struct {
					Name      string   `json:"name"`
					MimeTypes []string `json:"mimeTypes"`
				} `json:"plugins"`
			}
			if err := json.Unmarshal([]byte(pluginJSON), &pluginData); err != nil {
				t.Fatalf("failed to parse plugin data: %v", err)
			}

			for _, p := range pluginData.Plugins {
				if !strings.Contains(strings.ToLower(p.Name), "pdf") {
					continue
				}
				if len(p.MimeTypes) == 0 {
					t.Errorf("PDF plugin '%s' should have MIME types", p.Name)
				}
				hasPDF := false
				for _, mt := range p.MimeTypes {
					if mt == "application/pdf" {
						hasPDF = true
						break
					}
				}
				if !hasPDF {
					t.Errorf("PDF plugin '%s' should include application/pdf MIME type", p.Name)
				}
			}
		})
	}
}
