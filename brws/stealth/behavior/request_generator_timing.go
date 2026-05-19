package behavior

import (
	"encoding/json"
	"strings"
	"time"
)

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
