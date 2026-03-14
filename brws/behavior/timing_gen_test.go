package behavior

import (
	"math"
	"testing"

)

func TestGenerateChromeTiming_CSILoadTimesCoherence(t *testing.T) {
	// Run multiple seeds to verify consistency
	for seed := int64(1); seed <= 50; seed++ {
		timing := GenerateChromeTiming(seed)

		expectedStartE := timing.LoadTimes.RequestTime * 1000
		diff := math.Abs(timing.CSI.StartE - expectedStartE)

		if diff > 100 {
			t.Errorf("seed %d: startE=%.0f expected=%.0f diff=%.0fms (must be within 100ms)",
				seed, timing.CSI.StartE, expectedStartE, diff)
		}
		if diff > 5 {
			t.Errorf("seed %d: startE jitter=%.1fms is too large (expected <= 5ms)", seed, diff)
		}
	}
}

func TestGenerateChromeTiming_TimeOrdering(t *testing.T) {
	for seed := int64(1); seed <= 50; seed++ {
		timing := GenerateChromeTiming(seed)
		lt := timing.LoadTimes

		if lt.RequestTime >= lt.CommitLoadTime {
			t.Errorf("seed %d: requestTime (%.6f) should be < commitLoadTime (%.6f)",
				seed, lt.RequestTime, lt.CommitLoadTime)
		}
		if lt.CommitLoadTime >= lt.FinishDocumentLoadTime {
			t.Errorf("seed %d: commitLoadTime (%.6f) should be < finishDocumentLoadTime (%.6f)",
				seed, lt.CommitLoadTime, lt.FinishDocumentLoadTime)
		}
		if lt.FinishDocumentLoadTime >= lt.FinishLoadTime {
			t.Errorf("seed %d: finishDocumentLoadTime (%.6f) should be < finishLoadTime (%.6f)",
				seed, lt.FinishDocumentLoadTime, lt.FinishLoadTime)
		}
		if lt.StartLoadTime != lt.RequestTime {
			t.Errorf("seed %d: startLoadTime (%.6f) should equal requestTime (%.6f)",
				seed, lt.StartLoadTime, lt.RequestTime)
		}
		if lt.FirstPaintTime <= lt.CommitLoadTime {
			t.Errorf("seed %d: firstPaintTime (%.6f) should be > commitLoadTime (%.6f)",
				seed, lt.FirstPaintTime, lt.CommitLoadTime)
		}
	}
}

func TestGenerateChromeTiming_RealisticValues(t *testing.T) {
	for seed := int64(1); seed <= 50; seed++ {
		timing := GenerateChromeTiming(seed)
		lt := timing.LoadTimes

		// TTFB: 50-200ms
		ttfb := (lt.CommitLoadTime - lt.RequestTime) * 1000
		if ttfb < 50 || ttfb > 200 {
			t.Errorf("seed %d: TTFB=%.0fms (expected 50-200ms)", seed, ttfb)
		}

		// Total load time: should be < 5s
		totalLoad := (lt.FinishLoadTime - lt.RequestTime) * 1000
		if totalLoad > 5000 {
			t.Errorf("seed %d: total load=%.0fms (expected < 5000ms)", seed, totalLoad)
		}
		if totalLoad < 100 {
			t.Errorf("seed %d: total load=%.0fms (suspiciously fast, expected > 100ms)", seed, totalLoad)
		}

		// onLoadT should match total load time
		expectedOnLoad := (lt.FinishLoadTime - lt.RequestTime) * 1000
		onLoadDiff := math.Abs(timing.CSI.OnLoadT - expectedOnLoad)
		if onLoadDiff > 5 {
			t.Errorf("seed %d: onLoadT=%.1f expected=%.1f diff=%.1f", seed, timing.CSI.OnLoadT, expectedOnLoad, onLoadDiff)
		}

		// pageT should be reasonable (100-5000ms)
		if timing.CSI.PageT < 100 || timing.CSI.PageT > 10000 {
			t.Errorf("seed %d: pageT=%.0fms (expected 100-10000ms)", seed, timing.CSI.PageT)
		}

		// Navigation type should be valid
		validNavTypes := map[string]bool{"Other": true, "BackForward": true, "Reload": true}
		if !validNavTypes[lt.NavigationType] {
			t.Errorf("seed %d: invalid navigationType=%q", seed, lt.NavigationType)
		}
	}
}

func TestGeneratePerformanceTiming_HasValidURLs(t *testing.T) {
	for seed := int64(1); seed <= 20; seed++ {
		perf := GeneratePerformanceTiming("https://example.com/page", seed)

		for i, entry := range perf.Entries {
			if entry.URL == "" {
				t.Errorf("seed %d: entry[%d] has empty URL (name=%q entryType=%q)", seed, i, entry.Name, entry.EntryType)
			}
			if entry.Name == "" {
				t.Errorf("seed %d: entry[%d] has empty Name", seed, i)
			}
		}
	}
}

func TestGeneratePerformanceTiming_HasNavigation(t *testing.T) {
	for seed := int64(1); seed <= 20; seed++ {
		perf := GeneratePerformanceTiming("https://example.com/", seed)

		if len(perf.Entries) == 0 {
			t.Fatalf("seed %d: no entries generated", seed)
		}

		if perf.Entries[0].EntryType != "navigation" {
			t.Errorf("seed %d: first entry type=%q (expected 'navigation')", seed, perf.Entries[0].EntryType)
		}

		if perf.Entries[0].URL != "https://example.com/" {
			t.Errorf("seed %d: navigation entry URL=%q (expected page URL)", seed, perf.Entries[0].URL)
		}
	}
}

func TestGeneratePerformanceTiming_OrderedTimings(t *testing.T) {
	for seed := int64(1); seed <= 20; seed++ {
		perf := GeneratePerformanceTiming("https://example.com/", seed)

		// Group by entry type — resource entries should have increasing start times
		var resourceStarts []float64
		for _, entry := range perf.Entries {
			if entry.EntryType == "resource" {
				resourceStarts = append(resourceStarts, entry.StartTime)
			}
		}

		for i := 1; i < len(resourceStarts); i++ {
			if resourceStarts[i] < resourceStarts[i-1] {
				t.Errorf("seed %d: resource start times not ordered: [%d]=%.1f < [%d]=%.1f",
					seed, i, resourceStarts[i], i-1, resourceStarts[i-1])
			}
		}

		// Navigation entry should have startTime=0
		if len(perf.Entries) > 0 && perf.Entries[0].StartTime != 0 {
			t.Errorf("seed %d: navigation startTime=%.1f (expected 0)", seed, perf.Entries[0].StartTime)
		}
	}
}

func TestGeneratePerformanceTiming_EntryCount(t *testing.T) {
	for seed := int64(1); seed <= 20; seed++ {
		perf := GeneratePerformanceTiming("https://example.com/", seed)

		// Should have at least 5 entries (nav + 2 paints + at least 2 resources)
		if len(perf.Entries) < 5 {
			t.Errorf("seed %d: only %d entries (expected >= 5)", seed, len(perf.Entries))
		}
	}
}

func TestChromeTiming_PassesShieldCheck(t *testing.T) {
	// Replicate the shield's checkCSITiming logic exactly:
	// if abs(startE - requestTime*1000) > 100 => detected
	for seed := int64(1); seed <= 100; seed++ {
		timing := GenerateChromeTiming(seed)

		// Build navData map as the shield expects
		navData := map[string]interface{}{
			"chrome_csi": map[string]interface{}{
				"startE": timing.CSI.StartE,
			},
			"chrome_loadTimes": map[string]interface{}{
				"requestTime": timing.LoadTimes.RequestTime,
			},
		}

		// Extract values exactly as the shield does
		csi := navData["chrome_csi"].(map[string]interface{})
		lt := navData["chrome_loadTimes"].(map[string]interface{})
		startE := csi["startE"].(float64)
		requestTime := lt["requestTime"].(float64)

		expectedStartE := requestTime * 1000
		diff := startE - expectedStartE
		if diff < 0 {
			diff = -diff
		}

		if diff > 100 {
			t.Errorf("seed %d: shield would detect timing mismatch (startE=%.0f expected=%.0f diff=%.0fms, threshold=100ms)",
				seed, startE, expectedStartE, diff)
		}
	}
}

func TestChromeTiming_IntegrationWithGenerator(t *testing.T) {
	config := DefaultGeneratorConfig()
	config.Seed = 42
	config.PageURL = "https://example.com/test"

	gen := NewEventGenerator(config)
	data := gen.Generate()

	if data.ChromeTiming == nil {
		t.Fatal("ChromeTiming should be generated when EvadeTimingCoherence is true")
	}
	if data.PerformanceTiming == nil {
		t.Fatal("PerformanceTiming should be generated when EvadeTimingCoherence is true")
	}

	// Verify coherence
	expectedStartE := data.ChromeTiming.LoadTimes.RequestTime * 1000
	diff := math.Abs(data.ChromeTiming.CSI.StartE - expectedStartE)
	if diff > 100 {
		t.Errorf("generated timing failed coherence check: diff=%.1fms", diff)
	}

	// Verify performance entries have valid URLs
	for i, entry := range data.PerformanceTiming.Entries {
		if entry.URL == "" {
			t.Errorf("performance entry[%d] has empty URL", i)
		}
	}
}

func TestChromeTiming_DisabledWhenNotConfigured(t *testing.T) {
	config := DefaultGeneratorConfig()
	config.Seed = 42
	config.EvadeTimingCoherence = false

	gen := NewEventGenerator(config)
	data := gen.Generate()

	if data.ChromeTiming != nil {
		t.Error("ChromeTiming should be nil when EvadeTimingCoherence is false")
	}
	if data.PerformanceTiming != nil {
		t.Error("PerformanceTiming should be nil when EvadeTimingCoherence is false")
	}
}
