package adversarial

import (
	"fmt"
	"math"
	"strings"
)

// TimingAnalyzerConfig configures timing analysis thresholds.
type TimingAnalyzerConfig struct {
	MaxFixedIntervalCV float64  // CV below this = fixed intervals (bot)
	MinRequestGapMs    float64  // Gaps below this = too fast
	ExpectedOrder      []string // Expected resource loading order
}

// DefaultTimingAnalyzerConfig returns sensible defaults.
func DefaultTimingAnalyzerConfig() *TimingAnalyzerConfig {
	return &TimingAnalyzerConfig{
		MaxFixedIntervalCV: 0.15,
		MinRequestGapMs:    50.0,
		ExpectedOrder: []string{
			"text/html",
			"text/css",
			"application/javascript",
			"image/",
			"font/",
		},
	}
}

// TimingAnalyzer performs multi-request timing analysis.
type TimingAnalyzer struct {
	config *TimingAnalyzerConfig
}

// NewTimingAnalyzer creates a new TimingAnalyzer.
func NewTimingAnalyzer(config *TimingAnalyzerConfig) *TimingAnalyzer {
	if config == nil {
		config = DefaultTimingAnalyzerConfig()
	}
	return &TimingAnalyzer{config: config}
}

// RequestTimingEntry represents timing data for a single request.
type RequestTimingEntry struct {
	Timestamp       int64  `json:"timestamp_ms"`
	URL             string `json:"url"`
	ContentType     string `json:"content_type"`
	Referrer        string `json:"referrer"`
	Duration        int64  `json:"duration_ms"`
	TransferSize    int64  `json:"transfer_size"`
	EncodedBodySize int64  `json:"encoded_body_size"`
	Protocol        string `json:"next_hop_protocol"`
}

// PaintTimingEntry represents a performance paint entry.
type PaintTimingEntry struct {
	Name      string  `json:"name"`
	StartTime float64 `json:"start_time"`
}

// RequestTimingSequence represents a sequence of requests for analysis.
type RequestTimingSequence struct {
	Entries         []RequestTimingEntry `json:"entries"`
	PaintEntries    []PaintTimingEntry   `json:"paint_entries"`
	TTFB            float64              `json:"ttfb"`
	NavigationStart float64              `json:"navigationStart"`
	LoadEventEnd    float64              `json:"loadEventEnd"`
}

// NewRequestTimingSequenceFromMap populates RequestTimingSequence from a map.
func NewRequestTimingSequenceFromMap(timing map[string]interface{}) *RequestTimingSequence {
	seq := &RequestTimingSequence{}

	if entriesRaw, ok := timing["entries"].([]interface{}); ok {
		seq.Entries = make([]RequestTimingEntry, 0, len(entriesRaw))
		for _, e := range entriesRaw {
			if em, ok := e.(map[string]interface{}); ok {
				entry := RequestTimingEntry{}
				if ts, ok := em["timestamp_ms"].(float64); ok {
					entry.Timestamp = int64(ts)
				}
				if url, ok := em["url"].(string); ok {
					entry.URL = url
				}
				if ct, ok := em["content_type"].(string); ok {
					entry.ContentType = ct
				}
				if ref, ok := em["referrer"].(string); ok {
					entry.Referrer = ref
				}
				if dur, ok := em["duration_ms"].(float64); ok {
					entry.Duration = int64(dur)
				}
				if ts, ok := em["transfer_size"].(float64); ok {
					entry.TransferSize = int64(ts)
				}
				if ebs, ok := em["encoded_body_size"].(float64); ok {
					entry.EncodedBodySize = int64(ebs)
				}
				if proto, ok := em["next_hop_protocol"].(string); ok {
					entry.Protocol = proto
				}
				seq.Entries = append(seq.Entries, entry)
			}
		}
	}

	if v, ok := timing["ttfb"].(float64); ok {
		seq.TTFB = v
	}
	if v, ok := timing["navigationStart"].(float64); ok {
		seq.NavigationStart = v
	}
	if v, ok := timing["loadEventEnd"].(float64); ok {
		seq.LoadEventEnd = v
	}

	if paintRaw, ok := timing["paint_entries"].([]interface{}); ok {
		seq.PaintEntries = make([]PaintTimingEntry, 0, len(paintRaw))
		for _, p := range paintRaw {
			if pm, ok := p.(map[string]interface{}); ok {
				entry := PaintTimingEntry{}
				if name, ok := pm["name"].(string); ok {
					entry.Name = name
				}
				if st, ok := pm["start_time"].(float64); ok {
					entry.StartTime = st
				}
				seq.PaintEntries = append(seq.PaintEntries, entry)
			}
		}
	}

	return seq
}

// Analyze runs the full timing analysis suite.
func (ta *TimingAnalyzer) Analyze(seq *RequestTimingSequence) *VectorResult {
	result := &VectorResult{
		Vector:     "Request Timing Analysis",
		Category:   VectorTiming,
		Detected:   false,
		Score:      0,
		Indicators: make([]VectorIndicator, 0),
	}

	if seq == nil {
		return result
	}

	// Legacy checks
	if seq.TTFB == 0 {
		result.Indicators = append(result.Indicators, VectorIndicator{Check: "zero_ttfb"})
		result.Score += 0.4
	}

	if seq.NavigationStart > 0 && seq.LoadEventEnd > 0 {
		totalTime := seq.LoadEventEnd - seq.NavigationStart
		if totalTime < 100 {
			result.Indicators = append(result.Indicators, VectorIndicator{Check: "too_fast_load"})
			result.Score += 0.3
		}
	}

	if len(seq.Entries) < 2 {
		return result
	}

	// Check 1: Fixed inter-request intervals
	intervals := computeIntervals(seq.Entries)
	if len(intervals) > 2 {
		fixedScore := ta.detectFixedIntervals(intervals)
		if fixedScore > 0 {
			weight := 0.35
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "fixed_intervals",
				Message: "Request intervals are suspiciously uniform",
				Weight:  weight,
				Field:   "interval_cv",
				Value:   fmt.Sprintf("%.4f", fixedScore),
			})
			result.Score += weight
		}
	}

	// Check 2: Wrong resource loading order
	orderScore := ta.validateResourceOrder(seq.Entries)
	if orderScore > 0 {
		weight := 0.30
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "wrong_resource_order",
			Message: "Resources loaded in non-browser order (e.g., CSS after images)",
			Weight:  weight,
			Field:   "resource_order",
			Value:   fmt.Sprintf("%.2f", orderScore),
		})
		result.Score += weight * orderScore
	}

	// Check 3: Broken referrer chain
	referrerScore := ta.validateReferrerChain(seq.Entries)
	if referrerScore > 0 {
		weight := 0.25
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "broken_referrer_chain",
			Message: "Sub-resources are missing referrer headers",
			Weight:  weight,
			Field:   "referrer_chain",
			Value:   fmt.Sprintf("%.2f", referrerScore),
		})
		result.Score += weight * referrerScore
	}

	// Check 4: Too few timing entries.
	// Real page loads involve 20-100+ sub-resource requests. Fewer than 10
	// entries suggests synthetic generation. Score is proportional to deficit.
	entryCount := len(seq.Entries)
	if entryCount < 10 {
		weight := 0.30
		// Score linearly from 1.0 (1 entry) to 0.0 (10 entries)
		deficit := float64(10-entryCount) / 9.0
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "too_few_timing_entries",
			Message: fmt.Sprintf("Only %d timing entries (real pages have 20-100+)", entryCount),
			Weight:  weight,
			Field:   "entry_count",
			Value:   fmt.Sprintf("%d", entryCount),
		})
		result.Score += weight * deficit
	}

	// Check 5: Too-fast request gaps
	tooFastCount := 0
	for _, interval := range intervals {
		if interval < ta.config.MinRequestGapMs {
			tooFastCount++
		}
	}
	if len(intervals) > 0 && float64(tooFastCount)/float64(len(intervals)) > 0.5 {
		weight := 0.30
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "too_fast_gaps",
			Message: fmt.Sprintf("%.0f%% of request gaps are under %.0fms", float64(tooFastCount)/float64(len(intervals))*100, ta.config.MinRequestGapMs),
			Weight:  weight,
			Field:   "fast_gap_ratio",
			Value:   fmt.Sprintf("%.2f", float64(tooFastCount)/float64(len(intervals))),
		})
		result.Score += weight
	}

	// Check 6: Missing or suspicious byte counts (Phase 72)
	byteScore := ta.validateByteCounts(seq.Entries)
	if byteScore > 0 {
		weight := 0.35
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "timing_missing_byte_counts",
			Message: "Resource timing byte counts (transferSize/encodedBodySize) are zero or constant",
			Weight:  weight,
			Field:   "transfer_size",
			Value:   fmt.Sprintf("%.2f", byteScore),
		})
		result.Score += weight * byteScore
	}

	// Check 7: Inconsistent protocols (Phase 72)
	protoScore := ta.validateProtocols(seq.Entries)
	if protoScore > 0 {
		weight := 0.25
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "timing_inconsistent_protocols",
			Message: "Resource timing protocols (nextHopProtocol) are missing or inconsistent",
			Weight:  weight,
			Field:   "next_hop_protocol",
			Value:   fmt.Sprintf("%.2f", protoScore),
		})
		result.Score += weight * protoScore
	}

	// Phase 84: Navigation Timing Consistency
	// Normalize to absolute timestamps if needed
	firstEntryTS := float64(seq.Entries[0].Timestamp)
	lastEntry := seq.Entries[len(seq.Entries)-1]
	lastEntryEnd := float64(lastEntry.Timestamp + lastEntry.Duration)

	navStart := seq.NavigationStart
	loadEnd := seq.LoadEventEnd

	// If timestamps are small, they are relative to navigationStart
	if firstEntryTS < 1e11 && navStart > 1e11 {
		firstEntryTS += navStart
		lastEntryEnd += navStart
	}

	if navStart > 0 {
		if navStart > firstEntryTS {
			weight := 0.45
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "timing_navigation_start_inconsistent",
				Message: fmt.Sprintf("navigationStart (%.0f) is after the first resource request (%.0f)", navStart, firstEntryTS),
				Weight:  weight,
				Field:   "navigationStart",
				Value:   fmt.Sprintf("%.0f", navStart),
			})
			result.Score += weight
		}
	}

	if loadEnd > 0 {
		if loadEnd < lastEntryEnd {
			weight := 0.40
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "timing_load_event_inconsistent",
				Message: fmt.Sprintf("loadEventEnd (%.0f) is before the last resource finished (%.0f)", loadEnd, lastEntryEnd),
				Weight:  weight,
				Field:   "loadEventEnd",
				Value:   fmt.Sprintf("%.0f", loadEnd),
			})
			result.Score += weight
		}
	}

	// Check 8: Paint Timing Consistency (Phase 90)
	paintScore := ta.checkPaintTiming(seq)
	if paintScore > 0 {
		weight := 0.40
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "timing_paint_mismatch",
			Message: "Performance paint entries are missing or inconsistent with navigation lifecycle",
			Weight:  weight,
			Field:   "paint_entries",
			Value:   "mismatch",
		})
		result.Score += weight * paintScore
	}

	result.Score = math.Min(1.0, result.Score)
	result.Detected = result.Score > 0.3

	return result
}

// detectFixedIntervals checks if inter-request intervals have suspiciously low
// coefficient of variation (CV). Returns a score: 0 = natural, 1 = perfectly fixed.
func (ta *TimingAnalyzer) detectFixedIntervals(intervals []float64) float64 {
	if len(intervals) < 3 {
		return 0
	}

	mean, stddev := meanStddev(intervals)
	if mean == 0 {
		return 1.0 // All zero intervals = bot
	}

	cv := stddev / mean
	if cv < ta.config.MaxFixedIntervalCV {
		// Scale: cv=0 → score=1, cv=threshold → score=0
		return 1.0 - (cv / ta.config.MaxFixedIntervalCV)
	}

	return 0
}

// validateResourceOrder checks if resources are loaded in the expected browser order.
// Real browsers load HTML → CSS → JS → Images → Fonts. Bots often don't.
func (ta *TimingAnalyzer) validateResourceOrder(requests []RequestTimingEntry) float64 {
	if len(requests) < 3 {
		return 0
	}

	orderViolations := 0
	totalChecks := 0

	for i := 0; i < len(requests)-1; i++ {
		for j := i + 1; j < len(requests); j++ {
			orderI := resourcePriority(requests[i].ContentType)
			orderJ := resourcePriority(requests[j].ContentType)

			if orderI >= 0 && orderJ >= 0 {
				totalChecks++
				// If a lower-priority resource appears before a higher-priority one
				if orderI > orderJ {
					orderViolations++
				}
			}
		}
	}

	if totalChecks == 0 {
		return 0
	}

	return float64(orderViolations) / float64(totalChecks)
}

// validateReferrerChain checks if sub-resources have proper referrer headers.
func (ta *TimingAnalyzer) validateReferrerChain(requests []RequestTimingEntry) float64 {
	if len(requests) < 2 {
		return 0
	}

	// First request shouldn't need a referrer
	missingReferrers := 0
	subResources := 0

	for i := 1; i < len(requests); i++ {
		ct := strings.ToLower(requests[i].ContentType)
		// Sub-resources (CSS, JS, images) should have referrers
		if strings.HasPrefix(ct, "text/css") ||
			strings.HasPrefix(ct, "application/javascript") ||
			strings.HasPrefix(ct, "image/") ||
			strings.HasPrefix(ct, "font/") {
			subResources++
			if requests[i].Referrer == "" {
				missingReferrers++
			}
		}
	}

	if subResources == 0 {
		return 0
	}

	return float64(missingReferrers) / float64(subResources)
}

// computeIntervals extracts inter-request time gaps in milliseconds.
func computeIntervals(entries []RequestTimingEntry) []float64 {
	intervals := make([]float64, 0, len(entries)-1)
	for i := 1; i < len(entries); i++ {
		gap := float64(entries[i].Timestamp - entries[i-1].Timestamp)
		if gap >= 0 {
			intervals = append(intervals, gap)
		}
	}
	return intervals
}

// resourcePriority returns loading priority for resource types.
// Lower = should load first. -1 = unknown type.
func resourcePriority(contentType string) int {
	ct := strings.ToLower(contentType)
	switch {
	case strings.HasPrefix(ct, "text/html"):
		return 0
	case strings.HasPrefix(ct, "text/css"):
		return 1
	case strings.HasPrefix(ct, "application/javascript"), strings.HasPrefix(ct, "text/javascript"):
		return 2
	case strings.HasPrefix(ct, "image/"):
		return 3
	case strings.HasPrefix(ct, "font/"):
		return 4
	default:
		return -1
	}
}

func (ta *TimingAnalyzer) validateByteCounts(entries []RequestTimingEntry) float64 {
	if len(entries) < 5 {
		return 0
	}

	var zeroCount int
	var nonZeroEntries []int64
	for _, e := range entries {
		if e.TransferSize == 0 && e.EncodedBodySize == 0 {
			zeroCount++
		} else {
			nonZeroEntries = append(nonZeroEntries, e.TransferSize)
		}
	}

	// If ALL entries are zero byte, it's a huge signal.
	if zeroCount == len(entries) {
		return 1.0
	}

	// If majority are zero, it's also suspicious
	if float64(zeroCount)/float64(len(entries)) > 0.8 {
		return 0.7
	}

	// Check for "constant" sizes — a common lazy mock habit
	if len(nonZeroEntries) > 3 {
		allSame := true
		first := nonZeroEntries[0]
		for _, sz := range nonZeroEntries[1:] {
			if sz != first {
				allSame = false
				break
			}
		}
		if allSame {
			return 0.8
		}
	}

	return 0
}

func (ta *TimingAnalyzer) validateProtocols(entries []RequestTimingEntry) float64 {
	if len(entries) < 5 {
		return 0
	}

	var missingCount int
	protos := make(map[string]int)
	for _, e := range entries {
		if e.Protocol == "" {
			missingCount++
		} else {
			protos[e.Protocol]++
		}
	}

	// If ALL entries are missing protocol, it's suspicious
	if missingCount == len(entries) {
		return 1.0
	}

	// If we are on a modern site (inferred from many entries), we expect h2 or h3.
	// If it's all "http/1.1", it might be a simple proxy or tool.
	if protos["http/1.1"] > 0 && len(protos) == 1 {
		// Most browsers use h2/h3 for almost everything now.
		return 0.5
	}

	return 0
}

// checkPaintTiming validates PerformancePaintTiming consistency.
func (ta *TimingAnalyzer) checkPaintTiming(seq *RequestTimingSequence) float64 {
	if len(seq.Entries) < 5 {
		return 0 // Too few entries to judge paint markers
	}

	if len(seq.PaintEntries) == 0 {
		// Real browsers on real pages almost always have fcp/fp
		return 0.4
	}

	var fp, fcp float64
	for _, p := range seq.PaintEntries {
		if p.Name == "first-paint" {
			fp = p.StartTime
		} else if p.Name == "first-contentful-paint" {
			fcp = p.StartTime
		}
	}

	score := 0.0

	// FP and FCP must be positive
	if fp <= 0 || fcp <= 0 {
		score += 0.5
	}

	// Navigation started at 0 (relative) or absolute
	// Usually paint entries are relative to navigationStart
	if fcp < fp {
		score += 0.6 // FCP cannot be before FP
	}

	// Performance paint entries are typically > 10ms
	if fp < 10 && fp > 0 {
		score += 0.3
	}

	// Correlation with resources: FCP usually happens after the first
	// stylesheet or font finishes loading.
	firstVisualResourceEnd := 0.0
	for _, e := range seq.Entries {
		ct := strings.ToLower(e.ContentType)
		if strings.Contains(ct, "css") || strings.Contains(ct, "font") {
			end := float64(e.Timestamp + e.Duration)
			if firstVisualResourceEnd == 0 || end < firstVisualResourceEnd {
				firstVisualResourceEnd = end
			}
		}
	}

	// If FCP is significantly before the first CSS load on a page that HAS CSS, it's suspicious.
	if firstVisualResourceEnd > 0 && fcp > 0 {
		// Normalise firstVisualResourceEnd if absolute
		if firstVisualResourceEnd > 1e11 && seq.NavigationStart > 1e11 {
			firstVisualResourceEnd -= seq.NavigationStart
		}

		if fcp < firstVisualResourceEnd*0.5 {
			score += 0.4
		}
	}

	return math.Min(1.0, score)
}
