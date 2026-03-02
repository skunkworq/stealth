package adversarial

import (
	"fmt"
	"math"
	"strings"
)

// TimingAnalyzerConfig configures timing analysis thresholds.
type TimingAnalyzerConfig struct {
	MaxFixedIntervalCV float64 // CV below this = fixed intervals (bot)
	MinRequestGapMs    float64 // Gaps below this = too fast
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
	Timestamp   int64  `json:"timestamp_ms"`
	URL         string `json:"url"`
	ContentType string `json:"content_type"`
	Referrer    string `json:"referrer"`
	Duration    int64  `json:"duration_ms"`
}

// RequestTimingSequence represents a sequence of requests for analysis.
type RequestTimingSequence struct {
	Entries []RequestTimingEntry `json:"entries"`
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

	if seq == nil || len(seq.Entries) < 2 {
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
