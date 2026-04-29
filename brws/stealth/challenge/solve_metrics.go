package challenge

import (
	"encoding/json"
	"math"
	"sync"
	"time"
)

// SolveAttempt records a single captcha solve attempt for metrics tracking.
type SolveAttempt struct {
	ID                string                     `json:"id"`
	Timestamp         time.Time                  `json:"timestamp"`
	ChallengeType     string                     `json:"challenge_type"`
	ChallengeVariant  string                     `json:"challenge_variant"`
	Source            string                     `json:"source"` // "human", "solver", "trace_replay"
	Passed            bool                       `json:"passed"`
	DurationMs        int64                      `json:"duration_ms"`
	EventCount        int                        `json:"event_count"`
	SignalCount       int                        `json:"signal_count"`
	TotalSignalWeight float64                    `json:"total_signal_weight"`
	Signals           []TurnstileHeuristicSignal `json:"signals,omitempty"`
	BehavioralScore   float64                    `json:"behavioral_score"` // 0=bot, 1=human
}

// SolveMetricsTracker aggregates solve attempts across challenge types.
type SolveMetricsTracker struct {
	mu       sync.RWMutex
	attempts []SolveAttempt
}

// NewSolveMetricsTracker creates a new metrics tracker.
func NewSolveMetricsTracker() *SolveMetricsTracker {
	return &SolveMetricsTracker{
		attempts: make([]SolveAttempt, 0),
	}
}

// Record adds a solve attempt.
func (smt *SolveMetricsTracker) Record(attempt SolveAttempt) {
	smt.mu.Lock()
	defer smt.mu.Unlock()
	if attempt.Timestamp.IsZero() {
		attempt.Timestamp = time.Now().UTC()
	}
	smt.attempts = append(smt.attempts, attempt)
}

// RecordFromValidation creates an attempt from validation results.
func (smt *SolveMetricsTracker) RecordFromValidation(
	challengeType, variant, source string,
	passed bool,
	durationMs int64,
	eventCount int,
	signals []TurnstileHeuristicSignal,
	behavioralScore float64,
) {
	totalWeight := 0.0
	for _, s := range signals {
		totalWeight += s.Weight
	}
	smt.Record(SolveAttempt{
		ID:                generateAttemptID(challengeType),
		ChallengeType:     challengeType,
		ChallengeVariant:  variant,
		Source:            source,
		Passed:            passed,
		DurationMs:        durationMs,
		EventCount:        eventCount,
		SignalCount:       len(signals),
		TotalSignalWeight: totalWeight,
		Signals:           signals,
		BehavioralScore:   behavioralScore,
	})
}

// SolveMetricsReport is the full metrics output.
type SolveMetricsReport struct {
	TotalAttempts int                       `json:"total_attempts"`
	PassRate      float64                   `json:"pass_rate"`
	ByType        map[string]*TypeMetrics   `json:"by_type"`
	BySource      map[string]*SourceMetrics `json:"by_source"`
	TimingProfile TimingProfile             `json:"timing_profile"`
	TopSignals    []SignalFrequency         `json:"top_signals"`
	AnomalyFlags  []string                  `json:"anomaly_flags,omitempty"`
}

// TypeMetrics holds per-challenge-type stats.
type TypeMetrics struct {
	Attempts      int     `json:"attempts"`
	Passed        int     `json:"passed"`
	Failed        int     `json:"failed"`
	PassRate      float64 `json:"pass_rate"`
	AvgDurationMs float64 `json:"avg_duration_ms"`
	AvgSignals    float64 `json:"avg_signals"`
	AvgBehavioral float64 `json:"avg_behavioral_score"`
}

// SourceMetrics holds per-source (human/solver/replay) stats.
type SourceMetrics struct {
	Attempts      int     `json:"attempts"`
	Passed        int     `json:"passed"`
	PassRate      float64 `json:"pass_rate"`
	AvgDurationMs float64 `json:"avg_duration_ms"`
}

// TimingProfile captures timing distribution stats.
type TimingProfile struct {
	MinMs    int64   `json:"min_ms"`
	MaxMs    int64   `json:"max_ms"`
	MeanMs   float64 `json:"mean_ms"`
	MedianMs int64   `json:"median_ms"`
	P95Ms    int64   `json:"p95_ms"`
	StddevMs float64 `json:"stddev_ms"`
}

// SignalFrequency tracks how often each heuristic signal appears.
type SignalFrequency struct {
	Name            string  `json:"name"`
	Count           int     `json:"count"`
	AvgWeight       float64 `json:"avg_weight"`
	FailCorrelation float64 `json:"fail_correlation"` // % of times this signal appeared in failed attempts
}

// Report generates the full metrics report.
func (smt *SolveMetricsTracker) Report() SolveMetricsReport {
	smt.mu.RLock()
	defer smt.mu.RUnlock()

	report := SolveMetricsReport{
		TotalAttempts: len(smt.attempts),
		ByType:        make(map[string]*TypeMetrics),
		BySource:      make(map[string]*SourceMetrics),
	}

	if len(smt.attempts) == 0 {
		return report
	}

	passCount := 0
	var durations []int64
	signalCounts := make(map[string]*signalAcc)

	for _, a := range smt.attempts {
		if a.Passed {
			passCount++
		}
		durations = append(durations, a.DurationMs)

		// Per type
		tm, ok := report.ByType[a.ChallengeType]
		if !ok {
			tm = &TypeMetrics{}
			report.ByType[a.ChallengeType] = tm
		}
		tm.Attempts++
		if a.Passed {
			tm.Passed++
		} else {
			tm.Failed++
		}
		tm.AvgDurationMs += float64(a.DurationMs)
		tm.AvgSignals += float64(a.SignalCount)
		tm.AvgBehavioral += a.BehavioralScore

		// Per source
		sm, ok := report.BySource[a.Source]
		if !ok {
			sm = &SourceMetrics{}
			report.BySource[a.Source] = sm
		}
		sm.Attempts++
		if a.Passed {
			sm.Passed++
		}
		sm.AvgDurationMs += float64(a.DurationMs)

		// Signal tracking
		for _, sig := range a.Signals {
			acc, ok := signalCounts[sig.Name]
			if !ok {
				acc = &signalAcc{}
				signalCounts[sig.Name] = acc
			}
			acc.count++
			acc.totalWeight += sig.Weight
			if !a.Passed {
				acc.failCount++
			}
		}
	}

	report.PassRate = float64(passCount) / float64(len(smt.attempts))

	// Finalize averages
	for _, tm := range report.ByType {
		n := float64(tm.Attempts)
		tm.PassRate = float64(tm.Passed) / n
		tm.AvgDurationMs /= n
		tm.AvgSignals /= n
		tm.AvgBehavioral /= n
	}
	for _, sm := range report.BySource {
		n := float64(sm.Attempts)
		sm.PassRate = float64(sm.Passed) / n
		sm.AvgDurationMs /= n
	}

	// Timing profile
	report.TimingProfile = computeTimingProfile(durations)

	// Top signals
	failedTotal := len(smt.attempts) - passCount
	for name, acc := range signalCounts {
		failCorr := 0.0
		if failedTotal > 0 {
			failCorr = float64(acc.failCount) / float64(failedTotal)
		}
		report.TopSignals = append(report.TopSignals, SignalFrequency{
			Name:            name,
			Count:           acc.count,
			AvgWeight:       acc.totalWeight / float64(acc.count),
			FailCorrelation: failCorr,
		})
	}

	// Sort by count descending
	for i := 0; i < len(report.TopSignals); i++ {
		for j := i + 1; j < len(report.TopSignals); j++ {
			if report.TopSignals[j].Count > report.TopSignals[i].Count {
				report.TopSignals[i], report.TopSignals[j] = report.TopSignals[j], report.TopSignals[i]
			}
		}
	}

	// Anomaly detection
	report.AnomalyFlags = detectAnomalies(report)

	return report
}

// ReportJSON returns the report as JSON.
func (smt *SolveMetricsTracker) ReportJSON() ([]byte, error) {
	return json.MarshalIndent(smt.Report(), "", "  ")
}

// Count returns total attempts recorded.
func (smt *SolveMetricsTracker) Count() int {
	smt.mu.RLock()
	defer smt.mu.RUnlock()
	return len(smt.attempts)
}

type signalAcc struct {
	count       int
	totalWeight float64
	failCount   int
}

func computeTimingProfile(durations []int64) TimingProfile {
	if len(durations) == 0 {
		return TimingProfile{}
	}

	// Sort for percentiles
	sorted := make([]int64, len(durations))
	copy(sorted, durations)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j] < sorted[i] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	sum := int64(0)
	for _, d := range sorted {
		sum += d
	}
	mean := float64(sum) / float64(len(sorted))

	// Stddev
	varSum := 0.0
	for _, d := range sorted {
		diff := float64(d) - mean
		varSum += diff * diff
	}
	stddev := math.Sqrt(varSum / float64(len(sorted)))

	p95Idx := int(float64(len(sorted)) * 0.95)
	if p95Idx >= len(sorted) {
		p95Idx = len(sorted) - 1
	}

	return TimingProfile{
		MinMs:    sorted[0],
		MaxMs:    sorted[len(sorted)-1],
		MeanMs:   mean,
		MedianMs: sorted[len(sorted)/2],
		P95Ms:    sorted[p95Idx],
		StddevMs: stddev,
	}
}

func detectAnomalies(report SolveMetricsReport) []string {
	var flags []string

	// Solver pass rate below 50% is concerning
	for source, sm := range report.BySource {
		if source == "solver" && sm.PassRate < 0.50 && sm.Attempts > 5 {
			flags = append(flags, "solver_pass_rate_low: solver passing <50% of challenges")
		}
	}

	// Human traces should pass at very high rate
	for source, sm := range report.BySource {
		if source == "human" && sm.PassRate < 0.90 && sm.Attempts > 3 {
			flags = append(flags, "human_false_positive: real human traces failing >10%")
		}
	}

	// Timing anomaly: very low variance suggests automation
	if report.TimingProfile.StddevMs > 0 && report.TimingProfile.StddevMs < 50 && report.TotalAttempts > 10 {
		flags = append(flags, "low_timing_variance: solve times suspiciously consistent")
	}

	// Check for dominant failure signal
	for _, sig := range report.TopSignals {
		if sig.FailCorrelation > 0.80 && sig.Count > 3 {
			flags = append(flags, "dominant_failure_signal: "+sig.Name+" appears in >80% of failures")
		}
	}

	return flags
}

func generateAttemptID(challengeType string) string {
	return challengeType + "_" + time.Now().Format("20060102_150405.000")
}
