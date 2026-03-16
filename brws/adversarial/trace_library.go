package adversarial

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// TraceLibrary indexes saved traces and provides replay/interpolation.
type TraceLibrary struct {
	mu         sync.RWMutex
	recordings []*TraceRecording
	byType     map[string][]*TraceRecording // challengeType → recordings
	byVariant  map[string][]*TraceRecording // challengeType:variant → recordings
	baseDir    string
}

// NewTraceLibrary creates a library that loads from the given directory.
func NewTraceLibrary(baseDir string) *TraceLibrary {
	return &TraceLibrary{
		recordings: make([]*TraceRecording, 0),
		byType:     make(map[string][]*TraceRecording),
		byVariant:  make(map[string][]*TraceRecording),
		baseDir:    baseDir,
	}
}

// LoadAll scans the traces directory and indexes all recordings.
func (tl *TraceLibrary) LoadAll() error {
	tracesDir := filepath.Join(tl.baseDir, "traces")
	entries, err := os.ReadDir(tracesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	tl.mu.Lock()
	defer tl.mu.Unlock()

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		sessDir := filepath.Join(tracesDir, entry.Name())
		files, err := os.ReadDir(sessDir)
		if err != nil {
			continue
		}
		for _, f := range files {
			if f.Name() == "session.json" || !strings.HasSuffix(f.Name(), ".json") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(sessDir, f.Name()))
			if err != nil {
				continue
			}
			var rec TraceRecording
			if err := json.Unmarshal(data, &rec); err != nil {
				continue
			}
			tl.index(&rec)
		}
	}
	return nil
}

// Add manually adds a recording to the library (e.g. from an active session).
func (tl *TraceLibrary) Add(rec *TraceRecording) {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	tl.index(rec)
}

func (tl *TraceLibrary) index(rec *TraceRecording) {
	tl.recordings = append(tl.recordings, rec)
	tl.byType[rec.ChallengeType] = append(tl.byType[rec.ChallengeType], rec)
	key := rec.ChallengeType + ":" + rec.ChallengeVariant
	tl.byVariant[key] = append(tl.byVariant[key], rec)
}

// Count returns the total number of recordings.
func (tl *TraceLibrary) Count() int {
	tl.mu.RLock()
	defer tl.mu.RUnlock()
	return len(tl.recordings)
}

// CountByType returns counts per challenge type.
func (tl *TraceLibrary) CountByType() map[string]int {
	tl.mu.RLock()
	defer tl.mu.RUnlock()
	m := make(map[string]int)
	for k, v := range tl.byType {
		m[k] = len(v)
	}
	return m
}

// FindByType returns all recordings for a challenge type.
func (tl *TraceLibrary) FindByType(challengeType string) []*TraceRecording {
	tl.mu.RLock()
	defer tl.mu.RUnlock()
	return tl.byType[challengeType]
}

// FindByVariant returns recordings matching type and variant.
func (tl *TraceLibrary) FindByVariant(challengeType, variant string) []*TraceRecording {
	tl.mu.RLock()
	defer tl.mu.RUnlock()
	key := challengeType + ":" + variant
	return tl.byVariant[key]
}

// FindBestMatch finds the recording most similar to the given parameters.
func (tl *TraceLibrary) FindBestMatch(challengeType, variant string, targetDurationMs int64) *TraceRecording {
	tl.mu.RLock()
	defer tl.mu.RUnlock()

	candidates := tl.byVariant[challengeType+":"+variant]
	if len(candidates) == 0 {
		candidates = tl.byType[challengeType]
	}
	if len(candidates) == 0 {
		return nil
	}

	// Sort by duration similarity
	type scored struct {
		rec   *TraceRecording
		score float64
	}
	var scored_ []scored
	for _, r := range candidates {
		if !r.Solved {
			continue
		}
		diff := math.Abs(float64(r.DurationMs - targetDurationMs))
		scored_ = append(scored_, scored{rec: r, score: diff})
	}
	if len(scored_) == 0 {
		return candidates[0]
	}
	sort.Slice(scored_, func(i, j int) bool { return scored_[i].score < scored_[j].score })
	return scored_[0].rec
}

// ReplayParams controls how a trace is replayed.
type ReplayParams struct {
	TimeScale      float64 // 1.0 = original speed, 0.8 = faster, 1.2 = slower
	PositionJitter float64 // max px jitter added to positions
	TimingJitter   float64 // max ms jitter added to intervals (fraction of interval)
	OffsetX        float64 // translate all positions by this X offset
	OffsetY        float64 // translate all positions by this Y offset
}

// DefaultReplayParams returns reasonable defaults for human-like replay.
func DefaultReplayParams() ReplayParams {
	return ReplayParams{
		TimeScale:      1.0,
		PositionJitter: 2.0,
		TimingJitter:   0.15,
	}
}

// Replay generates a new event stream from a recording with timing/position variation.
func Replay(rec *TraceRecording, params ReplayParams, rng func() float64) []CaptchaEvent {
	if rec == nil || len(rec.Events) == 0 {
		return nil
	}

	scale := params.TimeScale
	if scale <= 0 {
		scale = 1.0
	}

	events := make([]CaptchaEvent, len(rec.Events))
	var cumulativeMs int64

	for i, orig := range rec.Events {
		e := orig // copy

		// Scale and jitter timing
		if i == 0 {
			e.ElapsedMs = 0
		} else {
			interval := float64(orig.ElapsedMs - rec.Events[i-1].ElapsedMs)
			interval *= scale
			// Add timing jitter
			if params.TimingJitter > 0 {
				jitter := (rng()*2 - 1) * params.TimingJitter * interval
				interval += jitter
			}
			if interval < 1 {
				interval = 1
			}
			cumulativeMs += int64(interval)
			e.ElapsedMs = cumulativeMs
		}

		// Jitter positions for mouse events
		if hasPosition(e.Type) && params.PositionJitter > 0 {
			e.X += (rng()*2 - 1) * params.PositionJitter
			e.Y += (rng()*2 - 1) * params.PositionJitter
		}

		// Apply offset
		if hasPosition(e.Type) {
			e.X += params.OffsetX
			e.Y += params.OffsetY
		}

		events[i] = e
	}

	return events
}

// Interpolate creates a new event stream by blending two recordings.
// Blend factor 0.0 = fully trace A, 1.0 = fully trace B.
func Interpolate(a, b *TraceRecording, blend float64, rng func() float64) []CaptchaEvent {
	if a == nil || b == nil || len(a.Events) == 0 || len(b.Events) == 0 {
		if a != nil {
			return Replay(a, DefaultReplayParams(), rng)
		}
		return nil
	}

	if blend < 0 {
		blend = 0
	}
	if blend > 1 {
		blend = 1
	}

	// Use the longer trace as base length, resample the shorter
	aLen, bLen := len(a.Events), len(b.Events)
	outLen := aLen
	if bLen > outLen {
		outLen = bLen
	}

	events := make([]CaptchaEvent, outLen)
	for i := range outLen {
		// Sample from both traces at proportional positions
		aIdx := float64(i) / float64(outLen) * float64(aLen-1)
		bIdx := float64(i) / float64(outLen) * float64(bLen-1)

		aEvt := a.Events[int(aIdx)]
		bEvt := b.Events[int(bIdx)]

		// Blend positions
		x := aEvt.X*(1-blend) + bEvt.X*blend
		y := aEvt.Y*(1-blend) + bEvt.Y*blend

		// Blend timing
		elapsed := float64(aEvt.ElapsedMs)*(1-blend) + float64(bEvt.ElapsedMs)*blend

		// Use the event type from the dominant trace
		evtType := aEvt.Type
		if blend > 0.5 {
			evtType = bEvt.Type
		}

		events[i] = CaptchaEvent{
			Type:      evtType,
			ElapsedMs: int64(elapsed),
			X:         x + (rng()*2-1)*1.5,
			Y:         y + (rng()*2-1)*1.5,
			Key:       aEvt.Key,
			Delta:     aEvt.Delta*(1-blend) + bEvt.Delta*blend,
		}
	}

	return events
}

// TraceLibrarySummary provides an overview of the library contents.
type TraceLibrarySummary struct {
	TotalRecordings int            `json:"total_recordings"`
	SolvedCount     int            `json:"solved_count"`
	ByType          map[string]int `json:"by_type"`
	ByVariant       map[string]int `json:"by_variant"`
	AvgDurationMs   int64          `json:"avg_duration_ms"`
	AvgEventCount   int            `json:"avg_event_count"`
}

// Summary returns an overview of the library.
func (tl *TraceLibrary) Summary() TraceLibrarySummary {
	tl.mu.RLock()
	defer tl.mu.RUnlock()

	s := TraceLibrarySummary{
		TotalRecordings: len(tl.recordings),
		ByType:          make(map[string]int),
		ByVariant:       make(map[string]int),
	}

	var totalDur int64
	var totalEvents int
	for _, r := range tl.recordings {
		if r.Solved {
			s.SolvedCount++
		}
		s.ByType[r.ChallengeType]++
		s.ByVariant[r.ChallengeType+":"+r.ChallengeVariant]++
		totalDur += r.DurationMs
		totalEvents += len(r.Events)
	}

	if s.TotalRecordings > 0 {
		s.AvgDurationMs = totalDur / int64(s.TotalRecordings)
		s.AvgEventCount = totalEvents / s.TotalRecordings
	}

	return s
}

func hasPosition(eventType string) bool {
	switch eventType {
	case "mousemove", "mousedown", "mouseup", "click":
		return true
	}
	return false
}

// GenerateFromTrace produces a new solve attempt by selecting the best matching
// trace from the library, then replaying it with human-like variation.
func (tl *TraceLibrary) GenerateFromTrace(challengeType, variant string, rng func() float64) ([]CaptchaEvent, error) {
	// Target a natural solve duration (1-3s for simple, 3-8s for complex)
	targetMs := int64(1500 + rng()*4000)

	rec := tl.FindBestMatch(challengeType, variant, targetMs)
	if rec == nil {
		return nil, fmt.Errorf("no traces found for %s:%s", challengeType, variant)
	}

	params := DefaultReplayParams()
	params.TimeScale = 0.85 + rng()*0.30 // 0.85x - 1.15x speed
	params.PositionJitter = 1.5 + rng()*2.0
	params.TimingJitter = 0.10 + rng()*0.10

	return Replay(rec, params, rng), nil
}
