package adversarial

import (
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DynamicSolver handles unknown challenges by classifying them, matching to
// traces, and replaying with adaptation. When no matching trace exists, it
// escalates to human-in-the-loop via the trace lab.
type DynamicSolver struct {
	mu       sync.RWMutex
	library  *TraceLibrary
	mappings map[string]*SolverMapping // fingerprint → mapping
	dataDir  string                    // for persisting learned mappings
	rng      *rand.Rand
}

// SolverMapping links a challenge fingerprint to a solving strategy.
type SolverMapping struct {
	Fingerprint  string          `json:"fingerprint"`
	Provider     string          `json:"provider"`
	Interaction  InteractionType `json:"interaction"`
	TraceType    string          `json:"trace_type"`    // challenge type key in trace library
	TraceVariant string          `json:"trace_variant"` // variant key in trace library
	Confidence   float64         `json:"confidence"`
	SolveCount   int             `json:"solve_count"`   // times this mapping was used
	SuccessCount int             `json:"success_count"` // times it succeeded
	CreatedAt    time.Time       `json:"created_at"`
	LastUsedAt   time.Time       `json:"last_used_at"`
}

// DynamicSolveResult contains the outcome of a dynamic solve attempt.
type DynamicSolveResult struct {
	// Events are the generated behavioral events for solving.
	Events []CaptchaEvent `json:"events"`

	// Signature is the classified challenge signature.
	Signature *ChallengeSignature `json:"signature"`

	// Mapping is the solver mapping that was used (or created).
	Mapping *SolverMapping `json:"mapping"`

	// Source describes how the events were generated.
	Source string `json:"source"` // "trace_replay", "trace_interpolate", "trace_generate", "escalate_human"

	// NeedsHuman is true if no suitable trace was found and human solving is needed.
	NeedsHuman bool `json:"needs_human"`
}

// NewDynamicSolver creates a dynamic solver backed by a trace library.
func NewDynamicSolver(library *TraceLibrary, dataDir string) *DynamicSolver {
	ds := &DynamicSolver{
		library:  library,
		mappings: make(map[string]*SolverMapping),
		dataDir:  dataDir,
		rng:      rand.New(rand.NewSource(time.Now().UnixNano())),
	}
	ds.loadMappings()
	return ds
}

// Solve attempts to solve a challenge by classifying it and matching to traces.
func (ds *DynamicSolver) Solve(body []byte, headers map[string][]string) *DynamicSolveResult {
	// Step 1: Classify the challenge
	sig := ClassifyChallenge(body, headers)

	// Step 2: Check if we have a cached mapping for this fingerprint
	ds.mu.RLock()
	mapping, hasCached := ds.mappings[sig.Fingerprint]
	ds.mu.RUnlock()

	if hasCached && mapping.SuccessCount > 0 {
		// Use the proven mapping
		events := ds.generateFromMapping(mapping)
		if events != nil {
			ds.recordUse(mapping)
			return &DynamicSolveResult{
				Events:    events,
				Signature: sig,
				Mapping:   mapping,
				Source:    "trace_replay",
			}
		}
	}

	// Step 3: Find traces matching the interaction type
	result := ds.solveByInteraction(sig)
	if result != nil {
		// Cache the mapping for next time
		ds.cacheMapping(sig, result.Mapping)
		return result
	}

	// Step 4: Try cross-variant matching (use any trace, adapt timing/position)
	result = ds.solveCrossVariant(sig)
	if result != nil {
		ds.cacheMapping(sig, result.Mapping)
		return result
	}

	// Step 5: No traces available — need human solving
	return &DynamicSolveResult{
		Signature:  sig,
		NeedsHuman: true,
		Source:     "escalate_human",
	}
}

// RecordOutcome feeds back whether a solve attempt succeeded.
// This updates the mapping's success rate, influencing future decisions.
func (ds *DynamicSolver) RecordOutcome(fingerprint string, success bool) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	mapping, ok := ds.mappings[fingerprint]
	if !ok {
		return
	}

	if success {
		mapping.SuccessCount++
	}
	mapping.LastUsedAt = time.Now()
	ds.saveMappings()
}

// Mappings returns all current solver mappings.
func (ds *DynamicSolver) Mappings() []*SolverMapping {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	result := make([]*SolverMapping, 0, len(ds.mappings))
	for _, m := range ds.mappings {
		result = append(result, m)
	}
	return result
}

// solveByInteraction finds traces that match the classified interaction type.
func (ds *DynamicSolver) solveByInteraction(sig *ChallengeSignature) *DynamicSolveResult {
	variants, ok := TraceVariantForInteraction[sig.Interaction]
	if !ok || len(variants) == 0 {
		return nil
	}

	// Try each variant mapping in order
	for _, variant := range variants {
		recs := ds.library.FindByVariant("turnstile", variant)
		if len(recs) == 0 {
			continue
		}

		// Pick a random recording and replay
		rec := recs[ds.rng.Intn(len(recs))]
		events := Replay(rec, DefaultReplayParams(), ds.rng.Float64)
		if len(events) == 0 {
			continue
		}

		mapping := &SolverMapping{
			Fingerprint:  sig.Fingerprint,
			Provider:     sig.Provider,
			Interaction:  sig.Interaction,
			TraceType:    rec.ChallengeType,
			TraceVariant: rec.ChallengeVariant,
			Confidence:   sig.Confidence,
			SolveCount:   1,
			CreatedAt:    time.Now(),
			LastUsedAt:   time.Now(),
		}

		return &DynamicSolveResult{
			Events:    events,
			Signature: sig,
			Mapping:   mapping,
			Source:    "trace_replay",
		}
	}

	return nil
}

// solveCrossVariant attempts to solve using any available trace, adapting
// timing and position patterns to fit the classified interaction.
func (ds *DynamicSolver) solveCrossVariant(sig *ChallengeSignature) *DynamicSolveResult {
	if ds.library.Count() == 0 {
		return nil
	}

	// Get all recordings, try to interpolate between two for novelty
	all := ds.library.FindByType("turnstile")
	if len(all) == 0 {
		return nil
	}

	var events []CaptchaEvent
	var source string

	if len(all) >= 2 {
		// Interpolate between two random traces for a novel but human-like pattern
		i, j := ds.rng.Intn(len(all)), ds.rng.Intn(len(all))
		if i == j {
			j = (j + 1) % len(all)
		}
		blend := 0.3 + ds.rng.Float64()*0.4 // blend between 0.3-0.7
		events = Interpolate(all[i], all[j], blend, ds.rng.Float64)
		source = "trace_interpolate"
	} else {
		// Only one trace — replay with extra variation
		params := ReplayParams{
			TimeScale:      0.8 + ds.rng.Float64()*0.4, // 0.8-1.2x speed
			PositionJitter: 4.0,                        // extra jitter
			TimingJitter:   0.2,                        // extra timing variation
		}
		events = Replay(all[0], params, ds.rng.Float64)
		source = "trace_generate"
	}

	if len(events) == 0 {
		return nil
	}

	// Adapt timing to interaction type
	events = adaptTimingForInteraction(events, sig.Interaction, ds.rng.Float64)

	bestVariant := ""
	if len(all) > 0 {
		bestVariant = all[0].ChallengeVariant
	}

	mapping := &SolverMapping{
		Fingerprint:  sig.Fingerprint,
		Provider:     sig.Provider,
		Interaction:  sig.Interaction,
		TraceType:    "turnstile",
		TraceVariant: bestVariant,
		Confidence:   sig.Confidence * 0.5, // lower confidence for cross-variant
		SolveCount:   1,
		CreatedAt:    time.Now(),
		LastUsedAt:   time.Now(),
	}

	return &DynamicSolveResult{
		Events:    events,
		Signature: sig,
		Mapping:   mapping,
		Source:    source,
	}
}

// adaptTimingForInteraction adjusts event timing to match expected patterns
// for the target interaction type.
func adaptTimingForInteraction(events []CaptchaEvent, interaction InteractionType, rng func() float64) []CaptchaEvent {
	if len(events) == 0 {
		return events
	}

	switch interaction {
	case InteractionClickButtons:
		// Button clicks should have pauses between clicks (thinking time)
		return injectPauses(events, 200, 600, rng)

	case InteractionWait:
		// JS challenges need longer duration with idle mouse movement
		return scaleTimingTo(events, 3000+int64(rng()*5000))

	case InteractionCheckbox:
		// Quick approach → click → done
		return scaleTimingTo(events, 800+int64(rng()*1200))

	default:
		return events
	}
}

// injectPauses adds random delays after click events to simulate thinking time.
func injectPauses(events []CaptchaEvent, minMs, maxMs int, rng func() float64) []CaptchaEvent {
	if len(events) == 0 {
		return events
	}

	result := make([]CaptchaEvent, len(events))
	var offset int64

	for i, e := range events {
		result[i] = e
		result[i].ElapsedMs += offset

		if e.Type == "click" || e.Type == "mouseup" {
			pause := int64(float64(minMs) + rng()*float64(maxMs-minMs))
			offset += pause
		}
	}

	return result
}

// scaleTimingTo rescales all events to fit within the target duration.
func scaleTimingTo(events []CaptchaEvent, targetMs int64) []CaptchaEvent {
	if len(events) < 2 {
		return events
	}

	currentDuration := events[len(events)-1].ElapsedMs - events[0].ElapsedMs
	if currentDuration <= 0 {
		return events
	}

	scale := float64(targetMs) / float64(currentDuration)
	result := make([]CaptchaEvent, len(events))
	for i, e := range events {
		result[i] = e
		result[i].ElapsedMs = int64(float64(e.ElapsedMs-events[0].ElapsedMs) * scale)
	}
	return result
}

func (ds *DynamicSolver) generateFromMapping(mapping *SolverMapping) []CaptchaEvent {
	recs := ds.library.FindByVariant(mapping.TraceType, mapping.TraceVariant)
	if len(recs) == 0 {
		recs = ds.library.FindByType(mapping.TraceType)
	}
	if len(recs) == 0 {
		return nil
	}

	rec := recs[ds.rng.Intn(len(recs))]
	return Replay(rec, DefaultReplayParams(), ds.rng.Float64)
}

func (ds *DynamicSolver) recordUse(mapping *SolverMapping) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	mapping.SolveCount++
	mapping.LastUsedAt = time.Now()
}

func (ds *DynamicSolver) cacheMapping(sig *ChallengeSignature, mapping *SolverMapping) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.mappings[sig.Fingerprint] = mapping
	ds.saveMappings()
}

// Persistence

func (ds *DynamicSolver) mappingsPath() string {
	return filepath.Join(ds.dataDir, "solver_mappings.json")
}

func (ds *DynamicSolver) loadMappings() {
	data, err := os.ReadFile(ds.mappingsPath())
	if err != nil {
		return
	}
	var mappings []*SolverMapping
	if err := json.Unmarshal(data, &mappings); err != nil {
		return
	}
	for _, m := range mappings {
		ds.mappings[m.Fingerprint] = m
	}
}

func (ds *DynamicSolver) saveMappings() {
	mappings := make([]*SolverMapping, 0, len(ds.mappings))
	for _, m := range ds.mappings {
		mappings = append(mappings, m)
	}
	data, err := json.MarshalIndent(mappings, "", "  ")
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(ds.mappingsPath()), 0o755)
	_ = os.WriteFile(ds.mappingsPath(), data, 0o644)
}
