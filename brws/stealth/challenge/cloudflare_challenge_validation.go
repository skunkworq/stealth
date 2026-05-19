package challenge

import (
	"fmt"
	"math"
	"time"
)

// ValidatePoW verifies that a PoW solution is correct for the given session.
func (cc *CloudflareChallenger) ValidatePoW(sessionID string, solution *PoWSolution) error {
	cc.mu.RLock()
	session, ok := cc.sessions[sessionID]
	cc.mu.RUnlock()

	if !ok {
		return fmt.Errorf("session not found: %s", sessionID)
	}
	if session.PoW == nil {
		return fmt.Errorf("no PoW challenge for session: %s", sessionID)
	}
	if time.Now().After(session.PoW.ExpiresAt) {
		return fmt.Errorf("PoW challenge expired")
	}
	if !cc.verifyPoWHash(session.PoW.Prefix, solution.Nonce, session.PoW.Difficulty) {
		return fmt.Errorf("invalid PoW solution")
	}
	return nil
}

// ValidateFingerprint scores a fingerprint for consistency. Returns 0.0 (human-like) to 1.0 (bot-like).
func (cc *CloudflareChallenger) ValidateFingerprint(sessionID string, fp *FingerprintPayload) float64 {
	if fp == nil {
		return 1.0
	}

	score := 0.0
	checks := 0.0

	// Check for missing critical fields
	if fp.CanvasHash == "" {
		score += 0.2
	}
	checks += 0.2

	if fp.WebGLVendor == "" || fp.WebGLRenderer == "" {
		score += 0.2
	}
	checks += 0.2

	if fp.Platform == "" {
		score += 0.15
	}
	checks += 0.15

	if len(fp.Languages) == 0 {
		score += 0.15
	}
	checks += 0.15

	if fp.HardwareConcurrency <= 0 {
		score += 0.1
	}
	checks += 0.1

	if fp.ScreenWidth <= 0 || fp.ScreenHeight <= 0 {
		score += 0.1
	}
	checks += 0.1

	if fp.ColorDepth <= 0 {
		score += 0.05
	}
	checks += 0.05

	if fp.Timezone == "" {
		score += 0.05
	}
	checks += 0.05

	// Normalize
	if checks > 0 {
		score = score / checks
	}

	cc.mu.Lock()
	if session, ok := cc.sessions[sessionID]; ok {
		session.Fingerprint = fp

		// Phase 7: bind fingerprint on first submission, detect drift on subsequent ones
		if session.BoundFingerprint == nil {
			session.BoundFingerprint = fp
		} else {
			drift := fingerprintDrift(session.BoundFingerprint, fp)
			session.FingerprintDrift = drift
			// Drift contributes to the bot score — hardware shouldn't change mid-session
			score = math.Min(1.0, score+drift*0.5)
		}
	}
	cc.mu.Unlock()

	return score
}

// fingerprintDrift computes a 0.0–1.0 drift score between two fingerprints.
// Hardware properties that cannot change within a session (platform, concurrency,
// device memory, GPU) are weighted heavily. Screen dimensions and timezone are
// weighted moderately (possible but suspicious).
func fingerprintDrift(bound, current *FingerprintPayload) float64 {
	if bound == nil || current == nil {
		return 0.0
	}

	drift := 0.0
	weights := 0.0

	// Canvas hash — same GPU/driver should produce the same hash
	if bound.CanvasHash != "" && current.CanvasHash != "" && bound.CanvasHash != current.CanvasHash {
		drift += 0.20
	}
	weights += 0.20

	// WebGL renderer — GPU can't change mid-session
	if bound.WebGLRenderer != "" && current.WebGLRenderer != "" && bound.WebGLRenderer != current.WebGLRenderer {
		drift += 0.15
	}
	weights += 0.15

	// WebGL vendor — GPU vendor can't change mid-session
	if bound.WebGLVendor != "" && current.WebGLVendor != "" && bound.WebGLVendor != current.WebGLVendor {
		drift += 0.10
	}
	weights += 0.10

	// Platform — impossible to change
	if bound.Platform != "" && current.Platform != "" && bound.Platform != current.Platform {
		drift += 0.15
	}
	weights += 0.15

	// Hardware concurrency — core count can't change
	if bound.HardwareConcurrency > 0 && current.HardwareConcurrency > 0 && bound.HardwareConcurrency != current.HardwareConcurrency {
		drift += 0.10
	}
	weights += 0.10

	// Device memory — RAM doesn't change mid-session
	if bound.DeviceMemory > 0 && current.DeviceMemory > 0 && bound.DeviceMemory != current.DeviceMemory {
		drift += 0.10
	}
	weights += 0.10

	// Screen dimensions — possible via window resize, but weighted lower
	if bound.ScreenWidth > 0 && current.ScreenWidth > 0 && (bound.ScreenWidth != current.ScreenWidth || bound.ScreenHeight != current.ScreenHeight) {
		drift += 0.05
	}
	weights += 0.05

	// Timezone — can't change mid-session
	if bound.Timezone != "" && current.Timezone != "" && bound.Timezone != current.Timezone {
		drift += 0.10
	}
	weights += 0.10

	// Color depth — can't change mid-session
	if bound.ColorDepth > 0 && current.ColorDepth > 0 && bound.ColorDepth != current.ColorDepth {
		drift += 0.05
	}
	weights += 0.05

	if weights > 0 {
		return drift / weights
	}
	return 0.0
}

// GetFingerprintDrift returns the accumulated fingerprint drift score for a session.
func (cc *CloudflareChallenger) GetFingerprintDrift(sessionID string) float64 {
	cc.mu.RLock()
	defer cc.mu.RUnlock()

	if session, ok := cc.sessions[sessionID]; ok {
		return session.FingerprintDrift
	}
	return 0.0
}

// ValidateBehavioral delegates to the BehavioralAnalyzer and returns a bot score.
func (cc *CloudflareChallenger) ValidateBehavioral(sessionID string, events []CaptchaEvent) float64 {
	if len(events) == 0 {
		return 1.0
	}

	enhanced := eventsToEnhancedBehavioral(events)
	result := cc.analyzer.Analyze(enhanced)

	cc.mu.Lock()
	if session, ok := cc.sessions[sessionID]; ok {
		session.Events = events
	}
	cc.mu.Unlock()

	return result.Score
}
