package adversarial

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ChallengeState tracks the lifecycle of a challenge session.
type ChallengeState string

const (
	StatePending    ChallengeState = "pending"
	StateInProgress ChallengeState = "in_progress"
	StateSolved     ChallengeState = "solved"
	StateEscalated  ChallengeState = "escalated"
	StateFailed     ChallengeState = "failed"
)

// PoWChallenge holds proof-of-work challenge parameters sent to the client.
type PoWChallenge struct {
	ChallengeID   string    `json:"challenge_id"`
	Prefix        string    `json:"prefix"`
	Difficulty    int       `json:"difficulty"`
	Algorithm     string    `json:"algorithm"`
	ExpiresAt     time.Time `json:"expires_at"`
	MaxIterations int64     `json:"max_iterations"`
}

// PoWSolution is the client's response to a PoW challenge.
type PoWSolution struct {
	Nonce      string `json:"nonce"`
	Hash       string `json:"hash"`
	Iterations int64  `json:"iterations"`
	TimeMs     int64  `json:"time_ms"`
}

// FingerprintPayload holds browser fingerprint data collected during a challenge.
type FingerprintPayload struct {
	CanvasHash          string   `json:"canvas_hash"`
	WebGLVendor         string   `json:"webgl_vendor"`
	WebGLRenderer       string   `json:"webgl_renderer"`
	Platform            string   `json:"platform"`
	Languages           []string `json:"languages"`
	HardwareConcurrency int      `json:"hardware_concurrency"`
	DeviceMemory        float64  `json:"device_memory"`
	ScreenWidth         int      `json:"screen_width"`
	ScreenHeight        int      `json:"screen_height"`
	TimezoneOffset      int      `json:"timezone_offset"`
	Timezone            string   `json:"timezone"`
	ColorDepth          int      `json:"color_depth"`
	TouchPoints         int      `json:"touch_points"`
}

// CloudflareChallengeSession tracks a full Cloudflare challenge lifecycle.
type CloudflareChallengeSession struct {
	ID                   string
	Type                 CloudflareChallengeType
	RayID                string
	SiteKey              string
	Hostname             string
	PoW                  *PoWChallenge
	RequiresFingerprint  bool
	RequiresBehavioral   bool
	Fingerprint          *FingerprintPayload
	Events               []CaptchaEvent
	TurnstileConfig      TurnstileWidgetConfig
	TurnstileTelemetry   WidgetTelemetry
	TurnstileSnapshot    *TurnstileClientSnapshot
	TurnstileToken       *LabTurnstileToken
	TurnstileTokenUsed   bool
	TurnstilePresented   bool
	TurnstilePresentedAt time.Time
	CreatedAt            time.Time
	SolvedAt             time.Time
	ClearanceCookie      string
	Passed               bool
	Score                float64

	// Phase 6: session state machine fields
	State          ChallengeState
	FailedAttempts int
	EscalatedFrom  string // previous challenge type before escalation
	CFBMValue      string // bound __cf_bm cookie value

	// Phase 7: session fingerprint binding
	BoundFingerprint *FingerprintPayload // first fingerprint seen, bound to session
	FingerprintDrift float64             // accumulated drift score from subsequent requests
}

// PoWDifficultyConfig controls PoW difficulty bounds.
type PoWDifficultyConfig struct {
	MinBits     int
	MaxBits     int
	DefaultBits int
}

// DefaultPoWDifficultyConfig returns sensible PoW difficulty defaults.
func DefaultPoWDifficultyConfig() *PoWDifficultyConfig {
	return &PoWDifficultyConfig{
		MinBits:     10,
		MaxBits:     24,
		DefaultBits: 16,
	}
}

// CloudflareChallenger is the server-side controller for Cloudflare challenge
// reproduction. It creates, validates, and manages challenge sessions.
type CloudflareChallenger struct {
	mu              sync.RWMutex
	sessions        map[string]*CloudflareChallengeSession
	powConfig       *PoWDifficultyConfig
	analyzer        *BehavioralAnalyzer
	tracer          *CaptchaTracer
	hmacKey         []byte
	turnstileSecret string
	RateLimiter     *TokenBucket // Per-IP rate limiter for solve endpoints
}

// NewCloudflareChallenger creates a new challenger with the given tracer and PoW config.
func NewCloudflareChallenger(tracer *CaptchaTracer, powConfig *PoWDifficultyConfig) *CloudflareChallenger {
	if powConfig == nil {
		powConfig = DefaultPoWDifficultyConfig()
	}
	if tracer == nil {
		tracer = NewCaptchaTracer()
	}

	key := make([]byte, 32)
	_, _ = rand.Read(key)

	return &CloudflareChallenger{
		sessions:        make(map[string]*CloudflareChallengeSession),
		powConfig:       powConfig,
		analyzer:        NewBehavioralAnalyzer(nil),
		tracer:          tracer,
		hmacKey:         key,
		turnstileSecret: fmt.Sprintf("lab_secret_%x", key[:8]),
		RateLimiter:     NewTokenBucket(DefaultRateLimitConfig()),
	}
}

// CreateJSChallenge creates a 503-style JS PoW challenge.
func (cc *CloudflareChallenger) CreateJSChallenge(sessionID string, detectionScore float64) *CloudflareChallengeSession {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	difficulty := cc.scaleDifficulty(detectionScore)
	pow := cc.generatePoW(difficulty)
	rayID := cc.generateRayID()

	cfbm := generateCFBMValue(sessionID)
	session := &CloudflareChallengeSession{
		ID:                  sessionID,
		Type:                ChallengeJS,
		RayID:               rayID,
		PoW:                 pow,
		RequiresFingerprint: false,
		RequiresBehavioral:  false,
		CreatedAt:           time.Now(),
		State:               StatePending,
		CFBMValue:           cfbm,
	}

	cc.sessions[sessionID] = session
	return session
}

// CreateManagedChallenge creates a "Just a moment..." managed challenge requiring
// PoW + fingerprint + behavioral data.
func (cc *CloudflareChallenger) CreateManagedChallenge(sessionID string, detectionScore float64) *CloudflareChallengeSession {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	difficulty := cc.scaleDifficulty(detectionScore)
	pow := cc.generatePoW(difficulty)
	rayID := cc.generateRayID()

	cfbm := generateCFBMValue(sessionID)
	session := &CloudflareChallengeSession{
		ID:                  sessionID,
		Type:                ChallengeManaged,
		RayID:               rayID,
		PoW:                 pow,
		RequiresFingerprint: true,
		RequiresBehavioral:  true,
		CreatedAt:           time.Now(),
		State:               StatePending,
		CFBMValue:           cfbm,
	}

	cc.sessions[sessionID] = session
	return session
}

// CreateTurnstileChallenge creates a Turnstile widget challenge with light PoW + behavioral.
func (cc *CloudflareChallenger) CreateTurnstileChallenge(sessionID string, siteKey string) *CloudflareChallengeSession {
	return cc.CreateTurnstileChallengeWithRisk(sessionID, siteKey, 0.30)
}

// CreateTurnstileChallengeWithRisk creates a Turnstile widget challenge configured for a risk tier.
func (cc *CloudflareChallenger) CreateTurnstileChallengeWithRisk(sessionID string, siteKey string, detectionScore float64) *CloudflareChallengeSession {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	pow := cc.generatePoW(cc.powConfig.MinBits)
	rayID := cc.generateRayID()

	cfbm := generateCFBMValue(sessionID)
	session := &CloudflareChallengeSession{
		ID:                  sessionID,
		Type:                ChallengeTurnstile,
		RayID:               rayID,
		SiteKey:             siteKey,
		PoW:                 pow,
		RequiresFingerprint: false,
		RequiresBehavioral:  true,
		TurnstileConfig:     turnstileWidgetConfigForRisk(sessionID, detectionScore),
		CreatedAt:           time.Now(),
		State:               StatePending,
		CFBMValue:           cfbm,
	}

	cc.sessions[sessionID] = session
	return session
}

// TurnstileSecretKey returns the lab-only secret used by local siteverify.
func (cc *CloudflareChallenger) TurnstileSecretKey() string {
	return cc.turnstileSecret
}

// GetSession retrieves a session by ID.
func (cc *CloudflareChallenger) GetSession(sessionID string) (*CloudflareChallengeSession, bool) {
	cc.mu.RLock()
	defer cc.mu.RUnlock()
	s, ok := cc.sessions[sessionID]
	return s, ok
}

// PresentTurnstileWidget marks that the local widget has been rendered for a session.
func (cc *CloudflareChallenger) PresentTurnstileWidget(sessionID, hostname string) bool {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	session, ok := cc.sessions[sessionID]
	if !ok {
		return false
	}

	session.TurnstilePresented = true
	if session.TurnstilePresentedAt.IsZero() {
		session.TurnstilePresentedAt = time.Now().UTC()
		session.TurnstileTelemetry.PresentedAt = session.TurnstilePresentedAt
	}
	if hostname != "" {
		session.Hostname = normalizeChallengeHost(hostname)
	}

	return true
}

// RecordTurnstileCallback records a widget lifecycle callback for a session.
func (cc *CloudflareChallenger) RecordTurnstileCallback(sessionID, callback string) bool {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	session, ok := cc.sessions[sessionID]
	if !ok {
		return false
	}

	session.TurnstilePresented = true
	if session.TurnstilePresentedAt.IsZero() {
		session.TurnstilePresentedAt = time.Now().UTC()
		session.TurnstileTelemetry.PresentedAt = session.TurnstilePresentedAt
	}
	session.TurnstileTelemetry.recordCallback(callback)
	session.TurnstileConfig.CallbackState = session.TurnstileTelemetry.CallbackState
	return true
}

// RecordTurnstileClientSnapshot stores a browser snapshot observed while the widget was active.
func (cc *CloudflareChallenger) RecordTurnstileClientSnapshot(sessionID string, snapshot *TurnstileClientSnapshot) bool {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	session, ok := cc.sessions[sessionID]
	if !ok || snapshot == nil {
		return false
	}

	copySnapshot := *snapshot
	copySnapshot.UserAgent = strings.TrimSpace(copySnapshot.UserAgent)
	copySnapshot.Language = strings.TrimSpace(copySnapshot.Language)
	copySnapshot.Platform = strings.TrimSpace(copySnapshot.Platform)
	copySnapshot.Timezone = strings.TrimSpace(copySnapshot.Timezone)
	copySnapshot.Languages = append([]string(nil), copySnapshot.Languages...)

	session.TurnstilePresented = true
	if session.TurnstilePresentedAt.IsZero() {
		session.TurnstilePresentedAt = time.Now().UTC()
		session.TurnstileTelemetry.PresentedAt = session.TurnstilePresentedAt
	}
	session.TurnstileSnapshot = &copySnapshot
	session.TurnstileTelemetry.ClientSnapshot = &copySnapshot

	return true
}

// RecordTurnstileInteractionProof stores the interaction proof captured while the widget was active.
func (cc *CloudflareChallenger) RecordTurnstileInteractionProof(sessionID string, proof *TurnstileInteractionProof) bool {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	session, ok := cc.sessions[sessionID]
	if !ok || proof == nil {
		return false
	}

	session.TurnstilePresented = true
	if session.TurnstilePresentedAt.IsZero() {
		session.TurnstilePresentedAt = time.Now().UTC()
		session.TurnstileTelemetry.PresentedAt = session.TurnstilePresentedAt
	}
	session.TurnstileTelemetry.recordInteraction(proof)
	return true
}

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

// CompleteChallengeJS validates a JS challenge (PoW only).
func (cc *CloudflareChallenger) CompleteChallengeJS(sessionID string, solution *PoWSolution) (*CloudflareSolution, error) {
	if err := cc.ValidatePoW(sessionID, solution); err != nil {
		cc.recordFailedAttempt(sessionID)
		return nil, fmt.Errorf("PoW validation failed: %w", err)
	}

	cookie := cc.generateClearanceCookie(sessionID)

	cc.mu.Lock()
	if session, ok := cc.sessions[sessionID]; ok {
		session.Passed = true
		session.SolvedAt = time.Now()
		session.ClearanceCookie = cookie.Value
		session.Score = 0.0
		session.State = StateSolved
	}
	cc.mu.Unlock()

	return &CloudflareSolution{
		ClearanceCookie: cookie,
		SolvedAt:        time.Now(),
		SolveTimeMs:     solution.TimeMs,
		Method:          "cloudflare_js",
	}, nil
}

// CompleteChallengeManaged validates a managed challenge (PoW 30% + fp 30% + behavioral 40%).
func (cc *CloudflareChallenger) CompleteChallengeManaged(
	sessionID string,
	solution *PoWSolution,
	fp *FingerprintPayload,
	events []CaptchaEvent,
) (*CloudflareSolution, error) {
	// Solve time bounds: reject superhuman solve times (< 1.5s for managed)
	cc.mu.RLock()
	session, exists := cc.sessions[sessionID]
	cc.mu.RUnlock()
	if exists {
		elapsed := time.Since(session.CreatedAt)
		if elapsed < 1500*time.Millisecond {
			cc.recordFailedAttempt(sessionID)
			return nil, fmt.Errorf("solve time too fast: %dms (minimum 1500ms)", elapsed.Milliseconds())
		}
	}

	if err := cc.ValidatePoW(sessionID, solution); err != nil {
		cc.recordFailedAttempt(sessionID)
		return nil, fmt.Errorf("PoW validation failed: %w", err)
	}

	fpScore := cc.ValidateFingerprint(sessionID, fp)
	behScore := cc.ValidateBehavioral(sessionID, events)

	// Composite score: lower is better (more human-like)
	// Weights: PoW=0.30 (binary pass/fail, already passed), fp=0.30, behavioral=0.40
	compositeScore := fpScore*0.30 + behScore*0.40

	// Hard reject: if any single signal is extremely bot-like, reject regardless of composite
	if behScore > 0.90 || fpScore > 0.90 {
		compositeScore = math.Max(compositeScore, 0.55)
	}

	if compositeScore > 0.50 {
		cc.recordFailedAttempt(sessionID)
		return nil, fmt.Errorf("managed challenge failed: composite score %.2f exceeds threshold", compositeScore)
	}

	cookie := cc.generateClearanceCookie(sessionID)

	cc.mu.Lock()
	if s, ok := cc.sessions[sessionID]; ok {
		s.Passed = true
		s.SolvedAt = time.Now()
		s.ClearanceCookie = cookie.Value
		s.Score = compositeScore
		s.State = StateSolved
	}
	cc.mu.Unlock()

	return &CloudflareSolution{
		ClearanceCookie: cookie,
		SolvedAt:        time.Now(),
		SolveTimeMs:     solution.TimeMs,
		Method:          "cloudflare_managed",
	}, nil
}

// CompleteTurnstile validates a Turnstile challenge (PoW + light behavioral).
// Turnstile uses a simpler behavioral check than the managed challenge:
// it only requires minimum event count and basic sanity, mirroring
// real Turnstile which is lighter than the full managed challenge.
func (cc *CloudflareChallenger) CompleteTurnstile(
	sessionID string,
	solution *PoWSolution,
	events []CaptchaEvent,
) (*CloudflareSolution, error) {
	if err := cc.ValidatePoW(sessionID, solution); err != nil {
		cc.recordFailedAttempt(sessionID)
		return nil, fmt.Errorf("PoW validation failed: %w", err)
	}

	behScore := cc.ValidateBehavioral(sessionID, events)
	eventSpan := turnstileEventSpan(events)

	cc.mu.RLock()
	session, exists := cc.sessions[sessionID]
	cc.mu.RUnlock()
	lifecycleScore := 0.0
	snapshotScore := 0.0
	interactionScore := 0.0
	if exists {
		switch {
		case session.TurnstileTelemetry.CallbackState.Error:
			cc.recordFailedAttempt(sessionID)
			return nil, fmt.Errorf("turnstile challenge failed: widget reported error state")
		case session.TurnstileTelemetry.CallbackState.Timeout:
			cc.recordFailedAttempt(sessionID)
			return nil, fmt.Errorf("turnstile challenge failed: widget reported timeout state")
		case session.TurnstilePresented &&
			(!session.TurnstileTelemetry.CallbackState.BeforeInteractive ||
				!session.TurnstileTelemetry.CallbackState.AfterInteractive):
			behScore = math.Max(behScore, 0.75)
		}
		lifecycleScore = evaluateTurnstileLifecycle(session, eventSpan)
		snapshotScore = evaluateTurnstileSnapshot(session.TurnstileSnapshot)
		interactionScore = evaluateTurnstileInteraction(session, events)
		if session.TurnstilePresented && session.TurnstileSnapshot == nil {
			snapshotScore = math.Max(snapshotScore, 0.95)
		}
	}

	mouseCount := 0
	mouseYConst := true
	lastMouseY := 0.0
	haveMouseY := false
	hasMouseDown := false
	hasMouseUp := false
	hasClick := false
	for _, e := range events {
		if e.Type == "mousemove" {
			mouseCount++
			if haveMouseY && math.Abs(e.Y-lastMouseY) > 2 {
				mouseYConst = false
			}
			lastMouseY = e.Y
			haveMouseY = true
		}
		switch e.Type {
		case "mousedown":
			hasMouseDown = true
		case "mouseup":
			hasMouseUp = true
		case "click":
			hasClick = true
		}
	}

	switch {
	case len(events) < 5:
		behScore = math.Max(behScore, 1.0)
	case mouseCount < 3:
		behScore = math.Max(behScore, 0.85)
	case eventSpan > 0 && eventSpan < 1100:
		behScore = math.Max(behScore, 0.80)
	case haveMouseY && mouseYConst:
		behScore = math.Max(behScore, 0.78)
	case !(hasMouseDown && hasMouseUp && hasClick):
		behScore = math.Max(behScore, 0.82)
	case behScore > 0.65:
		behScore = math.Max(behScore, 0.75)
	}

	compositeScore := behScore*0.40 + snapshotScore*0.20 + lifecycleScore*0.15 + interactionScore*0.25
	if lifecycleScore >= 0.90 || snapshotScore >= 0.90 || interactionScore >= 0.90 {
		compositeScore = math.Max(compositeScore, 0.85)
	}
	if eventSpan > 0 && eventSpan < 1100 {
		compositeScore = math.Max(compositeScore, 0.82)
	}
	if haveMouseY && mouseYConst {
		compositeScore = math.Max(compositeScore, 0.82)
	}
	if !(hasMouseDown && hasMouseUp && hasClick) {
		compositeScore = math.Max(compositeScore, 0.82)
	}
	if interactionScore >= 0.70 {
		compositeScore = math.Max(compositeScore, 0.83)
	}

	if compositeScore > 0.70 {
		cc.recordFailedAttempt(sessionID)
		return nil, fmt.Errorf("turnstile challenge failed: composite score %.2f exceeds threshold", compositeScore)
	}

	token := cc.issueTurnstileToken(sessionID)
	cookie := cc.generateClearanceCookie(sessionID)

	cc.mu.Lock()
	if session, ok := cc.sessions[sessionID]; ok {
		session.Passed = true
		session.SolvedAt = time.Now()
		session.ClearanceCookie = cookie.Value
		session.Score = behScore
		session.Score = compositeScore
		session.State = StateSolved
		session.TurnstileToken = token
		session.TurnstileTokenUsed = false
		session.TurnstileTelemetry.EventCount = len(events)
		session.TurnstileTelemetry.EventSpanMs = eventSpan
		if len(events) > 0 {
			lastTS := events[len(events)-1].Timestamp
			if lastTS > 0 {
				session.TurnstileTelemetry.LastEventAt = time.UnixMilli(lastTS)
			}
		}
		if session.TurnstileTelemetry.CallbackCount == 0 {
			session.TurnstileTelemetry.recordCallback("before-interactive")
			session.TurnstileTelemetry.recordCallback("after-interactive")
		}
		session.TurnstileTelemetry.recordCallback("success")
		session.TurnstileConfig.CallbackState = session.TurnstileTelemetry.CallbackState
	}
	cc.mu.Unlock()

	var telemetry *WidgetTelemetry
	cc.mu.RLock()
	if session, ok := cc.sessions[sessionID]; ok {
		copyTelemetry := session.TurnstileTelemetry
		telemetry = &copyTelemetry
	}
	cc.mu.RUnlock()

	return &CloudflareSolution{
		ClearanceCookie: cookie,
		TurnstileToken:  token.Value,
		Turnstile:       token,
		Telemetry:       telemetry,
		SolvedAt:        time.Now(),
		SolveTimeMs:     solution.TimeMs,
		Method:          "cloudflare_turnstile",
	}, nil
}

// generateClearanceCookie creates an HMAC-signed cf_clearance cookie with 30-min expiry.
// Format matches real CF: {token}-{timestamp}-{version}-{hmac_base64url}
// where token is a random hex string, timestamp is unix epoch, version is "1.0.1",
// and hmac is base64url-encoded HMAC-SHA256.
func (cc *CloudflareChallenger) generateClearanceCookie(sessionID string) *http.Cookie {
	expiry := time.Now().Add(30 * time.Minute)

	// Generate random token (16 bytes = 32 hex chars, like real CF)
	tokenBytes := make([]byte, 16)
	_, _ = rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)

	timestamp := time.Now().Unix()
	version := "1.0.1"

	// HMAC over sessionID|token|timestamp|version — includes session binding
	data := fmt.Sprintf("%s|%s|%d|%s|%d", sessionID, token, timestamp, version, expiry.UnixMilli())
	mac := hmac.New(sha256.New, cc.hmacKey)
	mac.Write([]byte(data))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	// Real CF format: {token}-{timestamp}-{version}-{hmac}
	value := fmt.Sprintf("%s-%d-%s-%s", token, timestamp, version, sig)

	return &http.Cookie{
		Name:     "cf_clearance",
		Value:    value,
		Path:     "/",
		Expires:  expiry,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}

// ValidateClearanceCookie checks if a cf_clearance cookie value is valid.
// Format: {token}-{timestamp}-{version}-{hmac_base64url}
// Validates: structural format, expiry, and that a solved session issued this exact cookie.
func (cc *CloudflareChallenger) ValidateClearanceCookie(cookieValue string) bool {
	parts := splitClearanceCookie(cookieValue)
	if parts == nil {
		return false
	}

	_, timestampStr, _, _ := parts[0], parts[1], parts[2], parts[3]

	// Check expiry via embedded timestamp
	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return false
	}
	expiryTime := time.Unix(timestamp, 0).Add(30 * time.Minute)
	if time.Now().After(expiryTime) {
		return false
	}

	// Verify this cookie was actually issued by us — lookup by stored value.
	// This is the authoritative check: the HMAC in the cookie prevents forgery,
	// and the session lookup prevents replay from other sessions.
	cc.mu.RLock()
	defer cc.mu.RUnlock()
	for _, s := range cc.sessions {
		if s.ClearanceCookie == cookieValue && s.State == StateSolved {
			return true
		}
	}
	return false
}

// splitClearanceCookie splits a cookie value into [token, timestamp, version, hmac].
// Format: {token}-{timestamp}-{version}-{hmac}
// Token is 32 hex chars, timestamp is unix epoch, version is like "1.0.1",
// hmac is base64url-encoded.
func splitClearanceCookie(value string) []string {
	// Split on hyphens, but version contains dots (e.g., "1.0.1") and hmac may contain hyphens.
	// Token is always 32 hex chars, followed by timestamp (digits), version (x.y.z), hmac.
	// Strategy: find first hyphen after 32-char token, then next hyphen after timestamp digits.
	if len(value) < 36 { // minimum: 32 token + "-" + 1 timestamp + "-" + 1 version + "-" + 1 hmac
		return nil
	}

	// Token is first 32 chars
	token := value[:32]
	rest := value[33:] // skip the hyphen after token

	// Find timestamp (digits until next hyphen)
	idx := strings.IndexByte(rest, '-')
	if idx <= 0 {
		return nil
	}
	timestamp := rest[:idx]
	rest = rest[idx+1:]

	// Find version (x.y.z format until next hyphen)
	idx = strings.IndexByte(rest, '-')
	if idx <= 0 {
		return nil
	}
	version := rest[:idx]
	hmacSig := rest[idx+1:]

	if hmacSig == "" {
		return nil
	}

	return []string{token, timestamp, version, hmacSig}
}

// scaleDifficulty maps a detection score to PoW difficulty bits.
func (cc *CloudflareChallenger) scaleDifficulty(detectionScore float64) int {
	switch {
	case detectionScore < 0.2:
		return cc.powConfig.MinBits
	case detectionScore < 0.4:
		return 14
	case detectionScore < 0.6:
		return cc.powConfig.DefaultBits
	case detectionScore < 0.8:
		return 20
	default:
		// Scale between 22-24 for very high scores
		bits := 22 + int(math.Round((detectionScore-0.8)*10))
		if bits > cc.powConfig.MaxBits {
			bits = cc.powConfig.MaxBits
		}
		return bits
	}
}

// verifyPoWHash checks that SHA-256(prefix+nonce) has the required leading zero bits.
func (cc *CloudflareChallenger) verifyPoWHash(prefix, nonce string, requiredBits int) bool {
	data := prefix + nonce
	hash := sha256.Sum256([]byte(data))
	return hasLeadingZeroBits(hash[:], requiredBits)
}

// hasLeadingZeroBits checks if a hash has at least n leading zero bits.
func hasLeadingZeroBits(hash []byte, n int) bool {
	fullBytes := n / 8
	remainBits := n % 8

	for i := 0; i < fullBytes; i++ {
		if i >= len(hash) {
			return false
		}
		if hash[i] != 0 {
			return false
		}
	}

	if remainBits > 0 && fullBytes < len(hash) {
		mask := byte(0xFF << (8 - remainBits))
		if hash[fullBytes]&mask != 0 {
			return false
		}
	}

	return true
}

// generatePoW creates a new PoW challenge with the given difficulty.
func (cc *CloudflareChallenger) generatePoW(difficulty int) *PoWChallenge {
	prefix := make([]byte, 32)
	_, _ = rand.Read(prefix)

	return &PoWChallenge{
		ChallengeID:   fmt.Sprintf("pow_%d", time.Now().UnixNano()),
		Prefix:        hex.EncodeToString(prefix),
		Difficulty:    difficulty,
		Algorithm:     "SHA-256",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
		MaxIterations: 50_000_000,
	}
}

// generateRayID creates a fake Cloudflare Ray ID.
func (cc *CloudflareChallenger) generateRayID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s-LAB", hex.EncodeToString(b))
}

func (cc *CloudflareChallenger) issueTurnstileToken(sessionID string) *LabTurnstileToken {
	b := make([]byte, 32)
	_, _ = rand.Read(b)

	cc.mu.RLock()
	session := cc.sessions[sessionID]
	cc.mu.RUnlock()

	issuedAt := time.Now()
	expiresAt := issuedAt.Add(defaultTurnstileTokenTTL)
	token := &LabTurnstileToken{
		Value:     fmt.Sprintf("0.%s.%s", hex.EncodeToString(b), sessionID),
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
	}
	if session != nil {
		token.Hostname = session.Hostname
		token.Action = session.TurnstileConfig.Action
		token.CData = session.TurnstileConfig.CData
	}

	return token
}

// VerifyTurnstileToken verifies a locally issued token using lab-only semantics.
func (cc *CloudflareChallenger) VerifyTurnstileToken(secret, response, hostname string) *VerificationResult {
	result := &VerificationResult{Success: false}

	if secret != cc.turnstileSecret {
		result.ErrorCodes = []string{"invalid-input-secret"}
		return result
	}
	if strings.TrimSpace(response) == "" {
		result.ErrorCodes = []string{"missing-input-response"}
		return result
	}

	cc.mu.Lock()
	defer cc.mu.Unlock()

	normalizedHost := normalizeChallengeHost(hostname)
	for _, session := range cc.sessions {
		if session.TurnstileToken == nil || session.TurnstileToken.Value != response {
			continue
		}

		switch {
		case time.Now().After(session.TurnstileToken.ExpiresAt):
			result.ErrorCodes = []string{"timeout-or-duplicate"}
			return result
		case session.TurnstileTokenUsed:
			result.ErrorCodes = []string{"timeout-or-duplicate"}
			return result
		case normalizedHost != "" && session.TurnstileToken.Hostname != "" &&
			!turnstileHostsEquivalent(normalizedHost, session.TurnstileToken.Hostname):
			result.ErrorCodes = []string{"hostname-mismatch"}
			return result
		default:
			session.TurnstileTokenUsed = true
			result.Success = true
			result.ChallengeTS = session.CreatedAt.Format(time.RFC3339)
			if normalizedHost != "" {
				result.Hostname = normalizedHost
			} else {
				result.Hostname = normalizeChallengeHost(session.Hostname)
			}
			result.Action = session.TurnstileConfig.Action
			result.CData = session.TurnstileConfig.CData
			return result
		}
	}

	result.ErrorCodes = []string{"invalid-input-response"}
	return result
}

// GetStats returns statistics about challenge sessions.
func (cc *CloudflareChallenger) GetStats() map[string]interface{} {
	cc.mu.RLock()
	defer cc.mu.RUnlock()

	total := len(cc.sessions)
	passed := 0
	byType := make(map[string]int)
	var totalSolveTime int64

	for _, s := range cc.sessions {
		byType[string(s.Type)]++
		if s.Passed {
			passed++
			totalSolveTime += s.SolvedAt.Sub(s.CreatedAt).Milliseconds()
		}
	}

	avgSolveTime := int64(0)
	if passed > 0 {
		avgSolveTime = totalSolveTime / int64(passed)
	}

	solveRate := 0.0
	if total > 0 {
		solveRate = float64(passed) / float64(total)
	}

	return map[string]interface{}{
		"total_sessions": total,
		"passed":         passed,
		"solve_rate":     solveRate,
		"avg_solve_ms":   avgSolveTime,
		"by_type":        byType,
	}
}

func normalizeChallengeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return ""
	}

	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		return parsedHost
	}

	return strings.Trim(host, "[]")
}

func turnstileHostsEquivalent(left, right string) bool {
	left = normalizeChallengeHost(left)
	right = normalizeChallengeHost(right)
	if left == right {
		return true
	}

	return isLoopbackOrLocalHost(left) && isLoopbackOrLocalHost(right)
}

func turnstileEventSpan(events []CaptchaEvent) int64 {
	if len(events) < 2 {
		return 0
	}

	first := events[0].Timestamp
	last := events[0].Timestamp
	for _, event := range events[1:] {
		if event.Timestamp < first {
			first = event.Timestamp
		}
		if event.Timestamp > last {
			last = event.Timestamp
		}
	}
	if last <= first {
		return 0
	}
	return last - first
}

func evaluateTurnstileLifecycle(session *CloudflareChallengeSession, eventSpan int64) float64 {
	if session == nil {
		return 1.0
	}
	if session.TurnstilePresented &&
		(!session.TurnstileTelemetry.CallbackState.BeforeInteractive ||
			!session.TurnstileTelemetry.CallbackState.AfterInteractive) {
		return 1.0
	}

	score := 0.0
	weights := 0.0
	order := session.TurnstileTelemetry.CallbackOrder

	if !session.TurnstilePresented {
		score += 0.45
	}
	weights += 0.45

	if len(order) < 2 || !isValidTurnstileCallbackOrder(order) {
		score += 0.35
	}
	weights += 0.35

	if session.TurnstileTelemetry.DuplicateCallbacks > 0 {
		score += 0.10
	}
	weights += 0.10

	if eventSpan > 0 && eventSpan < 1100 {
		score += 0.10
	}
	weights += 0.10

	if session.TurnstileTelemetry.CallbackState.Timeout ||
		session.TurnstileTelemetry.CallbackState.Error ||
		session.TurnstileTelemetry.CallbackState.Expired {
		return 1.0
	}

	if weights == 0 {
		return 0
	}
	return score / weights
}

func isValidTurnstileCallbackOrder(order []string) bool {
	beforeIdx := -1
	afterIdx := -1

	for idx, name := range order {
		switch name {
		case "before-interactive":
			if beforeIdx == -1 {
				beforeIdx = idx
			}
		case "after-interactive":
			if afterIdx == -1 {
				afterIdx = idx
			}
		case "success":
			if afterIdx == -1 || idx < afterIdx {
				return false
			}
		case "timeout", "error", "expired":
			return false
		}
	}

	return beforeIdx >= 0 && afterIdx > beforeIdx
}

func evaluateTurnstileSnapshot(snapshot *TurnstileClientSnapshot) float64 {
	if snapshot == nil {
		return 1.0
	}

	score := 0.0
	weights := 0.0
	ua := strings.ToLower(strings.TrimSpace(snapshot.UserAgent))
	platform := strings.TrimSpace(snapshot.Platform)

	if snapshot.Webdriver ||
		strings.Contains(ua, "headless") ||
		strings.Contains(ua, "playwright") ||
		strings.Contains(ua, "selenium") {
		return 1.0
	}

	if ua == "" {
		score += 0.35
	}
	weights += 0.35

	weights += 0.30

	if snapshot.Language == "" || len(snapshot.Languages) == 0 || snapshot.Language != snapshot.Languages[0] {
		score += 0.10
	}
	weights += 0.10

	if snapshot.HardwareConcurrency <= 0 || snapshot.HardwareConcurrency > 64 {
		score += 0.05
	}
	weights += 0.05

	if snapshot.ScreenWidth < 640 || snapshot.ScreenHeight < 480 {
		score += 0.05
	}
	weights += 0.05

	if snapshot.ColorDepth != 24 && snapshot.ColorDepth != 30 && snapshot.ColorDepth != 32 {
		score += 0.05
	}
	weights += 0.05

	if snapshot.Timezone == "" {
		score += 0.05
	}
	weights += 0.05

	if !snapshot.CookieEnabled {
		score += 0.05
	}
	weights += 0.05

	switch {
	case strings.Contains(ua, "windows") && platform != "Win32":
		score += 0.10
	case strings.Contains(ua, "macintosh") && platform != "MacIntel":
		score += 0.10
	case strings.Contains(ua, "linux") && !strings.Contains(strings.ToLower(platform), "linux"):
		score += 0.10
	}
	weights += 0.10

	if weights == 0 {
		return 0
	}

	return math.Min(1.0, score/weights)
}

type turnstileEventInteractionSummary struct {
	HasMouseDown   bool
	HasMouseUp     bool
	HasClick       bool
	MoveCount      int
	HoldDurationMs int
	DragDistancePx int
}

func evaluateTurnstileInteraction(session *CloudflareChallengeSession, events []CaptchaEvent) float64 {
	if session == nil {
		return 1.0
	}

	config := session.TurnstileConfig.Interaction
	if config.Type == "" {
		config.Type = turnstileInteractionCheckbox
	}

	summary := summarizeTurnstileInteractionEvents(events)
	proof := session.TurnstileTelemetry.InteractionProof
	if session.TurnstilePresented && proof == nil {
		return 1.0
	}

	score := 0.0
	weights := 0.0
	addPenalty := func(condition bool, weight float64) {
		if condition {
			score += weight
		}
		weights += weight
	}

	if proof != nil && proof.Type != "" && proof.Type != config.Type {
		return 1.0
	}

	switch config.Type {
	case turnstileInteractionHold:
		addPenalty(proof == nil || !proof.Completed, 0.30)
		addPenalty(proof == nil || proof.HoldDurationMs < config.RequiredHoldMs, 0.25)
		addPenalty(summary.HoldDurationMs < config.RequiredHoldMs, 0.25)
		addPenalty(!(summary.HasMouseDown && summary.HasMouseUp && summary.HasClick), 0.10)
		addPenalty(summary.MoveCount < 2, 0.10)
	case turnstileInteractionDrag:
		addPenalty(proof == nil || !proof.Completed, 0.30)
		addPenalty(proof == nil || proof.DragDistancePx < config.RequiredDragDistancePx, 0.20)
		addPenalty(proof == nil || proof.DragEventCount < config.RequiredDragEventCount, 0.10)
		addPenalty(summary.DragDistancePx < config.RequiredDragDistancePx, 0.20)
		addPenalty(summary.MoveCount < config.RequiredDragEventCount, 0.10)
		addPenalty(!(summary.HasMouseDown && summary.HasMouseUp && summary.HasClick), 0.10)
	default:
		addPenalty(proof == nil || !proof.Completed || proof.CheckboxClicks < 1, 0.35)
		addPenalty(!(summary.HasMouseDown && summary.HasMouseUp && summary.HasClick), 0.35)
		addPenalty(summary.MoveCount < 3, 0.10)
	}

	if weights == 0 {
		return 0.0
	}
	return math.Min(1.0, score/weights)
}

func summarizeTurnstileInteractionEvents(events []CaptchaEvent) turnstileEventInteractionSummary {
	summary := turnstileEventInteractionSummary{}
	var downTS int64
	minX := math.MaxFloat64
	maxX := -math.MaxFloat64

	for _, event := range events {
		switch event.Type {
		case "mousemove":
			summary.MoveCount++
			if event.X < minX {
				minX = event.X
			}
			if event.X > maxX {
				maxX = event.X
			}
		case "mousedown":
			summary.HasMouseDown = true
			if downTS == 0 {
				downTS = event.Timestamp
			}
			if event.X < minX {
				minX = event.X
			}
			if event.X > maxX {
				maxX = event.X
			}
		case "mouseup":
			summary.HasMouseUp = true
			if downTS > 0 && event.Timestamp >= downTS {
				summary.HoldDurationMs = int(event.Timestamp - downTS)
			}
			if event.X < minX {
				minX = event.X
			}
			if event.X > maxX {
				maxX = event.X
			}
		case "click":
			summary.HasClick = true
		}
	}

	if minX != math.MaxFloat64 && maxX != -math.MaxFloat64 && maxX > minX {
		summary.DragDistancePx = int(math.Round(maxX - minX))
	}

	return summary
}

// eventsToEnhancedBehavioral converts CaptchaEvent slice to EnhancedBehavioralEvents
// for the BehavioralAnalyzer.
func eventsToEnhancedBehavioral(events []CaptchaEvent) *EnhancedBehavioralEvents {
	enhanced := &EnhancedBehavioralEvents{
		BehavioralEvents: BehavioralEvents{},
	}

	for _, e := range events {
		switch e.Type {
		case "mousemove":
			enhanced.MouseTimestamps = append(enhanced.MouseTimestamps, e.Timestamp)
			enhanced.MousePositions = append(enhanced.MousePositions, Position{X: e.X, Y: e.Y})
			enhanced.BehavioralEvents.MouseEvents++
		case "keydown", "keyup", "keypress":
			enhanced.TypingTimestamps = append(enhanced.TypingTimestamps, e.Timestamp)
			enhanced.BehavioralEvents.TypingEvents++
		case "scroll", "wheel":
			enhanced.ScrollTimestamps = append(enhanced.ScrollTimestamps, e.Timestamp)
			enhanced.ScrollDeltas = append(enhanced.ScrollDeltas, e.Delta)
			enhanced.BehavioralEvents.ScrollEvents++
		case "click", "mousedown", "mouseup":
			enhanced.ClickTimestamps = append(enhanced.ClickTimestamps, e.Timestamp)
			enhanced.ClickPositions = append(enhanced.ClickPositions, Position{X: e.X, Y: e.Y})
		}
	}

	// Compute velocities from mouse positions and timestamps
	if len(enhanced.MouseTimestamps) > 1 {
		for i := 1; i < len(enhanced.MouseTimestamps); i++ {
			dt := float64(enhanced.MouseTimestamps[i]-enhanced.MouseTimestamps[i-1]) / 1000.0
			if dt > 0 {
				dx := enhanced.MousePositions[i].X - enhanced.MousePositions[i-1].X
				dy := enhanced.MousePositions[i].Y - enhanced.MousePositions[i-1].Y
				dist := math.Sqrt(dx*dx + dy*dy)
				enhanced.MouseVelocities = append(enhanced.MouseVelocities, dist/dt)
			}
		}
	}

	return enhanced
}

// SolvePoW is a utility that solves a PoW challenge (for testing).
func SolvePoW(prefix string, difficulty int, maxIterations int64) (*PoWSolution, error) {
	start := time.Now()

	for i := int64(0); i < maxIterations; i++ {
		nonce := fmt.Sprintf("%016x", i)
		data := prefix + nonce
		hash := sha256.Sum256([]byte(data))

		if hasLeadingZeroBits(hash[:], difficulty) {
			elapsed := time.Since(start).Milliseconds()
			return &PoWSolution{
				Nonce:      nonce,
				Hash:       hex.EncodeToString(hash[:]),
				Iterations: i + 1,
				TimeMs:     elapsed,
			}, nil
		}
	}

	return nil, fmt.Errorf("failed to solve PoW after %d iterations", maxIterations)
}

// SolvePoWRandom uses random nonces to solve PoW (more realistic).
func SolvePoWRandom(prefix string, difficulty int, maxIterations int64) (*PoWSolution, error) {
	start := time.Now()

	for i := int64(0); i < maxIterations; i++ {
		nonceBuf := make([]byte, 16)
		_, _ = rand.Read(nonceBuf)
		nonce := hex.EncodeToString(nonceBuf)

		data := prefix + nonce
		hash := sha256.Sum256([]byte(data))

		if hasLeadingZeroBits(hash[:], difficulty) {
			elapsed := time.Since(start).Milliseconds()
			return &PoWSolution{
				Nonce:      nonce,
				Hash:       hex.EncodeToString(hash[:]),
				Iterations: i + 1,
				TimeMs:     elapsed,
			}, nil
		}
	}

	return nil, fmt.Errorf("failed to solve PoW after %d iterations", maxIterations)
}

// recordFailedAttempt increments the failed attempt counter and updates state.
func (cc *CloudflareChallenger) recordFailedAttempt(sessionID string) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if session, ok := cc.sessions[sessionID]; ok {
		session.FailedAttempts++
		if session.State == StatePending {
			session.State = StateInProgress
		}
		if session.FailedAttempts >= 3 {
			session.State = StateFailed
		}
	}
}

// EscalateChallenge escalates a challenge: JS → Managed → Blocked.
// Returns the new session if escalated, or nil if already at maximum level.
func (cc *CloudflareChallenger) EscalateChallenge(sessionID string) *CloudflareChallengeSession {
	cc.mu.Lock()
	session, ok := cc.sessions[sessionID]
	if !ok {
		cc.mu.Unlock()
		return nil
	}
	previousType := string(session.Type)
	cc.mu.Unlock()

	switch CloudflareChallengeType(previousType) {
	case ChallengeJS:
		newSession := cc.CreateManagedChallenge(sessionID+"_esc", 0.7)
		cc.mu.Lock()
		newSession.State = StateEscalated
		newSession.EscalatedFrom = previousType
		session.State = StateEscalated
		cc.mu.Unlock()
		return newSession
	case ChallengeManaged:
		// Escalate to blocked — no more challenges to solve
		cc.mu.Lock()
		session.State = StateFailed
		blocked := &CloudflareChallengeSession{
			ID:            sessionID + "_blocked",
			Type:          ChallengeBlocked,
			RayID:         session.RayID,
			CreatedAt:     time.Now(),
			State:         StateFailed,
			EscalatedFrom: previousType,
		}
		cc.sessions[blocked.ID] = blocked
		cc.mu.Unlock()
		return blocked
	default:
		return nil
	}
}

// generateCFBMValue creates a realistic __cf_bm cookie value tied to a session ID.
func generateCFBMValue(sessionID string) string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	hash := sha256.Sum256(append([]byte(sessionID), b...))
	return hex.EncodeToString(hash[:])[:43] + "-" + fmt.Sprintf("%d", time.Now().Unix()) + "-1-1"
}

// ValidateCFBMCookie checks that the __cf_bm cookie in the request matches the
// session's bound value. Real CF binds __cf_bm to the challenge session — a
// solve request without the correct __cf_bm is suspicious (cookie replay or
// session hijacking).
func (cc *CloudflareChallenger) ValidateCFBMCookie(r *http.Request, sessionID string) error {
	cc.mu.RLock()
	session, ok := cc.sessions[sessionID]
	cc.mu.RUnlock()

	if !ok {
		return fmt.Errorf("session not found: %s", sessionID)
	}
	if session.CFBMValue == "" {
		// Session has no bound __cf_bm — skip validation
		return nil
	}

	cookie, err := r.Cookie("__cf_bm")
	if err != nil {
		return fmt.Errorf("missing __cf_bm cookie")
	}
	if cookie.Value != session.CFBMValue {
		return fmt.Errorf("__cf_bm cookie mismatch: expected session-bound value")
	}
	return nil
}

// EstimatePoWIterations returns the expected number of iterations for a given difficulty.
func EstimatePoWIterations(difficulty int) *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), uint(difficulty))
}
