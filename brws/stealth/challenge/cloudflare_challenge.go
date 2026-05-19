package challenge

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/skunkworq/stealth/brws/core/detection"
)

// Type aliases so challenge-package code can use these without qualifying the package.
type (
	BehavioralAnalyzer      = detection.BehavioralAnalyzer
	BehavioralEvents        = detection.BehavioralEvents
	EnhancedBehavioralEvents = detection.EnhancedBehavioralEvents
	Position                = detection.Position
)

// NewBehavioralAnalyzer delegates to detection.NewBehavioralAnalyzer.
func NewBehavioralAnalyzer(config *detection.BehavioralAnalyzerConfig) *BehavioralAnalyzer {
	return detection.NewBehavioralAnalyzer(config)
}

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
func (cc *CloudflareChallenger) CreateTurnstileChallenge(sessionID, siteKey string) *CloudflareChallengeSession {
	return cc.CreateTurnstileChallengeWithRisk(sessionID, siteKey, 0.30)
}

// CreateTurnstileChallengeWithRisk creates a Turnstile widget challenge configured for a risk tier.
func (cc *CloudflareChallenger) CreateTurnstileChallengeWithRisk(sessionID, siteKey string, detectionScore float64) *CloudflareChallengeSession {
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
	session.TurnstileTelemetry.RecordCallback(callback)
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
	session.TurnstileTelemetry.SnapshotAt = time.Now().UTC()

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
	session.TurnstileTelemetry.RecordInteraction(proof)
	return true
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
			if elapsed == 0 {
				elapsed = 1
			}
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
			if elapsed == 0 {
				elapsed = 1
			}
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

// selectCaptchaTypeFromScore maps a WAF detection score to a CAPTCHA challenge type.
func selectCaptchaTypeFromScore(score float64) string {
	switch {
	case score >= 0.80:
		return "cloudflare_managed"
	case score >= 0.60:
		return "cloudflare_js"
	case score >= 0.35:
		return "hcaptcha"
	default:
		return "text"
	}
}
