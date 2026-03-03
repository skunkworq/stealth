package adversarial

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"sync"
	"time"
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
	ID                  string
	Type                CloudflareChallengeType
	RayID               string
	SiteKey             string
	PoW                 *PoWChallenge
	RequiresFingerprint bool
	RequiresBehavioral  bool
	Fingerprint         *FingerprintPayload
	Events              []CaptchaEvent
	CreatedAt           time.Time
	SolvedAt            time.Time
	ClearanceCookie     string
	Passed              bool
	Score               float64
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
	mu        sync.RWMutex
	sessions  map[string]*CloudflareChallengeSession
	powConfig *PoWDifficultyConfig
	analyzer  *BehavioralAnalyzer
	tracer    *CaptchaTracer
	hmacKey   []byte
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
		sessions:  make(map[string]*CloudflareChallengeSession),
		powConfig: powConfig,
		analyzer:  NewBehavioralAnalyzer(nil),
		tracer:    tracer,
		hmacKey:   key,
	}
}

// CreateJSChallenge creates a 503-style JS PoW challenge.
func (cc *CloudflareChallenger) CreateJSChallenge(sessionID string, detectionScore float64) *CloudflareChallengeSession {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	difficulty := cc.scaleDifficulty(detectionScore)
	pow := cc.generatePoW(difficulty)
	rayID := cc.generateRayID()

	session := &CloudflareChallengeSession{
		ID:                  sessionID,
		Type:                ChallengeJS,
		RayID:               rayID,
		PoW:                 pow,
		RequiresFingerprint: false,
		RequiresBehavioral:  false,
		CreatedAt:           time.Now(),
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

	session := &CloudflareChallengeSession{
		ID:                  sessionID,
		Type:                ChallengeManaged,
		RayID:               rayID,
		PoW:                 pow,
		RequiresFingerprint: true,
		RequiresBehavioral:  true,
		CreatedAt:           time.Now(),
	}

	cc.sessions[sessionID] = session
	return session
}

// CreateTurnstileChallenge creates a Turnstile widget challenge with light PoW + behavioral.
func (cc *CloudflareChallenger) CreateTurnstileChallenge(sessionID string, siteKey string) *CloudflareChallengeSession {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	pow := cc.generatePoW(cc.powConfig.MinBits)
	rayID := cc.generateRayID()

	session := &CloudflareChallengeSession{
		ID:                  sessionID,
		Type:                ChallengeTurnstile,
		RayID:               rayID,
		SiteKey:             siteKey,
		PoW:                 pow,
		RequiresFingerprint: false,
		RequiresBehavioral:  true,
		CreatedAt:           time.Now(),
	}

	cc.sessions[sessionID] = session
	return session
}

// GetSession retrieves a session by ID.
func (cc *CloudflareChallenger) GetSession(sessionID string) (*CloudflareChallengeSession, bool) {
	cc.mu.RLock()
	defer cc.mu.RUnlock()
	s, ok := cc.sessions[sessionID]
	return s, ok
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
	}
	cc.mu.Unlock()

	return score
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
		return nil, fmt.Errorf("PoW validation failed: %w", err)
	}

	cookie := cc.generateClearanceCookie(sessionID)

	cc.mu.Lock()
	if session, ok := cc.sessions[sessionID]; ok {
		session.Passed = true
		session.SolvedAt = time.Now()
		session.ClearanceCookie = cookie.Value
		session.Score = 0.0
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
	if err := cc.ValidatePoW(sessionID, solution); err != nil {
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
		cc.mu.Lock()
		if session, ok := cc.sessions[sessionID]; ok {
			session.Score = compositeScore
		}
		cc.mu.Unlock()
		return nil, fmt.Errorf("managed challenge failed: composite score %.2f exceeds threshold", compositeScore)
	}

	cookie := cc.generateClearanceCookie(sessionID)

	cc.mu.Lock()
	if session, ok := cc.sessions[sessionID]; ok {
		session.Passed = true
		session.SolvedAt = time.Now()
		session.ClearanceCookie = cookie.Value
		session.Score = compositeScore
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
		return nil, fmt.Errorf("PoW validation failed: %w", err)
	}

	// Light behavioral check for Turnstile: require minimum event count
	// and at least some mouse movement (not zero-event bot submission)
	behScore := 0.0
	if len(events) < 5 {
		behScore = 1.0
	} else {
		mouseCount := 0
		for _, e := range events {
			if e.Type == "mousemove" {
				mouseCount++
			}
		}
		if mouseCount < 3 {
			behScore = 0.8
		}
	}

	if behScore > 0.70 {
		cc.mu.Lock()
		if session, ok := cc.sessions[sessionID]; ok {
			session.Score = behScore
		}
		cc.mu.Unlock()
		return nil, fmt.Errorf("turnstile challenge failed: behavioral score %.2f exceeds threshold", behScore)
	}

	token := cc.generateTurnstileToken(sessionID)
	cookie := cc.generateClearanceCookie(sessionID)

	cc.mu.Lock()
	if session, ok := cc.sessions[sessionID]; ok {
		session.Passed = true
		session.SolvedAt = time.Now()
		session.ClearanceCookie = cookie.Value
		session.Score = behScore
	}
	cc.mu.Unlock()

	return &CloudflareSolution{
		ClearanceCookie: cookie,
		TurnstileToken:  token,
		SolvedAt:        time.Now(),
		SolveTimeMs:     solution.TimeMs,
		Method:          "cloudflare_turnstile",
	}, nil
}

// generateClearanceCookie creates an HMAC-signed cf_clearance cookie with 30-min expiry.
func (cc *CloudflareChallenger) generateClearanceCookie(sessionID string) *http.Cookie {
	expiry := time.Now().Add(30 * time.Minute)
	data := fmt.Sprintf("%s|%d", sessionID, expiry.UnixMilli())

	mac := hmac.New(sha256.New, cc.hmacKey)
	mac.Write([]byte(data))
	sig := hex.EncodeToString(mac.Sum(nil))

	value := fmt.Sprintf("%s.%d.%s", sessionID, expiry.UnixMilli(), sig)

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
func (cc *CloudflareChallenger) ValidateClearanceCookie(cookieValue string) bool {
	// Format: sessionID.expiryMs.signature
	parts := splitClearanceCookie(cookieValue)
	if parts == nil {
		return false
	}

	sessionID, expiryMs, sig := parts[0], parts[1], parts[2]

	// Check expiry
	var expiry int64
	if _, err := fmt.Sscanf(expiryMs, "%d", &expiry); err != nil {
		return false
	}
	if time.Now().UnixMilli() > expiry {
		return false
	}

	// Verify HMAC
	data := fmt.Sprintf("%s|%d", sessionID, expiry)
	mac := hmac.New(sha256.New, cc.hmacKey)
	mac.Write([]byte(data))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(sig), []byte(expectedSig))
}

// splitClearanceCookie splits a cookie value into [sessionID, expiryMs, signature].
func splitClearanceCookie(value string) []string {
	// Find last two dots to split: sessionID may contain dots
	lastDot := -1
	secondLastDot := -1
	for i := len(value) - 1; i >= 0; i-- {
		if value[i] == '.' {
			if lastDot == -1 {
				lastDot = i
			} else {
				secondLastDot = i
				break
			}
		}
	}
	if secondLastDot == -1 || lastDot == -1 {
		return nil
	}
	return []string{
		value[:secondLastDot],
		value[secondLastDot+1 : lastDot],
		value[lastDot+1:],
	}
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

// generateTurnstileToken creates a Turnstile response token.
func (cc *CloudflareChallenger) generateTurnstileToken(sessionID string) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return fmt.Sprintf("0.%s.%s", hex.EncodeToString(b), sessionID)
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

// EstimatePoWIterations returns the expected number of iterations for a given difficulty.
func EstimatePoWIterations(difficulty int) *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), uint(difficulty))
}
