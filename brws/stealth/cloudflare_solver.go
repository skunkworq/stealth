package stealth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/behavior"
)

// CloudflareSolverClient solves lab-reproduced Cloudflare challenges.
// The fingerprint is pinned on first generation and reused for the lifetime
// of the client, ensuring session consistency (P7.2).
type CloudflareSolverClient struct {
	httpClient        *http.Client
	eventGen          *CaptchaSolver
	rng               *rand.Rand
	maxIterations     int64
	pinnedFingerprint *adversarial.FingerprintPayload
	pinnedProfile     *behavior.BrowserProfile
}

// CloudflareSolveResult holds the outcome of a Cloudflare challenge solve attempt.
type CloudflareSolveResult struct {
	SessionID        string                          `json:"session_id"`
	ChallengeType    string                          `json:"challenge_type"`
	Passed           bool                            `json:"passed"`
	ClearanceCookie  *http.Cookie                    `json:"clearance_cookie,omitempty"`
	TurnstileToken   string                          `json:"turnstile_token,omitempty"`
	Turnstile        *adversarial.LabTurnstileToken  `json:"turnstile,omitempty"`
	WidgetTelemetry  *adversarial.WidgetTelemetry    `json:"widget_telemetry,omitempty"`
	Verification     *adversarial.VerificationResult `json:"verification,omitempty"`
	PoWTimeMs        int64                           `json:"pow_time_ms"`
	TotalTimeMs      int64                           `json:"total_time_ms"`
	PoWIterations    int64                           `json:"pow_iterations"`
	PoWDifficulty    int                             `json:"pow_difficulty"`
	BehavioralScore  float64                         `json:"behavioral_score"`
	FingerprintScore float64                         `json:"fingerprint_score"`
}

// NewCloudflareSolverClient creates a new solver client.
func NewCloudflareSolverClient() *CloudflareSolverClient {
	jar, _ := cookiejar.New(nil)
	return &CloudflareSolverClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Jar:     jar,
		},
		eventGen: NewCaptchaSolver(),
		//nolint:gosec
		rng:           rand.New(rand.NewSource(time.Now().UnixNano())),
		maxIterations: 50_000_000,
	}
}

// cfInitResp mirrors the server's init response.
type cfInitResp struct {
	SessionID           string                             `json:"session_id"`
	Type                string                             `json:"type"`
	RayID               string                             `json:"ray_id"`
	PoW                 *adversarial.PoWChallenge          `json:"pow"`
	RequiresFingerprint bool                               `json:"requires_fingerprint"`
	RequiresBehavioral  bool                               `json:"requires_behavioral"`
	SiteKey             string                             `json:"site_key,omitempty"`
	Turnstile           *adversarial.TurnstileWidgetConfig `json:"turnstile,omitempty"`
}

// cfSolveResp mirrors the server's solve response.
type cfSolveResp struct {
	Success         bool                           `json:"success"`
	Error           string                         `json:"error,omitempty"`
	Method          string                         `json:"method,omitempty"`
	SolveMs         int64                          `json:"solve_ms,omitempty"`
	CfClearance     string                         `json:"cf_clearance,omitempty"`
	TurnstileToken  string                         `json:"turnstile_token,omitempty"`
	Turnstile       *adversarial.LabTurnstileToken `json:"turnstile,omitempty"`
	WidgetTelemetry *adversarial.WidgetTelemetry   `json:"widget_telemetry,omitempty"`
}

// SolveJSChallenge performs the full init→solvePoW→submit flow for a JS challenge.
func (cs *CloudflareSolverClient) SolveJSChallenge(baseURL string) (*CloudflareSolveResult, error) {
	if err := ensureCloudflareLabHostAllowed(baseURL); err != nil {
		return nil, err
	}
	totalStart := time.Now()

	// Step 1: Init
	initResp, err := cs.initChallenge(baseURL, "cloudflare_js", 0.5, "")
	if err != nil {
		return nil, fmt.Errorf("init failed: %w", err)
	}

	// Step 2: Solve PoW
	powSolution, err := cs.solvePoW(initResp.PoW.Prefix, initResp.PoW.Difficulty)
	if err != nil {
		return nil, fmt.Errorf("PoW failed: %w", err)
	}

	// Step 3: Submit
	body, _ := json.Marshal(map[string]interface{}{
		"session_id": initResp.SessionID,
		"solution":   powSolution,
	})

	resp, err := cs.httpClient.Post(baseURL+"/api/cloudflare/solve/js", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("solve request failed: %w", err)
	}
	defer resp.Body.Close()

	var solveResp cfSolveResp
	if err := json.NewDecoder(resp.Body).Decode(&solveResp); err != nil {
		return nil, fmt.Errorf("decode solve response: %w", err)
	}

	result := &CloudflareSolveResult{
		SessionID:     initResp.SessionID,
		ChallengeType: "cloudflare_js",
		Passed:        solveResp.Success,
		PoWTimeMs:     powSolution.TimeMs,
		TotalTimeMs:   time.Since(totalStart).Milliseconds(),
		PoWIterations: powSolution.Iterations,
		PoWDifficulty: initResp.PoW.Difficulty,
	}

	if solveResp.Success {
		result.ClearanceCookie = extractCfClearanceCookie(resp)
	}

	return result, nil
}

// SolveManagedChallenge performs the full managed challenge flow:
// init → solvePoW + generateFingerprint + generateEvents → human delay → submit
func (cs *CloudflareSolverClient) SolveManagedChallenge(baseURL string) (*CloudflareSolveResult, error) {
	if err := ensureCloudflareLabHostAllowed(baseURL); err != nil {
		return nil, err
	}
	totalStart := time.Now()

	// Step 1: Init
	initResp, err := cs.initChallenge(baseURL, "cloudflare_managed", 0.5, "")
	if err != nil {
		return nil, fmt.Errorf("init failed: %w", err)
	}

	// Step 2: Solve PoW
	powSolution, err := cs.solvePoW(initResp.PoW.Prefix, initResp.PoW.Difficulty)
	if err != nil {
		return nil, fmt.Errorf("PoW failed: %w", err)
	}

	// Step 3: Generate fingerprint from a random profile
	fp := cs.generateFingerprint()

	// Step 4: Generate behavioral events
	events := cs.eventGen.GenerateHumanEvents(5000)

	// Step 4.5: Human-like delay — managed challenges require ≥1.5s solve time
	elapsed := time.Since(totalStart)
	if elapsed < 1600*time.Millisecond {
		//nolint:gosec
		time.Sleep(1600*time.Millisecond - elapsed + time.Duration(cs.rng.Intn(500))*time.Millisecond)
	}

	// Step 5: Submit
	body, _ := json.Marshal(map[string]interface{}{
		"session_id":  initResp.SessionID,
		"solution":    powSolution,
		"fingerprint": fp,
		"events":      events,
	})

	resp, err := cs.httpClient.Post(baseURL+"/api/cloudflare/solve/managed", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("solve request failed: %w", err)
	}
	defer resp.Body.Close()

	var solveResp cfSolveResp
	if err := json.NewDecoder(resp.Body).Decode(&solveResp); err != nil {
		return nil, fmt.Errorf("decode solve response: %w", err)
	}

	result := &CloudflareSolveResult{
		SessionID:     initResp.SessionID,
		ChallengeType: "cloudflare_managed",
		Passed:        solveResp.Success,
		PoWTimeMs:     powSolution.TimeMs,
		TotalTimeMs:   time.Since(totalStart).Milliseconds(),
		PoWIterations: powSolution.Iterations,
		PoWDifficulty: initResp.PoW.Difficulty,
	}

	if solveResp.Success {
		result.ClearanceCookie = extractCfClearanceCookie(resp)
	}

	return result, nil
}

// HandleTurnstileLab performs the full local Turnstile challenge flow against owned environments only.
func (cs *CloudflareSolverClient) HandleTurnstileLab(baseURL string) (*CloudflareSolveResult, error) {
	if err := ensureCloudflareLabHostAllowed(baseURL); err != nil {
		return nil, err
	}
	totalStart := time.Now()

	// Step 1: Init
	initResp, err := cs.initChallenge(baseURL, "cloudflare_turnstile", 0.3, "")
	if err != nil {
		return nil, fmt.Errorf("init failed: %w", err)
	}

	// Step 2: Solve PoW
	powSolution, err := cs.solvePoW(initResp.PoW.Prefix, initResp.PoW.Difficulty)
	if err != nil {
		return nil, fmt.Errorf("PoW failed: %w", err)
	}

	// Step 3: Generate behavioral events
	events := cs.eventGen.GenerateHumanEvents(5000)

	// Step 4: Submit
	body, _ := json.Marshal(map[string]interface{}{
		"session_id": initResp.SessionID,
		"solution":   powSolution,
		"events":     events,
	})

	resp, err := cs.httpClient.Post(baseURL+"/api/cloudflare/solve/turnstile", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("solve request failed: %w", err)
	}
	defer resp.Body.Close()

	var solveResp cfSolveResp
	if err := json.NewDecoder(resp.Body).Decode(&solveResp); err != nil {
		return nil, fmt.Errorf("decode solve response: %w", err)
	}

	result := &CloudflareSolveResult{
		SessionID:       initResp.SessionID,
		ChallengeType:   "cloudflare_turnstile",
		Passed:          solveResp.Success,
		TurnstileToken:  solveResp.TurnstileToken,
		Turnstile:       solveResp.Turnstile,
		WidgetTelemetry: solveResp.WidgetTelemetry,
		PoWTimeMs:       powSolution.TimeMs,
		TotalTimeMs:     time.Since(totalStart).Milliseconds(),
		PoWIterations:   powSolution.Iterations,
		PoWDifficulty:   initResp.PoW.Difficulty,
	}

	if solveResp.Success {
		result.ClearanceCookie = extractCfClearanceCookie(resp)
	}

	return result, nil
}

// SolveTurnstile is kept as a compatibility wrapper around the lab-only handler.
func (cs *CloudflareSolverClient) SolveTurnstile(baseURL string) (*CloudflareSolveResult, error) {
	return cs.HandleTurnstileLab(baseURL)
}

// initChallenge sends a POST to /api/cloudflare/init and returns the session.
func (cs *CloudflareSolverClient) initChallenge(baseURL, challengeType string, score float64, siteKey string) (*cfInitResp, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"challenge_type":  challengeType,
		"detection_score": score,
		"site_key":        siteKey,
	})

	resp, err := cs.httpClient.Post(baseURL+"/api/cloudflare/init", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var initResp cfInitResp
	if err := json.NewDecoder(resp.Body).Decode(&initResp); err != nil {
		return nil, err
	}

	return &initResp, nil
}

// solvePoW performs the SHA-256 hashcash loop.
func (cs *CloudflareSolverClient) solvePoW(prefix string, difficulty int) (*adversarial.PoWSolution, error) {
	start := time.Now()

	for i := int64(0); i < cs.maxIterations; i++ {
		nonce := fmt.Sprintf("%016x", i)
		data := prefix + nonce
		hash := sha256.Sum256([]byte(data))

		if hasLeadingZeroBits(hash[:], difficulty) {
			return &adversarial.PoWSolution{
				Nonce:      nonce,
				Hash:       hex.EncodeToString(hash[:]),
				Iterations: i + 1,
				TimeMs:     time.Since(start).Milliseconds(),
			}, nil
		}
	}

	return nil, fmt.Errorf("failed to solve PoW after %d iterations", cs.maxIterations)
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

// timezoneToOffset maps IANA timezone strings to their UTC offset in minutes
// (matching JavaScript's Date.getTimezoneOffset() convention: negative = ahead of UTC).
func timezoneToOffset(tz string) int {
	switch tz {
	case "America/New_York":
		return -300
	case "America/Chicago":
		return -360
	case "America/Los_Angeles":
		return -480
	case "America/Denver":
		return -420
	case "Europe/London":
		return 0
	case "Europe/Berlin":
		return 60
	case "Europe/Paris":
		return 60
	case "Asia/Tokyo":
		return 540
	case "Asia/Shanghai":
		return 480
	case "Australia/Sydney":
		return 660
	default:
		return -300
	}
}

// generateFingerprint returns a session-pinned fingerprint. On the first call it
// selects a random browser profile and generates hardware parameters that are
// then reused for all subsequent calls, ensuring session consistency (P7.2).
func (cs *CloudflareSolverClient) generateFingerprint() *adversarial.FingerprintPayload {
	if cs.pinnedFingerprint != nil {
		return cs.pinnedFingerprint
	}

	profiles := behavior.DefaultProfiles()
	profile := profiles[cs.rng.Intn(len(profiles))]
	cs.pinnedProfile = profile

	// Pick a random resolution from the profile — pinned for session
	resIdx := cs.rng.Intn(len(profile.Resolutions))
	screenW := profile.Resolutions[resIdx][0]
	screenH := profile.Resolutions[resIdx][1]

	// Pick random hardware concurrency from profile — pinned for session
	hwConc := 4
	if len(profile.HardwareConcurrency) > 0 {
		hwConc = profile.HardwareConcurrency[cs.rng.Intn(len(profile.HardwareConcurrency))]
	}

	// Pick random device memory — pinned for session
	devMem := 8.0
	if len(profile.DeviceMemory) > 0 {
		devMem = float64(profile.DeviceMemory[cs.rng.Intn(len(profile.DeviceMemory))])
	}

	// Pick random color depth — pinned for session
	colorDepth := 24
	if len(profile.ColorDepths) > 0 {
		colorDepth = profile.ColorDepths[cs.rng.Intn(len(profile.ColorDepths))]
	}

	// Generate a stable canvas hash as a valid data:image/png;base64,... URL — pinned for session
	pngSig := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	ihdr := []byte{
		0x00, 0x00, 0x00, 0x0D, // length = 13
		0x49, 0x48, 0x44, 0x52, // "IHDR"
		0x00, 0x00, 0x00, 0x01, // width = 1
		0x00, 0x00, 0x00, 0x01, // height = 1
		0x08, 0x02, // bit depth 8, color type RGB
		0x00, 0x00, 0x00, // compression, filter, interlace
		0x90, 0x77, 0x53, 0xDE, // IHDR CRC
	}
	pixelByte := byte(cs.rng.Intn(256))
	idatData := []byte{
		0x78, 0x01, // zlib header
		0x01, 0x04, 0x00, 0xFB, 0xFF, // stored block header
		0x00, pixelByte, pixelByte, pixelByte, // filter=none + RGB pixel
	}
	s1 := uint32(1) + uint32(0) + uint32(pixelByte) + uint32(pixelByte) + uint32(pixelByte)
	s2 := uint32(1) + uint32(1) + uint32(1+pixelByte) + uint32(1+2*uint32(pixelByte)) + uint32(1+3*uint32(pixelByte))
	s1 %= 65521
	s2 %= 65521
	adler := (s2 << 16) | s1
	idatData = append(idatData, byte(adler>>24), byte(adler>>16), byte(adler>>8), byte(adler))
	idatLen := len(idatData)
	idat := make([]byte, 0, 4+4+idatLen+4)
	idat = append(idat, byte(idatLen>>24), byte(idatLen>>16), byte(idatLen>>8), byte(idatLen))
	idat = append(idat, 0x49, 0x44, 0x41, 0x54) // "IDAT"
	idat = append(idat, idatData...)
	idat = append(idat, 0x00, 0x00, 0x00, 0x00) // CRC placeholder
	iend := []byte{
		0x00, 0x00, 0x00, 0x00,
		0x49, 0x45, 0x4E, 0x44,
		0xAE, 0x42, 0x60, 0x82,
	}
	pngBytes := make([]byte, 0, len(pngSig)+len(ihdr)+len(idat)+len(iend))
	pngBytes = append(pngBytes, pngSig...)
	pngBytes = append(pngBytes, ihdr...)
	pngBytes = append(pngBytes, idat...)
	pngBytes = append(pngBytes, iend...)
	canvasHash := fmt.Sprintf("data:image/png;base64,%s", base64.StdEncoding.EncodeToString(pngBytes))

	// Pick a random WebGL renderer — pinned for session
	renderer := "ANGLE (Intel, Intel HD Graphics)"
	if len(profile.WebGLRenderers) > 0 {
		renderer = profile.WebGLRenderers[cs.rng.Intn(len(profile.WebGLRenderers))]
	}

	cs.pinnedFingerprint = &adversarial.FingerprintPayload{
		CanvasHash:          canvasHash,
		WebGLVendor:         profile.WebGLVendor,
		WebGLRenderer:       renderer,
		Platform:            profile.NavPlatform,
		Languages:           profile.Languages,
		HardwareConcurrency: hwConc,
		DeviceMemory:        devMem,
		ScreenWidth:         screenW,
		ScreenHeight:        screenH,
		TimezoneOffset:      timezoneToOffset(profile.Timezone),
		Timezone:            profile.Timezone,
		ColorDepth:          colorDepth,
		TouchPoints:         0,
	}

	return cs.pinnedFingerprint
}

// ResetFingerprint clears the pinned fingerprint, forcing a new one to be
// generated on the next call. Use this when starting a genuinely new session.
func (cs *CloudflareSolverClient) ResetFingerprint() {
	cs.pinnedFingerprint = nil
	cs.pinnedProfile = nil
}

// submitSolution posts a challenge solution to the appropriate CF solve endpoint.
// Used by the auto-solve flow when Navigate() encounters a CF challenge.
func (cs *CloudflareSolverClient) submitSolution(
	baseURL string,
	ch *adversarial.CloudflareChallenge,
	solution *adversarial.PoWSolution,
	fp *adversarial.FingerprintPayload,
	events []adversarial.CaptchaEvent,
) (*http.Cookie, error) {
	var endpoint string
	var payload map[string]interface{}

	switch ch.Type {
	case adversarial.ChallengeJS:
		endpoint = baseURL + "/api/cloudflare/solve/js"
		payload = map[string]interface{}{
			"session_id": ch.RayID,
			"solution":   solution,
		}
	case adversarial.ChallengeManaged:
		endpoint = baseURL + "/api/cloudflare/solve/managed"
		payload = map[string]interface{}{
			"session_id":  ch.RayID,
			"solution":    solution,
			"fingerprint": fp,
			"events":      events,
		}
	default:
		return nil, fmt.Errorf("unsupported challenge type for submit: %s", ch.Type)
	}

	body, _ := json.Marshal(payload)
	resp, err := cs.httpClient.Post(endpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	cookie := extractCfClearanceCookie(resp)
	if cookie == nil {
		return nil, fmt.Errorf("no cf_clearance cookie in solve response (status=%d)", resp.StatusCode)
	}
	return cookie, nil
}

// extractCfClearanceCookie finds the cf_clearance cookie in a response.
func extractCfClearanceCookie(resp *http.Response) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == "cf_clearance" {
			return c
		}
	}
	return nil
}

func ensureCloudflareLabHostAllowed(baseURL string) error {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("parse base URL: %w", err)
	}

	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return fmt.Errorf("cloudflare lab flow requires a hostname")
	}

	if adversarialHostAllowed(host) {
		return nil
	}

	return fmt.Errorf("cloudflare lab flow is restricted to localhost, loopback, or explicitly allowlisted owned hosts: %s", host)
}

func adversarialHostAllowed(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}

	if ip, err := netip.ParseAddr(host); err == nil && ip.IsLoopback() {
		return true
	}

	for _, envKey := range []string{"STEALTH_CLOUDFLARE_ALLOWED_HOSTS", "STEALTH_TURNSTILE_ALLOWED_HOSTS"} {
		for _, candidate := range strings.Split(os.Getenv(envKey), ",") {
			candidate = strings.TrimSpace(strings.ToLower(candidate))
			if candidate != "" && candidate == host {
				return true
			}
		}
	}

	return false
}
