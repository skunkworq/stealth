package solver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	httpclient "github.com/skunkworq/stealth/brws/network/client"
	"github.com/skunkworq/stealth/brws/stealth/challenge"
	"github.com/skunkworq/stealth/brws/stealth/behavior"
)

// CloudflareSolverClient solves lab-reproduced Cloudflare challenges.
// The fingerprint is pinned on first generation and reused for the lifetime
// of the client, ensuring session consistency (P7.2).
type CloudflareSolverClient struct {
	httpClient        *http.Client
	eventGen          *CaptchaSolver
	rng               *rand.Rand
	maxIterations     int64
	pinnedFingerprint *challenge.FingerprintPayload
	pinnedProfile     *behavior.BrowserProfile
}

// CloudflareSolveResult holds the outcome of a Cloudflare challenge solve attempt.
type CloudflareSolveResult struct {
	SessionID        string                          `json:"session_id"`
	ChallengeType    string                          `json:"challenge_type"`
	Passed           bool                            `json:"passed"`
	ClearanceCookie  *http.Cookie                    `json:"clearance_cookie,omitempty"`
	TurnstileToken   string                          `json:"turnstile_token,omitempty"`
	Turnstile        *challenge.LabTurnstileToken  `json:"turnstile,omitempty"`
	WidgetTelemetry  *challenge.WidgetTelemetry    `json:"widget_telemetry,omitempty"`
	Verification     *challenge.VerificationResult `json:"verification,omitempty"`
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
	client := httpclient.New(httpclient.DefaultConfig()) // DefaultConfig = 30s
	client.Jar = jar
	return &CloudflareSolverClient{
		httpClient:    client,
		eventGen:      NewCaptchaSolver(),
		//nolint:gosec
		rng:           rand.New(rand.NewSource(time.Now().UnixNano())),
		maxIterations: 50_000_000,
	}
}

// CFInitResp mirrors the server's init response.
type CFInitResp struct {
	SessionID           string                             `json:"session_id"`
	Type                string                             `json:"type"`
	RayID               string                             `json:"ray_id"`
	PoW                 *challenge.PoWChallenge          `json:"pow"`
	RequiresFingerprint bool                               `json:"requires_fingerprint"`
	RequiresBehavioral  bool                               `json:"requires_behavioral"`
	SiteKey             string                             `json:"site_key,omitempty"`
	Turnstile           *challenge.TurnstileWidgetConfig `json:"turnstile,omitempty"`
}

// cfInitResp is an alias kept for internal use.
type cfInitResp = CFInitResp

// cfSolveResp mirrors the server's solve response.
type cfSolveResp struct {
	Success         bool                           `json:"success"`
	Error           string                         `json:"error,omitempty"`
	Method          string                         `json:"method,omitempty"`
	SolveMs         int64                          `json:"solve_ms,omitempty"`
	CfClearance     string                         `json:"cf_clearance,omitempty"`
	TurnstileToken  string                         `json:"turnstile_token,omitempty"`
	Turnstile       *challenge.LabTurnstileToken `json:"turnstile,omitempty"`
	WidgetTelemetry *challenge.WidgetTelemetry   `json:"widget_telemetry,omitempty"`
}

// TurnstileFlowOptions controls how the owned-environment Turnstile flow is exercised.
type TurnstileFlowOptions struct {
	SiteKey        string
	DetectionScore float64
	Verifier       TurnstileVerifier
}

// TurnstileInteractionPlan holds a generated pointer event trace and its proof.
type TurnstileInteractionPlan struct {
	InteractionProof *challenge.TurnstileInteractionProof
	Events           []challenge.CaptchaEvent
}

type turnstileApproachProfile struct {
	minCloseMoves int
	minHoverMs    int
	minSettleMs   int
}

type turnstileApproachMetrics struct {
	hoverDurationMs int
	moveCount       int
	settleDelayMs   int64
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
	powSolution, err := cs.SolvePoW(initResp.PoW.Prefix, initResp.PoW.Difficulty)
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
	powSolution, err := cs.SolvePoW(initResp.PoW.Prefix, initResp.PoW.Difficulty)
	if err != nil {
		return nil, fmt.Errorf("PoW failed: %w", err)
	}

	// Step 3: Generate fingerprint from a random profile
	fp := cs.generateFingerprint()

	// Step 4: Generate a human-like pointer trace for the lab harness.
	events := cs.buildTurnstileInteractionPlan(nil).Events

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

// SolveTurnstileLab performs the full local Turnstile challenge flow against owned environments only.
func (cs *CloudflareSolverClient) SolveTurnstileLab(baseURL string) (*CloudflareSolveResult, error) {
	return cs.ExerciseTurnstileFlow(baseURL, nil)
}

// ExerciseTurnstileFlow performs the full local Turnstile widget flow and optional verification.
func (cs *CloudflareSolverClient) ExerciseTurnstileFlow(baseURL string, opts *TurnstileFlowOptions) (*CloudflareSolveResult, error) {
	if err := ensureCloudflareLabHostAllowed(baseURL); err != nil {
		return nil, err
	}
	totalStart := time.Now()

	siteKey := ""
	detectionScore := 0.30
	if opts != nil {
		siteKey = opts.SiteKey
		if opts.DetectionScore > 0 {
			detectionScore = opts.DetectionScore
		}
	}

	// Step 1: Init
	initResp, err := cs.initChallenge(baseURL, "cloudflare_turnstile", detectionScore, siteKey)
	if err != nil {
		return nil, fmt.Errorf("init failed: %w", err)
	}

	plan := cs.buildTurnstileInteractionPlan(initResp.Turnstile)

	// Step 2: Exercise the local widget lifecycle.
	if err := cs.exerciseTurnstileWidget(baseURL, initResp, plan); err != nil {
		return nil, fmt.Errorf("exercise widget: %w", err)
	}

	// Step 3: Solve PoW
	powSolution, err := cs.SolvePoW(initResp.PoW.Prefix, initResp.PoW.Difficulty)
	if err != nil {
		return nil, fmt.Errorf("PoW failed: %w", err)
	}

	// Step 4: Submit the same interaction trace that informed the widget proof.
	events := plan.Events

	// Step 5: Submit
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
	if !solveResp.Success {
		if solveResp.Error == "" {
			solveResp.Error = fmt.Sprintf("turnstile solve failed with status %d", resp.StatusCode)
		}
		return result, fmt.Errorf("%s", solveResp.Error)
	}

	if opts != nil && opts.Verifier != nil && solveResp.TurnstileToken != "" {
		verifyResult, err := opts.Verifier.Verify(context.Background(), solveResp.TurnstileToken)
		if err != nil {
			return nil, fmt.Errorf("verify turnstile token: %w", err)
		}
		result.Verification = verifyResult
		if !verifyResult.Success {
			return nil, fmt.Errorf("turnstile token verification failed: %v", verifyResult.ErrorCodes)
		}
	}

	return result, nil
}

// SolveTurnstile is kept as a compatibility wrapper around the lab-only handler.
func (cs *CloudflareSolverClient) SolveTurnstile(baseURL string) (*CloudflareSolveResult, error) {
	return cs.SolveTurnstileLab(baseURL)
}

func (cs *CloudflareSolverClient) exerciseTurnstileWidget(baseURL string, initResp *cfInitResp, plan *TurnstileInteractionPlan) error {
	widgetURL := fmt.Sprintf(
		"%s/api/cloudflare/turnstile/widget?session_id=%s&site_key=%s",
		strings.TrimRight(baseURL, "/"),
		url.QueryEscape(initResp.SessionID),
		url.QueryEscape(initResp.SiteKey),
	)

	resp, err := cs.httpClient.Get(widgetURL)
	if err != nil {
		return fmt.Errorf("fetch widget page: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read widget page: %w", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		return fmt.Errorf("unexpected widget status: %d", resp.StatusCode)
	}

	page := string(body)
	if !strings.Contains(page, `class="cf-turnstile"`) {
		return fmt.Errorf("widget page missing cf-turnstile marker")
	}
	if initResp.Turnstile != nil {
		for _, marker := range []string{
			fmt.Sprintf(`data-action="%s"`, initResp.Turnstile.Action),
			fmt.Sprintf(`data-cdata="%s"`, initResp.Turnstile.CData),
			fmt.Sprintf(`data-interaction="%s"`, initResp.Turnstile.Interaction.Type),
			fmt.Sprintf(`data-retry-interval="%d"`, initResp.Turnstile.RetryPolicy.IntervalMs),
		} {
			if !strings.Contains(page, marker) {
				return fmt.Errorf("widget page missing marker %q", marker)
			}
		}
	}

	if err := cs.postTurnstileSnapshot(baseURL, initResp.RayID, initResp.SessionID); err != nil {
		return err
	}
	cs.turnstileLiveDelay(45, 90)

	callbacks := []struct {
		name         string
		delayAfterMs [2]int
	}{
		{name: "before-interactive", delayAfterMs: [2]int{70, 130}},
		{name: "after-interactive", delayAfterMs: [2]int{150, 260}},
	}
	for _, callback := range callbacks {
		if err := cs.postTurnstileCallback(baseURL, initResp.RayID, initResp.SessionID, callback.name); err != nil {
			return err
		}
		cs.turnstileLiveDelay(callback.delayAfterMs[0], callback.delayAfterMs[1])
	}
	if plan != nil && plan.InteractionProof != nil {
		if err := cs.postTurnstileInteraction(baseURL, initResp.RayID, initResp.SessionID, plan.InteractionProof); err != nil {
			return err
		}
	}

	return nil
}

func (cs *CloudflareSolverClient) postTurnstileSnapshot(baseURL, rayID, sessionID string) error {
	snapshot := cs.buildTurnstileSnapshot()
	payload, err := json.Marshal(map[string]interface{}{
		"session_id": sessionID,
		"type":       "snapshot",
		"snapshot":   snapshot,
	})
	if err != nil {
		return fmt.Errorf("marshal snapshot payload: %w", err)
	}

	endpoint := fmt.Sprintf(
		"%s/cdn-cgi/challenge-platform/h/g/cv/result/%s",
		strings.TrimRight(baseURL, "/"),
		url.PathEscape(rayID),
	)

	resp, err := cs.httpClient.Post(endpoint, "application/json", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("post snapshot: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected snapshot status: %d", resp.StatusCode)
	}

	return nil
}

func (cs *CloudflareSolverClient) postTurnstileCallback(baseURL, rayID, sessionID, callback string) error {
	payload, err := json.Marshal(map[string]string{
		"session_id": sessionID,
		"callback":   callback,
	})
	if err != nil {
		return fmt.Errorf("marshal callback payload: %w", err)
	}

	endpoint := fmt.Sprintf(
		"%s/cdn-cgi/challenge-platform/h/g/cv/result/%s",
		strings.TrimRight(baseURL, "/"),
		url.PathEscape(rayID),
	)

	resp, err := cs.httpClient.Post(endpoint, "application/json", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("post %s callback: %w", callback, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected %s callback status: %d", callback, resp.StatusCode)
	}

	return nil
}

func (cs *CloudflareSolverClient) postTurnstileInteraction(baseURL, rayID, sessionID string, proof *challenge.TurnstileInteractionProof) error {
	if proof == nil {
		return nil
	}

	payload, err := json.Marshal(map[string]interface{}{
		"session_id":  sessionID,
		"type":        "interaction",
		"interaction": proof,
	})
	if err != nil {
		return fmt.Errorf("marshal interaction payload: %w", err)
	}

	endpoint := fmt.Sprintf(
		"%s/cdn-cgi/challenge-platform/h/g/cv/result/%s",
		strings.TrimRight(baseURL, "/"),
		url.PathEscape(rayID),
	)

	resp, err := cs.httpClient.Post(endpoint, "application/json", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("post interaction proof: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected interaction status: %d", resp.StatusCode)
	}

	return nil
}

// HTTPClient returns the internal HTTP client (used by tests to inject cookies).
func (cs *CloudflareSolverClient) HTTPClient() *http.Client {
	return cs.httpClient
}

// EventGen returns the internal captcha event generator.
func (cs *CloudflareSolverClient) EventGen() *CaptchaSolver {
	return cs.eventGen
}

// InitChallenge sends a POST to /api/cloudflare/init and returns the session.
func (cs *CloudflareSolverClient) InitChallenge(baseURL, challengeType string, score float64, siteKey string) (*cfInitResp, error) {
	return cs.initChallenge(baseURL, challengeType, score, siteKey)
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

// SolvePoW performs the SHA-256 hashcash loop (exported for testing).
func (cs *CloudflareSolverClient) SolvePoW(prefix string, difficulty int) (*challenge.PoWSolution, error) {
	return challenge.SolvePoW(prefix, difficulty, cs.maxIterations)
}

// TimezoneToOffset maps IANA timezone strings to their UTC offset in minutes
// (matching JavaScript's Date.getTimezoneOffset() convention: negative = ahead of UTC).
func TimezoneToOffset(tz string) int {
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

// GenerateFingerprint returns a session-pinned fingerprint (exported for testing).
func (cs *CloudflareSolverClient) GenerateFingerprint() *challenge.FingerprintPayload {
	return cs.generateFingerprint()
}

// generateFingerprint returns a session-pinned fingerprint. On the first call it
// selects a random browser profile and generates hardware parameters that are
// then reused for all subsequent calls, ensuring session consistency (P7.2).
func (cs *CloudflareSolverClient) generateFingerprint() *challenge.FingerprintPayload {
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

	cs.pinnedFingerprint = &challenge.FingerprintPayload{
		CanvasHash:          canvasHash,
		WebGLVendor:         profile.WebGLVendor,
		WebGLRenderer:       renderer,
		Platform:            profile.NavPlatform,
		Languages:           profile.Languages,
		HardwareConcurrency: hwConc,
		DeviceMemory:        devMem,
		ScreenWidth:         screenW,
		ScreenHeight:        screenH,
		TimezoneOffset:      TimezoneToOffset(profile.Timezone),
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

// SubmitSolution posts a challenge solution to the appropriate CF solve endpoint (exported for testing).
func (cs *CloudflareSolverClient) SubmitSolution(
	baseURL string,
	ch *challenge.CloudflareChallenge,
	solution *challenge.PoWSolution,
	fp *challenge.FingerprintPayload,
	events []challenge.CaptchaEvent,
) (*http.Cookie, error) {
	return cs.submitSolution(baseURL, ch, solution, fp, events)
}

// submitSolution posts a challenge solution to the appropriate CF solve endpoint.
// Used by the auto-solve flow when Navigate() encounters a CF challenge.
func (cs *CloudflareSolverClient) submitSolution(
	baseURL string,
	ch *challenge.CloudflareChallenge,
	solution *challenge.PoWSolution,
	fp *challenge.FingerprintPayload,
	events []challenge.CaptchaEvent,
) (*http.Cookie, error) {
	var endpoint string
	var payload map[string]interface{}

	switch ch.Type {
	case challenge.ChallengeJS:
		endpoint = baseURL + "/api/cloudflare/solve/js"
		payload = map[string]interface{}{
			"session_id": ch.RayID,
			"solution":   solution,
		}
	case challenge.ChallengeManaged:
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

func (cs *CloudflareSolverClient) buildTurnstileSnapshot() *challenge.TurnstileClientSnapshot {
	if cs.pinnedFingerprint == nil || cs.pinnedProfile == nil {
		cs.generateFingerprint()
	}

	profile := cs.pinnedProfile
	fp := cs.pinnedFingerprint
	if profile == nil || fp == nil {
		return &challenge.TurnstileClientSnapshot{
			UserAgent:           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
			Language:            "en-US",
			Languages:           []string{"en-US", "en"},
			Platform:            "Win32",
			HardwareConcurrency: 8,
			ScreenWidth:         1920,
			ScreenHeight:        1080,
			ColorDepth:          24,
			Timezone:            "America/New_York",
			CookieEnabled:       true,
		}
	}

	language := ""
	if len(profile.Languages) > 0 {
		language = profile.Languages[0]
	}

	return &challenge.TurnstileClientSnapshot{
		UserAgent:           profile.UserAgent,
		Language:            language,
		Languages:           append([]string(nil), profile.Languages...),
		Platform:            profile.NavPlatform,
		HardwareConcurrency: fp.HardwareConcurrency,
		Webdriver:           false,
		ScreenWidth:         fp.ScreenWidth,
		ScreenHeight:        fp.ScreenHeight,
		ColorDepth:          fp.ColorDepth,
		Timezone:            profile.Timezone,
		MaxTouchPoints:      profile.MaxTouchPoints,
		CookieEnabled:       true,
	}
}

// BuildTurnstileInteractionPlan builds a human-like pointer event trace for a Turnstile widget.
func (cs *CloudflareSolverClient) BuildTurnstileInteractionPlan(cfg *challenge.TurnstileWidgetConfig) *TurnstileInteractionPlan {
	return cs.buildTurnstileInteractionPlan(cfg)
}

func (cs *CloudflareSolverClient) buildTurnstileInteractionPlan(cfg *challenge.TurnstileWidgetConfig) *TurnstileInteractionPlan {
	builder := newTurnstileTraceBuilder()
	proof := &challenge.TurnstileInteractionProof{
		Type:           "checkbox",
		Completed:      true,
		CheckboxClicks: 1,
	}

	interactionType := "checkbox"
	if cfg != nil && cfg.Interaction.Type != "" {
		interactionType = cfg.Interaction.Type
	}

	switch interactionType {
	case "hold":
		requiredHoldMs := 900
		if cfg != nil && cfg.Interaction.RequiredHoldMs > 0 {
			requiredHoldMs = cfg.Interaction.RequiredHoldMs
		}
		downX := 206.0 + cs.turnstileJitter(1.8)
		downY := 194.0 + cs.turnstileJitter(1.5)
		approach := cs.appendTurnstileApproach(builder, downX, downY, turnstileApproachProfile{
			minCloseMoves: 4,
			minHoverMs:    260,
			minSettleMs:   110,
		})
		down := builder.addPointer(approach.settleDelayMs, "mousedown", downX, downY)

		holdMs := requiredHoldMs + 260 + cs.rng.Intn(380)
		holdMoves := 4 + cs.rng.Intn(3)
		heldFor := 0
		for i := 0; i < holdMoves; i++ {
			step := holdMs/holdMoves + cs.rng.Intn(80) - 25
			if step < 115 {
				step = 115
			}
			heldFor += step
			builder.addPointer(
				int64(step),
				"mousemove",
				downX+cs.turnstileJitter(2.2),
				downY+cs.turnstileJitter(1.7),
			)
			if i == holdMoves/2 {
				pause := cs.turnstileDelay(130, 210)
				heldFor += int(pause)
				builder.addPointer(
					pause,
					"mousemove",
					downX+cs.turnstileJitter(1.6),
					downY+cs.turnstileJitter(1.2),
				)
			}
		}
		if heldFor < holdMs {
			builder.addPointer(
				int64(holdMs-heldFor),
				"mousemove",
				downX+cs.turnstileJitter(1.5),
				downY+cs.turnstileJitter(1.2),
			)
		}
		up := builder.addPointer(
			cs.turnstileDelay(45, 80),
			"mouseup",
			downX+cs.turnstileJitter(1.6),
			downY+cs.turnstileJitter(1.2),
		)
		builder.addPointer(cs.turnstileDelay(20, 42), "click", up.X+cs.turnstileJitter(0.8), up.Y+cs.turnstileJitter(0.8))
		proof = &challenge.TurnstileInteractionProof{
			Type:           "hold",
			Completed:      true,
			HoldDurationMs: int(up.Timestamp - down.Timestamp),
		}
	case "drag_precision":
		requiredDistance := 162
		requiredEvents := 8
		requiredApproachHoverMs := 220
		requiredApproachMoves := 3
		requiredApproachSettleMs := 90
		requiredOvershootPx := 18
		requiredSettleMs := 180
		requiredDirectionChanges := 1
		targetZoneWidth := 24
		if cfg != nil {
			if cfg.Interaction.RequiredDragDistancePx > 0 {
				requiredDistance = cfg.Interaction.RequiredDragDistancePx
			}
			if cfg.Interaction.RequiredDragEventCount > 0 {
				requiredEvents = cfg.Interaction.RequiredDragEventCount
			}
			if cfg.Interaction.RequiredApproachHoverMs > 0 {
				requiredApproachHoverMs = cfg.Interaction.RequiredApproachHoverMs
			}
			if cfg.Interaction.RequiredApproachMoves > 0 {
				requiredApproachMoves = cfg.Interaction.RequiredApproachMoves
			}
			if cfg.Interaction.RequiredApproachSettleMs > 0 {
				requiredApproachSettleMs = cfg.Interaction.RequiredApproachSettleMs
			}
			if cfg.Interaction.RequiredOvershootPx > 0 {
				requiredOvershootPx = cfg.Interaction.RequiredOvershootPx
			}
			if cfg.Interaction.RequiredSettleMs > 0 {
				requiredSettleMs = cfg.Interaction.RequiredSettleMs
			}
			if cfg.Interaction.RequiredDirectionChanges > 0 {
				requiredDirectionChanges = cfg.Interaction.RequiredDirectionChanges
			}
			if cfg.Interaction.TargetZoneWidthPx > 0 {
				targetZoneWidth = cfg.Interaction.TargetZoneWidthPx
			}
		}
		downX := 122.0 + cs.turnstileJitter(1.4)
		downY := 244.0 + cs.turnstileJitter(1.2)
		approach := cs.appendTurnstileApproach(builder, downX, downY, turnstileApproachProfile{
			minCloseMoves: requiredApproachMoves + 1,
			minHoverMs:    requiredApproachHoverMs + 120 + cs.rng.Intn(140),
			minSettleMs:   requiredApproachSettleMs + 35 + cs.rng.Intn(60),
		})
		down := builder.addPointer(approach.settleDelayMs, "mousedown", downX, downY)

		dragMoves := requiredEvents + 4 + cs.rng.Intn(3)
		if dragMoves < 10 {
			dragMoves = 10
		}
		overshootGoal := requiredOvershootPx + 7 + cs.rng.Intn(8)
		maxOffset := requiredDistance + overshootGoal
		zonePadding := 4 + cs.rng.Intn(4)
		releaseOffset := requiredDistance + zonePadding
		maxZoneOffset := requiredDistance + targetZoneWidth - 3
		if maxZoneOffset < releaseOffset {
			maxZoneOffset = releaseOffset
		}
		if releaseOffset > maxZoneOffset {
			releaseOffset = maxZoneOffset
		}

		arcHeight := 4.5 + cs.rng.Float64()*5.0
		maxDragX := down.X
		directionChanges := 0
		lastDirection := 0
		lastMoveX := down.X
		dragMoveCount := 0
		lastMoveTS := down.Timestamp
		recordMove := func(delayMs int64, x, y float64) challenge.CaptchaEvent {
			move := builder.addPointer(delayMs, "mousemove", x, y)
			dragMoveCount++
			if move.X > maxDragX {
				maxDragX = move.X
			}
			delta := move.X - lastMoveX
			dir := 0
			if delta > 0 {
				dir = 1
			} else if delta < 0 {
				dir = -1
			}
			if lastDirection != 0 && dir != 0 && dir != lastDirection {
				directionChanges++
			}
			if dir != 0 {
				lastDirection = dir
			}
			lastMoveX = move.X
			lastMoveTS = move.Timestamp
			return move
		}

		forwardMoves := dragMoves - 2
		if forwardMoves < 7 {
			forwardMoves = 7
		}
		for i := 1; i <= forwardMoves; i++ {
			progress := float64(i) / float64(forwardMoves)
			eased := 1 - math.Pow(1-progress, 1.85)
			offset := float64(maxOffset)*eased + cs.turnstileJitter(1.8)
			delay := cs.turnstileDelay(68, 145)
			if i == forwardMoves/2 {
				delay = cs.turnstileDelay(140, 230)
			}
			recordMove(
				delay,
				down.X+offset,
				down.Y-math.Sin(progress*math.Pi)*arcHeight+cs.turnstileJitter(1.4),
			)
		}
		nearReleaseX := down.X + float64(releaseOffset+3) + cs.turnstileJitter(0.8)
		recordMove(cs.turnstileDelay(95, 160), nearReleaseX, down.Y+cs.turnstileJitter(1.2))
		finalMove := recordMove(
			cs.turnstileDelay(110, 175),
			down.X+float64(releaseOffset)+cs.turnstileJitter(0.6),
			down.Y+cs.turnstileJitter(1.0),
		)
		if directionChanges < requiredDirectionChanges {
			directionChanges = requiredDirectionChanges
		}

		up := builder.addPointer(
			int64(requiredSettleMs+80+cs.rng.Intn(150)),
			"mouseup",
			finalMove.X+cs.turnstileJitter(0.4),
			finalMove.Y+cs.turnstileJitter(0.4),
		)
		builder.addPointer(cs.turnstileDelay(24, 46), "click", up.X+cs.turnstileJitter(0.5), up.Y+cs.turnstileJitter(0.5))
		proof = &challenge.TurnstileInteractionProof{
			Type:              "drag_precision",
			Completed:         true,
			DragDistancePx:    int(math.Round(maxDragX - down.X)),
			DragEventCount:    dragMoveCount,
			ApproachHoverMs:   approach.hoverDurationMs,
			ApproachMoveCount: approach.moveCount,
			ApproachSettleMs:  int(approach.settleDelayMs),
			OvershootPx:       int(math.Round(maxDragX - up.X)),
			SettleDurationMs:  int(up.Timestamp - lastMoveTS),
			DirectionChanges:  directionChanges,
			FinalDragOffsetPx: int(math.Round(up.X - down.X)),
		}
	case "drag":
		requiredDistance := 160
		requiredEvents := 6
		if cfg != nil {
			if cfg.Interaction.RequiredDragDistancePx > 0 {
				requiredDistance = cfg.Interaction.RequiredDragDistancePx
			}
			if cfg.Interaction.RequiredDragEventCount > 0 {
				requiredEvents = cfg.Interaction.RequiredDragEventCount
			}
		}
		downX := 122.0 + cs.turnstileJitter(1.5)
		downY := 244.0 + cs.turnstileJitter(1.4)
		approach := cs.appendTurnstileApproach(builder, downX, downY, turnstileApproachProfile{
			minCloseMoves: 4,
			minHoverMs:    240,
			minSettleMs:   100,
		})
		down := builder.addPointer(approach.settleDelayMs, "mousedown", downX, downY)

		dragMoves := requiredEvents + 4 + cs.rng.Intn(3)
		if dragMoves < 9 {
			dragMoves = 9
		}
		goalDistance := requiredDistance + 20 + cs.rng.Intn(26)
		arcHeight := 4.5 + cs.rng.Float64()*4.5
		maxDragX := down.X
		recordMove := func(delayMs int64, x, y float64) {
			move := builder.addPointer(delayMs, "mousemove", x, y)
			if move.X > maxDragX {
				maxDragX = move.X
			}
		}

		for i := 1; i <= dragMoves; i++ {
			progress := float64(i) / float64(dragMoves)
			eased := 1 - math.Pow(1-progress, 1.72)
			x := down.X + float64(goalDistance)*eased + cs.turnstileJitter(2.2)
			y := down.Y - math.Sin(progress*math.Pi)*arcHeight + cs.turnstileJitter(1.5)
			delay := cs.turnstileDelay(60, 128)
			if i == dragMoves/2 {
				delay = cs.turnstileDelay(130, 220)
			}
			recordMove(delay, x, y)
		}
		if cs.rng.Float64() < 0.55 {
			dragMoves++
			recordMove(
				cs.turnstileDelay(82, 145),
				down.X+float64(goalDistance)-4+cs.turnstileJitter(1.2),
				down.Y+cs.turnstileJitter(1.0),
			)
		}

		upX := down.X + float64(goalDistance) + cs.turnstileJitter(1.4)
		upY := down.Y + cs.turnstileJitter(1.0)
		builder.addPointer(cs.turnstileDelay(90, 160), "mouseup", upX, upY)
		builder.addPointer(cs.turnstileDelay(18, 36), "click", upX+cs.turnstileJitter(0.7), upY+cs.turnstileJitter(0.7))
		proof = &challenge.TurnstileInteractionProof{
			Type:           "drag",
			Completed:      true,
			DragDistancePx: int(math.Round(maxDragX - down.X)),
			DragEventCount: dragMoves,
		}
	default:
		clickX := 302.0 + cs.turnstileJitter(1.5)
		clickY := 171.0 + cs.turnstileJitter(1.4)
		approach := cs.appendTurnstileApproach(builder, clickX, clickY, turnstileApproachProfile{
			minCloseMoves: 3,
			minHoverMs:    220,
			minSettleMs:   95,
		})
		builder.addPointer(
			cs.turnstileDelay(95, 165),
			"mousemove",
			clickX+cs.turnstileJitter(1.1),
			clickY+cs.turnstileJitter(1.0),
		)
		builder.addPointer(approach.settleDelayMs+cs.turnstileDelay(35, 75), "mousedown", clickX, clickY)
		up := builder.addPointer(
			cs.turnstileDelay(80, 135),
			"mouseup",
			clickX+cs.turnstileJitter(1.0),
			clickY+cs.turnstileJitter(1.0),
		)
		builder.addPointer(cs.turnstileDelay(22, 42), "click", up.X+cs.turnstileJitter(0.6), up.Y+cs.turnstileJitter(0.6))
	}

	return &TurnstileInteractionPlan{
		InteractionProof: proof,
		Events:           builder.events,
	}
}

func (cs *CloudflareSolverClient) appendTurnstileApproach(builder *turnstileTraceBuilder, targetX, targetY float64, profile turnstileApproachProfile) turnstileApproachMetrics {
	startX := targetX - (110.0 + cs.rng.Float64()*70.0)
	startY := targetY + (35.0 + cs.rng.Float64()*55.0)
	points := 9 + cs.rng.Intn(4)
	arcHeight := 10.0 + cs.rng.Float64()*8.0

	for i := 0; i < points; i++ {
		progress := float64(i+1) / float64(points)
		eased := 1 - math.Pow(1-progress, 1.55)
		pathNoise := 5.0 - progress*2.0
		x := startX + (targetX-startX)*eased + cs.turnstileJitter(pathNoise)
		y := startY + (targetY-startY)*eased - math.Sin(progress*math.Pi)*arcHeight + cs.turnstileJitter(2.8)
		builder.addPointer(cs.turnstileDelay(95, 185), "mousemove", x, y)
		if i == points/2 {
			builder.addWheel(cs.turnstileDelay(55, 110), 40.0+cs.rng.Float64()*95.0)
		}
	}

	closeMoves := profile.minCloseMoves
	if closeMoves <= 0 {
		closeMoves = 3
	}
	closeMoves += cs.rng.Intn(2)
	minHoverMs := profile.minHoverMs
	if minHoverMs <= 0 {
		minHoverMs = 220
	}
	firstCloseTS := int64(0)
	lastCloseTS := int64(0)
	for i := 0; i < closeMoves; i++ {
		move := builder.addPointer(
			cs.turnstileDelay(105, 175),
			"mousemove",
			targetX+cs.turnstileJitter(2.0),
			targetY+cs.turnstileJitter(1.6),
		)
		if firstCloseTS == 0 {
			firstCloseTS = move.Timestamp
		}
		lastCloseTS = move.Timestamp
	}
	for firstCloseTS > 0 && lastCloseTS-firstCloseTS < int64(minHoverMs) {
		move := builder.addPointer(
			cs.turnstileDelay(110, 170),
			"mousemove",
			targetX+cs.turnstileJitter(1.4),
			targetY+cs.turnstileJitter(1.1),
		)
		closeMoves++
		lastCloseTS = move.Timestamp
	}

	settleMin := profile.minSettleMs
	if settleMin <= 0 {
		settleMin = 95
	}

	return turnstileApproachMetrics{
		hoverDurationMs: int(lastCloseTS - firstCloseTS),
		moveCount:       closeMoves,
		settleDelayMs:   int64(settleMin + 20 + cs.rng.Intn(70)),
	}
}

func (cs *CloudflareSolverClient) turnstileDelay(minMs, maxMs int) int64 {
	if maxMs <= minMs {
		return int64(minMs)
	}
	return int64(minMs + cs.rng.Intn(maxMs-minMs+1))
}

func (cs *CloudflareSolverClient) turnstileLiveDelay(minMs, maxMs int) {
	time.Sleep(time.Duration(cs.turnstileDelay(minMs, maxMs)) * time.Millisecond)
}

func (cs *CloudflareSolverClient) turnstileJitter(amplitude float64) float64 {
	if amplitude <= 0 {
		return 0
	}
	return (cs.rng.Float64()*2 - 1) * amplitude
}

type turnstileTraceBuilder struct {
	base   int64
	cursor int64
	events []challenge.CaptchaEvent
}

func newTurnstileTraceBuilder() *turnstileTraceBuilder {
	return &turnstileTraceBuilder{
		base:   time.Now().UnixMilli(),
		events: make([]challenge.CaptchaEvent, 0, 16),
	}
}

func (tb *turnstileTraceBuilder) addPointer(delayMs int64, eventType string, x, y float64) challenge.CaptchaEvent {
	if delayMs < 0 {
		delayMs = 0
	}
	tb.cursor += delayMs
	event := challenge.CaptchaEvent{
		Type:      eventType,
		Timestamp: tb.base + tb.cursor,
		ElapsedMs: tb.cursor,
		X:         x,
		Y:         y,
	}
	tb.events = append(tb.events, event)
	return event
}

func (tb *turnstileTraceBuilder) addWheel(delayMs int64, delta float64) {
	if delayMs < 0 {
		delayMs = 0
	}
	tb.cursor += delayMs
	tb.events = append(tb.events, challenge.CaptchaEvent{
		Type:      "wheel",
		Timestamp: tb.base + tb.cursor,
		ElapsedMs: tb.cursor,
		Delta:     delta,
	})
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
