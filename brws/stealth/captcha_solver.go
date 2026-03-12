package stealth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/png"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/adversarial/captcha"
)

// CaptchaSolver detects and auto-solves captcha challenges from shield responses.
type CaptchaSolver struct {
	solver     *captcha.Solver
	httpClient *http.Client
	rng        *rand.Rand
	lastToken  string // most recent session token from captcha solve
}

// CaptchaResponse is a parsed captcha challenge from a shield response.
type CaptchaResponse struct {
	ChallengeID   string
	Type          string
	CaptchaID     string
	ImageBase64   string
	ChallengeData map[string]interface{}
}

// SolveResult holds the output of a captcha solve attempt.
type SolveResult struct {
	Solution    string
	Confidence  float64
	SolveTimeMs int64
	Token       string // Session token from successful solve (Part 4)
}

// NewCaptchaSolver creates a new CaptchaSolver backed by the ML captcha.Solver.
func NewCaptchaSolver() *CaptchaSolver {
	return &CaptchaSolver{
		solver: captcha.NewSolver(nil),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		//nolint:gosec
		rng: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// DetectCaptchaResponse checks response body and headers for a captcha challenge.
// Returns nil if no captcha is present.
//
// Supports two captcha types:
//   - "recaptcha-v2": indicated by X-Captcha-Type header; no inline image data,
//     client follows the 5-step reCAPTCHA v2 flow.
//   - inline captcha: the original flow with embedded image data.
func (cs *CaptchaSolver) DetectCaptchaResponse(body []byte, headers map[string][]string) *CaptchaResponse {
	// Check X-Captcha-Required header
	captchaRequired := false
	for _, v := range headers["X-Captcha-Required"] {
		if v == "1" {
			captchaRequired = true
			break
		}
	}
	if !captchaRequired {
		return nil
	}

	// Check for reCAPTCHA v2 redirect
	for _, v := range headers["X-Captcha-Type"] {
		if v == "recaptcha-v2" {
			// Parse body for init_url and site_key
			var respBody map[string]interface{}
			if err := json.Unmarshal(body, &respBody); err == nil {
				return &CaptchaResponse{
					Type:          "recaptcha-v2",
					ChallengeData: respBody,
				}
			}
			return &CaptchaResponse{Type: "recaptcha-v2"}
		}
	}

	// Fallback: inline captcha with embedded image
	var respBody map[string]interface{}
	if err := json.Unmarshal(body, &respBody); err != nil {
		return nil
	}

	captchaData, ok := respBody["captcha"].(map[string]interface{})
	if !ok {
		return nil
	}

	cr := &CaptchaResponse{
		ChallengeID: stringFromMap(captchaData, "challenge_id"),
		Type:        stringFromMap(captchaData, "type"),
		CaptchaID:   stringFromMap(captchaData, "captcha_id"),
	}

	if cd, ok := captchaData["challenge_data"].(map[string]interface{}); ok {
		cr.ChallengeData = cd
		cr.ImageBase64 = stringFromMap(cd, "image")
	}

	return cr
}

// SolveFromResponse detects a captcha in the response and attempts to solve it.
// Uses SegmentationSolver (rotation-aware boundary detection) as primary, with
// TemplateSolver as fallback. Picks the result with higher confidence.
// Returns nil if no captcha is detected.
func (cs *CaptchaSolver) SolveFromResponse(body []byte, headers map[string][]string) (*SolveResult, *CaptchaResponse, error) {
	cr := cs.DetectCaptchaResponse(body, headers)
	if cr == nil {
		return nil, nil, nil
	}

	if cr.ImageBase64 == "" {
		return nil, cr, fmt.Errorf("captcha response has no image data")
	}

	start := time.Now()

	// Decode base64 PNG → image.Image
	imgBytes, err := base64.StdEncoding.DecodeString(cr.ImageBase64)
	if err != nil {
		return nil, cr, fmt.Errorf("decode captcha image: %w", err)
	}

	img, err := png.Decode(bytes.NewReader(imgBytes))
	if err != nil {
		return nil, cr, fmt.Errorf("decode captcha PNG: %w", err)
	}

	// Extract num_chars from challenge data, fallback to 6
	numChars := 6
	if cr.ChallengeData != nil {
		if nc, ok := cr.ChallengeData["num_chars"].(float64); ok && int(nc) > 0 {
			numChars = int(nc)
		}
	}

	// Primary: SegmentationSolver (handles rotation + boundary detection)
	segSolver := captcha.NewSegmentationSolver()
	segSolution, segConfidence := segSolver.SolveWithSegmentation(img, numChars)

	// Fallback: TemplateSolver (fixed-width pixel correlation)
	templateSolver := captcha.NewTemplateSolver()
	tmplSolution, tmplConfidence := templateSolver.SolveWithTemplates(img, numChars)

	// Pick the result with higher confidence
	solution, confidence := segSolution, segConfidence
	if tmplConfidence > segConfidence {
		solution, confidence = tmplSolution, tmplConfidence
	}

	solveTime := time.Since(start).Milliseconds()

	return &SolveResult{
		Solution:    solution,
		Confidence:  confidence,
		SolveTimeMs: solveTime,
	}, cr, nil
}

// SubmitSolution posts the captcha solution to the shield's verify endpoint.
// Returns (solved, token, error). The token can be used for subsequent requests.
func (cs *CaptchaSolver) SubmitSolution(verifyURL, challengeID, solution string, events []adversarial.CaptchaEvent) (bool, error) {
	reqBody := map[string]interface{}{
		"challenge_id": challengeID,
		"solution":     solution,
	}
	if len(events) > 0 {
		reqBody["events"] = events
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return false, fmt.Errorf("marshal verify request: %w", err)
	}

	resp, err := cs.httpClient.Post(verifyURL, "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		return false, fmt.Errorf("submit captcha solution: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Solved       bool   `json:"solved"`
		Message      string `json:"message"`
		CaptchaToken string `json:"captcha_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, fmt.Errorf("decode verify response: %w", err)
	}

	// Store the captcha token if present
	if result.CaptchaToken != "" {
		cs.lastToken = result.CaptchaToken
	}

	return result.Solved, nil
}

// LastToken returns the most recent captcha session token from a successful solve.
func (cs *CaptchaSolver) LastToken() string {
	return cs.lastToken
}

// HumanEventOpts provides optional parameters for GenerateHumanEvents.
type HumanEventOpts struct {
	Solution string // characters to type (instead of dummy "a")
}

// GenerateHumanEvents creates realistic mouse/keyboard events that pass the
// BehavioralAnalyzer's 8 checks: interval entropy, path curvature, velocity,
// micro-tremors, keystroke CV, scroll deltas, click precision, scroll presence.
//
// Key design: mouse events are emitted as a CONTIGUOUS block (single Bézier
// path from start → input → submit) to avoid the interval gap caused by
// non-mouse phases (typing, scrolling). Non-mouse events are appended after.
// The analyzer extracts each event type independently, so array ordering
// (not timestamp ordering) determines which intervals are computed.
//
// Interval entropy: log-normal(60,30) clamped to [15,150]ms → bins get even
// mass, producing Shannon entropy ~2.5 (threshold: 1.5).
// Velocity: linear Bézier t (no ease-in-out) ensures ~10px steps; velocity
// is explicitly clamped above 8 px/s.
// Micro-tremors: 0.5-2.5px jitter events with 5-15ms intervals after ~20%
// of path points.
func (cs *CaptchaSolver) GenerateHumanEvents(solveTimeMs int64, opts ...HumanEventOpts) []adversarial.CaptchaEvent {
	mouseEvents := make([]adversarial.CaptchaEvent, 0, 50)
	otherEvents := make([]adversarial.CaptchaEvent, 0, 30)
	baseTime := time.Now().UnixMilli()

	// Landmark positions
	startX, startY := 100.0+cs.rng.Float64()*50, 150.0+cs.rng.Float64()*30
	inputX, inputY := 250.0+cs.rng.Float64()*60, 340.0+cs.rng.Float64()*30
	submitX, submitY := 350.0+cs.rng.Float64()*20, 400.0+cs.rng.Float64()*15

	// ======================== MOUSE EVENTS (contiguous) ========================
	// Single continuous path: start → input area → submit button.
	// All mouse events use a shared cursor so timestamps are contiguous.
	mouseCursor := 0.0
	prevX, prevY := startX, startY

	// --- Segment A: start → input area (15-20 points) ---
	numA := 15 + cs.rng.Intn(6)
	cpA1X := startX + (inputX-startX)*0.3 + (cs.rng.Float64()-0.5)*100
	cpA1Y := startY + (inputY-startY)*0.3 + (cs.rng.Float64()-0.5)*80
	cpA2X := startX + (inputX-startX)*0.7 + (cs.rng.Float64()-0.5)*100
	cpA2Y := startY + (inputY-startY)*0.7 + (cs.rng.Float64()-0.5)*80

	cs.emitMouseSegment(&mouseEvents, baseTime, &mouseCursor, &prevX, &prevY,
		numA, startX, startY, cpA1X, cpA1Y, cpA2X, cpA2Y, inputX, inputY)

	// --- Segment B: input area → submit button (8-12 points) ---
	numB := 8 + cs.rng.Intn(5)
	cpB1X := inputX + (submitX-inputX)*0.4 + (cs.rng.Float64()-0.5)*40
	cpB1Y := inputY + (submitY-inputY)*0.4 + (cs.rng.Float64()-0.5)*30
	cpB2X := inputX + (submitX-inputX)*0.7 + (cs.rng.Float64()-0.5)*40
	cpB2Y := inputY + (submitY-inputY)*0.7 + (cs.rng.Float64()-0.5)*30

	cs.emitMouseSegment(&mouseEvents, baseTime, &mouseCursor, &prevX, &prevY,
		numB, inputX, inputY, cpB1X, cpB1Y, cpB2X, cpB2Y, submitX, submitY)

	// ======================== NON-MOUSE EVENTS ========================
	otherCursor := 0.0

	// --- Scroll events (3-5 total, varied deltas) ---
	for i := 0; i < 1+cs.rng.Intn(2); i++ {
		otherCursor += cs.logNormalDuration(200, 100)
		otherEvents = append(otherEvents, adversarial.CaptchaEvent{
			Type: "scroll", Timestamp: baseTime + int64(otherCursor), ElapsedMs: int64(otherCursor),
			Delta: 80.0 + cs.rng.Float64()*120,
		})
	}

	// --- Click on input field (sub-pixel coords) ---
	otherCursor += cs.logNormalDuration(200, 80)
	clickX := inputX + cs.rng.Float64()*8.37
	clickY := inputY + cs.rng.Float64()*5.82
	otherEvents = append(otherEvents, adversarial.CaptchaEvent{
		Type: "click", Timestamp: baseTime + int64(otherCursor), ElapsedMs: int64(otherCursor),
		X: clickX, Y: clickY,
	})

	// --- Keystrokes with log-normal intervals (mean ~120ms, CV ~0.4) ---
	// Use solution characters if provided, otherwise fallback to dummy "a"
	solution := ""
	if len(opts) > 0 {
		solution = opts[0].Solution
	}
	keystrokeCount := 6
	if solution != "" {
		keystrokeCount = len(solution)
	}
	for i := 0; i < keystrokeCount; i++ {
		key := "a"
		if solution != "" {
			key = string(solution[i])
		}
		otherCursor += cs.logNormalDuration(120, 55)
		otherEvents = append(otherEvents, adversarial.CaptchaEvent{
			Type: "keydown", Timestamp: baseTime + int64(otherCursor), ElapsedMs: int64(otherCursor), Key: key,
		})
		holdTime := 30 + cs.rng.Float64()*50
		otherEvents = append(otherEvents, adversarial.CaptchaEvent{
			Type: "keyup", Timestamp: baseTime + int64(otherCursor+holdTime), ElapsedMs: int64(otherCursor + holdTime), Key: key,
		})
		if (i == 1 || i == 3) && cs.rng.Float64() < 0.7 {
			otherCursor += 500 + cs.rng.Float64()*800
		}
	}

	// --- More scroll events (2-3, varied deltas) ---
	for i := 0; i < 2+cs.rng.Intn(2); i++ {
		otherCursor += cs.logNormalDuration(300, 150)
		otherEvents = append(otherEvents, adversarial.CaptchaEvent{
			Type: "scroll", Timestamp: baseTime + int64(otherCursor), ElapsedMs: int64(otherCursor),
			Delta: 80.0 + cs.rng.Float64()*120,
		})
	}

	// --- Submit click (sub-pixel) ---
	otherCursor += cs.logNormalDuration(80, 35)
	otherEvents = append(otherEvents, adversarial.CaptchaEvent{
		Type: "click", Timestamp: baseTime + int64(otherCursor), ElapsedMs: int64(otherCursor),
		X: submitX + cs.rng.Float64()*3.14, Y: submitY + cs.rng.Float64()*2.71,
	})

	// ======================== COMBINE ========================
	// Mouse events first (contiguous block), then non-mouse events.
	// The analyzer extracts MouseTimestamps from "mousemove" events in array
	// order, so this guarantees no cross-phase gap in the interval sequence.
	events := make([]adversarial.CaptchaEvent, 0, len(mouseEvents)+len(otherEvents))
	events = append(events, mouseEvents...)
	events = append(events, otherEvents...)

	return events
}

// emitMouseSegment generates mouse events along a cubic Bézier curve segment
// with log-normal intervals, path noise, and interleaved micro-tremors.
func (cs *CaptchaSolver) emitMouseSegment(
	events *[]adversarial.CaptchaEvent,
	baseTime int64, cursor, prevX, prevY *float64,
	numPoints int,
	p0X, p0Y, cp1X, cp1Y, cp2X, cp2Y, p3X, p3Y float64,
) {
	for i := 0; i < numPoints; i++ {
		t := float64(i) / float64(numPoints-1) // linear — no ease-in-out

		x := bezierPoint(t, p0X, cp1X, cp2X, p3X)
		y := bezierPoint(t, p0Y, cp1Y, cp2Y, p3Y)

		// Path noise (3-8px) for curvature variance
		x += (cs.rng.Float64() - 0.5) * 12
		y += (cs.rng.Float64() - 0.5) * 8

		// Log-normal interval clamped to [15, 150]ms
		interval := cs.logNormalDuration(60, 30)
		if interval < 15 {
			interval = 15
		}
		if interval > 150 {
			interval = 150
		}

		// Ensure velocity > 8 px/s (threshold is 5)
		dx := x - *prevX
		dy := y - *prevY
		dist := math.Sqrt(dx*dx + dy*dy)
		maxInterval := dist * 125 // dist/(maxInterval/1000) = 8 px/s
		if maxInterval > 10 && interval > maxInterval {
			interval = maxInterval
		}

		*cursor += interval
		*events = append(*events, adversarial.CaptchaEvent{
			Type: "mousemove", Timestamp: baseTime + int64(*cursor), ElapsedMs: int64(*cursor), X: x, Y: y,
		})

		// Insert micro-tremor after ~20% of path points (0.5-2.5px, 5-15ms)
		if cs.rng.Float64() < 0.20 {
			angle := cs.rng.Float64() * 2 * math.Pi
			tremDist := 0.8 + cs.rng.Float64()*2.0
			tx := x + math.Cos(angle)*tremDist
			ty := y + math.Sin(angle)*tremDist
			*cursor += 5 + cs.rng.Float64()*10
			*events = append(*events, adversarial.CaptchaEvent{
				Type: "mousemove", Timestamp: baseTime + int64(*cursor), ElapsedMs: int64(*cursor), X: tx, Y: ty,
			})
			*prevX, *prevY = tx, ty
		} else {
			*prevX, *prevY = x, y
		}
	}
}

// bezierPoint evaluates a cubic Bézier curve at parameter t ∈ [0,1].
func bezierPoint(t, p0, p1, p2, p3 float64) float64 {
	u := 1 - t
	return u*u*u*p0 + 3*u*u*t*p1 + 3*u*t*t*p2 + t*t*t*p3
}

// logNormalDuration returns a log-normal distributed duration in ms.
// This produces human-like variation: mostly near the mean with occasional longer pauses.
func (cs *CaptchaSolver) logNormalDuration(meanMs, stddevMs float64) float64 {
	// Box-Muller transform for normal distribution
	u1 := cs.rng.Float64()
	u2 := cs.rng.Float64()
	// Avoid log(0)
	if u1 < 1e-10 {
		u1 = 1e-10
	}
	normal := math.Sqrt(-2*math.Log(u1)) * math.Cos(2*math.Pi*u2)

	// Convert normal parameters to log-normal parameters
	variance := stddevMs * stddevMs
	mu := math.Log(meanMs * meanMs / math.Sqrt(variance+meanMs*meanMs)) //nolint:mnd
	sigma := math.Sqrt(math.Log(1 + variance/(meanMs*meanMs)))          //nolint:mnd

	result := math.Exp(mu + sigma*normal)
	// Clamp to reasonable range
	if result < 5 {
		result = 5
	}
	if result > meanMs*5 {
		result = meanMs * 5
	}
	return result
}

// deriveBaseURL extracts scheme + host from a URL.
func deriveBaseURL(targetURL string) string {
	u, err := url.Parse(targetURL)
	if err != nil {
		return targetURL
	}
	return u.Scheme + "://" + u.Host
}

// deriveVerifyURL constructs the captcha verify endpoint from the target URL.
func deriveVerifyURL(targetURL string) string {
	u, err := url.Parse(targetURL)
	if err != nil {
		return targetURL + "/api/captcha/verify"
	}
	u.Path = "/api/captcha/verify"
	u.RawQuery = ""
	return u.String()
}

// stringFromMap safely extracts a string from a map.
func stringFromMap(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Sprintf("%v", v)
	}
	return s
}

// ReCaptchaV2Result holds the output of a full reCAPTCHA v2 solve attempt.
type ReCaptchaV2Result struct {
	Token           string  `json:"token"`
	BehavioralScore float64 `json:"behavioral_score"`
	Passed          bool    `json:"passed"`
	NeedChallenge   bool    `json:"need_challenge"`
	SolveAttempts   int     `json:"solve_attempts"`
	RefreshCount    int     `json:"refresh_count"`
	TotalTimeMs     int64   `json:"total_time_ms"`
}

// SolveReCaptchaV2 performs the full reCAPTCHA v2 interaction flow:
// 1. POST /api/recaptcha/init → sessionID
// 2. POST /api/recaptcha/checkbox + behavioral events → check if passed or need challenge
// 3. If need challenge: solve captcha with SegmentationSolver
// 4. On failure: refresh and retry up to 3 times
func (cs *CaptchaSolver) SolveReCaptchaV2(baseURL string) (*ReCaptchaV2Result, error) {
	start := time.Now()
	result := &ReCaptchaV2Result{}

	// Step 1: Init session
	initResp, err := cs.recaptchaPost(baseURL+"/api/recaptcha/init", map[string]interface{}{})
	if err != nil {
		return nil, fmt.Errorf("recaptcha init: %w", err)
	}
	sessionID, _ := initResp["session_id"].(string)
	if sessionID == "" {
		return nil, fmt.Errorf("recaptcha init: no session_id in response")
	}

	// Step 2: Checkbox click with behavioral events
	checkboxEvents := cs.GenerateHumanEvents(500)
	checkboxResp, err := cs.recaptchaPost(baseURL+"/api/recaptcha/checkbox", map[string]interface{}{
		"session_id": sessionID,
		"events":     checkboxEvents,
	})
	if err != nil {
		return nil, fmt.Errorf("recaptcha checkbox: %w", err)
	}

	if passed, ok := checkboxResp["passed"].(bool); ok && passed {
		// Low-risk pass — no challenge needed
		result.Passed = true
		result.NeedChallenge = false
		if token, ok := checkboxResp["token"].(string); ok {
			result.Token = token
		}
		if score, ok := checkboxResp["behavioral_score"].(float64); ok {
			result.BehavioralScore = score
		}
		result.TotalTimeMs = time.Since(start).Milliseconds()
		return result, nil
	}

	// Need to solve challenge
	result.NeedChallenge = true

	challengeData, ok := checkboxResp["challenge"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("recaptcha checkbox: no challenge data in response")
	}

	segSolver := captcha.NewSegmentationSolver()
	maxAttempts := 4 // 1 initial + 3 refreshes

	for attempt := 0; attempt < maxAttempts; attempt++ {
		result.SolveAttempts++

		// Extract challenge info
		imgB64, _ := challengeData["image_base64"].(string)
		numCharsF, _ := challengeData["num_chars"].(float64)
		numChars := int(numCharsF)
		if numChars <= 0 {
			numChars = 6
		}

		if imgB64 == "" {
			return nil, fmt.Errorf("challenge has no image data")
		}

		// Decode and solve
		img, err := decodeImageFromBase64(imgB64)
		if err != nil {
			return nil, fmt.Errorf("decode captcha image: %w", err)
		}

		solution, _ := segSolver.SolveWithSegmentation(img, numChars)

		// Submit solution with behavioral events (keystrokes match solution)
		solveEvents := cs.GenerateHumanEvents(2000, HumanEventOpts{Solution: solution})
		verifyResp, err := cs.recaptchaPost(baseURL+"/api/recaptcha/verify", map[string]interface{}{
			"session_id": sessionID,
			"solution":   solution,
			"events":     solveEvents,
		})
		if err != nil {
			return nil, fmt.Errorf("recaptcha verify: %w", err)
		}

		if success, ok := verifyResp["success"].(bool); ok && success {
			result.Passed = true
			if token, ok := verifyResp["token"].(string); ok {
				result.Token = token
			}
			if score, ok := verifyResp["behavioral_score"].(float64); ok {
				result.BehavioralScore = score
			}
			result.TotalTimeMs = time.Since(start).Milliseconds()
			return result, nil
		}

		// Failed — try refresh if we have attempts left
		if attempt < maxAttempts-1 {
			result.RefreshCount++

			// Generate refresh click events (simulating human clicking refresh button)
			refreshResp, err := cs.recaptchaPost(baseURL+"/api/recaptcha/refresh", map[string]interface{}{
				"session_id": sessionID,
			})
			if err != nil {
				// Max refreshes exceeded or other error — stop
				break
			}

			newChallenge, ok := refreshResp["challenge"].(map[string]interface{})
			if !ok {
				break
			}
			challengeData = newChallenge
		}
	}

	result.TotalTimeMs = time.Since(start).Milliseconds()
	return result, nil
}

// ReCaptchaV3Result holds the result of a reCAPTCHA v3 invisible assessment.
type ReCaptchaV3Result struct {
	Success     bool    `json:"success"`
	Score       float64 `json:"score"` // 0.0 (bot) – 1.0 (human)
	Action      string  `json:"action"`
	ChallengeTS string  `json:"challenge_ts"`
	Hostname    string  `json:"hostname"`
}

// AssessReCaptchaV3 sends a reCAPTCHA v3 invisible assessment request.
// It generates human-like behavioral events and POSTs them to the v3 assess
// endpoint. Returns the v3 score (1.0 = human, 0.0 = bot).
func (cs *CaptchaSolver) AssessReCaptchaV3(baseURL, action string) (*ReCaptchaV3Result, error) {
	events := cs.GenerateHumanEvents(3000)

	resp, err := cs.recaptchaPost(baseURL+"/api/recaptcha/v3/assess", map[string]interface{}{
		"action": action,
		"events": events,
	})
	if err != nil {
		return nil, fmt.Errorf("recaptcha v3 assess: %w", err)
	}

	result := &ReCaptchaV3Result{}
	if v, ok := resp["success"].(bool); ok {
		result.Success = v
	}
	if v, ok := resp["score"].(float64); ok {
		result.Score = v
	}
	if v, ok := resp["action"].(string); ok {
		result.Action = v
	}
	if v, ok := resp["challenge_ts"].(string); ok {
		result.ChallengeTS = v
	}
	if v, ok := resp["hostname"].(string); ok {
		result.Hostname = v
	}

	return result, nil
}

// recaptchaPost sends a JSON POST request and returns the decoded response.
func (cs *CaptchaSolver) recaptchaPost(url string, body map[string]interface{}) (map[string]interface{}, error) {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	resp, err := cs.httpClient.Post(url, "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}

// decodeImageFromBase64 decodes a base64-encoded PNG into an image.Image.
func decodeImageFromBase64(b64 string) (image.Image, error) {
	// Strip data URL prefix if present
	if idx := strings.Index(b64, ","); idx >= 0 {
		b64 = b64[idx+1:]
	}
	imgBytes, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	return png.Decode(bytes.NewReader(imgBytes))
}
