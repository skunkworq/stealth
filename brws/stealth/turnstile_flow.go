package stealth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"strings"
	"time"

	"github.com/skunkworq/stealth/brws/adversarial"
)

// TurnstileFlowResult separates token issuance, verification, and interaction
// telemetry for owned-environment Turnstile exercises.
type TurnstileFlowResult struct {
	SessionID       string
	ChallengeType   string
	Passed          bool
	ClearanceCookie *http.Cookie
	Widget          *adversarial.TurnstileWidgetConfig
	Token           *adversarial.LabTurnstileToken
	Verification    *adversarial.VerificationResult
	Telemetry       *adversarial.WidgetTelemetry
	PoWTimeMs       int64
	TotalTimeMs     int64
	PoWIterations   int64
	PoWDifficulty   int
}

// TurnstileVerificationAdapter verifies a token after the client completes a
// lab or owned test-mode widget flow.
type TurnstileVerificationAdapter interface {
	VerifyToken(ctx context.Context, token string) (*adversarial.VerificationResult, error)
	Provider() string
}

// SetTurnstileVerificationAdapter configures the verifier used after widget
// completion.
func (cs *CloudflareSolverClient) SetTurnstileVerificationAdapter(adapter TurnstileVerificationAdapter) {
	cs.turnstileVerifier = adapter
}

// AllowTurnstileHost adds an owned hostname to the explicit allowlist.
func (cs *CloudflareSolverClient) AllowTurnstileHost(host string) {
	if cs.turnstileAllowlist == nil {
		cs.turnstileAllowlist = defaultTurnstileAllowlist()
	}
	host = normalizeTurnstileHost(host)
	if host != "" {
		cs.turnstileAllowlist[host] = struct{}{}
	}
}

// VerifyTurnstileToken verifies a token using the configured adapter.
func (cs *CloudflareSolverClient) VerifyTurnstileToken(ctx context.Context, token string) (*adversarial.VerificationResult, error) {
	if cs.turnstileVerifier == nil {
		return nil, fmt.Errorf("no turnstile verification adapter configured")
	}
	return cs.turnstileVerifier.VerifyToken(ctx, token)
}

// HandleTurnstileLab performs the owned-environment Turnstile flow against the
// local lab harness or another explicitly allowlisted host.
func (cs *CloudflareSolverClient) HandleTurnstileLab(baseURL string) (*TurnstileFlowResult, error) {
	if !cs.isAllowedTurnstileTarget(baseURL) {
		return nil, fmt.Errorf("turnstile flow restricted to local or allowlisted owned hosts: %s", baseURL)
	}

	totalStart := time.Now()
	initResp, err := cs.initTurnstileChallenge(baseURL, nil)
	if err != nil {
		return nil, fmt.Errorf("init failed: %w", err)
	}

	widgetURL := resolveTurnstileURL(baseURL, initResp.WidgetURL)
	pageResp, err := cs.httpClient.Get(widgetURL)
	if err != nil {
		return nil, fmt.Errorf("widget page request failed: %w", err)
	}
	body, _ := io.ReadAll(pageResp.Body)
	pageResp.Body.Close()

	challenge := adversarial.DetectChallenge(pageResp.StatusCode, pageResp.Header, body)
	if challenge == nil || challenge.Type != adversarial.ChallengeTurnstile {
		return nil, fmt.Errorf("turnstile widget not detected on %s", widgetURL)
	}

	widget := challenge.Widget
	if widget == nil {
		widget = initResp.Widget
	}
	if widget == nil {
		return nil, fmt.Errorf("turnstile widget config missing from lab response")
	}

	_ = cs.postTurnstileCallback(baseURL, initResp.CallbackURL, initResp.SessionID, "render", "")

	powSolution, err := cs.solvePoW(initResp.PoW.Prefix, initResp.PoW.Difficulty)
	if err != nil {
		return nil, fmt.Errorf("PoW failed: %w", err)
	}

	events := cs.eventGen.GenerateHumanEvents(2500)
	telemetry := adversarial.BuildTurnstileTelemetry(
		events,
		widget,
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
		1365,
		880,
	)

	_ = cs.postTurnstileCallback(baseURL, initResp.CallbackURL, initResp.SessionID, "execute", "")

	payload, _ := json.Marshal(map[string]interface{}{
		"session_id": initResp.SessionID,
		"solution":   powSolution,
		"events":     events,
		"telemetry":  telemetry,
	})

	resp, err := cs.httpClient.Post(baseURL+"/api/cloudflare/solve/turnstile", "application/json", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("solve request failed: %w", err)
	}
	defer resp.Body.Close()

	var solveResp cfSolveResp
	if err := json.NewDecoder(resp.Body).Decode(&solveResp); err != nil {
		return nil, fmt.Errorf("decode solve response: %w", err)
	}
	if !solveResp.Success {
		return nil, fmt.Errorf("turnstile flow failed: %s", solveResp.Error)
	}

	result := &TurnstileFlowResult{
		SessionID:       initResp.SessionID,
		ChallengeType:   "cloudflare_turnstile",
		Passed:          solveResp.Success,
		ClearanceCookie: extractCfClearanceCookie(resp),
		Widget:          widget,
		Token:           solveResp.LabTurnstileToken,
		Telemetry:       solveResp.WidgetTelemetry,
		PoWTimeMs:       powSolution.TimeMs,
		TotalTimeMs:     time.Since(totalStart).Milliseconds(),
		PoWIterations:   powSolution.Iterations,
		PoWDifficulty:   initResp.PoW.Difficulty,
	}

	if result.Token == nil && solveResp.TurnstileToken != "" {
		result.Token = &adversarial.LabTurnstileToken{Token: solveResp.TurnstileToken}
	}
	if result.Telemetry == nil {
		result.Telemetry = telemetry
	}

	if cs.turnstileVerifier != nil && result.Token != nil {
		verification, err := cs.turnstileVerifier.VerifyToken(context.Background(), result.Token.Token)
		if err != nil {
			return nil, fmt.Errorf("turnstile verification failed via %s: %w", cs.turnstileVerifier.Provider(), err)
		}
		result.Verification = verification
		result.Passed = result.Passed && verification.Success
	}

	return result, nil
}

func (cs *CloudflareSolverClient) initTurnstileChallenge(baseURL string, cfg *adversarial.TurnstileWidgetConfig) (*cfInitResp, error) {
	body := map[string]interface{}{
		"challenge_type":  "cloudflare_turnstile",
		"detection_score": 0.3,
	}
	if cfg != nil {
		normalized := cfg.Normalize()
		body["site_key"] = normalized.SiteKey
		body["widget_mode"] = normalized.Mode
		body["action"] = normalized.Action
		body["cdata"] = normalized.CData
		body["theme"] = normalized.Theme
		body["size"] = normalized.Size
		body["appearance"] = normalized.Appearance
		body["execution"] = normalized.Execution
		body["retry"] = normalized.Retry
		body["retry_interval_ms"] = normalized.RetryIntervalMS
		body["refresh_expired"] = normalized.RefreshExpired
		body["refresh_timeout"] = normalized.RefreshTimeout
		body["token_ttl_seconds"] = normalized.TokenTTLSeconds
	}

	raw, _ := json.Marshal(body)
	resp, err := cs.httpClient.Post(baseURL+"/api/cloudflare/init", "application/json", bytes.NewReader(raw))
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

func (cs *CloudflareSolverClient) postTurnstileCallback(baseURL, callbackURL, sessionID, callback, errorCode string) error {
	callbackURL = resolveTurnstileURL(baseURL, callbackURL)
	body, _ := json.Marshal(map[string]string{
		"session_id": sessionID,
		"callback":   callback,
		"error_code": errorCode,
	})
	resp, err := cs.httpClient.Post(callbackURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (cs *CloudflareSolverClient) isAllowedTurnstileTarget(baseURL string) bool {
	parsed, err := neturl.Parse(baseURL)
	if err != nil {
		return false
	}
	host := normalizeTurnstileHost(parsed.Hostname())
	if host == "" {
		return false
	}
	_, ok := cs.turnstileAllowlist[host]
	return ok
}

func defaultTurnstileAllowlist() map[string]struct{} {
	allowlist := map[string]struct{}{
		"localhost": {},
		"127.0.0.1": {},
		"::1":       {},
	}
	if raw := os.Getenv("STEALTH_TURNSTILE_ALLOWED_HOSTS"); raw != "" {
		for _, part := range strings.Split(raw, ",") {
			host := normalizeTurnstileHost(part)
			if host != "" {
				allowlist[host] = struct{}{}
			}
		}
	}
	return allowlist
}

func normalizeTurnstileHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	if parsed, err := neturl.Parse("https://" + host); err == nil && parsed.Hostname() != "" {
		return strings.TrimSpace(strings.ToLower(parsed.Hostname()))
	}
	return host
}

func resolveTurnstileURL(baseURL, path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	if path == "" {
		return baseURL
	}
	return strings.TrimRight(baseURL, "/") + "/" + strings.TrimLeft(path, "/")
}
