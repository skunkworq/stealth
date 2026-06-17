package solver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// TwoCaptcha implements the Solver interface using the 2Captcha API.
//
// 2Captcha uses two endpoints:
//   - POST https://2captcha.com/in.php   (submit a task, returns a task id)
//   - GET  https://2captcha.com/res.php  (poll until the task is solved)
//
// Both endpoints accept `json=1` and respond with `{"status":0|1,"request":"..."}`.
type TwoCaptchaSolver struct {
	apiKey   string
	client   *http.Client
	timeout  time.Duration
	pollRate time.Duration
	// inURL / resURL are overridable for tests.
	inURL  string
	resURL string
}

// NewTwoCaptcha returns a 2Captcha-backed solver. Default poll interval is 5s
// and total timeout is 180s — 2Captcha typically resolves in 15-45s.
func NewTwoCaptcha(apiKey string) *TwoCaptchaSolver {
	return &TwoCaptchaSolver{
		apiKey:   apiKey,
		client:   &http.Client{Timeout: 180 * time.Second},
		timeout:  180 * time.Second,
		pollRate: 5 * time.Second,
		inURL:    "https://2captcha.com/in.php",
		resURL:   "https://2captcha.com/res.php",
	}
}

type twoCaptchaResponse struct {
	Status  int             `json:"status"`
	Request json.RawMessage `json:"request"`
}

// submit posts a task to in.php and returns the task id.
func (t *TwoCaptchaSolver) submit(ctx context.Context, params url.Values) (string, error) {
	params.Set("key", t.apiKey)
	params.Set("json", "1")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.inURL, strings.NewReader(params.Encode()))
	if err != nil {
		return "", fmt.Errorf("twocaptcha: build submit: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := t.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("twocaptcha: submit: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("twocaptcha: read submit: %w", err)
	}
	var parsed twoCaptchaResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("twocaptcha: decode submit (%q): %w", string(body), err)
	}
	reqStr := jsonRawToString(parsed.Request)
	if parsed.Status != 1 {
		return "", fmt.Errorf("twocaptcha: submit failed: %s", reqStr)
	}
	if reqStr == "" {
		return "", fmt.Errorf("twocaptcha: submit returned empty task id")
	}
	return reqStr, nil
}

// poll repeatedly hits res.php until a token is ready or the deadline is hit.
func (t *TwoCaptchaSolver) poll(ctx context.Context, taskID string) (string, error) {
	deadline := time.After(t.timeout)
	ticker := time.NewTicker(t.pollRate)
	defer ticker.Stop()

	pollOnce := func() (string, bool, error) {
		u, err := url.Parse(t.resURL)
		if err != nil {
			return "", false, fmt.Errorf("twocaptcha: parse res url: %w", err)
		}
		q := u.Query()
		q.Set("key", t.apiKey)
		q.Set("action", "get")
		q.Set("id", taskID)
		q.Set("json", "1")
		u.RawQuery = q.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return "", false, fmt.Errorf("twocaptcha: build poll: %w", err)
		}
		resp, err := t.client.Do(req)
		if err != nil {
			return "", false, fmt.Errorf("twocaptcha: poll: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", false, fmt.Errorf("twocaptcha: read poll: %w", err)
		}
		var parsed twoCaptchaResponse
		if err := json.Unmarshal(body, &parsed); err != nil {
			return "", false, fmt.Errorf("twocaptcha: decode poll (%q): %w", string(body), err)
		}
		reqStr := jsonRawToString(parsed.Request)
		if parsed.Status == 1 {
			return reqStr, true, nil
		}
		if reqStr == "CAPCHA_NOT_READY" {
			return "", false, nil
		}
		return "", false, fmt.Errorf("twocaptcha: poll failed: %s", reqStr)
	}

	// First poll immediately is fine but follow the 5s convention by waiting
	// for the first ticker.
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-deadline:
			return "", fmt.Errorf("twocaptcha: timeout waiting for solution")
		case <-ticker.C:
			token, done, err := pollOnce()
			if err != nil {
				return "", err
			}
			if done {
				return token, nil
			}
		}
	}
}

// SolveRecaptchaV2 submits a reCAPTCHA v2 task and returns the g-recaptcha-response token.
func (t *TwoCaptchaSolver) SolveRecaptchaV2(ctx context.Context, siteKey, pageURL string) (string, error) {
	v := url.Values{}
	v.Set("method", "userrecaptcha")
	v.Set("googlekey", siteKey)
	v.Set("pageurl", pageURL)
	id, err := t.submit(ctx, v)
	if err != nil {
		return "", err
	}
	return t.poll(ctx, id)
}

// SolveRecaptchaV3 submits a reCAPTCHA v3 task.
func (t *TwoCaptchaSolver) SolveRecaptchaV3(ctx context.Context, siteKey, pageURL string, minScore float64) (string, error) {
	v := url.Values{}
	v.Set("method", "userrecaptcha")
	v.Set("version", "v3")
	v.Set("googlekey", siteKey)
	v.Set("pageurl", pageURL)
	v.Set("action", "verify")
	v.Set("min_score", strconv.FormatFloat(minScore, 'f', -1, 64))
	id, err := t.submit(ctx, v)
	if err != nil {
		return "", err
	}
	return t.poll(ctx, id)
}

// SolveHCaptcha submits an hCaptcha task.
func (t *TwoCaptchaSolver) SolveHCaptcha(ctx context.Context, siteKey, pageURL string) (string, error) {
	v := url.Values{}
	v.Set("method", "hcaptcha")
	v.Set("sitekey", siteKey)
	v.Set("pageurl", pageURL)
	id, err := t.submit(ctx, v)
	if err != nil {
		return "", err
	}
	return t.poll(ctx, id)
}

// SolveTurnstile submits a Cloudflare Turnstile task. The Solver interface
// signature is (ctx, siteKey, url); 2Captcha additionally accepts an `action`
// field that we leave blank for the default flow.
func (t *TwoCaptchaSolver) SolveTurnstile(ctx context.Context, siteKey, pageURL string) (string, error) {
	v := url.Values{}
	v.Set("method", "turnstile")
	v.Set("sitekey", siteKey)
	v.Set("pageurl", pageURL)
	id, err := t.submit(ctx, v)
	if err != nil {
		return "", err
	}
	return t.poll(ctx, id)
}

// GetBalance hits res.php?action=getbalance.
func (t *TwoCaptchaSolver) GetBalance(ctx context.Context) (float64, error) {
	u, err := url.Parse(t.resURL)
	if err != nil {
		return 0, fmt.Errorf("twocaptcha: parse res url: %w", err)
	}
	q := u.Query()
	q.Set("key", t.apiKey)
	q.Set("action", "getbalance")
	q.Set("json", "1")
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, fmt.Errorf("twocaptcha: build balance: %w", err)
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("twocaptcha: balance: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("twocaptcha: read balance: %w", err)
	}
	var parsed twoCaptchaResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return 0, fmt.Errorf("twocaptcha: decode balance (%q): %w", string(body), err)
	}
	reqStr := jsonRawToString(parsed.Request)
	if parsed.Status != 1 {
		return 0, fmt.Errorf("twocaptcha: balance failed: %s", reqStr)
	}
	bal, err := strconv.ParseFloat(reqStr, 64)
	if err != nil {
		return 0, fmt.Errorf("twocaptcha: parse balance %q: %w", reqStr, err)
	}
	return bal, nil
}

// jsonRawToString unwraps the polymorphic `request` field: 2Captcha sometimes
// returns it as a JSON string (`"..."`) and sometimes as a bare number.
func jsonRawToString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	// Try string first.
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	// Fall back to raw bytes.
	return strings.Trim(string(raw), "\"")
}
