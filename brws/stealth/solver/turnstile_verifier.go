package solver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/skunkworq/stealth/brws/stealth/challenge"
)

const (
	// CloudflareTurnstileTestSiteKey is Cloudflare's documented visible-pass test sitekey.
	CloudflareTurnstileTestSiteKey = "1x00000000000000000000AA"
	// CloudflareTurnstileTestSecret is Cloudflare's documented test-mode secret key.
	CloudflareTurnstileTestSecret = "1x0000000000000000000000000000000AA"
	// CloudflareTurnstileDummyToken is Cloudflare's documented dummy token for siteverify testing.
	CloudflareTurnstileDummyToken = "XXXX.DUMMY.TOKEN.XXXX"
)

const cloudflareTurnstileSiteVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

// TurnstileVerifier verifies a Turnstile token in an owned environment.
type TurnstileVerifier interface {
	Verify(ctx context.Context, token string) (*challenge.VerificationResult, error)
}

// LabTurnstileVerifier verifies tokens issued by the local lab harness.
type LabTurnstileVerifier struct {
	HTTPClient *http.Client
	BaseURL    string
	Secret     string
	Hostname   string
}

// Verify posts the supplied token to the lab's siteverify endpoint.
func (v *LabTurnstileVerifier) Verify(ctx context.Context, token string) (*challenge.VerificationResult, error) {
	endpoint := strings.TrimRight(v.BaseURL, "/") + "/turnstile/v0/siteverify"
	return verifyTurnstileToken(ctx, v.httpClient(), endpoint, v.Secret, token, v.Hostname)
}

func (v *LabTurnstileVerifier) httpClient() *http.Client {
	if v.HTTPClient != nil {
		return v.HTTPClient
	}
	return http.DefaultClient
}

// CloudflareTestModeVerifier verifies tokens against Cloudflare's official test-mode siteverify endpoint.
type CloudflareTestModeVerifier struct {
	HTTPClient *http.Client
	Endpoint   string
	Secret     string
}

// Verify posts the supplied token to Cloudflare's official siteverify endpoint.
func (v *CloudflareTestModeVerifier) Verify(ctx context.Context, token string) (*challenge.VerificationResult, error) {
	endpoint := strings.TrimSpace(v.Endpoint)
	if endpoint == "" {
		endpoint = cloudflareTurnstileSiteVerifyURL
	}
	return verifyTurnstileToken(ctx, v.httpClient(), endpoint, v.Secret, token, "")
}

func (v *CloudflareTestModeVerifier) httpClient() *http.Client {
	if v.HTTPClient != nil {
		return v.HTTPClient
	}
	return http.DefaultClient
}

type turnstileSiteVerifyResponse struct {
	Success     bool     `json:"success"`
	ChallengeTS string   `json:"challenge_ts,omitempty"`
	Hostname    string   `json:"hostname,omitempty"`
	Action      string   `json:"action,omitempty"`
	CData       string   `json:"cdata,omitempty"`
	ErrorCodes  []string `json:"error-codes,omitempty"`
}

func verifyTurnstileToken(
	ctx context.Context,
	client *http.Client,
	endpoint string,
	secret string,
	token string,
	hostname string,
) (*challenge.VerificationResult, error) {
	if strings.TrimSpace(endpoint) == "" {
		return nil, fmt.Errorf("turnstile verifier requires an endpoint")
	}
	if strings.TrimSpace(secret) == "" {
		return nil, fmt.Errorf("turnstile verifier requires a secret")
	}
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("turnstile verifier requires a token")
	}

	body, err := json.Marshal(map[string]string{
		"secret":   secret,
		"response": token,
		"remoteip": hostname,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal siteverify request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build siteverify request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if hostname != "" {
		req.Host = hostname
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("post siteverify request: %w", err)
	}
	defer resp.Body.Close()

	var verifyResp turnstileSiteVerifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&verifyResp); err != nil {
		return nil, fmt.Errorf("decode siteverify response: %w", err)
	}

	return &challenge.VerificationResult{
		Success:     verifyResp.Success,
		ChallengeTS: verifyResp.ChallengeTS,
		Hostname:    verifyResp.Hostname,
		Action:      verifyResp.Action,
		CData:       verifyResp.CData,
		ErrorCodes:  verifyResp.ErrorCodes,
	}, nil
}
