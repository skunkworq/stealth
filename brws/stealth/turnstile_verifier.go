package stealth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/skunkworq/stealth/brws/adversarial"
)

// LabTurnstileVerifier verifies tokens against the local harness endpoint.
type LabTurnstileVerifier struct {
	BaseURL    string
	Secret     string
	HTTPClient *http.Client
}

func NewLabTurnstileVerifier(baseURL, secret string) *LabTurnstileVerifier {
	return &LabTurnstileVerifier{
		BaseURL: baseURL,
		Secret:  secret,
		HTTPClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func (v *LabTurnstileVerifier) Provider() string { return "lab" }

func (v *LabTurnstileVerifier) VerifyToken(_ context.Context, token string) (*adversarial.VerificationResult, error) {
	form := url.Values{
		"secret":   {v.Secret},
		"response": {token},
	}
	endpoint := strings.TrimRight(v.BaseURL, "/") + "/turnstile/v0/siteverify"
	resp, err := v.httpClient().Post(endpoint, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result adversarial.VerificationResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (v *LabTurnstileVerifier) httpClient() *http.Client {
	if v.HTTPClient != nil {
		return v.HTTPClient
	}
	v.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	return v.HTTPClient
}

// OfficialTurnstileTestVerifier talks to Cloudflare's public Siteverify
// endpoint. It is intended only for dummy/test secrets on owned properties.
type OfficialTurnstileTestVerifier struct {
	Secret           string
	Endpoint         string
	AllowedHostnames map[string]struct{}
	HTTPClient       *http.Client
}

func NewOfficialTurnstileTestVerifier(secret string, allowedHostnames ...string) *OfficialTurnstileTestVerifier {
	allowlist := make(map[string]struct{}, len(allowedHostnames))
	for _, host := range allowedHostnames {
		host = normalizeTurnstileHost(host)
		if host != "" {
			allowlist[host] = struct{}{}
		}
	}
	return &OfficialTurnstileTestVerifier{
		Secret:           secret,
		Endpoint:         "https://challenges.cloudflare.com/turnstile/v0/siteverify",
		AllowedHostnames: allowlist,
		HTTPClient: &http.Client{
			Timeout: 20 * time.Second,
		},
	}
}

func (v *OfficialTurnstileTestVerifier) Provider() string { return "cloudflare-testmode" }

func (v *OfficialTurnstileTestVerifier) VerifyToken(_ context.Context, token string) (*adversarial.VerificationResult, error) {
	form := url.Values{
		"secret":   {v.Secret},
		"response": {token},
	}
	resp, err := v.httpClient().Post(v.endpoint(), "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result adversarial.VerificationResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if result.Success && len(v.AllowedHostnames) > 0 {
		if _, ok := v.AllowedHostnames[normalizeTurnstileHost(result.Hostname)]; !ok {
			result.Success = false
			result.ErrorCodes = append(result.ErrorCodes, "hostname-mismatch")
		}
	}

	return &result, nil
}

func (v *OfficialTurnstileTestVerifier) endpoint() string {
	if v.Endpoint != "" {
		return v.Endpoint
	}
	return "https://challenges.cloudflare.com/turnstile/v0/siteverify"
}

func (v *OfficialTurnstileTestVerifier) httpClient() *http.Client {
	if v.HTTPClient != nil {
		return v.HTTPClient
	}
	v.HTTPClient = &http.Client{Timeout: 20 * time.Second}
	return v.HTTPClient
}

var _ TurnstileVerificationAdapter = (*LabTurnstileVerifier)(nil)
var _ TurnstileVerificationAdapter = (*OfficialTurnstileTestVerifier)(nil)

func (v *OfficialTurnstileTestVerifier) String() string {
	return fmt.Sprintf("OfficialTurnstileTestVerifier{endpoint=%s}", v.endpoint())
}
