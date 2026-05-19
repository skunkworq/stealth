package challenge

import (
	"testing"
)

func TestDetector_NoChallenge(t *testing.T) {
	d := NewDetector()
	ch := d.Detect([]byte("<html><body>Hello World</body></html>"), map[string][]string{})
	if ch != nil {
		t.Fatalf("expected nil (no challenge), got %v", ch)
	}
}

func TestDetector_CloudflareJS(t *testing.T) {
	d := NewDetector()
	body := []byte(`<html><head><title>Attention Required!</title></head>
	<body><div class="cf-challenge">Please wait...</div></body></html>`)
	headers := map[string][]string{"Server": {"cloudflare"}}
	ch := d.Detect(body, headers)
	if ch == nil {
		t.Fatal("expected challenge detection, got nil")
	}
	if ch.Type != ChallengeCloudflare {
		t.Fatalf("expected ChallengeCloudflare, got %v", ch.Type)
	}
}

func TestDetector_Turnstile(t *testing.T) {
	d := NewDetector()
	body := []byte(`<html><body><div class="cf-turnstile" data-sitekey="abc123"></div></body></html>`)
	headers := map[string][]string{"Server": {"cloudflare"}}
	ch := d.Detect(body, headers)
	if ch == nil {
		t.Fatal("expected challenge detection, got nil")
	}
	if ch.Type != ChallengeTurnstile {
		t.Fatalf("expected ChallengeTurnstile, got %v", ch.Type)
	}
}

func TestDetector_ReCAPTCHAv2(t *testing.T) {
	d := NewDetector()
	// g-recaptcha-response is the distinguishing marker for v2
	body := []byte(`<html><body>
		<div class="g-recaptcha" data-sitekey="abc123"></div>
		<input type="hidden" name="g-recaptcha-response">
	</body></html>`)
	ch := d.Detect(body, map[string][]string{})
	if ch == nil {
		t.Fatal("expected challenge detection, got nil")
	}
	if ch.Type != ChallengeRecaptchaV2 {
		t.Fatalf("expected ChallengeRecaptchaV2, got %v", ch.Type)
	}
}
