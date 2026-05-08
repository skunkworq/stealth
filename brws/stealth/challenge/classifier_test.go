package challenge

import (
	"testing"
)

func TestClassifierNone(t *testing.T) {
	c := NewClassifier()
	result := c.Classify([]byte("<html><body>Hello World</body></html>"))
	if result.Type != None {
		t.Fatalf("expected None, got %s", result.Type)
	}
	if result.Confidence != 1.0 {
		t.Fatalf("expected confidence 1.0, got %f", result.Confidence)
	}
}

func TestClassifierCloudflareJS(t *testing.T) {
	c := NewClassifier()
	body := []byte(`<html><head><title>Attention Required!</title></head>
	<body><div class="cf-challenge">Please wait...</div></body></html>`)
	result := c.Classify(body)
	if result.Type != CloudflareJS {
		t.Fatalf("expected CloudflareJS, got %s", result.Type)
	}
	if result.Confidence < 0.5 {
		t.Fatalf("expected confidence >= 0.5, got %f", result.Confidence)
	}
}

func TestClassifierTurnstile(t *testing.T) {
	c := NewClassifier()
	body := []byte(`<html><body><div class="cf-turnstile" data-sitekey="abc123"></div></body></html>`)
	result := c.Classify(body)
	if result.Type != CloudflareTurnstile {
		t.Fatalf("expected CloudflareTurnstile, got %s", result.Type)
	}
}

func TestClassifierReCAPTCHAv2(t *testing.T) {
	c := NewClassifier()
	body := []byte(`<html><body><div class="g-recaptcha" data-sitekey="abc123"></div></body></html>`)
	result := c.Classify(body)
	if result.Type != ReCAPTCHAv2 {
		t.Fatalf("expected ReCAPTCHAv2, got %s", result.Type)
	}
}
