package cloudflare_test

import (
	"context"
	"os"
	"testing"

	solverpkg "github.com/skunkworq/stealth/brws/stealth/solver"
)

func TestCloudflareTestModeVerifierRequiresSecret(t *testing.T) {
	verifier := &solverpkg.CloudflareTestModeVerifier{}
	if _, err := verifier.Verify(context.Background(), solverpkg.CloudflareTurnstileDummyToken); err == nil {
		t.Fatal("expected missing secret to fail")
	}
}

func TestCloudflareTestModeVerifierLiveDummyToken(t *testing.T) {
	if os.Getenv("STEALTH_RUN_CLOUDFLARE_TESTMODE") != "1" {
		t.Skip("set STEALTH_RUN_CLOUDFLARE_TESTMODE=1 to exercise the official test-mode verifier")
	}

	verifier := &solverpkg.CloudflareTestModeVerifier{
		Secret: solverpkg.CloudflareTurnstileTestSecret,
	}

	result, err := verifier.Verify(context.Background(), solverpkg.CloudflareTurnstileDummyToken)
	if err != nil {
		t.Fatalf("official test-mode verification failed: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected dummy token verification to succeed: %+v", result)
	}
}
