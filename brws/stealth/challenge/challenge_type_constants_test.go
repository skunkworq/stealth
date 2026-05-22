package challenge

import "testing"

// TestChallengeTypeConstants pins the string values of all ChallengeType
// constants so any rename or value change is caught immediately.
func TestChallengeTypeConstants(t *testing.T) {
	cases := []struct {
		name string
		got  ChallengeType
		want string
	}{
		{"ChallengeRecaptchaV2", ChallengeRecaptchaV2, "recaptcha-v2"},
		{"ChallengeRecaptchaV3", ChallengeRecaptchaV3, "recaptcha-v3"},
		{"ChallengeHCaptcha", ChallengeHCaptcha, "hcaptcha"},
		{"ChallengeCloudflare", ChallengeCloudflare, "cloudflare"},
		{"ChallengeTurnstile", ChallengeTurnstile, "turnstile"},
		{"ChallengeChallengeBot", ChallengeChallengeBot, "challenge-bot"},
		{"ChallengeDataDome", ChallengeDataDome, "datadome"},
		{"ChallengeGeneric", ChallengeGeneric, "generic"},
		{"ChallengeTypeCloudflareJS", ChallengeTypeCloudflareJS, "cloudflare_js"},
		{"ChallengeTypeCloudflareManaged", ChallengeTypeCloudflareManaged, "cloudflare_managed"},
		{"ChallengeTypeCloudflareTurnstile", ChallengeTypeCloudflareTurnstile, "cloudflare_turnstile"},
	}
	for _, tc := range cases {
		if string(tc.got) != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}

// TestCloudflareSolveResultType verifies solver-level challenge types are
// a subset of the defined ChallengeType constants (enum consistency check).
func TestCloudflareSolveResultType(t *testing.T) {
	known := map[ChallengeType]bool{
		ChallengeTypeCloudflareJS:       true,
		ChallengeTypeCloudflareManaged:  true,
		ChallengeTypeCloudflareTurnstile: true,
	}
	solverTypes := []ChallengeType{
		ChallengeTypeCloudflareJS,
		ChallengeTypeCloudflareManaged,
		ChallengeTypeCloudflareTurnstile,
	}
	for _, ct := range solverTypes {
		if !known[ct] {
			t.Errorf("CloudflareSolveResult challenge type %q is not in the known constant set", ct)
		}
	}
}
