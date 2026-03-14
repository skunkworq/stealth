package session

import (
	"testing"
)

func TestGenerateFingerprint_Deterministic(t *testing.T) {
	id := "test-session-12345678"
	fp1 := GenerateFingerprint(id)
	fp2 := GenerateFingerprint(id)

	if fp1.ID != fp2.ID {
		t.Errorf("same session ID produced different fingerprint IDs: %s vs %s", fp1.ID, fp2.ID)
	}
	if fp1.HTTP.UserAgent != fp2.HTTP.UserAgent {
		t.Errorf("same session ID produced different UAs: %s vs %s", fp1.HTTP.UserAgent, fp2.HTTP.UserAgent)
	}
}

func TestGenerateFingerprint_DiverseAcrossSessions(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := "session-" + string(rune('a'+i%26)) + string(rune('0'+i/26))
		fp := GenerateFingerprint(id)
		seen[fp.HTTP.UserAgent] = true
	}
	if len(seen) < 3 {
		t.Errorf("expected fingerprint diversity across sessions, got only %d unique UAs", len(seen))
	}
}

func TestGenerateFingerprint_AllProfilesCovered(t *testing.T) {
	profileHits := make(map[string]int)
	for i := 0; i < 1000; i++ {
		id := "coverage-test-" + string(rune(i))
		fp := GenerateFingerprint(id)
		key := fp.Metadata["browser"] + "-" + fp.Metadata["version"] + "-" + fp.Metadata["platform"]
		profileHits[key]++
	}
	if len(profileHits) < len(profileTable) {
		t.Errorf("expected all %d profiles covered, got %d", len(profileTable), len(profileHits))
	}
}

func TestGenerateFingerprint_ChromeHasClientHints(t *testing.T) {
	// Find a session that maps to a Chrome profile
	for i := 0; i < 100; i++ {
		id := "chrome-test-" + string(rune(i))
		fp := GenerateFingerprint(id)
		if fp.Metadata["browser"] == "chrome" {
			if fp.HTTP.ClientHints == nil {
				t.Error("Chrome profile should have client hints")
			}
			if fp.HTTP.ClientHints.SecCHUA == "" {
				t.Error("Chrome profile should have Sec-CH-UA")
			}
			return
		}
	}
	t.Skip("no Chrome profile hit in 100 attempts")
}

func TestGenerateFingerprint_FirefoxNoClientHints(t *testing.T) {
	for i := 0; i < 100; i++ {
		id := "firefox-test-" + string(rune(i))
		fp := GenerateFingerprint(id)
		if fp.Metadata["browser"] == "firefox" {
			if fp.HTTP.ClientHints != nil {
				t.Error("Firefox profile should NOT have client hints")
			}
			return
		}
	}
	t.Skip("no Firefox profile hit in 100 attempts")
}
