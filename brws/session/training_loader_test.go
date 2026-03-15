package session

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadTrainingProfiles_RealData(t *testing.T) {
	trainingDir := "../../training-data"
	if _, err := os.Stat(trainingDir); os.IsNotExist(err) {
		t.Skip("training-data directory not present")
	}

	profiles, err := LoadTrainingProfiles(trainingDir)
	if err != nil {
		t.Fatalf("LoadTrainingProfiles: %v", err)
	}

	if len(profiles) == 0 {
		t.Fatal("expected at least one trained profile")
	}

	for _, p := range profiles {
		t.Logf("Loaded: %s/%s/%s from %s (%d nav headers)",
			p.Name, p.Version, p.Platform, p.SourceSession, len(p.HeaderOrder))

		if p.UserAgent == "" {
			t.Error("trained profile has empty UserAgent")
		}
		if len(p.HeaderOrder) == 0 {
			t.Error("trained profile has empty HeaderOrder")
		}
	}
}

func TestLoadTrainingProfiles_SyntheticData(t *testing.T) {
	dir := t.TempDir()
	sessionDir := filepath.Join(dir, "session-test")
	if err := os.MkdirAll(sessionDir, 0o755); err != nil {
		t.Fatal(err)
	}

	patterns := headerPatterns{
		NavigationHeaderOrder:  []string{"accept", "user-agent", "sec-ch-ua"},
		SubresourceHeaderOrder: []string{"accept", "user-agent"},
		CommonHeaders: map[string]string{
			"user-agent":        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
			"sec-ch-ua":         `"Chromium";v="146", "Google Chrome";v="146"`,
			"sec-ch-ua-platform": `"Windows"`,
			"accept-language":   "en-US,en;q=0.9",
		},
		HeaderFrequency: map[string]int{
			"user-agent": 2,
			"sec-ch-ua":  2,
		},
	}

	data, _ := json.Marshal(patterns)
	if err := os.WriteFile(filepath.Join(sessionDir, "header_patterns.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	profiles, err := LoadTrainingProfiles(dir)
	if err != nil {
		t.Fatalf("LoadTrainingProfiles: %v", err)
	}

	if len(profiles) != 1 {
		t.Fatalf("expected 1 profile, got %d", len(profiles))
	}

	p := profiles[0]
	if p.Name != "chrome" {
		t.Errorf("expected browser 'chrome', got %q", p.Name)
	}
	if p.Version != "146" {
		t.Errorf("expected version '146', got %q", p.Version)
	}
	if p.Platform != "windows" {
		t.Errorf("expected platform 'windows', got %q", p.Platform)
	}
	if p.SourceSession != "session-test" {
		t.Errorf("expected source session 'session-test', got %q", p.SourceSession)
	}
	if len(p.HeaderOrder) != 3 {
		t.Errorf("expected 3 header order entries, got %d", len(p.HeaderOrder))
	}
}

func TestMergeTrainedProfiles(t *testing.T) {
	originalLen := len(profileTable)
	defer func() {
		// Restore original profile table
		profileTable = profileTable[len(profileTable)-originalLen:]
	}()

	trained := []TrainedProfile{
		{
			browserProfile: browserProfile{
				Name: "chrome", Version: "150", Platform: "linux",
				UserAgent: "Mozilla/5.0 Chrome/150.0.0.0",
			},
			HeaderOrder:   []string{"accept", "user-agent"},
			SourceSession: "test-session",
		},
	}

	added := MergeTrainedProfiles(trained)
	if added != 1 {
		t.Errorf("expected 1 new profile added, got %d", added)
	}

	if len(profileTable) != originalLen+1 {
		t.Errorf("expected %d profiles, got %d", originalLen+1, len(profileTable))
	}

	// The new profile should be first (prepended)
	if profileTable[0].Name != "chrome" || profileTable[0].Version != "150" {
		t.Error("trained profile should be prepended to table")
	}
}

func TestParseBrowserFromUA(t *testing.T) {
	tests := []struct {
		ua      string
		name    string
		version string
	}{
		{"Mozilla/5.0 (Windows NT 10.0) Chrome/146.0.0.0 Safari/537.36", "chrome", "146"},
		{"Mozilla/5.0 (Windows NT 10.0) Firefox/128.0", "firefox", "128"},
		{"Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0", "edge", "120"},
	}

	for _, tc := range tests {
		name, version := parseBrowserFromUA(tc.ua)
		if name != tc.name {
			t.Errorf("parseBrowserFromUA(%q) name = %q, want %q", tc.ua, name, tc.name)
		}
		if version != tc.version {
			t.Errorf("parseBrowserFromUA(%q) version = %q, want %q", tc.ua, version, tc.version)
		}
	}
}

func TestParsePlatformFromUA(t *testing.T) {
	tests := []struct {
		ua       string
		platform string
	}{
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "windows"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "macos"},
		{"Mozilla/5.0 (X11; Linux x86_64)", "linux"},
	}

	for _, tc := range tests {
		platform := parsePlatformFromUA(tc.ua)
		if platform != tc.platform {
			t.Errorf("parsePlatformFromUA(%q) = %q, want %q", tc.ua, platform, tc.platform)
		}
	}
}

func TestLoadTrainingProfiles_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadTrainingProfiles(dir)
	if err == nil {
		t.Error("expected error for empty training directory")
	}
}

func TestLoadTrainingProfiles_MissingDir(t *testing.T) {
	_, err := LoadTrainingProfiles("/nonexistent/path")
	if err == nil {
		t.Error("expected error for missing directory")
	}
}
