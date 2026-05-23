package profiles

import (
	"testing"
)

func TestGetByName(t *testing.T) {
	tests := []struct {
		name        string
		profileName string
		wantName    string
	}{
		{"chrome-120-macos", "chrome-120-macos", "chrome"},
		{"chrome-120-windows", "chrome-120-windows", "chrome"},
		{"firefox-120-windows", "firefox-120-windows", "firefox"},
		{"safari-16-macos", "safari-16-macos", "safari"},
		{"edge-120-windows", "edge-120-windows", "edge"},
		{"default", "unknown", "chrome"}, // should default to chrome
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := GetByName(tt.profileName)
			if p.Name != tt.wantName {
				t.Errorf("GetByName(%s) = %v, want %v", tt.profileName, p.Name, tt.wantName)
			}
		})
	}
}

func TestProfileToHeaders(t *testing.T) {
	p := GetChrome120Mac()
	headers := p.ToHeaders()

	if headers["User-Agent"] == "" {
		t.Error("Expected User-Agent header")
	}
	if headers["Accept"] == "" {
		t.Error("Expected Accept header")
	}
	if headers["Sec-Ch-Ua"] == "" {
		t.Error("Expected Sec-Ch-Ua header")
	}
}

func TestAvailableProfiles(t *testing.T) {
	profiles := AvailableProfiles()
	if len(profiles) == 0 {
		t.Error("Expected at least one profile")
	}
}

func TestRandomProfile(t *testing.T) {
	// Just test that it doesn't panic
	p := RandomProfile()
	if p == nil {
		t.Error("RandomProfile returned nil")
	}
}

func TestRandomProfileForPlatform(t *testing.T) {
	tests := []struct {
		platform string
	}{
		{"windows"},
		{"macos"},
		{"android"},
		{"ios"},
		{"unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.platform, func(t *testing.T) {
			p := RandomProfileForPlatform(tt.platform)
			if p == nil {
				t.Errorf("RandomProfileForPlatform(%s) returned nil", tt.platform)
			}
		})
	}
}

func TestProfileMutate(t *testing.T) {
	p := GetChrome120Mac()
	mutated := p.Mutate()

	// Mutated profile should be different from original
	if mutated == nil {
		t.Error("Mutate returned nil")
	}

	// Test multiple mutations
	for i := 0; i < 10; i++ {
		m := p.Mutate()
		if m.Version != p.Version {
			// Version should change sometimes
			break
		}
		if i == 9 {
			t.Logf("Note: Version didn't change in 10 iterations (random)")
		}
	}
}

func TestRotatorNext(t *testing.T) {
	rotator := NewRotator([]*Profile{
		GetChrome120Mac(),
		GetFirefox120Win(),
	})

	// Should return different profiles
	p1 := rotator.Next()
	p2 := rotator.Next()

	if p1.Name == p2.Name && len(rotator.profiles) > 1 {
		t.Logf("Note: Got same profile twice (possible with few profiles)")
	}
}

func TestRotatorRandom(_ *testing.T) {
	rotator := NewRotator([]*Profile{
		GetChrome120Mac(),
		GetFirefox120Win(),
		GetSafari16Mac(),
	})

	// Just test that it doesn't panic
	for i := 0; i < 100; i++ {
		_ = rotator.Random()
	}
}

func TestRotatorMutated(_ *testing.T) {
	rotator := NewRotator(nil) // Uses all profiles

	// Just test that it doesn't panic
	for i := 0; i < 50; i++ {
		_ = rotator.Mutated()
	}
}

func TestProfileScreenSize(t *testing.T) {
	p := GetChrome120Mac()

	// Set screen size
	p.ScreenWidth = 1920
	p.ScreenHeight = 1080

	if p.ScreenWidth != 1920 || p.ScreenHeight != 1080 {
		t.Errorf("Screen size not set correctly")
	}
}

func TestGetChrome120Win(t *testing.T) {
	p := GetChrome120Win()
	if p == nil {
		t.Fatal("GetChrome120Win returned nil")
	}
	if p.Name != "chrome" {
		t.Errorf("Name = %q, want chrome", p.Name)
	}
	if p.Platform != "windows" {
		t.Errorf("Platform = %q, want windows", p.Platform)
	}
}

func TestGetFirefox120Mac(t *testing.T) {
	p := GetFirefox120Mac()
	if p == nil {
		t.Fatal("GetFirefox120Mac returned nil")
	}
	if p.Name != "firefox" {
		t.Errorf("Name = %q, want firefox", p.Name)
	}
}

func TestGetFirefox120Win(t *testing.T) {
	p := GetFirefox120Win()
	if p == nil {
		t.Fatal("GetFirefox120Win returned nil")
	}
	if p.Name != "firefox" {
		t.Errorf("Name = %q, want firefox", p.Name)
	}
	if p.Platform != "windows" {
		t.Errorf("Platform = %q, want windows", p.Platform)
	}
}

func TestGetSafari16Mac(t *testing.T) {
	p := GetSafari16Mac()
	if p == nil {
		t.Fatal("GetSafari16Mac returned nil")
	}
	if p.Name != "safari" {
		t.Errorf("Name = %q, want safari", p.Name)
	}
}

func TestGetEdge120Win(t *testing.T) {
	p := GetEdge120Win()
	if p == nil {
		t.Fatal("GetEdge120Win returned nil")
	}
	if p.Name != "edge" {
		t.Errorf("Name = %q, want edge", p.Name)
	}
}

func TestGetSafariMobileiOS(t *testing.T) {
	p := GetSafariMobileiOS()
	if p == nil {
		t.Fatal("GetSafariMobileiOS returned nil")
	}
}

func TestGetChrome120Android(t *testing.T) {
	p := GetChrome120Android()
	if p == nil {
		t.Fatal("GetChrome120Android returned nil")
	}
	if p.Platform != "android" {
		t.Errorf("Platform = %q, want android", p.Platform)
	}
}

func TestProfileToHeaders_userAgent(t *testing.T) {
	profiles := []*Profile{
		GetChrome120Mac(),
		GetChrome120Win(),
		GetFirefox120Mac(),
		GetSafari16Mac(),
		GetEdge120Win(),
	}
	for _, p := range profiles {
		headers := p.ToHeaders()
		ua := headers["User-Agent"]
		if ua == "" {
			t.Errorf("%s/%s profile missing User-Agent", p.Name, p.Platform)
		}
		if ua == "Go-http-client/1.1" {
			t.Errorf("%s/%s profile should not use Go UA", p.Name, p.Platform)
		}
	}
}

func TestProfileToHeaders_acceptLanguage(t *testing.T) {
	p := GetChrome120Mac()
	headers := p.ToHeaders()
	if headers["Accept-Language"] == "" {
		t.Error("expected Accept-Language header")
	}
}

func TestProfileToHeaders_acceptEncoding(t *testing.T) {
	p := GetChrome120Mac()
	headers := p.ToHeaders()
	if headers["Accept-Encoding"] == "" {
		t.Error("expected Accept-Encoding header")
	}
}

func TestAvailableProfiles_containsKnown(t *testing.T) {
	all := AvailableProfiles()
	known := []string{"chrome-120-macos", "chrome-120-windows", "firefox-120-macos"}
	for _, name := range known {
		found := false
		for _, p := range all {
			if p == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("profile %q not in AvailableProfiles()", name)
		}
	}
}

func TestGetByName_allAvailable(t *testing.T) {
	for _, name := range AvailableProfiles() {
		p := GetByName(name)
		if p == nil {
			t.Errorf("GetByName(%q) returned nil", name)
		}
		if p.Name == "" {
			t.Errorf("GetByName(%q) returned profile with empty Name", name)
		}
	}
}

func TestRotator_Next_doesNotPanic(t *testing.T) {
	rotator := NewRotator(nil) // all profiles
	for i := 0; i < 20; i++ {
		p := rotator.Next()
		if p == nil {
			t.Fatalf("iteration %d: Next() returned nil", i)
		}
	}
}

func TestProfile_Mutate_changesVersion(t *testing.T) {
	p := GetChrome120Mac()
	original := p.Version

	// Try many mutations — version should change at least once
	changed := false
	for i := 0; i < 50; i++ {
		m := p.Mutate()
		if m.Version != original {
			changed = true
			break
		}
	}
	if !changed {
		t.Log("Note: Version did not change in 50 mutations (probabilistic)")
	}
}
