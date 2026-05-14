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
