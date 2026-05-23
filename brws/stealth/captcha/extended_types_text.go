package captcha

import "time"

// DistortedTextConfig holds configuration for distorted text CAPTCHAs.
type DistortedTextConfig struct {
	Length         int
	Width          int
	Height         int
	FontSize       int
	FontFamily     string
	CharSet        string
	NoiseLevel     int
	DistortionType string
	LineThickness  int
	ArcThickness   int
	BlurRadius     float64
	BackgroundURL  string
	TextColor      string
	BorderColor    string
	CaseSensitive  bool
	GridLines      int
}

// DefaultDistortedTextConfig provides default settings for distorted text CAPTCHAs.
var DefaultDistortedTextConfig = DistortedTextConfig{
	Length:         5,
	Width:          250,
	Height:         80,
	FontSize:       40,
	FontFamily:     "Arial",
	CharSet:        "ABCDEFGHJKLMNPQRSTUVWXYZ23456789",
	NoiseLevel:     3,
	DistortionType: "wave",
	LineThickness:  2,
	ArcThickness:   1,
	BlurRadius:     1.0,
	CaseSensitive:  true,
	GridLines:      3,
}

// DistortedTextCaptcha represents a distorted text CAPTCHA instance.
type DistortedTextCaptcha struct {
	ID        string
	Solution  string
	Config    DistortedTextConfig
	CreatedAt time.Time
	ExpiresAt time.Time
}

// NewDistortedTextCaptcha creates a new distorted text CAPTCHA instance.
func NewDistortedTextCaptcha(config *DistortedTextConfig) *DistortedTextCaptcha {
	if config == nil {
		config = &DefaultDistortedTextConfig
	}
	return &DistortedTextCaptcha{
		Config:    *config,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
}

// Generate creates a new distorted text CAPTCHA and returns the solution.
func (d *DistortedTextCaptcha) Generate() (string, error) {
	text := generateRandomString(d.Config.Length, d.Config.CharSet)
	d.Solution = text
	return text, nil
}

// Validate checks if the provided answer matches the solution.
func (d *DistortedTextCaptcha) Validate(answer string) bool {
	if d.Config.CaseSensitive {
		return d.Solution == answer
	}
	return toLower(d.Solution) == toLower(answer)
}

// IsExpired returns true if the distorted text CAPTCHA has expired.
func (d *DistortedTextCaptcha) IsExpired() bool {
	return time.Now().After(d.ExpiresAt)
}

// generateRandomString builds a pseudo-random string of the given length from
// charSet. Shared by DistortedTextCaptcha and AudioCaptcha.
func generateRandomString(length int, charSet string) string {
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		result[i] = charSet[i%len(charSet)]
	}
	return string(result)
}

func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		result[i] = c
	}
	return string(result)
}
