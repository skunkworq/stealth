package captcha

import "time"

// AudioConfig holds configuration for audio CAPTCHAs.
type AudioConfig struct {
	Language   string
	BitRate    int
	SampleRate int
	Channels   int
	CharSet    string
	DigitsOnly bool
	Length     int
	Speed      float64
	Volume     float64
	NoiseLevel float64
}

// DefaultAudioConfig provides default settings for audio CAPTCHAs.
var DefaultAudioConfig = AudioConfig{
	Language:   "en",
	BitRate:    128,
	SampleRate: 22050,
	Channels:   1,
	CharSet:    "0123456789",
	DigitsOnly: true,
	Length:     4,
	Speed:      1.0,
	Volume:     0.8,
	NoiseLevel: 0.1,
}

// AudioCaptcha represents an audio CAPTCHA instance.
type AudioCaptcha struct {
	ID        string
	Solution  string
	Config    AudioConfig
	AudioData []byte
	CreatedAt time.Time
	ExpiresAt time.Time
}

// NewAudioCaptcha creates a new audio CAPTCHA instance.
func NewAudioCaptcha(config *AudioConfig) *AudioCaptcha {
	if config == nil {
		config = &DefaultAudioConfig
	}
	return &AudioCaptcha{
		Config:    *config,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
}

// Generate creates a new audio CAPTCHA and returns the solution.
func (a *AudioCaptcha) Generate() (string, error) {
	charSet := a.Config.CharSet
	if a.Config.DigitsOnly {
		charSet = "0123456789"
	}
	text := generateRandomString(a.Config.Length, charSet)
	a.Solution = text
	return text, nil
}

// Validate checks if the provided answer matches the solution.
func (a *AudioCaptcha) Validate(answer string) bool {
	return a.Solution == answer
}

// IsExpired returns true if the audio CAPTCHA has expired.
func (a *AudioCaptcha) IsExpired() bool {
	return time.Now().After(a.ExpiresAt)
}
