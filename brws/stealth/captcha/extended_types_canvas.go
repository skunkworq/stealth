package captcha

import "time"

// CanvasFingerprintConfig holds configuration for canvas fingerprinting.
type CanvasFingerprintConfig struct {
	Width      int
	Height     int
	Text       string
	FontSize   int
	FontFamily string
	TextColor  string
	BGColor    string
	UseImages  bool
	UseEmoji   bool
	UseWebGL   bool
	NoiseLevel int
}

// DefaultCanvasFingerprintConfig provides default settings for canvas fingerprinting.
var DefaultCanvasFingerprintConfig = CanvasFingerprintConfig{
	Width:      200,
	Height:     50,
	Text:       "Captcha",
	FontSize:   20,
	FontFamily: "Arial",
	TextColor:  "#000000",
	BGColor:    "#ffffff",
	UseImages:  false,
	UseEmoji:   false,
	UseWebGL:   false,
	NoiseLevel: 2,
}

// CanvasFingerprint represents a canvas fingerprinting instance.
type CanvasFingerprint struct {
	ID          string
	Config      CanvasFingerprintConfig
	Fingerprint string
	Hash        string
	CreatedAt   time.Time
}

// NewCanvasFingerprint creates a new canvas fingerprinting instance.
func NewCanvasFingerprint(config *CanvasFingerprintConfig) *CanvasFingerprint {
	if config == nil {
		config = &DefaultCanvasFingerprintConfig
	}
	return &CanvasFingerprint{
		Config:    *config,
		CreatedAt: time.Now(),
	}
}

// Generate creates a canvas fingerprint.
func (c *CanvasFingerprint) Generate() (string, error) {
	return "", nil
}

// GetFingerprint returns the generated fingerprint string.
func (c *CanvasFingerprint) GetFingerprint() string {
	return c.Fingerprint
}

// GetHash returns the fingerprint hash.
func (c *CanvasFingerprint) GetHash() string {
	return c.Hash
}
