package captcha

import "time"

// ReCaptchaV2Config holds configuration for reCAPTCHA v2 challenges.
type ReCaptchaV2Config struct {
	Theme         string
	Size          string
	TabIndex      int
	SiteKey       string
	ChallengeType string
	ImageCount    int
	GridRows      int
	GridCols      int
	Instructions  string
	HintText      string
}

// DefaultReCaptchaV2Config provides default settings for reCAPTCHA v2.
var DefaultReCaptchaV2Config = ReCaptchaV2Config{
	Theme:         "light",
	Size:          "normal",
	TabIndex:      0,
	ChallengeType: "image",
	ImageCount:    9,
	GridRows:      3,
	GridCols:      3,
	Instructions:  "Select all images matching",
	HintText:      "Press and hold on matching images",
}

// ReCaptchaV2 represents a reCAPTCHA v2 challenge instance.
type ReCaptchaV2 struct {
	ID             string
	SiteKey        string
	ChallengeImage ImageChallenge
	TargetLabel    string
	Options        []ImageOption
	Config         ReCaptchaV2Config
	CreatedAt      time.Time
	ExpiresAt      time.Time
}

// ImageChallenge represents an image-based CAPTCHA challenge.
type ImageChallenge struct {
	ImageURL    string
	BaseImage   string
	GridSize    int
	Cells       []GridCell
	TargetClass string
}

// GridCell represents a single cell in an image grid challenge.
type GridCell struct {
	Index     int
	Row       int
	Col       int
	ImageData string
	IsTarget  bool
	Label     string
}

// ImageOption represents an option in an image CAPTCHA challenge.
type ImageOption struct {
	Index    int
	ImageURL string
	Label    string
	IsTarget bool
	Selected bool
}

// NewReCaptchaV2 creates a new reCAPTCHA v2 challenge instance.
func NewReCaptchaV2(config *ReCaptchaV2Config) *ReCaptchaV2 {
	if config == nil {
		config = &DefaultReCaptchaV2Config
	}
	return &ReCaptchaV2{
		Config:    *config,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(2 * time.Minute),
	}
}

// Generate generates a reCAPTCHA challenge for the given target.
func (r *ReCaptchaV2) Generate(target string) error {
	r.TargetLabel = target
	r.ChallengeImage.TargetClass = target

	imageCount := r.Config.ImageCount
	r.Options = make([]ImageOption, imageCount)

	for i := 0; i < imageCount; i++ {
		isTarget := i < 3
		r.Options[i] = ImageOption{
			Index:    i,
			ImageURL: "",
			Label:    "",
			IsTarget: isTarget,
			Selected: false,
		}
	}

	r.ChallengeImage.Cells = make([]GridCell, imageCount)
	cols := r.Config.GridCols

	for i := 0; i < imageCount; i++ {
		r.ChallengeImage.Cells[i] = GridCell{
			Index:     i,
			Row:       i / cols,
			Col:       i % cols,
			ImageData: "",
			IsTarget:  r.Options[i].IsTarget,
			Label:     r.TargetLabel,
		}
	}

	return nil
}

// Validate checks if the selected indices match the target options.
func (r *ReCaptchaV2) Validate(selectedIndices []int) bool {
	expected := 0
	for _, opt := range r.Options {
		if opt.IsTarget {
			expected++
		}
	}

	correct := 0
	for _, idx := range selectedIndices {
		if idx >= 0 && idx < len(r.Options) && r.Options[idx].IsTarget {
			correct++
		}
	}

	if expected == 0 {
		return correct == 0
	}

	return float64(correct) >= float64(expected)*0.7
}

// IsExpired returns true if the challenge has expired.
func (r *ReCaptchaV2) IsExpired() bool {
	return time.Now().After(r.ExpiresAt)
}
