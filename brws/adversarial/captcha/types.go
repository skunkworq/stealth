package captcha

import (
	"image"
	"image/color"
	"time"
)

// CaptchaType represents the type of CAPTCHA challenge.

type CaptchaType string

const (
	// CaptchaTypeText represents a text-based CAPTCHA.
	CaptchaTypeText CaptchaType = "text"
	// CaptchaTypeMath represents a math-based CAPTCHA.
	CaptchaTypeMath CaptchaType = "math"
	// CaptchaTypeImage represents an image-based CAPTCHA.
	CaptchaTypeImage CaptchaType = "image"
	// CaptchaTypeSlider represents a slider-based CAPTCHA.
	CaptchaTypeSlider CaptchaType = "slider"
)

// Difficulty represents the difficulty level of a CAPTCHA.
type Difficulty int

const (
	// DifficultyEasy represents easy difficulty.
	DifficultyEasy Difficulty = 1
	// DifficultyMedium represents medium difficulty.
	DifficultyMedium Difficulty = 2
	// DifficultyHard represents hard difficulty.
	DifficultyHard Difficulty = 3
	// DifficultyExtreme represents extreme difficulty.
	DifficultyExtreme Difficulty = 4
)

// CaptchaConfig holds configuration for CAPTCHA generation.

type CaptchaConfig struct {
	Length          int
	Width           int
	Height          int
	FontSize        int
	CharSet         string
	NoiseLines      int
	NoiseDots       int
	BackgroundColor color.RGBA
	TextColor       color.RGBA
	Difficulty      Difficulty
	Rotate          bool
	Wave            bool
	UseFonts        []string

	// Advanced deformation fields
	OverlapPx       int     // Negative char spacing (px overlap between adjacent chars)
	WaveFrequencies int     // Number of sine wave layers (1=mild, 3=heavy)
	WaveAmplitude   float64 // Max amplitude for each wave layer (px)
	PerCharColor    bool    // Each character gets a distinct random color
	PerCharSize     bool    // Each character gets ±20% font size variation
	ThickNoiseLines bool    // Noise lines 2-4px thick instead of 1px
	BackgroundGrid  bool    // Faint grid pattern behind text (anti-segmentation)
}

// DefaultConfig provides default settings for CAPTCHA generation.
var DefaultConfig = CaptchaConfig{
	Length:          6,
	Width:           200,
	Height:          80,
	FontSize:        36,
	CharSet:         "ABCDEFGHJKLMNPQRSTUVWXYZ23456789",
	NoiseLines:      3,
	NoiseDots:       50,
	BackgroundColor: color.RGBA{255, 255, 255, 255},
	TextColor:       color.RGBA{0, 0, 0, 255},
	Difficulty:      DifficultyMedium,
	Rotate:          true,
	Wave:            true,
	UseFonts:        []string{"arial", "times", "courier"},
	WaveFrequencies: 1,
	WaveAmplitude:   2,
}

// EasyConfig provides easy CAPTCHA settings — no overlap, mild wave, no grid.
var EasyConfig = CaptchaConfig{
	Length:          6,
	Width:           200,
	Height:          80,
	FontSize:        36,
	CharSet:         "ABCDEFGHJKLMNPQRSTUVWXYZ23456789",
	NoiseLines:      2,
	NoiseDots:       30,
	BackgroundColor: color.RGBA{255, 255, 255, 255},
	TextColor:       color.RGBA{0, 0, 0, 255},
	Difficulty:      DifficultyEasy,
	Rotate:          true,
	Wave:            true,
	OverlapPx:       0,
	WaveFrequencies: 1,
	WaveAmplitude:   2,
	PerCharColor:    false,
	PerCharSize:     false,
	ThickNoiseLines: false,
	BackgroundGrid:  false,
}

// HardConfig provides hard CAPTCHA settings — overlapping chars, multi-wave, thick lines, grid.
var HardConfig = CaptchaConfig{
	Length:          6,
	Width:           200,
	Height:          80,
	FontSize:        36,
	CharSet:         "ABCDEFGHJKLMNPQRSTUVWXYZ23456789",
	NoiseLines:      5,
	NoiseDots:       80,
	BackgroundColor: color.RGBA{255, 255, 255, 255},
	TextColor:       color.RGBA{0, 0, 0, 255},
	Difficulty:      DifficultyHard,
	Rotate:          true,
	Wave:            true,
	OverlapPx:       5,
	WaveFrequencies: 3,
	WaveAmplitude:   4,
	PerCharColor:    true,
	PerCharSize:     true,
	ThickNoiseLines: true,
	BackgroundGrid:  true,
}

// ExtremeConfig provides extreme CAPTCHA settings — heavy overlap, max deformation.
var ExtremeConfig = CaptchaConfig{
	Length:          6,
	Width:           200,
	Height:          80,
	FontSize:        36,
	CharSet:         "ABCDEFGHJKLMNPQRSTUVWXYZ23456789",
	NoiseLines:      7,
	NoiseDots:       120,
	BackgroundColor: color.RGBA{255, 255, 255, 255},
	TextColor:       color.RGBA{0, 0, 0, 255},
	Difficulty:      DifficultyExtreme,
	Rotate:          true,
	Wave:            true,
	OverlapPx:       8,
	WaveFrequencies: 3,
	WaveAmplitude:   5,
	PerCharColor:    true,
	PerCharSize:     true,
	ThickNoiseLines: true,
	BackgroundGrid:  true,
}

// ConfigForDifficulty returns the appropriate config preset for a given difficulty.
func ConfigForDifficulty(d Difficulty) *CaptchaConfig {
	switch d {
	case DifficultyEasy:
		cfg := EasyConfig
		return &cfg
	case DifficultyMedium:
		cfg := DefaultConfig
		return &cfg
	case DifficultyHard:
		cfg := HardConfig
		return &cfg
	case DifficultyExtreme:
		cfg := ExtremeConfig
		return &cfg
	default:
		cfg := DefaultConfig
		return &cfg
	}
}

// Captcha represents a generated CAPTCHA challenge.
type Captcha struct {
	ID        string
	Type      CaptchaType
	Image     image.Image
	Solution  interface{}
	Metadata  CaptchaMetadata
	CreatedAt time.Time
}

// CaptchaMetadata holds metadata about a generated CAPTCHA.

type CaptchaMetadata struct {
	Difficulty   Difficulty
	CharCount    int
	CharSetUsed  string
	HasNoise     bool
	HasRotation  bool
	HasWarp      bool
	GenerationMs int64
	EntropyBits  float64
}

// TextSolution represents a text-based CAPTCHA solution.
type TextSolution struct {
	Text   string
	Chars  []rune
	Tokens []string
}

// MathSolution represents a math-based CAPTCHA solution.
type MathSolution struct {
	Expression string
	Answer     int
	Operands   []int
	Operator   string
}

// ImageSolution represents an image-based CAPTCHA solution.
type ImageSolution struct {
	SelectedIndices []int
	TargetImage     string
	Distractors     []string
}

// SliderSolution represents a slider-based CAPTCHA solution.
type SliderSolution struct {
	StartX     int
	EndX       int
	Distance   int
	TrackWidth int
}

// CaptchaGenerator defines the interface for CAPTCHA generators.

type CaptchaGenerator interface {
	Generate(config *CaptchaConfig) (*Captcha, error)
	GenerateBatch(count int, config *CaptchaConfig) ([]*Captcha, error)
	Validate(captcha *Captcha, answer string) bool
}

// CaptchaStore provides storage for CAPTCHA challenges.

type CaptchaStore struct {
	captchas map[string]*Captcha
}

// NewCaptchaStore creates a new CAPTCHA store.
func NewCaptchaStore() *CaptchaStore {
	return &CaptchaStore{
		captchas: make(map[string]*Captcha),
	}
}

// Add adds a CAPTCHA to the store.
func (s *CaptchaStore) Add(captcha *Captcha) {
	s.captchas[captcha.ID] = captcha
}

// Get retrieves a CAPTCHA by ID from the store.
func (s *CaptchaStore) Get(id string) (*Captcha, bool) {
	c, ok := s.captchas[id]
	return c, ok
}

// Remove removes a CAPTCHA from the store by ID.
func (s *CaptchaStore) Remove(id string) {
	delete(s.captchas, id)
}

// Count returns the number of CAPTCHAs in the store.
func (s *CaptchaStore) Count() int {
	return len(s.captchas)
}

// Cleanup removes expired CAPTCHAs and returns the count removed.
func (s *CaptchaStore) Cleanup(maxAge time.Duration) int {
	now := time.Now()
	removed := 0
	for id, c := range s.captchas {
		if now.Sub(c.CreatedAt) > maxAge {
			delete(s.captchas, id)
			removed++
		}
	}
	return removed
}

// CaptchaStatistics holds statistics about CAPTCHA usage.

type CaptchaStatistics struct {
	TotalGenerated int
	TotalSolved    int
	TotalFailed    int
	SuccessRate    float64
	AvgSolveTimeMs float64
	ByType         map[CaptchaType]int
	ByDifficulty   map[Difficulty]int
}

// NewCaptchaStatistics creates a new statistics collector.
func NewCaptchaStatistics() *CaptchaStatistics {
	return &CaptchaStatistics{
		ByType:       make(map[CaptchaType]int),
		ByDifficulty: make(map[Difficulty]int),
	}
}

// RecordGeneration records a CAPTCHA generation event.
func (s *CaptchaStatistics) RecordGeneration(captcha *Captcha) {
	s.TotalGenerated++
	s.ByType[captcha.Type]++
	s.ByDifficulty[captcha.Metadata.Difficulty]++
}

// RecordSuccess records a successful CAPTCHA solve.
func (s *CaptchaStatistics) RecordSuccess(solveTimeMs int64) {
	s.TotalSolved++
	if s.TotalSolved > 0 {
		s.SuccessRate = float64(s.TotalSolved) / float64(s.TotalSolved+s.TotalFailed)
	}
	oldAvg := s.AvgSolveTimeMs * float64(s.TotalSolved-1)
	s.AvgSolveTimeMs = (oldAvg + float64(solveTimeMs)) / float64(s.TotalSolved)
}

// RecordFailure records a failed CAPTCHA solve attempt.
func (s *CaptchaStatistics) RecordFailure() {
	s.TotalFailed++
	if s.TotalSolved+s.TotalFailed > 0 {
		s.SuccessRate = float64(s.TotalSolved) / float64(s.TotalSolved+s.TotalFailed)
	}
}
