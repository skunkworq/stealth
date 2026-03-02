// Package captcha provides CAPTCHA solving and generation capabilities.
package captcha

import (
	"fmt"
	"math/rand"
	"time"
)

// webGLRand is a local random source for WebGL scene generation.
// math/rand is used intentionally (not crypto/rand) because:
// 1. We need reproducible randomness for visual scene generation
// 2. Performance is more important than cryptographic security for visual effects
// 3. The randomness is used for visual placement, not security
var webGLRand = rand.New(rand.NewSource(time.Now().UnixNano()))

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

// HCaptchaConfig holds configuration for hCaptcha challenges.
type HCaptchaConfig struct {
	SiteKey        string
	Theme          string
	ReportAPI      string
	AssetsHost     string
	Assets         string
	RequestAPI     string
	SentryEndpoint string
	SentAPI        string
	SurveyAPI      string
	APIHealthCheck string
	Parallax       bool
	Padding        bool
	Offset         int
}

// DefaultHCaptchaConfig provides default settings for hCaptcha.
var DefaultHCaptchaConfig = HCaptchaConfig{
	SiteKey:  "",
	Theme:    "light",
	Parallax: true,
	Padding:  true,
	Offset:   50,
}

// HCaptchaCategory represents a category for hCaptcha image challenges.
type HCaptchaCategory struct {
	Name         string
	Instructions string
	Examples     []string
}

// DefaultCategories provides default hCaptcha challenge categories.
var DefaultCategories = []HCaptchaCategory{
	{Name: "automobile", Instructions: "Select all images containing cars", Examples: []string{"car", "truck", "bus", "motorcycle"}},
	{Name: "bird", Instructions: "Select all images containing birds", Examples: []string{"sparrow", "eagle", "pigeon"}},
	{Name: "bicycle", Instructions: "Select all images containing bicycles", Examples: []string{"bike", "bicycle"}},
	{Name: "boat", Instructions: "Select all images containing boats", Examples: []string{"ship", "boat", "yacht"}},
	{Name: "bus", Instructions: "Select all images containing buses", Examples: []string{"bus", "coach"}},
	{Name: "cab", Instructions: "Select all images containing taxis", Examples: []string{"taxi", "cab", "uber"}},
	{Name: "cat", Instructions: "Select all images containing cats", Examples: []string{"cat", "kitten", "feline"}},
	{Name: "chair", Instructions: "Select all images containing chairs", Examples: []string{"chair", "seat"}},
	{Name: "chicken", Instructions: "Select all images containing chickens", Examples: []string{"chicken", "hen", "rooster"}},
	{Name: "clock", Instructions: "Select all images containing clocks", Examples: []string{"clock", "watch", "time"}},
	{Name: "dog", Instructions: "Select all images containing dogs", Examples: []string{"dog", "puppy", "canine"}},
	{Name: "dolphin", Instructions: "Select all images containing dolphins", Examples: []string{"dolphin", "porpoise"}},
	{Name: "flower", Instructions: "Select all images containing flowers", Examples: []string{"flower", "blossom", "bloom"}},
	{Name: "fruit", Instructions: "Select all images containing fruit", Examples: []string{"apple", "banana", "orange"}},
	{Name: "guitar", Instructions: "Select all images containing guitars", Examples: []string{"guitar", "instrument"}},
	{Name: "hamburger", Instructions: "Select all images containing hamburgers", Examples: []string{"burger", "hamburger"}},
	{Name: "horse", Instructions: "Select all images containing horses", Examples: []string{"horse", "pony", "stallion"}},
	{Name: "house", Instructions: "Select all images containing houses", Examples: []string{"house", "home", "building"}},
	{Name: "laptop", Instructions: "Select all images containing laptops", Examples: []string{"laptop", "computer", "notebook"}},
	{Name: "lemon", Instructions: "Select all images containing lemons", Examples: []string{"lemon", "citrus"}},
	{Name: "lion", Instructions: "Select all images containing lions", Examples: []string{"lion", "big cat"}},
	{Name: "milk", Instructions: "Select all images containing milk", Examples: []string{"milk", "dairy"}},
	{Name: "moon", Instructions: "Select all images containing the moon", Examples: []string{"moon", "lunar"}},
	{Name: "motorbike", Instructions: "Select all images containing motorcycles", Examples: []string{"motorcycle", "bike"}},
	{Name: "mountain", Instructions: "Select all images containing mountains", Examples: []string{"mountain", "peak", "hill"}},
	{Name: "pizza", Instructions: "Select all images containing pizza", Examples: []string{"pizza", "pie"}},
	{Name: "raccoon", Instructions: "Select all images containing raccoons", Examples: []string{"raccoon", "trash panda"}},
	{Name: "river", Instructions: "Select all images containing rivers", Examples: []string{"river", "stream", "water"}},
	{Name: "rocket", Instructions: "Select all images containing rockets", Examples: []string{"rocket", "spacecraft"}},
	{Name: "sea", Instructions: "Select all images containing the sea", Examples: []string{"sea", "ocean", "water"}},
	{Name: "skateboard", Instructions: "Select all images containing skateboards", Examples: []string{"skateboard", "skate"}},
	{Name: "snowman", Instructions: "Select all images containing snowmen", Examples: []string{"snowman", "snow"}},
	{Name: "soccer", Instructions: "Select all images containing soccer", Examples: []string{"soccer", "football"}},
	{Name: "stadium", Instructions: "Select all images containing stadiums", Examples: []string{"stadium", "arena"}},
	{Name: "star", Instructions: "Select all images containing stars", Examples: []string{"star", "celestial"}},
	{Name: "streetlight", Instructions: "Select all images containing streetlights", Examples: []string{"streetlight", "lamp post"}},
	{Name: "sunflower", Instructions: "Select all images containing sunflowers", Examples: []string{"sunflower", "flower"}},
	{Name: "taco", Instructions: "Select all images containing tacos", Examples: []string{"taco", "mexican food"}},
	{Name: "tank", Instructions: "Select all images containing tanks", Examples: []string{"tank", "military"}},
	{Name: "taxi", Instructions: "Select all images containing taxis", Examples: []string{"taxi", "cab"}},
	{Name: "tiger", Instructions: "Select all images containing tigers", Examples: []string{"tiger", "big cat"}},
	{Name: "toilet", Instructions: "Select all images containing toilets", Examples: []string{"toilet", "bathroom"}},
	{Name: "traffic", Instructions: "Select all images containing traffic", Examples: []string{"traffic", "road"}},
	{Name: "train", Instructions: "Select all images containing trains", Examples: []string{"train", "railway"}},
	{Name: "truck", Instructions: "Select all images containing trucks", Examples: []string{"truck", "lorry"}},
	{Name: "tv", Instructions: "Select all images containing TVs", Examples: []string{"tv", "television", "screen"}},
	{Name: "umbrella", Instructions: "Select all images containing umbrellas", Examples: []string{"umbrella", "parasol"}},
	{Name: "vampire", Instructions: "Select all images containing vampires", Examples: []string{"vampire", "dracula"}},
	{Name: "video", Instructions: "Select all images containing videos", Examples: []string{"video", "camera"}},
	{Name: "water", Instructions: "Select all images containing water", Examples: []string{"water", "lake"}},
	{Name: "whale", Instructions: "Select all images containing whales", Examples: []string{"whale", "ocean"}},
	{Name: "zebra", Instructions: "Select all images containing zebras", Examples: []string{"zebra", "stripes"}},
}

// HCaptcha represents an hCaptcha challenge instance.
type HCaptcha struct {
	ID        string
	SiteKey   string
	Category  HCaptchaCategory
	Options   []HCaptchaOption
	Config    HCaptchaConfig
	CreatedAt time.Time
	ExpiresAt time.Time
}

// HCaptchaOption represents an option in an hCaptcha challenge.
type HCaptchaOption struct {
	Index    int
	ImageURL string
	Label    string
	IsMatch  bool
	Selected bool
}

// NewHCaptcha creates a new hCaptcha challenge instance.
func NewHCaptcha(config *HCaptchaConfig, categoryName string) (*HCaptcha, error) {
	if config == nil {
		config = &DefaultHCaptchaConfig
	}

	category := DefaultCategories[0]
	for _, cat := range DefaultCategories {
		if cat.Name == categoryName {
			category = cat
			break
		}
	}

	return &HCaptcha{
		SiteKey:   config.SiteKey,
		Category:  category,
		Config:    *config,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(2 * time.Minute),
	}, nil
}

// Generate generates an hCaptcha challenge with the specified number of options.
// Generate generates an hCaptcha challenge with the specified number of options.
func (h *HCaptcha) Generate(numOptions int) error {
	h.Options = make([]HCaptchaOption, numOptions)

	targetCount := 4
	for i := 0; i < numOptions; i++ {
		isMatch := i < targetCount
		h.Options[i] = HCaptchaOption{
			Index:    i,
			ImageURL: "",
			Label:    h.Category.Name,
			IsMatch:  isMatch,
			Selected: false,
		}
	}

	return nil
}

// Validate checks if the selected indices match the target options.
// Validate checks if the selected indices match the target options.
func (h *HCaptcha) Validate(selectedIndices []int) bool {
	expected := 0
	for _, opt := range h.Options {
		if opt.IsMatch {
			expected++
		}
	}

	correct := 0
	for _, idx := range selectedIndices {
		if idx >= 0 && idx < len(h.Options) && h.Options[idx].IsMatch {
			correct++
		}
	}

	if expected == 0 {
		return correct == 0
	}

	return float64(correct) >= float64(expected)*0.7
}

// IsExpired returns true if the hCaptcha challenge has expired.
// IsExpired returns true if the challenge has expired.
func (h *HCaptcha) IsExpired() bool {
	return time.Now().After(h.ExpiresAt)
}

// TurnstileConfig holds configuration for Cloudflare Turnstile challenges.
// TurnstileConfig holds configuration for Turnstile challenges.
type TurnstileConfig struct {
	SiteKey                  string
	Theme                    string
	Action                   string
	cData                    string
	Callback                 string
	TimeoutCallback          string
	ErrorCallback            string
	BeforeEnterCB            string
	AfterEnterCB             string
	ExpiredCallback          string
	ChallengeExpiredCallback string
}

// DefaultTurnstileConfig provides default settings for Turnstile challenges.
// DefaultTurnstileConfig provides default settings for Turnstile challenges.
var DefaultTurnstileConfig = TurnstileConfig{
	SiteKey: "",
	Theme:   "auto",
	Action:  "",
}

// TurnstileChallenge represents a Cloudflare Turnstile challenge instance.
// TurnstileChallenge represents a Turnstile challenge instance.
type TurnstileChallenge struct {
	ID            string
	SiteKey       string
	Token         string
	ChallengeTS   int64
	Action        string
	CData         string
	SecurityLevel string
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

// NewTurnstile creates a new Turnstile challenge instance.
// NewTurnstile creates a new Turnstile challenge instance.
func NewTurnstile(config *TurnstileConfig) *TurnstileChallenge {
	if config == nil {
		config = &DefaultTurnstileConfig
	}
	return &TurnstileChallenge{
		SiteKey:       config.SiteKey,
		Action:        config.Action,
		CData:         config.cData,
		SecurityLevel: "moderate",
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(1 * time.Minute),
	}
}

// Generate generates a new Turnstile challenge token.
// Generate generates a Turnstile challenge token.
func (t *TurnstileChallenge) Generate() error {
	t.Token = generateToken()
	t.ChallengeTS = time.Now().Unix()
	return nil
}

// Validate checks if the provided token matches and is not expired.
// Validate checks if the provided token matches and is not expired.
func (t *TurnstileChallenge) Validate(token string) bool {
	return t.Token == token && !t.IsExpired()
}

// IsExpired returns true if the Turnstile challenge has expired.
// IsExpired returns true if the challenge has expired.
func (t *TurnstileChallenge) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

func generateToken() string {
	return "tok_" + simpleID(32)
}

func simpleID(length int) string {
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		result[i] = chars[i%len(chars)]
	}
	return string(result)
}

// DistortedTextConfig holds configuration for distorted text CAPTCHAs.
// DistortedTextConfig holds configuration for distorted text CAPTCHA challenges.
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
// DefaultDistortedTextConfig provides default settings for distorted text CAPTCHA.
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
// DistortedTextCaptcha represents a distorted text CAPTCHA instance.
type DistortedTextCaptcha struct {
	ID        string
	Solution  string
	Config    DistortedTextConfig
	CreatedAt time.Time
	ExpiresAt time.Time
}

// NewDistortedTextCaptcha creates a new distorted text CAPTCHA instance.
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
// Generate generates a distorted text CAPTCHA and returns the solution.
func (d *DistortedTextCaptcha) Generate() (string, error) {
	text := generateRandomString(d.Config.Length, d.Config.CharSet)
	d.Solution = text
	return text, nil
}

func generateRandomString(length int, charSet string) string {
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		result[i] = charSet[i%len(charSet)]
	}
	return string(result)
}

// Validate checks if the provided answer matches the solution.
// Validate checks if the provided answer matches the solution.
func (d *DistortedTextCaptcha) Validate(answer string) bool {
	if d.Config.CaseSensitive {
		return d.Solution == answer
	}
	return toLower(d.Solution) == toLower(answer)
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

// IsExpired returns true if the distorted text CAPTCHA has expired.
// IsExpired returns true if the CAPTCHA has expired.
func (d *DistortedTextCaptcha) IsExpired() bool {
	return time.Now().After(d.ExpiresAt)
}

// AudioConfig holds configuration for audio CAPTCHAs.
// AudioConfig holds configuration for audio CAPTCHA challenges.
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
// DefaultAudioConfig provides default settings for audio CAPTCHA.
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
// Generate generates an audio CAPTCHA and returns the solution.
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
// Validate checks if the provided answer matches the solution.
func (a *AudioCaptcha) Validate(answer string) bool {
	return a.Solution == answer
}

// IsExpired returns true if the audio CAPTCHA has expired.
// IsExpired returns true if the CAPTCHA has expired.
func (a *AudioCaptcha) IsExpired() bool {
	return time.Now().After(a.ExpiresAt)
}

// BehavioralConfig holds configuration for behavioral analysis.
type BehavioralConfig struct {
	MouseMovements   bool
	Keystrokes       bool
	ScrollPatterns   bool
	TouchGestures    bool
	SessionDuration  int
	MinEvents        int
	MaxPauseMs       int
	PatternThreshold float64
}

// DefaultBehavioralConfig provides default settings for behavioral analysis.
var DefaultBehavioralConfig = BehavioralConfig{
	MouseMovements:   true,
	Keystrokes:       true,
	ScrollPatterns:   true,
	TouchGestures:    false,
	SessionDuration:  30,
	MinEvents:        10,
	MaxPauseMs:       500,
	PatternThreshold: 0.7,
}

// BehavioralEvent represents a single behavioral event.
type BehavioralEvent struct {
	Type        string
	Timestamp   int64
	X           float64
	Y           float64
	Duration    int64
	Key         string
	ScrollDelta float64
}

// BehavioralProfile holds behavioral analysis data for a session.
type BehavioralProfile struct {
	Events        []BehavioralEvent
	TotalDuration int64
	EventCount    int
	MouseSpeed    float64
	TypingSpeed   float64
	ScrollPattern string
	IsHuman       bool
	Confidence    float64
}

// NewBehavioralProfile creates a new behavioral profile for analysis.
func NewBehavioralProfile(_ *BehavioralConfig) *BehavioralProfile {
	return &BehavioralProfile{
		Events: make([]BehavioralEvent, 0),
	}
}

// AddEvent adds a behavioral event to the profile.
func (b *BehavioralProfile) AddEvent(event BehavioralEvent) {
	b.Events = append(b.Events, event)
	b.EventCount = len(b.Events)
	if len(b.Events) > 1 {
		b.TotalDuration = event.Timestamp - b.Events[0].Timestamp
	}
}

// Analyze evaluates the behavioral profile and returns a human-likeness score.
func (b *BehavioralProfile) Analyze() float64 {
	if len(b.Events) < 5 {
		b.IsHuman = false
		b.Confidence = 0.0
		return 0.0
	}

	var mouseMovements int
	var keystrokes int
	var scrolls int

	for _, e := range b.Events {
		switch e.Type {
		case "mousemove", "mousedown", "mouseup", "click":
			mouseMovements++
		case "keydown", "keyup", "keypress":
			keystrokes++
		case "scroll", "wheel":
			scrolls++
		}
	}

	humanScore := 0.0

	if mouseMovements > 0 {
		avgSpeed := calculateAvgMouseSpeed(b.Events)
		if avgSpeed > 50 && avgSpeed < 500 {
			humanScore += 0.3
		}
	}

	if keystrokes > 0 {
		typingRhythm := analyzeTypingRhythm(b.Events)
		if typingRhythm > 0.3 {
			humanScore += 0.3
		}
	}

	if scrolls > 0 {
		humanScore += 0.2
	}

	if b.TotalDuration > 5000 {
		humanScore += 0.2
	}

	b.IsHuman = humanScore >= 0.5
	b.Confidence = humanScore

	return humanScore
}

func calculateAvgMouseSpeed(events []BehavioralEvent) float64 {
	var totalSpeed float64
	var count int

	for i := 1; i < len(events); i++ {
		if events[i].Type == "mousemove" && events[i-1].Type == "mousemove" {
			dx := events[i].X - events[i-1].X
			dy := events[i].Y - events[i-1].Y
			dt := float64(events[i].Timestamp - events[i-1].Timestamp)
			if dt > 0 {
				distance := dx*dx + dy*dy
				speed := distance / dt
				totalSpeed += speed
				count++
			}
		}
	}

	if count == 0 {
		return 0
	}
	return totalSpeed / float64(count)
}

func analyzeTypingRhythm(events []BehavioralEvent) float64 {
	var keydowns []int64

	for _, e := range events {
		if e.Type == "keydown" {
			keydowns = append(keydowns, e.Timestamp)
		}
	}

	if len(keydowns) < 2 {
		return 0.0
	}

	var totalVariance float64
	for i := 1; i < len(keydowns); i++ {
		interval := keydowns[i] - keydowns[i-1]
		totalVariance += float64(interval)
	}

	avgInterval := totalVariance / float64(len(keydowns)-1)

	if avgInterval > 50 && avgInterval < 300 {
		return 0.6
	}

	return 0.3
}

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

// CaptchaService provides management for multiple CAPTCHA types.

type CaptchaService struct {
	TextStore     *CaptchaStore
	ReCaptchaV2   map[string]*ReCaptchaV2
	HCaptcha      map[string]*HCaptcha
	Turnstile     map[string]*TurnstileChallenge
	DistortedText map[string]*DistortedTextCaptcha
	Audio         map[string]*AudioCaptcha
	Behavioral    map[string]*BehavioralProfile
	Canvas        map[string]*CanvasFingerprint
}

// NewCaptchaService creates a new CAPTCHA service instance.
// NewCaptchaService creates a new CAPTCHA service instance.
func NewCaptchaService() *CaptchaService {
	return &CaptchaService{
		TextStore:     NewCaptchaStore(),
		ReCaptchaV2:   make(map[string]*ReCaptchaV2),
		HCaptcha:      make(map[string]*HCaptcha),
		Turnstile:     make(map[string]*TurnstileChallenge),
		DistortedText: make(map[string]*DistortedTextCaptcha),
		Audio:         make(map[string]*AudioCaptcha),
		Behavioral:    make(map[string]*BehavioralProfile),
		Canvas:        make(map[string]*CanvasFingerprint),
	}
}

// CreateTextCaptcha creates a new text CAPTCHA with the given configuration.
func (s *CaptchaService) CreateTextCaptcha(cfg *CaptchaConfig) (*Captcha, error) {
	gen := NewGenerator(cfg)
	captcha, err := gen.Generate(CaptchaTypeText)
	if err != nil {
		return nil, err
	}
	s.TextStore.Add(captcha)
	return captcha, nil
}

// CreateWebGL creates a new WebGL-based CAPTCHA.
func (s *CaptchaService) CreateWebGL(cfg *WebGLSceneConfig) (*WebGLCaptcha, error) {
	captcha := NewWebGLCaptcha(cfg)
	return captcha, nil
}

// CreateMathCaptcha creates a new math-based CAPTCHA.
func (s *CaptchaService) CreateMathCaptcha(cfg *CaptchaConfig) (*Captcha, error) {
	gen := NewGenerator(cfg)
	captcha, err := gen.Generate(CaptchaTypeMath)
	if err != nil {
		return nil, err
	}
	s.TextStore.Add(captcha)
	return captcha, nil
}

// CreateReCaptchaV2 creates a new reCAPTCHA v2 challenge.
// CreateReCaptchaV2 creates a new reCAPTCHA v2 challenge with the given target.
func (s *CaptchaService) CreateReCaptchaV2(target string, cfg *ReCaptchaV2Config) (*ReCaptchaV2, error) {
	captcha := NewReCaptchaV2(cfg)
	if err := captcha.Generate(target); err != nil {
		return nil, err
	}
	s.ReCaptchaV2[captcha.ID] = captcha
	return captcha, nil
}

// CreateHCaptcha creates a new hCaptcha challenge.
// CreateHCaptcha creates a new hCaptcha challenge with the given category.
func (s *CaptchaService) CreateHCaptcha(category string, numOptions int, cfg *HCaptchaConfig) (*HCaptcha, error) {
	captcha, err := NewHCaptcha(cfg, category)
	if err != nil {
		return nil, err
	}
	if err := captcha.Generate(numOptions); err != nil {
		return nil, err
	}
	s.HCaptcha[captcha.ID] = captcha
	return captcha, nil
}

// CreateTurnstile creates a new Turnstile challenge.
// CreateTurnstile creates a new Turnstile challenge with the given configuration.
func (s *CaptchaService) CreateTurnstile(cfg *TurnstileConfig) (*TurnstileChallenge, error) {
	challenge := NewTurnstile(cfg)
	if err := challenge.Generate(); err != nil {
		return nil, err
	}
	s.Turnstile[challenge.ID] = challenge
	return challenge, nil
}

// CreateDistortedText creates a new distorted text CAPTCHA.
// CreateDistortedText creates a new distorted text CAPTCHA with the given configuration.
func (s *CaptchaService) CreateDistortedText(cfg *DistortedTextConfig) (*DistortedTextCaptcha, error) {
	captcha := NewDistortedTextCaptcha(cfg)
	if _, err := captcha.Generate(); err != nil {
		return nil, err
	}
	s.DistortedText[captcha.ID] = captcha
	return captcha, nil
}

// CreateAudio creates a new audio CAPTCHA.
// CreateAudio creates a new audio CAPTCHA with the given configuration.
func (s *CaptchaService) CreateAudio(cfg *AudioConfig) (*AudioCaptcha, error) {
	captcha := NewAudioCaptcha(cfg)
	if _, err := captcha.Generate(); err != nil {
		return nil, err
	}
	s.Audio[captcha.ID] = captcha
	return captcha, nil
}

// CreateBehavioralProfile creates a new behavioral profile for session analysis.
// CreateBehavioralProfile creates a new behavioral profile for the given session ID.
func (s *CaptchaService) CreateBehavioralProfile(sessionID string, cfg *BehavioralConfig) *BehavioralProfile {
	profile := NewBehavioralProfile(cfg)
	s.Behavioral[sessionID] = profile
	return profile
}

// GetTextCaptcha retrieves a text CAPTCHA by ID.
// GetTextCaptcha retrieves a text CAPTCHA by its ID.
func (s *CaptchaService) GetTextCaptcha(id string) (*Captcha, bool) {
	return s.TextStore.Get(id)
}

// GetReCaptchaV2 retrieves a reCAPTCHA v2 challenge by ID.
// GetReCaptchaV2 retrieves a reCAPTCHA v2 challenge by its ID.
func (s *CaptchaService) GetReCaptchaV2(id string) (*ReCaptchaV2, bool) {
	c, ok := s.ReCaptchaV2[id]
	return c, ok
}

// GetHCaptcha retrieves an hCaptcha challenge by ID.
// GetHCaptcha retrieves an hCaptcha challenge by its ID.
func (s *CaptchaService) GetHCaptcha(id string) (*HCaptcha, bool) {
	c, ok := s.HCaptcha[id]
	return c, ok
}

// GetTurnstile retrieves a Turnstile challenge by ID.
// GetTurnstile retrieves a Turnstile challenge by its ID.
func (s *CaptchaService) GetTurnstile(id string) (*TurnstileChallenge, bool) {
	c, ok := s.Turnstile[id]
	return c, ok
}

// Cleanup removes expired CAPTCHAs and returns the count of removed items.
// Cleanup removes expired CAPTCHAs and returns the count of removed items.
func (s *CaptchaService) Cleanup() int {
	removed := 0

	for id, captcha := range s.TextStore.captchas {
		if time.Since(captcha.CreatedAt) > 5*time.Minute {
			s.TextStore.Remove(id)
			removed++
		}
	}

	for id, captcha := range s.ReCaptchaV2 {
		if captcha.IsExpired() {
			delete(s.ReCaptchaV2, id)
			removed++
		}
	}

	for id, captcha := range s.HCaptcha {
		if captcha.IsExpired() {
			delete(s.HCaptcha, id)
			removed++
		}
	}

	for id, challenge := range s.Turnstile {
		if challenge.IsExpired() {
			delete(s.Turnstile, id)
			removed++
		}
	}

	for id, captcha := range s.DistortedText {
		if captcha.IsExpired() {
			delete(s.DistortedText, id)
			removed++
		}
	}

	for id, captcha := range s.Audio {
		if captcha.IsExpired() {
			delete(s.Audio, id)
			removed++
		}
	}

	return removed
}

// WebGLSceneConfig holds configuration for WebGL-based CAPTCHA scenes.
type WebGLSceneConfig struct {
	SceneType       string
	ObjectCount     int
	RotationEnabled bool
	ZoomEnabled     bool
	PanEnabled      bool
	ObjectTypes     []string
	TargetObject    string
	InstructionText string
	TimeLimit       int
	Difficulty      string
}

// DefaultWebGLSceneConfig provides default settings for WebGL CAPTCHA scenes.
var DefaultWebGLSceneConfig = WebGLSceneConfig{
	SceneType:       "3d_objects",
	ObjectCount:     5,
	RotationEnabled: true,
	ZoomEnabled:     true,
	PanEnabled:      false,
	ObjectTypes:     []string{"cube", "sphere", "cone", "cylinder", "torus"},
	TargetObject:    "sphere",
	InstructionText: "Find and click the sphere",
	TimeLimit:       30,
	Difficulty:      "medium",
}

// WebGLSceneObject represents an object in a WebGL CAPTCHA scene.
type WebGLSceneObject struct {
	ID        string     `json:"id"`
	Type      string     `json:"type"`
	Position  [3]float64 `json:"position"`
	Rotation  [3]float64 `json:"rotation"`
	Scale     float64    `json:"scale"`
	Color     string     `json:"color"`
	IsTarget  bool       `json:"is_target"`
	Clickable bool       `json:"clickable"`
	Occluded  bool       `json:"occluded"`
}

// WebGLCaptcha represents a WebGL-based interactive CAPTCHA.
type WebGLCaptcha struct {
	ID          string             `json:"id"`
	Config      WebGLSceneConfig   `json:"config"`
	Scene       []WebGLSceneObject `json:"scene"`
	TargetID    string             `json:"target_id"`
	StartTime   time.Time          `json:"start_time"`
	ExpiresAt   time.Time          `json:"expires_at"`
	Solved      bool               `json:"solved"`
	ClickEvents []WebGLClickEvent  `json:"click_events"`
}

// WebGLClickEvent represents a click event in a WebGL CAPTCHA.
type WebGLClickEvent struct {
	Timestamp int64   `json:"timestamp"`
	ObjectID  string  `json:"object_id"`
	X         float64 `json:"x"`
	Y         float64 `json:"y"`
	IsCorrect bool    `json:"is_correct"`
	ElapsedMs int64   `json:"elapsed_ms"`
}

// NewWebGLCaptcha creates a new WebGL CAPTCHA instance.
func NewWebGLCaptcha(config *WebGLSceneConfig) *WebGLCaptcha {
	if config == nil {
		config = &DefaultWebGLSceneConfig
	}

	now := time.Now()
	captcha := &WebGLCaptcha{
		ID:          fmt.Sprintf("webgl_%d_%d", now.Unix(), now.Nanosecond()),
		Config:      *config,
		Scene:       make([]WebGLSceneObject, 0),
		StartTime:   now,
		ExpiresAt:   now.Add(2 * time.Minute),
		Solved:      false,
		ClickEvents: make([]WebGLClickEvent, 0),
	}

	captcha.generateScene()
	return captcha
}


func (w *WebGLCaptcha) generateScene() {
	objects := make([]WebGLSceneObject, w.Config.ObjectCount)
	targetIndex := webGLRand.Intn(w.Config.ObjectCount)

	colors := []string{"#FF5733", "#33FF57", "#3357FF", "#F333FF", "#FF33F3", "#33FFF3", "#F3FF33", "#FF8C33"}

	for i := range objects {
		isTarget := (i == targetIndex)
		objType := w.Config.ObjectTypes[webGLRand.Intn(len(w.Config.ObjectTypes))]

		if isTarget {
			objType = w.Config.TargetObject
		}

		objects[i] = WebGLSceneObject{
			ID:   fmt.Sprintf("obj_%d", i),
			Type: objType,
			Position: [3]float64{
				float64(webGLRand.Intn(400) - 200),
				float64(webGLRand.Intn(400) - 200),
				float64(webGLRand.Intn(400) - 200),
			},
			Rotation: [3]float64{
				float64(webGLRand.Intn(360)),
				float64(webGLRand.Intn(360)),
				float64(webGLRand.Intn(360)),
			},
			Scale:     0.5 + webGLRand.Float64()*1.5,
			Color:     colors[webGLRand.Intn(len(colors))],
			IsTarget:  isTarget,
			Clickable: true,
			Occluded:  webGLRand.Float64() > 0.7,
		}
	}

	w.Scene = objects
	w.TargetID = objects[targetIndex].ID
}

// RecordClick records a click event and returns true if the CAPTCHA is solved.
func (w *WebGLCaptcha) RecordClick(x, y float64) bool {
	elapsedMs := time.Since(w.StartTime).Milliseconds()

	event := WebGLClickEvent{
		Timestamp: time.Now().UnixMilli(),
		ObjectID:  "",
		X:         x,
		Y:         y,
		IsCorrect: false,
		ElapsedMs: elapsedMs,
	}

	for _, obj := range w.Scene {
		if obj.IsTarget && obj.Clickable && !obj.Occluded {
			event.ObjectID = obj.ID
			event.IsCorrect = true
			break
		}
	}

	w.ClickEvents = append(w.ClickEvents, event)

	if event.IsCorrect {
		w.Solved = true
	}

	return w.Solved
}

// IsExpired returns true if the WebGL CAPTCHA has expired.
func (w *WebGLCaptcha) IsExpired() bool {
	return time.Now().After(w.ExpiresAt)
}

// GetMetrics returns performance metrics for the WebGL CAPTCHA challenge.
func (w *WebGLCaptcha) GetMetrics() *WebGLChallengeMetrics {
	metrics := &WebGLChallengeMetrics{
		TotalClicks:   len(w.ClickEvents),
		CorrectClicks: 0,
		SolveTimeMs:   0,
	}

	if len(w.ClickEvents) > 0 {
		metrics.SolveTimeMs = w.ClickEvents[len(w.ClickEvents)-1].ElapsedMs
	}

	for _, e := range w.ClickEvents {
		if e.IsCorrect {
			metrics.CorrectClicks++
		}
	}

	return metrics
}

// WebGLChallengeMetrics holds performance metrics for WebGL CAPTCHA challenges.
type WebGLChallengeMetrics struct {
	TotalClicks   int
	CorrectClicks int
	SolveTimeMs   int64
}
