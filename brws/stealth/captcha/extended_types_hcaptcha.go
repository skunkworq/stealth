package captcha

import "time"

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

// IsExpired returns true if the challenge has expired.
func (h *HCaptcha) IsExpired() bool {
	return time.Now().After(h.ExpiresAt)
}
