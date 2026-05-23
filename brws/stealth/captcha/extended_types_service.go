package captcha

import "time"

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

// CreateReCaptchaV2 creates a new reCAPTCHA v2 challenge with the given target.
func (s *CaptchaService) CreateReCaptchaV2(target string, cfg *ReCaptchaV2Config) (*ReCaptchaV2, error) {
	captcha := NewReCaptchaV2(cfg)
	if err := captcha.Generate(target); err != nil {
		return nil, err
	}
	s.ReCaptchaV2[captcha.ID] = captcha
	return captcha, nil
}

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

// CreateTurnstile creates a new Turnstile challenge with the given configuration.
func (s *CaptchaService) CreateTurnstile(cfg *TurnstileConfig) (*TurnstileChallenge, error) {
	challenge := NewTurnstile(cfg)
	if err := challenge.Generate(); err != nil {
		return nil, err
	}
	s.Turnstile[challenge.ID] = challenge
	return challenge, nil
}

// CreateDistortedText creates a new distorted text CAPTCHA with the given configuration.
func (s *CaptchaService) CreateDistortedText(cfg *DistortedTextConfig) (*DistortedTextCaptcha, error) {
	captcha := NewDistortedTextCaptcha(cfg)
	if _, err := captcha.Generate(); err != nil {
		return nil, err
	}
	s.DistortedText[captcha.ID] = captcha
	return captcha, nil
}

// CreateAudio creates a new audio CAPTCHA with the given configuration.
func (s *CaptchaService) CreateAudio(cfg *AudioConfig) (*AudioCaptcha, error) {
	captcha := NewAudioCaptcha(cfg)
	if _, err := captcha.Generate(); err != nil {
		return nil, err
	}
	s.Audio[captcha.ID] = captcha
	return captcha, nil
}

// CreateBehavioralProfile creates a new behavioral profile for the given session ID.
func (s *CaptchaService) CreateBehavioralProfile(sessionID string, cfg *BehaviorSimConfig) *BehavioralProfile {
	profile := NewBehavioralProfile(cfg)
	s.Behavioral[sessionID] = profile
	return profile
}

// GetTextCaptcha retrieves a text CAPTCHA by its ID.
func (s *CaptchaService) GetTextCaptcha(id string) (*Captcha, bool) {
	return s.TextStore.Get(id)
}

// GetReCaptchaV2 retrieves a reCAPTCHA v2 challenge by its ID.
func (s *CaptchaService) GetReCaptchaV2(id string) (*ReCaptchaV2, bool) {
	c, ok := s.ReCaptchaV2[id]
	return c, ok
}

// GetHCaptcha retrieves an hCaptcha challenge by its ID.
func (s *CaptchaService) GetHCaptcha(id string) (*HCaptcha, bool) {
	c, ok := s.HCaptcha[id]
	return c, ok
}

// GetTurnstile retrieves a Turnstile challenge by its ID.
func (s *CaptchaService) GetTurnstile(id string) (*TurnstileChallenge, bool) {
	c, ok := s.Turnstile[id]
	return c, ok
}

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
