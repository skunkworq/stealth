package captcha

import "time"

// TurnstileConfig holds configuration for Cloudflare Turnstile challenges.
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
var DefaultTurnstileConfig = TurnstileConfig{
	SiteKey: "",
	Theme:   "auto",
	Action:  "",
}

// TurnstileChallenge represents a Cloudflare Turnstile challenge instance.
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
func (t *TurnstileChallenge) Generate() error {
	t.Token = generateToken()
	t.ChallengeTS = time.Now().Unix()
	return nil
}

// Validate checks if the provided token matches and is not expired.
func (t *TurnstileChallenge) Validate(token string) bool {
	return t.Token == token && !t.IsExpired()
}

// IsExpired returns true if the Turnstile challenge has expired.
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
