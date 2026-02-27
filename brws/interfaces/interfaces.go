// Package interfaces defines interfaces for mocking and testing.
package interfaces

import (
	"context"
)

// Engine is the browser engine interface.
type Engine interface {
	Name() string
	Do(ctx context.Context, url string) (int, []byte, error)
	Close() error
}

// ChallengeDetector detects challenges in responses.
type ChallengeDetector interface {
	Detect(body []byte) (bool, string)
}

// SessionManager manages browser sessions.
type SessionManager interface {
	Create(name string) (Session, error)
	Get(id string) (Session, error)
	List() []Session
	Delete(id string) error
}

// Session represents a browser session.
type Session interface {
	ID() string
	Name() string
}

// ChallengeSolver solves challenges.
type ChallengeSolver interface {
	SolveRecaptchaV2(ctx context.Context, siteKey, url string) (string, error)
	SolveRecaptchaV3(ctx context.Context, siteKey, url string, minScore float64) (string, error)
	SolveHCaptcha(ctx context.Context, siteKey, url string) (string, error)
	SolveTurnstile(ctx context.Context, siteKey, url string) (string, error)
	GetBalance(ctx context.Context) (float64, error)
}
