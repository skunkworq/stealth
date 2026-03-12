// Package session provides cookie jar, cache abstraction, and profile management
// for persistent browser sessions.
package session

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/net/publicsuffix"
)

// sanitizePath validates and cleans a file path to prevent directory traversal
func sanitizePath(path string) (string, error) {
	cleanPath := filepath.Clean(path)
	if strings.Contains(cleanPath, "..") {
		return "", fmt.Errorf("invalid path contains directory traversal: %s", path)
	}
	return cleanPath, nil
}

// Session represents a persistent session with cookie jar and optional cache.
type Session struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Engine     string            `json:"engine"`
	ProfileDir string            `json:"profile_dir"`
	CreatedAt  time.Time         `json:"created_at"`
	LastUsedAt time.Time         `json:"last_used_at"`
	Metadata   map[string]string `json:"metadata,omitempty"`

	// Runtime fields (not serialized)
	cookieJar   http.CookieJar
	cookiesFile string
	mu          sync.RWMutex
}

// Manager handles session lifecycle and persistence.
type Manager struct {
	sessionsDir string
	sessions    map[string]*Session
	mu          sync.RWMutex
}

// NewManager creates a new session manager.
func NewManager(sessionsDir string) (*Manager, error) {
	if err := os.MkdirAll(sessionsDir, 0o750); err != nil {
		return nil, fmt.Errorf("creating sessions dir: %w", err)
	}

	m := &Manager{
		sessionsDir: sessionsDir,
		sessions:    make(map[string]*Session),
	}

	// Load existing sessions
	if err := m.loadSessions(); err != nil {
		return nil, fmt.Errorf("loading sessions: %w", err)
	}

	return m, nil
}

// Create creates a new session.
func (m *Manager) Create(name, engine string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	sessionID := uuid.New().String()
	profileDir := filepath.Join(m.sessionsDir, sessionID, "profile")

	if err := os.MkdirAll(profileDir, 0o750); err != nil {
		return nil, fmt.Errorf("creating profile dir: %w", err)
	}

	// Create cookie jar
	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	if err != nil {
		return nil, fmt.Errorf("creating cookie jar: %w", err)
	}

	session := &Session{
		ID:          sessionID,
		Name:        name,
		Engine:      engine,
		ProfileDir:  profileDir,
		CreatedAt:   time.Now(),
		LastUsedAt:  time.Now(),
		Metadata:    make(map[string]string),
		cookieJar:   jar,
		cookiesFile: filepath.Join(m.sessionsDir, sessionID, "cookies.json"),
	}

	m.sessions[sessionID] = session

	if err := m.saveSession(session); err != nil {
		return nil, fmt.Errorf("saving session: %w", err)
	}

	return session, nil
}

// Get retrieves a session by ID.
func (m *Manager) Get(id string) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, ok := m.sessions[id]
	if !ok {
		return nil, fmt.Errorf("session not found: %s", id)
	}

	return session, nil
}

// List returns all sessions.
func (m *Manager) List() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sessions := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	return sessions
}

// Delete removes a session and its data.
func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, ok := m.sessions[id]
	if !ok {
		return fmt.Errorf("session not found: %s", id)
	}

	// Remove profile directory
	sessionDir := filepath.Join(m.sessionsDir, id)
	if err := os.RemoveAll(sessionDir); err != nil {
		return fmt.Errorf("removing session dir: %w", err)
	}

	delete(m.sessions, id)
	return nil
}

// CookieJar returns the session's cookie jar.
func (s *Session) CookieJar() http.CookieJar {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cookieJar
}

// SetCookies sets cookies for a URL.
func (s *Session) SetCookies(u *url.URL, cookies []*http.Cookie) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cookieJar.SetCookies(u, cookies)
}

// Cookies gets cookies for a URL.
func (s *Session) Cookies(u *url.URL) []*http.Cookie {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cookieJar.Cookies(u)
}

// ExportCookies exports all cookies to a JSON file.
func (s *Session) ExportCookies(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// This is a simplified export - a full implementation would iterate
	// through all known domains in the jar
	cookies := s.exportCookieData()

	data, err := json.MarshalIndent(cookies, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling cookies: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing cookies file: %w", err)
	}

	return nil
}

// ImportCookies imports cookies from a JSON file.
func (s *Session) ImportCookies(path string) error {
	safePath, err := sanitizePath(path)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Clean(safePath))
	if err != nil {
		return fmt.Errorf("reading cookies file: %w", err)
	}

	var cookies []CookieData
	if err := json.Unmarshal(data, &cookies); err != nil {
		return fmt.Errorf("unmarshaling cookies: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, c := range cookies {
		u, err := url.Parse(c.Domain)
		if err != nil {
			continue
		}
		s.cookieJar.SetCookies(u, []*http.Cookie{c.ToHTTP()})
	}

	return nil
}

// CookieData represents a serializable cookie.
type CookieData struct {
	Name     string    `json:"name"`
	Value    string    `json:"value"`
	Domain   string    `json:"domain"`
	Path     string    `json:"path"`
	Expires  time.Time `json:"expires"`
	Secure   bool      `json:"secure"`
	HTTPOnly bool      `json:"http_only"`
	SameSite string    `json:"same_site"`
}

// ToHTTP converts to http.Cookie.
func (c *CookieData) ToHTTP() *http.Cookie {
	return &http.Cookie{
		Name:     c.Name,
		Value:    c.Value,
		Domain:   c.Domain,
		Path:     c.Path,
		Expires:  c.Expires,
		Secure:   c.Secure,
		HttpOnly: c.HTTPOnly,
		SameSite: parseSameSite(c.SameSite),
	}
}

func parseSameSite(s string) http.SameSite {
	switch s {
	case "Strict":
		return http.SameSiteStrictMode
	case "Lax":
		return http.SameSiteLaxMode
	case "None":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteDefaultMode
	}
}

// exportCookieData is a placeholder that would iterate the jar in a real implementation.
func (s *Session) exportCookieData() []CookieData {
	// Full implementation would require access to cookiejar internals
	// For now, return empty
	return []CookieData{}
}

func (m *Manager) loadSessions() error {
	entries, err := os.ReadDir(m.sessionsDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		sessionFile := filepath.Join(m.sessionsDir, entry.Name(), "session.json")
		safePath, err := sanitizePath(sessionFile)
		if err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Clean(safePath))
		if err != nil {
			continue
		}

		var session Session
		if err := json.Unmarshal(data, &session); err != nil {
			continue
		}

		// Create cookie jar
		jar, err := cookiejar.New(&cookiejar.Options{
			PublicSuffixList: publicsuffix.List,
		})
		if err != nil {
			continue
		}
		session.cookieJar = jar
		session.cookiesFile = filepath.Join(m.sessionsDir, session.ID, "cookies.json")

		m.sessions[session.ID] = &session
	}

	return nil
}

func (m *Manager) saveSession(s *Session) error {
	sessionFile := filepath.Join(m.sessionsDir, s.ID, "session.json")

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(sessionFile, data, 0o600)
}

// UpdateLastUsed updates the LastUsedAt timestamp.
func (s *Session) UpdateLastUsed() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastUsedAt = time.Now()
}

// DomainStats tracks request statistics for a domain
type DomainStats struct {
	Domain        string    `json:"domain"`
	SuccessCount  int       `json:"success_count"`
	FailureCount  int       `json:"failure_count"`
	LastSuccess   time.Time `json:"last_success"`
	LastFailure   time.Time `json:"last_failure"`
	AvgResponseMs int64     `json:"avg_response_ms"`
}

// GetDomainStats retrieves statistics for a specific domain
func (s *Session) GetDomainStats(domain string) *DomainStats {
	s.mu.Lock()
	defer s.mu.Unlock()

	stats, ok := s.Metadata[domain]
	if !ok {
		return nil
	}

	var ds DomainStats
	if err := json.Unmarshal([]byte(stats), &ds); err != nil {
		return nil
	}
	return &ds
}

// RecordSuccess records a successful request to a domain
func (s *Session) RecordSuccess(domain string, responseMs int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	stats := DomainStats{
		Domain:        domain,
		SuccessCount:  1,
		LastSuccess:   time.Now(),
		AvgResponseMs: responseMs,
	}

	if existing, ok := s.Metadata[domain]; ok {
		var ds DomainStats
		if err := json.Unmarshal([]byte(existing), &ds); err == nil {
			_ = ds.SuccessCount + ds.FailureCount
			stats.SuccessCount = ds.SuccessCount + 1
			stats.AvgResponseMs = (ds.AvgResponseMs*int64(ds.SuccessCount) + responseMs) / int64(stats.SuccessCount)
			stats.FailureCount = ds.FailureCount
			stats.LastFailure = ds.LastFailure
		}
	}

	data, err := json.Marshal(stats)
	if err != nil {
		return
	}
	s.Metadata[domain] = string(data)
}

// RecordFailure records a failure for the given domain.
func (s *Session) RecordFailure(domain string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	stats := DomainStats{
		Domain:       domain,
		FailureCount: 1,
		LastFailure:  time.Now(),
	}

	if existing, ok := s.Metadata[domain]; ok {
		var ds DomainStats
		if err := json.Unmarshal([]byte(existing), &ds); err == nil {
			stats.SuccessCount = ds.SuccessCount
			stats.FailureCount = ds.FailureCount + 1
			stats.LastSuccess = ds.LastSuccess
			stats.AvgResponseMs = ds.AvgResponseMs
		}
	}

	data, err := json.Marshal(stats)
	if err != nil {
		return
	}
	s.Metadata[domain] = string(data)
}

// GetTrustScore returns the trust score for the given domain.
func (s *Session) GetTrustScore(domain string) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	stats, ok := s.Metadata[domain]
	if !ok {
		return 1.0
	}

	var ds DomainStats
	if err := json.Unmarshal([]byte(stats), &ds); err != nil {
		return 1.0
	}

	total := ds.SuccessCount + ds.FailureCount
	if total == 0 {
		return 1.0
	}

	successRate := float64(ds.SuccessCount) / float64(total)
	freshness := 1.0

	if !ds.LastSuccess.IsZero() {
		age := time.Since(ds.LastSuccess)
		if age < 5*time.Minute {
			freshness = 1.0
		} else if age < 30*time.Minute {
			freshness = 0.9
		} else if age < 2*time.Hour {
			freshness = 0.7
		} else {
			freshness = 0.5
		}
	}

	return successRate * freshness
}

// ShouldRetry determines if a request to the given domain should be retried.
func (s *Session) ShouldRetry(domain string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	stats, ok := s.Metadata[domain]
	if !ok {
		return true
	}

	var ds DomainStats
	if err := json.Unmarshal([]byte(stats), &ds); err != nil {
		return true
	}

	return ds.FailureCount < 3
}

// RetryConfig configures retry behavior for failed requests.
type RetryConfig struct {
	MaxRetries    int
	InitialDelay  time.Duration
	MaxDelay      time.Duration
	BackoffFactor float64
}

// NewRetryConfig creates a new RetryConfig with default values.
func NewRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxRetries:    3,
		InitialDelay:  1 * time.Second,
		MaxDelay:      30 * time.Second,
		BackoffFactor: 2.0,
	}
}

// ExecuteWithRetry executes the given function with retry logic.
func ExecuteWithRetry(ctx context.Context, fn func() error, config *RetryConfig) error {
	var lastErr error
	delay := config.InitialDelay

	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
			delay = time.Duration(float64(delay) * config.BackoffFactor)
			if delay > config.MaxDelay {
				delay = config.MaxDelay
			}
		}

		lastErr = fn()
		if lastErr == nil {
			return nil
		}
	}

	return fmt.Errorf("max retries exceeded: %w", lastErr)
}
