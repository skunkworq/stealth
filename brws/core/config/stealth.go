// Package config provides comprehensive configuration for the stealth crawler.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the main configuration for the stealth crawler.
type Config struct {
	// Engine configuration
	Engine EngineConfig `json:"engine"`

	// Request configuration
	Request RequestConfig `json:"request"`

	// Retry configuration
	Retry RetryConfig `json:"retry"`

	// Session configuration
	Session SessionConfig `json:"session"`

	// Rate limiting configuration
	RateLimit RateLimitConfig `json:"rate_limit"`

	// Cloudflare configuration
	Cloudflare CloudflareConfig `json:"cloudflare"`

	// Semantic extraction configuration
	Semantic SemanticConfig `json:"semantic"`

	// Monitoring configuration
	Monitoring MonitoringConfig `json:"monitoring"`
}

// EngineConfig configures the browser/engine settings.
type EngineConfig struct {
	// Engine to use: native, chromium, chromium-stealth
	Name string `json:"name"`

	// Use TLS fingerprint spoofing
	StealthTLS bool `json:"stealth_tls"`

	// Use header spoofing
	Stealth bool `json:"stealth"`

	// Browser profile name (e.g., chrome-120-macos)
	Profile string `json:"profile"`

	// Chrome executable path (for chromium engines)
	ChromePath string `json:"chrome_path,omitempty"`

	// Run in headless mode
	Headless bool `json:"headless"`

	// Proxy URL
	Proxy string `json:"proxy,omitempty"`

	// Use IPv6
	IPv6 bool `json:"ipv6"`

	// Use HTTP/2
	HTTP2 bool `json:"http2"`

	// Use HTTP/3
	HTTP3 bool `json:"http3"`
}

// RequestConfig configures individual requests.
type RequestConfig struct {
	// Request timeout
	Timeout time.Duration `json:"timeout"`

	// Wait for navigation
	WaitForNavigation bool `json:"wait_for_navigation"`

	// Wait for selector
	WaitForSelector string `json:"wait_for_selector,omitempty"`

	// Follow redirects
	FollowRedirects bool `json:"follow_redirects"`

	// Max redirects
	MaxRedirects int `json:"max_redirects"`
}

// RetryConfig configures retry behavior.
type RetryConfig struct {
	// Enable retries
	Enabled bool `json:"enabled"`

	// Maximum retries
	MaxRetries int `json:"max_retries"`

	// Initial delay
	InitialDelay time.Duration `json:"initial_delay"`

	// Maximum delay
	MaxDelay time.Duration `json:"max_delay"`

	// Backoff multiplier
	BackoffMultiplier float64 `json:"backoff_multiplier"`

	// Retry on status codes
	RetryOnStatus []int `json:"retry_on_status,omitempty"`
}

// SessionConfig configures session/cookie management.
type SessionConfig struct {
	// Enable session persistence
	Enabled bool `json:"enabled"`

	// ProfileDir is the directory for session storage.
	ProfileDir string `json:"profile_dir,omitempty"`

	// SessionName is an optional human-readable label for this session.
	SessionName string `json:"session_name,omitempty"`

	// Save cookies
	SaveCookies bool `json:"save_cookies"`

	// Load cookies
	LoadCookies bool `json:"load_cookies"`

	// Session lifetime
	Lifetime time.Duration `json:"lifetime"`
}

// RateLimitConfig configures rate limiting.
type RateLimitConfig struct {
	// Enable rate limiting
	Enabled bool `json:"enabled"`

	// Requests per second
	RequestsPerSecond float64 `json:"requests_per_second"`

	// Delay between requests
	Delay time.Duration `json:"delay"`

	// Respect robots.txt
	RespectRobotsTxt bool `json:"respect_robots_txt"`

	// Maximum concurrent requests
	MaxConcurrent int `json:"max_concurrent"`
}

// CloudflareConfig configures Cloudflare bypass behavior.
type CloudflareConfig struct {
	// Enable Cloudflare detection
	Detect bool `json:"detect"`

	// Enable automatic solving
	Solve bool `json:"solve"`

	// Wait time for challenge
	WaitTime time.Duration `json:"wait_time"`

	// Maximum solve attempts
	MaxAttempts int `json:"max_attempts"`

	// Use external solver (e.g., 2Captcha)
	ExternalSolver ExternalSolverConfig `json:"external_solver,omitempty"`
}

// ExternalSolverConfig configures external CAPTCHA solver.
type ExternalSolverConfig struct {
	// Enable external solver
	Enabled bool `json:"enabled"`

	// Solver type: 2captcha, anticaptcha
	Type string `json:"type"`

	// API key
	APIKey string `json:"api_key,omitempty"`

	// API URL
	APIURL string `json:"api_url,omitempty"`
}

// SemanticConfig configures semantic extraction.
type SemanticConfig struct {
	// Enable semantic extraction
	Enabled bool `json:"enabled"`

	// Maximum chunks
	MaxChunks int `json:"max_chunks"`

	// Maximum concurrent LLM calls
	MaxConcurrentLLM int `json:"max_concurrent_llm"`

	// LLM API URL
	LLMURL string `json:"llm_url,omitempty"`

	// LLM API key
	LLMAPIKey string `json:"llm_api_key,omitempty"`

	// Use cache
	UseCache bool `json:"use_cache"`
}

// MonitoringConfig configures monitoring and metrics.
type MonitoringConfig struct {
	// Enable metrics
	Metrics bool `json:"metrics"`

	// Metrics port
	MetricsPort int `json:"metrics_port"`

	// Enable tracing
	Tracing bool `json:"tracing"`

	// Tracing endpoint
	TracingEndpoint string `json:"tracing_endpoint,omitempty"`

	// Log level
	LogLevel string `json:"log_level"`
}

// DefaultStealthConfig returns a default stealth configuration.
// It is an alias for DefaultConfig provided for API consistency with
// the getting-started documentation.
func DefaultStealthConfig() *Config {
	return DefaultConfig()
}

// DefaultConfig returns a default configuration.
func DefaultConfig() *Config {
	return &Config{
		Engine: EngineConfig{
			Name:       "native",
			StealthTLS: true,
			Stealth:    true,
			Profile:    "chrome-120-macos",
			Headless:   true,
			HTTP2:      true,
		},
		Request: RequestConfig{
			Timeout:           30 * time.Second,
			WaitForNavigation: true,
			FollowRedirects:   true,
			MaxRedirects:      10,
		},
		Retry: RetryConfig{
			Enabled:           true,
			MaxRetries:        3,
			InitialDelay:      time.Second,
			MaxDelay:          30 * time.Second,
			BackoffMultiplier: 2.0,
			RetryOnStatus:     []int{429, 500, 502, 503, 504},
		},
		Session: SessionConfig{
			Enabled:     false,
			SaveCookies: true,
			LoadCookies: true,
			Lifetime:    24 * time.Hour,
		},
		RateLimit: RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 5.0,
			Delay:             200 * time.Millisecond,
			RespectRobotsTxt:  true,
			MaxConcurrent:     10,
		},
		Cloudflare: CloudflareConfig{
			Detect:      true,
			Solve:       false,
			WaitTime:    5 * time.Second,
			MaxAttempts: 3,
		},
		Semantic: SemanticConfig{
			Enabled:          true,
			MaxChunks:        50,
			MaxConcurrentLLM: 0,
			UseCache:         true,
		},
		Monitoring: MonitoringConfig{
			Metrics:     true,
			MetricsPort: 9090,
			Tracing:     false,
			LogLevel:    "info",
		},
	}
}

// LoadFromFile loads configuration from a YAML file.
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}
	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}
	return cfg, nil
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	if c.Engine.Name == "" {
		c.Engine.Name = "native"
	}

	if c.Retry.MaxRetries < 0 {
		return fmt.Errorf("max_retries must be >= 0")
	}

	if c.RateLimit.RequestsPerSecond <= 0 {
		return fmt.Errorf("requests_per_second must be > 0")
	}

	if c.RateLimit.MaxConcurrent <= 0 {
		return fmt.Errorf("max_concurrent must be > 0")
	}

	return nil
}
