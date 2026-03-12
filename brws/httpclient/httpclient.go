// Package httpclient provides centralized HTTP client creation with sensible defaults.
package httpclient

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/skunkworq/stealth/brws/constants"
)

// Config holds configuration for creating an HTTP client.
type Config struct {
	Timeout           time.Duration
	KeepAlive         time.Duration
	MaxIdleConns      int
	IdleConnTimeout   time.Duration
	DisableKeepAlives bool
}

// DefaultConfig returns the default HTTP client configuration.
func DefaultConfig() *Config {
	return &Config{
		Timeout:           constants.DefaultTimeout,
		KeepAlive:         constants.KeepAliveTimeout,
		MaxIdleConns:      100,
		IdleConnTimeout:   90 * time.Second,
		DisableKeepAlives: false,
	}
}

// ShortTimeoutConfig returns a configuration with shorter timeouts.
func ShortTimeoutConfig() *Config {
	return &Config{
		Timeout:           constants.ShortTimeout,
		KeepAlive:         constants.KeepAliveTimeout,
		MaxIdleConns:      100,
		IdleConnTimeout:   90 * time.Second,
		DisableKeepAlives: false,
	}
}

// New creates a new HTTP client with the provided configuration.
func New(config *Config) *http.Client {
	if config == nil {
		config = DefaultConfig()
	}

	return &http.Client{
		Timeout: config.Timeout,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   config.Timeout,
				KeepAlive: config.KeepAlive,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          config.MaxIdleConns,
			IdleConnTimeout:       config.IdleConnTimeout,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			DisableKeepAlives:     config.DisableKeepAlives,
		},
	}
}

// NewWithProxy creates a new HTTP client that uses the specified proxy function.
func NewWithProxy(proxyFunc func(*http.Request) (*url.URL, error), config *Config) *http.Client {
	if config == nil {
		config = DefaultConfig()
	}

	return &http.Client{
		Timeout: config.Timeout,
		Transport: &http.Transport{
			Proxy: proxyFunc,
			DialContext: (&net.Dialer{
				Timeout:   config.Timeout,
				KeepAlive: config.KeepAlive,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          config.MaxIdleConns,
			IdleConnTimeout:       config.IdleConnTimeout,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

// NewWithDialer creates a new HTTP client with a custom dialer.
func NewWithDialer(dialer *net.Dialer, config *Config) *http.Client {
	if config == nil {
		config = DefaultConfig()
	}

	return &http.Client{
		Timeout: config.Timeout,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, addr)
			},
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          config.MaxIdleConns,
			IdleConnTimeout:       config.IdleConnTimeout,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

// DefaultClient returns a new HTTP client with default settings.
func DefaultClient() *http.Client {
	return New(DefaultConfig())
}

// ShortTimeoutClient returns a new HTTP client with short timeout.
func ShortTimeoutClient() *http.Client {
	return New(ShortTimeoutConfig())
}
