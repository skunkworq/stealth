// Package http3 provides HTTP/3 client support.
package http3

import (
	"crypto/tls"
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stealth/brwslab/brws/constants"
)

// Client provides HTTP/3 client capabilities
type Client struct {
	tlsConfig  *tls.Config
	quicConfig *quic.Config
	timeout    time.Duration
}

// Config for HTTP/3 client
type Config struct {
	TLSConfig *tls.Config
	Timeout   time.Duration
}

// DefaultConfig returns default HTTP/3 configuration
func DefaultConfig() *Config {
	return &Config{
		Timeout: constants.DefaultTimeout,
	}
}

// New creates a new HTTP/3 client
func New(cfg *Config) (*Client, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	tlsConfig := cfg.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: false,
			NextProtos:         []string{"h3", "h3-29"},
		}
	}

	return &Client{
		tlsConfig: tlsConfig,
		quicConfig: &quic.Config{
			MaxIdleTimeout:        constants.DefaultTimeout,
			MaxIncomingStreams:    100,
			MaxIncomingUniStreams: 100,
		},
		timeout: cfg.Timeout,
	}, nil
}

// NewTransport creates an HTTP/3 RoundTripper
func NewTransport(cfg *Config) (http.RoundTripper, error) {
	client, err := New(cfg)
	if err != nil {
		return nil, err
	}

	// Return a basic transport that can be extended
	return &Transport{client: client}, nil
}

// Transport implements http.RoundTripper for HTTP/3
type Transport struct {
	client *Client
}

// RoundTrip implements http.RoundTripper
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// This is a placeholder - full HTTP/3 implementation requires
	// significant code from quic-go/http3 or similar library
	// For now, return an error suggesting to use the native HTTP/2 client
	// or browser-based engines which handle HTTP/3 natively
	return nil, &httpError{"HTTP/3 transport not fully implemented - use browser engine for HTTP/3"}
}

type httpError struct {
	msg string
}

func (e *httpError) Error() string {
	return e.msg
}

// NewHTTP3Client creates an http.Client using HTTP/3
func NewHTTP3Client(cfg *Config) (*http.Client, error) {
	transport, err := NewTransport(cfg)
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
	}, nil
}
