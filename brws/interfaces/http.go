// Package interfaces defines interfaces for mocking and testing.
package interfaces

import (
	"net/http"
)

// HTTPClient is an interface for HTTP clients.
type HTTPClient interface {
	// Do sends an HTTP request and returns an HTTP response
	Do(req *http.Request) (*http.Response, error)
}

// HTTPClientFactory creates HTTP clients with specific configurations.
type HTTPClientFactory interface {
	// NewClient creates a new HTTP client
	NewClient() HTTPClient

	// NewClientWithTimeout creates a new HTTP client with a specific timeout
	NewClientWithTimeout(timeoutMs int) HTTPClient

	// NewClientWithProxy creates a new HTTP client with a proxy
	NewClientWithProxy(proxyURL string) (HTTPClient, error)
}

// RequestBuilder builds HTTP requests.
type RequestBuilder interface {
	// Build builds an HTTP request
	Build() (*http.Request, error)

	// WithHeader adds a header to the request
	WithHeader(key, value string) RequestBuilder

	// WithBody sets the request body
	WithBody(body []byte) RequestBuilder

	// WithMethod sets the HTTP method
	WithMethod(method string) RequestBuilder
}

// ResponseHandler handles HTTP responses.
type ResponseHandler interface {
	// Handle handles an HTTP response
	Handle(resp *http.Response) error

	// CanHandle returns true if this handler can handle the response
	CanHandle(resp *http.Response) bool
}
