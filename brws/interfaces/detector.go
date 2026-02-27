// Package interfaces defines interfaces for mocking and testing.
package interfaces

import (
	"net/http"
)

// DetectionVector represents a single detection vector result.
type DetectionVector struct {
	Name        string
	Category    string
	Score       float64
	Weight      float64
	Description string
	Passed      bool
}

// DetectionResult represents the result of a detection analysis.
type DetectionResult struct {
	Score      float64
	IsBot      bool
	Confidence float64
	Vectors    []DetectionVector
}

// Detector is the interface for bot/stealth detection.
type Detector interface {
	// Analyze analyzes an HTTP request and returns detection results
	Analyze(req *http.Request) (*DetectionResult, error)

	// AnalyzeHeaders analyzes HTTP headers for bot indicators
	AnalyzeHeaders(headers http.Header) (*DetectionResult, error)

	// Name returns the detector name
	Name() string
}

// VectorExtractor extracts detection vectors from requests.
type VectorExtractor interface {
	// Extract extracts a detection vector from an HTTP request
	Extract(req *http.Request) (*DetectionVector, error)

	// Name returns the extractor name
	Name() string

	// Category returns the vector category (e.g., "tls", "http", "navigator")
	Category() string
}

// ScoreCalculator calculates final scores from detection vectors.
type ScoreCalculator interface {
	// Calculate calculates the final score from detection vectors
	Calculate(vectors []DetectionVector) (*DetectionResult, error)

	// Thresholds returns the bot and suspicious thresholds
	Thresholds() (botThreshold, suspiciousThreshold float64)
}

// HeaderExtractor extracts typed data from HTTP headers.
type HeaderExtractor interface {
	// Extract retrieves and parses data from a specific header
	Extract(req *http.Request) (map[string]interface{}, error)

	// HeaderName returns the header name this extractor handles
	HeaderName() string
}

// TLSAnalyzer analyzes TLS fingerprints.
type TLSAnalyzer interface {
	// AnalyzeJA3 analyzes a JA3 fingerprint string
	AnalyzeJA3(ja3 string) (*DetectionVector, error)

	// AnalyzeJA4 analyzes a JA4 fingerprint string
	AnalyzeJA4(ja4 string) (*DetectionVector, error)

	// AnalyzeTLSVersion analyzes the TLS version
	AnalyzeTLSVersion(version uint16) (*DetectionVector, error)
}

// BrowserClassifier classifies browsers from User-Agent and other signals.
type BrowserClassifier interface {
	// Classify classifies the browser from an HTTP request
	Classify(req *http.Request) (*BrowserInfo, error)

	// ClassifyFromUA classifies the browser from User-Agent string only
	ClassifyFromUA(userAgent string) *BrowserInfo
}

// BrowserInfo holds browser classification information.
type BrowserInfo struct {
	Type           string
	Version        string
	Platform       string
	Mobile         bool
	Engine         string
	IsAutomated    bool
	Confidence     float64
}

// RequestIDExtractor extracts request IDs for tracing.
type RequestIDExtractor interface {
	// Extract extracts or generates a request ID from a request
	Extract(req *http.Request) string
}
