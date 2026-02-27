// Package extractors provides utilities for extracting data from HTTP headers.
package extractors

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// JSONExtractor extracts and parses JSON data from HTTP headers.
type JSONExtractor struct {
	// HeaderName is the name of the header to extract from
	HeaderName string
}

// NewJSONExtractor creates a new JSON extractor for the specified header.
func NewJSONExtractor(headerName string) *JSONExtractor {
	return &JSONExtractor{HeaderName: headerName}
}

// Extract retrieves and parses JSON data from the request header.
// Returns nil if the header is not present or cannot be parsed.
func (e *JSONExtractor) Extract(req *http.Request) (map[string]interface{}, error) {
	headerValue := req.Header.Get(e.HeaderName)
	if headerValue == "" {
		return nil, fmt.Errorf("header %s not found", e.HeaderName)
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(headerValue), &data); err != nil {
		return nil, fmt.Errorf("parsing header %s: %w", e.HeaderName, err)
	}

	return data, nil
}

// ExtractSafe retrieves and parses JSON data, returning nil on any error.
func (e *JSONExtractor) ExtractSafe(req *http.Request) map[string]interface{} {
	data, _ := e.Extract(req)
	return data
}

// ExtractString retrieves a string value from the extracted data.
func (e *JSONExtractor) ExtractString(req *http.Request, key string) (string, bool) {
	data, err := e.Extract(req)
	if err != nil {
		return "", false
	}

	value, ok := data[key].(string)

	return value, ok
}

// ExtractBool retrieves a boolean value from the extracted data.
func (e *JSONExtractor) ExtractBool(req *http.Request, key string) (bool, bool) {
	data, err := e.Extract(req)
	if err != nil {
		return false, false
	}

	value, ok := data[key].(bool)

	return value, ok
}

// ExtractFloat retrieves a float64 value from the extracted data.
func (e *JSONExtractor) ExtractFloat(req *http.Request, key string) (float64, bool) {
	data, err := e.Extract(req)
	if err != nil {
		return 0, false
	}

	// Handle both float64 and json.Number
	switch v := data[key].(type) {
	case float64:
		return v, true
	case json.Number:
		f, err := v.Float64()
		return f, err == nil
	default:
		return 0, false
	}
}

// HasKey checks if a key exists in the extracted data.
func (e *JSONExtractor) HasKey(req *http.Request, key string) bool {
	data, err := e.Extract(req)
	if err != nil {
		return false
	}

	_, exists := data[key]

	return exists
}

// MultiExtractor extracts data from multiple headers at once.
type MultiExtractor struct {
	extractors map[string]*JSONExtractor
}

// NewMultiExtractor creates a new multi-header extractor.
func NewMultiExtractor() *MultiExtractor {
	return &MultiExtractor{
		extractors: make(map[string]*JSONExtractor),
	}
}

// Add adds a header extractor to the multi-extractor.
func (m *MultiExtractor) Add(headerName string) *MultiExtractor {
	m.extractors[headerName] = NewJSONExtractor(headerName)
	return m
}

// ExtractAll extracts data from all registered headers.
// Returns a map of header names to extracted data.
func (m *MultiExtractor) ExtractAll(req *http.Request) map[string]map[string]interface{} {
	results := make(map[string]map[string]interface{})

	for headerName, extractor := range m.extractors {
		if data, err := extractor.Extract(req); err == nil {
			results[headerName] = data
		}
	}

	return results
}
