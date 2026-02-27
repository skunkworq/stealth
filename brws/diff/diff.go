// Package diff provides semantic and protocol diffs between HTTP responses
// and network traces from different engines.
package diff

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/stealth/brwslab/brws/engine"
)

// EngineResult holds the result from one engine.
type EngineResult struct {
	EngineName string
	Response   *engine.Response
	Trace      *engine.Trace
	Error      error
}

// Comparison holds the diff between multiple engine results.
type Comparison struct {
	Engines      []string               `json:"engines"`
	URL          string                 `json:"url"`
	StatusDiff   *StatusDiff            `json:"status_diff,omitempty"`
	HeaderDiffs  map[string]*HeaderDiff `json:"header_diffs,omitempty"`
	BodyDiff     *BodyDiff              `json:"body_diff,omitempty"`
	ProtocolDiff *ProtocolDiff          `json:"protocol_diff,omitempty"`
	TimingDiff   *TimingDiff            `json:"timing_diff,omitempty"`
	RedirectDiff *RedirectDiff          `json:"redirect_diff,omitempty"`
	Summary      string                 `json:"summary"`
}

// StatusDiff compares HTTP status codes.
type StatusDiff struct {
	Same   bool           `json:"same"`
	Values map[string]int `json:"values"`
}

// HeaderDiff compares a specific header across engines.
type HeaderDiff struct {
	Header  string            `json:"header"`
	Same    bool              `json:"same"`
	Values  map[string]string `json:"values"`
	Present map[string]bool   `json:"present"`
}

// BodyDiff compares response bodies.
type BodyDiff struct {
	Same       bool           `json:"same"`
	Lengths    map[string]int `json:"lengths"`
	Similarity float64        `json:"similarity"`
	Diff       string         `json:"diff,omitempty"`
}

// ProtocolDiff compares protocol details.
type ProtocolDiff struct {
	Same      bool              `json:"same"`
	Protocols map[string]string `json:"protocols"`
}

// TimingDiff compares timing information.
type TimingDiff struct {
	TotalTimes map[string]string `json:"total_times"`
}

// RedirectDiff compares redirect behavior.
type RedirectDiff struct {
	Same           bool           `json:"same"`
	RedirectCounts map[string]int `json:"redirect_counts"`
}

// Compare compares results from multiple engines.
func Compare(url string, results []EngineResult) *Comparison {
	comp := &Comparison{
		URL:         url,
		Engines:     make([]string, 0, len(results)),
		HeaderDiffs: make(map[string]*HeaderDiff),
	}

	for _, r := range results {
		comp.Engines = append(comp.Engines, r.EngineName)
	}

	// Compare status codes
	comp.compareStatuses(results)

	// Compare headers
	comp.compareHeaders(results)

	// Compare bodies
	comp.compareBodies(results)

	// Compare protocols
	comp.compareProtocols(results)

	// Compare timing
	comp.compareTiming(results)

	// Generate summary
	comp.generateSummary()

	return comp
}

func (c *Comparison) compareStatuses(results []EngineResult) {
	diff := &StatusDiff{
		Values: make(map[string]int),
	}

	var firstStatus int
	first := true

	for _, r := range results {
		if r.Error != nil {
			diff.Values[r.EngineName] = 0
			continue
		}

		status := r.Response.Status
		diff.Values[r.EngineName] = status

		if first {
			firstStatus = status
			first = false
		} else if status != firstStatus {
			diff.Same = false
		}
	}

	if first {
		diff.Same = true // All had errors
	}

	c.StatusDiff = diff
}

func (c *Comparison) compareHeaders(results []EngineResult) {
	// Collect all header names
	allHeaders := make(map[string]bool)
	for _, r := range results {
		if r.Error != nil || r.Response == nil {
			continue
		}
		for key := range r.Response.Headers {
			allHeaders[key] = true
		}
	}

	// Compare each header
	for header := range allHeaders {
		hd := &HeaderDiff{
			Header:  header,
			Values:  make(map[string]string),
			Present: make(map[string]bool),
		}

		var firstValue string
		first := true
		allSame := true

		for _, r := range results {
			if r.Error != nil || r.Response == nil {
				hd.Present[r.EngineName] = false
				continue
			}

			values, ok := r.Response.Headers[header]
			hd.Present[r.EngineName] = ok

			if !ok {
				allSame = false
				continue
			}

			value := strings.Join(values, ", ")
			hd.Values[r.EngineName] = value

			if first {
				firstValue = value
				first = false
			} else if value != firstValue {
				allSame = false
			}
		}

		hd.Same = allSame && !first
		c.HeaderDiffs[header] = hd
	}
}

func (c *Comparison) compareBodies(results []EngineResult) {
	diff := &BodyDiff{
		Lengths: make(map[string]int),
	}

	var firstBody []byte
	first := true

	for _, r := range results {
		if r.Error != nil || r.Response == nil {
			diff.Lengths[r.EngineName] = 0
			continue
		}

		body := r.Response.Body
		diff.Lengths[r.EngineName] = len(body)

		if first {
			firstBody = body
			first = false
		} else if !bytes.Equal(body, firstBody) {
			diff.Same = false
		}
	}

	if !first {
		diff.Same = true
	}

	c.BodyDiff = diff
}

func (c *Comparison) compareProtocols(results []EngineResult) {
	diff := &ProtocolDiff{
		Protocols: make(map[string]string),
	}

	var firstProto string
	first := true

	for _, r := range results {
		if r.Error != nil || r.Response == nil {
			diff.Protocols[r.EngineName] = ""
			continue
		}

		proto := r.Response.Protocol
		diff.Protocols[r.EngineName] = proto

		if first {
			firstProto = proto
			first = false
		} else if proto != firstProto {
			diff.Same = false
		}
	}

	if first {
		diff.Same = true
	}

	c.ProtocolDiff = diff
}

func (c *Comparison) compareTiming(results []EngineResult) {
	diff := &TimingDiff{
		TotalTimes: make(map[string]string),
	}

	for _, r := range results {
		if r.Error != nil || r.Response == nil {
			diff.TotalTimes[r.EngineName] = "N/A"
			continue
		}
		diff.TotalTimes[r.EngineName] = r.Response.Timing.Total.String()
	}

	c.TimingDiff = diff
}

func (c *Comparison) generateSummary() {
	var parts []string

	if !c.StatusDiff.Same {
		parts = append(parts, "status codes differ")
	}

	if !c.ProtocolDiff.Same {
		parts = append(parts, "protocols differ")
	}

	if !c.BodyDiff.Same {
		parts = append(parts, "bodies differ")
	}

	differentHeaders := 0
	for _, hd := range c.HeaderDiffs {
		if !hd.Same {
			differentHeaders++
		}
	}
	if differentHeaders > 0 {
		parts = append(parts, fmt.Sprintf("%d headers differ", differentHeaders))
	}

	if len(parts) == 0 {
		c.Summary = "All engines returned identical responses"
	} else {
		c.Summary = fmt.Sprintf("Differences found: %s", strings.Join(parts, ", "))
	}
}

// FormatPretty returns a human-readable string representation.
func (c *Comparison) FormatPretty() string {
	var b strings.Builder

	fmt.Fprintf(&b, "Comparison for: %s\n", c.URL)
	fmt.Fprintf(&b, "Engines: %s\n\n", strings.Join(c.Engines, ", "))

	fmt.Fprintf(&b, "Status: ")
	if c.StatusDiff.Same {
		for _, v := range c.StatusDiff.Values {
			fmt.Fprintf(&b, "%d (all engines)\n", v)
			break
		}
	} else {
		fmt.Fprintln(&b, "DIFFER")
		for engine, status := range c.StatusDiff.Values {
			fmt.Fprintf(&b, "  %s: %d\n", engine, status)
		}
	}

	fmt.Fprintf(&b, "\nProtocol: ")
	if c.ProtocolDiff.Same {
		for _, v := range c.ProtocolDiff.Protocols {
			fmt.Fprintf(&b, "%s (all engines)\n", v)
			break
		}
	} else {
		fmt.Fprintln(&b, "DIFFER")
		for engine, proto := range c.ProtocolDiff.Protocols {
			fmt.Fprintf(&b, "  %s: %s\n", engine, proto)
		}
	}

	fmt.Fprintf(&b, "\nBody: ")
	if c.BodyDiff.Same {
		for _, length := range c.BodyDiff.Lengths {
			fmt.Fprintf(&b, "%d bytes (all engines)\n", length)
			break
		}
	} else {
		fmt.Fprintln(&b, "DIFFER")
		for engine, length := range c.BodyDiff.Lengths {
			fmt.Fprintf(&b, "  %s: %d bytes\n", engine, length)
		}
	}

	fmt.Fprintln(&b, "\nHeaders:")
	var headerNames []string
	for name := range c.HeaderDiffs {
		headerNames = append(headerNames, name)
	}
	sort.Strings(headerNames)

	for _, name := range headerNames {
		hd := c.HeaderDiffs[name]
		if hd.Same {
			for _, v := range hd.Values {
				fmt.Fprintf(&b, "  %s: %s\n", name, v)
				break
			}
		} else {
			fmt.Fprintf(&b, "  %s: DIFFER\n", name)
			for engine, present := range hd.Present {
				if present {
					fmt.Fprintf(&b, "    %s: %s\n", engine, hd.Values[engine])
				} else {
					fmt.Fprintf(&b, "    %s: (not present)\n", engine)
				}
			}
		}
	}

	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "Summary: %s\n", c.Summary)

	return b.String()
}

// JSON returns the comparison as JSON.
func (c *Comparison) JSON() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}

// TraceComparison compares network traces.
type TraceComparison struct {
	Engines         []string                    `json:"engines"`
	RequestCounts   map[string]int              `json:"request_counts"`
	TimingDiffs     map[string]*TimingBreakdown `json:"timing_diffs"`
	TLSFingerprints map[string]string           `json:"tls_fingerprints,omitempty"`
}

// TimingBreakdown compares detailed timing.
type TimingBreakdown struct {
	DNS     string `json:"dns,omitempty"`
	Connect string `json:"connect,omitempty"`
	SSL     string `json:"ssl,omitempty"`
	Send    string `json:"send,omitempty"`
	Wait    string `json:"wait,omitempty"`
	Receive string `json:"receive,omitempty"`
	Total   string `json:"total"`
}

// CompareTraces compares network traces from multiple engines.
func CompareTraces(results []EngineResult) *TraceComparison {
	comp := &TraceComparison{
		Engines:         make([]string, 0, len(results)),
		RequestCounts:   make(map[string]int),
		TimingDiffs:     make(map[string]*TimingBreakdown),
		TLSFingerprints: make(map[string]string),
	}

	for _, r := range results {
		comp.Engines = append(comp.Engines, r.EngineName)

		if r.Error != nil || r.Trace == nil {
			continue
		}

		comp.RequestCounts[r.EngineName] = len(r.Trace.Entries)

		// Get timing from first entry
		if len(r.Trace.Entries) > 0 {
			timing := r.Trace.Entries[0].Timing
			comp.TimingDiffs[r.EngineName] = &TimingBreakdown{
				DNS:     timing.DNS.String(),
				Connect: timing.Connect.String(),
				SSL:     timing.SSL.String(),
				Send:    timing.Send.String(),
				Wait:    timing.Wait.String(),
				Receive: timing.Receive.String(),
				Total:   timing.Total.String(),
			}
		}
	}

	return comp
}

// HeaderSet extracts normalized headers for comparison.
type HeaderSet struct {
	Headers map[string][]string
}

// NewHeaderSet creates a HeaderSet from http.Header.
func NewHeaderSet(h http.Header) *HeaderSet {
	hs := &HeaderSet{
		Headers: make(map[string][]string),
	}
	for k, v := range h {
		hs.Headers[http.CanonicalHeaderKey(k)] = v
	}
	return hs
}

// Diff returns differences between two header sets.
func (hs *HeaderSet) Diff(other *HeaderSet) map[string][2][]string {
	diffs := make(map[string][2][]string)

	allKeys := make(map[string]bool)
	for k := range hs.Headers {
		allKeys[k] = true
	}
	for k := range other.Headers {
		allKeys[k] = true
	}

	for k := range allKeys {
		v1, ok1 := hs.Headers[k]
		v2, ok2 := other.Headers[k]

		if !ok1 || !ok2 || !stringSlicesEqual(v1, v2) {
			diffs[k] = [2][]string{v1, v2}
		}
	}

	return diffs
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ResponseAnalyzer provides deep analysis of a response.
type ResponseAnalyzer struct {
	Response *engine.Response
}

// Analyze performs comprehensive analysis.
func (ra *ResponseAnalyzer) Analyze() map[string]interface{} {
	analysis := make(map[string]interface{})

	if ra.Response == nil {
		return analysis
	}

	// Content analysis - get first Content-Type value
	contentType := ""
	if ctValues, ok := ra.Response.Headers["Content-Type"]; ok && len(ctValues) > 0 {
		contentType = ctValues[0]
	}
	analysis["content_type"] = contentType
	analysis["body_size"] = len(ra.Response.Body)
	analysis["protocol"] = ra.Response.Protocol
	analysis["status"] = ra.Response.Status

	// Header count
	analysis["header_count"] = len(ra.Response.Headers)

	// Security headers check
	securityHeaders := []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"Referrer-Policy",
	}
	present := make([]string, 0)
	for _, h := range securityHeaders {
		if _, ok := ra.Response.Headers[h]; ok {
			present = append(present, h)
		}
	}
	analysis["security_headers_present"] = present
	analysis["security_headers_missing"] = len(securityHeaders) - len(present)

	return analysis
}
