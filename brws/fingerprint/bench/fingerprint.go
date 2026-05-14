// Package benchmark provides fingerprint consistency testing
package benchmark

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/skunkworq/stealth/brws/browser/engine"
)

// FingerprintResult represents a single fingerprint capture
type FingerprintResult struct {
	EngineName       string            `json:"engine_name"`
	Iteration        int               `json:"iteration"`
	Timestamp        time.Time         `json:"timestamp"`
	Protocol         string            `json:"protocol"`
	UserAgent        string            `json:"user_agent"`
	Headers          map[string]string `json:"headers"`
	TLSFingerprint   *TLSInfo          `json:"tls_fingerprint,omitempty"`
	HTTP2Fingerprint *HTTP2Info        `json:"http2_fingerprint,omitempty"`
	Hash             string            `json:"hash"`
}

// TLSInfo contains TLS fingerprint information
type TLSInfo struct {
	Version         string   `json:"version"`
	CipherSuite     string   `json:"cipher_suite"`
	ALPN            string   `json:"alpn"`
	SNI             string   `json:"sni"`
	JA3Hash         string   `json:"ja3_hash,omitempty"`
	SupportedGroups []string `json:"supported_groups,omitempty"`
	Extensions      []string `json:"extensions,omitempty"`
}

// HTTP2Info contains HTTP/2 fingerprint information
type HTTP2Info struct {
	Settings       map[string]int  `json:"settings"`
	WindowSize     int             `json:"window_size"`
	HeaderPriority *HeaderPriority `json:"header_priority,omitempty"`
	PseudoOrder    []string        `json:"pseudo_order,omitempty"`
}

// HeaderPriority represents HTTP/2 priority information
type HeaderPriority struct {
	StreamDep int `json:"stream_dep"`
	Exclusive int `json:"exclusive"`
	Weight    int `json:"weight"`
}

// ConsistencyReport contains fingerprint consistency analysis
type ConsistencyReport struct {
	Timestamp   time.Time           `json:"timestamp"`
	EngineName  string              `json:"engine_name"`
	TargetURL   string              `json:"target_url"`
	Iterations  int                 `json:"iterations"`
	Results     []FingerprintResult `json:"results"`
	Consistency ConsistencyAnalysis `json:"consistency"`
	Variance    VarianceReport      `json:"variance"`
}

// ConsistencyAnalysis analyzes fingerprint consistency
type ConsistencyAnalysis struct {
	TotalIterations int      `json:"total_iterations"`
	UniqueHashes    int      `json:"unique_hashes"`
	ConsistencyRate float64  `json:"consistency_rate"`
	StableHeaders   []string `json:"stable_headers"`
	VariableHeaders []string `json:"variable_headers"`
}

// VarianceReport reports on fingerprint variance
type VarianceReport struct {
	ProtocolVariance  bool           `json:"protocol_variance"`
	UserAgentVariance bool           `json:"user_agent_variance"`
	HeaderVariance    map[string]int `json:"header_variance"`
	TLSVariance       bool           `json:"tls_variance"`
	HTTP2Variance     bool           `json:"http2_variance"`
}

// FingerprintBenchmark tests fingerprint consistency across requests
type FingerprintBenchmark struct {
	engineName   string
	targetURL    string
	iterations   int
	delayBetween time.Duration
	timeout      time.Duration
}

// NewFingerprintBenchmark creates a new fingerprint benchmark
func NewFingerprintBenchmark(engineName, targetURL string, iterations int) *FingerprintBenchmark {
	return &FingerprintBenchmark{
		engineName:   engineName,
		targetURL:    targetURL,
		iterations:   iterations,
		delayBetween: 2 * time.Second,
		timeout:      30 * time.Second,
	}
}

// WithDelay sets the delay between requests
func (fb *FingerprintBenchmark) WithDelay(delay time.Duration) *FingerprintBenchmark {
	fb.delayBetween = delay
	return fb
}

// WithTimeout sets the request timeout
func (fb *FingerprintBenchmark) WithTimeout(timeout time.Duration) *FingerprintBenchmark {
	fb.timeout = timeout
	return fb
}

// Run executes the fingerprint benchmark
func (fb *FingerprintBenchmark) Run(ctx context.Context) (*ConsistencyReport, error) {
	eng, err := engine.New(fb.engineName, engine.Options{
		Timeout:  fb.timeout,
		Headless: true,
		HTTP2:    true,
		HTTP3:    true,
	})
	if err != nil {
		return nil, fmt.Errorf("creating engine %s: %w", fb.engineName, err)
	}
	defer eng.Close()

	report := &ConsistencyReport{
		Timestamp:  time.Now(),
		EngineName: fb.engineName,
		TargetURL:  fb.targetURL,
		Iterations: fb.iterations,
		Results:    []FingerprintResult{},
	}

	for i := 0; i < fb.iterations; i++ {
		result, err := fb.captureFingerprint(ctx, eng, i)
		if err != nil {
			fmt.Printf("Warning: iteration %d failed: %v\n", i, err)
			continue
		}
		report.Results = append(report.Results, *result)

		// Delay between requests (except last)
		if i < fb.iterations-1 && fb.delayBetween > 0 {
			select {
			case <-ctx.Done():
				return report, ctx.Err()
			case <-time.After(fb.delayBetween):
			}
		}
	}

	report.Consistency = fb.analyzeConsistency(report.Results)
	report.Variance = fb.analyzeVariance(report.Results)

	return report, nil
}

// captureFingerprint captures a single fingerprint
func (fb *FingerprintBenchmark) captureFingerprint(
	ctx context.Context,
	eng engine.Engine,
	iteration int,
) (*FingerprintResult, error) {
	resp, err := eng.Do(ctx, &engine.Request{
		Method:            "GET",
		URL:               fb.targetURL,
		LoadStrategy: engine.LoadLoad,
		Timeout:      fb.timeout,
	})
	if err != nil {
		return nil, err
	}

	result := &FingerprintResult{
		EngineName: fb.engineName,
		Iteration:  iteration,
		Timestamp:  time.Now(),
		Protocol:   resp.Protocol,
		Headers:    make(map[string]string),
	}

	// Extract headers from trace if available
	if len(resp.Trace.Entries) > 0 {
		entry := resp.Trace.Entries[0]
		for k, v := range entry.Request.Headers {
			result.Headers[k] = v
		}
		// Extract User-Agent
		if ua, ok := entry.Request.Headers["User-Agent"]; ok {
			result.UserAgent = ua
		}
	}

	// Calculate hash of fingerprint data
	result.Hash = fb.calculateHash(result)

	return result, nil
}

// calculateHash creates a hash of fingerprint data
func (fb *FingerprintBenchmark) calculateHash(result *FingerprintResult) string {
	data, _ := json.Marshal(struct {
		Protocol  string            `json:"protocol"`
		UserAgent string            `json:"user_agent"`
		Headers   map[string]string `json:"headers"`
	}{
		Protocol:  result.Protocol,
		UserAgent: result.UserAgent,
		Headers:   result.Headers,
	})

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:8]) // First 8 bytes is enough
}

// analyzeConsistency analyzes fingerprint consistency
func (fb *FingerprintBenchmark) analyzeConsistency(results []FingerprintResult) ConsistencyAnalysis {
	if len(results) == 0 {
		return ConsistencyAnalysis{}
	}

	analysis := ConsistencyAnalysis{
		TotalIterations: len(results),
		StableHeaders:   []string{},
		VariableHeaders: []string{},
	}

	// Count unique hashes
	hashCount := make(map[string]int)
	for _, r := range results {
		hashCount[r.Hash]++
	}
	analysis.UniqueHashes = len(hashCount)

	if analysis.TotalIterations > 0 {
		mostCommonCount := 0
		for _, count := range hashCount {
			if count > mostCommonCount {
				mostCommonCount = count
			}
		}
		analysis.ConsistencyRate = float64(mostCommonCount) / float64(analysis.TotalIterations)
	}

	// Analyze header stability
	if len(results) > 0 {
		headerValues := make(map[string]map[string]int)
		for _, r := range results {
			for k, v := range r.Headers {
				if headerValues[k] == nil {
					headerValues[k] = make(map[string]int)
				}
				headerValues[k][v]++
			}
		}

		for header, values := range headerValues {
			uniqueValues := len(values)
			if uniqueValues == 1 {
				analysis.StableHeaders = append(analysis.StableHeaders, header)
			} else {
				analysis.VariableHeaders = append(analysis.VariableHeaders, header)
			}
		}
	}

	return analysis
}

// analyzeVariance analyzes fingerprint variance
func (fb *FingerprintBenchmark) analyzeVariance(results []FingerprintResult) VarianceReport {
	variance := VarianceReport{
		HeaderVariance: make(map[string]int),
	}

	if len(results) < 2 {
		return variance
	}

	// Check protocol variance
	protocols := make(map[string]int)
	userAgents := make(map[string]int)

	for _, r := range results {
		protocols[r.Protocol]++
		userAgents[r.UserAgent]++
	}

	variance.ProtocolVariance = len(protocols) > 1
	variance.UserAgentVariance = len(userAgents) > 1

	// Check header variance
	headerValues := make(map[string]map[string]int)
	for _, r := range results {
		for k, v := range r.Headers {
			if headerValues[k] == nil {
				headerValues[k] = make(map[string]int)
			}
			headerValues[k][v]++
		}
	}

	for header, values := range headerValues {
		variance.HeaderVariance[header] = len(values)
	}

	return variance
}

// MultiEngineFingerprintBenchmark compares fingerprints across engines
type MultiEngineFingerprintBenchmark struct {
	engines    []string
	targetURL  string
	iterations int
}

// NewMultiEngineFingerprintBenchmark creates a multi-engine benchmark
func NewMultiEngineFingerprintBenchmark(engines []string, targetURL string, iterations int) *MultiEngineFingerprintBenchmark {
	return &MultiEngineFingerprintBenchmark{
		engines:    engines,
		targetURL:  targetURL,
		iterations: iterations,
	}
}

// Run executes the multi-engine fingerprint benchmark
func (mb *MultiEngineFingerprintBenchmark) Run(ctx context.Context) (map[string]*ConsistencyReport, error) {
	reports := make(map[string]*ConsistencyReport)

	for _, engineName := range mb.engines {
		fmt.Printf("Testing engine: %s\n", engineName)
		benchmark := NewFingerprintBenchmark(engineName, mb.targetURL, mb.iterations)
		report, err := benchmark.Run(ctx)
		if err != nil {
			fmt.Printf("Warning: benchmark failed for %s: %v\n", engineName, err)
			continue
		}
		reports[engineName] = report
	}

	return reports, nil
}

// CompareEngines compares fingerprints across engines
func CompareEngines(reports map[string]*ConsistencyReport) *EngineComparison {
	comparison := &EngineComparison{
		Timestamp:     time.Now(),
		EngineReports: reports,
		Similarities:  make(map[string][]string),
		Differences:   make(map[string][]string),
	}

	// Collect all protocols used
	protocols := make(map[string][]string)
	userAgents := make(map[string][]string)

	for engineName, report := range reports {
		if len(report.Results) > 0 {
			protocols[report.Results[0].Protocol] = append(protocols[report.Results[0].Protocol], engineName)
			userAgents[report.Results[0].UserAgent] = append(userAgents[report.Results[0].UserAgent], engineName)
		}
	}

	// Find similarities (engines using same protocol)
	for proto, engines := range protocols {
		if len(engines) > 1 {
			key := fmt.Sprintf("Protocol: %s", proto)
			comparison.Similarities[key] = engines
		}
	}

	// Find differences (engines using different user agents)
	for ua, engines := range userAgents {
		if len(engines) == 1 {
			key := fmt.Sprintf("User-Agent: %s", ua[:min(len(ua), 50)])
			comparison.Differences[key] = engines
		}
	}

	return comparison
}

// EngineComparison compares multiple engines
type EngineComparison struct {
	Timestamp     time.Time                     `json:"timestamp"`
	EngineReports map[string]*ConsistencyReport `json:"engine_reports"`
	Similarities  map[string][]string           `json:"similarities"`
	Differences   map[string][]string           `json:"differences"`
}
