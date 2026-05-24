// Package benchmark provides comprehensive benchmarking capabilities
package fingerprintbench

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/skunkworq/stealth/brws/browser/engine"
)

// SuiteType represents the type of benchmark suite
type SuiteType string

const (
	SuiteEndpoints    SuiteType = "endpoints"    // Test against various endpoints
	SuiteCapabilities SuiteType = "capabilities" // Test engine capabilities
	SuiteFingerprint  SuiteType = "fingerprint"  // Test fingerprint consistency
	SuitePerformance  SuiteType = "performance"  // Performance benchmarks
	SuiteAll          SuiteType = "all"          // Run all suites
)

// SuiteConfig configures a benchmark suite
type SuiteConfig struct {
	Type         SuiteType
	Engines      []string
	Categories   []string
	Endpoints    []Endpoint
	Iterations   int
	Timeout      time.Duration
	OutputFormat string // "json", "yaml", "table"
	OutputPath   string
	Verbose      bool
	Parallel     bool
	MaxParallel  int
}

// SuiteResult contains all benchmark results
type SuiteResult struct {
	Timestamp          time.Time                     `json:"timestamp"`
	Duration           time.Duration                 `json:"duration"`
	Config             SuiteConfig                   `json:"config"`
	EndpointResults    []EndpointBenchmarkResult     `json:"endpoint_results,omitempty"`
	CapabilityReport   *CapabilityReport             `json:"capability_report,omitempty"`
	FingerprintReports map[string]*ConsistencyReport `json:"fingerprint_reports,omitempty"`
	PerformanceResults []PerformanceResult           `json:"performance_results,omitempty"`
	Summary            SuiteSummary                  `json:"summary"`
}

// EndpointBenchmarkResult represents results from endpoint testing
type EndpointBenchmarkResult struct {
	EngineName string        `json:"engine_name"`
	Endpoint   Endpoint      `json:"endpoint"`
	Success    bool          `json:"success"`
	StatusCode int           `json:"status_code"`
	Duration   time.Duration `json:"duration"`
	BodySize   int           `json:"body_size"`
	Protocol   string        `json:"protocol"`
	Error      string        `json:"error,omitempty"`
	Blocked    bool          `json:"blocked"`
	Blocker    string        `json:"blocker,omitempty"`
	Evidence   string        `json:"evidence,omitempty"`
	RetryCount int           `json:"retry_count"`
	Timestamp  time.Time     `json:"timestamp"`
}

// PerformanceResult represents a performance benchmark result
type PerformanceResult struct {
	EngineName string        `json:"engine_name"`
	TestName   string        `json:"test_name"`
	Iterations int           `json:"iterations"`
	TotalTime  time.Duration `json:"total_time"`
	AvgTime    time.Duration `json:"avg_time"`
	MinTime    time.Duration `json:"min_time"`
	MaxTime    time.Duration `json:"max_time"`
	P95Time    time.Duration `json:"p95_time"`
	P99Time    time.Duration `json:"p99_time"`
}

// SuiteSummary provides overall summary
type SuiteSummary struct {
	TotalTests   int                        `json:"total_tests"`
	PassedTests  int                        `json:"passed_tests"`
	FailedTests  int                        `json:"failed_tests"`
	BlockedTests int                        `json:"blocked_tests"`
	SkippedTests int                        `json:"skipped_tests"`
	ByEngine     map[string]EngineSummary   `json:"by_engine"`
	ByCategory   map[string]CategorySummary `json:"by_category"`
}

// EngineSummary summary per engine
type EngineSummary struct {
	Total       int           `json:"total"`
	Passed      int           `json:"passed"`
	Failed      int           `json:"failed"`
	Blocked     int           `json:"blocked"`
	SuccessRate float64       `json:"success_rate"`
	AvgLatency  time.Duration `json:"avg_latency"`
}

// CategorySummary summary per category
type CategorySummary struct {
	Total   int `json:"total"`
	Passed  int `json:"passed"`
	Failed  int `json:"failed"`
	Blocked int `json:"blocked"`
}

// SuiteRunner runs benchmark suites
type SuiteRunner struct {
	config SuiteConfig
}

// NewSuiteRunner creates a new suite runner
func NewSuiteRunner(config SuiteConfig) *SuiteRunner {
	// Set defaults
	if config.Iterations == 0 {
		config.Iterations = 3
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.OutputFormat == "" {
		config.OutputFormat = "table"
	}
	if len(config.Engines) == 0 {
		config.Engines = GetAllEngines()
	}
	if config.MaxParallel == 0 {
		config.MaxParallel = 4
	}

	return &SuiteRunner{config: config}
}

// Run executes the benchmark suite
func (sr *SuiteRunner) Run(ctx context.Context) (*SuiteResult, error) {
	start := time.Now()
	result := &SuiteResult{
		Timestamp:          time.Now(),
		Config:             sr.config,
		EndpointResults:    []EndpointBenchmarkResult{},
		FingerprintReports: make(map[string]*ConsistencyReport),
	}

	switch sr.config.Type {
	case SuiteEndpoints:
		sr.runEndpointSuite(ctx, result)
	case SuiteCapabilities:
		sr.runCapabilitySuite(ctx, result)
	case SuiteFingerprint:
		sr.runFingerprintSuite(ctx, result)
	case SuitePerformance:
		sr.runPerformanceSuite(ctx, result)
	case SuiteAll:
		sr.runEndpointSuite(ctx, result)
		sr.runCapabilitySuite(ctx, result)
		sr.runFingerprintSuite(ctx, result)
		sr.runPerformanceSuite(ctx, result)
	default:
		return nil, fmt.Errorf("unknown suite type: %s", sr.config.Type)
	}

	result.Duration = time.Since(start)
	result.Summary = sr.generateSummary(result)

	return result, nil
}

// runEndpointSuite tests endpoints across engines
func (sr *SuiteRunner) runEndpointSuite(ctx context.Context, result *SuiteResult) {
	endpoints := sr.getEndpoints()

	for _, engineName := range sr.config.Engines {
		eng, err := engine.New(engineName, engine.Options{
			Timeout:  sr.config.Timeout,
			Headless: true,
			HTTP2:    true,
			HTTP3:    true,
		})
		if err != nil {
			if sr.config.Verbose {
				fmt.Printf("Warning: failed to create engine %s: %v\n", engineName, err)
			}
			continue
		}

		caps := eng.Capabilities()

		for _, endpoint := range endpoints {
			// Check if endpoint is compatible with engine
			if !isCompatible(endpoint.RequiredCaps, caps) {
				if sr.config.Verbose {
					fmt.Printf("Skipping %s for %s: incompatible capabilities\n", endpoint.Name, engineName)
				}
				continue
			}

			testResult := sr.testEndpoint(ctx, eng, engineName, endpoint)
			result.EndpointResults = append(result.EndpointResults, testResult)
		}

		eng.Close()
	}
}

// runCapabilitySuite tests engine capabilities
func (sr *SuiteRunner) runCapabilitySuite(ctx context.Context, result *SuiteResult) {
	evaluator := NewCapabilityEvaluator(sr.config.Engines, sr.config.Timeout)
	report, err := evaluator.Run(ctx)
	if err != nil {
		fmt.Printf("Warning: capability evaluation failed: %v\n", err)
		return
	}
	result.CapabilityReport = report
}

// runFingerprintSuite tests fingerprint consistency
func (sr *SuiteRunner) runFingerprintSuite(ctx context.Context, result *SuiteResult) {
	// Test against a stable endpoint
	targetURL := "https://httpbin.org/headers"

	for _, engineName := range sr.config.Engines {
		benchmark := NewFingerprintBenchmark(engineName, targetURL, sr.config.Iterations)
		benchmark.WithTimeout(sr.config.Timeout)

		report, err := benchmark.Run(ctx)
		if err != nil {
			if sr.config.Verbose {
				fmt.Printf("Warning: fingerprint benchmark failed for %s: %v\n", engineName, err)
			}
			continue
		}

		result.FingerprintReports[engineName] = report
	}
}

// runPerformanceSuite tests engine performance
func (sr *SuiteRunner) runPerformanceSuite(ctx context.Context, result *SuiteResult) {
	testURL := "https://www.google.com"
	iterations := sr.config.Iterations * 3 // More iterations for performance

	for _, engineName := range sr.config.Engines {
		perfResult := sr.benchmarkEnginePerformance(ctx, engineName, testURL, iterations)
		if perfResult != nil {
			result.PerformanceResults = append(result.PerformanceResults, *perfResult)
		}
	}
}

// testEndpoint tests a single endpoint
func (sr *SuiteRunner) testEndpoint(
	ctx context.Context,
	eng engine.Engine,
	engineName string,
	endpoint Endpoint,
) EndpointBenchmarkResult {
	result := EndpointBenchmarkResult{
		EngineName: engineName,
		Endpoint:   endpoint,
		Timestamp:  time.Now(),
	}

	timeout := endpoint.Timeout
	if timeout == 0 {
		timeout = sr.config.Timeout
	}

	start := time.Now()
	resp, err := eng.Do(ctx, &engine.Request{
		Method:          "GET",
		URL:             endpoint.URL,
		FollowRedirects: true,
		Timeout:         timeout,
		LoadStrategy:    engine.LoadLoad,
	})
	result.Duration = time.Since(start)

	if err != nil {
		result.Error = err.Error()
		result.Success = false
		return result
	}

	result.StatusCode = resp.Status
	result.BodySize = len(resp.Body)
	result.Protocol = resp.Protocol

	// Check for expected content
	if endpoint.ExpectedContent != "" {
		if strings.Contains(strings.ToLower(string(resp.Body)), strings.ToLower(endpoint.ExpectedContent)) {
			result.Success = true
			result.Evidence = fmt.Sprintf("found '%s'", endpoint.ExpectedContent)
		} else {
			result.Success = false
			result.Evidence = fmt.Sprintf("expected '%s' not found", endpoint.ExpectedContent)
		}
	} else {
		// No expected content, just check for non-error status
		result.Success = resp.Status >= 200 && resp.Status < 400
	}

	// Check for blocking indicators
	result.Blocked = sr.isBlocked(resp.Body, endpoint)
	if result.Blocked {
		result.Blocker = string(endpoint.Protection)
	}

	return result
}

// isBlocked checks if the response indicates blocking
func (sr *SuiteRunner) isBlocked(body []byte, endpoint Endpoint) bool {
	indicators := []string{
		"Incapsula",
		"incident_id",
		"Request unsuccessful",
		"Cloudflare",
		"cf-ray",
		"Access denied",
		"blocked",
		"captcha",
		"CAPTCHA",
		"DataDome",
		"perimeterx",
		"akamai",
		"challenge",
	}

	bodyStr := strings.ToLower(string(body))
	for _, indicator := range indicators {
		if strings.Contains(bodyStr, strings.ToLower(indicator)) {
			return true
		}
	}

	// Check for small response on protected endpoint
	if endpoint.Protection != ProtectionNone && len(body) < 1000 {
		return true
	}

	return false
}

// benchmarkEnginePerformance benchmarks an engine's performance
func (sr *SuiteRunner) benchmarkEnginePerformance(
	ctx context.Context,
	engineName string,
	testURL string,
	iterations int,
) *PerformanceResult {
	eng, err := engine.New(engineName, engine.Options{
		Timeout:  sr.config.Timeout,
		Headless: true,
	})
	if err != nil {
		return nil
	}
	defer eng.Close()

	var times []time.Duration

	for i := 0; i < iterations; i++ {
		start := time.Now()
		_, err := eng.Do(ctx, &engine.Request{
			Method:  "GET",
			URL:     testURL,
			Timeout: sr.config.Timeout,
		})
		if err != nil {
			continue
		}
		times = append(times, time.Since(start))

		// Small delay between requests
		if i < iterations-1 {
			time.Sleep(100 * time.Millisecond)
		}
	}

	if len(times) == 0 {
		return nil
	}

	// Calculate statistics
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })

	var total time.Duration
	for _, t := range times {
		total += t
	}
	avg := total / time.Duration(len(times))

	p95Idx := int(float64(len(times)) * 0.95)
	p99Idx := int(float64(len(times)) * 0.99)

	return &PerformanceResult{
		EngineName: engineName,
		TestName:   "page_load",
		Iterations: len(times),
		TotalTime:  total,
		AvgTime:    avg,
		MinTime:    times[0],
		MaxTime:    times[len(times)-1],
		P95Time:    times[p95Idx],
		P99Time:    times[p99Idx],
	}
}

// GetEngineForInspection creates an engine for capability inspection only
func GetEngineForInspection(name string) (engine.Engine, error) {
	return engine.New(name, engine.Options{
		Headless: true,
		Timeout:  10 * time.Second,
	})
}

// getEndpoints returns the list of endpoints to test
func (sr *SuiteRunner) getEndpoints() []Endpoint {
	if len(sr.config.Endpoints) > 0 {
		return sr.config.Endpoints
	}

	if len(sr.config.Categories) > 0 {
		var endpoints []Endpoint
		for _, cat := range sr.config.Categories {
			endpoints = append(endpoints, GetEndpointsByCategory(cat)...)
		}
		return endpoints
	}

	// Default: return a subset of key endpoints
	return []Endpoint{
		{
			Name:            "httpbin_get",
			URL:             "https://httpbin.org/get",
			Description:     "Basic HTTP GET test",
			ExpectedContent: "origin",
			Protection:      ProtectionNone,
			Category:        "basic",
		},
		{
			Name:            "http2_google",
			URL:             "https://www.google.com",
			Description:     "HTTP/2 protocol test",
			ExpectedContent: "google",
			Protection:      ProtectionBasic,
			Category:        "protocol",
		},
		{
			Name:            "wikipedia",
			URL:             "https://en.wikipedia.org/wiki/Test",
			Description:     "Wikipedia static content",
			ExpectedContent: "test",
			Protection:      ProtectionNone,
			Category:        "content",
		},
		{
			Name:            "react_docs",
			URL:             "https://react.dev",
			Description:     "React documentation (JS required)",
			ExpectedContent: "React",
			Protection:      ProtectionNone,
			RequiredCaps:    []CapabilityTest{CapJavaScript},
			Category:        "javascript",
		},
	}
}

// generateSummary creates the suite summary
func (sr *SuiteRunner) generateSummary(result *SuiteResult) SuiteSummary {
	summary := SuiteSummary{
		ByEngine:   make(map[string]EngineSummary),
		ByCategory: make(map[string]CategorySummary),
	}

	// Summarize endpoint results
	for _, r := range result.EndpointResults {
		summary.TotalTests++

		if r.Blocked {
			summary.BlockedTests++
		} else if r.Success {
			summary.PassedTests++
		} else {
			summary.FailedTests++
		}

		// By engine
		engineStats := summary.ByEngine[r.EngineName]
		engineStats.Total++
		if r.Blocked {
			engineStats.Blocked++
		} else if r.Success {
			engineStats.Passed++
			engineStats.AvgLatency += r.Duration
		} else {
			engineStats.Failed++
		}
		summary.ByEngine[r.EngineName] = engineStats

		// By category
		catStats := summary.ByCategory[r.Endpoint.Category]
		catStats.Total++
		if r.Blocked {
			catStats.Blocked++
		} else if r.Success {
			catStats.Passed++
		} else {
			catStats.Failed++
		}
		summary.ByCategory[r.Endpoint.Category] = catStats
	}

	// Calculate success rates and averages
	for engineName, stats := range summary.ByEngine {
		if stats.Total > 0 {
			stats.SuccessRate = float64(stats.Passed) / float64(stats.Total)
		}
		if stats.Passed > 0 {
			stats.AvgLatency = stats.AvgLatency / time.Duration(stats.Passed)
		}
		summary.ByEngine[engineName] = stats
	}

	return summary
}

// PrintResults outputs results in the configured format
func (sr *SuiteRunner) PrintResults(result *SuiteResult) error {
	switch sr.config.OutputFormat {
	case "json":
		return sr.printJSON(result)
	case "table":
		return sr.printTable(result)
	default:
		return sr.printTable(result)
	}
}

// printJSON outputs results as JSON
func (sr *SuiteRunner) printJSON(result *SuiteResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}

	if sr.config.OutputPath != "" {
		return os.WriteFile(sr.config.OutputPath, data, 0o644)
	}

	fmt.Println(string(data))
	return nil
}

// printTable outputs results as a formatted table
func (sr *SuiteRunner) printTable(result *SuiteResult) error {
	fmt.Println("\n========================================")
	fmt.Println("Benchmark Suite Results")
	fmt.Println("========================================")
	fmt.Printf("Timestamp: %s\n", result.Timestamp.Format(time.RFC3339))
	fmt.Printf("Duration: %s\n", result.Duration)
	fmt.Printf("Type: %s\n", result.Config.Type)
	fmt.Println()

	// Summary
	fmt.Println("--- Summary ---")
	fmt.Printf("Total Tests:   %d\n", result.Summary.TotalTests)
	fmt.Printf("Passed:        %d (%.1f%%)\n", result.Summary.PassedTests, float64(result.Summary.PassedTests)/float64(result.Summary.TotalTests)*100)
	fmt.Printf("Failed:        %d (%.1f%%)\n", result.Summary.FailedTests, float64(result.Summary.FailedTests)/float64(result.Summary.TotalTests)*100)
	fmt.Printf("Blocked:       %d (%.1f%%)\n", result.Summary.BlockedTests, float64(result.Summary.BlockedTests)/float64(result.Summary.TotalTests)*100)
	fmt.Println()

	// By Engine
	fmt.Println("--- By Engine ---")
	fmt.Printf("%-20s %8s %8s %8s %8s %12s\n", "Engine", "Total", "Passed", "Failed", "Blocked", "Avg Latency")
	fmt.Println(strings.Repeat("-", 72))
	for engineName, stats := range result.Summary.ByEngine {
		fmt.Printf("%-20s %8d %8d %8d %8d %12s\n",
			engineName, stats.Total, stats.Passed, stats.Failed, stats.Blocked, stats.AvgLatency)
	}
	fmt.Println()

	// By Category
	fmt.Println("--- By Category ---")
	fmt.Printf("%-20s %8s %8s %8s %8s\n", "Category", "Total", "Passed", "Failed", "Blocked")
	fmt.Println(strings.Repeat("-", 56))
	for cat, stats := range result.Summary.ByCategory {
		fmt.Printf("%-20s %8d %8d %8d %8d\n",
			cat, stats.Total, stats.Passed, stats.Failed, stats.Blocked)
	}
	fmt.Println()

	// Detailed results if verbose
	if sr.config.Verbose && len(result.EndpointResults) > 0 {
		fmt.Println("--- Detailed Results ---")
		for _, r := range result.EndpointResults {
			status := "✓"
			if !r.Success {
				status = "✗"
			}
			if r.Blocked {
				status = "🚫"
			}
			fmt.Printf("%s %-15s %-25s %s (%.2fs)\n",
				status, r.EngineName, r.Endpoint.Name, r.Endpoint.URL, r.Duration.Seconds())
		}
		fmt.Println()
	}

	// Capability report summary
	if result.CapabilityReport != nil {
		fmt.Println("--- Capability Report ---")
		fmt.Printf("Total Tests: %d, Passed: %d, Failed: %d\n",
			result.CapabilityReport.Summary.TotalTests,
			result.CapabilityReport.Summary.PassedTests,
			result.CapabilityReport.Summary.FailedTests)
		fmt.Println()
	}

	// Performance summary
	if len(result.PerformanceResults) > 0 {
		fmt.Println("--- Performance Summary ---")
		fmt.Printf("%-20s %8s %12s %12s %12s\n", "Engine", "Iters", "Avg", "Min", "Max")
		fmt.Println(strings.Repeat("-", 72))
		for _, pr := range result.PerformanceResults {
			fmt.Printf("%-20s %8d %12s %12s %12s\n",
				pr.EngineName, pr.Iterations, pr.AvgTime, pr.MinTime, pr.MaxTime)
		}
		fmt.Println()
	}

	fmt.Println("========================================")

	return nil
}
