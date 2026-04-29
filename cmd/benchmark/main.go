// benchmark provides comprehensive HTTP client benchmarking across multiple
// dimensions: endpoints, capabilities, fingerprint consistency, and performance.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/skunkworq/stealth/brws/fingerprint/bench"
	"github.com/skunkworq/stealth/brws/browser/engine"
	_ "github.com/skunkworq/stealth/brws/browser/engine/chromium"
	_ "github.com/skunkworq/stealth/brws/browser/engine/firefox"
	_ "github.com/skunkworq/stealth/brws/browser/engine/native"
	_ "github.com/skunkworq/stealth/brws/browser/engine/webkit"
)

var (
	// Engine selection
	engines []string

	// Test configuration
	categories  []string
	suiteType   string
	iterations  int
	timeout     time.Duration
	parallel    bool
	maxParallel int

	// Output configuration
	outputFormat string
	outputPath   string
	verbose      bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "benchmark",
		Short: "Comprehensive HTTP client benchmark suite",
		Long: `benchmark provides comprehensive testing across multiple dimensions:

1. Endpoint Testing - Test against various endpoints with different protection levels
2. Capability Testing - Verify engine capabilities (JS, HTTP/2, HTTP/3, WebSocket)
3. Fingerprint Consistency - Test fingerprint stability across requests
4. Performance Benchmarking - Measure request latency and throughput

Examples:
  # Run all tests against all engines
  benchmark --suite all

  # Test specific categories
  benchmark --suite endpoints --categories basic,protocol,javascript

  # Test specific engines
  benchmark --engines native,chromium,firefox

  # Capability evaluation only
  benchmark --suite capabilities

  # Fingerprint consistency test
  benchmark --suite fingerprint --iterations 5

  # Performance benchmark
  benchmark --suite performance --iterations 10

  # Output as JSON
  benchmark --suite all --format json --output results.json`,
		RunE: runBenchmark,
	}

	// Global flags
	rootCmd.PersistentFlags().StringArrayVar(&engines, "engines", []string{}, "Engines to test (default: all available)")
	rootCmd.PersistentFlags().StringArrayVar(&categories, "categories", []string{}, "Endpoint categories to test (basic, protocol, javascript, websocket, content, protected, cloudflare, api, ecommerce, social)")
	rootCmd.PersistentFlags().StringVar(&suiteType, "suite", "endpoints", "Suite type (endpoints, capabilities, fingerprint, performance, all)")
	rootCmd.PersistentFlags().IntVar(&iterations, "iterations", 3, "Number of iterations for fingerprint/performance tests")
	rootCmd.PersistentFlags().DurationVar(&timeout, "timeout", 30*time.Second, "Request timeout")
	rootCmd.PersistentFlags().BoolVar(&parallel, "parallel", false, "Run tests in parallel")
	rootCmd.PersistentFlags().IntVar(&maxParallel, "max-parallel", 4, "Maximum parallel tests")
	rootCmd.PersistentFlags().StringVar(&outputFormat, "format", "table", "Output format (table, json)")
	rootCmd.PersistentFlags().StringVar(&outputPath, "output", "", "Output file path (default: stdout)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	// Add subcommands
	rootCmd.AddCommand(listCmd())
	rootCmd.AddCommand(enginesCmd())
	rootCmd.AddCommand(shieldCmd())
	rootCmd.AddCommand(compareCmd())
	rootCmd.AddCommand(blackboxCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runBenchmark(cmd *cobra.Command, args []string) error {
	// Validate suite type
	validSuites := map[string]benchmark.SuiteType{
		"endpoints":    benchmark.SuiteEndpoints,
		"capabilities": benchmark.SuiteCapabilities,
		"fingerprint":  benchmark.SuiteFingerprint,
		"performance":  benchmark.SuitePerformance,
		"all":          benchmark.SuiteAll,
	}

	suite, ok := validSuites[suiteType]
	if !ok {
		return fmt.Errorf("invalid suite type: %s (valid: endpoints, capabilities, fingerprint, performance, all)", suiteType)
	}

	// Get engines if not specified
	if len(engines) == 0 {
		engines = benchmark.GetAllEngines()
	}

	if verbose {
		fmt.Printf("Benchmark Configuration:\n")
		fmt.Printf("  Suite: %s\n", suiteType)
		fmt.Printf("  Engines: %s\n", strings.Join(engines, ", "))
		fmt.Printf("  Categories: %s\n", strings.Join(categories, ", "))
		fmt.Printf("  Iterations: %d\n", iterations)
		fmt.Printf("  Timeout: %s\n", timeout)
		fmt.Println()
	}

	// Create config
	config := benchmark.SuiteConfig{
		Type:         suite,
		Engines:      engines,
		Categories:   categories,
		Iterations:   iterations,
		Timeout:      timeout,
		Parallel:     parallel,
		MaxParallel:  maxParallel,
		OutputFormat: outputFormat,
		OutputPath:   outputPath,
		Verbose:      verbose,
	}

	// Create and run suite
	runner := benchmark.NewSuiteRunner(config)
	ctx := context.Background()

	fmt.Printf("Running benchmark suite: %s\n", suiteType)
	start := time.Now()

	result, err := runner.Run(ctx)
	if err != nil {
		return fmt.Errorf("benchmark failed: %w", err)
	}

	duration := time.Since(start)
	fmt.Printf("Completed in %s\n", duration)

	// Print results
	if err := runner.PrintResults(result); err != nil {
		return fmt.Errorf("failed to print results: %w", err)
	}

	// Exit with error code if tests failed
	if result.Summary.FailedTests > 0 || result.Summary.BlockedTests > 0 {
		totalTests := result.Summary.TotalTests
		if totalTests > 0 {
			successRate := float64(result.Summary.PassedTests) / float64(totalTests)
			fmt.Printf("\nSuccess rate: %.1f%% (%d/%d tests passed)\n",
				successRate*100, result.Summary.PassedTests, totalTests)

			if successRate < 0.5 {
				os.Exit(1)
			}
		}
	}

	return nil
}

func listCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List available endpoints and categories",
		RunE: func(cmd *cobra.Command, args []string) error {
			categories := benchmark.DefaultEndpoints()

			fmt.Println("Available Endpoint Categories:")
			fmt.Println("==============================")

			for _, cat := range categories {
				fmt.Printf("\n%s - %s\n", cat.Name, cat.Description)
				fmt.Println(strings.Repeat("-", 40))

				for _, ep := range cat.Endpoints {
					fmt.Printf("  %-25s %s\n", ep.Name, ep.URL)
					if ep.Protection != "none" {
						fmt.Printf("    Protection: %s\n", ep.Protection)
					}
					if len(ep.RequiredCaps) > 0 {
						caps := make([]string, len(ep.RequiredCaps))
						for i, c := range ep.RequiredCaps {
							caps[i] = string(c)
						}
						fmt.Printf("    Requires: %s\n", strings.Join(caps, ", "))
					}
				}
			}

			fmt.Println("\n\nProtection Levels:")
			fmt.Println("  none       - No protection")
			fmt.Println("  basic      - Basic rate limiting")
			fmt.Println("  cloudflare - Cloudflare protection")
			fmt.Println("  incapsula  - Incapsula/Imperva protection")
			fmt.Println("  datadome   - DataDome protection")
			fmt.Println("  custom     - Custom/proprietary protection")

			fmt.Println("\n\nCapabilities:")
			fmt.Println("  javascript       - JavaScript execution")
			fmt.Println("  http2            - HTTP/2 support")
			fmt.Println("  http3            - HTTP/3/QUIC support")
			fmt.Println("  websocket        - WebSocket support")
			fmt.Println("  intercept        - Request interception")
			fmt.Println("  persistent_prof  - Persistent browser profiles")
			fmt.Println("  netlog           - Network logging")

			return nil
		},
	}
}

func shieldCmd() *cobra.Command {
	var includeBehavioral bool
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "shield",
		Short: "Evaluate shield detection effectiveness against evasion profiles",
		Long: `Runs the shield detector against a comprehensive set of evasion profiles
ranging from bare bots (curl, python-requests) to advanced stealth (full Chrome
impersonation with behavioral data). Reports accuracy, precision, recall, F1
score, and per-vector coverage.

Examples:
  # Full shield evaluation with behavioral data
  benchmark shield

  # HTTP-only evaluation (no behavioral data)
  benchmark shield --no-behavioral

  # JSON output
  benchmark shield --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := &benchmark.ShieldSuiteConfig{
				IncludeBehavioral: includeBehavioral,
				Verbose:           verbose,
			}

			report := benchmark.RunShieldEvaluation(cfg)

			if jsonOutput {
				data, err := benchmark.ExportReportJSON(report)
				if err != nil {
					return err
				}
				fmt.Println(string(data))
			} else {
				benchmark.PrintReport(report)
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&includeBehavioral, "behavioral", true, "Include behavioral analysis profiles")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output as JSON")

	return cmd
}

func compareCmd() *cobra.Command {
	var includeBehavioral bool
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "compare",
		Short: "Compare shield detection rate across popular scraping/automation tools",
		Long: `Runs the shield detector against accurate HTTP request profiles for 10
popular scraping and automation tools, then ranks them by evasion rate.
Shows which vectors fire against which tools and whether our stealth
sword outperforms the competition.

Tools compared:
  python-requests, Scrapy, Playwright (default), Puppeteer (default),
  curl-impersonate, nodriver, Scrapling (stealthy), Scrapling (playwright),
  our stealth sword (positive control), our broken stealth (negative control)

Examples:
  benchmark compare              # formatted report
  benchmark compare --json       # JSON output for CI
  benchmark compare -v           # verbose per-vector detail`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := &benchmark.ToolComparisonConfig{
				IncludeBehavioral: includeBehavioral,
				Iterations:        1,
				Verbose:           verbose,
			}

			report := benchmark.RunToolComparison(cfg)

			if jsonOutput {
				data, err := benchmark.ExportComparisonJSON(report)
				if err != nil {
					return err
				}
				fmt.Println(string(data))
			} else {
				benchmark.PrintComparisonReport(report)
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&includeBehavioral, "behavioral", true, "Include behavioral analysis in evaluation")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output as JSON")

	return cmd
}

func blackboxCmd() *cobra.Command {
	var (
		baseURL        string
		toolNames      []string
		pythonBin      string
		allowMissing   bool
		insecureTLS    bool
		jsonOutput     bool
		includeModeled bool
	)

	cmd := &cobra.Command{
		Use:   "blackbox",
		Short: "Run real external scraping tools against the local lab and shield",
		Long: `Runs real tool processes against the owned lab endpoints instead of
modeled request profiles. Each tool is probed in two phases:

1. /capture/json      - raw fingerprint capture
2. /api/stealth-test  - shield scoring

This is intended for defensive benchmarking of real locally installed tools,
not for tuning or improving evasion behavior.

Examples:
  benchmark blackbox --base-url http://127.0.0.1:8080
  benchmark blackbox --tools scrapy_default,nodriver
  benchmark blackbox --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			tools := benchmark.DefaultBlackboxToolSpecs(pythonBin)
			tools = benchmark.FilterBlackboxTools(tools, toolNames)
			if len(tools) == 0 {
				return fmt.Errorf("no blackbox tools selected")
			}

			report, err := benchmark.RunBlackboxBenchmark(context.Background(), &benchmark.BlackboxConfig{
				BaseURL:                  baseURL,
				InsecureTLS:              insecureTLS,
				Tools:                    tools,
				AllowMissing:             allowMissing,
				IncludeModeledComparison: includeModeled,
				Verbose:                  verbose,
			})
			if err != nil {
				return err
			}

			if jsonOutput {
				data, err := benchmark.ExportBlackboxJSON(report)
				if err != nil {
					return err
				}
				fmt.Println(string(data))
				return nil
			}

			benchmark.PrintBlackboxReport(report)
			return nil
		},
	}

	cmd.Flags().StringVar(&baseURL, "base-url", "http://127.0.0.1:8080", "Base URL for the owned lab server")
	cmd.Flags().StringSliceVar(&toolNames, "tools", nil, "Tool names to run (default: all built-in blackbox presets)")
	cmd.Flags().StringVar(&pythonBin, "python", "python3", "Python binary to use for Python-based tool probes")
	cmd.Flags().BoolVar(&allowMissing, "allow-missing", true, "Skip unavailable local tools instead of failing")
	cmd.Flags().BoolVar(&insecureTLS, "insecure-tls", false, "Allow self-signed TLS for local HTTPS lab endpoints")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output as JSON")
	cmd.Flags().BoolVar(&includeModeled, "modeled", true, "Include modeled profile comparison data")

	return cmd
}

func enginesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "engines",
		Short: "List available engines",
		RunE: func(cmd *cobra.Command, args []string) error {
			engines := benchmark.GetAllEngines()

			fmt.Println("Available Engines:")
			fmt.Println("==================")

			for _, name := range engines {
				eng, err := engine.New(name, engine.Options{Headless: true})
				if err != nil {
					fmt.Printf("  %-15s (error: %v)\n", name, err)
					continue
				}

				caps := eng.Capabilities()
				fmt.Printf("  %-15s JS:%t HTTP2:%t HTTP3:%t WS:%t\n",
					name,
					caps.JavaScript,
					caps.HTTP2,
					caps.HTTP3,
					caps.WebSocket)
				eng.Close()
			}

			fmt.Println("\nLegend:")
			fmt.Println("  JS    - JavaScript execution support")
			fmt.Println("  HTTP2 - HTTP/2 protocol support")
			fmt.Println("  HTTP3 - HTTP/3/QUIC protocol support")
			fmt.Println("  WS    - WebSocket support")

			return nil
		},
	}
}
