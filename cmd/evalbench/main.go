// evalbench compares different HTTP clients against protected endpoints
// and measures their success rates, performance, and fingerprint characteristics.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/skunkworq/stealth/brws/browser/engine"
	_ "github.com/skunkworq/stealth/brws/browser/engine/browser/chromium"
	cstealth "github.com/skunkworq/stealth/brws/browser/engine/browser/chromium/stealth"
	_ "github.com/skunkworq/stealth/brws/browser/engine/browser/firefox"
	_ "github.com/skunkworq/stealth/brws/browser/engine/http/native"
	_ "github.com/skunkworq/stealth/brws/stealth/script/spoof"
	_ "github.com/skunkworq/stealth/brws/browser/engine/browser/webkit"
)

// TestTarget represents a URL to test against
type TestTarget struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	Description string `json:"description"`
	Expected    string `json:"expected"` // Substring expected in successful response
	BlockedBy   string `json:"blocked_by"`
}

// TestResult holds the result of a single test
type TestResult struct {
	Tool       string        `json:"tool"`
	Target     string        `json:"target"`
	URL        string        `json:"url"`
	Success    bool          `json:"success"`
	StatusCode int           `json:"status_code"`
	Duration   time.Duration `json:"duration"`
	BodySize   int           `json:"body_size"`
	Error      string        `json:"error,omitempty"`
	Blocked    bool          `json:"blocked"`
	Blocker    string        `json:"blocker,omitempty"`
	Evidence   string        `json:"evidence,omitempty"` // What indicates success/failure
}

// BenchmarkReport aggregates all test results
type BenchmarkReport struct {
	Timestamp time.Time        `json:"timestamp"`
	Targets   []TestTarget     `json:"targets"`
	Results   []TestResult     `json:"results"`
	Summary   BenchmarkSummary `json:"summary"`
}

// BenchmarkSummary provides aggregated stats
type BenchmarkSummary struct {
	TotalTests   int                    `json:"total_tests"`
	SuccessCount int                    `json:"success_count"`
	BlockedCount int                    `json:"blocked_count"`
	ErrorCount   int                    `json:"error_count"`
	ByTool       map[string]ToolSummary `json:"by_tool"`
}

// ToolSummary stats per tool
type ToolSummary struct {
	Total   int `json:"total"`
	Success int `json:"success"`
	Blocked int `json:"blocked"`
	Errors  int `json:"errors"`
}

var (
	// Predefined test targets
	defaultTargets = []TestTarget{
		{
			Name:        "coles-avocado",
			URL:         "https://www.coles.com.au/product/coles-hass-avocados-1-each-5900530",
			Description: "Coles supermarket product page (Incapsula protected)",
			Expected:    "avocado",
			BlockedBy:   "Incapsula",
		},
		{
			Name:        "httpbin-get",
			URL:         "https://httpbin.org/get",
			Description: "HttpBin test endpoint (no protection)",
			Expected:    "origin",
			BlockedBy:   "",
		},
		{
			Name:        "wikipedia",
			URL:         "https://en.wikipedia.org/wiki/Avocado",
			Description: "Wikipedia page (generally accessible)",
			Expected:    "Avocado",
			BlockedBy:   "",
		},
		{
			Name:        "linkedin-ben-ebsworth",
			URL:         "https://www.linkedin.com/in/ben-ebsworth/",
			Description: "LinkedIn profile page (heavily protected)",
			Expected:    "Ben",
			BlockedBy:   "LinkedIn",
		},
	}

	// Tools to test
	toolsToTest    []string
	timeout        time.Duration
	outputJSON     bool

	// Stealth options
	stealth        bool
	compareStealth bool
	headless       bool
	dwell          time.Duration
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "evalbench",
		Short: "Benchmark HTTP clients against protected endpoints",
		Long: `evalbench compares various HTTP clients (curl, curl-impersonate, brwslab engines)
against protected endpoints and measures success rates, performance, and fingerprint
effectiveness.`,
		RunE: runBenchmark,
	}

	rootCmd.Flags().StringArrayVar(&toolsToTest, "tools", []string{"all"}, "Tools to test (curl, curl-impersonate-chrome, curl-impersonate-ff, brwslab-native, brwslab-chromium, brwslab-chromium-stealth, brwslab-spoof-chrome, brwslab-spoof-firefox, all)")
	rootCmd.Flags().BoolVar(&stealth, "stealth", false, "Enable stealth mode (adds brwslab-chromium-stealth)")
	rootCmd.Flags().BoolVar(&compareStealth, "compare-stealth", false, "Run brwslab-chromium and brwslab-chromium-stealth back-to-back and print comparison")
	rootCmd.Flags().BoolVar(&headless, "headless", !detectDisplay(), "Run Chrome in headless mode (default: false on local desktop, true in cloud/SSH/container)")
	rootCmd.Flags().DurationVar(&timeout, "timeout", 60*time.Second, "Request timeout")
	rootCmd.Flags().DurationVar(&dwell, "dwell", 0, "Keep browser window open for N seconds after page load so you can visually inspect (e.g. 10s)")
	rootCmd.Flags().BoolVar(&outputJSON, "json", false, "Output results as JSON")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runBenchmark(cmd *cobra.Command, args []string) error {
	fmt.Println("=== HTTP Client Benchmark ===")
	fmt.Printf("Timestamp: %s\n\n", time.Now().Format(time.RFC3339))

	// Determine which tools to test
	tools := resolveTools(toolsToTest)

	report := BenchmarkReport{
		Timestamp: time.Now(),
		Targets:   defaultTargets,
		Results:   []TestResult{},
	}

	// Run tests for each tool against each target
	for _, tool := range tools {
		fmt.Printf("Testing: %s\n", tool)
		for _, target := range defaultTargets {
			result := testTool(tool, target)
			report.Results = append(report.Results, result)
			printResult(result)
		}
		fmt.Println()
	}

	// Generate summary
	report.Summary = generateSummary(report.Results)

	// Side-by-side stealth comparison
	if compareStealth {
		printStealthComparison(report.Results)
	}

	// Output
	if outputJSON {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal report: %w", err)
		}
		fmt.Println(string(data))
	} else {
		printSummary(report.Summary)
	}

	return nil
}

func resolveTools(tools []string) []string {
	if compareStealth {
		return []string{"brwslab-chromium", "brwslab-chromium-stealth"}
	}
	if len(tools) == 1 && tools[0] == "all" {
		allTools := []string{
			"curl",
			"curl-impersonate-chrome",
			"curl-impersonate-ff",
			"brwslab-native",
			"brwslab-spoof-chrome",
			"brwslab-spoof-firefox",
			"brwslab-chromium",
		}
		if stealth {
			allTools = append(allTools, "brwslab-chromium-stealth")
		}
		return allTools
	}
	return tools
}

func testTool(tool string, target TestTarget) TestResult {
	start := time.Now()
	result := TestResult{
		Tool:   tool,
		Target: target.Name,
		URL:    target.URL,
	}

	switch tool {
	case "curl":
		result = runCurl(target, start)
	case "curl-impersonate-chrome":
		result = runCurlImpersonateChrome(target, start)
	case "curl-impersonate-ff":
		result = runCurlImpersonateFirefox(target, start)
	case "brwslab-native":
		result = runBrwslabNative(target, start)
	case "brwslab-chromium-stealth":
		result = runBrwslabChromiumStealth(target, start)
	case "brwslab-spoof-chrome":
		result = runBrwslabSpoofChrome(target, start)
	case "brwslab-spoof-firefox":
		result = runBrwslabSpoofFirefox(target, start)
	case "brwslab-chromium":
		result = runBrwslabChromium(target, start)
	default:
		result.Error = "unknown tool"
	}

	return result
}

func runCurl(target TestTarget, start time.Time) TestResult {
	result := TestResult{
		Tool:   "curl",
		Target: target.Name,
		URL:    target.URL,
	}

	//nolint:gosec // Subprocess execution with validated input
	cmd := exec.Command("curl", "-s", "-L", "-m", fmt.Sprintf("%.0f", timeout.Seconds()),
		"-A", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		target.URL)

	output, err := cmd.CombinedOutput()
	result.Duration = time.Since(start)
	result.BodySize = len(output)

	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.StatusCode = 200 // curl returns success
	result.Success = checkSuccess(output, target)
	result.Blocked = checkBlocked(output, target)

	if result.Blocked {
		result.Blocker = target.BlockedBy
	}

	if result.Success {
		result.Evidence = fmt.Sprintf("found '%s'", target.Expected)
	} else if result.Blocked {
		result.Evidence = fmt.Sprintf("blocked by %s", result.Blocker)
	}

	return result
}

func runCurlImpersonateChrome(target TestTarget, start time.Time) TestResult {
	result := TestResult{
		Tool:   "curl-impersonate-chrome",
		Target: target.Name,
		URL:    target.URL,
	}

	//nolint:gosec // Subprocess execution with validated input
	cmd := exec.Command("docker", "run", "--rm",
		"lwthiker/curl-impersonate:0.6-chrome",
		"curl_chrome116",
		"-s", "-L", "-m", fmt.Sprintf("%.0f", timeout.Seconds()),
		target.URL)

	output, err := cmd.CombinedOutput()
	result.Duration = time.Since(start)
	result.BodySize = len(output)

	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.StatusCode = 200
	result.Success = checkSuccess(output, target)
	result.Blocked = checkBlocked(output, target)

	if result.Blocked {
		result.Blocker = target.BlockedBy
	}

	if result.Success {
		result.Evidence = fmt.Sprintf("found '%s'", target.Expected)
	} else if result.Blocked {
		result.Evidence = fmt.Sprintf("blocked by %s", result.Blocker)
	}

	return result
}

func runCurlImpersonateFirefox(target TestTarget, start time.Time) TestResult {
	result := TestResult{
		Tool:   "curl-impersonate-ff",
		Target: target.Name,
		URL:    target.URL,
	}

	//nolint:gosec // Subprocess execution with validated input
	cmd := exec.Command("docker", "run", "--rm",
		"lwthiker/curl-impersonate:0.6-ff",
		"curl_ff109",
		"-s", "-L", "-m", fmt.Sprintf("%.0f", timeout.Seconds()),
		target.URL)

	output, err := cmd.CombinedOutput()
	result.Duration = time.Since(start)
	result.BodySize = len(output)

	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.StatusCode = 200
	result.Success = checkSuccess(output, target)
	result.Blocked = checkBlocked(output, target)

	if result.Blocked {
		result.Blocker = target.BlockedBy
	}

	if result.Success {
		result.Evidence = fmt.Sprintf("found '%s'", target.Expected)
	} else if result.Blocked {
		result.Evidence = fmt.Sprintf("blocked by %s", result.Blocker)
	}

	return result
}

func runBrwslabNative(target TestTarget, start time.Time) TestResult {
	result := TestResult{
		Tool:   "brwslab-native",
		Target: target.Name,
		URL:    target.URL,
	}

	eng, err := engine.New("native", engine.Options{
		Timeout: timeout,
		HTTP2:   true,
	})
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer eng.Close()

	resp, err := eng.Do(context.Background(), &engine.Request{
		Method:          "GET",
		URL:             target.URL,
		FollowRedirects: true,
		Timeout:         timeout,
	})

	result.Duration = time.Since(start)

	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.StatusCode = resp.Status
	result.BodySize = len(resp.Body)
	result.Success = checkSuccess(resp.Body, target)
	result.Blocked = checkBlocked(resp.Body, target)

	if result.Blocked {
		result.Blocker = target.BlockedBy
	}

	if result.Success {
		result.Evidence = fmt.Sprintf("found '%s'", target.Expected)
	} else if result.Blocked {
		result.Evidence = fmt.Sprintf("blocked by %s", result.Blocker)
	}

	return result
}

func runBrwslabChromium(target TestTarget, start time.Time) TestResult {
	result := TestResult{
		Tool:   "brwslab-chromium",
		Target: target.Name,
		URL:    target.URL,
	}

	eng, err := engine.New("chromium", engine.Options{
		Timeout:  timeout,
		Headless: headless,
	})
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer eng.Close()

	resp, err := eng.Do(context.Background(), &engine.Request{
		Method:          "GET",
		URL:             target.URL,
		FollowRedirects: true,
		Timeout:         timeout,
	})

	// Dwell: keep browser open so user can visually inspect the page
	if dwell > 0 {
		fmt.Printf("  ⏳ Dwelling for %v...\n", dwell)
		time.Sleep(dwell)
	}

	result.Duration = time.Since(start)

	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.StatusCode = resp.Status
	result.BodySize = len(resp.Body)
	result.Success = checkSuccess(resp.Body, target)
	result.Blocked = checkBlocked(resp.Body, target)

	if result.Blocked {
		result.Blocker = target.BlockedBy
	}

	if result.Success {
		result.Evidence = fmt.Sprintf("found '%s'", target.Expected)
	} else if result.Blocked {
		result.Evidence = fmt.Sprintf("blocked by %s", result.Blocker)
	}

	return result
}

func runBrwslabSpoofChrome(target TestTarget, start time.Time) TestResult {
	result := TestResult{
		Tool:   "brwslab-spoof-chrome",
		Target: target.Name,
		URL:    target.URL,
	}

	eng, err := engine.New("spoof-chrome", engine.Options{
		Timeout: timeout,
		HTTP2:   true,
	})
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer eng.Close()

	resp, err := eng.Do(context.Background(), &engine.Request{
		Method:          "GET",
		URL:             target.URL,
		FollowRedirects: true,
		Timeout:         timeout,
	})

	// Dwell: keep browser open so user can visually inspect the page
	if dwell > 0 {
		fmt.Printf("  ⏳ Dwelling for %v...\n", dwell)
		time.Sleep(dwell)
	}

	result.Duration = time.Since(start)

	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.StatusCode = resp.Status
	result.BodySize = len(resp.Body)
	result.Success = checkSuccess(resp.Body, target)
	result.Blocked = checkBlocked(resp.Body, target)

	if result.Blocked {
		result.Blocker = target.BlockedBy
	}

	if result.Success {
		result.Evidence = fmt.Sprintf("found '%s'", target.Expected)
	} else if result.Blocked {
		result.Evidence = fmt.Sprintf("blocked by %s", result.Blocker)
	}

	return result
}

func runBrwslabSpoofFirefox(target TestTarget, start time.Time) TestResult {
	result := TestResult{
		Tool:   "brwslab-spoof-firefox",
		Target: target.Name,
		URL:    target.URL,
	}

	eng, err := engine.New("spoof-firefox", engine.Options{
		Timeout: timeout,
		HTTP2:   true,
	})
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer eng.Close()

	resp, err := eng.Do(context.Background(), &engine.Request{
		Method:          "GET",
		URL:             target.URL,
		FollowRedirects: true,
		Timeout:         timeout,
	})

	// Dwell: keep browser open so user can visually inspect the page
	if dwell > 0 {
		fmt.Printf("  ⏳ Dwelling for %v...\n", dwell)
		time.Sleep(dwell)
	}

	result.Duration = time.Since(start)

	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.StatusCode = resp.Status
	result.BodySize = len(resp.Body)
	result.Success = checkSuccess(resp.Body, target)
	result.Blocked = checkBlocked(resp.Body, target)

	if result.Blocked {
		result.Blocker = target.BlockedBy
	}

	if result.Success {
		result.Evidence = fmt.Sprintf("found '%s'", target.Expected)
	} else if result.Blocked {
		result.Evidence = fmt.Sprintf("blocked by %s", result.Blocker)
	}

	return result
}

func runBrwslabChromiumStealth(target TestTarget, start time.Time) TestResult {
	result := TestResult{
		Tool:   "brwslab-chromium-stealth",
		Target: target.Name,
		URL:    target.URL,
	}

	eng, err := engine.New("chromium-stealth", engine.Options{
		Timeout:  timeout,
		Headless: headless,
	})
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer eng.Close()

	// Disable human-like delays for benchmarking speed
	if stealthEng, ok := eng.(*cstealth.StealthEngine); ok {
		opts := cstealth.DefaultStealthOptions()
		opts.RandomDelays = false
		stealthEng.SetStealthOptions(opts)
	}

	resp, err := eng.Do(context.Background(), &engine.Request{
		Method:          "GET",
		URL:             target.URL,
		FollowRedirects: true,
		Timeout:         timeout,
	})

	// Dwell: keep browser open so user can visually inspect the page
	if dwell > 0 {
		fmt.Printf("  ⏳ Dwelling for %v...\n", dwell)
		time.Sleep(dwell)
	}

	result.Duration = time.Since(start)

	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.StatusCode = resp.Status
	result.BodySize = len(resp.Body)
	result.Success = checkSuccess(resp.Body, target)
	result.Blocked = checkBlocked(resp.Body, target)

	if result.Blocked {
		result.Blocker = target.BlockedBy
	}

	if result.Success {
		result.Evidence = fmt.Sprintf("found '%s'", target.Expected)
	} else if result.Blocked {
		result.Evidence = fmt.Sprintf("blocked by %s", result.Blocker)
	}

	return result
}

func checkSuccess(body []byte, target TestTarget) bool {
	if target.Expected == "" {
		return true
	}
	return bytes.Contains(bytes.ToLower(body), bytes.ToLower([]byte(target.Expected)))
}

func checkBlocked(body []byte, target TestTarget) bool {
	// Check for common WAF/blocking indicators
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
	}

	for _, indicator := range indicators {
		if bytes.Contains(body, []byte(indicator)) {
			return true
		}
	}

	// Check if body is very small (likely a block page)
	if len(body) < 1000 && target.BlockedBy != "" {
		return true
	}

	return false
}

func printResult(r TestResult) {
	status := "✓"
	if !r.Success {
		status = "✗"
	}
	if r.Error != "" {
		status = "!"
	}

	fmt.Printf("  %s %-25s -> %s (%.2fs, %d bytes)",
		status, r.Target, r.URL, r.Duration.Seconds(), r.BodySize)

	if r.Success {
		fmt.Printf(" [%s]", r.Evidence)
	} else if r.Blocked {
		fmt.Printf(" [BLOCKED by %s]", r.Blocker)
	} else if r.Error != "" {
		fmt.Printf(" [ERROR: %s]", r.Error)
	}
	fmt.Println()
}

func generateSummary(results []TestResult) BenchmarkSummary {
	summary := BenchmarkSummary{
		TotalTests: len(results),
		ByTool:     make(map[string]ToolSummary),
	}

	toolStats := make(map[string]*ToolSummary)

	for _, r := range results {
		stats, ok := toolStats[r.Tool]
		if !ok {
			stats = &ToolSummary{}
			toolStats[r.Tool] = stats
		}
		stats.Total++

		if r.Success {
			summary.SuccessCount++
			stats.Success++
		} else if r.Blocked {
			summary.BlockedCount++
			stats.Blocked++
		} else if r.Error != "" {
			summary.ErrorCount++
			stats.Errors++
		}
	}

	// Convert to map
	for tool, stats := range toolStats {
		summary.ByTool[tool] = *stats
	}

	return summary
}

func printSummary(summary BenchmarkSummary) {
	fmt.Println("=== Summary ===")
	fmt.Printf("Total tests:   %d\n", summary.TotalTests)
	fmt.Printf("Success:       %d (%.1f%%)\n", summary.SuccessCount, float64(summary.SuccessCount)/float64(summary.TotalTests)*100)
	fmt.Printf("Blocked:       %d (%.1f%%)\n", summary.BlockedCount, float64(summary.BlockedCount)/float64(summary.TotalTests)*100)
	fmt.Printf("Errors:        %d (%.1f%%)\n", summary.ErrorCount, float64(summary.ErrorCount)/float64(summary.TotalTests)*100)
	fmt.Println()

	fmt.Println("By Tool:")
	fmt.Printf("%-30s %8s %8s %8s %8s\n", "Tool", "Total", "Success", "Blocked", "Errors")
	fmt.Println(strings.Repeat("-", 64))
	for tool, stats := range summary.ByTool {
		fmt.Printf("%-30s %8d %8d %8d %8d\n", tool, stats.Total, stats.Success, stats.Blocked, stats.Errors)
	}
}

// printStealthComparison shows a side-by-side comparison of brwslab-chromium vs
// brwslab-chromium-stealth for each target.
func printStealthComparison(results []TestResult) {
	// Group results by target
	byTarget := make(map[string][]TestResult)
	for _, r := range results {
		byTarget[r.Target] = append(byTarget[r.Target], r)
	}

	fmt.Println()
	fmt.Println("=== Stealth Comparison: brwslab-chromium vs brwslab-chromium-stealth ===")
	fmt.Println()
	fmt.Printf("%-28s │ %-12s │ %-12s │ %-10s │ %s\n", "Target", "No Stealth", "Stealth", "Delta", "Winner")
	fmt.Println(strings.Repeat("─", 95))

	for target, targetResults := range byTarget {
		var plain, stealth *TestResult
		for i := range targetResults {
			if targetResults[i].Tool == "brwslab-chromium" {
				plain = &targetResults[i]
			} else if targetResults[i].Tool == "brwslab-chromium-stealth" {
				stealth = &targetResults[i]
			}
		}
		if plain == nil || stealth == nil {
			continue
		}

		plainStatus := statusEmoji(plain)
		stealthStatus := statusEmoji(stealth)

		var delta, winner string
		if plain.Success && !stealth.Success {
			delta = "stealth worse"
			winner = "plain"
		} else if !plain.Success && stealth.Success {
			delta = "stealth better"
			winner = "stealth"
		} else if plain.Success && stealth.Success {
			delta = "same"
			winner = "tie"
			if stealth.BodySize > plain.BodySize {
				delta = fmt.Sprintf("+%dB", stealth.BodySize-plain.BodySize)
			} else if stealth.BodySize < plain.BodySize {
				delta = fmt.Sprintf("-%dB", plain.BodySize-stealth.BodySize)
			}
		} else {
			delta = "same"
			winner = "tie"
		}

		fmt.Printf("%-28s │ %-12s │ %-12s │ %-10s │ %s\n",
			target, plainStatus, stealthStatus, delta, winner)
	}
	fmt.Println()
}

func statusEmoji(r *TestResult) string {
	if r.Success {
		return "✅ pass"
	}
	if r.Blocked {
		return "❌ blocked"
	}
	if r.Error != "" {
		return "💥 error"
	}
	return "?"
}

// detectDisplay returns true when running on a local desktop with a real
// display server (X11 or Wayland) — suitable for showing browser windows.
// Returns false for SSH sessions, containers, Kubernetes, and headless servers.
func detectDisplay() bool {
	// No DISPLAY or WAYLAND_DISPLAY means no GUI at all
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		return false
	}
	// SSH session — display is remote, not local
	if os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_CLIENT") != "" {
		return false
	}
	// Kubernetes / container environments
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return false
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return false
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return false
	}
	// Wayland session present — likely local desktop
	if os.Getenv("WAYLAND_DISPLAY") != "" {
		return true
	}
	// Verify X11 is actually reachable
	if os.Getenv("DISPLAY") != "" {
		if _, err := exec.LookPath("xset"); err == nil {
			cmd := exec.Command("xset", "q")
			cmd.Env = os.Environ()
			if err := cmd.Run(); err == nil {
				return true
			}
		}
		if _, err := exec.LookPath("xdpyinfo"); err == nil {
			cmd := exec.Command("xdpyinfo")
			cmd.Env = os.Environ()
			if err := cmd.Run(); err == nil {
				return true
			}
		}
	}
	return false
}
