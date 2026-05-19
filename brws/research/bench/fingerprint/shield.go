// Package benchmark provides comprehensive benchmarking capabilities
package fingerprintbench

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"

	"github.com/skunkworq/stealth/brws/stealth/challenge"
)

// ShieldSuiteConfig configures the shield evaluation benchmark.
type ShieldSuiteConfig struct {
	IncludeBehavioral bool // Include behavioral data in profiles
	Verbose           bool
}

// ShieldProfile represents an evasion strategy with optional behavioral/timing data.
type ShieldProfile struct {
	Name        string
	Category    string // "bare_bot", "basic_bot", "stealth", "advanced_stealth"
	ShouldCatch bool   // Whether shield SHOULD detect this as a bot
	BuildReq    func() *http.Request
}

// ShieldResult is the evaluation result for a single profile.
type ShieldResult struct {
	Profile      string             `json:"profile"`
	Category     string             `json:"category"`
	ShouldCatch  bool               `json:"should_catch"`
	BotScore     float64            `json:"bot_score"`
	IsBot        bool               `json:"is_bot"`
	Correct      bool               `json:"correct"` // true if detection matches expectation
	VectorScores map[string]float64 `json:"vector_scores"`
	Indicators   []string           `json:"indicators"`
}

// ShieldReport is the full evaluation report.
type ShieldReport struct {
	TotalProfiles  int                      `json:"total_profiles"`
	CorrectCount   int                      `json:"correct_count"`
	Accuracy       float64                  `json:"accuracy"`
	TruePositives  int                      `json:"true_positives"`
	FalseNegatives int                      `json:"false_negatives"`
	TrueNegatives  int                      `json:"true_negatives"`
	FalsePositives int                      `json:"false_positives"`
	Precision      float64                  `json:"precision"`
	Recall         float64                  `json:"recall"`
	F1Score        float64                  `json:"f1_score"`
	ByCategory     map[string]CategoryStats `json:"by_category"`
	VectorCoverage map[string]VectorStats   `json:"vector_coverage"`
	Results        []ShieldResult           `json:"results"`
}

// CategoryStats shows detection rates per category.
type CategoryStats struct {
	Total  int     `json:"total"`
	Caught int     `json:"caught"`
	Rate   float64 `json:"rate"`
}

// VectorStats shows how often each vector fires.
type VectorStats struct {
	Fires      int     `json:"fires"`
	TotalTests int     `json:"total_tests"`
	FireRate   float64 `json:"fire_rate"`
	AvgScore   float64 `json:"avg_score"`
}

// RunShieldEvaluation evaluates the shield detector against a comprehensive set of profiles.
func RunShieldEvaluation(cfg *ShieldSuiteConfig) *ShieldReport {
	if cfg == nil {
		cfg = &ShieldSuiteConfig{IncludeBehavioral: true}
	}

	detector := challenge.NewStealthDetector()
	profiles := buildAllProfiles(cfg.IncludeBehavioral)
	results := make([]ShieldResult, 0, len(profiles))

	for _, p := range profiles {
		req := p.BuildReq()
		detection := detector.AnalyzeRequest(req, nil)

		result := ShieldResult{
			Profile:      p.Name,
			Category:     p.Category,
			ShouldCatch:  p.ShouldCatch,
			BotScore:     detection.Score,
			IsBot:        detection.IsBot,
			VectorScores: make(map[string]float64),
			Indicators:   make([]string, 0),
		}

		for _, vec := range detection.Vectors {
			result.VectorScores[vec.Category] = vec.Score
			if vec.Detected {
				result.Indicators = append(result.Indicators, vec.Indicators...)
			}
		}

		// Correct if detection matches expectation
		result.Correct = (p.ShouldCatch && detection.IsBot) || (!p.ShouldCatch && !detection.IsBot)
		results = append(results, result)
	}

	return generateReport(results)
}

func generateReport(results []ShieldResult) *ShieldReport {
	report := &ShieldReport{
		TotalProfiles:  len(results),
		ByCategory:     make(map[string]CategoryStats),
		VectorCoverage: make(map[string]VectorStats),
		Results:        results,
	}

	for _, r := range results {
		if r.Correct {
			report.CorrectCount++
		}

		if r.ShouldCatch && r.IsBot {
			report.TruePositives++
		} else if r.ShouldCatch && !r.IsBot {
			report.FalseNegatives++
		} else if !r.ShouldCatch && !r.IsBot {
			report.TrueNegatives++
		} else if !r.ShouldCatch && r.IsBot {
			report.FalsePositives++
		}

		// Category stats
		cat := report.ByCategory[r.Category]
		cat.Total++
		if r.IsBot {
			cat.Caught++
		}
		cat.Rate = float64(cat.Caught) / float64(cat.Total)
		report.ByCategory[r.Category] = cat

		// Vector coverage
		for vec, score := range r.VectorScores {
			vs := report.VectorCoverage[vec]
			vs.TotalTests++
			if score > 0.3 {
				vs.Fires++
			}
			vs.AvgScore += score
			report.VectorCoverage[vec] = vs
		}
	}

	// Finalize averages
	for vec, vs := range report.VectorCoverage {
		if vs.TotalTests > 0 {
			vs.AvgScore /= float64(vs.TotalTests)
			vs.FireRate = float64(vs.Fires) / float64(vs.TotalTests)
		}
		report.VectorCoverage[vec] = vs
	}

	if report.TotalProfiles > 0 {
		report.Accuracy = float64(report.CorrectCount) / float64(report.TotalProfiles)
	}

	tp := float64(report.TruePositives)
	fp := float64(report.FalsePositives)
	fn := float64(report.FalseNegatives)

	if tp+fp > 0 {
		report.Precision = tp / (tp + fp)
	}
	if tp+fn > 0 {
		report.Recall = tp / (tp + fn)
	}
	if report.Precision+report.Recall > 0 {
		report.F1Score = 2 * (report.Precision * report.Recall) / (report.Precision + report.Recall)
	}

	return report
}

// PrintReport prints a formatted shield evaluation report.
func PrintReport(report *ShieldReport) {
	fmt.Println()
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║              SHIELD BENCHMARK EVALUATION REPORT              ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Summary metrics
	fmt.Println("━━━ Classification Metrics ━━━")
	fmt.Printf("  Accuracy:   %.1f%% (%d/%d correct)\n", report.Accuracy*100, report.CorrectCount, report.TotalProfiles)
	fmt.Printf("  Precision:  %.1f%% (of flagged bots, how many are real bots)\n", report.Precision*100)
	fmt.Printf("  Recall:     %.1f%% (of real bots, how many are caught)\n", report.Recall*100)
	fmt.Printf("  F1 Score:   %.3f\n", report.F1Score)
	fmt.Println()
	fmt.Printf("  TP: %d  FP: %d  TN: %d  FN: %d\n", report.TruePositives, report.FalsePositives, report.TrueNegatives, report.FalseNegatives)
	fmt.Println()

	// Category breakdown
	fmt.Println("━━━ Detection by Category ━━━")
	for cat, stats := range report.ByCategory {
		bar := strings.Repeat("█", int(math.Round(stats.Rate*20)))
		fmt.Printf("  %-20s: %d/%d caught (%5.1f%%) %s\n", cat, stats.Caught, stats.Total, stats.Rate*100, bar)
	}
	fmt.Println()

	// Vector coverage
	fmt.Println("━━━ Vector Coverage ━━━")
	fmt.Printf("  %-12s │ %5s │ %8s │ %8s\n", "Vector", "Fires", "FireRate", "AvgScore")
	fmt.Println("  " + strings.Repeat("─", 45))
	for vec, vs := range report.VectorCoverage {
		fmt.Printf("  %-12s │ %3d/%d │ %7.1f%% │ %8.3f\n", vec, vs.Fires, vs.TotalTests, vs.FireRate*100, vs.AvgScore)
	}
	fmt.Println()

	// Per-profile results
	fmt.Println("━━━ Per-Profile Results ━━━")
	fmt.Printf("  %-40s │ %5s │ %3s │ %7s │ %s\n", "Profile", "Score", "Bot", "Correct", "Category")
	fmt.Println("  " + strings.Repeat("─", 80))
	for _, r := range report.Results {
		botMark := "  "
		if r.IsBot {
			botMark = "!!"
		}
		correct := "YES"
		if !r.Correct {
			correct = "NO "
		}
		fmt.Printf("  %-40s │ %5.3f │ %s  │ %7s │ %s\n", r.Profile, r.BotScore, botMark, correct, r.Category)
	}
	fmt.Println()
}

// ExportReportJSON exports the report as JSON.
func ExportReportJSON(report *ShieldReport) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}

// buildAllProfiles creates a comprehensive set of evasion profiles for evaluation.
func buildAllProfiles(includeBehavioral bool) []ShieldProfile {
	profiles := []ShieldProfile{
		// Category: bare_bot — no evasion at all
		{Name: "curl_default", Category: "bare_bot", ShouldCatch: true, BuildReq: func() *http.Request {
			req, _ := http.NewRequest("GET", "http://test/", nil)
			req.Header.Set("User-Agent", "curl/8.5.0")
			return req
		}},
		{Name: "wget_default", Category: "bare_bot", ShouldCatch: true, BuildReq: func() *http.Request {
			req, _ := http.NewRequest("GET", "http://test/", nil)
			req.Header.Set("User-Agent", "Wget/1.21")
			return req
		}},
		{Name: "go_http_client", Category: "bare_bot", ShouldCatch: true, BuildReq: func() *http.Request {
			req, _ := http.NewRequest("GET", "http://test/", nil)
			req.Header.Set("User-Agent", "Go-http-client/2.0")
			return req
		}},
		{Name: "python_requests", Category: "bare_bot", ShouldCatch: true, BuildReq: func() *http.Request {
			req, _ := http.NewRequest("GET", "http://test/", nil)
			req.Header.Set("User-Agent", "python-requests/2.31.0")
			req.Header.Set("Accept", "*/*")
			req.Header.Set("Accept-Encoding", "gzip, deflate")
			req.Header.Set("Connection", "keep-alive")
			return req
		}},
		{Name: "scrapy_bot", Category: "bare_bot", ShouldCatch: true, BuildReq: func() *http.Request {
			req, _ := http.NewRequest("GET", "http://test/", nil)
			req.Header.Set("User-Agent", "Scrapy/2.11.0 (+https://scrapy.org)")
			req.Header.Set("Accept", "text/html,application/xhtml+xml")
			return req
		}},
		{Name: "no_ua", Category: "bare_bot", ShouldCatch: true, BuildReq: func() *http.Request {
			req, _ := http.NewRequest("GET", "http://test/", nil)
			return req
		}},

		// Category: basic_bot — UA spoofed, but other signals missing
		{Name: "headless_chrome_raw", Category: "basic_bot", ShouldCatch: true, BuildReq: func() *http.Request {
			req, _ := http.NewRequest("GET", "http://test/", nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/134.0.0.0 Safari/537.36")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			req.Header.Set("Accept-Encoding", "gzip, deflate, br")
			return req
		}},
		{Name: "selenium_webdriver_exposed", Category: "basic_bot", ShouldCatch: true, BuildReq: func() *http.Request {
			req, _ := http.NewRequest("GET", "http://test/", nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			req.Header.Set("Accept-Encoding", "gzip, deflate, br")
			req.Header.Set("X-Navigator-Webdriver", "true")
			return req
		}},
		{Name: "chrome_no_sec_fetch", Category: "basic_bot", ShouldCatch: true, BuildReq: func() *http.Request {
			req, _ := http.NewRequest("GET", "http://test/", nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			req.Header.Set("Accept-Encoding", "gzip, deflate, br")
			// No Sec-Fetch-* or Sec-Ch-Ua — real Chrome always sends these
			return req
		}},

		// Category: stealth — proper header impersonation
		{Name: "stealth_chrome_no_hints", Category: "stealth", ShouldCatch: false, BuildReq: func() *http.Request {
			req, _ := http.NewRequest("GET", "http://test/", nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			req.Header.Set("Accept-Encoding", "gzip, deflate, br")
			req.Header.Set("Upgrade-Insecure-Requests", "1")
			req.Header.Set("Sec-Fetch-Dest", "document")
			req.Header.Set("Sec-Fetch-Mode", "navigate")
			req.Header.Set("Sec-Fetch-Site", "none")
			req.Header.Set("Sec-Fetch-User", "?1")
			return req
		}},
		{Name: "stealth_chrome_full", Category: "stealth", ShouldCatch: false, BuildReq: func() *http.Request {
			req, _ := http.NewRequest("GET", "http://test/", nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
			req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
			req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
			req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
			req.Header.Set("Sec-Fetch-Dest", "document")
			req.Header.Set("Sec-Fetch-Mode", "navigate")
			req.Header.Set("Sec-Fetch-Site", "none")
			req.Header.Set("Sec-Fetch-User", "?1")
			req.Header.Set("Upgrade-Insecure-Requests", "1")
			return req
		}},
		{Name: "stealth_firefox", Category: "stealth", ShouldCatch: false, BuildReq: func() *http.Request {
			req, _ := http.NewRequest("GET", "http://test/", nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
			req.Header.Set("Accept-Language", "en-US,en;q=0.5")
			req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
			req.Header.Set("Connection", "keep-alive")
			req.Header.Set("Upgrade-Insecure-Requests", "1")
			req.Header.Set("Sec-Fetch-Dest", "document")
			req.Header.Set("Sec-Fetch-Mode", "navigate")
			req.Header.Set("Sec-Fetch-Site", "none")
			req.Header.Set("Sec-Fetch-User", "?1")
			req.Header.Set("DNT", "1")
			return req
		}},
		{Name: "playwright_stealth", Category: "stealth", ShouldCatch: false, BuildReq: func() *http.Request {
			req, _ := http.NewRequest("GET", "http://test/", nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
			req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
			req.Header.Set("Sec-Ch-Ua-Platform", `"macOS"`)
			req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
			req.Header.Set("Sec-Fetch-Dest", "document")
			req.Header.Set("Sec-Fetch-Mode", "navigate")
			req.Header.Set("Sec-Fetch-Site", "none")
			req.Header.Set("Sec-Fetch-User", "?1")
			req.Header.Set("Upgrade-Insecure-Requests", "1")
			return req
		}},
	}

	// New vector profiles — WebGL, font, plugin, screen, timing
	profiles = append(profiles,
		// WebGL spoofed (SwiftShader masked as NVIDIA) → should catch
		ShieldProfile{Name: "webgl_swiftshader_spoofed", Category: "basic_bot", ShouldCatch: true, BuildReq: func() *http.Request {
			req, _ := http.NewRequest("GET", "http://test/", nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
			req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
			req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
			req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
			req.Header.Set("Sec-Fetch-Dest", "document")
			req.Header.Set("Sec-Fetch-Mode", "navigate")
			req.Header.Set("Sec-Fetch-Site", "none")
			req.Header.Set("Upgrade-Insecure-Requests", "1")
			req.Header.Set("X-WebGL-Data", `{"vendor":"Google Inc.","renderer":"NVIDIA GeForce RTX 4070","unmasked_vendor":"Google Inc.","unmasked_renderer":"Google SwiftShader","version":"WebGL 2.0","platform":"Win32","webgl2_supported":true}`)
			return req
		}},
		// Empty plugins on Chrome → should catch
		ShieldProfile{Name: "empty_plugins_chrome", Category: "basic_bot", ShouldCatch: true, BuildReq: func() *http.Request {
			req, _ := http.NewRequest("GET", "http://test/", nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
			req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
			req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
			req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
			req.Header.Set("Sec-Fetch-Dest", "document")
			req.Header.Set("Sec-Fetch-Mode", "navigate")
			req.Header.Set("Sec-Fetch-Site", "none")
			req.Header.Set("Upgrade-Insecure-Requests", "1")
			req.Header.Set("X-Plugin-Data", `{"plugins":[],"plugin_count":0}`)
			return req
		}},
		// Headless screen geometry → should catch
		ShieldProfile{Name: "headless_screen_geometry", Category: "basic_bot", ShouldCatch: true, BuildReq: func() *http.Request {
			req, _ := http.NewRequest("GET", "http://test/", nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
			req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
			req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
			req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
			req.Header.Set("Sec-Fetch-Dest", "document")
			req.Header.Set("Sec-Fetch-Mode", "navigate")
			req.Header.Set("Sec-Fetch-Site", "none")
			req.Header.Set("Upgrade-Insecure-Requests", "1")
			req.Header.Set("X-Screen-Data", `{"width":800,"height":600,"avail_width":800,"avail_height":600,"color_depth":24,"pixel_ratio":1.0,"outer_width":800,"outer_height":600,"inner_width":800,"inner_height":600}`)
			return req
		}},
		// Minimal fonts on headless Linux → should catch
		ShieldProfile{Name: "minimal_fonts_headless", Category: "basic_bot", ShouldCatch: true, BuildReq: func() *http.Request {
			req, _ := http.NewRequest("GET", "http://test/", nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
			req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
			req.Header.Set("Sec-Ch-Ua-Platform", `"Linux"`)
			req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
			req.Header.Set("Sec-Fetch-Dest", "document")
			req.Header.Set("Sec-Fetch-Mode", "navigate")
			req.Header.Set("Sec-Fetch-Site", "none")
			req.Header.Set("Upgrade-Insecure-Requests", "1")
			req.Header.Set("X-Font-Data", `{"fonts":["Arial","Times New Roman","Courier New","Georgia","Verdana","Trebuchet MS","Impact","Comic Sans MS"],"font_count":8,"platform":"linux"}`)
			return req
		}},
		// Fixed timing intervals → should catch
		ShieldProfile{Name: "fixed_timing_100ms", Category: "basic_bot", ShouldCatch: true, BuildReq: func() *http.Request {
			req, _ := http.NewRequest("GET", "http://test/", nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
			req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
			req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
			req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
			req.Header.Set("Sec-Fetch-Dest", "document")
			req.Header.Set("Sec-Fetch-Mode", "navigate")
			req.Header.Set("Sec-Fetch-Site", "none")
			req.Header.Set("Upgrade-Insecure-Requests", "1")
			req.Header.Set("X-Timing-Data", `{"entries":[{"timestamp_ms":0,"content_type":"text/html"},{"timestamp_ms":100,"content_type":"text/css"},{"timestamp_ms":200,"content_type":"application/javascript"},{"timestamp_ms":300,"content_type":"image/png"},{"timestamp_ms":400,"content_type":"image/jpeg"}]}`)
			return req
		}},
		// Perfect stealth with all valid headers → should NOT catch
		ShieldProfile{Name: "perfect_stealth_all_vectors", Category: "stealth", ShouldCatch: false, BuildReq: func() *http.Request {
			req, _ := http.NewRequest("GET", "http://test/", nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
			req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
			req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
			req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
			req.Header.Set("Sec-Fetch-Dest", "document")
			req.Header.Set("Sec-Fetch-Mode", "navigate")
			req.Header.Set("Sec-Fetch-Site", "none")
			req.Header.Set("Sec-Fetch-User", "?1")
			req.Header.Set("Upgrade-Insecure-Requests", "1")
			return req
		}},
		// Datacenter IP with good headers → should NOT catch (IP alone isn't enough)
		ShieldProfile{Name: "datacenter_ip_good_headers", Category: "stealth", ShouldCatch: false, BuildReq: func() *http.Request {
			req, _ := http.NewRequest("GET", "http://test/", nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
			req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
			req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
			req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
			req.Header.Set("Sec-Fetch-Dest", "document")
			req.Header.Set("Sec-Fetch-Mode", "navigate")
			req.Header.Set("Sec-Fetch-Site", "none")
			req.Header.Set("Sec-Fetch-User", "?1")
			req.Header.Set("Upgrade-Insecure-Requests", "1")
			req.Header.Set("X-Forwarded-For", "3.12.45.67")
			return req
		}},
		// Spoofed plugin array → should catch
		ShieldProfile{Name: "spoofed_plugin_array", Category: "basic_bot", ShouldCatch: true, BuildReq: func() *http.Request {
			req, _ := http.NewRequest("GET", "http://test/", nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
			req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
			req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
			req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
			req.Header.Set("Sec-Fetch-Dest", "document")
			req.Header.Set("Sec-Fetch-Mode", "navigate")
			req.Header.Set("Sec-Fetch-Site", "none")
			req.Header.Set("Upgrade-Insecure-Requests", "1")
			req.Header.Set("X-Plugin-Data", `{"plugins":[{"name":"0","filename":""},{"name":"0","filename":""},{"name":"0","filename":""},{"name":"0","filename":""},{"name":"0","filename":""}],"plugin_count":5}`)
			return req
		}},
	)

	// Behavioral profiles — only when enabled
	if includeBehavioral {
		profiles = append(profiles,
			// Stealth with bot-like behavior should be caught
			ShieldProfile{Name: "stealth_chrome_bot_behavior", Category: "advanced_stealth", ShouldCatch: true, BuildReq: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://test/", nil)
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
				req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
				req.Header.Set("Accept-Language", "en-US,en;q=0.9")
				req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
				req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
				req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
				req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
				req.Header.Set("Sec-Fetch-Dest", "document")
				req.Header.Set("Sec-Fetch-Mode", "navigate")
				req.Header.Set("Sec-Fetch-Site", "none")
				req.Header.Set("Sec-Fetch-User", "?1")
				req.Header.Set("Upgrade-Insecure-Requests", "1")
				req.Header.Set("X-Behavioral-Data", `{
					"mouseTimestamps": [0,100,200,300,400,500,600,700,800,900],
					"typingTimestamps": [0,100,200,300,400,500,600,700],
					"mousePositions": [
						{"x":0,"y":0},{"x":50,"y":50},{"x":100,"y":100},
						{"x":150,"y":150},{"x":200,"y":200},{"x":250,"y":250},
						{"x":300,"y":300},{"x":350,"y":350},{"x":400,"y":400},
						{"x":450,"y":450},{"x":500,"y":500}
					],
					"mouseVelocities": [707,707,707,707,707,707,707,707]
				}`)
				return req
			}},
			// Stealth with human-like behavior should pass
			ShieldProfile{Name: "stealth_chrome_human_behavior", Category: "advanced_stealth", ShouldCatch: false, BuildReq: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://test/", nil)
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
				req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
				req.Header.Set("Accept-Language", "en-US,en;q=0.9")
				req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
				req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
				req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
				req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
				req.Header.Set("Sec-Fetch-Dest", "document")
				req.Header.Set("Sec-Fetch-Mode", "navigate")
				req.Header.Set("Sec-Fetch-Site", "none")
				req.Header.Set("Sec-Fetch-User", "?1")
				req.Header.Set("Upgrade-Insecure-Requests", "1")
				req.Header.Set("X-Behavioral-Data", `{
					"mouseTimestamps": [0,32,48,91,152,184,267,345,391,480,512,599,678,745,812,890,965,1040,1120,1200],
					"typingTimestamps": [0,87,143,231,312,398,511,602],
					"mousePositions": [
						{"x":100,"y":200},{"x":102,"y":201},{"x":105,"y":198},{"x":112,"y":195},
						{"x":118,"y":202},{"x":125,"y":210},{"x":127,"y":212},{"x":130,"y":215},
						{"x":138,"y":208},{"x":142,"y":203},{"x":150,"y":198},{"x":151,"y":199},
						{"x":155,"y":205},{"x":162,"y":218},{"x":170,"y":230},{"x":172,"y":231},
						{"x":178,"y":225},{"x":185,"y":220},{"x":192,"y":228},{"x":200,"y":235}
					],
					"mouseVelocities": [50,80,120,90,110,40,70,95,130,60,20,85,140,100,30,75,105,115,80]
				}`)
				return req
			}},
			// Bot with puppeteer-humanized behavior — borderline case, current shield may miss
			ShieldProfile{Name: "puppeteer_humanized_behavior", Category: "advanced_stealth", ShouldCatch: false, BuildReq: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://test/", nil)
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
				req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
				req.Header.Set("Accept-Language", "en-US,en;q=0.9")
				req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
				req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
				req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
				req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
				req.Header.Set("Sec-Fetch-Dest", "document")
				req.Header.Set("Sec-Fetch-Mode", "navigate")
				req.Header.Set("Sec-Fetch-Site", "none")
				req.Header.Set("Sec-Fetch-User", "?1")
				req.Header.Set("Upgrade-Insecure-Requests", "1")
				// Slightly humanized but still has straight-line movement
				req.Header.Set("X-Behavioral-Data", `{
					"mouseTimestamps": [0,83,178,290,412,510,635,788,890,1020],
					"mousePositions": [
						{"x":0,"y":0},{"x":25,"y":18},{"x":55,"y":42},{"x":90,"y":58},
						{"x":130,"y":80},{"x":165,"y":105},{"x":195,"y":135},
						{"x":230,"y":160},{"x":270,"y":190},{"x":310,"y":215}
					],
					"mouseVelocities": [350,420,380,500,320,450,400,360]
				}`)
				return req
			}},
		)
	}

	return profiles
}
