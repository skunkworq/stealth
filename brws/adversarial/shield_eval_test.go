package adversarial

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// EvasionProfile represents a specific stealth configuration strategy.
type EvasionProfile struct {
	Name        string
	Description string
	BuildReq    func() *http.Request
}

// ShieldEvalResult is the evaluation output for a single profile.
type ShieldEvalResult struct {
	Profile    string
	BotScore   float64
	IsBot      bool
	Vectors    map[string]float64 // vector name → score
	Indicators []string
}

// buildEvasionProfiles returns a set of evasion strategies from "no evasion" to "full stealth".
func buildEvasionProfiles() []EvasionProfile {
	return []EvasionProfile{
		{
			Name:        "bare_curl",
			Description: "Raw curl — no headers, no stealth",
			BuildReq: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://localhost:8080/api/ml/trap", nil)
				req.Header.Set("User-Agent", "curl/8.5.0")
				return req
			},
		},
		{
			Name:        "python_requests",
			Description: "Python requests library defaults",
			BuildReq: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://localhost:8080/api/ml/trap", nil)
				req.Header.Set("User-Agent", "python-requests/2.31.0")
				req.Header.Set("Accept", "*/*")
				req.Header.Set("Accept-Encoding", "gzip, deflate")
				req.Header.Set("Connection", "keep-alive")
				return req
			},
		},
		{
			Name:        "headless_chrome_raw",
			Description: "Headless Chrome — webdriver exposed, no stealth",
			BuildReq: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://localhost:8080/api/ml/trap", nil)
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/134.0.0.0 Safari/537.36")
				req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
				req.Header.Set("Accept-Language", "en-US,en;q=0.9")
				req.Header.Set("Accept-Encoding", "gzip, deflate, br")
				req.Header.Set("X-Navigator-Webdriver", "true")
				return req
			},
		},
		{
			Name:        "selenium_basic",
			Description: "Selenium with basic UA spoofing",
			BuildReq: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://localhost:8080/api/ml/trap", nil)
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
				req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
				req.Header.Set("Accept-Language", "en-US,en;q=0.9")
				req.Header.Set("Accept-Encoding", "gzip, deflate, br")
				// Webdriver still exposed
				req.Header.Set("X-Navigator-Webdriver", "true")
				return req
			},
		},
		{
			Name:        "stealth_no_client_hints",
			Description: "Spoofed UA, removed webdriver, but missing client hints",
			BuildReq: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://localhost:8080/api/ml/trap", nil)
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
			},
		},
		{
			Name:        "stealth_with_hints",
			Description: "Full Chrome-like headers including client hints",
			BuildReq: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://localhost:8080/api/ml/trap", nil)
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
				req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
				req.Header.Set("Accept-Language", "en-US,en;q=0.9")
				req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
				req.Header.Set("Upgrade-Insecure-Requests", "1")
				req.Header.Set("Sec-Fetch-Dest", "document")
				req.Header.Set("Sec-Fetch-Mode", "navigate")
				req.Header.Set("Sec-Fetch-Site", "none")
				req.Header.Set("Sec-Fetch-User", "?1")
				req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
				req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
				req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
				return req
			},
		},
		{
			Name:        "stealth_full_chrome",
			Description: "Maximum Chrome impersonation — all headers, hints, sec-fetch",
			BuildReq: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://localhost:8080/api/ml/trap", nil)
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
				req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
				req.Header.Set("Accept-Language", "en-US,en;q=0.9")
				req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
				req.Header.Set("Connection", "keep-alive")
				req.Header.Set("Upgrade-Insecure-Requests", "1")
				req.Header.Set("Sec-Fetch-Dest", "document")
				req.Header.Set("Sec-Fetch-Mode", "navigate")
				req.Header.Set("Sec-Fetch-Site", "none")
				req.Header.Set("Sec-Fetch-User", "?1")
				req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
				req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
				req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
				req.Header.Set("Sec-Ch-Ua-Full-Version-List", `"Chromium";v="134.0.6998.88", "Google Chrome";v="134.0.6998.88", "Not-A.Brand";v="99.0.0.0"`)
				req.Header.Set("Sec-Ch-Ua-Arch", `"x86"`)
				req.Header.Set("Sec-Ch-Ua-Bitness", `"64"`)
				req.Header.Set("Sec-Ch-Ua-Platform-Version", `"15.0.0"`)
				req.Header.Set("Cache-Control", "max-age=0")
				req.Header.Set("Priority", "u=0, i")
				return req
			},
		},
		{
			Name:        "stealth_firefox_impersonate",
			Description: "Full Firefox impersonation — no client hints (Firefox doesn't send them)",
			BuildReq: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://localhost:8080/api/ml/trap", nil)
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
				req.Header.Set("Priority", "u=0, i")
				return req
			},
		},
		{
			Name:        "go_http_default",
			Description: "Go net/http default client — minimal headers",
			BuildReq: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://localhost:8080/api/ml/trap", nil)
				req.Header.Set("User-Agent", "Go-http-client/2.0")
				return req
			},
		},
		{
			Name:        "playwright_stealth",
			Description: "Playwright with stealth plugin patterns",
			BuildReq: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://localhost:8080/api/ml/trap", nil)
				req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
				req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
				req.Header.Set("Accept-Language", "en-US,en;q=0.9")
				req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
				req.Header.Set("Upgrade-Insecure-Requests", "1")
				req.Header.Set("Sec-Fetch-Dest", "document")
				req.Header.Set("Sec-Fetch-Mode", "navigate")
				req.Header.Set("Sec-Fetch-Site", "none")
				req.Header.Set("Sec-Fetch-User", "?1")
				req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
				req.Header.Set("Sec-Ch-Ua-Platform", `"macOS"`)
				req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
				// Playwright often has slightly wrong header ordering
				return req
			},
		},
	}
}

// TestShieldEvaluation runs all evasion profiles through the StealthDetector
// and produces a coverage matrix showing which vectors catch which profiles.
func TestShieldEvaluation(t *testing.T) {
	detector := NewStealthDetector()
	profiles := buildEvasionProfiles()
	results := make([]ShieldEvalResult, 0, len(profiles))

	// Header for the report
	fmt.Println()
	fmt.Println("╔═══════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                    SHIELD EFFECTIVENESS EVALUATION                        ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	for _, profile := range profiles {
		req := profile.BuildReq()
		detection := detector.AnalyzeRequest(req, nil)

		evalResult := ShieldEvalResult{
			Profile:    profile.Name,
			BotScore:   detection.Score,
			IsBot:      detection.IsBot,
			Vectors:    make(map[string]float64),
			Indicators: make([]string, 0),
		}

		for _, vec := range detection.Vectors {
			evalResult.Vectors[vec.Category] = vec.Score
			if vec.Detected {
				for _, ind := range vec.Indicators {
					evalResult.Indicators = append(evalResult.Indicators, ind)
				}
			}
		}

		results = append(results, evalResult)
	}

	// Print coverage matrix
	fmt.Println("━━━ Detection Coverage Matrix ━━━")
	fmt.Println()

	// Collect all vector categories
	allCategories := make([]string, 0)
	catSet := make(map[string]bool)
	for _, r := range results {
		for cat := range r.Vectors {
			if !catSet[cat] {
				catSet[cat] = true
				allCategories = append(allCategories, cat)
			}
		}
	}

	// Print header
	fmt.Printf("%-28s │ %5s │ %3s │", "Profile", "Score", "Bot")
	for _, cat := range allCategories {
		short := cat
		if len(short) > 8 {
			short = short[:8]
		}
		fmt.Printf(" %8s │", short)
	}
	fmt.Println()
	fmt.Println(strings.Repeat("─", 40+10*len(allCategories)))

	// Print each result
	for i, r := range results {
		botMark := "  "
		if r.IsBot {
			botMark = "!!"
		}
		fmt.Printf("%-28s │ %5.3f │ %s  │", profiles[i].Name, r.BotScore, botMark)
		for _, cat := range allCategories {
			score := r.Vectors[cat]
			if score > 0.3 {
				fmt.Printf(" %8.3f │", score) // Detected
			} else if score > 0 {
				fmt.Printf(" %7.3f  │", score) // Partial
			} else {
				fmt.Printf("     -    │")
			}
		}
		fmt.Println()
	}

	fmt.Println()

	// Detailed findings per profile
	fmt.Println("━━━ Detailed Indicators ━━━")
	fmt.Println()
	for i, r := range results {
		status := "PASS"
		if r.IsBot {
			status = "DETECTED"
		}
		fmt.Printf("[%s] %s (score=%.3f)\n", status, profiles[i].Name, r.BotScore)
		if len(r.Indicators) > 0 {
			for _, ind := range r.Indicators {
				fmt.Printf("    - %s\n", ind)
			}
		} else {
			fmt.Printf("    (no indicators triggered)\n")
		}
		fmt.Println()
	}

	// Blind spot analysis
	fmt.Println("━━━ Blind Spot Analysis ━━━")
	fmt.Println()

	// Count how many bots each vector catches
	vectorCatchCount := make(map[string]int)
	totalBots := 0
	for _, r := range results {
		if r.BotScore > 0.2 { // Should-be-detected profiles
			totalBots++
			for cat, score := range r.Vectors {
				if score > 0.3 {
					vectorCatchCount[cat]++
				}
			}
		}
	}

	fmt.Printf("Profiles that SHOULD be detected: %d\n", totalBots)
	for _, cat := range allCategories {
		count := vectorCatchCount[cat]
		pct := 0.0
		if totalBots > 0 {
			pct = float64(count) / float64(totalBots) * 100
		}
		bar := strings.Repeat("█", int(pct/5))
		fmt.Printf("  %-12s: %d/%d caught (%5.1f%%) %s\n", cat, count, totalBots, pct, bar)
	}
	fmt.Println()

	// False negative analysis
	fmt.Println("━━━ False Negative Analysis (evasions that pass as human) ━━━")
	fmt.Println()
	falseNegatives := 0
	for i, r := range results {
		if !r.IsBot && profiles[i].Name != "stealth_full_chrome" && profiles[i].Name != "stealth_firefox_impersonate" && profiles[i].Name != "playwright_stealth" && profiles[i].Name != "stealth_with_hints" {
			falseNegatives++
			fmt.Printf("  FALSE NEGATIVE: %s (score=%.3f)\n", profiles[i].Name, r.BotScore)
			fmt.Printf("    Description: %s\n", profiles[i].Description)
			fmt.Println()
		}
	}
	if falseNegatives == 0 {
		fmt.Println("  None — all obvious bots detected!")
	}

	// Evasion success analysis
	fmt.Println("━━━ Evasion Success Analysis (stealth profiles that evade) ━━━")
	fmt.Println()
	stealthProfiles := []string{"stealth_no_client_hints", "stealth_with_hints", "stealth_full_chrome", "stealth_firefox_impersonate", "playwright_stealth"}
	for i, r := range results {
		for _, sp := range stealthProfiles {
			if profiles[i].Name == sp {
				status := "EVADED"
				if r.IsBot {
					status = "CAUGHT"
				}
				fmt.Printf("  [%s] %-28s score=%.3f\n", status, profiles[i].Name, r.BotScore)
			}
		}
	}
	fmt.Println()

	// Summary
	fmt.Println("━━━ Summary ━━━")
	detectedCount := 0
	for _, r := range results {
		if r.IsBot {
			detectedCount++
		}
	}
	fmt.Printf("  Total profiles:  %d\n", len(results))
	fmt.Printf("  Detected as bot: %d\n", detectedCount)
	fmt.Printf("  Passed as human: %d\n", len(results)-detectedCount)
	fmt.Printf("  Detection rate:  %.1f%%\n", float64(detectedCount)/float64(len(results))*100)
}

// TestNewShieldAnalyzers exercises the new Phase 4 analyzers with specific
// attack vectors to evaluate their standalone effectiveness.
func TestNewShieldAnalyzers(t *testing.T) {
	fmt.Println()
	fmt.Println("━━━ New Shield Analyzer Effectiveness ━━━")
	fmt.Println()

	// Behavioral Analyzer
	ba := NewBehavioralAnalyzer(nil)

	behavTests := []struct {
		name   string
		events *EnhancedBehavioralEvents
	}{
		{"selenium_bot", &EnhancedBehavioralEvents{
			MouseTimestamps:  []int64{0, 100, 200, 300, 400, 500, 600, 700, 800, 900},
			TypingTimestamps: []int64{0, 50, 100, 150, 200, 250, 300, 350},
			MousePositions: []Position{
				{0, 0},
				{100, 100},
				{200, 200},
				{300, 300},
				{400, 400},
				{500, 500},
				{600, 600},
				{700, 700},
				{800, 800},
				{900, 900},
			},
			MouseVelocities: []float64{1414, 1414, 1414, 1414, 1414, 1414, 1414, 1414},
		}},
		{"puppeteer_humanized", &EnhancedBehavioralEvents{
			MouseTimestamps:  []int64{0, 83, 178, 290, 412, 510, 635, 788, 890, 1020},
			TypingTimestamps: []int64{0, 62, 145, 198, 285, 340, 420, 510},
			MousePositions: []Position{
				{0, 0},
				{25, 18},
				{55, 42},
				{90, 58},
				{130, 80},
				{165, 105},
				{195, 135},
				{230, 160},
				{270, 190},
				{310, 215},
			},
			MouseVelocities: []float64{350, 420, 380, 500, 320, 450, 400, 360},
		}},
		{"real_human", &EnhancedBehavioralEvents{
			MouseTimestamps:  []int64{0, 32, 48, 91, 152, 184, 267, 345, 391, 480, 512, 599, 678, 745, 812, 890, 965, 1040, 1120, 1200},
			TypingTimestamps: []int64{0, 87, 143, 231, 312, 398, 511, 602},
			MousePositions: []Position{
				{100, 200},
				{102, 201},
				{105, 198},
				{112, 195},
				{118, 202},
				{125, 210},
				{127, 212},
				{130, 215},
				{138, 208},
				{142, 203},
				{150, 198},
				{151, 199},
				{155, 205},
				{162, 218},
				{170, 230},
				{172, 231},
				{178, 225},
				{185, 220},
				{192, 228},
				{200, 235},
			},
			MouseVelocities: []float64{50, 80, 120, 90, 110, 40, 70, 95, 130, 60, 20, 85, 140, 100, 30, 75, 105, 115, 80},
		}},
	}

	fmt.Printf("  %-24s │ %5s │ %3s │ Indicators\n", "Scenario", "Score", "Bot")
	fmt.Println("  " + strings.Repeat("─", 70))

	for _, tt := range behavTests {
		result := ba.Analyze(tt.events)
		botMark := "  "
		if result.Detected {
			botMark = "!!"
		}
		indicators := make([]string, 0)
		for _, ind := range result.Indicators {
			indicators = append(indicators, ind.Check)
		}
		indStr := strings.Join(indicators, ", ")
		if indStr == "" {
			indStr = "(none)"
		}
		fmt.Printf("  %-24s │ %5.3f │ %s  │ %s\n", tt.name, result.Score, botMark, indStr)
	}
	fmt.Println()

	// WebGL Analyzer
	wa := NewWebGLAnalyzer()

	webglTests := []struct {
		name string
		data *WebGLData
	}{
		{"headless_swiftshader", &WebGLData{
			Renderer: "Google SwiftShader", UnmaskedRenderer: "Google SwiftShader",
			Platform: "Win32", WebGL2Supported: true,
		}},
		{"spoofed_gpu", &WebGLData{
			Renderer: "NVIDIA GeForce RTX 4070", UnmaskedRenderer: "Google SwiftShader",
			Platform: "Win32", WebGL2Supported: true,
		}},
		{"real_nvidia_win", &WebGLData{
			Renderer: "NVIDIA GeForce RTX 4070", UnmaskedRenderer: "NVIDIA GeForce RTX 4070",
			Platform: "Win32", WebGL2Supported: true,
		}},
		{"real_apple_mac", &WebGLData{
			Renderer: "Apple M2 Pro", UnmaskedRenderer: "Apple M2 Pro",
			Platform: "MacIntel", WebGL2Supported: true,
		}},
		{"cross_platform_spoof", &WebGLData{
			Renderer: "Apple M2", UnmaskedRenderer: "Apple M2",
			Platform: "Win32", WebGL2Supported: true,
		}},
	}

	fmt.Printf("  %-24s │ %5s │ %3s │ Indicators\n", "WebGL Scenario", "Score", "Bot")
	fmt.Println("  " + strings.Repeat("─", 70))

	for _, tt := range webglTests {
		result := wa.Analyze(tt.data)
		botMark := "  "
		if result.Detected {
			botMark = "!!"
		}
		indicators := make([]string, 0)
		for _, ind := range result.Indicators {
			indicators = append(indicators, ind.Check)
		}
		indStr := strings.Join(indicators, ", ")
		if indStr == "" {
			indStr = "(none)"
		}
		fmt.Printf("  %-24s │ %5.3f │ %s  │ %s\n", tt.name, result.Score, botMark, indStr)
	}
	fmt.Println()

	// Timing Analyzer
	ta := NewTimingAnalyzer(nil)

	timingTests := []struct {
		name string
		seq  *RequestTimingSequence
	}{
		{"scraper_fixed_100ms", &RequestTimingSequence{Entries: []RequestTimingEntry{
			{Timestamp: 0, ContentType: "text/html"},
			{Timestamp: 100, ContentType: "text/css"},
			{Timestamp: 200, ContentType: "application/javascript"},
			{Timestamp: 300, ContentType: "image/png"},
			{Timestamp: 400, ContentType: "image/jpeg"},
		}}},
		{"scraper_burst", &RequestTimingSequence{Entries: []RequestTimingEntry{
			{Timestamp: 0, ContentType: "text/html"},
			{Timestamp: 5, ContentType: "text/css"},
			{Timestamp: 10, ContentType: "application/javascript"},
			{Timestamp: 15, ContentType: "image/png"},
			{Timestamp: 20, ContentType: "image/jpeg"},
		}}},
		{"real_browser_load", &RequestTimingSequence{Entries: []RequestTimingEntry{
			{Timestamp: 0, ContentType: "text/html", Referrer: ""},
			{Timestamp: 150, ContentType: "text/css", Referrer: "http://example.com"},
			{Timestamp: 320, ContentType: "application/javascript", Referrer: "http://example.com"},
			{Timestamp: 890, ContentType: "image/png", Referrer: "http://example.com"},
			{Timestamp: 1200, ContentType: "font/woff2", Referrer: "http://example.com"},
		}}},
	}

	fmt.Printf("  %-24s │ %5s │ %3s │ Indicators\n", "Timing Scenario", "Score", "Bot")
	fmt.Println("  " + strings.Repeat("─", 70))

	for _, tt := range timingTests {
		result := ta.Analyze(tt.seq)
		botMark := "  "
		if result.Detected {
			botMark = "!!"
		}
		indicators := make([]string, 0)
		for _, ind := range result.Indicators {
			indicators = append(indicators, ind.Check)
		}
		indStr := strings.Join(indicators, ", ")
		if indStr == "" {
			indStr = "(none)"
		}
		fmt.Printf("  %-24s │ %5.3f │ %s  │ %s\n", tt.name, result.Score, botMark, indStr)
	}
	fmt.Println()

	// Adaptive Scorer
	scorer := NewAdaptiveScorer(nil)

	fmt.Println("  Adaptive Scorer: Weight evolution after bypass learning")
	fmt.Println("  " + strings.Repeat("─", 50))

	initialWeights := scorer.GetWeights()

	// Simulate: HTTP vector gets bypassed frequently, TLS rarely
	for i := 0; i < 50; i++ {
		scorer.RecordOutcome(BypassRecord{Category: VectorHTTP, Bypassed: true})
		scorer.RecordOutcome(BypassRecord{Category: VectorTLS, Bypassed: false})
		scorer.RecordOutcome(BypassRecord{Category: VectorBehavioral, Bypassed: i%3 == 0}) // 33% bypass
	}

	adjustedWeights := scorer.GetWeights()
	rates := scorer.GetBypassRates()

	fmt.Printf("  %-12s │ %8s │ %8s │ %8s │ %s\n", "Vector", "Initial", "Adjusted", "Delta", "Bypass%")
	fmt.Println("  " + strings.Repeat("─", 60))
	for _, cat := range []VectorCategory{VectorTLS, VectorHTTP, VectorBehavioral, VectorNavigator, VectorCanvas} {
		initial := initialWeights[cat]
		adjusted := adjustedWeights[cat]
		delta := adjusted - initial
		rate := rates[cat]
		fmt.Printf("  %-12s │ %8.4f │ %8.4f │ %+7.4f │ %5.1f%%\n", cat, initial, adjusted, delta, rate*100)
	}
	fmt.Println()
}

// TestShieldWithEnhancedData tests AnalyzeRequest with behavioral/timing/WebGL data
// passed through custom headers, simulating a full browser session evaluation.
func TestShieldWithEnhancedData(t *testing.T) {
	detector := NewStealthDetector()

	fmt.Println()
	fmt.Println("━━━ Full-Stack Shield Evaluation (with behavioral + timing data) ━━━")
	fmt.Println()

	type enhancedProfile struct {
		Name          string
		BuildReq      func() *http.Request
		ExpectBot     bool
		ExpectVectors []string // vector categories expected to fire
	}

	profiles := []enhancedProfile{
		{
			Name:          "selenium_bot_with_behavioral",
			ExpectBot:     true,
			ExpectVectors: []string{"http", "behavioral"},
			BuildReq: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://localhost:8080/test", nil)
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
				req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
				req.Header.Set("Accept-Language", "en-US,en;q=0.9")
				req.Header.Set("Accept-Encoding", "gzip, deflate, br")
				req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
				req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
				req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
				req.Header.Set("Sec-Fetch-Dest", "document")
				req.Header.Set("Sec-Fetch-Mode", "navigate")
				req.Header.Set("Sec-Fetch-Site", "none")
				// Bot-like behavioral data: uniform 100ms intervals, straight-line movement
				req.Header.Set("X-Behavioral-Data", `{
					"mouseTimestamps": [0,100,200,300,400,500,600,700,800,900],
					"typingTimestamps": [0,50,100,150,200,250,300,350],
					"mousePositions": [
						{"x":0,"y":0},{"x":100,"y":100},{"x":200,"y":200},
						{"x":300,"y":300},{"x":400,"y":400},{"x":500,"y":500},
						{"x":600,"y":600},{"x":700,"y":700},{"x":800,"y":800},
						{"x":900,"y":900}
					],
					"mouseVelocities": [1414,1414,1414,1414,1414,1414,1414,1414]
				}`)
				return req
			},
		},
		{
			Name:          "stealth_chrome_with_humanlike_behavior",
			ExpectBot:     false, // Human-like events should remain below bot threshold.
			ExpectVectors: []string{},
			BuildReq: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://localhost:8080/test", nil)
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

				// Add header order to avoid isomorphic penalty from random map iteration
				req.Header.Set("X-Stealth-Header-Order", "sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,upgrade-insecure-requests,user-agent,accept,sec-fetch-site,sec-fetch-mode,sec-fetch-user,sec-fetch-dest,accept-encoding,accept-language")

				// Human-like behavioral data with real epoch timestamps, micro-tremors, bimodal velocity
				req.Header.Set("X-Behavioral-Data", `{
					"mouseTimestamps": [1709500000000,1709500000032,1709500000078,1709500000131,1709500000192,1709500000284,1709500000367,1709500000445,1709500000591,1709500000680,1709500000712,1709500000799,1709500000878,1709500000945,1709500001012,1709500001190,1709500001265,1709500001340,1709500001420,1709500001500],
					"typingTimestamps": [1709500002000,1709500002087,1709500002243,1709500002431,1709500002612,1709500002798,1709500003011,1709500003202],
					"mousePositions": [
						{"x":100,"y":200},{"x":101.2,"y":200.8},{"x":102.5,"y":199.3},{"x":115,"y":190},
						{"x":135,"y":178},{"x":160,"y":175},{"x":161.5,"y":175.8},{"x":190,"y":182},
						{"x":210,"y":195},{"x":205,"y":200},{"x":195,"y":210},{"x":196.2,"y":209.5},
						{"x":200,"y":215},{"x":350,"y":160},{"x":351.8,"y":160.5},{"x":395,"y":165},
						{"x":390,"y":180},{"x":420,"y":300},{"x":500,"y":340},{"x":550,"y":350}
					],
					"mouseVelocities": [8,15,320,90,250,2,40,470,95,450,20,7,385,3,140,600,30,205,415,80],
					"scrollTimestamps": [1709500004000,1709500004150,1709500004380],
					"scrollDeltas": [250,180,120]
				}`)
				return req
			},
		},
		{
			Name:          "stealth_chrome_with_bot_behavior",
			ExpectBot:     true,
			ExpectVectors: []string{"behavioral"},
			BuildReq: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://localhost:8080/test", nil)
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
				req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
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
				// Perfect headers BUT bot behavioral data (uniform intervals, straight lines)
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
			},
		},
	}

	fmt.Printf("  %-40s │ %5s │ %3s │ %7s │ Vectors\n", "Profile", "Score", "Bot", "Expect")
	fmt.Println("  " + strings.Repeat("─", 90))

	for _, p := range profiles {
		req := p.BuildReq()
		detection := detector.AnalyzeRequest(req, nil)

		expectStr := "human"
		if p.ExpectBot {
			expectStr = "BOT"
		}

		botMark := "  "
		if detection.IsBot {
			botMark = "!!"
		}

		vectors := make([]string, 0)
		for _, v := range detection.Vectors {
			if v.Detected {
				vectors = append(vectors, fmt.Sprintf("%s(%.2f)", v.Category, v.Score))
			}
		}
		vecStr := "(none)"
		if len(vectors) > 0 {
			vecStr = strings.Join(vectors, ", ")
		}

		fmt.Printf("  %-40s │ %5.3f │ %s  │ %7s │ %s\n", p.Name, detection.Score, botMark, expectStr, vecStr)

		if p.ExpectBot && !detection.IsBot {
			t.Errorf("[%s] expected bot detection (score=%.3f), got human", p.Name, detection.Score)
		}
		if !p.ExpectBot && detection.IsBot {
			t.Errorf("[%s] expected human classification (score=%.3f), got bot", p.Name, detection.Score)
		}
	}
	fmt.Println()
}

// TestIntervalEntropySpectrum is a helper for understanding entropy values across scenarios.
func TestIntervalEntropySpectrum(t *testing.T) {
	ba := NewBehavioralAnalyzer(nil)

	// All identical
	e0 := ba.CalculateIntervalEntropy([]int64{0, 100, 200, 300, 400, 500})
	// Slightly varied
	e1 := ba.CalculateIntervalEntropy([]int64{0, 95, 205, 310, 405, 495})
	// Moderately varied (human-like)
	e2 := ba.CalculateIntervalEntropy([]int64{0, 80, 195, 340, 420, 510, 670, 780, 890, 1020})
	// Highly varied
	e3 := ba.CalculateIntervalEntropy([]int64{0, 20, 350, 360, 900, 910, 2000, 2005, 3500, 3600})

	fmt.Printf("\nEntropy values (threshold: low<%.1f, high>%.1f):\n",
		ba.config.MinIntervalEntropy, ba.config.MaxIntervalEntropy)
	fmt.Printf("  All identical:       %.4f\n", e0)
	fmt.Printf("  Slightly varied:     %.4f\n", e1)
	fmt.Printf("  Moderately varied:   %.4f\n", e2)
	fmt.Printf("  Highly varied:       %.4f\n", e3)
}

// TestFullPipelineDetection exercises all new vectors with targeted profiles.
func TestFullPipelineDetection(t *testing.T) {
	detector := NewStealthDetector()

	type fullPipelineProfile struct {
		Name          string
		ExpectBot     bool
		ExpectVectors []string
		BuildReq      func() *http.Request
	}

	profiles := []fullPipelineProfile{
		{
			Name:          "webgl_swiftshader_spoofed",
			ExpectBot:     true,
			ExpectVectors: []string{"webgl"},
			BuildReq: func() *http.Request {
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
				// SwiftShader masked as NVIDIA
				req.Header.Set("X-WebGL-Data", `{"vendor":"Google Inc.","renderer":"NVIDIA GeForce RTX 4070","unmasked_vendor":"Google Inc.","unmasked_renderer":"Google SwiftShader","version":"WebGL 2.0","platform":"Win32","webgl2_supported":true}`)
				return req
			},
		},
		{
			Name:          "timing_fixed_100ms",
			ExpectBot:     true,
			ExpectVectors: []string{"timing"},
			BuildReq: func() *http.Request {
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
				// Fixed 100ms intervals
				req.Header.Set("X-Timing-Data", `{"entries":[{"timestamp_ms":0,"content_type":"text/html"},{"timestamp_ms":100,"content_type":"text/css"},{"timestamp_ms":200,"content_type":"application/javascript"},{"timestamp_ms":300,"content_type":"image/png"},{"timestamp_ms":400,"content_type":"image/jpeg"}]}`)
				return req
			},
		},
		{
			Name:          "headless_no_window_chrome",
			ExpectBot:     true,
			ExpectVectors: []string{"screen"},
			BuildReq: func() *http.Request {
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
				// Headless screen: outer == inner
				req.Header.Set("X-Screen-Data", `{"width":1920,"height":1080,"avail_width":1920,"avail_height":1080,"color_depth":24,"pixel_ratio":1.0,"outer_width":1920,"outer_height":1080,"inner_width":1920,"inner_height":1080}`)
				return req
			},
		},
		{
			Name:          "datacenter_ip_aws",
			ExpectBot:     false, // IP alone shouldn't trigger bot detection
			ExpectVectors: []string{},
			BuildReq: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://test/", nil)
				// Firefox UA from a datacenter IP — no Client Hints (Firefox doesn't send them)
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
				req.Header.Set("X-Forwarded-For", "3.12.45.67")
				return req
			},
		},
		{
			Name:          "empty_plugins_headless_chrome",
			ExpectBot:     true,
			ExpectVectors: []string{"plugin", "screen"},
			BuildReq: func() *http.Request {
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
				// Empty plugins + headless screen → combined signal
				req.Header.Set("X-Plugin-Data", `{"plugins":[],"plugin_count":0}`)
				req.Header.Set("X-Screen-Data", `{"width":800,"height":600,"avail_width":800,"avail_height":600,"color_depth":24,"pixel_ratio":1.0,"outer_width":800,"outer_height":600,"inner_width":800,"inner_height":600}`)
				return req
			},
		},
		{
			Name:          "minimal_fonts_headless",
			ExpectBot:     true,
			ExpectVectors: []string{"font"},
			BuildReq: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://test/", nil)
				req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
				req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
				req.Header.Set("Accept-Language", "en-US,en;q=0.9")
				req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
				req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
				req.Header.Set("Sec-Ch-Ua-Platform", `"Linux"`)
				req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
				req.Header.Set("Sec-Fetch-Dest", "document")
				req.Header.Set("Sec-Fetch-Mode", "navigate")
				req.Header.Set("Sec-Fetch-Site", "none")
				req.Header.Set("Sec-Fetch-User", "?1")
				req.Header.Set("Upgrade-Insecure-Requests", "1")
				// Only 8 fonts on Linux = headless
				req.Header.Set("X-Font-Data", `{"fonts":["Arial","Times New Roman","Courier New","Georgia","Verdana","Trebuchet MS","Impact","Comic Sans MS"],"font_count":8,"platform":"linux"}`)
				return req
			},
		},
		{
			Name:          "stealth_perfect_all_vectors",
			ExpectBot:     true,
			ExpectVectors: []string{"navigator", "webgl", "timing", "isomorphic"},
			BuildReq: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://test/", nil)
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
				req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
				req.Header.Set("Accept-Language", "en-US,en;q=0.9")
				req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
				req.Header.Set("Connection", "keep-alive")
				req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
				req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
				req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
				req.Header.Set("Sec-Fetch-Dest", "document")
				req.Header.Set("Sec-Fetch-Mode", "navigate")
				req.Header.Set("Sec-Fetch-Site", "none")
				req.Header.Set("Sec-Fetch-User", "?1")
				req.Header.Set("Upgrade-Insecure-Requests", "1")
				// Valid navigator with correlated RTT/downlink, chrome.app, chrome.csi, performance.memory, timezone
				req.Header.Set("X-Navigator-Data", `{"webdriver":false,"webdriverString":"function () { [native code] }","platform":"Win32","vendor":"Google Inc.","userAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36","appVersion":"5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36","hardwareConcurrency":8,"deviceMemory":16,"cookieEnabled":true,"pdfViewerEnabled":true,"connection":{"rtt":50,"downlink":8.5,"effectiveType":"4g"},"languages":["en-US","en"],"screen_color_depth":24,"screen_inner_width":1900,"screen_outer_width":1920,"productSub":"20030107","maxTouchPoints":0,"chrome":{},"chrome_app":{"isInstalled":false,"InstallState":{"DISABLED":"disabled","INSTALLED":"installed","NOT_INSTALLED":"not_installed"},"RunningState":{"CANNOT_RUN":"cannot_run","READY_TO_RUN":"ready_to_run","RUNNING":"running"}},"chrome_csi":{"onloadT":2500,"pageT":2000,"startE":1709500000000,"tran":15},"performance_memory":{"jsHeapSizeLimit":4294705152,"totalJSHeapSize":35000000,"usedJSHeapSize":20000000},"timezone":"America/New_York"}`)
				// Valid WebGL with extensions
				req.Header.Set("X-WebGL-Data", `{"vendor":"Google Inc.","renderer":"NVIDIA GeForce RTX 4070","unmasked_vendor":"Google Inc.","unmasked_renderer":"NVIDIA GeForce RTX 4070","version":"WebGL 2.0","shading_version":"WebGL GLSL ES 3.00","platform":"Win32","webgl2_supported":true,"max_texture_size":16384,"extensions":["ANGLE_instanced_arrays","EXT_blend_minmax","EXT_color_buffer_half_float","EXT_disjoint_timer_query","EXT_float_blend","EXT_frag_depth","EXT_shader_texture_lod","EXT_texture_compression_bptc","EXT_texture_compression_rgtc","EXT_texture_filter_anisotropic","KHR_parallel_shader_compile","OES_element_index_uint","OES_fbo_render_mipmap","OES_standard_derivatives","OES_texture_float","OES_texture_float_linear","OES_texture_half_float","OES_texture_half_float_linear","OES_vertex_array_object","WEBGL_color_buffer_float","WEBGL_compressed_texture_s3tc","WEBGL_debug_renderer_info","WEBGL_depth_texture","WEBGL_draw_buffers","WEBGL_lose_context"]}`)
				// Valid plugins with MIME types
				req.Header.Set("X-Plugin-Data", `{"plugins":[{"name":"PDF Viewer","filename":"internal-pdf-viewer","mimeTypes":["application/pdf"]},{"name":"Chrome PDF Viewer","filename":"internal-pdf-viewer","mimeTypes":["application/pdf"]},{"name":"Chromium PDF Viewer","filename":"internal-pdf-viewer","mimeTypes":["application/pdf"]},{"name":"Microsoft Edge PDF Viewer","filename":"internal-pdf-viewer","mimeTypes":["application/pdf"]},{"name":"WebKit built-in PDF","filename":"internal-pdf-viewer","mimeTypes":["application/pdf"]}],"plugin_count":5}`)
				// Valid screen with orientation
				req.Header.Set("X-Screen-Data", `{"width":1920,"height":1080,"avail_width":1920,"avail_height":1040,"color_depth":24,"pixel_ratio":1.0,"outer_width":1920,"outer_height":1040,"inner_width":1900,"inner_height":950,"orientation_type":"landscape-primary","orientation_angle":0}`)
				// Valid fonts
				req.Header.Set("X-Font-Data", `{"fonts":["Arial","Times New Roman","Courier New","Georgia","Verdana","Segoe UI","Calibri","Consolas","Tahoma","Trebuchet MS","Impact","Comic Sans MS","Palatino Linotype","Lucida Console","Lucida Sans Unicode","MS Gothic","MS Mincho","MS PGothic","MS PMincho","MS Sans Serif","MS Serif","MS UI Gothic"],"font_count":22,"platform":"windows"}`)
				// Valid timing (18 entries in correct order)
				req.Header.Set("X-Timing-Data", `{"entries":[{"timestamp_ms":0,"content_type":"text/html","referrer":""},{"timestamp_ms":150,"content_type":"text/css","referrer":"http://example.com"},{"timestamp_ms":220,"content_type":"text/css","referrer":"http://example.com"},{"timestamp_ms":310,"content_type":"text/css","referrer":"http://example.com"},{"timestamp_ms":420,"content_type":"application/javascript","referrer":"http://example.com"},{"timestamp_ms":530,"content_type":"application/javascript","referrer":"http://example.com"},{"timestamp_ms":620,"content_type":"application/javascript","referrer":"http://example.com"},{"timestamp_ms":700,"content_type":"application/javascript","referrer":"http://example.com"},{"timestamp_ms":1050,"content_type":"image/png","referrer":"http://example.com"},{"timestamp_ms":1250,"content_type":"image/jpeg","referrer":"http://example.com"},{"timestamp_ms":1400,"content_type":"image/webp","referrer":"http://example.com"},{"timestamp_ms":1500,"content_type":"image/svg+xml","referrer":"http://example.com"},{"timestamp_ms":1600,"content_type":"image/png","referrer":"http://example.com"},{"timestamp_ms":1900,"content_type":"font/woff2","referrer":"http://example.com"},{"timestamp_ms":2050,"content_type":"font/woff2","referrer":"http://example.com"},{"timestamp_ms":2150,"content_type":"font/woff2","referrer":"http://example.com"},{"timestamp_ms":2500,"content_type":"application/json","referrer":"http://example.com"},{"timestamp_ms":2800,"content_type":"application/json","referrer":"http://example.com"}]}`)
				// Valid audio data
				req.Header.Set("X-Audio-Data", `{"sample_rate":48000,"channel_count":2,"max_channel_count":2,"base_latency":0.01,"output_latency":0.0,"state":"suspended"}`)
				// Valid canvas fingerprint
				req.Header.Set("X-Canvas-Fingerprint", `{"hash":"data:image/png;base64,iVBOR","consistent":true}`)
				// Human behavioral data with epoch timestamps, micro-tremors, bimodal velocity
				req.Header.Set("X-Behavioral-Data", `{
					"mouseTimestamps": [1709500000000,1709500000032,1709500000078,1709500000131,1709500000192,1709500000284,1709500000367,1709500000445,1709500000591,1709500000680,1709500000712,1709500000799,1709500000878,1709500000945,1709500001012,1709500001190,1709500001265,1709500001340,1709500001420,1709500001500],
					"typingTimestamps": [1709500002000,1709500002087,1709500002243,1709500002431,1709500002612,1709500002798,1709500003011,1709500003202],
					"mousePositions": [
						{"x":100,"y":200},{"x":101.2,"y":200.8},{"x":102.5,"y":199.3},{"x":115,"y":190},
						{"x":135,"y":178},{"x":160,"y":175},{"x":161.5,"y":175.8},{"x":190,"y":182},
						{"x":210,"y":195},{"x":205,"y":200},{"x":195,"y":210},{"x":196.2,"y":209.5},
						{"x":200,"y":215},{"x":350,"y":160},{"x":351.8,"y":160.5},{"x":395,"y":165},
						{"x":390,"y":180},{"x":420,"y":300},{"x":500,"y":340},{"x":550,"y":350}
					],
					"mouseVelocities": [8,15,320,90,250,2,40,470,95,450,20,7,385,3,140,600,30,205,415,80],
					"scrollTimestamps": [1709500004000,1709500004150,1709500004380],
					"scrollDeltas": [250,180,120]
				}`)
				return req
			},
		},
	}

	fmt.Println()
	fmt.Println("━━━ Full Pipeline Detection Test ━━━")
	fmt.Println()
	fmt.Printf("  %-35s │ %5s │ %3s │ %7s │ Vectors\n", "Profile", "Score", "Bot", "Expect")
	fmt.Println("  " + strings.Repeat("─", 90))

	for _, p := range profiles {
		req := p.BuildReq()
		detection := detector.AnalyzeRequest(req, nil)

		expectStr := "human"
		if p.ExpectBot {
			expectStr = "BOT"
		}

		botMark := "  "
		if detection.IsBot {
			botMark = "!!"
		}

		vectors := make([]string, 0)
		for _, v := range detection.Vectors {
			if v.Detected {
				vectors = append(vectors, fmt.Sprintf("%s(%.2f)", v.Category, v.Score))
			}
		}
		vecStr := "(none)"
		if len(vectors) > 0 {
			vecStr = strings.Join(vectors, ", ")
		}

		fmt.Printf("  %-35s │ %5.3f │ %s  │ %7s │ %s\n", p.Name, detection.Score, botMark, expectStr, vecStr)

		if p.ExpectBot && !detection.IsBot {
			t.Errorf("[%s] expected bot detection (score=%.3f), got human", p.Name, detection.Score)
		}
		if !p.ExpectBot && detection.IsBot {
			t.Errorf("[%s] expected human classification (score=%.3f), got bot", p.Name, detection.Score)
		}

		// Verify expected vectors fire
		for _, expectedVec := range p.ExpectVectors {
			found := false
			for _, v := range detection.Vectors {
				if v.Category == expectedVec && v.Detected {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("[%s] expected vector %q to fire but it didn't", p.Name, expectedVec)
			}
		}
	}
	fmt.Println()
}

// TestSwordDoesNotTrigger verifies that a perfect stealth request with all valid
// X-* headers providing human-like data passes the shield (score < 0.35).
func TestSwordDoesNotTrigger(t *testing.T) {
	detector := NewStealthDetector()

	req, _ := http.NewRequest("GET", "http://test/", nil)
	// Perfect Chrome headers
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Cache-Control", "max-age=0")
	req.Header.Set("X-Stealth-Header-Order", "Sec-Ch-Ua,Sec-Ch-Ua-Platform,Sec-Ch-Ua-Mobile,Upgrade-Insecure-Requests,User-Agent,Accept,Accept-Language,Accept-Encoding,Connection,Sec-Fetch-Dest,Sec-Fetch-Mode,Sec-Fetch-Site,Sec-Fetch-User,Cache-Control,X-Navigator-Data,X-WebGL-Data,X-Plugin-Data,X-Screen-Data,X-Font-Data,X-Timing-Data,X-Audio-Data,X-Canvas-Fingerprint,X-Behavioral-Data")

	// Valid navigator with correlated RTT/downlink and required Chrome APIs.
	req.Header.Set("X-Navigator-Data", `{"webdriver":false,"webdriverString":"function () { [native code] }","platform":"Win32","vendor":"Google Inc.","userAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36","appVersion":"5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36","hardwareConcurrency":8,"deviceMemory":8,"cookieEnabled":true,"pdfViewerEnabled":true,"connection":{"rtt":50,"downlink":8.5,"effectiveType":"4g","saveData":false},"languages":["en-US","en"],"screen_color_depth":24,"screen_inner_width":1903,"screen_outer_width":1920,"productSub":"20030107","maxTouchPoints":0,"keyboard":{},"Notification_permission":"default","chrome":{},"chrome_app":{"isInstalled":false,"InstallState":{"DISABLED":"disabled","INSTALLED":"installed","NOT_INSTALLED":"not_installed"},"RunningState":{"CANNOT_RUN":"cannot_run","READY_TO_RUN":"ready_to_run","RUNNING":"running"}},"chrome_csi":{"onloadT":2500,"pageT":2000,"startE":1709500000000,"tran":15},"chrome_loadTimes":{"requestTime":1709500000.000,"startLoadTime":1709500000.150,"commitLoadTime":1709500000.300,"firstPaintTime":1709500000.600,"finishDocumentLoadTime":1709500000.900,"finishLoadTime":1709500001.200,"connectionInfo":"h2","navigationType":"Other","npnNegotiatedProtocol":"h2","wasFetchedViaSpdy":true,"wasNpnNegotiated":true,"firstPaintAfterLoadTime":0,"wasAlternateProtocolAvailable":false},"performance_memory":{"jsHeapSizeLimit":4294705152,"totalJSHeapSize":35000000,"usedJSHeapSize":20000000},"timezone":"America/New_York","vibrate":true,"onLine":true,"mediaCapabilities":{},"mediaSession":{},"serviceWorker":{},"sharedWorker":{},"getGamepads":{},"media_query_hover":"hover","storage_quota":25000000000,"storage_usage":500000000,"storage_persisted":true,"media_devices":[{"deviceId":"8976543210abcdef8976543210abcdef8976543210abcdef8976543210abcdef","kind":"audioinput","label":"","groupId":"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"},{"deviceId":"8976543210abcdef8976543210abcdef8976543210abcdef8976543210abcdef","kind":"audiooutput","label":"","groupId":"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"},{"deviceId":"8976543210abcdef8976543210abcdef8976543210abcdef8976543210abcdef","kind":"videoinput","label":"","groupId":"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"}],"userAgentData":{"brands":[{"brand":"Chromium","version":"134"},{"brand":"Google Chrome","version":"134"},{"brand":"Not-A.Brand","version":"99"}],"mobile":false,"platform":"Windows","architecture":"x86","bitness":"64","fullVersionList":[{"brand":"Chromium","version":"134.0.6998.77"},{"brand":"Google Chrome","version":"134.0.6998.77"},{"brand":"Not-A.Brand","version":"99.0.0.0"}],"platformVersion":"15.0.0"},"scheduling":{},"locks":{},"math_precision":{"sin1e15":-0.8510825272633096,"cos1e15":-0.9352358826620556},"bluetooth":{"getAvailability":{}},"usb":{"getDevices":{}},"clipboard":{},"credentials":{},"userActivation":{"hasBeenActive":true,"isActive":true},"webrtc_data":{"ice_candidates":[{"candidate":"candidate:1 1 UDP 2122260223 192.168.1.100 50000 typ host","sdpMid":"0","sdpMLineIndex":0}]}}`)
	// Valid WebGL with required dimensions and extension count for Win32.
	req.Header.Set("X-WebGL-Data", `{"vendor":"Google Inc.","renderer":"NVIDIA GeForce RTX 4070","unmasked_vendor":"Google Inc.","unmasked_renderer":"NVIDIA GeForce RTX 4070","version":"WebGL 2.0","shading_version":"WebGL GLSL ES 3.00","platform":"Win32","webgl2_supported":true,"max_texture_size":16384,"max_viewport_width":16384,"max_viewport_height":16384,"webgl_extensions":["ANGLE_instanced_arrays","EXT_blend_minmax","EXT_color_buffer_half_float","EXT_disjoint_timer_query","EXT_float_blend","EXT_frag_depth","EXT_shader_texture_lod","EXT_texture_compression_bptc","EXT_texture_compression_rgtc","EXT_texture_filter_anisotropic","KHR_parallel_shader_compile","OES_element_index_uint","OES_fbo_render_mipmap","OES_standard_derivatives","OES_texture_float","OES_texture_float_linear","OES_texture_half_float","OES_texture_half_float_linear","OES_vertex_array_object","WEBGL_color_buffer_float","WEBGL_compressed_texture_s3tc","WEBGL_debug_renderer_info","WEBGL_depth_texture","WEBGL_draw_buffers","WEBGL_lose_context","WEBGL_compressed_texture_etc1","WEBGL_compressed_texture_astc","WEBGL_multi_draw","EXT_clip_control","EXT_texture_mirror_clamp_to_edge"],"shader_precision":{"VERTEX_SHADER_LOW_FLOAT":{"range_min":127,"range_max":127,"precision":23},"VERTEX_SHADER_MEDIUM_FLOAT":{"range_min":127,"range_max":127,"precision":23},"VERTEX_SHADER_HIGH_FLOAT":{"range_min":127,"range_max":127,"precision":23},"FRAGMENT_SHADER_LOW_FLOAT":{"range_min":127,"range_max":127,"precision":23},"FRAGMENT_SHADER_MEDIUM_FLOAT":{"range_min":127,"range_max":127,"precision":23},"FRAGMENT_SHADER_HIGH_FLOAT":{"range_min":127,"range_max":127,"precision":23}},"context_attributes":{"antialias":true,"depth":true,"stencil":true,"alpha":true,"premultipliedAlpha":true,"preserveDrawingBuffer":false,"failIfMajorPerformanceCaveat":false}}`)
	// Valid plugins (standard Chrome 5 with MIME types)
	req.Header.Set("X-Plugin-Data", `{"plugins":[{"name":"PDF Viewer","filename":"internal-pdf-viewer","mimeTypes":["application/pdf"]},{"name":"Chrome PDF Viewer","filename":"internal-pdf-viewer","mimeTypes":["application/pdf"]},{"name":"Chromium PDF Viewer","filename":"internal-pdf-viewer","mimeTypes":["application/pdf"]},{"name":"Microsoft Edge PDF Viewer","filename":"internal-pdf-viewer","mimeTypes":["application/pdf"]},{"name":"WebKit built-in PDF","filename":"internal-pdf-viewer","mimeTypes":["application/pdf"]}],"plugin_count":5}`)
	// Valid screen (desktop with taskbar, browser chrome, and orientation)
	req.Header.Set("X-Screen-Data", `{"width":1920,"height":1080,"avail_width":1920,"avail_height":1040,"color_depth":24,"pixel_ratio":1.0,"outer_width":1920,"outer_height":1040,"inner_width":1903,"inner_height":969,"orientation_type":"landscape-primary","orientation_angle":0,"is_extended":false,"has_orientation_lock":false}`)
	// Valid fonts (Windows with Segoe UI)
	req.Header.Set("X-Font-Data", `{"fonts":["Arial","Times New Roman","Courier New","Georgia","Verdana","Segoe UI","Calibri","Consolas","Tahoma","Trebuchet MS","Impact","Comic Sans MS","Palatino Linotype","Lucida Console","Lucida Sans Unicode","MS Gothic","MS Mincho","MS PGothic","MS PMincho","MS Sans Serif","MS Serif","MS UI Gothic"],"font_count":22,"platform":"windows"}`)
	// Natural timing (18 entries in correct order) with non-zero TTFB and URLs.
	req.Header.Set("X-Timing-Data", `{"ttfb":120,"navigationStart":1709500000000,"loadEventEnd":1709500003000,"entries":[{"timestamp_ms":0,"responseEnd":1709500000100,"content_type":"text/html","referrer":"","url":"http://example.com/","transfer_size":5000,"encoded_body_size":4800,"next_hop_protocol":"h2"},{"timestamp_ms":150,"responseEnd":1709500000250,"content_type":"text/css","referrer":"http://example.com","url":"http://example.com/style.css","transfer_size":1200,"encoded_body_size":1000, "next_hop_protocol":"h2"},{"timestamp_ms":220,"responseEnd":1709500000320,"content_type":"text/css","referrer":"http://example.com","url":"http://example.com/theme.css","transfer_size":800,"encoded_body_size":600, "next_hop_protocol":"h2"},{"timestamp_ms":310,"responseEnd":1709500000410,"content_type":"text/css","referrer":"http://example.com","url":"http://example.com/layout.css","transfer_size":1500,"encoded_body_size":1300, "next_hop_protocol":"h2"},{"timestamp_ms":420,"responseEnd":1709500000620,"content_type":"application/javascript","referrer":"http://example.com","url":"http://example.com/app.js","transfer_size":50000,"encoded_body_size":45000, "next_hop_protocol":"h2"},{"timestamp_ms":530,"responseEnd":1709500000830,"content_type":"application/javascript","referrer":"http://example.com","url":"http://example.com/vendor.js","transfer_size":120000,"encoded_body_size":110000, "next_hop_protocol":"h2"},{"timestamp_ms":620,"responseEnd":1709500000720,"content_type":"application/javascript","referrer":"http://example.com","url":"http://example.com/utils.js","transfer_size":5000,"encoded_body_size":4000, "next_hop_protocol":"h2"},{"timestamp_ms":700,"responseEnd":1709500000800,"content_type":"application/javascript","referrer":"http://example.com","url":"http://example.com/api.js","transfer_size":2000,"encoded_body_size":1500, "next_hop_protocol":"h2"},{"timestamp_ms":1050,"responseEnd":1709500001150,"content_type":"image/png","referrer":"http://example.com","url":"http://example.com/logo.png","transfer_size":15000,"encoded_body_size":15000, "next_hop_protocol":"h2"},{"timestamp_ms":1250,"responseEnd":1709500001450,"content_type":"image/jpeg","referrer":"http://example.com","url":"http://example.com/hero.jpg","transfer_size":85000,"encoded_body_size":85000, "next_hop_protocol":"h2"},{"timestamp_ms":1400,"responseEnd":1709500001500,"content_type":"image/webp","referrer":"http://example.com","url":"http://example.com/avatar.webp","transfer_size":12000,"encoded_body_size":12000, "next_hop_protocol":"h2"},{"timestamp_ms":1500,"responseEnd":1709500001550,"content_type":"image/svg+xml","referrer":"http://example.com","url":"http://example.com/icon.svg","transfer_size":1000,"encoded_body_size":1000, "next_hop_protocol":"h2"},{"timestamp_ms":1600,"responseEnd":1709500001800,"content_type":"image/png","referrer":"http://example.com","url":"http://example.com/bg.png","transfer_size":250000,"encoded_body_size":250000, "next_hop_protocol":"h2"},{"timestamp_ms":1900,"responseEnd":1709500002100,"content_type":"font/woff2","referrer":"http://example.com","url":"http://example.com/font1.woff2","transfer_size":32000,"encoded_body_size":32000, "next_hop_protocol":"h2"},{"timestamp_ms":2050,"responseEnd":1709500002250,"content_type":"font/woff2","referrer":"http://example.com","url":"http://example.com/font2.woff2","transfer_size":45000,"encoded_body_size":45000, "next_hop_protocol":"h2"},{"timestamp_ms":2150,"responseEnd":1709500002350,"content_type":"font/woff2","referrer":"http://example.com","url":"http://example.com/font3.woff2","transfer_size":18000,"encoded_body_size":18000, "next_hop_protocol":"h2"},{"timestamp_ms":2500,"responseEnd":1709500002600,"content_type":"application/json","referrer":"http://example.com","url":"http://example.com/api/v1/data","transfer_size":1200,"encoded_body_size":800, "next_hop_protocol":"h2"},{"timestamp_ms":2800,"responseEnd":1709500002900,"content_type":"application/json","referrer":"http://example.com","url":"http://example.com/api/v1/user","transfer_size":600,"encoded_body_size":400, "next_hop_protocol":"h2"}],"paint_entries":[{"name":"first-paint","start_time":600},{"name":"first-contentful-paint","start_time":650}]}`)
	req.Header.Set("X-Audio-Data", `{"sample_rate":44100,"channel_count":2,"max_channel_count":2,"base_latency":0.012345,"output_latency":0.012345,"state":"running","audio_worklet_available":true,"offline_context_hash":"abcdef123456","compressor_attack":0.003,"compressor_release":0.25}`)
	// Valid canvas fingerprint
	req.Header.Set("X-Canvas-Fingerprint", `{"hash":"data:image/png;base64,iVBOR","consistent":true}`)
	// Human-like behavioral data with real epoch timestamps.
	// Includes micro-tremors (1-3px jitter), bimodal velocity (slow + fast),
	// overshoots/corrections, and varied segment efficiency.
	// Velocities all above 5.0 to avoid velocity_low detection.
	// Events interleaved to avoid sequential ordering detection.
	// Click positions offset 4-7px from nearest mouse position (human imprecision)
	// with non-integer coordinates to avoid click_position_too_precise.
	// Scroll data: positive autocorrelation (momentum), correlated intervals/deltas,
	// high interval CV (>0.50), varied delta ratios (stddev >0.15).
	// Mouse intervals have temporal clustering (fast burst then slow).
	// Click velocities are low (near slow mouse events) = deceleration before click.
	// Mouse density drops during typing phase.
	// Velocities follow a smooth arc (lag-2 autocorr ~0.38, lag-3 ~0.06) to
	// pass Checks 27/28. Only 3 clicks = 2 Fitts pairs (below min 3), so
	// Check 29 does not fire.
	req.Header.Set("X-Behavioral-Data", `{
		"mouseTimestamps": [1709500003500,1709500003532,1709500003578,1709500003631,1709500003692,1709500003784,1709500003867,1709500005000,1709500005600,1709500006000,1709500006700,1709500007600],
		"typingTimestamps": [1709500004500,1709500004587,1709500004743,1709500005500,1709500005700,1709500006300,1709500007000,1709500007700],
		"scrollTimestamps": [1709500004300,1709500004355,1709500006155,1709500008055,1709500008120,1709500008820],
		"scrollDeltas": [350,320,300,100,120,80],
		"clickTimestamps": [1709500004150,1709500006200,1709500007500],
		"clickPositions": [{"x":398.3,"y":168.7},{"x":205.1,"y":220.4},{"x":425.8,"y":305.2}],
		"mousePositions": [
			{"x":100,"y":200},{"x":101.2,"y":200.8},{"x":102.5,"y":199.3},{"x":115,"y":190},
			{"x":135,"y":178},{"x":160,"y":175},{"x":161.5,"y":175.8},{"x":395,"y":165},
			{"x":200,"y":215},{"x":420,"y":300},{"x":500,"y":340},{"x":550,"y":350}
		],
		"mouseVelocities": [30,60,110,170,210,230,240,235,230,225,215,200]
	}`)

	detection := detector.AnalyzeRequest(req, nil)

	if detection.Score >= 0.35 {
		t.Errorf("perfect stealth request should pass (score < 0.35), got %.3f", detection.Score)
		fmt.Println("  Triggered vectors:")
		for _, v := range detection.Vectors {
			if v.Detected {
				fmt.Printf("    %s: %.3f %v\n", v.Category, v.Score, v.Indicators)
			}
		}
	}

	if detection.IsBot {
		t.Error("perfect stealth request should not be classified as bot")
	}
}
