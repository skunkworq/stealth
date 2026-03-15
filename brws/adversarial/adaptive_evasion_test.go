package adversarial_test

import (
	"fmt"
	"testing"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/behavior"
)

// TestAdaptiveEvasionFSM runs the finite state machine loop against the shield.
// The shield should catch the current strategy set and force the FSM to walk
// through the ladder instead of converging on the first transport trick.
func TestAdaptiveEvasionFSM(t *testing.T) {
	shield := adversarial.NewStealthDetector()
	profiles := []*behavior.BrowserProfile{
		behavior.ChromeWindowsProfile(),
		behavior.ChromeMacOSProfile(),
		behavior.ChromeLinuxProfile(),
		behavior.FirefoxWindowsProfile(),
	}

	maxTrials := len(behavior.DefaultStrategies()) * 3

	for _, profile := range profiles {
		t.Run(profile.Name, func(t *testing.T) {
			fsm := behavior.NewAdaptiveEvasionFSM()

			for trial := 0; trial < maxTrials; trial++ {
				strategy := fsm.CurrentStrategy()

				config := behavior.MaxEvasionConfig(profile)
				config.EvasionStrategy = strategy

				rg := behavior.NewRequestGenerator(config)
				req := rg.GenerateRequest("https://example.com/api/telemetry")
				result := shield.AnalyzeRequest(req, nil)

				fsm.RecordResult(result.Score, result.IsBot)

			}

			strategy := fsm.CurrentStrategy()
			t.Logf("\n%s", fsm.Summary())
			t.Logf("Ended on: %s (fidelity=%.0f%%)", strategy.Name(), strategy.Fidelity()*100)

			if fsm.Converged() {
				t.Errorf("FSM should not converge when the shield catches every strategy")
			}
			if fsm.StateIndex() != len(behavior.DefaultStrategies())-1 {
				t.Errorf("FSM should advance to terminal state %d, got %d", len(behavior.DefaultStrategies())-1, fsm.StateIndex())
			}
		})
	}
}

// TestEvasionStrategyComparison runs every strategy independently against the
// shield for every profile and reports a fidelity vs detection matrix.
func TestEvasionStrategyComparison(t *testing.T) {
	shield := adversarial.NewStealthDetector()
	profiles := []*behavior.BrowserProfile{
		behavior.ChromeWindowsProfile(),
		behavior.ChromeMacOSProfile(),
		behavior.ChromeLinuxProfile(),
		behavior.FirefoxWindowsProfile(),
	}
	strategies := behavior.DefaultStrategies()
	trials := 20

	t.Logf("\n%-24s %-22s  %8s  %8s  %10s  %s",
		"Profile", "Strategy", "Fidelity", "Det%", "AvgScore", "Result")
	t.Logf("%-24s %-22s  %8s  %8s  %10s  %s",
		"-------", "--------", "--------", "----", "--------", "------")

	for _, profile := range profiles {
		for _, strategy := range strategies {
			detections := 0
			var totalScore float64
			indicators := make(map[string]int)

			for i := 0; i < trials; i++ {
				config := behavior.MaxEvasionConfig(profile)
				config.EvasionStrategy = strategy

				rg := behavior.NewRequestGenerator(config)
				req := rg.GenerateRequest("https://example.com/api/telemetry")
				result := shield.AnalyzeRequest(req, nil)

				totalScore += result.Score
				if result.IsBot {
					detections++
				}
				for _, ind := range result.Indicators {
					indicators[ind.Name]++
				}
			}

			avgScore := totalScore / float64(trials)
			detRate := float64(detections) / float64(trials)
			status := "WEAK"
			if detRate >= 0.95 {
				status = "CAUGHT"
			}

			t.Logf("%-24s %-22s  %7.0f%%  %7.0f%%  %9.3f  %s",
				profile.Name, strategy.Name(),
				strategy.Fidelity()*100, detRate*100, avgScore, status)

			if detRate < 0.95 {
				t.Errorf("%s/%s detection %.0f%% < 95%%", profile.Name, strategy.Name(), detRate*100)
			}
			if avgScore < 0.50 {
				t.Errorf("%s/%s avg score %.3f < 0.50", profile.Name, strategy.Name(), avgScore)
			}

			// Show top indicators if any detection occurred
			if detRate > 0 {
				type hit struct {
					name  string
					count int
				}
				var hits []hit
				for name, count := range indicators {
					hits = append(hits, hit{name, count})
				}
				for i := 0; i < len(hits); i++ {
					for j := i + 1; j < len(hits); j++ {
						if hits[j].count > hits[i].count {
							hits[i], hits[j] = hits[j], hits[i]
						}
					}
				}
				for k := 0; k < len(hits) && k < 3; k++ {
					t.Logf("  %55s  %s (%d/%d)",
						"", hits[k].name, hits[k].count, trials)
				}
			}
		}
	}
}

// TestFSMFallbackConvergence verifies the FSM exhausts the strategy ladder when
// the shield catches every available evasion strategy.
func TestFSMFallbackConvergence(t *testing.T) {
	shield := adversarial.NewStealthDetector()
	profile := behavior.ChromeWindowsProfile()

	fsm := behavior.NewAdaptiveEvasionFSM()

	maxTrials := len(behavior.DefaultStrategies()) * 3
	for trial := 0; trial < maxTrials; trial++ {
		strategy := fsm.CurrentStrategy()

		config := behavior.MaxEvasionConfig(profile)
		config.EvasionStrategy = strategy

		rg := behavior.NewRequestGenerator(config)
		req := rg.GenerateRequest("https://example.com/api/telemetry")
		result := shield.AnalyzeRequest(req, nil)

		fsm.RecordResult(result.Score, result.IsBot)
	}

	t.Logf("\n%s", fsm.Summary())

	if fsm.Converged() {
		t.Error("FSM should not converge when the shield catches every strategy")
	}

	strategy := fsm.CurrentStrategy()
	t.Logf("Final strategy: %s (fidelity=%.0f%%)", strategy.Name(), strategy.Fidelity()*100)

	if fsm.StateIndex() != len(behavior.DefaultStrategies())-1 {
		t.Fatalf("FSM should end on terminal state %d, got state %d", len(behavior.DefaultStrategies())-1, fsm.StateIndex())
	}

	// Verify the terminal strategy is also still caught.
	config := behavior.MaxEvasionConfig(profile)
	config.EvasionStrategy = strategy

	detectionCount := 0
	for i := 0; i < 20; i++ {
		rg := behavior.NewRequestGenerator(config)
		req := rg.GenerateRequest("https://example.com/api/telemetry")
		result := shield.AnalyzeRequest(req, nil)
		if result.IsBot {
			detectionCount++
		}
	}

	detectionRate := float64(detectionCount) / 20.0
	t.Logf("Verification: %s detected %.0f%%", strategy.Name(), detectionRate*100)

	if detectionRate < 0.95 {
		t.Errorf("terminal strategy should still be detected, got %.0f%% detection", detectionRate*100)
	}
}

// TestFidelityPreservation verifies high-fidelity strategies preserve data.
func TestFidelityPreservation(t *testing.T) {
	profile := behavior.ChromeWindowsProfile()
	strategies := behavior.DefaultStrategies()

	headerNames := []string{
		"X-Navigator-Data", "X-WebGL-Data", "X-Plugin-Data",
		"X-Screen-Data", "X-Font-Data", "X-WebRTC-Data",
		"X-Behavioral-Data", "X-Timing-Data",
		"X-Canvas-Fingerprint", "X-Audio-Data",
	}

	for _, strategy := range strategies {
		t.Run(strategy.Name(), func(t *testing.T) {
			config := behavior.MaxEvasionConfig(profile)
			config.EvasionStrategy = strategy

			rg := behavior.NewRequestGenerator(config)
			req := rg.GenerateRequest("https://example.com/api/telemetry")

			headerPresent := 0
			for _, h := range headerNames {
				if req.Header.Get(h) != "" {
					headerPresent++
				}
			}

			bodyHasData := false
			if req.Body != nil {
				buf := make([]byte, 64*1024)
				n, _ := req.Body.Read(buf)
				bodyStr := string(buf[:n])
				for _, kw := range []string{"navigator", "timing", "canvas", "audio", "webgl"} {
					if len(bodyStr) > 0 && containsStr(bodyStr, kw) {
						bodyHasData = true
						break
					}
				}
			}

			t.Logf("%-22s: headers_present=%d/10 body_has_data=%v fidelity=%.0f%%",
				strategy.Name(), headerPresent, bodyHasData, strategy.Fidelity()*100)

			// High-fidelity strategies must have data somewhere
			if strategy.Fidelity() >= 0.9 {
				if headerPresent < 5 && !bodyHasData {
					t.Errorf("high-fidelity strategy %q preserves no data (headers=%d, body=%v)",
						strategy.Name(), headerPresent, bodyHasData)
				}
			}
		})
	}
}

// TestArmedSwordWithAdaptiveStrategy verifies the shield catches the armed
// sword's adaptive strategy across all browser profiles.
func TestArmedSwordWithAdaptiveStrategy(t *testing.T) {
	shield := adversarial.NewStealthDetector()
	profiles := []*behavior.BrowserProfile{
		behavior.ChromeWindowsProfile(),
		behavior.ChromeMacOSProfile(),
		behavior.ChromeLinuxProfile(),
		behavior.FirefoxWindowsProfile(),
	}

	trials := 20
	totalDetections := 0
	totalTrials := 0
	var totalScore float64

	for _, profile := range profiles {
		t.Run(fmt.Sprintf("adaptive_%s", profile.Name), func(t *testing.T) {
			detections := 0
			var score float64

			for i := 0; i < trials; i++ {
				config := behavior.MaxEvasionConfig(profile)
				rg := behavior.NewRequestGenerator(config)
				req := rg.GenerateRequest("https://example.com/api/telemetry")
				result := shield.AnalyzeRequest(req, nil)

				score += result.Score
				if result.IsBot {
					detections++
				}
			}

			avgScore := score / float64(trials)
			detectionRate := float64(detections) / float64(trials)
			totalDetections += detections
			totalTrials += trials
			totalScore += score

			t.Logf("Adaptive %s: detection=%.0f%% avg_score=%.3f",
				profile.Name, detectionRate*100, avgScore)

			if detectionRate < 0.95 {
				t.Errorf("adaptive strategy detected %.0f%% (want >= 95%%)", detectionRate*100)
			}
			if avgScore < 0.50 {
				t.Errorf("adaptive strategy avg_score=%.3f (want >= 0.50)", avgScore)
			}
		})
	}

	overallDetectionRate := float64(totalDetections) / float64(totalTrials)
	overallAvgScore := totalScore / float64(totalTrials)
	t.Logf("\nOverall: detection=%.0f%% avg_score=%.3f",
		overallDetectionRate*100, overallAvgScore)

	if overallDetectionRate < 0.95 {
		t.Errorf("expected overall detection >= 95%%, got %.0f%%", overallDetectionRate*100)
	}
	if overallAvgScore < 0.50 {
		t.Errorf("expected overall avg score >= 0.50, got %.3f", overallAvgScore)
	}
}

// TestFSMExhaustionSignal verifies that when the shield catches all strategies,
// the FSM exhausts and recommends browser escalation.
func TestFSMExhaustionSignal(t *testing.T) {
	shield := adversarial.NewStealthDetector()
	profile := behavior.ChromeWindowsProfile()

	fsm := behavior.NewAdaptiveEvasionFSM()

	maxTrials := len(behavior.DefaultStrategies()) * 3
	for trial := 0; trial < maxTrials; trial++ {
		strategy := fsm.CurrentStrategy()

		config := behavior.MaxEvasionConfig(profile)
		config.EvasionStrategy = strategy

		rg := behavior.NewRequestGenerator(config)
		req := rg.GenerateRequest("https://example.com/api/telemetry")
		result := shield.AnalyzeRequest(req, nil)

		fsm.RecordResult(result.Score, result.IsBot)
	}

	t.Logf("\n%s", fsm.Summary())

	if !fsm.Exhausted() {
		t.Error("FSM should exhaust when every strategy is caught")
	}

	if fsm.Converged() {
		t.Error("FSM should not converge when every strategy is caught")
	}

	if !fsm.ShouldEscalate() {
		t.Error("FSM should recommend escalation after exhaustion")
	}
}

// TestExoticDestStrategiesBlockedOnTelemetryURLs verifies that after shield
// hardening, exotic dest strategies are caught when targeting telemetry URLs.
// The shield's exotic dest + telemetry URL gate blocks these.
func TestExoticDestStrategiesBlockedOnTelemetryURLs(t *testing.T) {
	shield := adversarial.NewStealthDetector()
	profile := behavior.ChromeWindowsProfile()

	strategies := []behavior.EvasionStrategy{
		&behavior.IframeNavigationStrategy{},
		&behavior.ScriptFetchStrategy{},
		&behavior.ImagePixelStrategy{},
		&behavior.StyleFetchStrategy{},
		&behavior.WorkerImportStrategy{},
	}

	for _, s := range strategies {
		t.Run(s.Name(), func(t *testing.T) {
			detections := 0
			var totalScore float64
			trials := 10

			for i := 0; i < trials; i++ {
				config := behavior.MaxEvasionConfig(profile)
				config.EvasionStrategy = s
				gen := behavior.NewRequestGenerator(config)
				req := gen.GenerateRequest("https://api.example.com/telemetry")
				result := shield.AnalyzeRequest(req, nil)

				totalScore += result.Score
				if result.IsBot {
					detections++
				}
			}

			avgScore := totalScore / float64(trials)
			detRate := float64(detections) / float64(trials)

			t.Logf("%-20s detection=%.0f%% avg_score=%.3f", s.Name(), detRate*100, avgScore)

			// Shield should now catch these on telemetry URLs
			if detRate < 0.80 {
				t.Errorf("exotic dest strategy %q should be caught on telemetry URLs: only %.0f%% detected", s.Name(), detRate*100)
			}
		})
	}
}

// TestExoticDestStrategiesEvadeOnPageURLs verifies exotic dest strategies still
// evade on normal page URLs (the exotic dest + telemetry URL gate only fires
// for telemetry/API endpoints).
func TestExoticDestStrategiesEvadeOnPageURLs(t *testing.T) {
	shield := adversarial.NewStealthDetector()
	profile := behavior.ChromeWindowsProfile()

	strategies := []behavior.EvasionStrategy{
		&behavior.IframeNavigationStrategy{},
		&behavior.ScriptFetchStrategy{},
		&behavior.ImagePixelStrategy{},
		&behavior.StyleFetchStrategy{},
		&behavior.WorkerImportStrategy{},
	}

	for _, s := range strategies {
		t.Run(s.Name(), func(t *testing.T) {
			detections := 0
			var totalScore float64
			trials := 20

			for i := 0; i < trials; i++ {
				config := behavior.MaxEvasionConfig(profile)
				config.EvasionStrategy = s
				gen := behavior.NewRequestGenerator(config)
				req := gen.GenerateRequest("https://www.example.com/products/shoes")
				result := shield.AnalyzeRequest(req, nil)

				totalScore += result.Score
				if result.IsBot {
					detections++
				}
			}

			avgScore := totalScore / float64(trials)
			detRate := float64(detections) / float64(trials)

			t.Logf("%-20s detection=%.0f%% avg_score=%.3f", s.Name(), detRate*100, avgScore)

			if detRate > 0.05 {
				t.Errorf("exotic dest strategy %q on page URL detected %.0f%% (want < 5%%)", s.Name(), detRate*100)
			}
			if avgScore > 0.30 {
				t.Errorf("exotic dest strategy %q on page URL avg_score=%.3f (want < 0.30)", s.Name(), avgScore)
			}
		})
	}
}

// TestChromeFetchStrategiesEvadeTelemetryURLs verifies the new Chrome
// same-origin fetch strategies evade the shield on telemetry URLs.
func TestChromeFetchStrategiesEvadeTelemetryURLs(t *testing.T) {
	shield := adversarial.NewStealthDetector()
	profile := behavior.ChromeWindowsProfile()

	strategies := []behavior.EvasionStrategy{
		&behavior.ChromeSameOriginFetchStrategy{},
		&behavior.ChromeCrossSiteFetchStrategy{},
		&behavior.ChromeNoCORSBeaconStrategy{},
	}

	for _, s := range strategies {
		t.Run(s.Name(), func(t *testing.T) {
			detections := 0
			var totalScore float64
			trials := 20

			for i := 0; i < trials; i++ {
				config := behavior.MaxEvasionConfig(profile)
				config.EvasionStrategy = s
				gen := behavior.NewRequestGenerator(config)
				req := gen.GenerateRequest("https://api.example.com/telemetry")
				result := shield.AnalyzeRequest(req, nil)

				totalScore += result.Score
				if result.IsBot {
					detections++
				}

				if i == 0 {
					t.Logf("  vectors: %d, total_score=%.3f", len(result.Vectors), result.Score)
					for _, v := range result.Vectors {
						t.Logf("    %s: score=%.3f weight=%.2f detected=%v indicators=%v",
							v.Name, v.Score, v.Weight, v.Detected, v.Indicators)
					}
				}
			}

			avgScore := totalScore / float64(trials)
			detRate := float64(detections) / float64(trials)

			t.Logf("%-30s detection=%.0f%% avg_score=%.3f", s.Name(), detRate*100, avgScore)

			if detRate > 0.05 {
				t.Errorf("Chrome fetch strategy %q detected %.0f%% (want < 5%%)", s.Name(), detRate*100)
			}
			// Bot threshold is 0.35 — strategies must stay below it
			if avgScore > 0.35 {
				t.Errorf("Chrome fetch strategy %q avg_score=%.3f (want < 0.35)", s.Name(), avgScore)
			}
		})
	}
}

// TestURLAwareFSMConvergesOnTelemetryURL verifies the URL-aware FSM converges
// on an exotic dest strategy for telemetry URLs instead of exhausting.
func TestURLAwareFSMConvergesOnTelemetryURL(t *testing.T) {
	shield := adversarial.NewStealthDetector()
	profile := behavior.ChromeWindowsProfile()
	targetURL := "https://api.example.com/telemetry"

	fsm := behavior.NewAdaptiveEvasionFSMForURL(targetURL)

	// Run enough trials to let the FSM converge
	maxTrials := len(behavior.StrategiesForURL(targetURL)) * 3
	for trial := 0; trial < maxTrials; trial++ {
		strategy := fsm.CurrentStrategy()
		config := behavior.MaxEvasionConfig(profile)
		config.EvasionStrategy = strategy
		gen := behavior.NewRequestGenerator(config)
		req := gen.GenerateRequest(targetURL)
		result := shield.AnalyzeRequest(req, nil)
		fsm.RecordResult(result.Score, result.IsBot)

		// Stop early if converged
		if fsm.Converged() {
			break
		}
	}

	t.Logf("\n%s", fsm.Summary())

	strategy := fsm.CurrentStrategy()
	t.Logf("Converged on: %s (fidelity=%.0f%%)", strategy.Name(), strategy.Fidelity()*100)

	// The FSM should converge — NOT exhaust
	if fsm.Exhausted() {
		t.Error("URL-aware FSM should converge on an exotic dest strategy, not exhaust")
	}
	if !fsm.Converged() {
		t.Error("URL-aware FSM should converge on one of the exotic dest strategies")
	}

	// The converged strategy should be one of the Chrome fetch strategies
	// (these bypass catch-all via Sec-Ch-Ua and coverage via pre-load headers)
	chromeNames := map[string]bool{
		"chrome_same_origin_fetch": true,
		"chrome_cross_site_fetch":  true,
		"chrome_nocors_beacon":     true,
	}
	if !chromeNames[strategy.Name()] {
		t.Errorf("expected convergence on a Chrome fetch strategy, got %q", strategy.Name())
	}
}

// TestURLClassification verifies the URL classifier mirrors the shield's detection patterns.
func TestURLClassification(t *testing.T) {
	tests := []struct {
		url      string
		wantType behavior.URLType
	}{
		{"https://api.example.com/telemetry", behavior.URLTypeTelemetry},
		{"https://api.example.com/v1/data", behavior.URLTypeTelemetry},    // api. prefix
		{"https://metrics.example.com/report", behavior.URLTypeTelemetry}, // metrics. prefix
		{"https://example.com/api/ml/trap", behavior.URLTypeTelemetry},    // /api/ml/ path
		{"https://example.com/collect", behavior.URLTypeTelemetry},        // /collect path
		{"https://example.com/beacon", behavior.URLTypeTelemetry},         // /beacon path
		{"https://www.example.com/", behavior.URLTypePage},
		{"https://www.example.com/about", behavior.URLTypePage},
		{"https://example.com/products/widget", behavior.URLTypePage},
		{"https://data.example.com/ingest", behavior.URLTypePage}, // not in shield's pattern list
	}

	chromeStrategies := map[string]bool{
		"chrome_same_origin_fetch": true,
		"chrome_cross_site_fetch":  true,
		"chrome_nocors_beacon":     true,
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			strategies := behavior.StrategiesForURL(tt.url)
			gotType := behavior.URLTypePage
			if chromeStrategies[strategies[0].Name()] {
				gotType = behavior.URLTypeTelemetry
			}
			if gotType != tt.wantType {
				t.Errorf("classifyURL(%q) = %d, want %d (first strategy=%q)", tt.url, gotType, tt.wantType, strategies[0].Name())
			}
		})
	}
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
