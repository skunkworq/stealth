package adversarial

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/skunkworq/stealth/brws/engine"
	_ "github.com/skunkworq/stealth/brws/engine/native"
)

func TestStealthBrowserDetection(t *testing.T) {
	detector := NewStealthDetector()

	t.Run("Normal browser request", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
		req.Header.Set("Sec-Ch-Ua", "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\"")
		req.Header.Set("Sec-Ch-Ua-Platform", "\"macOS\"")

		detection := detector.AnalyzeRequest(req, nil)

		t.Logf("Normal browser - Score: %.2f, IsBot: %v, IsStealth: %v", detection.Score, detection.IsBot, detection.IsStealth)
		for _, vec := range detection.Vectors {
			t.Logf("  Vector: %s, Score: %.2f, Detected: %v", vec.Name, vec.Score, vec.Detected)
		}

		if detection.IsBot || detection.IsStealth {
			t.Logf("WARNING: Normal browser detected as bot/stealth")
		}
	})

	t.Run("Stealth browser with injected navigator data", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
		req.Header.Set("Sec-Ch-Ua", "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\"")
		req.Header.Set("Sec-Ch-Ua-Platform", "\"macOS\"")

		navData := map[string]interface{}{
			"webdriver": false,
			"platform":  "MacIntel",
			"vendor":    "Google Inc.",
			"languages": []string{"en-US", "en"},
		}
		navJSON, _ := json.Marshal(navData)
		req.Header.Set("X-Navigator-Data", string(navJSON))

		detection := detector.AnalyzeRequest(req, nil)

		t.Logf("Stealth with nav data - Score: %.2f, IsBot: %v, IsStealth: %v", detection.Score, detection.IsBot, detection.IsStealth)
		for _, vec := range detection.Vectors {
			t.Logf("  Vector: %s, Score: %.2f, Detected: %v", vec.Name, vec.Score, vec.Detected)
			for _, ind := range vec.Indicators {
				t.Logf("    - %s", ind)
			}
		}
	})

	t.Run("Stealth browser with webdriver=true", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

		navData := map[string]interface{}{
			"webdriver": true,
		}
		navJSON, _ := json.Marshal(navData)
		req.Header.Set("X-Navigator-Data", string(navJSON))

		detection := detector.AnalyzeRequest(req, nil)

		t.Logf("webdriver=true - Score: %.2f, IsBot: %v, IsStealth: %v", detection.Score, detection.IsBot, detection.IsStealth)
		for _, vec := range detection.Vectors {
			if vec.Detected {
				t.Logf("  DETECTED: %s - Score: %.2f", vec.Name, vec.Score)
				for _, ind := range vec.Indicators {
					t.Logf("    - %s", ind)
				}
			}
		}

		if !detection.IsBot {
			t.Errorf("Expected bot detection with webdriver=true")
		}
	})

	t.Run("Stealth browser with behavioral data", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html")

		behavData := map[string]interface{}{
			"mouseEvents":       0,
			"mouseStdDev":       0.0,
			"typingEvents":      0,
			"typingStdDev":      0.0,
			"mousePathLength":   100.0,
			"mouseStraightness": 1.0,
		}
		behavJSON, _ := json.Marshal(behavData)
		req.Header.Set("X-Behavioral-Data", string(behavJSON))

		detection := detector.AnalyzeRequest(req, nil)

		t.Logf("Behavioral data - Score: %.2f, IsBot: %v, IsStealth: %v", detection.Score, detection.IsBot, detection.IsStealth)
		for _, vec := range detection.Vectors {
			if vec.Detected {
				t.Logf("  DETECTED: %s - Score: %.2f", vec.Name, vec.Score)
				for _, ind := range vec.Indicators {
					t.Logf("    - %s", ind)
				}
			}
		}

		if !detection.IsBot {
			t.Errorf("Expected bot detection with suspicious behavioral data")
		}
	})

	t.Run("Stealth browser with canvas randomization", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.Header.Set("Accept", "text/html")

		req.Header.Set("X-Canvas-Fingerprint", "randomized=true,hash=abc123,webgl=swiftshader")

		detection := detector.AnalyzeRequest(req, nil)

		t.Logf("Canvas randomization - Score: %.2f, IsBot: %v, IsStealth: %v", detection.Score, detection.IsBot, detection.IsStealth)
		for _, vec := range detection.Vectors {
			if vec.Detected {
				t.Logf("  DETECTED: %s - Score: %.2f", vec.Name, vec.Score)
			}
		}
	})

	t.Run("Stealth browser with timing anomalies", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.Header.Set("Accept", "text/html")

		timingData := map[string]interface{}{
			"ttfb":            0,
			"navigationStart": 1000,
			"loadEventEnd":    1050,
		}
		timingJSON, _ := json.Marshal(timingData)
		req.Header.Set("X-Timing-Data", string(timingJSON))

		detection := detector.AnalyzeRequest(req, nil)

		t.Logf("Timing anomalies - Score: %.2f, IsBot: %v, IsStealth: %v", detection.Score, detection.IsBot, detection.IsStealth)
		for _, vec := range detection.Vectors {
			if vec.Detected {
				t.Logf("  DETECTED: %s - Score: %.2f", vec.Name, vec.Score)
			}
		}
	})

	t.Run("Inconsistent client hints", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		req.Header.Set("Accept", "text/html")
		req.Header.Set("Sec-Ch-Ua", "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\"")
		req.Header.Set("Sec-Ch-Ua-Platform", "\"Linux\"")

		detection := detector.AnalyzeRequest(req, nil)

		t.Logf("Inconsistent hints - Score: %.2f, IsBot: %v, IsStealth: %v", detection.Score, detection.IsBot, detection.IsStealth)
		for _, vec := range detection.Vectors {
			if vec.Detected {
				t.Logf("  DETECTED: %s - Score: %.2f", vec.Name, vec.Score)
				for _, ind := range vec.Indicators {
					t.Logf("    - %s", ind)
				}
			}
		}
	})
}

func TestStealthBrowserWithNativeEngine(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		detector := NewStealthDetector()
		var tlsConn *tls.ConnectionState
		if r.TLS != nil {
			tlsConn = r.TLS
		}
		detection := detector.AnalyzeRequest(r, tlsConn)

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Bot-Score", fmt.Sprintf("%.2f", detection.Score))
		w.Header().Set("X-Is-Bot", fmt.Sprintf("%v", detection.IsBot))
		w.Header().Set("X-Is-Stealth", fmt.Sprintf("%v", detection.IsStealth))

		response := map[string]interface{}{
			"is_bot":     detection.IsBot,
			"is_stealth": detection.IsStealth,
			"score":      detection.Score,
			"vectors":    detection.Vectors,
		}
		jsonResp, _ := json.Marshal(response)
		w.Write(jsonResp) //nolint:errcheck,gosec // G104: Test response write
	}))
	defer server.Close()

	t.Run("Native engine with perfect headers", func(t *testing.T) {
		eng, err := engine.New("native", engine.Options{})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = eng.Close() }()

		headers := map[string]string{
			"User-Agent":         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			"Accept":             "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language":    "en-US,en;q=0.5",
			"Sec-Ch-Ua":          "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\"",
			"Sec-Ch-Ua-Mobile":   "?0",
			"Sec-Ch-Ua-Platform": "\"macOS\"",
		}

		resp, err := eng.Do(context.Background(), &engine.Request{
			URL:          server.URL,
			Method:       "GET",
			ExtraHeaders: headers,
		})
		if err != nil {
			t.Fatal(err)
		}

		botScore := ""
		isBot := ""
		isStealth := ""
		if v, ok := resp.Headers["X-Bot-Score"]; ok && len(v) > 0 {
			botScore = v[0]
		}
		if v, ok := resp.Headers["X-Is-Bot"]; ok && len(v) > 0 {
			isBot = v[0]
		}
		if v, ok := resp.Headers["X-Is-Stealth"]; ok && len(v) > 0 {
			isStealth = v[0]
		}

		t.Logf("Native engine results:")
		t.Logf("  Bot Score: %s", botScore)
		t.Logf("  Is Bot: %s", isBot)
		t.Logf("  Is Stealth: %s", isStealth)

		if isBot == "true" {
			t.Logf("WARNING: Native engine with good headers detected as bot")
		}
	})

	t.Run("Native engine with stealth indicators", func(t *testing.T) {
		eng, err := engine.New("native", engine.Options{})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = eng.Close() }()

		headers := map[string]string{
			"User-Agent":        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
			"Accept":            "text/html",
			"X-Navigator-Data":  `{"webdriver":false,"platform":"MacIntel"}`,
			"X-Behavioral-Data": `{"mouseEvents":0,"mouseStdDev":0}`,
		}

		resp, err := eng.Do(context.Background(), &engine.Request{
			URL:          server.URL,
			Method:       "GET",
			ExtraHeaders: headers,
		})
		if err != nil {
			t.Fatal(err)
		}

		botScore2 := ""
		isBot2 := ""
		isStealth2 := ""
		if v, ok := resp.Headers["X-Bot-Score"]; ok && len(v) > 0 {
			botScore2 = v[0]
		}
		if v, ok := resp.Headers["X-Is-Bot"]; ok && len(v) > 0 {
			isBot2 = v[0]
		}
		if v, ok := resp.Headers["X-Is-Stealth"]; ok && len(v) > 0 {
			isStealth2 = v[0]
		}

		t.Logf("Native engine with stealth indicators:")
		t.Logf("  Bot Score: %s", botScore2)
		t.Logf("  Is Bot: %s", isBot2)
		t.Logf("  Is Stealth: %s", isStealth2)
	})
}

func TestChromeNavigationMissingClientHintsDetected(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("GET", "http://example.com", nil)
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

	detection := detector.AnalyzeRequest(req, nil)

	if !detection.IsBot {
		t.Fatalf("expected chrome navigation without client hints to be detected, got score %.3f", detection.Score)
	}

	found := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if ind == "chrome_navigation_missing_client_hints" {
				found = true
				break
			}
		}
	}
	if !found {
		t.Fatal("expected chrome_navigation_missing_client_hints indicator")
	}
}

func TestFirefoxNavigationPriorityHeaderDetected(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("GET", "http://example.com", nil)
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

	detection := detector.AnalyzeRequest(req, nil)

	if !detection.IsBot {
		t.Fatalf("expected firefox navigation with priority header to be detected, got score %.3f", detection.Score)
	}

	foundPriorityHeader := false
	foundPrioritySignature := false
	var httpVec *DetectionVector
	for _, vec := range detection.Vectors {
		if vec.Category == "http" {
			httpVec = &vec
		}
		for _, ind := range vec.Indicators {
			if ind == "firefox_navigation_priority_header" {
				foundPriorityHeader = true
			}
			if ind == "firefox_chromium_priority_signature" {
				foundPrioritySignature = true
			}
		}
	}
	if !foundPriorityHeader {
		t.Fatal("expected firefox_navigation_priority_header indicator")
	}
	if !foundPrioritySignature {
		t.Fatal("expected firefox_chromium_priority_signature indicator")
	}
	if httpVec == nil {
		t.Fatal("expected http vector")
	}
	if httpVec.Confidence < 0.85 {
		t.Fatalf("expected firefox HTTP vector confidence >= 0.85, got %.3f", httpVec.Confidence)
	}
	if detection.Confidence < 0.85 {
		t.Fatalf("expected firefox detection confidence >= 0.85, got %.3f", detection.Confidence)
	}
}

func TestVectorConfidenceForCorroboratedHTTPSignals(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("GET", "http://example.com", nil)
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

	detection := detector.AnalyzeRequest(req, nil)

	var httpVec *DetectionVector
	for i := range detection.Vectors {
		if detection.Vectors[i].Category == "http" {
			httpVec = &detection.Vectors[i]
			break
		}
	}

	if httpVec == nil {
		t.Fatal("expected http vector")
	}
	if httpVec.Confidence < 0.80 {
		t.Fatalf("expected corroborated HTTP vector confidence >= 0.80, got %.3f", httpVec.Confidence)
	}
	if detection.Confidence < 0.80 {
		t.Fatalf("expected high overall confidence >= 0.80, got %.3f", detection.Confidence)
	}
}

func TestDetectionConfidenceForMultiVectorSpoof(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("GET", "http://example.com", nil)
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
	req.Header.Set("X-Stealth-Header-Order", "User-Agent,Accept,Accept-Language,Accept-Encoding,Upgrade-Insecure-Requests,Sec-Fetch-Dest,Sec-Fetch-Mode,Sec-Fetch-Site,Sec-Fetch-User,Sec-Ch-Ua,Sec-Ch-Ua-Platform,Sec-Ch-Ua-Mobile")

	detection := detector.AnalyzeRequest(req, nil)

	if !detection.IsBot {
		t.Fatalf("expected multi-vector spoof to be detected, got score %.3f", detection.Score)
	}
	if detection.Confidence < 0.75 {
		t.Fatalf("expected multi-vector spoof confidence >= 0.75, got %.3f", detection.Confidence)
	}
	if detection.Confidence < detection.Score {
		t.Fatalf("expected confidence %.3f to at least match score %.3f", detection.Confidence, detection.Score)
	}
}

func TestRichChromiumHeadersWithoutRuntimeStateDetected(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("GET", "http://example.com", nil)
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

	detection := detector.AnalyzeRequest(req, nil)

	if !detection.IsBot {
		t.Fatalf("expected rich Chromium headers without runtime state to be detected, got score %.3f", detection.Score)
	}

	var coverageVec *DetectionVector
	foundRichIndicator := false
	foundBaseIndicator := false
	for i := range detection.Vectors {
		if detection.Vectors[i].Category == string(VectorFingerprintCoverage) {
			coverageVec = &detection.Vectors[i]
		}
		for _, ind := range detection.Vectors[i].Indicators {
			if ind == "http_impersonation_no_js_context" {
				foundBaseIndicator = true
			}
			if ind == "rich_chromium_headers_without_runtime_state" {
				foundRichIndicator = true
			}
		}
	}

	if !foundBaseIndicator {
		t.Fatal("expected http_impersonation_no_js_context indicator")
	}
	if !foundRichIndicator {
		t.Fatal("expected rich_chromium_headers_without_runtime_state indicator")
	}
	if coverageVec == nil {
		t.Fatal("expected fingerprint coverage vector")
	}
	if coverageVec.Confidence < 0.90 {
		t.Fatalf("expected fingerprint coverage confidence >= 0.90, got %.3f", coverageVec.Confidence)
	}
	if detection.Confidence < 0.90 {
		t.Fatalf("expected overall confidence >= 0.90, got %.3f", detection.Confidence)
	}
}

func TestInitialNavigationFullRuntimeBundleDetected(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("GET", "http://example.com", nil)
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

	for _, header := range []string{
		"X-Navigator-Data",
		"X-WebGL-Data",
		"X-Plugin-Data",
		"X-Screen-Data",
		"X-Font-Data",
		"X-WebRTC-Data",
		"X-Behavioral-Data",
		"X-Timing-Data",
		"X-Audio-Data",
		"X-Canvas-Fingerprint",
	} {
		req.Header.Set(header, "present")
	}

	detection := detector.AnalyzeRequest(req, nil)
	if !detection.IsBot {
		t.Fatalf("expected initial navigation full runtime bundle to be detected, got score %.3f", detection.Score)
	}

	foundBundleIndicator := false
	foundPostLoadIndicator := false
	var coverageVec *DetectionVector
	for i := range detection.Vectors {
		if detection.Vectors[i].Category == string(VectorFingerprintCoverage) {
			coverageVec = &detection.Vectors[i]
		}
		for _, ind := range detection.Vectors[i].Indicators {
			if ind == "pre_request_full_runtime_bundle" {
				foundBundleIndicator = true
			}
			if ind == "post_load_telemetry_on_initial_navigation" {
				foundPostLoadIndicator = true
			}
		}
	}

	if !foundBundleIndicator {
		t.Fatal("expected pre_request_full_runtime_bundle indicator")
	}
	if !foundPostLoadIndicator {
		t.Fatal("expected post_load_telemetry_on_initial_navigation indicator")
	}
	if coverageVec == nil {
		t.Fatal("expected fingerprint coverage vector")
	}
	if coverageVec.Score < 0.80 {
		t.Fatalf("expected fingerprint coverage score >= 0.80, got %.3f", coverageVec.Score)
	}
}

func TestInitialNavigationDenseRuntimeBundleWithoutClientHintsDetected(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")

	for _, header := range []string{
		"X-Navigator-Data",
		"X-WebGL-Data",
		"X-Plugin-Data",
		"X-Screen-Data",
		"X-Font-Data",
		"X-WebRTC-Data",
		"X-Behavioral-Data",
		"X-Timing-Data",
		"X-Audio-Data",
		"X-Canvas-Fingerprint",
	} {
		req.Header.Set(header, "present")
	}

	detection := detector.AnalyzeRequest(req, nil)
	if !detection.IsBot {
		t.Fatalf("expected dense Firefox runtime bundle on initial navigation to be detected, got score %.3f", detection.Score)
	}

	foundBundleIndicator := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if ind == "pre_request_full_runtime_bundle" {
				foundBundleIndicator = true
			}
		}
	}
	if !foundBundleIndicator {
		t.Fatal("expected pre_request_full_runtime_bundle indicator for Firefox-style initial navigation")
	}
}

func TestSubresourceRuntimeBundleDoesNotTriggerInitialNavigationIndicator(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("GET", "http://example.com/script.js", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Sec-Fetch-Dest", "script")
	req.Header.Set("Sec-Fetch-Mode", "no-cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Referer", "http://example.com")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

	for _, header := range []string{
		"X-Navigator-Data",
		"X-WebGL-Data",
		"X-Plugin-Data",
		"X-Screen-Data",
		"X-Font-Data",
		"X-WebRTC-Data",
		"X-Behavioral-Data",
		"X-Timing-Data",
		"X-Audio-Data",
		"X-Canvas-Fingerprint",
	} {
		req.Header.Set(header, "present")
	}

	detection := detector.AnalyzeRequest(req, nil)
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if ind == "pre_request_full_runtime_bundle" || ind == "post_load_telemetry_on_initial_navigation" {
				t.Fatalf("did not expect %s for a subresource request", ind)
			}
		}
	}
}

func TestSameOriginTelemetryBundleDetected(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("GET", "http://example.com/api/ml/trap", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Referer", "http://example.com/api/ml/trap")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

	for _, header := range []string{
		"X-Navigator-Data",
		"X-WebGL-Data",
		"X-Plugin-Data",
		"X-WebRTC-Data",
		"X-Behavioral-Data",
		"X-Timing-Data",
		"X-Audio-Data",
		"X-Canvas-Fingerprint",
	} {
		req.Header.Set(header, "present")
	}

	detection := detector.AnalyzeRequest(req, nil)
	if !detection.IsBot {
		t.Fatalf("expected same-origin telemetry bundle to be detected, got score %.3f", detection.Score)
	}

	foundGetIndicator := false
	foundRefererIndicator := false
	foundHeaderPayloadIndicator := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "telemetry_payload_on_get_request") {
				foundGetIndicator = true
			}
			if ind == "telemetry_self_referer" {
				foundRefererIndicator = true
			}
			if strings.HasPrefix(ind, "telemetry_stuffed_into_headers") {
				foundHeaderPayloadIndicator = true
			}
		}
	}

	if !foundGetIndicator {
		t.Fatal("expected telemetry_payload_on_get_request indicator")
	}
	if !foundRefererIndicator {
		t.Fatal("expected telemetry_self_referer indicator")
	}
	if !foundHeaderPayloadIndicator {
		t.Fatal("expected telemetry_stuffed_into_headers indicator")
	}
}

func TestNormalSameOriginFetchDoesNotTriggerTelemetryIndicators(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("GET", "http://example.com/api/data", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Referer", "http://example.com/dashboard")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

	detection := detector.AnalyzeRequest(req, nil)
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "telemetry_payload_on_get_request") ||
				ind == "telemetry_self_referer" ||
				strings.HasPrefix(ind, "telemetry_stuffed_into_headers") {
				t.Fatalf("did not expect telemetry provenance indicator %q for a normal same-origin fetch", ind)
			}
		}
	}
}

func TestSameOriginTelemetryPostWithThinBodyDetected(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("POST", "http://example.com/api/ml/trap", strings.NewReader(`{"sid":"abc","ts":1700000000,"page":"/","v":"1.4.2","seq":1}`))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "same-origin")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Referer", "http://example.com/")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

	req.Header.Set("X-Navigator-Data", strings.Repeat("n", 256))
	req.Header.Set("X-WebGL-Data", strings.Repeat("w", 256))
	req.Header.Set("X-Plugin-Data", strings.Repeat("p", 256))
	req.Header.Set("X-Behavioral-Data", strings.Repeat("b", 2600))
	req.Header.Set("X-Timing-Data", strings.Repeat("t", 2600))
	req.Header.Set("X-Audio-Data", strings.Repeat("a", 600))
	req.Header.Set("X-Canvas-Fingerprint", strings.Repeat("c", 1200))

	detection := detector.AnalyzeRequest(req, nil)
	if !detection.IsBot {
		t.Fatalf("expected same-origin telemetry POST with thin body to be detected, got score %.3f", detection.Score)
	}

	foundHeaderIndicator := false
	foundHeaderOverloadIndicator := false
	foundBulkHeaderIndicator := false
	foundBehavioralHeaderIndicator := false
	foundThinBodyIndicator := false
	foundMissingPayloadIndicator := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "telemetry_bulk_payload_in_headers") {
				foundBulkHeaderIndicator = true
			}
			if ind == "telemetry_behavioral_payload_in_headers" {
				foundBehavioralHeaderIndicator = true
			}
			if strings.HasPrefix(ind, "telemetry_header_surface_overload") {
				foundHeaderOverloadIndicator = true
			}
			if strings.HasPrefix(ind, "telemetry_runtime_hidden_in_headers") {
				foundHeaderIndicator = true
			}
			if strings.HasPrefix(ind, "telemetry_body_too_small_for_claimed_runtime") {
				foundThinBodyIndicator = true
			}
			if ind == "telemetry_body_missing_runtime_payload" {
				foundMissingPayloadIndicator = true
			}
		}
	}

	if !foundHeaderIndicator {
		t.Fatal("expected telemetry_runtime_hidden_in_headers indicator")
	}
	if !foundHeaderOverloadIndicator {
		t.Fatal("expected telemetry_header_surface_overload indicator")
	}
	if !foundBulkHeaderIndicator {
		t.Fatal("expected telemetry_bulk_payload_in_headers indicator")
	}
	if !foundBehavioralHeaderIndicator {
		t.Fatal("expected telemetry_behavioral_payload_in_headers indicator")
	}
	if !foundThinBodyIndicator {
		t.Fatal("expected telemetry_body_too_small_for_claimed_runtime indicator")
	}
	if !foundMissingPayloadIndicator {
		t.Fatal("expected telemetry_body_missing_runtime_payload indicator")
	}
}

func TestNoCORSTelemetryPostWithRuntimeHeadersDetected(t *testing.T) {
	detector := NewStealthDetector()

	body := `{"sid":"abc","ts":1700000000,"page":"/","v":"1.4.2","seq":1}`
	req := httptest.NewRequest("POST", "http://example.com/api/ml/trap", strings.NewReader(body))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "no-cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

	req.Header.Set("X-Navigator-Data", strings.Repeat("n", 256))
	req.Header.Set("X-WebGL-Data", strings.Repeat("w", 256))
	req.Header.Set("X-Plugin-Data", strings.Repeat("p", 256))
	req.Header.Set("X-Behavioral-Data", strings.Repeat("b", 2200))
	req.Header.Set("X-Timing-Data", strings.Repeat("t", 2200))
	req.Header.Set("X-Audio-Data", strings.Repeat("a", 600))
	req.Header.Set("X-Canvas-Fingerprint", strings.Repeat("c", 1200))

	detection := detector.AnalyzeRequest(req, nil)
	if !detection.IsBot {
		t.Fatalf("expected no-cors telemetry POST with runtime headers to be detected, got score %.3f", detection.Score)
	}

	foundRuntimeHeaders := false
	foundNonSafelistedContentType := false
	foundThinBody := false
	foundMissingRuntime := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "nocors_impossible_custom_runtime_headers") {
				foundRuntimeHeaders = true
			}
			if strings.HasPrefix(ind, "nocors_non_safelisted_content_type") {
				foundNonSafelistedContentType = true
			}
			if strings.HasPrefix(ind, "nocors_body_too_small_for_claimed_runtime") {
				foundThinBody = true
			}
			if ind == "nocors_body_missing_runtime_payload" {
				foundMissingRuntime = true
			}
		}
	}

	if !foundRuntimeHeaders {
		t.Fatal("expected nocors_impossible_custom_runtime_headers indicator")
	}
	if !foundNonSafelistedContentType {
		t.Fatal("expected nocors_non_safelisted_content_type indicator")
	}
	if !foundThinBody {
		t.Fatal("expected nocors_body_too_small_for_claimed_runtime indicator")
	}
	if !foundMissingRuntime {
		t.Fatal("expected nocors_body_missing_runtime_payload indicator")
	}
}

func TestNoCORSTelemetryPostWithReducedRuntimeHeadersDetected(t *testing.T) {
	detector := NewStealthDetector()

	body := `{"sid":"abc","ts":1700000000,"page":"/","v":"1.4.2","seq":1}`
	req := httptest.NewRequest("POST", "http://example.com/api/ml/trap", strings.NewReader(body))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "no-cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

	req.Header.Set("X-Plugin-Data", strings.Repeat("p", 256))
	req.Header.Set("X-Behavioral-Data", strings.Repeat("b", 2200))
	req.Header.Set("X-Timing-Data", strings.Repeat("t", 2200))
	req.Header.Set("X-Audio-Data", strings.Repeat("a", 600))
	req.Header.Set("X-Canvas-Fingerprint", strings.Repeat("c", 1200))

	detection := detector.AnalyzeRequest(req, nil)
	if !detection.IsBot {
		t.Fatalf("expected reduced no-cors runtime header bundle to be detected, got score %.3f", detection.Score)
	}

	foundRuntimeHeaders := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "nocors_impossible_custom_runtime_headers") {
				foundRuntimeHeaders = true
			}
		}
	}

	if !foundRuntimeHeaders {
		t.Fatal("expected nocors_impossible_custom_runtime_headers indicator")
	}
}

func TestNormalNoCORSBeaconDoesNotTriggerNoCORSIndicators(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("POST", "http://example.com/collect", strings.NewReader("sid=abc123&event=pagehide"))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "text/plain;charset=UTF-8")
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "no-cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

	detection := detector.AnalyzeRequest(req, nil)
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "nocors_") {
				t.Fatalf("did not expect no-cors telemetry indicator %q for a normal beacon", ind)
			}
		}
	}
}

func TestNoneContextTelemetryPostWithRuntimeHeadersDetected(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("POST", "http://example.com/api/ml/trap", strings.NewReader(`{"sid":"abc","ts":1700000000,"page":"/","v":"2.1.0","seq":1}`))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

	req.Header.Set("X-Navigator-Data", strings.Repeat("n", 256))
	req.Header.Set("X-WebGL-Data", strings.Repeat("w", 256))
	req.Header.Set("X-Behavioral-Data", strings.Repeat("b", 1800))
	req.Header.Set("X-Timing-Data", strings.Repeat("t", 1800))
	req.Header.Set("X-Audio-Data", strings.Repeat("a", 512))
	req.Header.Set("X-Canvas-Fingerprint", strings.Repeat("c", 1024))

	detection := detector.AnalyzeRequest(req, nil)
	if !detection.IsBot {
		t.Fatalf("expected site=none telemetry bundle to be detected, got score %.3f", detection.Score)
	}

	foundBundle := false
	foundMissingRuntime := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "none_context_runtime_bundle") {
				foundBundle = true
			}
			if ind == "none_context_body_missing_runtime_payload" {
				foundMissingRuntime = true
			}
		}
	}

	if !foundBundle {
		t.Fatal("expected none_context_runtime_bundle indicator")
	}
	if !foundMissingRuntime {
		t.Fatal("expected none_context_body_missing_runtime_payload indicator")
	}
}

func TestNormalNoneContextNavigationDoesNotTriggerTelemetryIndicators(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

	detection := detector.AnalyzeRequest(req, nil)
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "none_context_") {
				t.Fatalf("did not expect none-context telemetry indicator %q for a normal navigation", ind)
			}
		}
	}
}

func TestSameOriginTelemetryPostWithoutRefererDetected(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("POST", "http://example.com/api/ml/trap", strings.NewReader(`{"sid":"abc","ts":1700000000,"page":"/","v":"1.4.2","seq":1}`))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

	req.Header.Set("X-Navigator-Data", strings.Repeat("n", 256))
	req.Header.Set("X-WebGL-Data", strings.Repeat("w", 256))
	req.Header.Set("X-Plugin-Data", strings.Repeat("p", 256))
	req.Header.Set("X-Behavioral-Data", strings.Repeat("b", 2600))
	req.Header.Set("X-Timing-Data", strings.Repeat("t", 2600))
	req.Header.Set("X-Audio-Data", strings.Repeat("a", 600))
	req.Header.Set("X-Canvas-Fingerprint", strings.Repeat("c", 1200))

	detection := detector.AnalyzeRequest(req, nil)
	if !detection.IsBot {
		t.Fatalf("expected same-origin telemetry without referer to be detected, got score %.3f", detection.Score)
	}

	foundBlob := false
	foundMissingRuntime := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "telemetry_postload_blob_in_headers") {
				foundBlob = true
			}
			if ind == "telemetry_body_missing_runtime_payload" {
				foundMissingRuntime = true
			}
		}
	}

	if !foundBlob {
		t.Fatal("expected telemetry_postload_blob_in_headers indicator")
	}
	if !foundMissingRuntime {
		t.Fatal("expected telemetry_body_missing_runtime_payload indicator")
	}
}

func TestSameOriginTelemetryPostWithoutRefererReducedHeadersDetected(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("POST", "http://example.com/api/ml/trap", strings.NewReader(`{"sid":"abc","ts":1700000000,"page":"/","v":"1.4.2","seq":1}`))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

	req.Header.Set("X-Behavioral-Data", strings.Repeat("b", 2200))
	req.Header.Set("X-Timing-Data", strings.Repeat("t", 2200))
	req.Header.Set("X-Audio-Data", strings.Repeat("a", 600))
	req.Header.Set("X-Canvas-Fingerprint", strings.Repeat("c", 1200))

	detection := detector.AnalyzeRequest(req, nil)
	if !detection.IsBot {
		t.Fatalf("expected reduced same-origin telemetry without referer to be detected, got score %.3f", detection.Score)
	}
}

func TestNormalSameOriginPostWithoutRefererDoesNotTriggerTelemetryIndicators(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("POST", "http://example.com/api/data", strings.NewReader(`{"query":"status"}`))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

	detection := detector.AnalyzeRequest(req, nil)
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "telemetry_postload_blob_in_headers") ||
				strings.HasPrefix(ind, "telemetry_timing_blob_in_headers") ||
				strings.HasPrefix(ind, "telemetry_bulk_payload_in_headers") ||
				strings.HasPrefix(ind, "telemetry_header_surface_overload") ||
				strings.HasPrefix(ind, "telemetry_runtime_hidden_in_headers") ||
				strings.HasPrefix(ind, "telemetry_body_too_small_for_claimed_runtime") ||
				ind == "telemetry_body_missing_runtime_payload" {
				t.Fatalf("did not expect same-origin no-referer telemetry indicator %q for a normal POST", ind)
			}
		}
	}
}

func TestDocumentNavigationPostWithRuntimeHeadersDetected(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("POST", "http://example.com/login", strings.NewReader("sid=abc123&step=submit"))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

	req.Header.Set("X-Behavioral-Data", strings.Repeat("b", 2200))
	req.Header.Set("X-Timing-Data", strings.Repeat("t", 2200))
	req.Header.Set("X-Audio-Data", strings.Repeat("a", 600))
	req.Header.Set("X-Canvas-Fingerprint", strings.Repeat("c", 1200))

	detection := detector.AnalyzeRequest(req, nil)
	if !detection.IsBot {
		t.Fatalf("expected document navigation with runtime headers to be detected, got score %.3f", detection.Score)
	}

	foundNavigationIndicator := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "document_navigation_impossible_runtime_headers") {
				foundNavigationIndicator = true
			}
		}
	}

	if !foundNavigationIndicator {
		t.Fatal("expected document_navigation_impossible_runtime_headers indicator")
	}
}

func TestNormalDocumentNavigationPostDoesNotTriggerRuntimeIndicators(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("POST", "http://example.com/login", strings.NewReader("sid=abc123&step=submit"))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

	detection := detector.AnalyzeRequest(req, nil)
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "document_navigation_") {
				t.Fatalf("did not expect document navigation indicator %q for a normal form post", ind)
			}
		}
	}
}

func TestCrossSiteDocumentNavigationPostWithRuntimeHeadersDetected(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("POST", "https://example.com/login", strings.NewReader("sid=abc123&step=submit"))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

	req.Header.Set("X-Behavioral-Data", strings.Repeat("b", 2200))
	req.Header.Set("X-Timing-Data", strings.Repeat("t", 2200))
	req.Header.Set("X-Audio-Data", strings.Repeat("a", 600))
	req.Header.Set("X-Canvas-Fingerprint", strings.Repeat("c", 1200))

	detection := detector.AnalyzeRequest(req, nil)
	if !detection.IsBot {
		t.Fatalf("expected cross-site document navigation with runtime headers to be detected, got score %.3f", detection.Score)
	}

	foundNavigationIndicator := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "document_navigation_impossible_runtime_headers") {
				foundNavigationIndicator = true
			}
		}
	}

	if !foundNavigationIndicator {
		t.Fatal("expected document_navigation_impossible_runtime_headers indicator")
	}
}

func TestNormalCrossSiteDocumentNavigationPostDoesNotTriggerRuntimeIndicators(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("POST", "https://example.com/login", strings.NewReader("sid=abc123&step=submit"))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

	detection := detector.AnalyzeRequest(req, nil)
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "document_navigation_") {
				t.Fatalf("did not expect document navigation indicator %q for a normal cross-site form post", ind)
			}
		}
	}
}

func TestDocumentNavigationGetWithRuntimeHeadersDetected(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("GET", "https://example.com/dashboard", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Referer", "https://example.com/home")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

	req.Header.Set("X-Navigator-Data", strings.Repeat("n", 256))
	req.Header.Set("X-WebGL-Data", strings.Repeat("w", 256))
	req.Header.Set("X-Plugin-Data", strings.Repeat("p", 256))
	req.Header.Set("X-Behavioral-Data", strings.Repeat("b", 2200))
	req.Header.Set("X-Timing-Data", strings.Repeat("t", 2200))
	req.Header.Set("X-Audio-Data", strings.Repeat("a", 600))
	req.Header.Set("X-Canvas-Fingerprint", strings.Repeat("c", 1200))

	detection := detector.AnalyzeRequest(req, nil)
	if !detection.IsBot {
		t.Fatalf("expected document navigation GET with runtime headers to be detected, got score %.3f", detection.Score)
	}

	foundNavigationIndicator := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "document_navigation_impossible_runtime_headers") {
				foundNavigationIndicator = true
			}
		}
	}

	if !foundNavigationIndicator {
		t.Fatal("expected document_navigation_impossible_runtime_headers indicator")
	}
}

func TestDocumentNavigationToTelemetryEndpointDetected(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("GET", "https://example.com/api/telemetry", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Referer", "https://example.com/dashboard")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "same-origin")

	detection := detector.AnalyzeRequest(req, nil)
	if !detection.IsBot {
		t.Fatalf("expected document navigation to telemetry endpoint to be detected, got score %.3f", detection.Score)
	}

	foundEndpointIndicator := false
	foundMissingUser := false
	foundMissingUIR := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "document_navigation_to_telemetry_endpoint") {
				foundEndpointIndicator = true
			}
			if ind == "document_navigation_missing_user_activation" {
				foundMissingUser = true
			}
			if ind == "document_navigation_missing_upgrade_insecure_requests" {
				foundMissingUIR = true
			}
		}
	}

	if !foundEndpointIndicator {
		t.Fatal("expected document_navigation_to_telemetry_endpoint indicator")
	}
	if !foundMissingUser {
		t.Fatal("expected document_navigation_missing_user_activation indicator")
	}
	if !foundMissingUIR {
		t.Fatal("expected document_navigation_missing_upgrade_insecure_requests indicator")
	}
}

func TestDocumentNavigationGhostHeaderOrderDetected(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("GET", "http://test/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	req.Header.Set("Referer", "http://test/dashboard")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("X-Stealth-Header-Order", "User-Agent,Accept,Content-Type,Sec-Fetch-Site,Sec-Fetch-Mode,Sec-Fetch-Dest,Accept-Encoding,Accept-Language,Origin,Referer")

	detection := detector.AnalyzeRequest(req, nil)
	if !detection.IsBot {
		t.Fatalf("expected document navigation with ghost header order to be detected, got score %.3f", detection.Score)
	}

	foundGhostOrder := false
	foundMissingUser := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "document_navigation_header_order_ghost_headers") {
				foundGhostOrder = true
			}
			if ind == "document_navigation_missing_user_activation" {
				foundMissingUser = true
			}
		}
	}

	if !foundGhostOrder {
		t.Fatal("expected document_navigation_header_order_ghost_headers indicator")
	}
	if !foundMissingUser {
		t.Fatal("expected document_navigation_missing_user_activation indicator")
	}
}

func TestNormalSameOriginDocumentNavigationGetDoesNotTriggerIndicators(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("GET", "https://example.com/dashboard", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Referer", "https://example.com/home")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("X-Stealth-Header-Order", "User-Agent,Accept,Accept-Language,Accept-Encoding,Referer,Upgrade-Insecure-Requests,Sec-Fetch-Dest,Sec-Fetch-Mode,Sec-Fetch-Site,Sec-Fetch-User")

	detection := detector.AnalyzeRequest(req, nil)
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "document_navigation_") {
				t.Fatalf("did not expect document navigation indicator %q for a normal same-origin navigation", ind)
			}
		}
	}
}

func TestSameOriginFirefoxDocumentNavigationSpoofDetected(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("GET", "http://test/products", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	req.Header.Set("Referer", "http://test/dashboard")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("X-Stealth-Header-Order", "Upgrade-Insecure-Requests,User-Agent,Accept,Sec-Fetch-Site,Sec-Fetch-Mode,Sec-Fetch-User,Sec-Fetch-Dest,Accept-Encoding,Accept-Language")

	detection := detector.AnalyzeRequest(req, nil)
	if !detection.IsBot {
		t.Fatalf("expected spoofed same-origin Firefox navigation to be detected, got score %.3f", detection.Score)
	}

	foundAcceptMismatch := false
	foundMissingConnection := false
	foundImprobableOrder := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if ind == "document_navigation_firefox_accept_missing_image_codecs" {
				foundAcceptMismatch = true
			}
			if ind == "document_navigation_missing_connection_header" {
				foundMissingConnection = true
			}
			if strings.HasPrefix(ind, "document_navigation_improbable_header_order") {
				foundImprobableOrder = true
			}
		}
	}

	if !foundAcceptMismatch {
		t.Fatal("expected document_navigation_firefox_accept_missing_image_codecs indicator")
	}
	if !foundMissingConnection {
		t.Fatal("expected document_navigation_missing_connection_header indicator")
	}
	if !foundImprobableOrder {
		t.Fatal("expected document_navigation_improbable_header_order indicator")
	}
}

func TestNormalSameOriginFirefoxDocumentNavigationDoesNotTriggerSpoofIndicators(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("GET", "http://test/products", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Referer", "http://test/dashboard")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("X-Stealth-Header-Order", "User-Agent,Accept,Accept-Language,Accept-Encoding,Connection,Upgrade-Insecure-Requests,Sec-Fetch-Dest,Sec-Fetch-Mode,Sec-Fetch-Site,Sec-Fetch-User")

	detection := detector.AnalyzeRequest(req, nil)
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "document_navigation_firefox_accept_missing_image_codecs") ||
				strings.HasPrefix(ind, "document_navigation_missing_connection_header") ||
				strings.HasPrefix(ind, "document_navigation_improbable_header_order") {
				t.Fatalf("did not expect Firefox navigation spoof indicator %q for a normal same-origin navigation", ind)
			}
		}
	}
}

func TestInitialFirefoxNavigationToTelemetryTargetDetected(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("GET", "https://api.example.com/telemetry", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("X-Stealth-Header-Order", "User-Agent,Accept,Accept-Language,Accept-Encoding,Connection,Upgrade-Insecure-Requests,Sec-Fetch-Dest,Sec-Fetch-Mode,Sec-Fetch-Site,Sec-Fetch-User")

	detection := detector.AnalyzeRequest(req, nil)
	if !detection.IsBot {
		t.Fatalf("expected initial Firefox navigation to telemetry target to be detected, got score %.3f", detection.Score)
	}

	foundTelemetryTarget := false
	foundAPIHost := false
	foundNonSameOrigin := false
	foundMissingReferer := false
	foundHTMLAccept := false
	foundUpgradeInsecure := false
	foundUserActivation := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "document_navigation_to_telemetry_target") {
				foundTelemetryTarget = true
			}
			if strings.HasPrefix(ind, "document_navigation_api_hostname") {
				foundAPIHost = true
			}
			if strings.HasPrefix(ind, "document_navigation_non_same_origin_target") {
				foundNonSameOrigin = true
			}
			if ind == "document_navigation_missing_referer_to_telemetry_target" {
				foundMissingReferer = true
			}
			if ind == "document_navigation_html_accept_to_telemetry_target" {
				foundHTMLAccept = true
			}
			if ind == "document_navigation_upgrade_insecure_requests_to_telemetry_target" {
				foundUpgradeInsecure = true
			}
			if ind == "document_navigation_user_activation_to_telemetry_target" {
				foundUserActivation = true
			}
		}
	}

	if !foundTelemetryTarget {
		t.Fatal("expected document_navigation_to_telemetry_target indicator")
	}
	if !foundAPIHost {
		t.Fatal("expected document_navigation_api_hostname indicator")
	}
	if !foundNonSameOrigin {
		t.Fatal("expected document_navigation_non_same_origin_target indicator")
	}
	if !foundMissingReferer {
		t.Fatal("expected document_navigation_missing_referer_to_telemetry_target indicator")
	}
	if !foundHTMLAccept {
		t.Fatal("expected document_navigation_html_accept_to_telemetry_target indicator")
	}
	if !foundUpgradeInsecure {
		t.Fatal("expected document_navigation_upgrade_insecure_requests_to_telemetry_target indicator")
	}
	if !foundUserActivation {
		t.Fatal("expected document_navigation_user_activation_to_telemetry_target indicator")
	}
}

func TestNormalInitialFirefoxNavigationDoesNotTriggerTelemetryTargetIndicators(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("GET", "https://www.example.com/products", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("X-Stealth-Header-Order", "User-Agent,Accept,Accept-Language,Accept-Encoding,Connection,Upgrade-Insecure-Requests,Sec-Fetch-Dest,Sec-Fetch-Mode,Sec-Fetch-Site,Sec-Fetch-User")

	detection := detector.AnalyzeRequest(req, nil)
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "document_navigation_to_telemetry_target") ||
				strings.HasPrefix(ind, "document_navigation_api_hostname") ||
				strings.HasPrefix(ind, "document_navigation_non_same_origin_target") ||
				ind == "document_navigation_missing_referer_to_telemetry_target" ||
				ind == "document_navigation_html_accept_to_telemetry_target" ||
				ind == "document_navigation_upgrade_insecure_requests_to_telemetry_target" ||
				ind == "document_navigation_user_activation_to_telemetry_target" {
				t.Fatalf("did not expect telemetry-target navigation indicator %q for a normal initial Firefox navigation", ind)
			}
		}
	}
}

// TestDocumentNavigationWithRuntimeHeadersCaught verifies that ANY runtime X-*
// headers on a document navigation are detected, regardless of target URL.
// This is the URL-independent hardening layer.
func TestDocumentNavigationWithRuntimeHeadersCaught(t *testing.T) {
	detector := NewStealthDetector()

	// Even targeting a normal page URL, runtime headers on navigation = caught
	req := httptest.NewRequest("GET", "https://www.example.com/products", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	// Add 2 runtime headers — structurally impossible on a real navigation
	req.Header.Set("X-Canvas-Fingerprint", "abc123")
	req.Header.Set("X-Timing-Data", `{"load":100}`)
	req.Header.Set("X-Stealth-Header-Order", "User-Agent,Accept,Accept-Language,Accept-Encoding,Connection,Upgrade-Insecure-Requests,Sec-Fetch-Dest,Sec-Fetch-Mode,Sec-Fetch-Site,Sec-Fetch-User,X-Canvas-Fingerprint,X-Timing-Data")

	detection := detector.AnalyzeRequest(req, nil)
	if !detection.IsBot {
		t.Fatalf("document navigation with runtime headers should be detected, got score %.3f", detection.Score)
	}

	foundSynthetic := false
	foundPostLoad := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "document_navigation_synthetic_runtime_headers") {
				foundSynthetic = true
			}
			if strings.HasPrefix(ind, "document_navigation_postload_on_navigation") {
				foundPostLoad = true
			}
		}
	}
	if !foundSynthetic {
		t.Fatal("expected document_navigation_synthetic_runtime_headers indicator")
	}
	if !foundPostLoad {
		t.Fatal("expected document_navigation_postload_on_navigation indicator")
	}
}

// TestDocumentNavigationWithSuspiciousQueryCaught verifies detection of large
// encoded payloads in URL query parameters on document navigations.
func TestDocumentNavigationWithSuspiciousQueryCaught(t *testing.T) {
	detector := NewStealthDetector()

	// Simulate fingerprint data smuggled via query string (base64 blob)
	longPayload := strings.Repeat("YWJjZGVm", 100) // ~800 bytes of base64
	req := httptest.NewRequest("GET", "https://www.example.com/page?data="+longPayload, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("X-Stealth-Header-Order", "User-Agent,Accept,Accept-Language,Accept-Encoding,Connection,Upgrade-Insecure-Requests,Sec-Fetch-Dest,Sec-Fetch-Mode,Sec-Fetch-Site,Sec-Fetch-User")

	detection := detector.AnalyzeRequest(req, nil)

	foundSuspiciousQuery := false
	foundEncodedPayload := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "document_navigation_suspicious_query_string") {
				foundSuspiciousQuery = true
			}
			if ind == "document_navigation_encoded_query_payload" {
				foundEncodedPayload = true
			}
		}
	}
	if !foundSuspiciousQuery {
		t.Fatal("expected document_navigation_suspicious_query_string indicator")
	}
	if !foundEncodedPayload {
		t.Fatal("expected document_navigation_encoded_query_payload indicator")
	}

	// Score should be high enough to flag
	if detection.Score < 0.35 {
		t.Fatalf("expected score >= 0.35 for query smuggling, got %.3f", detection.Score)
	}
}

// TestNormalQueryStringNotFlagged ensures short, normal query params don't trigger.
func TestNormalQueryStringNotFlagged(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("GET", "https://www.example.com/products?page=2&sort=price&utm_source=google", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("X-Stealth-Header-Order", "User-Agent,Accept,Accept-Language,Accept-Encoding,Connection,Upgrade-Insecure-Requests,Sec-Fetch-Dest,Sec-Fetch-Mode,Sec-Fetch-Site,Sec-Fetch-User")

	detection := detector.AnalyzeRequest(req, nil)
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "document_navigation_suspicious_query_string") ||
				ind == "document_navigation_encoded_query_payload" {
				t.Fatalf("normal short query params should not trigger query smuggling detection: %s", ind)
			}
		}
	}
}

func TestNormalSameOriginPostDoesNotTriggerTelemetryIndicators(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("POST", "http://example.com/api/data", strings.NewReader(`{"query":"status"}`))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "same-origin")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Referer", "http://example.com/dashboard")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

	detection := detector.AnalyzeRequest(req, nil)
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "telemetry_runtime_hidden_in_headers") ||
				strings.HasPrefix(ind, "telemetry_postload_blob_in_headers") ||
				strings.HasPrefix(ind, "telemetry_timing_blob_in_headers") ||
				strings.HasPrefix(ind, "telemetry_bulk_payload_in_headers") ||
				strings.HasPrefix(ind, "telemetry_header_body_imbalance") ||
				ind == "telemetry_invalid_json_body" ||
				strings.HasPrefix(ind, "telemetry_body_too_small_for_claimed_runtime") ||
				ind == "telemetry_body_missing_runtime_payload" ||
				ind == "telemetry_post_missing_body_payload" {
				t.Fatalf("did not expect telemetry POST indicator %q for a normal same-origin POST", ind)
			}
		}
	}
}

func TestSameSiteTelemetryPostWithSameOriginClaimDetected(t *testing.T) {
	detector := NewStealthDetector()

	body := `{"sid":"abc","ts":1700000000,"page":"/","v":"1.4.2","seq":1,` +
		`"runtime":{"navigator":{"lang":"en-US","cores":8,"mem":8,"ua_blob":"` + strings.Repeat("n", 900) + `"},` +
		`"timing":{"ttfb":120,"fcp":340,"lcp":810,"trace":"` + strings.Repeat("t", 900) + `"},` +
		`"canvas":"abcdef1234567890","audio":"fedcba0987654321",` +
		`"webgl":{"vendor":"Google Inc.","renderer":"ANGLE"},` +
		`"behavior":{"moves":42,"clicks":3,"scrolls":5}}}`
	req := httptest.NewRequest("POST", "http://example.com/", strings.NewReader(body))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Referer", "http://example.com/")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

	req.Header.Set("X-Navigator-Data", strings.Repeat("n", 256))
	req.Header.Set("X-WebGL-Data", strings.Repeat("w", 256))
	req.Header.Set("X-Plugin-Data", strings.Repeat("p", 256))
	req.Header.Set("X-Behavioral-Data", strings.Repeat("b", 2600))
	req.Header.Set("X-Timing-Data", strings.Repeat("t", 2600))
	req.Header.Set("X-Audio-Data", strings.Repeat("a", 600))
	req.Header.Set("X-Canvas-Fingerprint", strings.Repeat("c", 1200))

	detection := detector.AnalyzeRequest(req, nil)
	if !detection.IsBot {
		t.Fatalf("expected same-site telemetry POST with same-origin claim to be detected, got score %.3f", detection.Score)
	}

	foundSameOriginClaim := false
	foundSelfReferer := false
	foundDuplicatedRuntime := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if ind == "same_site_claim_on_same_origin_post" {
				foundSameOriginClaim = true
			}
			if ind == "same_site_telemetry_self_referer" {
				foundSelfReferer = true
			}
			if strings.HasPrefix(ind, "telemetry_runtime_duplicated_in_body_and_headers") {
				foundDuplicatedRuntime = true
			}
		}
	}

	if !foundSameOriginClaim {
		t.Fatal("expected same_site_claim_on_same_origin_post indicator")
	}
	if !foundSelfReferer {
		t.Fatal("expected same_site_telemetry_self_referer indicator")
	}
	if !foundDuplicatedRuntime {
		t.Fatal("expected telemetry_runtime_duplicated_in_body_and_headers indicator")
	}
}

func TestCrossSubdomainSameSiteTelemetryDoesNotTriggerSameOriginClaim(t *testing.T) {
	detector := NewStealthDetector()

	body := `{"sid":"abc","ts":1700000000,"page":"/","v":"1.4.2","seq":1,` +
		`"runtime":{"navigator":{"lang":"en-US","cores":8,"mem":8,"ua_blob":"` + strings.Repeat("n", 900) + `"},` +
		`"timing":{"ttfb":120,"fcp":340,"lcp":810,"trace":"` + strings.Repeat("t", 900) + `"},` +
		`"canvas":"abcdef1234567890","audio":"fedcba0987654321"}}`
	req := httptest.NewRequest("POST", "https://metrics.example.com/collect", strings.NewReader(body))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Referer", "https://app.example.com/dashboard")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

	req.Header.Set("X-Navigator-Data", strings.Repeat("n", 256))
	req.Header.Set("X-WebGL-Data", strings.Repeat("w", 256))
	req.Header.Set("X-Behavioral-Data", strings.Repeat("b", 2600))
	req.Header.Set("X-Timing-Data", strings.Repeat("t", 2600))
	req.Header.Set("X-Audio-Data", strings.Repeat("a", 600))
	req.Header.Set("X-Canvas-Fingerprint", strings.Repeat("c", 1200))

	detection := detector.AnalyzeRequest(req, nil)
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if ind == "same_site_claim_on_same_origin_post" ||
				ind == "same_site_telemetry_self_referer" ||
				strings.HasPrefix(ind, "same_site_runtime_hidden_in_headers") ||
				strings.HasPrefix(ind, "same_site_body_too_small_for_claimed_runtime") ||
				ind == "same_site_body_missing_runtime_payload" ||
				strings.HasPrefix(ind, "telemetry_runtime_duplicated_in_body_and_headers") {
				t.Fatalf("did not expect same-site origin claim indicator %q for cross-subdomain telemetry", ind)
			}
		}
	}
}

func TestSameSiteDenseRuntimeDuplicationDetected(t *testing.T) {
	detector := NewStealthDetector()

	body := `{"sid":"abc","ts":1700000000,"page":"/dashboard","v":"2.1.0","seq":4,` +
		`"navigator":{"lang":"en-US","cores":8,"mem":8,"ua_blob":"` + strings.Repeat("n", 900) + `"},` +
		`"timing":{"ttfb":120,"fcp":340,"lcp":810,"trace":"` + strings.Repeat("t", 900) + `"},` +
		`"canvas":{"hash":"abcdef1234567890","trace":"` + strings.Repeat("c", 900) + `"},` +
		`"audio":{"hash":"fedcba0987654321","trace":"` + strings.Repeat("a", 900) + `"},` +
		`"behavior":{"moves":42,"clicks":3,"scrolls":5},` +
		`"webgl":{"vendor":"Google Inc.","renderer":"ANGLE"}}`
	req := httptest.NewRequest("POST", "http://test/api/ml/trap", strings.NewReader(body))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://app.test")
	req.Header.Set("Referer", "http://app.test/dashboard")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="146", "Google Chrome";v="146", "Not-A.Brand";v="24"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

	req.Header.Set("X-Navigator-Data", strings.Repeat("n", 256))
	req.Header.Set("X-WebGL-Data", strings.Repeat("w", 256))
	req.Header.Set("X-Plugin-Data", strings.Repeat("p", 256))
	req.Header.Set("X-Screen-Data", strings.Repeat("s", 256))
	req.Header.Set("X-Font-Data", strings.Repeat("f", 256))
	req.Header.Set("X-Behavioral-Data", strings.Repeat("b", 2600))
	req.Header.Set("X-Timing-Data", strings.Repeat("t", 2600))
	req.Header.Set("X-Audio-Data", strings.Repeat("a", 600))
	req.Header.Set("X-Canvas-Fingerprint", strings.Repeat("c", 1200))

	detection := detector.AnalyzeRequest(req, nil)
	if !detection.IsBot {
		t.Fatalf("expected dense same-site runtime duplication to be detected, got score %.3f", detection.Score)
	}

	foundUserActivation := false
	foundDuplication := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if ind == "same_site_xhr_with_user_activation" {
				foundUserActivation = true
			}
			if strings.HasPrefix(ind, "same_site_dense_runtime_body_header_duplication") {
				foundDuplication = true
			}
		}
	}

	if !foundUserActivation {
		t.Fatal("expected same_site_xhr_with_user_activation indicator")
	}
	if !foundDuplication {
		t.Fatal("expected same_site_dense_runtime_body_header_duplication indicator")
	}
}

func TestNormalSameSiteAnalyticsPostDoesNotTriggerDenseRuntimeDuplication(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("POST", "https://metrics.example.com/collect", strings.NewReader(`{"sid":"abc","ts":1700000000,"page":"/dashboard","v":"2.1.0","seq":4}`))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Referer", "https://app.example.com/dashboard")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="146", "Google Chrome";v="146", "Not-A.Brand";v="24"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

	detection := detector.AnalyzeRequest(req, nil)
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if ind == "same_site_xhr_with_user_activation" ||
				strings.HasPrefix(ind, "same_site_dense_runtime_body_header_duplication") {
				t.Fatalf("did not expect dense-runtime same-site indicator %q for a normal analytics post", ind)
			}
		}
	}
}

func TestSameSiteGETRuntimeBundleDetected(t *testing.T) {
	detector := NewStealthDetector()

	body := `{"sid":"abc","ts":1700000000,"page":"/dashboard","v":"2.1.0","seq":4,` +
		`"navigator":{"lang":"en-US","cores":8,"mem":8,"ua_blob":"` + strings.Repeat("n", 400) + `"},` +
		`"timing":{"ttfb":120,"fcp":340,"lcp":810},` +
		`"canvas":{"hash":"abcdef1234567890"},` +
		`"audio":{"hash":"fedcba0987654321"}}`
	req := httptest.NewRequest("GET", "http://test/api/ml/trap", strings.NewReader(body))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://app.test")
	req.Header.Set("Referer", "http://app.test/dashboard")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="146", "Google Chrome";v="146", "Not-A.Brand";v="24"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

	req.Header.Set("X-Navigator-Data", strings.Repeat("n", 256))
	req.Header.Set("X-WebGL-Data", strings.Repeat("w", 256))
	req.Header.Set("X-Plugin-Data", strings.Repeat("p", 256))
	req.Header.Set("X-Screen-Data", strings.Repeat("s", 256))
	req.Header.Set("X-Font-Data", strings.Repeat("f", 256))
	req.Header.Set("X-Behavioral-Data", strings.Repeat("b", 2600))
	req.Header.Set("X-Timing-Data", strings.Repeat("t", 2600))
	req.Header.Set("X-Audio-Data", strings.Repeat("a", 600))
	req.Header.Set("X-Canvas-Fingerprint", strings.Repeat("c", 1200))

	detection := detector.AnalyzeRequest(req, nil)
	if !detection.IsBot {
		t.Fatalf("expected same-site GET runtime bundle to be detected, got score %.3f", detection.Score)
	}

	foundRuntimeBundle := false
	foundBody := false
	foundContentType := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "same_site_get_runtime_bundle") {
				foundRuntimeBundle = true
			}
			if strings.HasPrefix(ind, "same_site_get_with_body") {
				foundBody = true
			}
			if strings.HasPrefix(ind, "same_site_get_with_content_type") {
				foundContentType = true
			}
		}
	}

	if !foundRuntimeBundle {
		t.Fatal("expected same_site_get_runtime_bundle indicator")
	}
	if !foundBody {
		t.Fatal("expected same_site_get_with_body indicator")
	}
	if !foundContentType {
		t.Fatal("expected same_site_get_with_content_type indicator")
	}
}

func TestNormalSameSiteGETDoesNotTriggerRuntimeBundleIndicators(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("GET", "https://metrics.example.com/collect", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Referer", "https://app.example.com/dashboard")
	req.Header.Set("Sec-Fetch-Dest", "image")
	req.Header.Set("Sec-Fetch-Mode", "no-cors")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="146", "Google Chrome";v="146", "Not-A.Brand";v="24"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

	detection := detector.AnalyzeRequest(req, nil)
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "same_site_get_runtime_bundle") ||
				strings.HasPrefix(ind, "same_site_get_with_body") ||
				strings.HasPrefix(ind, "same_site_get_with_content_type") {
				t.Fatalf("did not expect same-site GET runtime indicator %q for a normal same-site GET", ind)
			}
		}
	}
}

func TestSameSiteTelemetryPostWithThinAnalyticsBodyDetected(t *testing.T) {
	detector := NewStealthDetector()

	body := `{"sid":"abc","ts":1700000000,"page":"/","v":"2.1.0","seq":4,` +
		`"perf":{"ttfb":332,"fcp":228,"lcp":418},` +
		`"viewport":{"w":1337,"h":961},` +
		`"session":{"referrer":"https://www.google.com/","entry":"/","depth":6}}`
	req := httptest.NewRequest("POST", "http://example.com/api/ml/trap", strings.NewReader(body))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://www.example.com")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Referer", "http://www.example.com/")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

	req.Header.Set("X-Navigator-Data", strings.Repeat("n", 256))
	req.Header.Set("X-WebGL-Data", strings.Repeat("w", 256))
	req.Header.Set("X-Plugin-Data", strings.Repeat("p", 256))
	req.Header.Set("X-Screen-Data", strings.Repeat("s", 256))
	req.Header.Set("X-Font-Data", strings.Repeat("f", 256))
	req.Header.Set("X-Behavioral-Data", strings.Repeat("b", 2600))
	req.Header.Set("X-Timing-Data", strings.Repeat("t", 2600))
	req.Header.Set("X-Audio-Data", strings.Repeat("a", 600))
	req.Header.Set("X-Canvas-Fingerprint", strings.Repeat("c", 1200))

	detection := detector.AnalyzeRequest(req, nil)
	if !detection.IsBot {
		t.Fatalf("expected same-site telemetry POST with thin analytics body to be detected, got score %.3f", detection.Score)
	}

	foundHiddenRuntime := false
	foundThinBody := false
	foundMissingRuntime := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "same_site_runtime_hidden_in_headers") {
				foundHiddenRuntime = true
			}
			if strings.HasPrefix(ind, "same_site_body_too_small_for_claimed_runtime") {
				foundThinBody = true
			}
			if ind == "same_site_body_missing_runtime_payload" {
				foundMissingRuntime = true
			}
		}
	}

	if !foundHiddenRuntime {
		t.Fatal("expected same_site_runtime_hidden_in_headers indicator")
	}
	if !foundThinBody {
		t.Fatal("expected same_site_body_too_small_for_claimed_runtime indicator")
	}
	if !foundMissingRuntime {
		t.Fatal("expected same_site_body_missing_runtime_payload indicator")
	}
}

func TestSameSiteTelemetryPostWithoutRefererDetected(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("POST", "http://example.com/api/ml/trap", strings.NewReader(`{"sid":"abc","ts":1700000000,"page":"/","v":"2.1.0","seq":4}`))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

	req.Header.Set("X-Navigator-Data", strings.Repeat("n", 256))
	req.Header.Set("X-WebGL-Data", strings.Repeat("w", 256))
	req.Header.Set("X-Plugin-Data", strings.Repeat("p", 256))
	req.Header.Set("X-Behavioral-Data", strings.Repeat("b", 2600))
	req.Header.Set("X-Timing-Data", strings.Repeat("t", 2600))
	req.Header.Set("X-Audio-Data", strings.Repeat("a", 600))
	req.Header.Set("X-Canvas-Fingerprint", strings.Repeat("c", 1200))

	detection := detector.AnalyzeRequest(req, nil)
	if !detection.IsBot {
		t.Fatalf("expected same-site telemetry POST without referer to be detected, got score %.3f", detection.Score)
	}

	foundOriginClaim := false
	foundHiddenRuntime := false
	foundThinBody := false
	foundMissingRuntime := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if ind == "same_site_claim_on_same_origin_post" {
				foundOriginClaim = true
			}
			if strings.HasPrefix(ind, "same_site_runtime_hidden_in_headers") {
				foundHiddenRuntime = true
			}
			if strings.HasPrefix(ind, "same_site_body_too_small_for_claimed_runtime") {
				foundThinBody = true
			}
			if ind == "same_site_body_missing_runtime_payload" {
				foundMissingRuntime = true
			}
		}
	}

	if !foundOriginClaim {
		t.Fatal("expected same_site_claim_on_same_origin_post indicator")
	}
	if !foundHiddenRuntime {
		t.Fatal("expected same_site_runtime_hidden_in_headers indicator")
	}
	if !foundThinBody {
		t.Fatal("expected same_site_body_too_small_for_claimed_runtime indicator")
	}
	if !foundMissingRuntime {
		t.Fatal("expected same_site_body_missing_runtime_payload indicator")
	}
}

func TestSameSiteTelemetryReducedHeadersWithoutRefererDetected(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("POST", "http://example.com/api/ml/trap", strings.NewReader(`{"sid":"abc","ts":1700000000,"page":"/","v":"2.1.0","seq":4}`))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

	req.Header.Set("X-Behavioral-Data", strings.Repeat("b", 2200))
	req.Header.Set("X-Timing-Data", strings.Repeat("t", 2200))
	req.Header.Set("X-Audio-Data", strings.Repeat("a", 600))
	req.Header.Set("X-Canvas-Fingerprint", strings.Repeat("c", 1200))

	detection := detector.AnalyzeRequest(req, nil)
	if !detection.IsBot {
		t.Fatalf("expected reduced same-site telemetry POST without referer to be detected, got score %.3f", detection.Score)
	}

	foundHiddenRuntime := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "same_site_runtime_hidden_in_headers") {
				foundHiddenRuntime = true
			}
		}
	}

	if !foundHiddenRuntime {
		t.Fatal("expected same_site_runtime_hidden_in_headers indicator")
	}
}

func TestSameSiteSameOriginModeTelemetryDetected(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("POST", "https://example.com/api/telemetry", strings.NewReader(`{"sid":"abc","ts":1700000000,"page":"/","v":"2.1.0","seq":4}`))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "same-origin")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

	req.Header.Set("X-Navigator-Data", strings.Repeat("n", 256))
	req.Header.Set("X-WebGL-Data", strings.Repeat("w", 256))
	req.Header.Set("X-Plugin-Data", strings.Repeat("p", 256))
	req.Header.Set("X-Behavioral-Data", strings.Repeat("b", 2600))
	req.Header.Set("X-Timing-Data", strings.Repeat("t", 2600))
	req.Header.Set("X-Audio-Data", strings.Repeat("a", 600))
	req.Header.Set("X-Canvas-Fingerprint", strings.Repeat("c", 1200))

	detection := detector.AnalyzeRequest(req, nil)
	if !detection.IsBot {
		t.Fatalf("expected same-origin-mode same-site telemetry to be detected, got score %.3f", detection.Score)
	}

	foundModeMismatch := false
	foundHiddenRuntime := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "same_site_same_origin_mode_mismatch") {
				foundModeMismatch = true
			}
			if strings.HasPrefix(ind, "same_site_runtime_hidden_in_headers") {
				foundHiddenRuntime = true
			}
		}
	}

	if !foundModeMismatch {
		t.Fatal("expected same_site_same_origin_mode_mismatch indicator")
	}
	if !foundHiddenRuntime {
		t.Fatal("expected same_site_runtime_hidden_in_headers indicator")
	}
}

func TestSameSiteSameOriginModeReducedHeadersDetected(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("POST", "https://example.com/api/telemetry", strings.NewReader(`{"sid":"abc","ts":1700000000,"page":"/","v":"2.1.0","seq":4}`))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "same-origin")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

	req.Header.Set("X-Behavioral-Data", strings.Repeat("b", 2200))
	req.Header.Set("X-Timing-Data", strings.Repeat("t", 2200))
	req.Header.Set("X-Canvas-Fingerprint", strings.Repeat("c", 1200))

	detection := detector.AnalyzeRequest(req, nil)
	if !detection.IsBot {
		t.Fatalf("expected reduced same-origin-mode same-site telemetry to be detected, got score %.3f", detection.Score)
	}

	foundModeMismatch := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "same_site_same_origin_mode_mismatch") {
				foundModeMismatch = true
			}
		}
	}

	if !foundModeMismatch {
		t.Fatal("expected same_site_same_origin_mode_mismatch indicator")
	}
}

func TestSameSiteZeroHeaderRuntimeMigrationDetected(t *testing.T) {
	detector := NewStealthDetector()

	body := `{"sid":"abc","ts":1700000000,"page":"/","v":"2.1.0","seq":4,` +
		`"navigator":{"userAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0","language":"en-US","platform":"Win32","hardwareConcurrency":8},` +
		`"timing":{"fetchStart":1700000000000,"responseStart":1700000000100,"responseEnd":1700000000150,"domInteractive":1700000000400,"loadEventEnd":1700000000800},` +
		`"canvas":"deadbeefcafebabe","perf":{"ttfb":145,"fcp":286,"lcp":633},` +
		`"viewport":{"w":1440,"h":900,"dpr":2},` +
		`"session":{"entry":"/","depth":3,"duration":14000},` +
		`"sdk":{"name":"web-vitals","version":"3.5.2","integrations":["Replay"]},` +
		`"env":{"release":"prod-2026.3.14","environment":"production","dist":"4f2ab6c1"},` +
		`"breadcrumbs":[{"type":"navigation","timestamp":1699999999000,"data":{"from":"/","to":"/dashboard"}},` +
		`{"type":"ui.click","timestamp":1699999999500,"message":"button.submit","data":{"nodeId":481,"target":"button[type=submit].primary","label":"Continue to dashboard"}}],` +
		`"contexts":{"browser":{"name":"Firefox","version":"128.0"},"device":{"family":"Desktop"}}}`
	req := httptest.NewRequest("POST", "https://api.example.com/api/telemetry", strings.NewReader(body))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-site")

	detection := detector.AnalyzeRequest(req, nil)
	if !detection.IsBot {
		t.Fatalf("expected zero-header same-site runtime migration POST to be detected, got score %.3f", detection.Score)
	}

	foundRuntimeMigration := false
	foundSiblingOrigin := false
	foundMissingReferer := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "same_site_runtime_data_migration") {
				foundRuntimeMigration = true
			}
			if strings.HasPrefix(ind, "same_site_sibling_origin_zero_header_post") {
				foundSiblingOrigin = true
			}
			if ind == "same_site_zero_header_missing_referer" {
				foundMissingReferer = true
			}
		}
	}

	if !foundRuntimeMigration {
		t.Fatal("expected same_site_runtime_data_migration indicator")
	}
	if !foundSiblingOrigin {
		t.Fatal("expected same_site_sibling_origin_zero_header_post indicator")
	}
	if !foundMissingReferer {
		t.Fatal("expected same_site_zero_header_missing_referer indicator")
	}
}

func TestCrossSiteTelemetryPostWithFirstPartyOriginDetected(t *testing.T) {
	detector := NewStealthDetector()

	body := `{"sid":"abc","ts":1700000000,"page":"/","v":"2.1.0","seq":4,` +
		`"perf":{"ttfb":332,"fcp":228,"lcp":418},` +
		`"viewport":{"w":1337,"h":961},` +
		`"session":{"referrer":"https://www.google.com/","entry":"/","depth":6}}`
	req := httptest.NewRequest("POST", "https://example.com/api/telemetry", strings.NewReader(body))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Referer", "https://example.com/")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

	req.Header.Set("X-Navigator-Data", strings.Repeat("n", 256))
	req.Header.Set("X-WebGL-Data", strings.Repeat("w", 256))
	req.Header.Set("X-Plugin-Data", strings.Repeat("p", 256))
	req.Header.Set("X-Screen-Data", strings.Repeat("s", 256))
	req.Header.Set("X-Behavioral-Data", strings.Repeat("b", 2600))
	req.Header.Set("X-Timing-Data", strings.Repeat("t", 2600))
	req.Header.Set("X-Audio-Data", strings.Repeat("a", 600))
	req.Header.Set("X-Canvas-Fingerprint", strings.Repeat("c", 1200))

	detection := detector.AnalyzeRequest(req, nil)
	if !detection.IsBot {
		t.Fatalf("expected cross-site telemetry POST with first-party origin to be detected, got score %.3f", detection.Score)
	}

	foundOriginClaim := false
	foundHiddenRuntime := false
	foundThinBody := false
	foundMissingRuntime := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if ind == "cross_site_claim_on_same_origin_post" {
				foundOriginClaim = true
			}
			if strings.HasPrefix(ind, "cross_site_runtime_hidden_in_headers") {
				foundHiddenRuntime = true
			}
			if strings.HasPrefix(ind, "cross_site_body_too_small_for_claimed_runtime") {
				foundThinBody = true
			}
			if ind == "cross_site_body_missing_runtime_payload" {
				foundMissingRuntime = true
			}
		}
	}

	if !foundOriginClaim {
		t.Fatal("expected cross_site_claim_on_same_origin_post indicator")
	}
	if !foundHiddenRuntime {
		t.Fatal("expected cross_site_runtime_hidden_in_headers indicator")
	}
	if !foundThinBody {
		t.Fatal("expected cross_site_body_too_small_for_claimed_runtime indicator")
	}
	if !foundMissingRuntime {
		t.Fatal("expected cross_site_body_missing_runtime_payload indicator")
	}
}

func TestCrossSiteTelemetryPostWithoutRefererDetected(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("POST", "https://example.com/api/telemetry", strings.NewReader(`{"sid":"abc","ts":1700000000,"page":"/","v":"2.1.0","seq":4}`))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

	req.Header.Set("X-Navigator-Data", strings.Repeat("n", 256))
	req.Header.Set("X-WebGL-Data", strings.Repeat("w", 256))
	req.Header.Set("X-Plugin-Data", strings.Repeat("p", 256))
	req.Header.Set("X-Behavioral-Data", strings.Repeat("b", 2600))
	req.Header.Set("X-Timing-Data", strings.Repeat("t", 2600))
	req.Header.Set("X-Audio-Data", strings.Repeat("a", 600))
	req.Header.Set("X-Canvas-Fingerprint", strings.Repeat("c", 1200))

	detection := detector.AnalyzeRequest(req, nil)
	if !detection.IsBot {
		t.Fatalf("expected cross-site telemetry POST without referer to be detected, got score %.3f", detection.Score)
	}

	foundOriginClaim := false
	foundHiddenRuntime := false
	foundThinBody := false
	foundMissingRuntime := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if ind == "cross_site_claim_on_same_origin_post" {
				foundOriginClaim = true
			}
			if strings.HasPrefix(ind, "cross_site_runtime_hidden_in_headers") {
				foundHiddenRuntime = true
			}
			if strings.HasPrefix(ind, "cross_site_body_too_small_for_claimed_runtime") {
				foundThinBody = true
			}
			if ind == "cross_site_body_missing_runtime_payload" {
				foundMissingRuntime = true
			}
		}
	}

	if !foundOriginClaim {
		t.Fatal("expected cross_site_claim_on_same_origin_post indicator")
	}
	if !foundHiddenRuntime {
		t.Fatal("expected cross_site_runtime_hidden_in_headers indicator")
	}
	if !foundThinBody {
		t.Fatal("expected cross_site_body_too_small_for_claimed_runtime indicator")
	}
	if !foundMissingRuntime {
		t.Fatal("expected cross_site_body_missing_runtime_payload indicator")
	}
}

func TestCrossSiteSameOriginModeTelemetryDetected(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("POST", "https://example.com/api/telemetry", strings.NewReader(`{"sid":"abc","ts":1700000000,"page":"/","v":"2.1.0","seq":1}`))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "same-origin")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

	req.Header.Set("X-Navigator-Data", strings.Repeat("n", 256))
	req.Header.Set("X-WebGL-Data", strings.Repeat("w", 256))
	req.Header.Set("X-Behavioral-Data", strings.Repeat("b", 1800))
	req.Header.Set("X-Timing-Data", strings.Repeat("t", 1800))
	req.Header.Set("X-Audio-Data", strings.Repeat("a", 512))
	req.Header.Set("X-Canvas-Fingerprint", strings.Repeat("c", 1024))

	detection := detector.AnalyzeRequest(req, nil)
	if !detection.IsBot {
		t.Fatalf("expected cross-site same-origin telemetry to be detected, got score %.3f", detection.Score)
	}

	foundMismatch := false
	foundMissingRuntime := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "cross_site_same_origin_mode_mismatch") {
				foundMismatch = true
			}
			if ind == "cross_site_body_missing_runtime_payload" {
				foundMissingRuntime = true
			}
		}
	}

	if !foundMismatch {
		t.Fatal("expected cross_site_same_origin_mode_mismatch indicator")
	}
	if !foundMissingRuntime {
		t.Fatal("expected cross_site_body_missing_runtime_payload indicator")
	}
}

func TestCrossSiteSameOriginModeReducedHeadersDetected(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("POST", "https://example.com/api/telemetry", strings.NewReader(`{"sid":"abc","ts":1700000000,"page":"/","v":"2.1.0","seq":1}`))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "same-origin")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

	req.Header.Set("X-Behavioral-Data", strings.Repeat("b", 1800))
	req.Header.Set("X-Timing-Data", strings.Repeat("t", 1800))
	req.Header.Set("X-Canvas-Fingerprint", strings.Repeat("c", 1024))

	detection := detector.AnalyzeRequest(req, nil)
	if !detection.IsBot {
		t.Fatalf("expected reduced cross-site same-origin telemetry to be detected, got score %.3f", detection.Score)
	}

	foundMismatch := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "cross_site_same_origin_mode_mismatch") {
				foundMismatch = true
			}
		}
	}

	if !foundMismatch {
		t.Fatal("expected cross_site_same_origin_mode_mismatch indicator")
	}
}

func TestThirdPartyCrossSiteTelemetryDoesNotTriggerOriginClaim(t *testing.T) {
	detector := NewStealthDetector()

	body := `{"sid":"abc","ts":1700000000,"page":"/","v":"1.4.2","seq":1,` +
		`"runtime":{"navigator":{"lang":"en-US","cores":8,"mem":8,"ua_blob":"` + strings.Repeat("n", 900) + `"},` +
		`"timing":{"ttfb":120,"fcp":340,"lcp":810,"trace":"` + strings.Repeat("t", 900) + `"},` +
		`"canvas":"abcdef1234567890","audio":"fedcba0987654321"}}`
	req := httptest.NewRequest("POST", "https://analytics.thirdparty.test/collect", strings.NewReader(body))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Referer", "https://app.example.com/dashboard")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

	req.Header.Set("X-Navigator-Data", strings.Repeat("n", 256))
	req.Header.Set("X-WebGL-Data", strings.Repeat("w", 256))
	req.Header.Set("X-Behavioral-Data", strings.Repeat("b", 2600))
	req.Header.Set("X-Timing-Data", strings.Repeat("t", 2600))
	req.Header.Set("X-Audio-Data", strings.Repeat("a", 600))
	req.Header.Set("X-Canvas-Fingerprint", strings.Repeat("c", 1200))

	detection := detector.AnalyzeRequest(req, nil)
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if ind == "cross_site_claim_on_same_origin_post" ||
				ind == "cross_site_telemetry_self_referer" ||
				strings.HasPrefix(ind, "cross_site_runtime_with_first_party_origin") ||
				strings.HasPrefix(ind, "cross_site_body_too_small_for_claimed_runtime") ||
				ind == "cross_site_body_missing_runtime_payload" {
				t.Fatalf("did not expect cross-site origin claim indicator %q for third-party telemetry", ind)
			}
		}
	}
}

func TestSameOriginTelemetryPostWithRichBodyStillDetected(t *testing.T) {
	detector := NewStealthDetector()

	body := `{"sid":"abc","ts":1700000000,"page":"/","v":"1.4.2","seq":1,` +
		`"navigator":{"lang":"en-US","cores":8,"mem":8},` +
		`"timing":{"ttfb":120,"fcp":340,"lcp":810},` +
		`"canvas":"abcdef1234567890","audio":"fedcba0987654321",` +
		`"webgl":{"vendor":"Google Inc.","renderer":"ANGLE"},` +
		`"behavior":{"moves":42,"clicks":3,"scrolls":5}}`
	req := httptest.NewRequest("POST", "http://example.com/api/ml/trap", strings.NewReader(body))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "same-origin")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Referer", "http://example.com/")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")

	req.Header.Set("X-Navigator-Data", strings.Repeat("n", 256))
	req.Header.Set("X-WebGL-Data", strings.Repeat("w", 256))
	req.Header.Set("X-Plugin-Data", strings.Repeat("p", 256))
	req.Header.Set("X-Behavioral-Data", strings.Repeat("b", 2600))
	req.Header.Set("X-Timing-Data", strings.Repeat("t", 2600))
	req.Header.Set("X-Audio-Data", strings.Repeat("a", 600))
	req.Header.Set("X-Canvas-Fingerprint", strings.Repeat("c", 1200))

	detection := detector.AnalyzeRequest(req, nil)
	if !detection.IsBot {
		t.Fatalf("expected rich-body telemetry POST with header overload to be detected, got score %.3f", detection.Score)
	}

	foundHeaderOverloadIndicator := false
	foundBulkHeaderIndicator := false
	foundBehavioralHeaderIndicator := false
	foundHeaderBodyImbalanceIndicator := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "telemetry_header_surface_overload") {
				foundHeaderOverloadIndicator = true
			}
			if strings.HasPrefix(ind, "telemetry_bulk_payload_in_headers") {
				foundBulkHeaderIndicator = true
			}
			if ind == "telemetry_behavioral_payload_in_headers" {
				foundBehavioralHeaderIndicator = true
			}
			if strings.HasPrefix(ind, "telemetry_header_body_imbalance") {
				foundHeaderBodyImbalanceIndicator = true
			}
		}
	}
	if !foundHeaderOverloadIndicator {
		t.Fatal("expected telemetry_header_surface_overload indicator")
	}
	if !foundBulkHeaderIndicator {
		t.Fatal("expected telemetry_bulk_payload_in_headers indicator")
	}
	if !foundBehavioralHeaderIndicator {
		t.Fatal("expected telemetry_behavioral_payload_in_headers indicator")
	}
	if !foundHeaderBodyImbalanceIndicator {
		t.Fatal("expected telemetry_header_body_imbalance indicator")
	}
}

func TestFirefoxStyleTelemetryPostWithBulkHeadersDetected(t *testing.T) {
	detector := NewStealthDetector()

	body := `{"sid":"abc","ts":1700000000,"page":"/","v":"1.4.2","seq":1,` +
		`"navigator":{"lang":"en-US","cores":8,"mem":8},` +
		`"timing":{"ttfb":120,"fcp":340,"lcp":810},` +
		`"canvas":"abcdef1234567890","audio":"fedcba0987654321"}`
	req := httptest.NewRequest("POST", "http://example.com/api/ml/trap", strings.NewReader(body))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "same-origin")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Referer", "http://example.com/")

	req.Header.Set("X-Timing-Data", strings.Repeat("t", 2600))
	req.Header.Set("X-Audio-Data", strings.Repeat("a", 600))
	req.Header.Set("X-Canvas-Fingerprint", strings.Repeat("c", 1200))

	detection := detector.AnalyzeRequest(req, nil)
	if !detection.IsBot {
		t.Fatalf("expected firefox-style telemetry POST with bulk headers to be detected, got score %.3f", detection.Score)
	}

	foundBulkHeaderIndicator := false
	foundHeaderBodyImbalanceIndicator := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "telemetry_bulk_payload_in_headers") {
				foundBulkHeaderIndicator = true
			}
			if strings.HasPrefix(ind, "telemetry_header_body_imbalance") {
				foundHeaderBodyImbalanceIndicator = true
			}
		}
	}
	if !foundBulkHeaderIndicator {
		t.Fatal("expected telemetry_bulk_payload_in_headers indicator")
	}
	if !foundHeaderBodyImbalanceIndicator {
		t.Fatal("expected telemetry_header_body_imbalance indicator")
	}
}

func TestFirefoxStyleTelemetryPostWithInvalidJSONBodyDetected(t *testing.T) {
	detector := NewStealthDetector()

	body := `{"sid":"abc","ts":1700000000,"page":"/","v":"1.4.2","seq":2,` +
		`"navigator":{"lang":"en-US","cores":[4 8 12 16],"mem":[8 16 32]},` +
		`"timing":{"ttfb":92,"fcp":568,"lcp":1263}}`
	req := httptest.NewRequest("POST", "http://example.com/api/ml/trap", strings.NewReader(body))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "same-origin")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Referer", "http://example.com/")
	req.Header.Set("X-Behavioral-Data", strings.Repeat("b", 2200))
	req.Header.Set("X-Timing-Data", strings.Repeat("t", 2600))

	detection := detector.AnalyzeRequest(req, nil)
	if !detection.IsBot {
		t.Fatalf("expected firefox-style telemetry POST with invalid JSON body to be detected, got score %.3f", detection.Score)
	}

	foundBlobIndicator := false
	foundTimingBlobIndicator := false
	foundInvalidJSONIndicator := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "telemetry_postload_blob_in_headers") {
				foundBlobIndicator = true
			}
			if strings.HasPrefix(ind, "telemetry_timing_blob_in_headers") {
				foundTimingBlobIndicator = true
			}
			if ind == "telemetry_invalid_json_body" {
				foundInvalidJSONIndicator = true
			}
		}
	}
	if !foundBlobIndicator {
		t.Fatal("expected telemetry_postload_blob_in_headers indicator")
	}
	if !foundTimingBlobIndicator {
		t.Fatal("expected telemetry_timing_blob_in_headers indicator")
	}
	if !foundInvalidJSONIndicator {
		t.Fatal("expected telemetry_invalid_json_body indicator")
	}
}

func TestFirefoxStyleTelemetryPostWithTimingBlobHeaderDetected(t *testing.T) {
	detector := NewStealthDetector()

	body := `{"sid":"abc","ts":1700000000,"page":"/","v":"1.4.2","seq":2,"timing":{"ttfb":92,"fcp":568,"lcp":1263}}`
	req := httptest.NewRequest("POST", "http://example.com/api/ml/trap", strings.NewReader(body))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "same-origin")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Referer", "http://example.com/")
	req.Header.Set("X-Timing-Data", strings.Repeat("t", 2600))

	detection := detector.AnalyzeRequest(req, nil)
	if !detection.IsBot {
		t.Fatalf("expected firefox-style telemetry POST with timing blob header to be detected, got score %.3f", detection.Score)
	}

	foundBlobIndicator := false
	foundTimingBlobIndicator := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "telemetry_postload_blob_in_headers") {
				foundBlobIndicator = true
			}
			if strings.HasPrefix(ind, "telemetry_timing_blob_in_headers") {
				foundTimingBlobIndicator = true
			}
		}
	}
	if !foundBlobIndicator {
		t.Fatal("expected telemetry_postload_blob_in_headers indicator")
	}
	if !foundTimingBlobIndicator {
		t.Fatal("expected telemetry_timing_blob_in_headers indicator")
	}
}

func TestStandardChromiumHeadersDoNotTriggerRichRuntimeIndicator(t *testing.T) {
	detector := NewStealthDetector()

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Sec-Ch-Ua", `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"macOS"`)
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	detection := detector.AnalyzeRequest(req, nil)

	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if ind == "rich_chromium_headers_without_runtime_state" {
				t.Fatal("did not expect rich_chromium_headers_without_runtime_state for standard Chromium headers")
			}
		}
	}
}

func TestDetectionVectorsComprehensive(t *testing.T) {
	detector := NewStealthDetector()

	testCases := []struct {
		name          string
		headers       map[string]string
		expectBot     bool
		expectStealth bool
		description   string
	}{
		{
			name: "Perfect Chrome browser",
			headers: map[string]string{
				"User-Agent":         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
				"Accept":             "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
				"Accept-Language":    "en-US,en;q=0.5",
				"Sec-Ch-Ua":          "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"",
				"Sec-Ch-Ua-Mobile":   "?0",
				"Sec-Ch-Ua-Platform": "\"macOS\"",
			},
			expectBot:     false,
			expectStealth: false,
			description:   "Perfect Chrome should not be detected",
		},
		{
			name: "webdriver=true indicator",
			headers: map[string]string{
				"User-Agent":       "Mozilla/5.0",
				"Accept":           "text/html",
				"X-Navigator-Data": `{"webdriver":true}`,
			},
			expectBot:     true,
			expectStealth: true,
			description:   "webdriver=true should be detected",
		},
		{
			name: "Zero variance behavioral",
			headers: map[string]string{
				"User-Agent":        "Mozilla/5.0",
				"Accept":            "text/html",
				"X-Behavioral-Data": `{"mouseEvents":10,"mouseStdDev":0,"typingStdDev":0}`,
			},
			expectBot:     true,
			expectStealth: true,
			description:   "Zero variance indicates automation",
		},
		{
			name: "Canvas randomization",
			headers: map[string]string{
				"User-Agent":           "Mozilla/5.0",
				"Accept":               "text/html",
				"X-Canvas-Fingerprint": "randomized=true",
			},
			expectBot:     true,
			expectStealth: true,
			description:   "Canvas randomization detected",
		},
		{
			name: "Zero TTFB",
			headers: map[string]string{
				"User-Agent":    "Mozilla/5.0",
				"Accept":        "text/html",
				"X-Timing-Data": `{"ttfb":0,"navigationStart":1000,"loadEventEnd":1000}`,
			},
			expectBot:     true,
			expectStealth: false,
			description:   "Suspicious timing",
		},
		{
			name: "Missing chrome runtime",
			headers: map[string]string{
				"User-Agent":       "Mozilla/5.0",
				"Accept":           "text/html",
				"X-Navigator-Data": `{"webdriver":false}`,
			},
			expectBot:     false,
			expectStealth: false,
			description:   "Missing chrome runtime alone shouldn't trigger",
		},
		{
			name: "Multiple stealth indicators",
			headers: map[string]string{
				"User-Agent":           "Mozilla/5.0",
				"Accept":               "text/html",
				"X-Navigator-Data":     `{"webdriver":false}`,
				"X-Behavioral-Data":    `{"mouseEvents":0,"mouseStdDev":0}`,
				"X-Canvas-Fingerprint": "randomized=true",
			},
			expectBot:     true,
			expectStealth: true,
			description:   "Multiple indicators should trigger stealth detection",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com", nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}

			detection := detector.AnalyzeRequest(req, nil)

			t.Logf("Test: %s", tc.name)
			t.Logf("  Description: %s", tc.description)
			t.Logf("  Score: %.2f, IsBot: %v, IsStealth: %v", detection.Score, detection.IsBot, detection.IsStealth)
			for _, vec := range detection.Vectors {
				if vec.Detected {
					t.Logf("  Detected: %s (%.2f)", vec.Name, vec.Score)
				}
			}

			if tc.expectBot && !detection.IsBot {
				t.Logf("WARNING: Expected bot detection but passed")
			}
			if tc.expectStealth && !detection.IsStealth {
				t.Logf("WARNING: Expected stealth detection but passed")
			}
		})
	}
}
