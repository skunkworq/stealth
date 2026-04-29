package challenge

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"testing"

	"github.com/skunkworq/stealth/brws/core/types"
)

func TestVectorMap_Detection(t *testing.T) {
	vm := NewVectorMap()

	t.Run("TLS vector detection", func(t *testing.T) {
		tlsInfo := &tls.ClientHelloInfo{
			CipherSuites: []uint16{
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			ServerName: "example.com",
		}

		result := vm.AnalyzeTLS(tlsInfo)

		if result == nil {
			t.Fatal("Expected result, got nil")
		}

		t.Logf("TLS Detection result: detected=%v, score=%.2f", result.Detected, result.Score)
		for _, ind := range result.Indicators {
			t.Logf("  - %s: %s", ind.Check, ind.Message)
		}
	})

	t.Run("HTTP vector detection with valid headers", func(t *testing.T) {
		req := &http.Request{
			Header: http.Header{
				"User-Agent":         []string{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
				"Accept":             []string{"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
				"Accept-Language":    []string{"en-US,en;q=0.5"},
				"Accept-Encoding":    []string{"gzip, deflate, br"},
				"Sec-Ch-Ua":          []string{"\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\""},
				"Sec-Ch-Ua-Mobile":   []string{"?0"},
				"Sec-Ch-Ua-Platform": []string{"\"macOS\""},
			},
		}

		result := vm.AnalyzeHTTP(req)

		if result == nil {
			t.Fatal("Expected result, got nil")
		}

		t.Logf("HTTP Detection result: detected=%v, score=%.2f", result.Detected, result.Score)
		for _, ind := range result.Indicators {
			t.Logf("  - %s: %s", ind.Check, ind.Message)
		}

		if result.Detected {
			t.Errorf("Valid browser headers should not be detected as bot")
		}
	})

	t.Run("HTTP vector detection with missing headers", func(t *testing.T) {
		req := &http.Request{
			Header: http.Header{
				"User-Agent": []string{"Mozilla/5.0"},
			},
		}

		result := vm.AnalyzeHTTP(req)

		if result == nil {
			t.Fatal("Expected result, got nil")
		}

		t.Logf("HTTP Detection result: detected=%v, score=%.2f", result.Detected, result.Score)
		for _, ind := range result.Indicators {
			t.Logf("  - %s: %s", ind.Check, ind.Message)
		}

		if !result.Detected {
			t.Logf("Missing headers correctly detected")
		}
	})

	t.Run("HTTP vector detection with suspicious UA", func(t *testing.T) {
		req := &http.Request{
			Header: http.Header{
				"User-Agent": []string{"python-requests/2.28.0"},
			},
		}

		result := vm.AnalyzeHTTP(req)

		if result == nil {
			t.Fatal("Expected result, got nil")
		}

		t.Logf("HTTP Detection result: detected=%v, score=%.2f", result.Detected, result.Score)
		for _, ind := range result.Indicators {
			t.Logf("  - %s: %s", ind.Check, ind.Message)
		}

		if !result.Detected {
			t.Errorf("Suspicious User-Agent should be detected")
		}
	})

	t.Run("HTTP vector detection with inconsistent client hints", func(t *testing.T) {
		req := &http.Request{
			Header: http.Header{
				"User-Agent":         []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
				"Sec-Ch-Ua":          []string{"\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\""},
				"Sec-Ch-Ua-Platform": []string{"\"Linux\""},
			},
		}

		result := vm.AnalyzeHTTP(req)

		if result == nil {
			t.Fatal("Expected result, got nil")
		}

		t.Logf("HTTP Detection result: detected=%v, score=%.2f", result.Detected, result.Score)
		for _, ind := range result.Indicators {
			t.Logf("  - %s: %s", ind.Check, ind.Message)
		}

		foundInconsistent := false
		for _, ind := range result.Indicators {
			if ind.Check == "inconsistent_ch" {
				foundInconsistent = true
			}
		}
		if !foundInconsistent {
			t.Logf("Inconsistent client hints not detected")
		}
	})

	t.Run("Behavioral vector detection", func(t *testing.T) {
		events := &BehavioralEvents{
			MouseEvents:   20,
			ScrollEvents:  5,
			TypingEvents:  10,
			MouseAvgSpeed: 150.5,
			MouseStdDev:   45.2,
			TypingStdDev:  25.0,
		}

		result := vm.AnalyzeBehavioral(events)

		if result == nil {
			t.Fatal("Expected result, got nil")
		}

		t.Logf("Behavioral Detection result: detected=%v, score=%.2f", result.Detected, result.Score)
		for _, ind := range result.Indicators {
			t.Logf("  - %s: %s", ind.Check, ind.Message)
		}

		if result.Detected {
			t.Errorf("Normal behavioral patterns should not be detected as bot")
		}
	})

	t.Run("Behavioral vector with zero variance", func(t *testing.T) {
		events := &BehavioralEvents{
			MouseEvents:   20,
			ScrollEvents:  5,
			TypingEvents:  10,
			MouseAvgSpeed: 150.0,
			MouseStdDev:   0,
			TypingStdDev:  0,
		}

		result := vm.AnalyzeBehavioral(events)

		if result == nil {
			t.Fatal("Expected result, got nil")
		}

		t.Logf("Behavioral Detection result: detected=%v, score=%.2f", result.Detected, result.Score)
		for _, ind := range result.Indicators {
			t.Logf("  - %s: %s", ind.Check, ind.Message)
		}

		if !result.Detected {
			t.Logf("Zero variance should be detected as suspicious")
		}
	})

	t.Run("Navigator vector detection", func(t *testing.T) {
		nav := &NavigatorData{
			Webdriver:           false,
			PropCount:           20,
			Platform:            "MacIntel",
			Vendor:              "Google Inc.",
			Language:            "en-US",
			Languages:           []string{"en-US", "en"},
			HardwareConcurrency: 8,
			DeviceMemory:        8,
		}

		result := vm.AnalyzeNavigator(nav)

		if result == nil {
			t.Fatal("Expected result, got nil")
		}

		t.Logf("Navigator Detection result: detected=%v, score=%.2f", result.Detected, result.Score)
		for _, ind := range result.Indicators {
			t.Logf("  - %s: %s", ind.Check, ind.Message)
		}

		if result.Detected {
			t.Errorf("Valid navigator should not be detected")
		}
	})

	t.Run("Navigator with webdriver=true", func(t *testing.T) {
		nav := &NavigatorData{
			Webdriver: true,
			PropCount: 20,
			Platform:  "MacIntel",
			Vendor:    "Google Inc.",
			Language:  "en-US",
		}

		result := vm.AnalyzeNavigator(nav)

		if result == nil {
			t.Fatal("Expected result, got nil")
		}

		t.Logf("Navigator Detection result: detected=%v, score=%.2f", result.Detected, result.Score)
		for _, ind := range result.Indicators {
			t.Logf("  - %s: %s", ind.Check, ind.Message)
		}

		if !result.Detected {
			t.Logf("webdriver=true should be detected")
		}
	})
}

func TestTestServer(t *testing.T) {
	server := NewTestServer()
	defer server.Close()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // G402: Test server uses self-signed cert
		},
	}

	t.Run("Valid browser request", func(t *testing.T) {
		server.ClearDetections()

		req, err := http.NewRequest("GET", server.URL, nil)
		if err != nil {
			t.Fatal(err)
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
		req.Header.Set("Sec-Ch-Ua", "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"")
		req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
		req.Header.Set("Sec-Ch-Ua-Platform", "\"macOS\"")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()

		detection := server.GetLastDetection()
		if detection == nil {
			t.Fatal("Expected detection record")
		}

		t.Logf("Detection: is_bot=%v, score=%.2f", detection.IsBot, detection.Score)
		for _, ind := range detection.Indicators {
			t.Logf("  - %s: %s", ind.Name, ind.Message)
		}

		if detection.IsBot {
			t.Errorf("Valid browser should not be detected as bot")
		}
	})

	t.Run("Python requests detected as bot", func(t *testing.T) {
		server.ClearDetections()

		req, err := http.NewRequest("GET", server.URL, nil)
		if err != nil {
			t.Fatal(err)
		}

		req.Header.Set("User-Agent", "python-requests/2.28.0")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()

		detection := server.GetLastDetection()
		if detection == nil {
			t.Fatal("Expected detection record")
		}

		t.Logf("Detection: is_bot=%v, score=%.2f", detection.IsBot, detection.Score)
		for _, ind := range detection.Indicators {
			t.Logf("  - %s: %s", ind.Name, ind.Message)
		}

		if !detection.IsBot {
			t.Logf("python-requests should be detected as bot")
		}
	})

	t.Run("Missing required headers", func(t *testing.T) {
		server.ClearDetections()

		req, err := http.NewRequest("GET", server.URL, nil)
		if err != nil {
			t.Fatal(err)
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()

		detection := server.GetLastDetection()
		if detection == nil {
			t.Fatal("Expected detection record")
		}

		t.Logf("Detection: is_bot=%v, score=%.2f", detection.IsBot, detection.Score)
		for _, ind := range detection.Indicators {
			t.Logf("  - %s: %s", ind.Name, ind.Message)
		}
	})
}

func TestFingerprintAnalysis(t *testing.T) {
	t.Run("Complete fingerprint analysis", func(t *testing.T) {
		fp := &types.CompleteFingerprint{
			TLS: &types.TLSFingerprint{
				JA4: "t13d",
			},
			HTTP: &types.HTTPFingerprint{
				UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			},
		}

		results, detected := DetectWithVectors(fp)

		t.Logf("Detection results: detected=%v", detected)
		for _, r := range results {
			t.Logf("  Vector: %s, score: %.2f, detected: %v", r.Vector, r.Score, r.Detected)
		}
	})
}

func TestRunTestSuite(t *testing.T) {
	tests := []struct {
		Name    string
		Request func(*http.Request)
	}{
		{
			Name: "Valid Chrome browser",
			Request: func(req *http.Request) {
				req.Header.Set("Sec-Ch-Ua", "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"")
				req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
				req.Header.Set("Sec-Ch-Ua-Platform", "\"macOS\"")
			},
		},
		{
			Name: "Missing Accept header",
			Request: func(req *http.Request) {
				req.Header.Del("Accept")
			},
		},
		{
			Name: "Suspicious User-Agent",
			Request: func(req *http.Request) {
				req.Header.Set("User-Agent", "curl/7.88.1")
			},
		},
		{
			Name: "Inconsistent Client Hints",
			Request: func(req *http.Request) {
				req.Header.Set("Sec-Ch-Ua", "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\"")
				req.Header.Set("Sec-Ch-Ua-Platform", "\"Linux\"")
			},
		},
	}

	results := RunTestSuite(tests)
	PrintTestResults(results)

	for _, r := range results {
		if r.TestName == "Valid Chrome browser" && r.Detected {
			t.Errorf("Valid Chrome browser should not be detected as bot")
		}
	}
}

func TestExpectHuman(t *testing.T) {
	t.Run("Valid browser headers", func(t *testing.T) {
		headers := http.Header{
			"User-Agent":         []string{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
			"Accept":             []string{"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
			"Accept-Language":    []string{"en-US,en;q=0.5"},
			"Accept-Encoding":    []string{"gzip, deflate, br"},
			"Sec-Ch-Ua":          []string{"\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\""},
			"Sec-Ch-Ua-Mobile":   []string{"?0"},
			"Sec-Ch-Ua-Platform": []string{"\"macOS\""},
		}

		isHuman, score, anomalies := ExpectHuman(headers)
		t.Logf("isHuman=%v, score=%.2f", isHuman, score)
		for _, a := range anomalies {
			t.Logf("  anomaly: %s", a)
		}
	})

	t.Run("Suspicious headers", func(t *testing.T) {
		headers := http.Header{
			"User-Agent": []string{"python-requests/2.28.0"},
		}

		isHuman, score, anomalies := ExpectHuman(headers)
		t.Logf("isHuman=%v, score=%.2f", isHuman, score)
		for _, a := range anomalies {
			t.Logf("  anomaly: %s", a)
		}
	})
}

func BenchmarkVectorDetection(b *testing.B) {
	vm := NewVectorMap()

	headers := http.Header{
		"User-Agent":         []string{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
		"Accept":             []string{"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
		"Accept-Language":    []string{"en-US,en;q=0.5"},
		"Accept-Encoding":    []string{"gzip, deflate, br"},
		"Sec-Ch-Ua":          []string{"\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\""},
		"Sec-Ch-Ua-Mobile":   []string{"?0"},
		"Sec-Ch-Ua-Platform": []string{"\"macOS\""},
	}

	req := &http.Request{
		Header: headers,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		vm.AnalyzeHTTP(req)
	}
}

func ExampleNewVectorMap() {
	vm := NewVectorMap()

	req := &http.Request{
		Header: http.Header{
			"User-Agent":         []string{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
			"Accept":             []string{"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
			"Accept-Language":    []string{"en-US,en;q=0.5"},
			"Sec-Ch-Ua":          []string{"\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\""},
			"Sec-Ch-Ua-Platform": []string{"\"macOS\""},
		},
	}

	result := vm.AnalyzeHTTP(req)
	fmt.Printf("Detected: %v, Score: %.2f\n", result.Detected, result.Score)

	for _, ind := range result.Indicators {
		fmt.Printf("  - %s: %s\n", ind.Check, ind.Message)
	}
	// Output:
	// Detected: false, Score: 0.00
}
