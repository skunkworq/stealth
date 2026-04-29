package challenge

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDetectChallenge_JSChallenge(t *testing.T) {
	headers := http.Header{}
	headers.Set("Server", "cloudflare")
	headers.Set("Cf-Ray", "abc123-IAD")

	body := []byte(`<html>
		<head><title>Just a moment...</title></head>
		<body>
			<div id="cf-browser-verification">
				<script>var _cf_chl_opt={chlApiUrl:"challenge-api"}</script>
			</div>
		</body>
	</html>`)

	challenge := DetectChallenge(503, headers, body)
	if challenge == nil {
		t.Fatal("expected challenge to be detected, got nil")
	}
	if challenge.Type != ChallengeJS {
		t.Errorf("expected challenge type %s, got %s", ChallengeJS, challenge.Type)
	}
	if challenge.StatusCode != 503 {
		t.Errorf("expected status code 503, got %d", challenge.StatusCode)
	}
	if challenge.RayID != "abc123-IAD" {
		t.Errorf("expected ray ID 'abc123-IAD', got %q", challenge.RayID)
	}
}

func TestDetectChallenge_JSChallenge_LegacyMarker(t *testing.T) {
	headers := http.Header{}
	headers.Set("Server", "cloudflare")
	headers.Set("Cf-Ray", "def456-SFO")

	body := []byte(`<html>
		<body>
			<form id="challenge-form" action="/cdn-cgi/challenge-platform">
				<input type="hidden" name="jschl_vc" value="test_value"/>
				<input type="hidden" name="jschl_answer" value=""/>
			</form>
		</body>
	</html>`)

	challenge := DetectChallenge(503, headers, body)
	if challenge == nil {
		t.Fatal("expected JS challenge to be detected, got nil")
	}
	if challenge.Type != ChallengeJS {
		t.Errorf("expected challenge type %s, got %s", ChallengeJS, challenge.Type)
	}
}

func TestDetectChallenge_Turnstile(t *testing.T) {
	headers := http.Header{}
	headers.Set("Server", "cloudflare")
	headers.Set("Cf-Ray", "ghi789-LHR")

	body := []byte(`<html>
		<body>
			<div class="cf-turnstile" data-sitekey="0x4AAAAAAA_test_sitekey_123"></div>
			<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
		</body>
	</html>`)

	challenge := DetectChallenge(403, headers, body)
	if challenge == nil {
		t.Fatal("expected Turnstile challenge to be detected, got nil")
	}
	if challenge.Type != ChallengeTurnstile {
		t.Errorf("expected challenge type %s, got %s", ChallengeTurnstile, challenge.Type)
	}
	if challenge.SiteKey != "0x4AAAAAAA_test_sitekey_123" {
		t.Errorf("expected sitekey '0x4AAAAAAA_test_sitekey_123', got %q", challenge.SiteKey)
	}
	if challenge.RayID != "ghi789-LHR" {
		t.Errorf("expected ray ID 'ghi789-LHR', got %q", challenge.RayID)
	}
}

func TestDetectChallenge_ManagedChallenge(t *testing.T) {
	headers := http.Header{}
	headers.Set("Server", "cloudflare")
	headers.Set("Cf-Ray", "jkl012-CDG")

	body := []byte(`<html>
		<body>
			<div id="challenge-platform">
				<div class="managed_challenge">Verifying you are human...</div>
			</div>
		</body>
	</html>`)

	challenge := DetectChallenge(403, headers, body)
	if challenge == nil {
		t.Fatal("expected managed challenge to be detected, got nil")
	}
	if challenge.Type != ChallengeManaged {
		t.Errorf("expected challenge type %s, got %s", ChallengeManaged, challenge.Type)
	}
}

func TestDetectChallenge_Blocked(t *testing.T) {
	headers := http.Header{}
	headers.Set("Server", "cloudflare")
	headers.Set("Cf-Ray", "mno345-NRT")

	body := []byte(`<html>
		<body>
			<h1>Access denied</h1>
			<p>Sorry, you have been blocked.</p>
		</body>
	</html>`)

	challenge := DetectChallenge(403, headers, body)
	if challenge == nil {
		t.Fatal("expected blocked challenge to be detected, got nil")
	}
	if challenge.Type != ChallengeBlocked {
		t.Errorf("expected challenge type %s, got %s", ChallengeBlocked, challenge.Type)
	}
	if challenge.StatusCode != 403 {
		t.Errorf("expected status code 403, got %d", challenge.StatusCode)
	}
}

func TestDetectChallenge_NoChallenge(t *testing.T) {
	headers := http.Header{}
	headers.Set("Server", "nginx")
	headers.Set("Content-Type", "text/html")

	body := []byte(`<html><body><h1>Hello World</h1></body></html>`)

	challenge := DetectChallenge(200, headers, body)
	if challenge != nil {
		t.Errorf("expected no challenge for normal page, got %v", challenge)
	}
}

func TestDetectChallenge_NoChallenge_CloudflareButOK(t *testing.T) {
	// A 200 from Cloudflare should not be detected as a challenge
	headers := http.Header{}
	headers.Set("Server", "cloudflare")
	headers.Set("Cf-Ray", "pqr678-SYD")

	body := []byte(`<html><body><h1>Welcome!</h1></body></html>`)

	challenge := DetectChallenge(200, headers, body)
	if challenge != nil {
		t.Errorf("expected no challenge for 200 OK from Cloudflare, got %v", challenge)
	}
}

func TestExtractClearanceCookie(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:  "cf_clearance",
			Value: "abc123_clearance_value",
			Path:  "/",
		})
		http.SetCookie(w, &http.Cookie{
			Name:  "__cf_bm",
			Value: "bot_management_token",
			Path:  "/",
		})
		w.WriteHeader(200)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	cookie := ExtractClearanceCookie(resp)
	if cookie == nil {
		t.Fatal("expected cf_clearance cookie, got nil")
	}
	if cookie.Name != "cf_clearance" {
		t.Errorf("expected cookie name 'cf_clearance', got %q", cookie.Name)
	}
	if cookie.Value != "abc123_clearance_value" {
		t.Errorf("expected cookie value 'abc123_clearance_value', got %q", cookie.Value)
	}
}

func TestExtractClearanceCookie_NoCookie(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:  "session_id",
			Value: "some_session",
		})
		w.WriteHeader(200)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	cookie := ExtractClearanceCookie(resp)
	if cookie != nil {
		t.Errorf("expected nil cookie when cf_clearance is absent, got %v", cookie)
	}
}

func TestExtractClearanceCookie_NilResponse(t *testing.T) {
	cookie := ExtractClearanceCookie(nil)
	if cookie != nil {
		t.Errorf("expected nil cookie for nil response, got %v", cookie)
	}
}

func TestIsCloudflarePage(t *testing.T) {
	tests := []struct {
		name     string
		headers  http.Header
		expected bool
	}{
		{
			name: "cloudflare server header",
			headers: func() http.Header {
				h := http.Header{}
				h.Set("Server", "cloudflare")
				return h
			}(),
			expected: true,
		},
		{
			name: "cf-ray header present",
			headers: func() http.Header {
				h := http.Header{}
				h.Set("Cf-Ray", "abc123-IAD")
				return h
			}(),
			expected: true,
		},
		{
			name: "both cloudflare indicators",
			headers: func() http.Header {
				h := http.Header{}
				h.Set("Server", "cloudflare")
				h.Set("Cf-Ray", "def456-SFO")
				return h
			}(),
			expected: true,
		},
		{
			name: "nginx server",
			headers: func() http.Header {
				h := http.Header{}
				h.Set("Server", "nginx")
				return h
			}(),
			expected: false,
		},
		{
			name: "apache server",
			headers: func() http.Header {
				h := http.Header{}
				h.Set("Server", "Apache/2.4.41")
				return h
			}(),
			expected: false,
		},
		{
			name:     "empty headers",
			headers:  http.Header{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsCloudflarePage(tt.headers)
			if result != tt.expected {
				t.Errorf("IsCloudflarePage() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestCloudflareChallenge_String(t *testing.T) {
	challenge := &CloudflareChallenge{
		Type:       ChallengeJS,
		StatusCode: 503,
		RayID:      "abc123-IAD",
		URL:        "https://example.com",
	}

	str := challenge.String()
	if str == "" {
		t.Error("expected non-empty string representation")
	}
	if !containsAll(str, "js_challenge", "503", "abc123-IAD", "https://example.com") {
		t.Errorf("string representation missing expected fields: %s", str)
	}

	// Test with sitekey
	challenge.SiteKey = "0x4AAAA_test"
	str = challenge.String()
	if !containsAll(str, "sitekey=0x4AAAA_test") {
		t.Errorf("string representation missing sitekey: %s", str)
	}

	// Test nil challenge
	var nilChallenge *CloudflareChallenge
	nilStr := nilChallenge.String()
	if nilStr != "CloudflareChallenge{none}" {
		t.Errorf("expected 'CloudflareChallenge{none}' for nil, got %q", nilStr)
	}
}

func TestCloudflareDetector_AnalyzeRequest(t *testing.T) {
	detector := NewCloudflareDetector()

	t.Run("clean request with CF cookies", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		req.AddCookie(&http.Cookie{Name: "__cf_bm", Value: "bot_mgmt_token"})
		req.AddCookie(&http.Cookie{Name: "cf_clearance", Value: "clearance_value"})

		signals := detector.AnalyzeRequest(req)
		// Should have minimal or no signals for a clean request
		for _, s := range signals {
			if s.Score > 0.5 {
				t.Errorf("clean request produced high-score signal: %s (score=%.2f)", s.Name, s.Score)
			}
		}
	})

	t.Run("request missing CF cookies", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
		req.Header.Set("Accept", "text/html")
		req.Header.Set("Accept-Language", "en-US")

		signals := detector.AnalyzeRequest(req)
		foundMissing := false
		for _, s := range signals {
			if s.Name == "missing_cf_cookies" {
				foundMissing = true
				break
			}
		}
		if !foundMissing {
			t.Error("expected missing_cf_cookies signal for request without CF cookies")
		}
	})

	t.Run("request missing browser headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
		// Deliberately omit Accept-Language and Accept

		signals := detector.AnalyzeRequest(req)
		foundHeaderOrder := false
		for _, s := range signals {
			if s.Name == "header_order" {
				foundHeaderOrder = true
				break
			}
		}
		if !foundHeaderOrder {
			t.Error("expected header_order signal for request missing browser headers")
		}
	})

	t.Run("request with proxy headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
		req.Header.Set("Accept", "text/html")
		req.Header.Set("Accept-Language", "en-US")
		req.Header.Set("X-Forwarded-For", "10.0.0.1")
		req.Header.Set("X-Real-Ip", "10.0.0.1")
		req.Header.Set("Via", "1.1 proxy.example.com")
		req.AddCookie(&http.Cookie{Name: "__cf_bm", Value: "token"})

		signals := detector.AnalyzeRequest(req)
		foundTLS := false
		for _, s := range signals {
			if s.Name == "suspicious_tls" {
				foundTLS = true
				break
			}
		}
		if !foundTLS {
			t.Error("expected suspicious_tls signal for request with multiple proxy headers")
		}
	})

	t.Run("request with rapid solve header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
		req.Header.Set("Accept", "text/html")
		req.Header.Set("Accept-Language", "en-US")
		req.Header.Set("X-Cf-Solve-Time-Ms", "150")
		req.AddCookie(&http.Cookie{Name: "__cf_bm", Value: "token"})

		signals := detector.AnalyzeRequest(req)
		foundRapid := false
		for _, s := range signals {
			if s.Name == "rapid_solve" {
				foundRapid = true
				if s.Score < 0.7 {
					t.Errorf("expected rapid_solve score >= 0.7, got %.2f", s.Score)
				}
				break
			}
		}
		if !foundRapid {
			t.Error("expected rapid_solve signal for 150ms solve time")
		}
	})
}

func TestCloudflareDetector_AnalyzeResponse(t *testing.T) {
	detector := NewCloudflareDetector()

	t.Run("rate limited response", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 429,
			Header:     http.Header{},
		}
		resp.Header.Set("Server", "cloudflare")
		resp.Header.Set("Cf-Ray", "test-ray")

		signals := detector.AnalyzeResponse(resp)
		foundRateLimit := false
		for _, s := range signals {
			if s.Name == "rate_limited" {
				foundRateLimit = true
				break
			}
		}
		if !foundRateLimit {
			t.Error("expected rate_limited signal for 429 response from Cloudflare")
		}
	})

	t.Run("challenge loop", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 503,
			Header:     http.Header{},
		}
		resp.Header.Set("Server", "cloudflare")
		resp.Header.Set("Cf-Ray", "new-ray-id")

		signals := detector.AnalyzeResponse(resp)
		foundLoop := false
		for _, s := range signals {
			if s.Name == "challenge_loop" {
				foundLoop = true
				break
			}
		}
		if !foundLoop {
			t.Error("expected challenge_loop signal for 503 from Cloudflare with Cf-Ray")
		}
	})

	t.Run("captcha escalation", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 403,
			Header:     http.Header{},
		}
		resp.Header.Set("Server", "cloudflare")
		resp.Header.Set("Retry-After", "10")

		signals := detector.AnalyzeResponse(resp)
		foundEscalation := false
		for _, s := range signals {
			if s.Name == "captcha_escalation" {
				foundEscalation = true
				break
			}
		}
		if !foundEscalation {
			t.Error("expected captcha_escalation signal for 403 with Retry-After from Cloudflare")
		}
	})

	t.Run("nil response", func(t *testing.T) {
		signals := detector.AnalyzeResponse(nil)
		if len(signals) != 0 {
			t.Errorf("expected no signals for nil response, got %d", len(signals))
		}
	})
}

func TestCloudflareDetector_ScoreRequest(t *testing.T) {
	detector := NewCloudflareDetector()

	t.Run("clean request scores low", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.AddCookie(&http.Cookie{Name: "__cf_bm", Value: "token"})
		req.AddCookie(&http.Cookie{Name: "cf_clearance", Value: "clearance"})

		score := detector.ScoreRequest(req)
		if score > 0.3 {
			t.Errorf("expected clean request score <= 0.3, got %.2f", score)
		}
	})

	t.Run("bot-like request scores high", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
		// Missing Accept, Accept-Language, CF cookies, plus rapid solve
		req.Header.Set("X-Cf-Solve-Time-Ms", "100")

		score := detector.ScoreRequest(req)
		if score < 0.3 {
			t.Errorf("expected bot-like request score >= 0.3, got %.2f", score)
		}
	})

	t.Run("score bounded at 1.0", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
		req.Header.Set("X-Cf-Solve-Time-Ms", "50")
		req.Header.Set("X-Forwarded-For", "10.0.0.1")
		req.Header.Set("X-Real-Ip", "10.0.0.1")
		req.Header.Set("Via", "1.1 proxy")

		score := detector.ScoreRequest(req)
		if score > 1.0 {
			t.Errorf("expected score <= 1.0, got %.2f", score)
		}
	})

	t.Run("empty signals score zero", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
		req.Header.Set("Accept", "text/html")
		req.Header.Set("Accept-Language", "en-US")
		req.AddCookie(&http.Cookie{Name: "__cf_bm", Value: "token"})
		req.AddCookie(&http.Cookie{Name: "cf_clearance", Value: "val"})

		score := detector.ScoreRequest(req)
		if score != 0.0 {
			t.Errorf("expected score 0.0 for request with no signals, got %.2f", score)
		}
	})
}

func TestDetectChallenge_TurnstileSiteKeyExtraction(t *testing.T) {
	headers := http.Header{}
	headers.Set("Server", "cloudflare")
	headers.Set("Cf-Ray", "test-ray")

	body := []byte(`<html>
		<body>
			<div class="cf-turnstile" data-sitekey="0x4AAAAAAADnPIDROrmt1Wwj"></div>
		</body>
	</html>`)

	challenge := DetectChallenge(403, headers, body)
	if challenge == nil {
		t.Fatal("expected challenge, got nil")
	}
	if challenge.SiteKey != "0x4AAAAAAADnPIDROrmt1Wwj" {
		t.Errorf("expected sitekey '0x4AAAAAAADnPIDROrmt1Wwj', got %q", challenge.SiteKey)
	}
}

// containsAll checks whether s contains all the given substrings.
func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !contains(s, sub) {
			return false
		}
	}
	return true
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && searchString(s, sub)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
