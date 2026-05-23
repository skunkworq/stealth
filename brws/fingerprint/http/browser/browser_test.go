package browser_test

import (
	"strings"
	"testing"

	"github.com/skunkworq/stealth/brws/fingerprint/http/browser"
)

func TestBrowserType_String(t *testing.T) {
	tests := []struct {
		typ  browser.Type
		want string
	}{
		{browser.BrowserUnknown, "Unknown"},
		{browser.BrowserChrome, "Chrome"},
		{browser.BrowserFirefox, "Firefox"},
		{browser.BrowserSafari, "Safari"},
		{browser.BrowserEdge, "Edge"},
		{browser.BrowserOpera, "Opera"},
		{browser.BrowserBrave, "Brave"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.typ.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBrowserType_String_unknown(t *testing.T) {
	var unknown browser.Type = 999
	if unknown.String() != "Unknown" {
		t.Errorf("unknown type String() = %q, want Unknown", unknown.String())
	}
}

func TestDetectFromUA_Chrome(t *testing.T) {
	ua := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	got := browser.DetectFromUA(ua)
	if got != browser.BrowserChrome {
		t.Errorf("DetectFromUA(Chrome UA) = %v, want Chrome", got)
	}
}

func TestDetectFromUA_Firefox(t *testing.T) {
	ua := "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
	got := browser.DetectFromUA(ua)
	if got != browser.BrowserFirefox {
		t.Errorf("DetectFromUA(Firefox UA) = %v, want Firefox", got)
	}
}

func TestDetectFromUA_Safari(t *testing.T) {
	ua := "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
	got := browser.DetectFromUA(ua)
	if got != browser.BrowserSafari {
		t.Errorf("DetectFromUA(Safari UA) = %v, want Safari", got)
	}
}

func TestDetectFromUA_Edge(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
	got := browser.DetectFromUA(ua)
	if got != browser.BrowserEdge {
		t.Errorf("DetectFromUA(Edge UA) = %v, want Edge", got)
	}
}

func TestDetectFromUA_Opera(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0"
	got := browser.DetectFromUA(ua)
	if got != browser.BrowserOpera {
		t.Errorf("DetectFromUA(Opera UA) = %v, want Opera", got)
	}
}

func TestDetectFromUA_Brave(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 Brave/1.0"
	got := browser.DetectFromUA(ua)
	if got != browser.BrowserBrave {
		t.Errorf("DetectFromUA(Brave UA) = %v, want Brave", got)
	}
}

func TestDetectFromUA_GoClient(t *testing.T) {
	ua := "Go-http-client/1.1"
	got := browser.DetectFromUA(ua)
	if got != browser.BrowserUnknown {
		t.Errorf("DetectFromUA(Go UA) = %v, want Unknown", got)
	}
}

func TestDetectFromUA_empty(t *testing.T) {
	got := browser.DetectFromUA("")
	if got != browser.BrowserUnknown {
		t.Errorf("DetectFromUA('') = %v, want Unknown", got)
	}
}

func TestBrowserType_IsChrome(t *testing.T) {
	if !browser.BrowserChrome.IsChrome() {
		t.Error("Chrome.IsChrome() should be true")
	}
	if browser.BrowserFirefox.IsChrome() {
		t.Error("Firefox.IsChrome() should be false")
	}
	if browser.BrowserSafari.IsChrome() {
		t.Error("Safari.IsChrome() should be false")
	}
}

func TestBrowserType_IsWebKit(t *testing.T) {
	if !browser.BrowserSafari.IsWebKit() {
		t.Error("Safari.IsWebKit() should be true")
	}
	// Chrome-based browsers also return true (Blink is a WebKit fork)
	if !browser.BrowserChrome.IsWebKit() {
		t.Error("Chrome.IsWebKit() should be true (Blink/WebKit)")
	}
	if browser.BrowserFirefox.IsWebKit() {
		t.Error("Firefox.IsWebKit() should be false (Gecko engine)")
	}
}

func TestBrowserType_IsGecko(t *testing.T) {
	if !browser.BrowserFirefox.IsGecko() {
		t.Error("Firefox.IsGecko() should be true")
	}
	if browser.BrowserChrome.IsGecko() {
		t.Error("Chrome.IsGecko() should be false")
	}
}

func TestBrowserType_MatchesPlatform(t *testing.T) {
	tests := []struct {
		typ      browser.Type
		platform string
		want     bool
	}{
		{browser.BrowserChrome, "macOS", true},
		{browser.BrowserChrome, "Windows", true},
		{browser.BrowserSafari, "macOS", true},
		{browser.BrowserSafari, "Windows", false}, // Safari not on Windows
		{browser.BrowserFirefox, "Linux", true},
	}
	for _, tt := range tests {
		got := tt.typ.MatchesPlatform(tt.platform)
		if got != tt.want {
			t.Errorf("%v.MatchesPlatform(%q) = %v, want %v", tt.typ, tt.platform, got, tt.want)
		}
	}
}

func TestParse_Chrome(t *testing.T) {
	ua := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	info := browser.Parse(ua)
	if info == nil {
		t.Fatal("Parse returned nil")
	}
	if info.Type != browser.BrowserChrome {
		t.Errorf("Type = %v, want Chrome", info.Type)
	}
	if !strings.Contains(info.Version, "120") {
		t.Errorf("Version = %q, expected to contain '120'", info.Version)
	}
}

func TestParse_Firefox(t *testing.T) {
	ua := "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
	info := browser.Parse(ua)
	if info == nil {
		t.Fatal("Parse returned nil")
	}
	if info.Type != browser.BrowserFirefox {
		t.Errorf("Type = %v, want Firefox", info.Type)
	}
}

func TestParse_empty(t *testing.T) {
	info := browser.Parse("")
	if info == nil {
		t.Fatal("Parse returned nil for empty UA")
	}
	if info.Type != browser.BrowserUnknown {
		t.Errorf("Parse('').Type = %v, want Unknown", info.Type)
	}
}

func TestBrowserType_MatchesTLS_unknownJA4(t *testing.T) {
	got := browser.BrowserChrome.MatchesTLS("unknown-ja4-hash")
	// Should not panic - just return false for unknown JA4
	_ = got
}
