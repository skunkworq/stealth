package stealth

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"

	"github.com/skunkworq/stealth/brws/browser/engine"
	_ "github.com/skunkworq/stealth/brws/browser/engine/native"
)

// TestExampleCom_IsolateDetectionVector tests different combinations to find
// exactly what CF is keying on for example.com's challenge.
func TestExampleCom_IsolateDetectionVector(t *testing.T) {
	url := "https://example.com"

	tests := []struct {
		Name string
		Do   func(t *testing.T) (int, string, string) // returns status, body preview, proto
	}{
		{
			"1_bare_go_default",
			func(t *testing.T) (int, string, string) {
				resp, err := http.Get(url)
				if err != nil {
					skipExternalNetworkIssue(t, url, err)
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				return resp.StatusCode, extractTitle(string(body)), resp.Proto
			},
		},
		{
			"2_utls_chrome_no_headers",
			func(t *testing.T) (int, string, string) {
				// uTLS Chrome fingerprint but no stealth headers
				return doUTLSRequest(t, url, utls.HelloChrome_120, nil)
			},
		},
		{
			"3_utls_chrome_ua_only",
			func(t *testing.T) (int, string, string) {
				// uTLS Chrome + only User-Agent header
				headers := map[string]string{
					"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
				}
				return doUTLSRequest(t, url, utls.HelloChrome_120, headers)
			},
		},
		{
			"4_utls_chrome_minimal_browser_headers",
			func(t *testing.T) (int, string, string) {
				// uTLS Chrome + minimal browser headers (UA + Accept + Accept-Language)
				headers := map[string]string{
					"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
					"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
					"Accept-Language": "en-US,en;q=0.9",
				}
				return doUTLSRequest(t, url, utls.HelloChrome_120, headers)
			},
		},
		{
			"5_utls_chrome_full_browser_headers",
			func(t *testing.T) (int, string, string) {
				// uTLS Chrome + full stealth headers including Sec-Ch-Ua
				headers := map[string]string{
					"User-Agent":                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
					"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
					"Accept-Language":           "en-US,en;q=0.9",
					"Accept-Encoding":           "gzip, deflate, br",
					"Sec-Ch-Ua":                 `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`,
					"Sec-Ch-Ua-Mobile":          "?0",
					"Sec-Ch-Ua-Platform":        `"macOS"`,
					"Sec-Fetch-Dest":            "document",
					"Sec-Fetch-Mode":            "navigate",
					"Sec-Fetch-Site":            "none",
					"Sec-Fetch-User":            "?1",
					"Upgrade-Insecure-Requests": "1",
				}
				return doUTLSRequest(t, url, utls.HelloChrome_120, headers)
			},
		},
		{
			"6_utls_chrome_h2_settings_tuned",
			func(t *testing.T) (int, string, string) {
				// uTLS Chrome + Chrome-like HTTP/2 SETTINGS
				headers := map[string]string{
					"User-Agent":                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
					"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
					"Accept-Language":           "en-US,en;q=0.9",
					"Accept-Encoding":           "gzip, deflate, br",
					"Sec-Ch-Ua":                 `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`,
					"Sec-Ch-Ua-Mobile":          "?0",
					"Sec-Ch-Ua-Platform":        `"macOS"`,
					"Sec-Fetch-Dest":            "document",
					"Sec-Fetch-Mode":            "navigate",
					"Sec-Fetch-Site":            "none",
					"Sec-Fetch-User":            "?1",
					"Upgrade-Insecure-Requests": "1",
				}
				return doUTLSRequestWithH2Settings(t, url, utls.HelloChrome_120, headers)
			},
		},
		{
			"7_engine_stealth_tls_only",
			func(t *testing.T) (int, string, string) {
				// Engine with StealthTLS=true but Stealth=false (uTLS but no stealth headers)
				eng, err := engine.New("native", engine.Options{
					Timeout:     15 * time.Second,
					HTTP2:       true,
					Stealth:     false,
					StealthTLS:  true,
					ProfileName: "chrome-120-macos",
				})
				if err != nil {
					t.Fatalf("engine error: %v", err)
				}
				defer eng.Close()
				resp, err := eng.Do(context.Background(), &engine.Request{
					Method:  "GET",
					URL:     url,
					Timeout: 15 * time.Second,
				})
				if err != nil {
					skipExternalNetworkIssue(t, url, err)
				}
				return resp.Status, extractTitle(string(resp.Body)), resp.Protocol
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			status, title, proto := tt.Do(t)
			result := "PASS"
			if status == 403 {
				result = "CHALLENGED"
			} else if status != 200 {
				result = fmt.Sprintf("HTTP_%d", status)
			}
			t.Logf("%-40s status=%d %-12s proto=%-8s title=%q",
				tt.Name, status, result, proto, title)
		})
	}
}

// doUTLSRequest makes a request using uTLS with optional custom headers.
func doUTLSRequest(t *testing.T, targetURL string, fingerprint utls.ClientHelloID, headers map[string]string) (int, string, string) {
	t.Helper()

	// Dial TCP
	conn, err := net.DialTimeout("tcp", "example.com:443", 10*time.Second)
	if err != nil {
		skipExternalNetworkIssue(t, targetURL, err)
	}

	// uTLS handshake
	tlsConn := utls.UClient(conn, &utls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}, fingerprint)

	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		skipExternalNetworkIssue(t, targetURL, err)
	}

	negotiated := tlsConn.ConnectionState().NegotiatedProtocol

	if negotiated == "h2" {
		// HTTP/2
		h2t := &http2.Transport{}
		h2cc, err := h2t.NewClientConn(tlsConn)
		if err != nil {
			tlsConn.Close()
			skipExternalNetworkIssue(t, targetURL, err)
		}

		req, _ := http.NewRequest("GET", targetURL, nil)
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := h2cc.RoundTrip(req)
		if err != nil {
			skipExternalNetworkIssue(t, targetURL, err)
		}
		body := decompressBody(t, resp)
		resp.Body.Close()
		return resp.StatusCode, extractTitle(string(body)), "h2"
	}

	// HTTP/1.1 fallback
	t.Log("  (negotiated HTTP/1.1)")
	tlsConn.Close()
	return 0, "", "h1"
}

// doUTLSRequestWithH2Settings makes a request with Chrome-like HTTP/2 SETTINGS.
func doUTLSRequestWithH2Settings(t *testing.T, targetURL string, fingerprint utls.ClientHelloID, headers map[string]string) (int, string, string) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", "example.com:443", 10*time.Second)
	if err != nil {
		skipExternalNetworkIssue(t, targetURL, err)
	}

	tlsConn := utls.UClient(conn, &utls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}, fingerprint)

	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		skipExternalNetworkIssue(t, targetURL, err)
	}

	// HTTP/2 transport with Chrome-like settings
	h2t := &http2.Transport{
		// Chrome-like HTTP/2 settings
		MaxHeaderListSize:         262144,
		MaxDecoderHeaderTableSize: 65536,
		MaxReadFrameSize:          16384,
	}

	h2cc, err := h2t.NewClientConn(tlsConn)
	if err != nil {
		tlsConn.Close()
		skipExternalNetworkIssue(t, targetURL, err)
	}

	req, _ := http.NewRequest("GET", targetURL, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := h2cc.RoundTrip(req)
	if err != nil {
		skipExternalNetworkIssue(t, targetURL, err)
	}
	body := decompressBody(t, resp)
	resp.Body.Close()
	return resp.StatusCode, extractTitle(string(body)), "h2-tuned"
}

func decompressBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	encoding := strings.ToLower(resp.Header.Get("Content-Encoding"))
	var reader io.Reader = resp.Body

	switch encoding {
	case "gzip":
		gr, err := gzip.NewReader(resp.Body)
		if err != nil {
			body, _ := io.ReadAll(resp.Body)
			return body
		}
		defer gr.Close()
		reader = gr
	case "br":
		reader = brotli.NewReader(resp.Body)
	}

	body, _ := io.ReadAll(reader)
	return body
}

func extractTitle(body string) string {
	start := strings.Index(body, "<title>")
	if start == -1 {
		return "(no title)"
	}
	start += 7
	end := strings.Index(body[start:], "</title>")
	if end == -1 {
		return "(no closing title)"
	}
	return body[start : start+end]
}
