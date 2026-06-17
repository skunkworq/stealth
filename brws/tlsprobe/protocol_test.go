package tlsprobe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestDetectProtocol_HTTP2_HSTS_AltSvc starts an HTTP/2-capable TLS server
// that emits HSTS preload-eligible headers and an h3 Alt-Svc token, then
// asserts that DetectProtocol surfaces all three signals correctly.
func TestDetectProtocol_HTTP2_HSTS_AltSvc(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		w.Header().Set("Alt-Svc", `h3=":443"; ma=2592000`)
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewUnstartedServer(handler)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)

	host, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("splitting server addr: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	info, err := DetectProtocol(ctx, host, port)
	if err != nil {
		t.Fatalf("DetectProtocol: %v", err)
	}

	if info.HTTPVersion != "HTTP/2.0" {
		t.Errorf("HTTPVersion: want %q, got %q", "HTTP/2.0", info.HTTPVersion)
	}

	if info.ProtoMajor != 2 {
		t.Errorf("ProtoMajor: want 2, got %d", info.ProtoMajor)
	}

	if info.ALPN != "h2" {
		t.Errorf("ALPN: want %q, got %q", "h2", info.ALPN)
	}

	if !info.SupportsHTTP2 {
		t.Error("SupportsHTTP2: want true, got false")
	}

	if !info.SupportsHTTP3 {
		t.Error("SupportsHTTP3: want true, got false")
	}

	if info.HSTS == nil {
		t.Fatal("HSTS: want non-nil HSTSInfo, got nil")
	}

	if !info.HSTS.PreloadEligible {
		t.Errorf("HSTS.PreloadEligible: want true; got false (MaxAge=%d, IncludeSubDomains=%v, Preload=%v)",
			info.HSTS.MaxAge, info.HSTS.IncludeSubDomains, info.HSTS.Preload)
	}
}

// TestDetectProtocol_HTTP1Only starts a TLS server with HTTP/2 disabled and
// verifies that DetectProtocol reports ProtoMajor==1 and SupportsHTTP2==false.
func TestDetectProtocol_HTTP1Only(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// httptest.NewTLSServer does not enable HTTP/2 by default.
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)

	host, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("splitting server addr: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	info, err := DetectProtocol(ctx, host, port)
	if err != nil {
		t.Fatalf("DetectProtocol: %v", err)
	}

	if info.ProtoMajor != 1 {
		t.Errorf("ProtoMajor: want 1, got %d", info.ProtoMajor)
	}

	if info.SupportsHTTP2 {
		t.Error("SupportsHTTP2: want false, got true")
	}
}

// TestDetectProtocol_Unreachable verifies that DetectProtocol returns (nil,
// non-nil error) and does not panic when the target port is not listening.
func TestDetectProtocol_Unreachable(t *testing.T) {
	// Bind an ephemeral port then immediately close the listener so nothing is
	// listening when DetectProtocol dials.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	addr := ln.Addr().String()
	ln.Close()

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("splitting addr: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := DetectProtocol(ctx, host, port)
	if err == nil {
		t.Error("expected non-nil error for unreachable host, got nil")
	}

	if result != nil {
		t.Errorf("expected nil result for unreachable host, got %+v", result)
	}
}

// TestParseHSTS exercises the pure parseHSTS helper with a variety of header
// values to ensure correct directive parsing and preload eligibility logic.
func TestParseHSTS(t *testing.T) {
	tests := []struct {
		name           string
		header         string
		wantMaxAge     int
		wantIncludeSub bool
		wantPreload    bool
		wantEligible   bool
	}{
		{
			name:           "nil on empty",
			header:         "",
			wantMaxAge:     0,
			wantIncludeSub: false,
			wantPreload:    false,
			wantEligible:   false,
		},
		{
			name:           "max-age only",
			header:         "max-age=86400",
			wantMaxAge:     86400,
			wantIncludeSub: false,
			wantPreload:    false,
			wantEligible:   false,
		},
		{
			name:           "preload eligible",
			header:         "max-age=31536000; includeSubDomains; preload",
			wantMaxAge:     31536000,
			wantIncludeSub: true,
			wantPreload:    true,
			wantEligible:   true,
		},
		{
			name:           "preload ineligible: max-age too short",
			header:         "max-age=3600; includeSubDomains; preload",
			wantMaxAge:     3600,
			wantIncludeSub: true,
			wantPreload:    true,
			wantEligible:   false,
		},
		{
			name:           "preload ineligible: missing includeSubDomains",
			header:         "max-age=31536000; preload",
			wantMaxAge:     31536000,
			wantIncludeSub: false,
			wantPreload:    true,
			wantEligible:   false,
		},
		{
			name:           "preload ineligible: missing preload directive",
			header:         "max-age=31536000; includeSubDomains",
			wantMaxAge:     31536000,
			wantIncludeSub: true,
			wantPreload:    false,
			wantEligible:   false,
		},
		{
			name:           "case-insensitive directives",
			header:         "Max-Age=31536000; IncludeSubDomains; Preload",
			wantMaxAge:     31536000,
			wantIncludeSub: true,
			wantPreload:    true,
			wantEligible:   true,
		},
		{
			name:           "extra whitespace",
			header:         "  max-age=31536000 ;  includeSubDomains ;  preload  ",
			wantMaxAge:     31536000,
			wantIncludeSub: true,
			wantPreload:    true,
			wantEligible:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.header == "" {
				got := parseHSTS(tc.header)
				if got != nil {
					t.Errorf("parseHSTS(%q): want nil, got %+v", tc.header, got)
				}

				return
			}

			got := parseHSTS(tc.header)
			if got == nil {
				t.Fatalf("parseHSTS(%q): want non-nil HSTSInfo, got nil", tc.header)
			}

			if got.MaxAge != tc.wantMaxAge {
				t.Errorf("MaxAge: want %d, got %d", tc.wantMaxAge, got.MaxAge)
			}

			if got.IncludeSubDomains != tc.wantIncludeSub {
				t.Errorf("IncludeSubDomains: want %v, got %v", tc.wantIncludeSub, got.IncludeSubDomains)
			}

			if got.Preload != tc.wantPreload {
				t.Errorf("Preload: want %v, got %v", tc.wantPreload, got.Preload)
			}

			if got.PreloadEligible != tc.wantEligible {
				t.Errorf("PreloadEligible: want %v, got %v", tc.wantEligible, got.PreloadEligible)
			}

			if got.RawHeader != tc.header {
				t.Errorf("RawHeader: want %q, got %q", tc.header, got.RawHeader)
			}
		})
	}
}

// TestParseAltSvc exercises the pure parseAltSvc helper with various Alt-Svc
// header values including h3, h3-29, other protocols, and edge cases.
func TestParseAltSvc(t *testing.T) {
	tests := []struct {
		name          string
		header        string
		wantH3        bool
		wantEndpoints []string
	}{
		{
			name:          "empty header",
			header:        "",
			wantH3:        false,
			wantEndpoints: nil,
		},
		{
			name:          "h3 only",
			header:        `h3=":443"; ma=2592000`,
			wantH3:        true,
			wantEndpoints: []string{":443"},
		},
		{
			name:          "h3 and h3-29",
			header:        `h3=":443"; ma=2592000, h3-29=":443"; ma=2592000`,
			wantH3:        true,
			wantEndpoints: []string{":443", ":443"},
		},
		{
			name:          "h3 with non-standard port",
			header:        `h3="example.com:8443"`,
			wantH3:        true,
			wantEndpoints: []string{"example.com:8443"},
		},
		{
			name:          "non-h3 protocol only",
			header:        `h2=":443"`,
			wantH3:        false,
			wantEndpoints: nil,
		},
		{
			name:          "mixed h3 and non-h3",
			header:        `h2=":443", h3=":443"; ma=86400`,
			wantH3:        true,
			wantEndpoints: []string{":443"},
		},
		{
			name:          "clear directive (no h3)",
			header:        "clear",
			wantH3:        false,
			wantEndpoints: nil,
		},
		{
			name:          "no h3 in header",
			header:        `h2=":443"; ma=3600`,
			wantH3:        false,
			wantEndpoints: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotH3, gotEndpoints := parseAltSvc(tc.header)

			if gotH3 != tc.wantH3 {
				t.Errorf("supportsH3: want %v, got %v", tc.wantH3, gotH3)
			}

			if len(gotEndpoints) != len(tc.wantEndpoints) {
				t.Errorf("endpoints length: want %d, got %d (endpoints: %v)",
					len(tc.wantEndpoints), len(gotEndpoints), gotEndpoints)
				return
			}

			for i, want := range tc.wantEndpoints {
				if gotEndpoints[i] != want {
					t.Errorf("endpoints[%d]: want %q, got %q", i, want, gotEndpoints[i])
				}
			}
		})
	}
}
