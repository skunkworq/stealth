package tlsprobe

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ProtocolInfo holds HTTP transport and protocol negotiation results for a host.
type ProtocolInfo struct {
	// HTTPVersion is the HTTP version string as reported by the server (e.g. "HTTP/2.0").
	HTTPVersion string `json:"http_version"`
	// ProtoMajor is the major HTTP version number (1 or 2).
	ProtoMajor int `json:"proto_major"`
	// ALPN is the TLS Application-Layer Protocol Negotiation value (e.g. "h2", "http/1.1").
	ALPN string `json:"alpn"`
	// SupportsHTTP2 is true when the server negotiated HTTP/2 or offered h2 via ALPN.
	SupportsHTTP2 bool `json:"supports_http2"`
	// SupportsHTTP3 is true when the server advertises HTTP/3 support via Alt-Svc.
	SupportsHTTP3 bool `json:"supports_http3"`
	// AltSvc is the raw value of the Alt-Svc response header, if present.
	AltSvc string `json:"alt_svc"`
	// HTTP3Endpoints lists the h3/h3-29 endpoints parsed from Alt-Svc.
	HTTP3Endpoints []string `json:"http3_endpoints"`
	// HTTPSRedirect describes whether the server issues an HTTPS redirect on plain HTTP port 80.
	// Nil when the HTTP redirect probe failed (non-fatal).
	HTTPSRedirect *RedirectInfo `json:"https_redirect,omitempty"`
	// HSTS holds parsed Strict-Transport-Security header details, if present.
	HSTS *HSTSInfo `json:"hsts,omitempty"`
}

// RedirectInfo describes an HTTP-to-HTTPS redirect probe result.
type RedirectInfo struct {
	// Detected is true when the server responded with a redirect status (3xx).
	Detected bool `json:"detected"`
	// StatusCode is the HTTP status code returned by the server.
	StatusCode int `json:"status_code"`
	// Location is the raw value of the Location header.
	Location string `json:"location"`
	// IsHTTPSTarget is true when Location parses to an https:// URL.
	IsHTTPSTarget bool `json:"is_https_target"`
}

// HSTSInfo holds parsed Strict-Transport-Security header details.
type HSTSInfo struct {
	// RawHeader is the verbatim Strict-Transport-Security header value.
	RawHeader string `json:"raw_header"`
	// MaxAge is the max-age directive in seconds.
	MaxAge int `json:"max_age"`
	// IncludeSubDomains is true when the includeSubDomains directive is present.
	IncludeSubDomains bool `json:"include_subdomains"`
	// Preload is true when the preload directive is present.
	Preload bool `json:"preload"`
	// PreloadEligible is true when all HSTS preload requirements are met:
	// MaxAge >= 31536000, IncludeSubDomains == true, and Preload == true.
	PreloadEligible bool `json:"preload_eligible"`
}

// DetectProtocol probes host:port over HTTPS to determine the HTTP version,
// ALPN, HTTP/3 support (via Alt-Svc), HSTS policy, and whether the server
// redirects plain HTTP requests to HTTPS (always probed on port 80).
//
// The HTTPS probe is required; if it fails the error is returned. The HTTP
// redirect probe is best-effort: a dial failure leaves HTTPSRedirect nil.
func DetectProtocol(ctx context.Context, host, port string) (*ProtocolInfo, error) {
	// ── HTTPS probe ──────────────────────────────────────────────────────────
	httpsTransport := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true, // #nosec G402 -- intentional inspect-only probe; we evaluate, not trust
		},
		ForceAttemptHTTP2: true,
	}

	httpsClient := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: httpsTransport,
	}

	targetURL := "https://" + host + ":" + port + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := httpsClient.Do(req)
	if err != nil {
		return nil, err
	}

	// Drain and close body; errors are not actionable here.
	_, _ = resp.Body.Read(make([]byte, 0)) // #nosec G104
	resp.Body.Close()                      // #nosec G104

	info := &ProtocolInfo{
		HTTPVersion: resp.Proto,
		ProtoMajor:  resp.ProtoMajor,
	}

	// Extract ALPN from TLS connection state.
	if resp.TLS != nil {
		info.ALPN = resp.TLS.NegotiatedProtocol
	}

	info.SupportsHTTP2 = info.ProtoMajor == 2 || info.ALPN == "h2"

	// Parse Alt-Svc for HTTP/3 support.
	altSvc := resp.Header.Get("Alt-Svc")
	info.AltSvc = altSvc
	if altSvc != "" {
		info.SupportsHTTP3, info.HTTP3Endpoints = parseAltSvc(altSvc)
	}

	// Parse HSTS header.
	if hsts := resp.Header.Get("Strict-Transport-Security"); hsts != "" {
		info.HSTS = parseHSTS(hsts)
	}

	// ── HTTP redirect probe (best-effort, always port 80) ────────────────────
	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	httpURL := "http://" + host + ":80/"
	httpReq, httpReqErr := http.NewRequestWithContext(ctx, http.MethodGet, httpURL, nil)
	if httpReqErr == nil {
		httpResp, httpErr := httpClient.Do(httpReq)
		if httpErr == nil {
			_, _ = httpResp.Body.Read(make([]byte, 0)) // #nosec G104
			httpResp.Body.Close()                      // #nosec G104

			location := httpResp.Header.Get("Location")
			isRedirect := isRedirectStatus(httpResp.StatusCode)
			isHTTPS := false

			if location != "" {
				if parsed, parseErr := url.Parse(location); parseErr == nil {
					isHTTPS = parsed.Scheme == "https"
				}
			}

			info.HTTPSRedirect = &RedirectInfo{
				Detected:      isRedirect,
				StatusCode:    httpResp.StatusCode,
				Location:      location,
				IsHTTPSTarget: isHTTPS,
			}
		}
		// dial/request failure → leave HTTPSRedirect nil (best-effort)
	}

	return info, nil
}

// isRedirectStatus reports whether the HTTP status code is a redirect (3xx
// that typically carries a Location header: 301, 302, 303, 307, 308).
func isRedirectStatus(code int) bool {
	switch code {
	case http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusSeeOther,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

// parseHSTS parses a Strict-Transport-Security header value into an HSTSInfo.
// Unrecognised directives are silently ignored per RFC 6797.
func parseHSTS(header string) *HSTSInfo {
	if header == "" {
		return nil
	}

	info := &HSTSInfo{RawHeader: header}

	for _, directive := range strings.Split(header, ";") {
		directive = strings.TrimSpace(directive)
		lower := strings.ToLower(directive)

		switch {
		case strings.HasPrefix(lower, "max-age="):
			val := strings.TrimPrefix(lower, "max-age=")
			if n, err := strconv.Atoi(val); err == nil {
				info.MaxAge = n
			}
		case lower == "includesubdomains":
			info.IncludeSubDomains = true
		case lower == "preload":
			info.Preload = true
		}
	}

	// Preload eligibility: max-age >= 1 year, includeSubDomains, and preload
	// directive all required per https://hstspreload.org.
	const minPreloadAge = 31536000
	info.PreloadEligible = info.MaxAge >= minPreloadAge && info.IncludeSubDomains && info.Preload

	return info
}

// parseAltSvc parses an Alt-Svc header value and returns whether HTTP/3 is
// advertised and the list of h3/h3-29 endpoint authority strings.
//
// Alt-Svc format (RFC 7838): comma-separated list of alt-authority tokens of
// the form protocol="host:port"; optional parameters follow each token.
// Example: h3=":443"; ma=2592000, h3-29=":443"; ma=2592000
func parseAltSvc(header string) (supportsH3 bool, endpoints []string) {
	if header == "" {
		return false, nil
	}

	lower := strings.ToLower(header)

	// Fast-path: check if any h3 token appears before doing expensive parsing.
	if !strings.Contains(lower, "h3") {
		return false, nil
	}

	// Split on commas to get individual alt-authority entries.
	// Each entry looks like: h3=":443"; ma=2592000
	for _, entry := range strings.Split(header, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		// The first token before any ";" is the protocol="authority" pair.
		parts := strings.SplitN(entry, ";", 2)
		token := strings.TrimSpace(parts[0])

		// Split token on "=" to get protocol name and quoted authority.
		eqIdx := strings.IndexByte(token, '=')
		if eqIdx < 0 {
			continue
		}

		proto := strings.ToLower(strings.TrimSpace(token[:eqIdx]))
		authority := strings.TrimSpace(token[eqIdx+1:])
		// Strip surrounding quotes from the authority.
		authority = strings.Trim(authority, `"`)

		if proto == "h3" || proto == "h3-29" {
			supportsH3 = true
			endpoints = append(endpoints, authority)
		}
	}

	return supportsH3, endpoints
}
