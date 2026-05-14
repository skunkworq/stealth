package extract

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// IsURL reports whether text is a standalone http(s) URL.
func IsURL(text string) bool {
	text = strings.TrimSpace(text)
	if text == "" || strings.ContainsAny(text, " \n\t") {
		return false
	}

	u, err := url.Parse(text)
	if err != nil {
		return false
	}
	if u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return false
	}

	host := u.Hostname()
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	return strings.Contains(host, ".")
}

// DownloadTextFromURL downloads text content from URL.
func DownloadTextFromURL(ctx context.Context, rawURL string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "stealth-langextract/1.0")

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if contentType != "" {
		isText := strings.Contains(contentType, "text/") ||
			strings.Contains(contentType, "application/json") ||
			strings.Contains(contentType, "application/xml")
		if !isText {
			return "", fmt.Errorf("content type %q is not text-based", contentType)
		}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}
