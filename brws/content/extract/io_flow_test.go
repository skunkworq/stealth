package extract

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIsURLVariants(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "https-domain", input: "https://example.com/a", want: true},
		{name: "http-localhost", input: "http://localhost:8080/x", want: true},
		{name: "https-ipv4", input: "https://127.0.0.1/path", want: true},
		{name: "missing-scheme", input: "example.com/path", want: false},
		{name: "bad-scheme", input: "ftp://example.com/file", want: false},
		{name: "host-without-dot", input: "https://example/path", want: false},
		{name: "contains-space", input: "https://example.com bad", want: false},
		{name: "empty", input: "", want: false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := IsURL(tc.input); got != tc.want {
				t.Fatalf("IsURL(%q)=%v want=%v", tc.input, got, tc.want)
			}
		})
	}
}

func TestDownloadTextFromURLSuccess(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("hello world"))
	}))
	defer server.Close()

	body, err := DownloadTextFromURL(context.Background(), server.URL, 2*time.Second)
	if err != nil {
		t.Fatalf("download failed: %v", err)
	}
	if body != "hello world" {
		t.Fatalf("unexpected body: %q", body)
	}
}

func TestDownloadTextFromURLRejectsBinaryContentType(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("not-image-bytes"))
	}))
	defer server.Close()

	_, err := DownloadTextFromURL(context.Background(), server.URL, 2*time.Second)
	if err == nil {
		t.Fatalf("expected content type rejection")
	}
	if !strings.Contains(err.Error(), "not text-based") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDownloadTextFromURLStatusError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	_, err := DownloadTextFromURL(context.Background(), server.URL, 2*time.Second)
	if err == nil {
		t.Fatalf("expected status error")
	}
	if !strings.Contains(err.Error(), "status 503") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExtractRawFetchesURLInputByDefault(t *testing.T) {
	t.Parallel()

	const pageText = "Alice Johnson is a software engineer at Acme Corp."
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(pageText))
	}))
	defer server.Close()

	model := newFakeExtractor(`{"extractions":[{"person":"Alice Johnson"}]}`)
	raw, err := ExtractRaw(
		context.Background(),
		server.URL,
		WithExamples(testExamples()...),
		WithModel(model),
		WithFetchTimeoutSeconds(2),
	)
	if err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	if raw.Text != pageText {
		t.Fatalf("expected fetched text, got: %q", raw.Text)
	}
	if len(model.calls) == 0 || len(model.calls[0]) == 0 {
		t.Fatalf("expected model to be called with prompt")
	}
	if !strings.Contains(model.calls[0][0], pageText) {
		t.Fatalf("expected prompt to include fetched text")
	}
}

func TestExtractRawTreatsURLAsLiteralWhenFetchDisabled(t *testing.T) {
	t.Parallel()

	const inputURL = "https://example.com/records/42"
	model := newFakeExtractor(`{"extractions":[{"person":"Alice"}]}`)
	raw, err := ExtractRaw(
		context.Background(),
		inputURL,
		WithExamples(testExamples()...),
		WithModel(model),
		WithFetchURLs(false),
	)
	if err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	if raw.Text != inputURL {
		t.Fatalf("expected literal URL input, got: %q", raw.Text)
	}
	if len(model.calls) == 0 || len(model.calls[0]) == 0 {
		t.Fatalf("expected model to be called with prompt")
	}
	if !strings.Contains(model.calls[0][0], inputURL) {
		t.Fatalf("expected prompt to include literal URL input")
	}
}
