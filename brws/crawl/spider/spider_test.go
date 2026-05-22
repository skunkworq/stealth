package spider

import (
	"net/url"
	"strings"
	"testing"
)

// TestNewSpider_ParseCallback verifies that the parse callback is called with
// the response and that returned requests are forwarded correctly.
func TestNewSpider_ParseCallback(t *testing.T) {
	startURL := "https://example.com/"
	start := []*Request{NewRequest(startURL, nil)}

	called := false
	var gotResp Response
	parse := func(resp Response) []*Request {
		called = true
		gotResp = resp
		return []*Request{NewRequest("https://example.com/next", nil)}
	}

	sp := NewSpider("test-spider", start, parse)

	if sp.Name() != "test-spider" {
		t.Errorf("expected name %q, got %q", "test-spider", sp.Name())
	}
	if len(sp.Start()) != 1 || sp.Start()[0].URL != startURL {
		t.Errorf("expected start URL %q", startURL)
	}

	resp := Response{URL: startURL, Status: 200, Text: "<html/>"}
	reqs := sp.Parse(resp)

	if !called {
		t.Error("expected parse callback to be called")
	}
	if gotResp.URL != startURL {
		t.Errorf("expected resp.URL=%q, got %q", startURL, gotResp.URL)
	}
	if len(reqs) != 1 || reqs[0].URL != "https://example.com/next" {
		t.Errorf("unexpected parse output: %v", reqs)
	}
}

// TestNewSpider_NilParse verifies that a nil parse callback returns nil safely.
func TestNewSpider_NilParse(t *testing.T) {
	sp := NewSpider("noop", nil, nil)
	reqs := sp.Parse(Response{URL: "https://example.com/", Status: 200})
	if reqs != nil {
		t.Errorf("expected nil from nil parse, got %v", reqs)
	}
}

// TestNewFormRequest_BodyEncoding verifies that form fields are URL-encoded
// and the correct method and Content-Type are set.
func TestNewFormRequest_BodyEncoding(t *testing.T) {
	formData := map[string]string{
		"username": "alice",
		"password": "s3cr3t!",
	}
	req := NewFormRequest("https://example.com/login", formData, nil)

	if req.Method != "POST" {
		t.Errorf("expected method POST, got %s", req.Method)
	}
	if req.Headers["Content-Type"] != "application/x-www-form-urlencoded" {
		t.Errorf("expected Content-Type application/x-www-form-urlencoded, got %q", req.Headers["Content-Type"])
	}
	if req.URL != "https://example.com/login" {
		t.Errorf("expected URL https://example.com/login, got %s", req.URL)
	}

	body := string(req.Body)
	// Parse body as URL-encoded form and verify fields
	vals, err := url.ParseQuery(body)
	if err != nil {
		t.Fatalf("failed to parse form body: %v", err)
	}
	if vals.Get("username") != "alice" {
		t.Errorf("expected username=alice, got %q", vals.Get("username"))
	}
	if vals.Get("password") != "s3cr3t!" {
		t.Errorf("expected password=s3cr3t!, got %q", vals.Get("password"))
	}
}

// TestGetLinks_HTMLFixture verifies that GetLinks extracts href values from all
// anchor tags in an HTML document.
func TestGetLinks_HTMLFixture(t *testing.T) {
	html := `<html><body>
		<a href="https://example.com/page1">Page 1</a>
		<a href="/relative/path">Relative</a>
		<a href="https://other.com/ext">External</a>
		<p>No link here</p>
	</body></html>`

	resp := Response{
		Text:   html,
		Status: 200,
		URL:    "https://example.com/",
	}

	links := resp.GetLinks()

	if len(links) != 3 {
		t.Errorf("expected 3 links, got %d: %v", len(links), links)
	}

	wantLinks := map[string]bool{
		"https://example.com/page1": true,
		"/relative/path":            true,
		"https://other.com/ext":     true,
	}
	for _, l := range links {
		if !wantLinks[l] {
			t.Errorf("unexpected link %q", l)
		}
	}
}

// TestGetLinks_NoAnchors verifies that an HTML page without anchor tags returns
// an empty (nil) slice without panicking.
func TestGetLinks_NoAnchors(t *testing.T) {
	resp := Response{Text: "<html><body><p>No links</p></body></html>", Status: 200}
	links := resp.GetLinks()
	if len(links) != 0 {
		t.Errorf("expected no links, got %v", links)
	}
}

// TestGetTitle_HTMLFixture verifies that GetTitle extracts the <title> text.
func TestGetTitle_HTMLFixture(t *testing.T) {
	resp := Response{
		Text:   "<html><head><title>My Page</title></head><body/></html>",
		Status: 200,
	}
	if got := resp.GetTitle(); got != "My Page" {
		t.Errorf("expected title %q, got %q", "My Page", got)
	}
}

// TestNewFormRequest_SpecialChars verifies that special characters in form
// values are properly percent-encoded.
func TestNewFormRequest_SpecialChars(t *testing.T) {
	req := NewFormRequest("https://example.com/search", map[string]string{
		"q": "hello world & more",
	}, nil)

	body := string(req.Body)
	if !strings.Contains(body, "q=") {
		t.Errorf("expected q= in body, got %q", body)
	}
	vals, _ := url.ParseQuery(body)
	if vals.Get("q") != "hello world & more" {
		t.Errorf("expected decoded value %q, got %q", "hello world & more", vals.Get("q"))
	}
}
