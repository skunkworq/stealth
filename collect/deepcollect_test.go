package collect

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// fakeSite is a URL-keyed renderer (keyed by canonicalURL) so multi-page
// traversal can be tested without network. Unmapped URLs error, which
// exercises the subpage skip-on-error path.
type fakeSite map[string]*RawPage

func (s fakeSite) Render(_ context.Context, rawURL string) (*RawPage, error) {
	if p, ok := s[canonicalURL(rawURL)]; ok {
		return p, nil
	}
	return nil, fmt.Errorf("fakeSite: no page for %q", rawURL)
}

func pg(html, final string) *RawPage { return &RawPage{HTML: []byte(html), FinalURL: final} }

func newDC(site fakeSite, maxPages int) *DeepCollector {
	dc := NewDeepCollector(site, maxPages)
	dc.c.now = func() time.Time { return time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) }
	return dc
}

func TestDeepCollectorFollowsContactAndAbout(t *testing.T) {
	home := `<html><body>
	  <a href="/about">About us</a>
	  <a href="/contact">Contact</a>
	  <a href="https://other.com/contact">external</a>
	</body></html>`
	site := fakeSite{
		"https://acme.com.au":         pg(home, "https://acme.com.au/"),
		"https://acme.com.au/contact": pg(`<html><body>contact</body></html>`, "https://acme.com.au/contact"),
		"https://acme.com.au/about":   pg(`<html><body>about</body></html>`, "https://acme.com.au/about"),
	}
	docs, pages, err := newDC(site, 3).Collect(context.Background(), "https://acme.com.au")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://acme.com.au/", "https://acme.com.au/contact", "https://acme.com.au/about"}
	if len(pages) != 3 {
		t.Fatalf("pages = %v, want 3", pages)
	}
	for i := range want {
		if pages[i] != want[i] {
			t.Errorf("pages[%d] = %q, want %q", i, pages[i], want[i])
		}
	}
	if len(docs) != 6 { // 3 pages × 2 views
		t.Errorf("docs = %d, want 6", len(docs))
	}
}

func TestDeepCollectorRespectsMaxPages(t *testing.T) {
	home := `<html><body>
	  <a href="/contact">Contact</a>
	  <a href="/about">About</a>
	  <a href="/services">Services</a>
	</body></html>`
	site := fakeSite{
		"https://acme.com.au":          pg(home, "https://acme.com.au/"),
		"https://acme.com.au/contact":  pg(`<p>c</p>`, "https://acme.com.au/contact"),
		"https://acme.com.au/about":    pg(`<p>a</p>`, "https://acme.com.au/about"),
		"https://acme.com.au/services": pg(`<p>s</p>`, "https://acme.com.au/services"),
	}
	_, pages, _ := newDC(site, 2).Collect(context.Background(), "https://acme.com.au")
	if len(pages) != 2 || pages[1] != "https://acme.com.au/contact" {
		t.Fatalf("pages = %v, want [home, /contact]", pages)
	}
}

func TestDeepCollectorSameDomainOnly(t *testing.T) {
	home := `<html><body><a href="https://other.com/contact">ext</a></body></html>`
	site := fakeSite{"https://acme.com.au": pg(home, "https://acme.com.au/")}
	_, pages, _ := newDC(site, 5).Collect(context.Background(), "https://acme.com.au")
	if len(pages) != 1 {
		t.Fatalf("pages = %v, want only homepage (external filtered)", pages)
	}
}

func TestDeepCollectorDedupesVisited(t *testing.T) {
	home := `<html><body>
	  <a href="/contact">Contact</a>
	  <a href="/contact#form">Contact form</a>
	  <a href="/contact/">Contact slash</a>
	  <a href="/">Home</a>
	</body></html>`
	site := fakeSite{
		"https://acme.com.au":         pg(home, "https://acme.com.au/"),
		"https://acme.com.au/contact": pg(`<p>c</p>`, "https://acme.com.au/contact"),
	}
	_, pages, _ := newDC(site, 10).Collect(context.Background(), "https://acme.com.au")
	if len(pages) != 2 {
		t.Fatalf("pages = %v, want [home, /contact] (variants + home deduped)", pages)
	}
}

func TestDeepCollectorSkipsSubpageError(t *testing.T) {
	home := `<html><body>
	  <a href="/contact">Contact</a>
	  <a href="/about">About</a>
	</body></html>`
	// /contact is referenced but absent from the site → Render errors.
	site := fakeSite{
		"https://acme.com.au":       pg(home, "https://acme.com.au/"),
		"https://acme.com.au/about": pg(`<p>a</p>`, "https://acme.com.au/about"),
	}
	_, pages, err := newDC(site, 3).Collect(context.Background(), "https://acme.com.au")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://acme.com.au/", "https://acme.com.au/about"}
	if len(pages) != 2 || pages[1] != want[1] {
		t.Fatalf("pages = %v, want %v (errored /contact skipped)", pages, want)
	}
}

func TestDeepCollectorHomepageErrorPropagates(t *testing.T) {
	docs, pages, err := newDC(fakeSite{}, 3).Collect(context.Background(), "https://acme.com.au")
	if err == nil {
		t.Fatal("expected error when homepage fetch fails")
	}
	if docs != nil || pages != nil {
		t.Errorf("want nil docs/pages on homepage error, got %v / %v", docs, pages)
	}
}

func TestRankLinks(t *testing.T) {
	html := `<html><body>
	  <a href="/services">Services</a>
	  <a href="/about-us">About</a>
	  <a href="/contact-us">Contact us</a>
	  <a href="/contact">Contact</a>
	  <a href="/blog">Blog</a>
	  <a href="https://other.com/contact">ext</a>
	</body></html>`
	got := rankLinks(html, "https://acme.com.au/")
	var order []string
	for _, l := range got {
		order = append(order, l.URL)
	}
	want := []string{
		"https://acme.com.au/contact-us", // 40
		"https://acme.com.au/contact",    // 30
		"https://acme.com.au/about-us",   // 20
		"https://acme.com.au/services",   // 10
	}
	if len(order) != len(want) {
		t.Fatalf("ranked = %v, want %v (blog score-0 + external dropped)", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Errorf("rank[%d] = %q, want %q", i, order[i], want[i])
		}
	}
}

func TestCanonicalURL(t *testing.T) {
	cases := map[string]string{
		"https://acme.com.au/contact#form": "https://acme.com.au/contact",
		"https://acme.com.au/contact/":     "https://acme.com.au/contact",
		"HTTPS://ACME.com.au/Contact":      "https://acme.com.au/Contact",
		"https://acme.com.au/":             "https://acme.com.au",
		"://not a url":                     "://not a url",
	}
	for in, want := range cases {
		if got := canonicalURL(in); got != want {
			t.Errorf("canonicalURL(%q) = %q, want %q", in, got, want)
		}
	}
}
