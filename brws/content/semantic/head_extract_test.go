package semantic

import (
	"strings"
	"testing"

	"golang.org/x/net/html"
)

const testExtractHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <title>Acme Corp - Building the Future</title>
    <meta name="description" content="Acme Corp builds innovative software solutions.">
    <meta name="author" content="Jane Doe">
    <meta name="publisher" content="Acme Publishing">
    <meta name="keywords" content="software, innovation, cloud">
    <meta name="theme-color" content="#4a90d9">
    <meta property="og:title" content="Acme Corp">
    <meta property="og:description" content="Building the future of software.">
    <meta property="og:url" content="https://acme.com/">
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:title" content="Acme Corp">
    <link rel="canonical" href="https://acme.com/">
    <link href="https://fonts.googleapis.com/css?family=Inter:400,700|Playfair+Display:700" rel="stylesheet">
    <style>
        body { font-family: "Custom Font", sans-serif; color: #2b5797; background: #f5f5f5; }
        .accent { color: rgb(220, 50, 47); }
    </style>
</head>
<body>
    <nav>
        <a href="/">Home</a>
        <a href="/about">About Us</a>
        <a href="https://blog.acme.com/news">Blog</a>
    </nav>
    <main>
        <p>Welcome to Acme Corp.</p>
        <a href="https://example.com/partner" rel="nofollow">Partner Site</a>
    </main>
    <footer>
        <a href="https://linkedin.com/company/acme-corp">LinkedIn</a>
        <a href="https://twitter.com/acmecorp">Twitter</a>
        <a href="https://github.com/acme">GitHub</a>
        <a href="https://discord.gg/acme">Discord</a>
    </footer>
</body>
</html>`

func mustParse(t *testing.T, s string) *html.Node {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(s))
	if err != nil {
		t.Fatalf("failed to parse HTML: %v", err)
	}
	return doc
}

func TestExtractPageMeta(t *testing.T) {
	doc := mustParse(t, testExtractHTML)
	meta := ExtractPageMeta(doc, "https://acme.com/")

	if meta.Title != "Acme Corp - Building the Future" {
		t.Errorf("title: got %q", meta.Title)
	}
	if meta.Description != "Acme Corp builds innovative software solutions." {
		t.Errorf("description: got %q", meta.Description)
	}
	if meta.Author != "Jane Doe" {
		t.Errorf("author: got %q", meta.Author)
	}
	if meta.Publisher != "Acme Publishing" {
		t.Errorf("publisher: got %q", meta.Publisher)
	}
	if meta.CanonicalURL != "https://acme.com/" {
		t.Errorf("canonical: got %q", meta.CanonicalURL)
	}
	if meta.Language != "en" {
		t.Errorf("language: got %q", meta.Language)
	}
	if len(meta.Keywords) != 3 || meta.Keywords[0] != "software" {
		t.Errorf("keywords: got %v", meta.Keywords)
	}
	if meta.OG["title"] != "Acme Corp" {
		t.Errorf("og:title: got %q", meta.OG["title"])
	}
	if meta.OG["description"] != "Building the future of software." {
		t.Errorf("og:description: got %q", meta.OG["description"])
	}
	if meta.TwitterCard["card"] != "summary_large_image" {
		t.Errorf("twitter:card: got %q", meta.TwitterCard["card"])
	}
	if meta.TwitterCard["title"] != "Acme Corp" {
		t.Errorf("twitter:title: got %q", meta.TwitterCard["title"])
	}
}

func TestExtractPageMeta_NoHead(t *testing.T) {
	doc := mustParse(t, `<html><body><p>No head</p></body></html>`)
	meta := ExtractPageMeta(doc, "https://example.com/")

	if meta.Title != "" {
		t.Errorf("expected empty title, got %q", meta.Title)
	}
	if meta.Description != "" {
		t.Errorf("expected empty description, got %q", meta.Description)
	}
}

func TestExtractLinks(t *testing.T) {
	doc := mustParse(t, testExtractHTML)
	links := ExtractLinks(doc, "https://acme.com/")

	if len(links) == 0 {
		t.Fatal("expected links, got none")
	}

	var homeFound, externalFound, nofollowFound bool
	for _, l := range links {
		if l.URL == "https://acme.com/" && l.Text == "Home" {
			homeFound = true
		}
		if l.URL == "https://example.com/partner" {
			externalFound = true
			if !l.IsExternal {
				t.Error("partner link should be external")
			}
			if !l.IsNofollow {
				t.Error("partner link should be nofollow")
			}
			nofollowFound = true
		}
	}
	if !homeFound {
		t.Error("home link not found or not resolved")
	}
	if !externalFound {
		t.Error("external link not found")
	}
	if !nofollowFound {
		t.Error("nofollow link not found")
	}

	// Check dedup: no duplicate URLs.
	seen := make(map[string]bool)
	for _, l := range links {
		norm := normalizeURLFull(l.URL)
		if seen[norm] {
			t.Errorf("duplicate link URL: %s", l.URL)
		}
		seen[norm] = true
	}
}

func TestExtractSocialLinks(t *testing.T) {
	doc := mustParse(t, testExtractHTML)
	social := ExtractSocialLinks(doc)

	if social.LinkedIn != "https://linkedin.com/company/acme-corp" {
		t.Errorf("linkedin: got %q", social.LinkedIn)
	}
	if social.Twitter != "https://twitter.com/acmecorp" {
		t.Errorf("twitter: got %q", social.Twitter)
	}
	if social.GitHub != "https://github.com/acme" {
		t.Errorf("github: got %q", social.GitHub)
	}
	if social.Discord != "https://discord.gg/acme" {
		t.Errorf("discord: got %q", social.Discord)
	}
}

func TestExtractSocialLinks_XDotCom(t *testing.T) {
	doc := mustParse(t, `<html><body><a href="https://x.com/acmecorp">X</a></body></html>`)
	social := ExtractSocialLinks(doc)
	if social.Twitter != "https://x.com/acmecorp" {
		t.Errorf("expected x.com recognized as twitter, got %q", social.Twitter)
	}
}

func TestExtractColors(t *testing.T) {
	doc := mustParse(t, testExtractHTML)
	colors := ExtractColors(doc)

	if len(colors) == 0 {
		t.Fatal("expected colors, got none")
	}

	found := make(map[string]bool)
	for _, c := range colors {
		found[c.Hex] = true
	}

	if !found["#4a90d9"] {
		t.Error("theme-color #4a90d9 not found")
	}
	if !found["#2b5797"] {
		t.Error("CSS color #2b5797 not found")
	}
	if !found["#dc322f"] {
		t.Errorf("rgb color #dc322f not found, colors: %v", colors)
	}
	if found["#000000"] || found["#ffffff"] {
		t.Error("common colors should be filtered")
	}
}

func TestExtractFonts(t *testing.T) {
	doc := mustParse(t, testExtractHTML)
	fonts := ExtractFonts(doc)

	if len(fonts) == 0 {
		t.Fatal("expected fonts, got none")
	}

	found := make(map[string]FontInfo)
	for _, f := range fonts {
		found[f.Family] = f
	}

	if fi, ok := found["Inter"]; !ok {
		t.Error("Google Font 'Inter' not found")
	} else if fi.Source != "google-fonts" {
		t.Errorf("Inter source: got %q", fi.Source)
	}

	if fi, ok := found["Playfair Display"]; !ok {
		t.Error("Google Font 'Playfair Display' not found")
	} else if fi.Source != "google-fonts" {
		t.Errorf("Playfair Display source: got %q", fi.Source)
	}

	if _, ok := found["Custom Font"]; !ok {
		t.Error("CSS font 'Custom Font' not found")
	}
}

func TestExtractFonts_GoogleV2(t *testing.T) {
	htmlStr := `<html><head>
		<link href="https://fonts.googleapis.com/css2?family=Roboto+Slab:wght@400;700&family=Open+Sans:ital@0;1" rel="stylesheet">
	</head><body></body></html>`
	doc := mustParse(t, htmlStr)
	fonts := ExtractFonts(doc)

	found := make(map[string]FontInfo)
	for _, f := range fonts {
		found[f.Family] = f
	}
	if _, ok := found["Roboto Slab"]; !ok {
		t.Error("Google Fonts v2 'Roboto Slab' not found")
	}
	if _, ok := found["Open Sans"]; !ok {
		t.Error("Google Fonts v2 'Open Sans' not found")
	}
}

func TestExtractFonts_FiltersGenerics(t *testing.T) {
	htmlStr := `<html><head><style>body { font-family: sans-serif; } h1 { font-family: system-ui; }</style></head><body></body></html>`
	doc := mustParse(t, htmlStr)
	fonts := ExtractFonts(doc)
	if len(fonts) != 0 {
		t.Errorf("expected no fonts (all generic), got %d: %v", len(fonts), fonts)
	}
}

func TestExtractionBeforeClean(t *testing.T) {
	doc := mustParse(t, testExtractHTML)

	// Extract before cleaning.
	meta := ExtractPageMeta(doc, "https://acme.com/")
	social := ExtractSocialLinks(doc)
	colors := ExtractColors(doc)
	fonts := ExtractFonts(doc)

	// Clean mutates the doc (strips head, styles, scripts).
	_ = cleanHTMLNode(doc)

	// Verify extracted data survives the mutation.
	if meta.Title != "Acme Corp - Building the Future" {
		t.Errorf("meta title lost after clean: %q", meta.Title)
	}
	if social.LinkedIn != "https://linkedin.com/company/acme-corp" {
		t.Errorf("social linkedin lost after clean: %q", social.LinkedIn)
	}
	if len(colors) == 0 {
		t.Error("colors lost after clean")
	}
	if len(fonts) == 0 {
		t.Error("fonts lost after clean")
	}
}
