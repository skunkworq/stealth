package stealth_test

import (
	"testing"

	"github.com/skunkworq/stealth/brws/content/understand"
	"github.com/skunkworq/stealth/brws/stealth"
)

const testHTML = `<!DOCTYPE html>
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
    <meta property="og:image" content="https://acme.com/og-image.png">
    <meta property="og:url" content="https://acme.com/">
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:title" content="Acme Corp">
    <meta name="twitter:image" content="https://acme.com/twitter-card.png">
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
        <a href="/products">Products</a>
        <a href="https://blog.acme.com/news">Blog</a>
    </nav>
    <main>
        <img src="/images/hero.jpg" alt="Hero">
        <img src="https://acme.com/images/product.png" alt="Product">
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

func TestResponse_Title(t *testing.T) {
	r := &stealth.Response{Body: []byte(testHTML), FinalURL: "https://acme.com/"}
	title := r.Title()
	if title != "Acme Corp - Building the Future" {
		t.Errorf("expected 'Acme Corp - Building the Future', got %q", title)
	}
}

func TestResponse_TitleFallbackOG(t *testing.T) {
	html := `<html><head><meta property="og:title" content="OG Title Only"></head><body></body></html>`
	r := &stealth.Response{Body: []byte(html)}
	title := r.Title()
	if title != "OG Title Only" {
		t.Errorf("expected 'OG Title Only', got %q", title)
	}
}

func TestResponse_TitleEmpty(t *testing.T) {
	r := &stealth.Response{Body: []byte{}}
	title := r.Title()
	if title != "" {
		t.Errorf("expected empty title, got %q", title)
	}
}

func TestResponse_Meta(t *testing.T) {
	r := &stealth.Response{Body: []byte(testHTML), FinalURL: "https://acme.com/"}
	meta := r.Meta()

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

func TestResponse_Links(t *testing.T) {
	r := &stealth.Response{Body: []byte(testHTML), FinalURL: "https://acme.com/"}
	links := r.Links()

	if len(links) == 0 {
		t.Fatal("expected links, got none")
	}

	// Check relative URL resolution
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
}

func TestResponse_LinksDedup(t *testing.T) {
	html := `<html><body>
		<a href="https://acme.com/page">Link 1</a>
		<a href="https://acme.com/page">Link 2</a>
		<a href="https://acme.com/page#section">Link 3</a>
	</body></html>`
	r := &stealth.Response{Body: []byte(html), FinalURL: "https://acme.com/"}
	links := r.Links()
	if len(links) != 1 {
		t.Errorf("expected 1 deduplicated link, got %d", len(links))
	}
}

func TestResponse_Images(t *testing.T) {
	r := &stealth.Response{Body: []byte(testHTML), FinalURL: "https://acme.com/"}
	images := r.Images()

	if len(images) < 3 {
		t.Fatalf("expected at least 3 images (2 img + og:image), got %d: %v", len(images), images)
	}

	// Should include resolved relative URL
	found := map[string]bool{}
	for _, img := range images {
		found[img] = true
	}
	if !found["https://acme.com/images/hero.jpg"] {
		t.Error("hero image not found or not resolved")
	}
	if !found["https://acme.com/og-image.png"] {
		t.Error("og:image not found")
	}
	if !found["https://acme.com/twitter-card.png"] {
		t.Error("twitter:image not found")
	}
}

func TestResponse_SocialLinks(t *testing.T) {
	r := &stealth.Response{Body: []byte(testHTML), FinalURL: "https://acme.com/"}
	social := r.SocialLinks()

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

func TestResponse_SocialLinksXDotCom(t *testing.T) {
	html := `<html><body>
		<a href="https://x.com/acmecorp">Follow us on X</a>
	</body></html>`
	r := &stealth.Response{Body: []byte(html)}
	social := r.SocialLinks()
	if social.Twitter != "https://x.com/acmecorp" {
		t.Errorf("expected x.com recognized as twitter, got %q", social.Twitter)
	}
}

func TestResponse_Colors(t *testing.T) {
	r := &stealth.Response{Body: []byte(testHTML), FinalURL: "https://acme.com/"}
	colors := r.Colors()

	if len(colors) == 0 {
		t.Fatal("expected colors, got none")
	}

	found := map[string]bool{}
	for _, c := range colors {
		found[c.Hex] = true
	}
	// theme-color: #4a90d9
	if !found["#4a90d9"] {
		t.Error("theme-color #4a90d9 not found")
	}
	// CSS color: #2b5797
	if !found["#2b5797"] {
		t.Error("CSS color #2b5797 not found")
	}
	// rgb(220, 50, 47) -> #dc322f
	if !found["#dc322f"] {
		t.Errorf("rgb color #dc322f not found, colors: %v", colors)
	}
	// #f5f5f5 should be filtered as common gray? No, it's not in the common list.
	// #000000 / #ffffff should be filtered if present
	if found["#000000"] || found["#ffffff"] {
		t.Error("common colors should be filtered")
	}
}

func TestResponse_Fonts(t *testing.T) {
	r := &stealth.Response{Body: []byte(testHTML), FinalURL: "https://acme.com/"}
	fonts := r.Fonts()

	if len(fonts) == 0 {
		t.Fatal("expected fonts, got none")
	}

	found := map[string]stealth.FontInfo{}
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

func TestResponse_FontsFiltersGeneric(t *testing.T) {
	html := `<html><head><style>body { font-family: sans-serif; } h1 { font-family: system-ui; }</style></head><body></body></html>`
	r := &stealth.Response{Body: []byte(html)}
	fonts := r.Fonts()
	if len(fonts) != 0 {
		t.Errorf("expected no fonts (all generic), got %d: %v", len(fonts), fonts)
	}
}

func TestResponse_EmptyBody(t *testing.T) {
	r := &stealth.Response{Body: nil}

	if title := r.Title(); title != "" {
		t.Errorf("title: got %q", title)
	}
	if meta := r.Meta(); meta.Description != "" {
		t.Errorf("meta description: got %q", meta.Description)
	}
	if links := r.Links(); links != nil {
		t.Errorf("links: got %v", links)
	}
	if images := r.Images(); images != nil {
		t.Errorf("images: got %v", images)
	}
	social := r.SocialLinks()
	if social.LinkedIn != "" || social.Twitter != "" {
		t.Errorf("social: got %+v", social)
	}
	if colors := r.Colors(); colors != nil {
		t.Errorf("colors: got %v", colors)
	}
	if fonts := r.Fonts(); fonts != nil {
		t.Errorf("fonts: got %v", fonts)
	}
}

func TestResponse_NonHTML(t *testing.T) {
	jsonBody := `{"status":"ok","data":{"count":42}}`
	r := &stealth.Response{Body: []byte(jsonBody)}

	// All methods should return zero values gracefully
	if title := r.Title(); title != "" {
		t.Errorf("title: got %q", title)
	}
	if links := r.Links(); links != nil {
		t.Errorf("links: got %v", links)
	}
	social := r.SocialLinks()
	if social.LinkedIn != "" {
		t.Errorf("social: got %+v", social)
	}
}

func TestResponse_Meta_DelegatesToTree(t *testing.T) {
	tree := &understand.SemanticTree{
		Meta: &understand.PageMeta{
			Title:       "Tree Title",
			Description: "Tree Description",
			Author:      "Tree Author",
			Language:    "fr",
			Keywords:    []string{"tree", "test"},
			OG:          map[string]string{"title": "OG from tree"},
			TwitterCard: map[string]string{"card": "summary"},
		},
		Social: &understand.SocialLinks{
			LinkedIn: "https://linkedin.com/company/tree",
			Twitter:  "https://twitter.com/tree",
		},
		Links: []understand.Link{
			{URL: "https://tree.com/link", Text: "Tree Link", IsExternal: true},
		},
		Colors: []understand.ColorInfo{
			{Hex: "#aabbcc", Source: "meta"},
		},
		Fonts: []understand.FontInfo{
			{Family: "Tree Font", Source: "google-fonts"},
		},
	}

	r := &stealth.Response{Body: []byte(testHTML), FinalURL: "https://acme.com/"}
	r.AttachSemanticTree(tree)

	// Title delegates to tree.
	if title := r.Title(); title != "Tree Title" {
		t.Errorf("Title: expected 'Tree Title', got %q", title)
	}

	// Meta delegates to tree.
	meta := r.Meta()
	if meta.Description != "Tree Description" {
		t.Errorf("Meta.Description: got %q", meta.Description)
	}
	if meta.Author != "Tree Author" {
		t.Errorf("Meta.Author: got %q", meta.Author)
	}

	// Links delegates to tree.
	links := r.Links()
	if len(links) != 1 || links[0].URL != "https://tree.com/link" {
		t.Errorf("Links: got %v", links)
	}

	// SocialLinks delegates to tree.
	social := r.SocialLinks()
	if social.LinkedIn != "https://linkedin.com/company/tree" {
		t.Errorf("Social.LinkedIn: got %q", social.LinkedIn)
	}

	// Colors delegates to tree.
	colors := r.Colors()
	if len(colors) != 1 || colors[0].Hex != "#aabbcc" {
		t.Errorf("Colors: got %v", colors)
	}

	// Fonts delegates to tree.
	fonts := r.Fonts()
	if len(fonts) != 1 || fonts[0].Family != "Tree Font" {
		t.Errorf("Fonts: got %v", fonts)
	}
}

func TestResponse_ImagesWithContext_CustomerSection(t *testing.T) {
	html := `<!DOCTYPE html><html><body>
	<header>
		<a href="/"><img src="/logo.svg" alt="Acme Logo" class="brand-logo" id="site-logo"></a>
	</header>
	<section class="customer-logos">
		<h2>Trusted by leading companies</h2>
		<div class="logo-grid">
			<a href="/customers/figma"><img src="https://cdn.acme.com/logos/figma.svg" alt="Figma"></a>
			<a href="/customers/notion"><img src="https://cdn.acme.com/logos/notion.png" alt="Notion"></a>
		</div>
	</section>
	<section class="partners_showcase__abc123">
		<h3>Our Partners</h3>
		<img src="/images/partner-aws.png" alt="AWS">
	</section>
	</body></html>`

	r := &stealth.Response{Body: []byte(html), FinalURL: "https://acme.com"}
	imgs := r.ImagesWithContext()

	if len(imgs) != 4 {
		t.Fatalf("expected 4 images, got %d", len(imgs))
	}

	// Find images by alt text.
	byAlt := map[string]stealth.ImageWithContext{}
	for _, img := range imgs {
		byAlt[img.Alt] = img
	}

	// Brand logo — no section tag.
	logo := byAlt["Acme Logo"]
	if logo.SectionTag != "" {
		t.Errorf("brand logo should have empty section tag, got %q", logo.SectionTag)
	}
	if logo.Classes != "brand-logo" {
		t.Errorf("brand logo classes: got %q", logo.Classes)
	}
	if logo.ID != "site-logo" {
		t.Errorf("brand logo id: got %q", logo.ID)
	}

	// Customer logos — should be classified.
	figma := byAlt["Figma"]
	if figma.SectionTag != "customer-logos" {
		t.Errorf("Figma section tag: got %q", figma.SectionTag)
	}
	if figma.ParentHref != "/customers/figma" {
		t.Errorf("Figma parent href: got %q", figma.ParentHref)
	}
	if figma.NearestHeading == "" {
		t.Error("Figma should have a nearest heading")
	}

	notion := byAlt["Notion"]
	if notion.SectionTag != "customer-logos" {
		t.Errorf("Notion section tag: got %q", notion.SectionTag)
	}

	// Partner logo — should be classified (CSS Modules class prefix).
	aws := byAlt["AWS"]
	if aws.SectionTag != "partner-logos" {
		t.Errorf("AWS section tag: got %q, want 'partner-logos'", aws.SectionTag)
	}
}

func TestResponse_ImagesWithContext_CSSModules(t *testing.T) {
	// Test CSS Modules mangled class names (e.g. Linear uses socialProof_container__xyz).
	html := `<!DOCTYPE html><html><body>
	<div class="socialProof_container__abc123">
		<div class="socialProof_grid__def456">
			<img src="/img1.png" alt="Customer1">
			<img src="/img2.png" alt="Customer2">
		</div>
	</div>
	</body></html>`

	r := &stealth.Response{Body: []byte(html), FinalURL: "https://example.com"}
	imgs := r.ImagesWithContext()

	if len(imgs) != 2 {
		t.Fatalf("expected 2 images, got %d", len(imgs))
	}
	for _, img := range imgs {
		if img.SectionTag != "customer-logos" {
			t.Errorf("img %q: expected 'customer-logos', got %q", img.Alt, img.SectionTag)
		}
	}
}

func TestResponse_ImagesWithContext_DataAttributes(t *testing.T) {
	html := `<!DOCTYPE html><html><body>
	<div data-analytics-name="SocialProofSection">
		<img src="/proof1.png" alt="Proof1">
	</div>
	<div data-testid="customer-logos-grid">
		<img src="/proof2.png" alt="Proof2">
	</div>
	</body></html>`

	r := &stealth.Response{Body: []byte(html), FinalURL: "https://example.com"}
	imgs := r.ImagesWithContext()

	if len(imgs) != 2 {
		t.Fatalf("expected 2 images, got %d", len(imgs))
	}
	for _, img := range imgs {
		if img.SectionTag != "customer-logos" {
			t.Errorf("img %q: expected 'customer-logos', got %q", img.Alt, img.SectionTag)
		}
	}
}

func TestResponse_ImagesWithContext_EmptyBody(t *testing.T) {
	r := &stealth.Response{Body: nil}
	imgs := r.ImagesWithContext()
	if imgs != nil {
		t.Errorf("expected nil for empty body, got %v", imgs)
	}
}

func TestResponse_ImagesWithContext_NoCustomerSection(t *testing.T) {
	html := `<!DOCTYPE html><html><body>
	<main>
		<img src="/hero.jpg" alt="Hero">
		<img src="/product.png" alt="Product">
	</main>
	</body></html>`

	r := &stealth.Response{Body: []byte(html), FinalURL: "https://example.com"}
	imgs := r.ImagesWithContext()

	if len(imgs) != 2 {
		t.Fatalf("expected 2 images, got %d", len(imgs))
	}
	for _, img := range imgs {
		if img.SectionTag != "" {
			t.Errorf("img %q: expected empty section tag, got %q", img.Alt, img.SectionTag)
		}
	}
}

// TestResponse_LazyParsing is omitted in the black-box test package because it
// checks unexported fields (doc, bodyStr) that are not accessible from outside
// the stealth package.

func TestResponse_Meta_FallsBackWhenNoTree(t *testing.T) {
	// No tree attached — should fall back to regex extraction.
	r := &stealth.Response{Body: []byte(testHTML), FinalURL: "https://acme.com/"}

	if title := r.Title(); title != "Acme Corp - Building the Future" {
		t.Errorf("Title fallback: got %q", title)
	}

	meta := r.Meta()
	if meta.Description != "Acme Corp builds innovative software solutions." {
		t.Errorf("Meta.Description fallback: got %q", meta.Description)
	}

	links := r.Links()
	if len(links) == 0 {
		t.Error("Links fallback: expected links")
	}

	social := r.SocialLinks()
	if social.LinkedIn != "https://linkedin.com/company/acme-corp" {
		t.Errorf("Social fallback: got %q", social.LinkedIn)
	}

	colors := r.Colors()
	if len(colors) == 0 {
		t.Error("Colors fallback: expected colors")
	}

	fonts := r.Fonts()
	if len(fonts) == 0 {
		t.Error("Fonts fallback: expected fonts")
	}
}
