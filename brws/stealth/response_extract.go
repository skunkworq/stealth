package stealth

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/net/html"

	coretypes "github.com/skunkworq/stealth/brws/core/types"
)

// Type aliases exposing the core semantic types through the stealth package
// surface. These are the same types used by content/understand; both packages
// alias them from brws/core/types so no upward import is needed.
type (
	PageMeta         = coretypes.PageMeta
	SocialLinks      = coretypes.SocialLinks
	Link             = coretypes.Link
	ColorInfo        = coretypes.ColorInfo
	FontInfo         = coretypes.FontInfo
	ImageWithContext = coretypes.ImageWithContext
)

// AttachSemanticTree attaches a pre-built semantic tree to the response.
// When non-nil, extraction methods (Title, Meta, Links, etc.) delegate to
// the tree instead of re-parsing the raw HTML body.
// The tree must implement coretypes.SemanticPage; *understand.SemanticTree
// satisfies this interface.
func (r *Response) AttachSemanticTree(tree coretypes.SemanticPage) {
	r.semanticTree = tree
}

// --- Compiled regexes (package-level, compiled once) ---

// Title & metadata
var (
	reTitle       = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	reInlineTag   = regexp.MustCompile(`(?is)<[^>]+>`)
	reCanonical   = regexp.MustCompile(`(?i)<link[^>]*rel=["']canonical["'][^>]*href=["']([^"']+)["']`)
	reLang        = regexp.MustCompile(`(?i)<html[^>]*lang=["']([^"']+)["']`)
	reMetaNameVal = regexp.MustCompile(`(?is)<meta[^>]*name=["']([^"']+)["'][^>]*content=["']([^"']+)["'][^>]*>`)
	reMetaValName = regexp.MustCompile(`(?is)<meta[^>]*content=["']([^"']+)["'][^>]*name=["']([^"']+)["'][^>]*>`)
	reMetaPropVal = regexp.MustCompile(`(?is)<meta[^>]*property=["']([^"']+)["'][^>]*content=["']([^"']+)["'][^>]*>`)
	reMetaValProp = regexp.MustCompile(`(?is)<meta[^>]*content=["']([^"']+)["'][^>]*property=["']([^"']+)["'][^>]*>`)
)

// Links & images
var (
	reAnchor   = regexp.MustCompile(`(?is)<a[^>]*href=["']([^"']+)["'][^>]*>(.*?)</a>`)
	reImgSrc   = regexp.MustCompile(`(?i)<img[^>]*src=["']([^"']+)["']`)
	reNofollow = regexp.MustCompile(`(?i)rel=["'][^"']*nofollow[^"']*["']`)
)

// Social platform patterns
var socialPatterns = map[string]*regexp.Regexp{
	"linkedin":  regexp.MustCompile(`https?://(?:www\.)?linkedin\.com/(?:company|in)/[^"'\s]+`),
	"twitter":   regexp.MustCompile(`https?://(?:www\.)?(?:twitter\.com|x\.com)/[^"'\s]+`),
	"instagram": regexp.MustCompile(`https?://(?:www\.)?instagram\.com/[^"'\s]+`),
	"facebook":  regexp.MustCompile(`https?://(?:www\.)?facebook\.com/[^"'\s]+`),
	"youtube":   regexp.MustCompile(`https?://(?:www\.)?(?:youtube\.com|youtu\.be)/[^"'\s]+`),
	"github":    regexp.MustCompile(`https?://(?:www\.)?github\.com/[^"'\s]+`),
	"tiktok":    regexp.MustCompile(`https?://(?:www\.)?tiktok\.com/[^"'\s]+`),
	"pinterest": regexp.MustCompile(`https?://(?:www\.)?pinterest\.com/[^"'\s]+`),
	"discord":   regexp.MustCompile(`https?://(?:www\.)?discord\.(?:com|gg)/[^"'\s]+`),
}

// Colors
var (
	reThemeColor = regexp.MustCompile(`(?i)<meta[^>]*name=["']theme-color["'][^>]*content=["']([^"']+)["']`)
	reHexColor   = regexp.MustCompile(`#([0-9A-Fa-f]{3}){1,2}`)
	reRGBColor   = regexp.MustCompile(`rgba?\s*\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)`)
)

// Fonts
var (
	reGoogleFontsV1 = regexp.MustCompile(`fonts\.googleapis\.com/css\?family=([^"']+)`)
	reGoogleFontsV2 = regexp.MustCompile(`fonts\.googleapis\.com/css2\?family=([^"']+)`)
	reCSSFontFamily = regexp.MustCompile(`font-family\s*:\s*([^;]+)`)
)

// --- Lazy parser ---

func (r *Response) ensureParsed() {
	r.parseOnce.Do(func() {
		r.bodyStr = string(r.Body)
		doc, err := html.Parse(strings.NewReader(r.bodyStr))
		if err != nil {
			return
		}
		r.doc = doc
	})
}

// --- URL utilities (unexported) ---

func resolveURL(baseURL, ref string) string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return ref
	}
	refURL, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return base.ResolveReference(refURL).String()
}

func extractDomain(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func normalizeURL(urlStr string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}
	u.Fragment = ""
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	return u.String()
}

func shouldSkipHref(href string) bool {
	lower := strings.ToLower(strings.TrimSpace(href))
	for _, prefix := range []string{"#", "javascript:", "mailto:", "tel:", "data:"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// --- Helper functions ---

func cleanSocialURL(u string) string {
	u = strings.TrimRight(u, ".,;:!?')}\"")
	if strings.HasPrefix(u, "http://") {
		u = "https://" + u[7:]
	}
	return u
}

func normalizeHexColor(hex string) string {
	hex = strings.ToLower(strings.TrimSpace(hex))
	if len(hex) == 4 && hex[0] == '#' {
		return "#" + string(hex[1]) + string(hex[1]) +
			string(hex[2]) + string(hex[2]) +
			string(hex[3]) + string(hex[3])
	}
	return hex
}

func isCommonColor(hex string) bool {
	common := []string{
		"#000000", "#ffffff", "#000", "#fff",
		"#333333", "#666666", "#999999", "#cccccc",
		"#111111", "#222222", "#444444", "#555555",
		"#777777", "#888888", "#aaaaaa", "#bbbbbb",
		"#dddddd", "#eeeeee",
	}
	for _, c := range common {
		if strings.EqualFold(hex, c) {
			return true
		}
	}
	return false
}

func rgbToHex(r, g, b string) string {
	ri, _ := strconv.Atoi(strings.TrimSpace(r))
	gi, _ := strconv.Atoi(strings.TrimSpace(g))
	bi, _ := strconv.Atoi(strings.TrimSpace(b))
	return fmt.Sprintf("#%02x%02x%02x", ri, gi, bi)
}

func isGenericFont(font string) bool {
	generics := []string{
		"serif", "sans-serif", "monospace", "cursive", "fantasy",
		"system-ui", "ui-serif", "ui-sans-serif", "ui-monospace",
		"-apple-system", "blinkmacsystemfont", "segoe ui", "roboto",
		"helvetica", "arial", "noto sans", "ubuntu", "cantarell",
		"inherit", "unset", "initial", "revert", "normal", "none",
	}
	lower := strings.ToLower(font)
	for _, g := range generics {
		if lower == g {
			return true
		}
	}
	return false
}

func isValidFontFamily(font string) bool {
	clean := strings.TrimSpace(strings.ToLower(font))
	if clean == "" || len(clean) > 80 {
		return false
	}
	for _, snippet := range []string{"{", "}", "#", ";", ":", "url(", "var(", "@", "--"} {
		if strings.Contains(clean, snippet) {
			return false
		}
	}
	hasLetter := false
	for _, r := range clean {
		if unicode.IsLetter(r) {
			hasLetter = true
			break
		}
	}
	return hasLetter
}

func extractPrimaryFont(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Split(value, "!important")[0]
	value = strings.Trim(value, `"'`)

	parts := strings.Split(value, ",")
	for _, part := range parts {
		font := strings.TrimSpace(strings.Trim(part, `"'`))
		if font == "" || !isValidFontFamily(font) {
			continue
		}
		if !isGenericFont(font) {
			return font
		}
	}
	return ""
}

// --- Public extraction methods ---

// Title returns the page title, falling back to og:title.
func (r *Response) Title() string {
	if r.semanticTree != nil {
		if m := r.semanticTree.GetMeta(); m != nil {
			return m.Title
		}
	}
	r.ensureParsed()
	if r.bodyStr == "" {
		return ""
	}

	// Try <title> tag
	matches := reTitle.FindStringSubmatch(r.bodyStr)
	if len(matches) >= 2 {
		title := strings.TrimSpace(matches[1])
		if title != "" {
			// Strip inline tags
			title = reInlineTag.ReplaceAllString(title, " ")
			title = strings.Join(strings.Fields(strings.TrimSpace(title)), " ")
			return title
		}
	}

	// Fallback to og:title
	for _, match := range reMetaPropVal.FindAllStringSubmatch(r.bodyStr, -1) {
		if len(match) >= 3 && strings.EqualFold(match[1], "og:title") {
			return strings.TrimSpace(match[2])
		}
	}
	for _, match := range reMetaValProp.FindAllStringSubmatch(r.bodyStr, -1) {
		if len(match) >= 3 && strings.EqualFold(match[2], "og:title") {
			return strings.TrimSpace(match[1])
		}
	}

	return ""
}

// Meta returns structured page metadata including OG and Twitter Card tags.
func (r *Response) Meta() PageMeta {
	if r.semanticTree != nil {
		if m := r.semanticTree.GetMeta(); m != nil {
			return *m
		}
	}
	r.ensureParsed()
	meta := PageMeta{
		OG:          make(map[string]string),
		TwitterCard: make(map[string]string),
	}
	if r.bodyStr == "" {
		return meta
	}

	meta.Title = r.Title()

	// Collect meta name=X content=Y
	for _, match := range reMetaNameVal.FindAllStringSubmatch(r.bodyStr, -1) {
		if len(match) < 3 {
			continue
		}
		name, content := strings.ToLower(match[1]), strings.TrimSpace(match[2])
		switch name {
		case "description":
			if meta.Description == "" {
				meta.Description = content
			}
		case "author":
			meta.Author = content
		case "publisher":
			meta.Publisher = content
		case "keywords":
			meta.Keywords = parseKeywords(content)
		}
		if strings.HasPrefix(name, "twitter:") {
			meta.TwitterCard[strings.TrimPrefix(name, "twitter:")] = content
		}
	}

	// Collect meta content=X name=Y (reversed attr order)
	for _, match := range reMetaValName.FindAllStringSubmatch(r.bodyStr, -1) {
		if len(match) < 3 {
			continue
		}
		content, name := strings.TrimSpace(match[1]), strings.ToLower(match[2])
		switch name {
		case "description":
			if meta.Description == "" {
				meta.Description = content
			}
		case "author":
			if meta.Author == "" {
				meta.Author = content
			}
		case "publisher":
			if meta.Publisher == "" {
				meta.Publisher = content
			}
		case "keywords":
			if len(meta.Keywords) == 0 {
				meta.Keywords = parseKeywords(content)
			}
		}
		if strings.HasPrefix(name, "twitter:") {
			key := strings.TrimPrefix(name, "twitter:")
			if _, exists := meta.TwitterCard[key]; !exists {
				meta.TwitterCard[key] = content
			}
		}
	}

	// OG: property=X content=Y
	for _, match := range reMetaPropVal.FindAllStringSubmatch(r.bodyStr, -1) {
		if len(match) < 3 {
			continue
		}
		prop, content := strings.ToLower(match[1]), strings.TrimSpace(match[2])
		if strings.HasPrefix(prop, "og:") {
			meta.OG[strings.TrimPrefix(prop, "og:")] = content
		}
	}

	// OG: content=X property=Y (reversed)
	for _, match := range reMetaValProp.FindAllStringSubmatch(r.bodyStr, -1) {
		if len(match) < 3 {
			continue
		}
		content, prop := strings.TrimSpace(match[1]), strings.ToLower(match[2])
		if strings.HasPrefix(prop, "og:") {
			key := strings.TrimPrefix(prop, "og:")
			if _, exists := meta.OG[key]; !exists {
				meta.OG[key] = content
			}
		}
	}

	// Fallback description from OG
	if meta.Description == "" {
		if desc, ok := meta.OG["description"]; ok {
			meta.Description = desc
		}
	}

	// Canonical URL
	if matches := reCanonical.FindStringSubmatch(r.bodyStr); len(matches) >= 2 {
		meta.CanonicalURL = strings.TrimSpace(matches[1])
	}

	// Language
	if matches := reLang.FindStringSubmatch(r.bodyStr); len(matches) >= 2 {
		meta.Language = strings.TrimSpace(matches[1])
	}

	return meta
}

// Links extracts anchor links, resolves relative URLs, and categorizes internal/external.
func (r *Response) Links() []Link {
	if r.semanticTree != nil {
		return r.semanticTree.GetLinks()
	}
	r.ensureParsed()
	if r.bodyStr == "" {
		return nil
	}

	baseDomain := extractDomain(r.FinalURL)
	seen := make(map[string]bool)
	var links []Link

	matches := reAnchor.FindAllStringSubmatch(r.bodyStr, -1)
	for _, match := range matches {
		if len(match) < 3 {
			continue
		}

		href := strings.TrimSpace(match[1])
		if shouldSkipHref(href) {
			continue
		}

		// Resolve relative URLs
		resolved := href
		if r.FinalURL != "" {
			resolved = resolveURL(r.FinalURL, href)
		}

		// Dedup by normalized URL
		normalized := normalizeURL(resolved)
		if seen[normalized] {
			continue
		}
		seen[normalized] = true

		// Strip inline tags from text
		text := reInlineTag.ReplaceAllString(match[2], "")
		text = strings.Join(strings.Fields(strings.TrimSpace(text)), " ")

		link := Link{
			URL:        resolved,
			Text:       text,
			IsExternal: baseDomain != "" && extractDomain(resolved) != baseDomain,
		}

		// Check nofollow
		if reNofollow.MatchString(match[0]) {
			link.IsNofollow = true
		}

		links = append(links, link)
	}

	return links
}

// Images extracts image URLs from img src, og:image, and twitter:image.
func (r *Response) Images() []string {
	r.ensureParsed()
	if r.bodyStr == "" {
		return nil
	}

	seen := make(map[string]bool)
	var images []string

	addImage := func(src string) {
		src = strings.TrimSpace(src)
		if src == "" {
			return
		}
		if r.FinalURL != "" {
			src = resolveURL(r.FinalURL, src)
		}
		normalized := normalizeURL(src)
		if !seen[normalized] {
			seen[normalized] = true
			images = append(images, src)
		}
	}

	// <img src>
	for _, match := range reImgSrc.FindAllStringSubmatch(r.bodyStr, -1) {
		if len(match) >= 2 {
			addImage(match[1])
		}
	}

	// og:image and twitter:image from meta property tags
	for _, match := range reMetaPropVal.FindAllStringSubmatch(r.bodyStr, -1) {
		if len(match) >= 3 {
			prop := strings.ToLower(match[1])
			if prop == "og:image" {
				addImage(match[2])
			}
		}
	}
	for _, match := range reMetaValProp.FindAllStringSubmatch(r.bodyStr, -1) {
		if len(match) >= 3 {
			prop := strings.ToLower(match[2])
			if prop == "og:image" {
				addImage(match[1])
			}
		}
	}

	// twitter:image from meta name tags
	for _, match := range reMetaNameVal.FindAllStringSubmatch(r.bodyStr, -1) {
		if len(match) >= 3 {
			name := strings.ToLower(match[1])
			if name == "twitter:image" {
				addImage(match[2])
			}
		}
	}
	for _, match := range reMetaValName.FindAllStringSubmatch(r.bodyStr, -1) {
		if len(match) >= 3 {
			name := strings.ToLower(match[2])
			if name == "twitter:image" {
				addImage(match[1])
			}
		}
	}

	return images
}

// SocialLinks extracts social media profile URLs from anchor hrefs.
func (r *Response) SocialLinks() SocialLinks {
	if r.semanticTree != nil {
		if s := r.semanticTree.GetSocial(); s != nil {
			return *s
		}
	}
	r.ensureParsed()
	var social SocialLinks
	if r.bodyStr == "" {
		return social
	}

	// Extract all anchor hrefs
	hrefMatches := reAnchor.FindAllStringSubmatch(r.bodyStr, -1)
	var hrefs []string
	for _, match := range hrefMatches {
		if len(match) >= 2 {
			hrefs = append(hrefs, strings.TrimSpace(match[1]))
		}
	}

	for platform, re := range socialPatterns {
		for _, href := range hrefs {
			match := re.FindString(href)
			if match == "" {
				continue
			}
			match = cleanSocialURL(match)

			switch platform {
			case "linkedin":
				social.LinkedIn = match
			case "twitter":
				social.Twitter = match
			case "instagram":
				social.Instagram = match
			case "facebook":
				social.Facebook = match
			case "youtube":
				social.YouTube = match
			case "github":
				social.GitHub = match
			case "tiktok":
				social.TikTok = match
			case "pinterest":
				social.Pinterest = match
			case "discord":
				social.Discord = match
			}
			break // first match per platform
		}
	}

	return social
}

// Colors extracts colors from theme-color meta, CSS hex, and rgb/rgba values.
func (r *Response) Colors() []ColorInfo {
	if r.semanticTree != nil {
		return r.semanticTree.GetColors()
	}
	r.ensureParsed()
	if r.bodyStr == "" {
		return nil
	}

	seen := make(map[string]bool)
	var colors []ColorInfo

	addColor := func(hex, source string) {
		hex = normalizeHexColor(hex)
		if isCommonColor(hex) || seen[hex] {
			return
		}
		seen[hex] = true
		colors = append(colors, ColorInfo{Hex: hex, Source: source})
	}

	// theme-color meta
	if matches := reThemeColor.FindStringSubmatch(r.bodyStr); len(matches) >= 2 {
		addColor(matches[1], "meta")
	}

	// CSS hex colors
	for _, hex := range reHexColor.FindAllString(r.bodyStr, -1) {
		addColor(hex, "css")
	}

	// CSS rgb/rgba
	for _, match := range reRGBColor.FindAllStringSubmatch(r.bodyStr, -1) {
		if len(match) >= 4 {
			hex := rgbToHex(match[1], match[2], match[3])
			addColor(hex, "css")
		}
	}

	return colors
}

// Fonts extracts font information from Google Fonts URLs and CSS font-family declarations.
func (r *Response) Fonts() []FontInfo {
	if r.semanticTree != nil {
		return r.semanticTree.GetFonts()
	}
	r.ensureParsed()
	if r.bodyStr == "" {
		return nil
	}

	fonts := make(map[string]FontInfo)

	// Google Fonts API v1
	if matches := reGoogleFontsV1.FindStringSubmatch(r.bodyStr); len(matches) >= 2 {
		families := strings.Split(matches[1], "|")
		for _, family := range families {
			parts := strings.Split(family, ":")
			name := strings.ReplaceAll(parts[0], "+", " ")
			fi := FontInfo{Family: name, Source: "google-fonts"}
			if len(parts) > 1 {
				fi.Variants = strings.Split(parts[1], ",")
			}
			fonts[name] = fi
		}
	}

	// Google Fonts API v2
	if matches := reGoogleFontsV2.FindStringSubmatch(r.bodyStr); len(matches) >= 2 {
		families := strings.Split(matches[1], "&family=")
		for _, family := range families {
			family = strings.Split(family, "&")[0]
			parts := strings.Split(family, ":")
			name := strings.ReplaceAll(parts[0], "+", " ")
			fi := FontInfo{Family: name, Source: "google-fonts"}
			if len(parts) > 1 {
				fi.Variants = parseFontVariants(parts[1])
			}
			if existing, ok := fonts[name]; ok {
				existing.Variants = mergeStringSlice(existing.Variants, fi.Variants)
				fonts[name] = existing
			} else {
				fonts[name] = fi
			}
		}
	}

	// CSS font-family
	seen := make(map[string]bool)
	for _, match := range reCSSFontFamily.FindAllStringSubmatch(r.bodyStr, -1) {
		if len(match) < 2 {
			continue
		}
		family := extractPrimaryFont(match[1])
		if family == "" || seen[family] || isGenericFont(family) {
			continue
		}
		seen[family] = true
		if _, ok := fonts[family]; !ok {
			fonts[family] = FontInfo{Family: family, Source: "css"}
		}
	}

	result := make([]FontInfo, 0, len(fonts))
	for _, f := range fonts {
		result = append(result, f)
	}
	return result
}

// ImagesWithContext extracts images from the rendered DOM along with their
// surrounding context (ancestor class names, IDs, parent href, section headings).
// This enables downstream consumers to classify images (e.g. customer logo vs brand
// logo) based on their position in the page structure — something regex-based
// extraction on raw HTML cannot reliably do for JS-rendered pages.
func (r *Response) ImagesWithContext() []ImageWithContext {
	r.ensureParsed()
	if r.doc == nil {
		return nil
	}

	seen := make(map[string]bool)
	var results []ImageWithContext

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "img" {
			img := extractImageNodeContext(n, r.FinalURL)
			if img.URL == "" {
				return
			}
			normalized := normalizeURL(img.URL)
			if !seen[normalized] {
				seen[normalized] = true
				results = append(results, img)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(r.doc)

	return results
}

// extractImageNodeContext collects context for a single <img> node by examining
// its own attributes and walking up the ancestor chain.
func extractImageNodeContext(imgNode *html.Node, baseURL string) ImageWithContext {
	img := ImageWithContext{}

	// Collect <img> own attributes.
	for _, a := range imgNode.Attr {
		switch a.Key {
		case "src":
			img.URL = strings.TrimSpace(a.Val)
		case "alt":
			img.Alt = strings.TrimSpace(a.Val)
		case "class":
			img.Classes = strings.TrimSpace(a.Val)
		case "id":
			img.ID = strings.TrimSpace(a.Val)
		}
	}

	if img.URL == "" {
		return img
	}

	// Resolve relative URL.
	if baseURL != "" {
		img.URL = resolveURL(baseURL, img.URL)
	}

	// Walk up ancestors (max 8 levels) collecting context.
	var parentClasses, parentIDs []string
	node := imgNode.Parent
	for depth := 0; node != nil && depth < 8; depth++ {
		if node.Type != html.ElementNode {
			node = node.Parent
			continue
		}

		cls := attrVal(node, "class")
		id := attrVal(node, "id")
		dataAttrs := collectDataAttrs(node)

		if cls != "" {
			parentClasses = append(parentClasses, cls)
		}
		if id != "" {
			parentIDs = append(parentIDs, id)
		}

		// Capture href from closest <a> ancestor.
		if node.Data == "a" && img.ParentHref == "" {
			img.ParentHref = attrVal(node, "href")
		}

		// Capture nearest heading text from sibling heading elements.
		if img.NearestHeading == "" {
			img.NearestHeading = findSiblingHeading(node)
		}

		// Check data attributes for section classification hints.
		for _, dv := range dataAttrs {
			parentClasses = append(parentClasses, dv)
		}

		node = node.Parent
	}

	img.ParentClasses = strings.Join(parentClasses, " ")
	img.ParentIDs = strings.Join(parentIDs, " ")

	// Classify the image based on aggregated context.
	img.SectionTag = classifyImageSection(img)

	return img
}

// classifyImageSection determines whether an image is inside a customer/partner
// showcase section based on aggregated DOM context signals.
func classifyImageSection(img ImageWithContext) string {
	// Combine all context into a single string for keyword matching.
	context := strings.ToLower(strings.Join([]string{
		img.Classes, img.ID,
		img.ParentClasses, img.ParentIDs,
		img.ParentHref, img.NearestHeading,
		img.Alt,
	}, " "))

	// Customer/partner section signals (ordered by specificity).
	customerPatterns := []struct {
		keyword string
		tag     string
	}{
		{"customer", "customer-logos"},
		{"client", "customer-logos"},
		{"trusted", "customer-logos"},
		{"social-proof", "customer-logos"},
		{"socialproof", "customer-logos"},
		{"social_proof", "customer-logos"},
		{"partner", "partner-logos"},
		{"integration", "partner-logos"},
		{"showcase", "customer-logos"},
		{"logo-wall", "customer-logos"},
		{"logowall", "customer-logos"},
		{"logo_wall", "customer-logos"},
		{"logo-grid", "customer-logos"},
		{"logogrid", "customer-logos"},
		{"logo-bar", "customer-logos"},
		{"logo-strip", "customer-logos"},
		{"logo-carousel", "customer-logos"},
		{"case-stud", "customer-logos"},
		{"casestud", "customer-logos"},
		{"/customers/", "customer-logos"},
		{"/partners/", "partner-logos"},
		{"/clients/", "customer-logos"},
		{"/case-stud", "customer-logos"},
	}

	for _, p := range customerPatterns {
		if strings.Contains(context, p.keyword) {
			return p.tag
		}
	}

	return ""
}

// attrVal returns the value of the named attribute on an HTML element node.
func attrVal(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return strings.TrimSpace(a.Val)
		}
	}
	return ""
}

// collectDataAttrs returns values of data-* attributes that might contain
// section classification hints.
func collectDataAttrs(n *html.Node) []string {
	var vals []string
	for _, a := range n.Attr {
		if strings.HasPrefix(a.Key, "data-") && a.Val != "" {
			vals = append(vals, a.Val)
		}
	}
	return vals
}

// findSiblingHeading scans the immediate children of a node for heading
// elements (h1–h6) and returns the text content of the first one found.
func findSiblingHeading(parent *html.Node) string {
	for c := parent.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode {
			switch c.Data {
			case "h1", "h2", "h3", "h4", "h5", "h6":
				text := collectText(c)
				if text != "" {
					return text
				}
			}
		}
	}
	return ""
}

// collectText extracts visible text content from an HTML node subtree.
func collectText(n *html.Node) string {
	if n.Type == html.TextNode {
		return strings.TrimSpace(n.Data)
	}
	var parts []string
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if t := collectText(c); t != "" {
			parts = append(parts, t)
		}
	}
	return strings.Join(parts, " ")
}

// --- Internal helpers ---

func parseKeywords(keywords string) []string {
	parts := strings.Split(keywords, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		k := strings.TrimSpace(p)
		if k != "" {
			result = append(result, k)
		}
	}
	return result
}

func parseFontVariants(variantStr string) []string {
	variants := strings.Split(variantStr, ",")
	for i, v := range variants {
		if strings.Contains(v, "@") {
			parts := strings.Split(v, "@")
			if len(parts) == 2 {
				variants[i] = parts[0] + " " + strings.ReplaceAll(parts[1], ";", ", ")
			}
		}
	}
	return variants
}

func mergeStringSlice(a, b []string) []string {
	seen := make(map[string]bool, len(a))
	result := make([]string, 0, len(a)+len(b))
	for _, v := range a {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	for _, v := range b {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result
}
