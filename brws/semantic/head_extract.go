package semantic

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/net/html"
)

// Social platform regexes (compiled once at package level).
var socialPlatformPatterns = map[string]*regexp.Regexp{
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

// Color & font regexes.
var (
	reHexColorDOM      = regexp.MustCompile(`#([0-9A-Fa-f]{3}){1,2}`)
	reRGBColorDOM      = regexp.MustCompile(`rgba?\s*\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)`)
	reGoogleFontsV1DOM = regexp.MustCompile(`fonts\.googleapis\.com/css\?family=([^"']+)`)
	reGoogleFontsV2DOM = regexp.MustCompile(`fonts\.googleapis\.com/css2\?family=([^"']+)`)
	reCSSFontFamilyDOM = regexp.MustCompile(`font-family\s*:\s*([^;]+)`)
	reNofollowDOM      = regexp.MustCompile(`(?i)\bnofollow\b`)
)

// ExtractPageMeta extracts page metadata from the parsed DOM before head is stripped.
func ExtractPageMeta(doc *html.Node, pageURL string) PageMeta {
	meta := PageMeta{
		OG:          make(map[string]string),
		TwitterCard: make(map[string]string),
	}

	// Extract lang from <html> element.
	htmlEl := findElement(doc, "html")
	if htmlEl != nil {
		if lang := getAttr(htmlEl, "lang"); lang != "" {
			meta.Language = lang
		}
	}

	// Walk <head> for meta tags, title, canonical link.
	head := findElement(doc, "head")
	if head == nil {
		return meta
	}

	for c := head.FirstChild; c != nil; c = c.NextSibling {
		if c.Type != html.ElementNode {
			continue
		}
		switch c.Data {
		case "title":
			if meta.Title == "" {
				meta.Title = strings.TrimSpace(extractTextContent(c))
			}
		case "meta":
			extractMetaAttrs(c, &meta)
		case "link":
			if strings.EqualFold(getAttr(c, "rel"), "canonical") {
				if href := getAttr(c, "href"); href != "" {
					meta.CanonicalURL = strings.TrimSpace(href)
				}
			}
		}
	}

	// Fallback description from OG.
	if meta.Description == "" {
		if desc, ok := meta.OG["description"]; ok {
			meta.Description = desc
		}
	}

	return meta
}

// ExtractLinks extracts anchor links from the <body>, resolves relative URLs, and classifies internal/external.
func ExtractLinks(doc *html.Node, pageURL string) []Link {
	body := findElement(doc, "body")
	if body == nil {
		return nil
	}

	baseDomain := extractHostname(pageURL)
	seen := make(map[string]bool)
	var links []Link

	forEachElement(body, "a", func(n *html.Node) {
		href := strings.TrimSpace(getAttr(n, "href"))
		if href == "" || shouldSkipHrefDOM(href) {
			return
		}

		resolved := resolveURLFull(pageURL, href)
		normalized := normalizeURLFull(resolved)
		if seen[normalized] {
			return
		}
		seen[normalized] = true

		text := strings.Join(strings.Fields(strings.TrimSpace(extractTextContent(n))), " ")

		link := Link{
			URL:        resolved,
			Text:       text,
			IsExternal: baseDomain != "" && extractHostname(resolved) != baseDomain,
		}

		rel := getAttr(n, "rel")
		if rel != "" && reNofollowDOM.MatchString(rel) {
			link.IsNofollow = true
		}

		links = append(links, link)
	})

	return links
}

// ExtractSocialLinks finds social media profile URLs from anchor hrefs in <body>.
func ExtractSocialLinks(doc *html.Node) SocialLinks {
	var social SocialLinks
	body := findElement(doc, "body")
	if body == nil {
		return social
	}

	forEachElement(body, "a", func(n *html.Node) {
		href := strings.TrimSpace(getAttr(n, "href"))
		if href == "" {
			return
		}
		setSocialField(&social, href)
	})

	return social
}

// ExtractColors extracts colors from theme-color meta and <style> blocks.
func ExtractColors(doc *html.Node) []ColorInfo {
	seen := make(map[string]bool)
	var colors []ColorInfo

	addColor := func(hex, source string) {
		hex = normalizeHexColorDOM(hex)
		if isCommonColorDOM(hex) || seen[hex] {
			return
		}
		seen[hex] = true
		colors = append(colors, ColorInfo{Hex: hex, Source: source})
	}

	// theme-color from <meta> in <head>.
	forEachElement(doc, "meta", func(n *html.Node) {
		name := getAttr(n, "name")
		if strings.EqualFold(name, "theme-color") {
			if content := getAttr(n, "content"); content != "" {
				addColor(content, "meta")
			}
		}
	})

	// Colors from <style> blocks.
	forEachElement(doc, "style", func(n *html.Node) {
		css := extractTextContent(n)
		for _, hex := range reHexColorDOM.FindAllString(css, -1) {
			addColor(hex, "css")
		}
		for _, match := range reRGBColorDOM.FindAllStringSubmatch(css, -1) {
			if len(match) >= 4 {
				addColor(rgbToHexDOM(match[1], match[2], match[3]), "css")
			}
		}
	})

	return colors
}

// ExtractFonts extracts font information from Google Fonts links and <style> CSS.
func ExtractFonts(doc *html.Node) []FontInfo {
	fonts := make(map[string]FontInfo)

	// Google Fonts from <link> elements.
	forEachElement(doc, "link", func(n *html.Node) {
		href := getAttr(n, "href")
		if href == "" {
			return
		}
		parseFontLinkDOM(href, fonts)
	})

	// CSS font-family from <style> blocks.
	seen := make(map[string]bool)
	forEachElement(doc, "style", func(n *html.Node) {
		css := extractTextContent(n)
		for _, match := range reCSSFontFamilyDOM.FindAllStringSubmatch(css, -1) {
			if len(match) < 2 {
				continue
			}
			family := extractPrimaryFontDOM(match[1])
			if family == "" || seen[family] || isGenericFontDOM(family) {
				continue
			}
			seen[family] = true
			if _, ok := fonts[family]; !ok {
				fonts[family] = FontInfo{Family: family, Source: "css"}
			}
		}
	})

	result := make([]FontInfo, 0, len(fonts))
	for _, f := range fonts {
		result = append(result, f)
	}
	return result
}

// --- Unexported helpers ---

func extractMetaAttrs(n *html.Node, meta *PageMeta) {
	name := strings.ToLower(getAttr(n, "name"))
	property := strings.ToLower(getAttr(n, "property"))
	content := strings.TrimSpace(getAttr(n, "content"))
	if content == "" {
		return
	}

	// name-based meta tags.
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
			meta.Keywords = splitKeywords(content)
		}
	}

	// twitter:* from name attribute.
	if strings.HasPrefix(name, "twitter:") {
		key := strings.TrimPrefix(name, "twitter:")
		if _, exists := meta.TwitterCard[key]; !exists {
			meta.TwitterCard[key] = content
		}
	}

	// og:* from property attribute.
	if strings.HasPrefix(property, "og:") {
		key := strings.TrimPrefix(property, "og:")
		if _, exists := meta.OG[key]; !exists {
			meta.OG[key] = content
		}
	}
}

func splitKeywords(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		k := strings.TrimSpace(p)
		if k != "" {
			result = append(result, k)
		}
	}
	return result
}

func setSocialField(s *SocialLinks, href string) {
	for platform, re := range socialPlatformPatterns {
		match := re.FindString(href)
		if match == "" {
			continue
		}
		match = cleanSocialURLDOM(match)
		switch platform {
		case "linkedin":
			if s.LinkedIn == "" {
				s.LinkedIn = match
			}
		case "twitter":
			if s.Twitter == "" {
				s.Twitter = match
			}
		case "instagram":
			if s.Instagram == "" {
				s.Instagram = match
			}
		case "facebook":
			if s.Facebook == "" {
				s.Facebook = match
			}
		case "youtube":
			if s.YouTube == "" {
				s.YouTube = match
			}
		case "github":
			if s.GitHub == "" {
				s.GitHub = match
			}
		case "tiktok":
			if s.TikTok == "" {
				s.TikTok = match
			}
		case "pinterest":
			if s.Pinterest == "" {
				s.Pinterest = match
			}
		case "discord":
			if s.Discord == "" {
				s.Discord = match
			}
		}
	}
}

func shouldSkipHrefDOM(href string) bool {
	lower := strings.ToLower(strings.TrimSpace(href))
	for _, prefix := range []string{"#", "javascript:", "mailto:", "tel:", "data:"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func cleanSocialURLDOM(u string) string {
	u = strings.TrimRight(u, ".,;:!?')}\"")
	if strings.HasPrefix(u, "http://") {
		u = "https://" + u[7:]
	}
	return u
}

// --- URL helpers (using net/url for proper resolution) ---

func resolveURLFull(baseURL, ref string) string {
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

func normalizeURLFull(urlStr string) string {
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

func extractHostname(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// --- Color helpers ---

func normalizeHexColorDOM(hex string) string {
	hex = strings.ToLower(strings.TrimSpace(hex))
	if len(hex) == 4 && hex[0] == '#' {
		return "#" + string(hex[1]) + string(hex[1]) +
			string(hex[2]) + string(hex[2]) +
			string(hex[3]) + string(hex[3])
	}
	return hex
}

func isCommonColorDOM(hex string) bool {
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

func rgbToHexDOM(r, g, b string) string {
	ri, _ := strconv.Atoi(strings.TrimSpace(r))
	gi, _ := strconv.Atoi(strings.TrimSpace(g))
	bi, _ := strconv.Atoi(strings.TrimSpace(b))
	return fmt.Sprintf("#%02x%02x%02x", ri, gi, bi)
}

// --- Font helpers ---

func isGenericFontDOM(font string) bool {
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

func isValidFontFamilyDOM(font string) bool {
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

func extractPrimaryFontDOM(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Split(value, "!important")[0]
	value = strings.Trim(value, `"'`)

	parts := strings.Split(value, ",")
	for _, part := range parts {
		font := strings.TrimSpace(strings.Trim(part, `"'`))
		if font == "" || !isValidFontFamilyDOM(font) {
			continue
		}
		if !isGenericFontDOM(font) {
			return font
		}
	}
	return ""
}

func parseFontLinkDOM(href string, fonts map[string]FontInfo) {
	// Google Fonts API v1.
	if matches := reGoogleFontsV1DOM.FindStringSubmatch(href); len(matches) >= 2 {
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
		return
	}

	// Google Fonts API v2.
	if matches := reGoogleFontsV2DOM.FindStringSubmatch(href); len(matches) >= 2 {
		families := strings.Split(matches[1], "&family=")
		for _, family := range families {
			family = strings.Split(family, "&")[0]
			parts := strings.Split(family, ":")
			name := strings.ReplaceAll(parts[0], "+", " ")
			fi := FontInfo{Family: name, Source: "google-fonts"}
			if len(parts) > 1 {
				fi.Variants = parseFontVariantsDOM(parts[1])
			}
			if existing, ok := fonts[name]; ok {
				existing.Variants = mergeStringSliceDOM(existing.Variants, fi.Variants)
				fonts[name] = existing
			} else {
				fonts[name] = fi
			}
		}
	}
}

func parseFontVariantsDOM(variantStr string) []string {
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

func mergeStringSliceDOM(a, b []string) []string {
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
