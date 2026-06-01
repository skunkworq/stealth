package collect

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"

	"golang.org/x/net/html"

	"github.com/skunkworq/stealth/brws/semantic"
	"github.com/skunkworq/stealth/extract"
)

// LdJSONExtractor harvests schema.org fields from <script type=application/ld+json>
// blocks. Each emitted value is the literal JSON string (verbatim in doc.Text),
// so the Validator confirms it. Runs only on raw-HTML documents.
type LdJSONExtractor struct{}

func (LdJSONExtractor) Name() string { return "ld_json" }

func (LdJSONExtractor) Extract(_ context.Context, doc *extract.SourceDocument) ([]extract.Candidate, error) {
	if doc == nil || doc.ContentType != "text/html" {
		return nil, nil
	}
	node, err := html.Parse(strings.NewReader(doc.Text))
	if err != nil {
		return nil, nil
	}
	var out []extract.Candidate
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "script" &&
			attrVal(n, "type") == "application/ld+json" && n.FirstChild != nil {
			out = append(out, candidatesFromLdJSON(n.FirstChild.Data)...)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(node)
	return out, nil
}

func attrVal(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

func candidatesFromLdJSON(raw string) []extract.Candidate {
	var v any
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &v); err != nil {
		return nil
	}
	var out []extract.Candidate
	// depth bound: ld+json is scraped from arbitrary sites; a deeply-nested
	// (adversarial) @graph must not blow the stack — a panic would not be
	// caught by the engine's error guard.
	var walk func(any, int)
	walk = func(x any, depth int) {
		if depth > 64 {
			return
		}
		switch t := x.(type) {
		case []any:
			for _, e := range t {
				walk(e, depth+1)
			}
		case map[string]any:
			str := func(k string) string {
				s, _ := t[k].(string)
				return strings.TrimSpace(s)
			}
			emit := func(val string, fk extract.FieldKey, conf float64) {
				if val != "" {
					out = append(out, extract.Candidate{Key: fk, Value: val, Method: extract.MethodLdJSON, Conf: conf})
				}
			}
			emit(str("telephone"), extract.KeyPhone, 0.95)
			emit(str("email"), extract.KeyEmail, 0.95)
			emit(str("url"), extract.KeyWebsite, 0.8)
			if ln := str("legalName"); ln != "" {
				emit(ln, extract.KeyLegalName, 0.8)
			} else {
				emit(str("name"), extract.KeyLegalName, 0.7)
			}
			switch lg := t["logo"].(type) {
			case string:
				emit(strings.TrimSpace(lg), extract.KeyLogoURL, 0.8)
			case map[string]any:
				if u, ok := lg["url"].(string); ok {
					emit(strings.TrimSpace(u), extract.KeyLogoURL, 0.8)
				}
			}
			if addr, ok := t["address"].(map[string]any); ok {
				if s, ok := addr["streetAddress"].(string); ok {
					emit(strings.TrimSpace(s), extract.KeyAddress, 0.85)
				}
			} else if s, ok := t["address"].(string); ok {
				emit(strings.TrimSpace(s), extract.KeyAddress, 0.85)
			}
			for _, val := range t {
				walk(val, depth+1) // recurse into @graph / nested objects
			}
		}
	}
	walk(v, 0)
	return out
}

// MetaExtractor harvests social profile links and og metadata, reusing
// stealth's semantic head extractors. Social/og URLs are verbatim in the page
// markup so the Validator (URL class) confirms them. Runs only on raw HTML.
type MetaExtractor struct{}

func (MetaExtractor) Name() string { return "og_meta" }

func (MetaExtractor) Extract(_ context.Context, doc *extract.SourceDocument) ([]extract.Candidate, error) {
	if doc == nil || doc.ContentType != "text/html" {
		return nil, nil
	}
	node, err := html.Parse(strings.NewReader(doc.Text))
	if err != nil {
		return nil, nil
	}
	social := semantic.ExtractSocialLinks(node)
	meta := semantic.ExtractPageMeta(node, doc.Ref)

	var out []extract.Candidate
	add := func(val string, fk extract.FieldKey, conf float64) {
		if v := strings.TrimSpace(val); v != "" {
			out = append(out, extract.Candidate{Key: fk, Value: v, Method: extract.MethodOgMeta, Conf: conf})
		}
	}
	addSocial := func(val string, fk extract.FieldKey) {
		if v := strings.TrimSpace(val); v != "" && !isPlatformSocial(v) {
			out = append(out, extract.Candidate{Key: fk, Value: v, Method: extract.MethodOgMeta, Conf: 0.9})
		}
	}
	addSocial(social.Facebook, extract.KeySocialFB)
	addSocial(social.Instagram, extract.KeySocialIG)
	addSocial(social.LinkedIn, extract.KeySocialLI)
	if meta.OG != nil {
		add(meta.OG["image"], extract.KeyLogoURL, 0.6)
	}
	return out, nil
}

// platformSocialRE matches social URLs that belong to the website builder, a
// share/intent button, or an FB plugin — not the business. These leak from
// site footers/meta (e.g. a Wix-built site links facebook.com/wix) and would
// otherwise be persisted as the tradie's own social.
// The builder-handle tokens are anchored to a path-segment boundary ([/?#] or
// end) so a real business handle that merely starts with one (e.g.
// facebook.com/wixsonplumbing, /wordpressexperts) is NOT dropped — only the
// exact builder handle (facebook.com/wix) is. Path-component patterns
// (/sharer, /plugins/, company/<builder>) are distinctive enough to match
// directly, with the company/<builder> form also boundary-anchored.
var platformSocialRE = regexp.MustCompile(`(?i)` +
	`(facebook|instagram|linkedin)\.com/(wix|wixstudio|squarespace|shopify|godaddy|weebly|wordpress|wordpresscom|explore)([/?#]|$)` +
	`|company/(wix-com|squarespace)([/?#]|$)` +
	`|/sharer|/plugins/|/2008/fbml|/intent/|/hashtag/|/dialog/|/share\?`)

func isPlatformSocial(u string) bool { return platformSocialRE.MatchString(u) }
