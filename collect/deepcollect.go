package collect

import (
	"context"
	"net/url"
	"sort"
	"strings"

	"golang.org/x/net/html"

	"github.com/skunkworq/stealth/brws/semantic"
	"github.com/skunkworq/stealth/extract"
)

// DeepCollector does one-hop, same-domain traversal: it collects a homepage,
// discovers contact/about-style links on it, and collects up to maxPages-1 of
// them in priority order. It composes a *Collector so every page is rendered
// and split into the same text/plain + text/html views (and so the injected
// clock stays deterministic across pages). maxPages includes the homepage;
// maxPages <= 1 means homepage only. Traversal is one-hop only — links are
// discovered from the homepage, never recursively from sub-pages.
type DeepCollector struct {
	c        *Collector
	maxPages int
}

func NewDeepCollector(r Renderer, maxPages int) *DeepCollector {
	return &DeepCollector{c: NewCollector(r), maxPages: maxPages}
}

// Collect renders startURL, then follows same-domain contact/about links in
// priority order until maxPages pages (homepage inclusive) have been collected.
// Returns the flattened documents across all pages and the ordered list of URLs
// actually collected (homepage first). It errors only if the homepage fetch
// fails; per-subpage errors are skipped.
func (d *DeepCollector) Collect(ctx context.Context, startURL string) ([]extract.SourceDocument, []string, error) {
	docs, err := d.c.Collect(ctx, startURL)
	if err != nil {
		return nil, nil, err
	}
	if docs == nil {
		return nil, nil, nil
	}

	var rawHTML, finalURL string
	for _, doc := range docs {
		if doc.ContentType == "text/html" {
			rawHTML, finalURL = doc.Text, doc.Ref
		}
	}
	if finalURL == "" {
		finalURL = startURL
	}

	visited := map[string]bool{canonicalURL(finalURL): true}
	crawled := []string{finalURL}

	if d.maxPages > 1 {
		for _, link := range rankLinks(rawHTML, finalURL) {
			if len(crawled) >= d.maxPages {
				break
			}
			cu := canonicalURL(link.URL)
			if visited[cu] {
				continue
			}
			visited[cu] = true
			sub, err := d.c.Collect(ctx, link.URL)
			if err != nil || sub == nil {
				continue
			}
			docs = append(docs, sub...)
			crawled = append(crawled, link.URL)
		}
	}
	return docs, crawled, nil
}

type scoredLink struct {
	URL   string
	Score int
}

// rankLinks parses rawHTML, keeps same-domain links that look like a
// contact/about page (score > 0), dedupes by canonical URL (and drops any link
// canonical-equal to the page itself), and returns them sorted by score desc
// (stable — original document order breaks ties).
func rankLinks(rawHTML, pageURL string) []scoredLink {
	if rawHTML == "" {
		return nil
	}
	node, err := html.Parse(strings.NewReader(rawHTML))
	if err != nil {
		return nil
	}
	self := canonicalURL(pageURL)
	seen := map[string]bool{}
	var out []scoredLink
	for _, l := range semantic.ExtractLinks(node, pageURL) {
		if l.IsExternal {
			continue
		}
		s := scoreLink(l)
		if s == 0 {
			continue
		}
		cu := canonicalURL(l.URL)
		if cu == self || seen[cu] {
			continue
		}
		seen[cu] = true
		out = append(out, scoredLink{URL: l.URL, Score: s})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}

// scoreLink ranks a link by contact/about specificity. Higher = follow sooner.
// Tiered so the broad "contact" substring never outranks "contact-us", and
// about/services sit below contact. Case order handles "contact" ⊂ "contact-us".
func scoreLink(l semantic.Link) int {
	hay := strings.ToLower(l.URL + " " + l.Text)
	switch {
	case strings.Contains(hay, "contact-us") || strings.Contains(hay, "contact us"):
		return 40
	case strings.Contains(hay, "contact"):
		return 30
	case strings.Contains(hay, "about"):
		return 20
	case strings.Contains(hay, "service"):
		return 10
	default:
		return 0
	}
}

// canonicalURL strips the fragment, trims a trailing slash from the path, and
// lowercases scheme+host so cosmetic variations of the same page dedupe to one
// visited-set key. Malformed input is returned unchanged.
func canonicalURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.Fragment = ""
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	return u.String()
}
