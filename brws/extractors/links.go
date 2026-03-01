package extractors

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/stealth/brwslab/brws/spider"
)

type LinkExtractor struct {
	Allow        []*regexp.Regexp
	Deny         []*regexp.Regexp
	AllowDomains []string
	DenyDomains  []string
	CSSSelector  string
	XPath        string
	Tags         []string
	Attrs        []string
}

func NewLinkExtractor() *LinkExtractor {
	return &LinkExtractor{
		Tags:  []string{"a", "area", "frame", "iframe"},
		Attrs: []string{"href"},
	}
}

func (le *LinkExtractor) Extract(resp spider.Response) []spider.Link {
	var links []spider.Link

	elements := resp.CSS(le.CSSSelector)
	if len(elements) == 0 && le.CSSSelector != "" {
		elements = resp.CSS("a")
	}

	for _, el := range elements {
		href := el.Attr("href")
		if href == "" || strings.HasPrefix(href, "javascript:") || strings.HasPrefix(href, "mailto:") {
			continue
		}

		parsedURL, err := url.Parse(href)
		if err != nil {
			continue
		}

		if parsedURL.Scheme == "" {
			baseURL, err := url.Parse(resp.URL)
			if err != nil {
				continue
			}
			parsedURL = baseURL.ResolveReference(parsedURL)
		}

		linkURL := parsedURL.String()

		if le.AllowDomains != nil {
			allowed := false
			for _, domain := range le.AllowDomains {
				if strings.Contains(linkURL, domain) {
					allowed = true
					break
				}
			}
			if !allowed {
				continue
			}
		}

		if le.DenyDomains != nil {
			denied := false
			for _, domain := range le.DenyDomains {
				if strings.Contains(linkURL, domain) {
					denied = true
					break
				}
			}
			if denied {
				continue
			}
		}

		if le.Allow != nil {
			allowed := false
			for _, pattern := range le.Allow {
				if pattern.MatchString(linkURL) {
					allowed = true
					break
				}
			}
			if !allowed {
				continue
			}
		}

		if le.Deny != nil {
			denied := false
			for _, pattern := range le.Deny {
				if pattern.MatchString(linkURL) {
					denied = true
					break
				}
			}
			if denied {
				continue
			}
		}

		links = append(links, spider.Link{
			URL:  linkURL,
			Text: strings.TrimSpace(el.Text()),
		})
	}

	return links
}

func Allow(patterns ...string) func(*LinkExtractor) {
	return func(le *LinkExtractor) {
		for _, p := range patterns {
			if re, err := regexp.Compile(p); err == nil {
				le.Allow = append(le.Allow, re)
			}
		}
	}
}

func Deny(patterns ...string) func(*LinkExtractor) {
	return func(le *LinkExtractor) {
		for _, p := range patterns {
			if re, err := regexp.Compile(p); err == nil {
				le.Deny = append(le.Deny, re)
			}
		}
	}
}

func AllowDomains(domains ...string) func(*LinkExtractor) {
	return func(le *LinkExtractor) {
		le.AllowDomains = append(le.AllowDomains, domains...)
	}
}

func DenyDomains(domains ...string) func(*LinkExtractor) {
	return func(le *LinkExtractor) {
		le.DenyDomains = append(le.DenyDomains, domains...)
	}
}

func RestrictCSS(selector string) func(*LinkExtractor) {
	return func(le *LinkExtractor) {
		le.CSSSelector = selector
	}
}
