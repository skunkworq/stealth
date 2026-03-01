package spider

import (
	"encoding/xml"
	"io"
	"net/url"
	"strings"
)

type SitemapSpider struct {
	name        string
	startURLs   []string
	sitemapURLs []string
	parseFunc   func(Response) []ParseResult
}

func NewSitemapSpider(name string, sitemapURLs []string) Spider {
	return &SitemapSpider{
		name:        name,
		sitemapURLs: sitemapURLs,
	}
}

func (s *SitemapSpider) Name() string {
	return s.name
}

func (s *SitemapSpider) StartRequests() []Request {
	var requests []Request

	for _, smURL := range s.sitemapURLs {
		requests = append(requests, Request{
			URL:      smURL,
			Meta:     map[string]any{"spider_type": "sitemap"},
			Callback: s.parseSitemap,
		})
	}

	for _, u := range s.startURLs {
		requests = append(requests, Request{
			URL:      u,
			Meta:     map[string]any{"spider_type": "start"},
			Callback: s.parsePage,
		})
	}

	return requests
}

func (s *SitemapSpider) Parse(resp Response) []ParseResult {
	if s.parseFunc != nil {
		return s.parseFunc(resp)
	}
	return s.parsePage(resp)
}

func (s *SitemapSpider) parseSitemap(resp Response) []ParseResult {
	decoder := xml.NewDecoder(strings.NewReader(resp.Text()))
	var links []string

	for {
		tok, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		if se, ok := tok.(xml.StartElement); ok {
			if se.Name.Local == "loc" {
				var loc string
				if err := decoder.DecodeElement(&loc, &se); err == nil {
					links = append(links, strings.TrimSpace(loc))
				}
			}
		}
	}

	var results []ParseResult
	for _, link := range links {
		parsedURL, _ := url.Parse(link)
		if parsedURL != nil {
			results = append(results, ParseResult{
				Request: &Request{
					URL:      parsedURL.String(),
					Meta:     map[string]any{"spider_type": "page"},
					Callback: s.parsePage,
				},
			})
		}
	}
	return results
}

func (s *SitemapSpider) parsePage(resp Response) []ParseResult {
	return nil
}

func (s *SitemapSpider) SetParseFunc(f func(Response) []ParseResult) {
	s.parseFunc = f
}
