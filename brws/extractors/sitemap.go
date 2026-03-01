package extractors

import (
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"strings"

	"github.com/stealth/brwslab/brws/spider"
)

type SitemapExtractor struct {
	client *http.Client
}

func NewSitemapExtractor() *SitemapExtractor {
	return &SitemapExtractor{
		client: &http.Client{},
	}
}

func (s *SitemapExtractor) ExtractFromURL(url string) ([]spider.Link, error) {
	resp, err := s.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return s.Extract(resp.Body)
}

func (s *SitemapExtractor) Extract(r io.Reader) ([]spider.Link, error) {
	decoder := xml.NewDecoder(r)
	var links []spider.Link

	for {
		tok, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if se, ok := tok.(xml.StartElement); ok {
			if se.Name.Local == "loc" {
				var loc string
				if err := decoder.DecodeElement(&loc, &se); err != nil {
					continue
				}
				links = append(links, spider.Link{
					URL: strings.TrimSpace(loc),
				})
			}
		}
	}

	return links, nil
}

type SitemapIndex struct {
	XMLName  xml.Name  `xml:"sitemapindex"`
	Sitemaps []Sitemap `xml:"sitemap"`
}

type Sitemap struct {
	Loc     string `xml:"loc"`
	LastMod string `xml:"lastmod"`
}

type UrlSet struct {
	XMLName xml.Name `xml:"urlset"`
	URLs    []URL    `xml:"url"`
}

type URL struct {
	Loc        string `xml:"loc"`
	LastMod    string `xml:"lastmod"`
	ChangeFreq string `xml:"changefreq"`
	Priority   string `xml:"priority"`
}

func ExtractSitemaps(ctx context.Context, url string) ([]string, error) {
	ext := NewSitemapExtractor()
	links, err := ext.ExtractFromURL(url)
	if err != nil {
		return nil, err
	}

	var sitemaps []string
	for _, link := range links {
		sitemaps = append(sitemaps, link.URL)
	}

	return sitemaps, nil
}
