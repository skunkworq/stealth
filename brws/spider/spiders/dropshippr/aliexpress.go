package dropshippr

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	crawlv1 "github.com/skunkworq/stealth/internal/gen/dropshippr/crawl/v1"
)

func init() {
	Register("aliexpress", aliexpressSearch)
}

// aliexpressSearch walks /wholesale?SearchText=<seed> result pages, extracting
// product cards from the page's embedded `_init_data_` JS-object. Each seed is
// a search query (e.g. "wireless earbuds"). The endpoint serves the data we
// need inline in the HTML, so we don't need JS execution.
func aliexpressSearch(ctx context.Context, job *crawlv1.CrawlJob, emit Emitter) error {
	seeds := job.GetSeeds()
	if len(seeds) == 0 {
		return fmt.Errorf("aliexpress requires at least one seed (search query)")
	}
	fetcher, err := FetcherFromJob(job.GetEngineHint().String(), job.GetParams())
	if err != nil {
		return err
	}
	maxPages := int(job.GetMaxPages())
	if maxPages <= 0 {
		maxPages = 1
	}
	// Pre-warm the AE session once per spider invocation so the upcoming
	// search-result URLs hit with realistic cookies + a settled fingerprint.
	// AE's rate-limiter trips fast on cold burst sequences.
	if err := fetcher.WarmUp(ctx, "https://www.aliexpress.com/", 5*time.Minute); err != nil {
		emit(&crawlv1.CrawlResult{
			JobId: job.GetId(),
			Kind:  crawlv1.ResultKind_RESULT_KIND_PAGE,
			Payload: &crawlv1.CrawlResult_Page{
				Page: &crawlv1.PageMeta{Url: "https://www.aliexpress.com/", Status: 0},
			},
		})
	}

	for _, query := range seeds {
		for page := 1; page <= maxPages; page++ {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			u := fmt.Sprintf(
				"https://www.aliexpress.com/wholesale?SearchText=%s&page=%d",
				url.QueryEscape(query), page,
			)
			res, err := fetcher.Get(ctx, u, map[string]string{
				"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			})
			status := 0
			if res != nil {
				status = res.Status
			}
			emit(&crawlv1.CrawlResult{
				JobId: job.GetId(),
				Kind:  crawlv1.ResultKind_RESULT_KIND_PAGE,
				Payload: &crawlv1.CrawlResult_Page{
					Page: &crawlv1.PageMeta{Url: u, Status: int32(status)},
				},
			})
			if err != nil {
				emit(&crawlv1.CrawlResult{
					JobId: job.GetId(),
					Kind:  crawlv1.ResultKind_RESULT_KIND_ERROR,
					Payload: &crawlv1.CrawlResult_Error{
						Error: &crawlv1.CrawlError{
							Url: u, Code: "fetch_failed", Message: err.Error(),
						},
					},
				})
				break
			}
			items := extractAliExpressProducts(res.Body)
			if len(items) == 0 {
				break
			}
			now := time.Now().UTC().Format(time.RFC3339)
			for _, it := range items {
				it.Attrs["query"] = query
				it.Attrs["page"] = strconv.Itoa(page)
				it.FetchedAt = now
				emit(&crawlv1.CrawlResult{
					JobId:   job.GetId(),
					Kind:    crawlv1.ResultKind_RESULT_KIND_ITEM,
					Payload: &crawlv1.CrawlResult_CatalogItem{CatalogItem: it},
				})
			}
		}
	}
	return nil
}

// Field extractors run over a fixed-size window starting at each productId.
// The data is JSON-in-HTML, not a clean JSON document; full structural parsing
// would require either pre-extracting the `_init_data_=` blob (boundary
// detection is its own bug source) or vendoring an HTML+JS parser. A windowed
// regex pass keeps the spider lean and survives minor schema drift.
var (
	aeProductIDRe = regexp.MustCompile(`"productId":"(\d{8,})"`)
	aeTitleRe     = regexp.MustCompile(`"displayTitle":"((?:[^"\\]|\\.)*)"`)
	aeImageRe     = regexp.MustCompile(`"imgUrl":"((?:[^"\\]|\\.)*)"`)
	aeSalePriceRe = regexp.MustCompile(`"salePrice":\{[^}]*?"cent":(-?\d+)[^}]*?"currencyCode":"([A-Z]{3})"[^}]*?\}`)
	aeAltSalePriceRe = regexp.MustCompile(`"salePrice":\{[^}]*?"currencyCode":"([A-Z]{3})"[^}]*?"cent":(-?\d+)[^}]*?\}`)
	aeOrigPriceRe = regexp.MustCompile(`"originalPrice":\{[^}]*?"cent":(-?\d+)[^}]*?"currencyCode":"([A-Z]{3})"[^}]*?\}`)
	aeDetailURLRe = regexp.MustCompile(`"productDetailUrl":"((?:[^"\\]|\\.)*)"`)
)

const aeBlockSize = 4096

func extractAliExpressProducts(body []byte) []*crawlv1.CatalogItem {
	html := string(body)
	// Constrain to the data-bearing region to avoid catching script ids.
	start := strings.Index(html, "_init_data_= {")
	if start < 0 {
		return nil
	}
	end := strings.Index(html[start:], "</script>")
	scope := html[start:]
	if end > 0 {
		scope = scope[:end]
	}

	seen := map[string]bool{}
	var items []*crawlv1.CatalogItem
	for _, idx := range aeProductIDRe.FindAllStringSubmatchIndex(scope, -1) {
		id := scope[idx[2]:idx[3]]
		if seen[id] {
			continue
		}
		seen[id] = true

		blockEnd := idx[1] + aeBlockSize
		if blockEnd > len(scope) {
			blockEnd = len(scope)
		}
		block := scope[idx[1]:blockEnd]

		title := jsonUnescape(firstGroup(aeTitleRe, block))
		if title == "" {
			continue
		}
		img := normaliseProtocolRelativeURL(jsonUnescape(firstGroup(aeImageRe, block)))
		deepLink := normaliseProtocolRelativeURL(jsonUnescape(firstGroup(aeDetailURLRe, block)))
		if deepLink == "" {
			deepLink = "https://www.aliexpress.com/item/" + id + ".html"
		}

		var priceMinor int64
		var currency string
		if sp := aeSalePriceRe.FindStringSubmatch(block); sp != nil {
			priceMinor, _ = strconv.ParseInt(sp[1], 10, 64)
			currency = sp[2]
		} else if sp := aeAltSalePriceRe.FindStringSubmatch(block); sp != nil {
			priceMinor, _ = strconv.ParseInt(sp[2], 10, 64)
			currency = sp[1]
		} else if op := aeOrigPriceRe.FindStringSubmatch(block); op != nil {
			priceMinor, _ = strconv.ParseInt(op[1], 10, 64)
			currency = op[2]
		}
		if priceMinor == 0 {
			continue
		}

		items = append(items, &crawlv1.CatalogItem{
			SourceId:     id,
			Title:        title,
			PriceMinor:   priceMinor,
			Currency:     currency,
			Availability: "in_stock",
			ImageUrl:     img,
			DeepLink:     deepLink,
			Attrs:        map[string]string{},
		})
	}
	return items
}

func firstGroup(re *regexp.Regexp, s string) string {
	m := re.FindStringSubmatch(s)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

func jsonUnescape(s string) string {
	if s == "" {
		return s
	}
	var out string
	if err := json.Unmarshal([]byte("\""+s+"\""), &out); err == nil {
		return out
	}
	return s
}

func normaliseProtocolRelativeURL(s string) string {
	if strings.HasPrefix(s, "//") {
		return "https:" + s
	}
	return s
}
