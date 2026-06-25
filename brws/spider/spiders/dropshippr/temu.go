package dropshippr

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	crawlv1 "github.com/skunkworq/stealth/internal/gen/dropshippr/crawl/v1"
)

func init() {
	Register("temu", temuSearch)
}

// temuSearch hits /search_result.html?search_key=<seed> and extracts product
// cards from the embedded `window.rawData` JSON blob. Like AliExpress, Temu
// serves the search-result data inline so JS execution is not strictly needed.
//
// Important: Temu is aggressive about bot detection — expect the native engine
// to be blocked from non-residential IPs. Use --engine CHROMIUM (or supply a
// residential proxy via params["proxy"]) for live runs.
func temuSearch(ctx context.Context, job *crawlv1.CrawlJob, emit Emitter) error {
	seeds := job.GetSeeds()
	if len(seeds) == 0 {
		return fmt.Errorf("temu requires at least one seed (search query)")
	}
	fetcher, err := FetcherFromJob(job.GetEngineHint().String(), job.GetParams())
	if err != nil {
		return err
	}

	maxPages := int(job.GetMaxPages())
	if maxPages <= 0 {
		maxPages = 1
	}

	for _, query := range seeds {
		for page := 1; page <= maxPages; page++ {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			u := fmt.Sprintf(
				"https://www.temu.com/search_result.html?search_key=%s&page=%d",
				url.QueryEscape(query), page,
			)
			res, err := fetcher.Get(ctx, u, map[string]string{
				"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
				"Accept-Language": "en-US,en;q=0.9",
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
						Error: &crawlv1.CrawlError{Url: u, Code: "fetch_failed", Message: err.Error()},
					},
				})
				break
			}
			if isTemuBotChallenge(res.Body) {
				emit(&crawlv1.CrawlResult{
					JobId: job.GetId(),
					Kind:  crawlv1.ResultKind_RESULT_KIND_ERROR,
					Payload: &crawlv1.CrawlResult_Error{
						Error: &crawlv1.CrawlError{
							Url:     u,
							Code:    "anti_bot_challenge",
							Message: "Temu served a verification interstitial — upgrade to ENGINE_CHROMIUM or supply a residential proxy",
						},
					},
				})
				break
			}
			items := extractTemuProducts(res.Body)
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

var (
	temuGoodsIDRe  = regexp.MustCompile(`"goods_id":\s*"?(\d{8,})"?`)
	temuTitleRe    = regexp.MustCompile(`"goods_name":"((?:[^"\\]|\\.)*)"`)
	temuPriceRe    = regexp.MustCompile(`"price_str":"([^"]+)"|"price":\{[^}]*"price":(\d+)`)
	temuImageRe    = regexp.MustCompile(`"hd_thumb_url":"((?:[^"\\]|\\.)*)"|"thumb_url":"((?:[^"\\]|\\.)*)"`)
	temuCurrencyRe = regexp.MustCompile(`"currency":"([A-Z]{3})"`)
)

func extractTemuProducts(body []byte) []*crawlv1.CatalogItem {
	html := string(body)
	start := strings.Index(html, "window.rawData")
	if start < 0 {
		start = strings.Index(html, "\"goods_id\"")
		if start < 0 {
			return nil
		}
	}
	scope := html[start:]
	currency := firstGroup(temuCurrencyRe, scope)
	if currency == "" {
		currency = "USD"
	}

	seen := map[string]bool{}
	var items []*crawlv1.CatalogItem
	for _, idx := range temuGoodsIDRe.FindAllStringSubmatchIndex(scope, -1) {
		id := scope[idx[2]:idx[3]]
		if seen[id] {
			continue
		}
		seen[id] = true

		blockEnd := idx[1] + 3000
		if blockEnd > len(scope) {
			blockEnd = len(scope)
		}
		block := scope[idx[1]:blockEnd]

		title := jsonUnescape(firstGroup(temuTitleRe, block))
		if title == "" {
			continue
		}
		img := normaliseProtocolRelativeURL(jsonUnescape(temuFirstImage(block)))

		priceMinor := int64(0)
		if m := temuPriceRe.FindStringSubmatch(block); m != nil {
			if m[1] != "" {
				priceMinor = parseDisplayPriceToMinor(m[1])
			} else if m[2] != "" {
				n, _ := strconv.ParseInt(m[2], 10, 64)
				priceMinor = n
			}
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
			DeepLink:     fmt.Sprintf("https://www.temu.com/goods.html?goods_id=%s", id),
			Attrs:        map[string]string{},
		})
	}
	return items
}

func temuFirstImage(block string) string {
	if m := temuImageRe.FindStringSubmatch(block); m != nil {
		if m[1] != "" {
			return m[1]
		}
		return m[2]
	}
	return ""
}

func parseDisplayPriceToMinor(s string) int64 {
	digits := make([]rune, 0, len(s))
	for _, r := range s {
		if (r >= '0' && r <= '9') || r == '.' || r == ',' {
			if r == ',' {
				continue
			}
			digits = append(digits, r)
		}
	}
	return parseDecimalToMinor(string(digits))
}

func isTemuBotChallenge(body []byte) bool {
	if len(body) > 200_000 {
		return false
	}
	s := strings.ToLower(string(body))
	return strings.Contains(s, "verifying you are human") ||
		strings.Contains(s, "verify before continue") ||
		strings.Contains(s, "geetest")
}
