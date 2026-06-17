package dropshippr

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	crawlv1 "github.com/skunkworq/stealth/internal/gen/dropshippr/crawl/v1"
)

func init() {
	Register("shopify_discovery", shopifyDiscovery)
}

// shopifyDiscovery walks each seed storefront's public /products.json endpoint
// (Shopify exposes this on every storefront by default). It paginates until a
// page returns zero products or until max_pages is reached.
//
// Seed format: bare host, e.g. "allbirds.com" or "shop.allbirds.com".
func shopifyDiscovery(ctx context.Context, job *crawlv1.CrawlJob, emit Emitter) error {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	maxPages := int(job.GetMaxPages())
	if maxPages <= 0 {
		maxPages = 5
	}
	pageSize := 250
	if v, ok := job.GetParams()["page_size"]; ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 250 {
			pageSize = n
		}
	}

	seeds := job.GetSeeds()
	if len(seeds) == 0 {
		return fmt.Errorf("shopify_discovery requires at least one seed (storefront host)")
	}

	for _, raw := range seeds {
		host := normalizeShopifyHost(raw)
		if host == "" {
			continue
		}
		for page := 1; page <= maxPages; page++ {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			pageURL := fmt.Sprintf("https://%s/products.json?limit=%d&page=%d", host, pageSize, page)
			items, status, err := fetchShopifyPage(ctx, client, pageURL)
			emit(&crawlv1.CrawlResult{
				JobId: job.GetId(),
				Kind:  crawlv1.ResultKind_RESULT_KIND_PAGE,
				Payload: &crawlv1.CrawlResult_Page{
					Page: &crawlv1.PageMeta{Url: pageURL, Status: int32(status)},
				},
			})
			if err != nil {
				emit(&crawlv1.CrawlResult{
					JobId: job.GetId(),
					Kind:  crawlv1.ResultKind_RESULT_KIND_ERROR,
					Payload: &crawlv1.CrawlResult_Error{
						Error: &crawlv1.CrawlError{
							Url:     pageURL,
							Code:    "fetch_failed",
							Message: err.Error(),
						},
					},
				})
				break
			}
			if len(items) == 0 {
				break
			}
			now := time.Now().UTC().Format(time.RFC3339)
			for _, p := range items {
				item := shopifyProductToCatalogItem(host, p, now)
				emit(&crawlv1.CrawlResult{
					JobId:   job.GetId(),
					Kind:    crawlv1.ResultKind_RESULT_KIND_ITEM,
					Payload: &crawlv1.CrawlResult_CatalogItem{CatalogItem: item},
				})
			}
			if len(items) < pageSize {
				break
			}
		}
	}
	return nil
}

func normalizeShopifyHost(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimSuffix(s, "/")
	if s == "" {
		return ""
	}
	// Trim trailing path if any was provided.
	if i := strings.Index(s, "/"); i >= 0 {
		s = s[:i]
	}
	return s
}

type shopifyProduct struct {
	ID          int64  `json:"id"`
	Title       string `json:"title"`
	Handle      string `json:"handle"`
	Vendor      string `json:"vendor"`
	ProductType string `json:"product_type"`
	BodyHTML    string `json:"body_html"`
	Images      []struct {
		Src string `json:"src"`
	} `json:"images"`
	Variants []struct {
		ID        int64  `json:"id"`
		Sku       string `json:"sku"`
		Price     string `json:"price"`
		Available bool   `json:"available"`
		Title     string `json:"title"`
	} `json:"variants"`
}

func fetchShopifyPage(ctx context.Context, client *http.Client, url string) ([]shopifyProduct, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	// Public endpoint, but some hosts gate by UA.
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json,text/plain,*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, resp.StatusCode, fmt.Errorf("http %d", resp.StatusCode)
	}
	var payload struct {
		Products []shopifyProduct `json:"products"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("decode products.json: %w", err)
	}
	return payload.Products, resp.StatusCode, nil
}

func shopifyProductToCatalogItem(host string, p shopifyProduct, fetchedAt string) *crawlv1.CatalogItem {
	priceMinor := int64(0)
	currency := ""
	available := false
	for _, v := range p.Variants {
		if v.Available {
			available = true
		}
		if priceMinor == 0 && v.Price != "" {
			priceMinor = parseDecimalToMinor(v.Price)
		}
	}
	availability := "out_of_stock"
	if available {
		availability = "in_stock"
	}
	img := ""
	if len(p.Images) > 0 {
		img = p.Images[0].Src
	}
	attrs := map[string]string{}
	if p.Vendor != "" {
		attrs["vendor"] = p.Vendor
	}
	if p.ProductType != "" {
		attrs["product_type"] = p.ProductType
	}
	if len(p.Variants) > 0 {
		attrs["variant_count"] = strconv.Itoa(len(p.Variants))
	}
	return &crawlv1.CatalogItem{
		SourceId:     strconv.FormatInt(p.ID, 10),
		Title:        p.Title,
		Subtitle:     p.Vendor,
		PriceMinor:   priceMinor,
		Currency:     currency,
		Availability: availability,
		ImageUrl:     img,
		DeepLink:     fmt.Sprintf("https://%s/products/%s", host, p.Handle),
		Attrs:        attrs,
		FetchedAt:    fetchedAt,
	}
}

func parseDecimalToMinor(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	dot := strings.Index(s, ".")
	if dot < 0 {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return 0
		}
		return n * 100
	}
	whole := s[:dot]
	frac := s[dot+1:]
	if len(frac) > 2 {
		frac = frac[:2]
	}
	for len(frac) < 2 {
		frac += "0"
	}
	w, _ := strconv.ParseInt(whole, 10, 64)
	f, _ := strconv.ParseInt(frac, 10, 64)
	return w*100 + f
}
