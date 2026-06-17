package dropshippr

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	crawlv1 "github.com/skunkworq/stealth/internal/gen/dropshippr/crawl/v1"
)

func init() {
	Register("amazon_competitor", amazonCompetitor)
}

// amazonCompetitor takes ASINs as seeds, fetches each /dp/<ASIN> page, and
// emits a CompetitorPrice envelope with extracted buy-box price + availability.
//
// Implementation note: this uses the shared dropshippr.Fetcher which wraps
// `engine.New("native", StealthTLS: true)` — uTLS Chrome impersonation
// + matching header profile. Most TLS-fingerprint-based blocks fall to this.
// Sites that gate behind a JS-served Cloudflare interstitial still need to be
// wrapped in `brws/stealth.Client` with AutoSolve.
func amazonCompetitor(ctx context.Context, job *crawlv1.CrawlJob, emit Emitter) error {
	seeds := job.GetSeeds()
	if len(seeds) == 0 {
		return fmt.Errorf("amazon_competitor requires at least one seed (ASIN)")
	}
	tld := job.GetParams()["tld"]
	if tld == "" {
		tld = "com"
	}
	currency := job.GetParams()["currency"]
	if currency == "" {
		currency = currencyForTLD(tld)
	}
	delayMs := 750
	fetcher, err := FetcherFromJob(job.GetEngineHint().String(), job.GetParams())
	if err != nil {
		return err
	}
	// Warm the Amazon session once before any /dp/ASIN hits — bypasses the
	// "automated access" sentinel that fires on cold burst.
	if err := fetcher.WarmUp(ctx, fmt.Sprintf("https://www.amazon.%s/", tld), 5*time.Minute); err != nil {
		emit(&crawlv1.CrawlResult{
			JobId: job.GetId(),
			Kind:  crawlv1.ResultKind_RESULT_KIND_PAGE,
			Payload: &crawlv1.CrawlResult_Page{
				Page: &crawlv1.PageMeta{Url: fmt.Sprintf("https://www.amazon.%s/", tld), Status: 0},
			},
		})
	}

	for i, asin := range seeds {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		asin = strings.TrimSpace(asin)
		if !asinPattern.MatchString(asin) {
			emit(&crawlv1.CrawlResult{
				JobId: job.GetId(),
				Kind:  crawlv1.ResultKind_RESULT_KIND_ERROR,
				Payload: &crawlv1.CrawlResult_Error{
					Error: &crawlv1.CrawlError{
						Url:     asin,
						Code:    "invalid_asin",
						Message: "expected 10-char ASIN",
					},
				},
			})
			continue
		}
		url := fmt.Sprintf("https://www.amazon.%s/dp/%s", tld, asin)
		res, err := fetcher.Get(ctx, url, map[string]string{
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
				Page: &crawlv1.PageMeta{Url: url, Status: int32(status)},
			},
		})
		if err != nil {
			emit(&crawlv1.CrawlResult{
				JobId: job.GetId(),
				Kind:  crawlv1.ResultKind_RESULT_KIND_ERROR,
				Payload: &crawlv1.CrawlResult_Error{
					Error: &crawlv1.CrawlError{
						Url:     url,
						Code:    "fetch_failed",
						Message: err.Error(),
					},
				},
			})
		}
		if err == nil && isAmazonBotChallenge(res.Body) {
			emit(&crawlv1.CrawlResult{
				JobId: job.GetId(),
				Kind:  crawlv1.ResultKind_RESULT_KIND_ERROR,
				Payload: &crawlv1.CrawlResult_Error{
					Error: &crawlv1.CrawlError{
						Url:     url,
						Code:    "anti_bot_challenge",
						Message: "Amazon served robot-check interstitial; native engine cannot pass — upgrade to brws/stealth chromium + AutoSolve",
					},
				},
			})
		} else if err == nil {
			price, observedCurrency, seller, prime, inStock := extractAmazonOffer(res.Body)
			effectiveCurrency := currency
			if observedCurrency != "" {
				effectiveCurrency = observedCurrency
			}
			emit(&crawlv1.CrawlResult{
				JobId: job.GetId(),
				Kind:  crawlv1.ResultKind_RESULT_KIND_ITEM,
				Payload: &crawlv1.CrawlResult_CompetitorPrice{
					CompetitorPrice: &crawlv1.CompetitorPrice{
						Asin:         asin,
						PriceMinor:   price,
						Currency:     effectiveCurrency,
						BuyBoxSeller: seller,
						Prime:        prime,
						InStock:      inStock,
						CapturedAt:   time.Now().UTC().Format(time.RFC3339),
						SourceUrl:    url,
					},
				},
			})
		}
		if i < len(seeds)-1 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(delayMs) * time.Millisecond):
			}
		}
	}
	return nil
}

var asinPattern = regexp.MustCompile(`^[A-Z0-9]{10}$`)

// isAmazonBotChallenge detects the lightweight HTML Amazon returns when it has
// flagged the request as automated (the "Type the characters you see..." page).
// The body is ~5KB, the real product page is ~1MB+, and it mentions captcha
// or automated access. We treat this as a fetch failure rather than a parse
// failure so callers can distinguish.
func isAmazonBotChallenge(body []byte) bool {
	if len(body) > 50_000 {
		return false
	}
	s := string(body)
	return strings.Contains(s, "automated access")
}

func currencyForTLD(tld string) string {
	switch strings.ToLower(tld) {
	case "com":
		return "USD"
	case "co.uk":
		return "GBP"
	case "de", "fr", "it", "es", "nl":
		return "EUR"
	case "ca":
		return "CAD"
	case "com.au":
		return "AUD"
	case "co.jp":
		return "JPY"
	}
	return "USD"
}

// Amazon renders the buy-box price as e.g. <span class="a-offscreen">$24.99</span>
// inside <span class="a-price">. We grab the first such span. This regex is
// resilient to whitespace but not to layout overhauls; selectors get updated as
// Amazon's templates evolve.
var (
	// We can't rely on the .a-price parent always wrapping a-offscreen — the
	// chromium-rendered DOM sometimes inlines the offscreen span under a
	// styled <span color="base">. Instead, match every a-offscreen and pick
	// the first one that looks like a currency value.
	// Locate `<span class="a-price ...>` price blocks, then within each block
	// grab the displayed value out of aria-hidden / a-offscreen. We skip blocks
	// flagged data-a-strike (the "was" price).
	pricePackRe   = regexp.MustCompile(`<span class="a-price[^"]*"[^>]*>`)
	priceInnerRe  = regexp.MustCompile(`<span aria-hidden="true">([^<]+)</span>|<span class="a-offscreen">([^<]+)</span>`)
	priceValueRe  = regexp.MustCompile(`^\s*(?:[A-Z]{2,4}\s*)?[$£€¥₹]?\s*\d{1,9}(?:[.,]\d{1,2})?\s*(?:[A-Z]{2,4}\s*)?$`)
	sellerRe      = regexp.MustCompile(`(?s)id="sellerProfileTriggerId"[^>]*>([^<]+)<`)
	merchantRe    = regexp.MustCompile(`(?s)id="merchant-info"[^>]*>(.*?)</`)
	primeRe       = regexp.MustCompile(`(?i)class="[^"]*a-icon-prime`)
	availabilityRe = regexp.MustCompile(`(?s)class="[^"]*primary-availability-message[^"]*"[^>]*>([^<]+)<|id="availability"[^>]*>\s*<span[^>]*>([^<]+)<`)
)

func extractAmazonOffer(html []byte) (priceMinor int64, currency, seller string, prime, inStock bool) {
	// Bail before extraction if the page explicitly says the listing is dead.
	// Otherwise a "Compare with similar items" carousel price leaks into the
	// buy-box field (e.g. on B07XJ8C8F5 we'd emit $55.22 for a product Amazon
	// is currently not selling at all).
	if isAmazonUnavailable(html) {
		return 0, "", "", false, false
	}
	priceMinor, currency = pickBuyBoxPrice(html)
	if m := sellerRe.FindSubmatch(html); m != nil {
		seller = strings.TrimSpace(string(m[1]))
	} else if m := merchantRe.FindSubmatch(html); m != nil {
		seller = strings.TrimSpace(stripTags(string(m[1])))
	}
	prime = primeRe.Match(html)
	if m := availabilityRe.FindSubmatch(html); m != nil {
		raw := m[1]
		if len(raw) == 0 {
			raw = m[2]
		}
		txt := strings.ToLower(strings.TrimSpace(string(raw)))
		switch {
		case strings.Contains(txt, "cannot be shipped"):
			inStock = false
		case strings.Contains(txt, "unavailable"):
			inStock = false
		case strings.Contains(txt, "out of stock"):
			inStock = false
		case strings.Contains(txt, "in stock") || strings.Contains(txt, "available"):
			inStock = true
		default:
			// Default to true when a real price was found and no negative signal.
			inStock = priceMinor > 0
		}
	} else if priceMinor > 0 {
		inStock = true
	}
	return
}

// buyBoxContainers are the DOM regions Amazon uses for the live buy-box. We
// scope price extraction to these so unrelated `a-price` widgets (compare-
// with-similar carousels, frequently-bought-together strips) cannot leak in.
var buyBoxContainers = []string{
	`id="corePriceDisplay_desktop_feature_div"`,
	`id="corePrice_feature_div"`,
	`id="apex_desktop"`,
	`id="apex_offerDisplay_desktop"`,
	`id="buybox"`,
	`id="desktop_buybox"`,
	`id="qualifiedBuybox"`,
}

func extractBuyBoxRegion(html []byte) []byte {
	for _, anchor := range buyBoxContainers {
		start := strings.Index(string(html), anchor)
		if start < 0 {
			continue
		}
		// Take ~32KB after the anchor — enough for the full buy box block,
		// far short of nearby carousels.
		end := start + 32_000
		if end > len(html) {
			end = len(html)
		}
		return html[start:end]
	}
	return nil
}

// isAmazonUnavailable looks for an unavailability message inside Amazon's
// availability container — NOT page-wide. The naive page-wide search false-
// positives on the i18n string dictionary that's embedded in every product
// page ("currentlyUnavailableMessage":"Currently unavailable.").
func isAmazonUnavailable(html []byte) bool {
	region := extractAvailabilityRegion(html)
	if region == nil {
		return false
	}
	s := string(region)
	for _, marker := range []string{
		"Currently unavailable",
		"Currently Unavailable",
		"this item is unavailable",
		"We don't know when or if this item will be back in stock",
		">Unavailable<",
	} {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}

func extractAvailabilityRegion(html []byte) []byte {
	for _, anchor := range []string{
		`id="availability"`,
		`id="outOfStock"`,
		`id="availability_feature_div"`,
	} {
		start := strings.Index(string(html), anchor)
		if start < 0 {
			continue
		}
		end := start + 4_000
		if end > len(html) {
			end = len(html)
		}
		return html[start:end]
	}
	return nil
}

// pickBuyBoxPrice returns (priceMinor, ISO-4217 currency) for the buy-box price.
// Returns (0, "") if no candidate is found. Scopes the search to the buy-box
// region when one is detectable, falling back to the full document only as a
// last resort (and only for `data-a-color="base"` price spans).
func pickBuyBoxPrice(html []byte) (int64, string) {
	region := extractBuyBoxRegion(html)
	if region != nil {
		if p, c := pickBuyBoxPriceIn(region, false); p > 0 {
			return p, c
		}
	}
	return pickBuyBoxPriceIn(html, true)
}

func pickBuyBoxPriceIn(html []byte, requireBaseColor bool) (int64, string) {
	for _, idx := range pricePackRe.FindAllIndex(html, -1) {
		openerStart, openerEnd := idx[0], idx[1]
		opener := string(html[openerStart:openerEnd])
		if strings.Contains(opener, `data-a-strike="true"`) {
			continue
		}
		if requireBaseColor && !strings.Contains(opener, `data-a-color="base"`) {
			continue
		}
		blockEnd := openerEnd + 600
		if blockEnd > len(html) {
			blockEnd = len(html)
		}
		block := string(html[openerEnd:blockEnd])
		for _, mm := range priceInnerRe.FindAllStringSubmatch(block, 2) {
			candidate := strings.TrimSpace(mm[1])
			if candidate == "" {
				candidate = strings.TrimSpace(mm[2])
			}
			if candidate == "" || len(candidate) > 16 {
				continue
			}
			if !priceValueRe.MatchString(candidate) {
				continue
			}
			n := parseAmazonPrice(candidate)
			if n <= 0 {
				continue
			}
			return n, detectCurrency(candidate)
		}
	}
	return 0, ""
}

// detectCurrency reads an ISO code (e.g. "AUD62.14" → "AUD") or symbol
// (e.g. "$62.14" → "USD") from a displayed price string.
func detectCurrency(s string) string {
	s = strings.TrimSpace(s)
	for _, c := range []string{"AUD", "USD", "GBP", "EUR", "CAD", "NZD", "JPY", "INR"} {
		if strings.HasPrefix(s, c) || strings.HasSuffix(s, c) {
			return c
		}
	}
	switch {
	case strings.Contains(s, "$"):
		return "USD"
	case strings.Contains(s, "£"):
		return "GBP"
	case strings.Contains(s, "€"):
		return "EUR"
	case strings.Contains(s, "¥"):
		return "JPY"
	case strings.Contains(s, "₹"):
		return "INR"
	}
	return ""
}

func parseAmazonPrice(s string) int64 {
	// Strip currency symbols and commas.
	cleaned := strings.Map(func(r rune) rune {
		if (r >= '0' && r <= '9') || r == '.' {
			return r
		}
		return -1
	}, s)
	return parseDecimalToMinor(cleaned)
}

func stripTags(s string) string {
	out := make([]rune, 0, len(s))
	inTag := false
	for _, r := range s {
		switch {
		case r == '<':
			inTag = true
		case r == '>':
			inTag = false
		case !inTag:
			out = append(out, r)
		}
	}
	return strings.Join(strings.Fields(string(out)), " ")
}
