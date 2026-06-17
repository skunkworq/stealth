package dropshippr

import (
	"os"
	"path/filepath"
	"testing"
)

// Fixtures were captured live via CDP through ../scripts/start-crawler-chrome.sh
// (../testdata/*.html). Re-capture with:
//   curl-like dump_amzn_cdp via tmp/dump_cdp2.go in dropshippr docs/crawler.md
// when Amazon ships a layout change that breaks these tests.

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	p := filepath.Join("testdata", name)
	data, err := os.ReadFile(p)
	if err != nil {
		t.Skipf("fixture %s not present: %v", p, err)
	}
	return data
}

func TestExtractAmazonOffer_AvailableBuyBox(t *testing.T) {
	html := loadFixture(t, "amazon-available.html")
	price, currency, _, prime, _ := extractAmazonOffer(html)
	if price != 6214 {
		t.Errorf("priceMinor: got %d want 6214", price)
	}
	if currency != "AUD" {
		t.Errorf("currency: got %q want AUD", currency)
	}
	if !prime {
		t.Errorf("prime: got false, want true")
	}
}

func TestExtractAmazonOffer_Unavailable_NoSpilloverPrice(t *testing.T) {
	// B07XJ8C8F5 displays "Currently unavailable" but has a "Compare with
	// similar items" carousel that contains a-price spans for OTHER products.
	// Before the buy-box scoping + unavailable-sentinel fix, the extractor
	// would emit that carousel price as the buy-box price.
	html := loadFixture(t, "amazon-unavailable.html")
	price, _, _, _, inStock := extractAmazonOffer(html)
	if price != 0 {
		t.Errorf("priceMinor: got %d want 0 (page is currently unavailable)", price)
	}
	if inStock {
		t.Errorf("inStock: got true, want false")
	}
}

func TestIsAmazonUnavailable_DoesNotFalsePositiveOnI18nString(t *testing.T) {
	// The i18n dictionary baked into every Amazon page contains the literal
	// string "currentlyUnavailableMessage":"Currently unavailable.". A naive
	// page-wide string match false-positives even on in-stock products.
	html := loadFixture(t, "amazon-available.html")
	if isAmazonUnavailable(html) {
		t.Errorf("isAmazonUnavailable false-positive on available product page")
	}
}

func TestIsAmazonUnavailable_DetectsRealUnavailability(t *testing.T) {
	html := loadFixture(t, "amazon-unavailable.html")
	if !isAmazonUnavailable(html) {
		t.Errorf("isAmazonUnavailable missed the Currently unavailable banner")
	}
}
