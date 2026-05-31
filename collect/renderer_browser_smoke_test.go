//go:build browser

package collect

import (
	"context"
	"testing"
	"time"

	"github.com/skunkworq/stealth/brws/stealth"
)

func TestBrowserRendererSmoke(t *testing.T) {
	client, err := stealth.New()
	if err != nil {
		t.Skipf("stealth client unavailable: %v", err)
	}
	defer func() { _ = client.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	page, err := BrowserRenderer{Client: client}.Render(ctx, "https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(page.HTML) == 0 {
		t.Fatal("no html rendered")
	}
}
