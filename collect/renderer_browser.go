package collect

import (
	"context"

	"github.com/skunkworq/stealth/brws/stealth"
)

// BrowserRenderer renders a URL with stealth's full Chrome (JS execution,
// Cloudflare/CAPTCHA handling). The *stealth.Client is injected by the caller,
// which owns Chromium configuration. This is the production-default Renderer.
type BrowserRenderer struct {
	Client *stealth.Client
}

func (b BrowserRenderer) Render(ctx context.Context, url string) (*RawPage, error) {
	resp, err := b.Client.Navigate(ctx, url)
	if err != nil {
		return nil, err
	}
	final := resp.FinalURL
	if final == "" {
		final = url
	}
	return &RawPage{HTML: resp.Body, FinalURL: final}, nil
}
