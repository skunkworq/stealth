package collect

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

// HTTPRenderer is a static fetch (no JS). Fast fallback / fast-path.
type HTTPRenderer struct {
	Client *http.Client // nil → http.DefaultClient
}

func (r HTTPRenderer) Render(ctx context.Context, url string) (*RawPage, error) {
	client := r.Client
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; stealth-collect/1.0)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("http %d for %s", resp.StatusCode, url)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	final := url
	if resp.Request != nil && resp.Request.URL != nil {
		final = resp.Request.URL.String()
	}
	return &RawPage{HTML: body, FinalURL: final}, nil
}
