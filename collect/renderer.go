package collect

import "context"

// RawPage is the rendered output of a single URL fetch.
type RawPage struct {
	HTML     []byte
	FinalURL string
}

// Renderer fetches a URL and returns its (possibly JS-rendered) HTML. Pluggable
// so callers can choose stealth-browser rendering or a plain HTTP GET, and so
// tests can inject a fake.
type Renderer interface {
	Render(ctx context.Context, url string) (*RawPage, error)
}
