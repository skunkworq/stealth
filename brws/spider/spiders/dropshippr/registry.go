// Package dropshippr hosts spiders that feed the dropshippr discovery
// pipeline. Each spider is registered by string name; the crawl-job-runner
// binary dispatches incoming CrawlJob requests by spider_name.
package dropshippr

import (
	"context"
	"fmt"
	"sync"

	crawlv1 "github.com/skunkworq/stealth/internal/gen/dropshippr/crawl/v1"
)

// Emitter is how a spider streams results back to the caller. Each call writes
// one framed CrawlResult to stdout (in the runner). DONE is emitted by the
// runner itself, not by the spider.
type Emitter func(*crawlv1.CrawlResult)

// Spider executes a CrawlJob, calling emit for every produced result envelope
// (items, page meta, errors). It MUST NOT emit a DONE envelope; the runner
// adds that after the spider returns. Returning a non-nil error converts to
// an ERROR envelope before DONE.
type Spider func(ctx context.Context, job *crawlv1.CrawlJob, emit Emitter) error

var (
	mu       sync.RWMutex
	registry = map[string]Spider{}
)

// Register installs a spider under name. Idempotent overwrite — last writer wins,
// which keeps test harnesses simple.
func Register(name string, s Spider) {
	mu.Lock()
	defer mu.Unlock()
	registry[name] = s
}

// Lookup returns the spider for name or an error if unknown.
func Lookup(name string) (Spider, error) {
	mu.RLock()
	defer mu.RUnlock()
	s, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("spider %q not registered", name)
	}
	return s, nil
}

// Names returns the list of registered spider names (for diagnostics).
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	return out
}
