package dropshippr

import (
	"context"
	"time"

	crawlv1 "github.com/skunkworq/stealth/internal/gen/dropshippr/crawl/v1"
)

func init() {
	Register("noop_echo", noopEcho)
}

// noopEcho is the round-trip smoke spider. It emits one CatalogItem per seed
// without touching the network, so the TS↔Go boundary can be exercised in
// CI/dev without external dependencies.
func noopEcho(_ context.Context, job *crawlv1.CrawlJob, emit Emitter) error {
	now := time.Now().UTC().Format(time.RFC3339)
	for i, seed := range job.GetSeeds() {
		emit(&crawlv1.CrawlResult{
			JobId: job.GetId(),
			Kind:  crawlv1.ResultKind_RESULT_KIND_ITEM,
			Payload: &crawlv1.CrawlResult_CatalogItem{
				CatalogItem: &crawlv1.CatalogItem{
					SourceId:  seed,
					Title:     "echo: " + seed,
					Subtitle:  "noop spider",
					DeepLink:  seed,
					FetchedAt: now,
					Attrs: map[string]string{
						"index": itoa(i),
					},
				},
			},
		})
	}
	return nil
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}
