package dropshippr

import (
	"context"
	"fmt"

	crawlv1 "github.com/skunkworq/stealth/internal/gen/dropshippr/crawl/v1"
)

func init() {
	Register("cj", cjStub)
	Register("spocket", spocketStub)
	Register("dsers", dsersStub)
}

// The following three spiders are registered so the CLI / TS layer can address
// them, but their implementations require work that the native HTTP engine
// cannot do alone:
//
//   * cj       — public list pages are SSR-disabled (Next.js client render).
//                Plan: switch to ENGINE_CHROMIUM and parse window.__NEXT_DATA__
//                JSON blob; OR call cjdropshipping.com's public listing API
//                once reverse-engineered. ~half day.
//
//   * spocket  — full catalog is behind /login. Plan: implement session
//                bootstrap via brws/session + brws/stealth form filling,
//                store credentials via params["session_ref"]. ~1 day.
//
//   * dsers    — even with a DSers account, their import catalog is gated
//                behind a Shopify OAuth connection. Plan: defer until we
//                actually need a DSers-specific dataset (CJ + Spocket cover
//                95% of the same supplier pool). ~1 day plus OAuth setup.
//
// Each stub emits a clear NOT_IMPLEMENTED error so callers can distinguish
// "spider unknown" (Lookup error) from "spider known but not yet built".

func cjStub(_ context.Context, job *crawlv1.CrawlJob, emit Emitter) error {
	return notImplementedStub(job, emit, "cj",
		"CJ Dropshipping listing is client-rendered. Re-implement using ENGINE_CHROMIUM "+
			"and extract from window.__NEXT_DATA__, or call the public list API directly.")
}

func spocketStub(_ context.Context, job *crawlv1.CrawlJob, emit Emitter) error {
	return notImplementedStub(job, emit, "spocket",
		"Spocket catalog is behind /login. Wire brws/session + brws/stealth form login "+
			"using params[\"session_ref\"] / params[\"username\"] / params[\"password\"].")
}

func dsersStub(_ context.Context, job *crawlv1.CrawlJob, emit Emitter) error {
	return notImplementedStub(job, emit, "dsers",
		"DSers requires a Shopify-linked DSers account. Implement OAuth bootstrap, then "+
			"call DSers' internal /api/catalog endpoints with the resulting session cookie.")
}

func notImplementedStub(job *crawlv1.CrawlJob, emit Emitter, name, plan string) error {
	emit(&crawlv1.CrawlResult{
		JobId: job.GetId(),
		Kind:  crawlv1.ResultKind_RESULT_KIND_ERROR,
		Payload: &crawlv1.CrawlResult_Error{
			Error: &crawlv1.CrawlError{
				Url:     "",
				Code:    "not_implemented",
				Message: fmt.Sprintf("spider %q is registered but not yet implemented: %s", name, plan),
			},
		},
	})
	return nil
}
