// Package integration provides the convergence layer between stealth browser
// automation and semantic web extraction.
//
// This package bridges:
//   - brws/stealth (browser automation, CAPTCHA solving, fingerprinting)
//   - brws/semantic (content extraction, compression, vector search)
//   - brws/pipeline (crawling, instrumentation)
//
// # Architecture
//
// The integration layer provides three main components:
//
//  1. SemanticNavigator - Navigate pages using semantic understanding
//  2. SemanticFormFiller - Auto-fill forms from semantic schema
//  3. SmartCrawler - Crawl with semantic prioritization
//
// # Quick Start
//
// Basic semantic navigation:
//
//	client, _ := stealth.New()
//	pipe, _ := pipeline.New(config)
//
//	nav := integration.NewSemanticNavigator(client, pipe)
//	result, _ := nav.NavigateWithIntent(ctx, url, "find login form")
//
// # Semantic Form Filling
//
// Auto-detect and fill forms:
//
//	filler := integration.NewSemanticFormFiller(client)
//	_ = filler.Fill(ctx, "https://example.com/signup", map[string]string{
//	    "email": "user@example.com",
//	    "name":  "John Doe",
//	})
//
// # Smart Crawling
//
// Crawl with semantic prioritization:
//
//	crawler := integration.NewSmartCrawler(client, pipe)
//	results := crawler.Crawl(ctx, seedURLs, "find product pages")
package integration
