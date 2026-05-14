// Package integration bridges stealth browser automation with semantic web
// extraction for intent-driven crawling at scale.
//
// It sits above both stealth/ (browser automation, CAPTCHA solving,
// fingerprinting) and content/semantic (semantic tree parsing, compression,
// vector search), combining them into components that operate on semantic
// page representations rather than raw HTML.
//
// # Components
//
//   - Navigator         — navigates to a URL with a semantic intent (e.g.
//                         "find the login form"); uses the semantic tree to
//                         locate and interact with the target element.
//
//   - SmartNavigator    — multi-step navigation with semantic-tree diffing
//                         and backtracking when a step fails.
//
//   - FormFiller        — detects and fills forms using semantic field
//                         matching; accepts a map[string]string of field
//                         labels to values.
//
//   - ChangeDetector    — compares semantic trees across two visits to the
//                         same URL and reports meaningful content changes,
//                         ignoring structural noise.
//
//   - DataExtractor     — pulls structured data from a semantic tree using
//                         caller-supplied schema templates.
//
//   - AdaptiveCrawler   — steers the crawl frontier using semantic quality
//                         signals (extraction yield, freshness, challenge
//                         rate). Reads strategy hints from ml/adaptive.
//
//   - SessionManager    — manages a pool of stealth sessions across
//                         AdaptiveCrawler workers; retires blocked sessions.
//
//   - Orchestrator      — top-level coordinator that wires the above
//                         components into a full crawl run.
//
//   - Monitoring        — emits crawl-specific metrics: pages/s, extraction
//                         quality score, challenge rate per domain.
//
// # Relationship to crawl/spider
//
// crawl/spider is a general-purpose high-throughput crawler that operates on
// raw HTTP responses (no live browser required). Use it when JS rendering and
// anti-bot handling are not needed.
//
// crawl/integration requires a live stealth browser and the semantic pipeline.
// Use it when you need intent-driven navigation, form interaction, or
// semantic-quality-driven frontier management.
//
// # Quick start
//
//	client, _ := stealth.NewAdaptive(stealth.WithChallengeSolver("capsolver", key))
//	pipe := understand.NewPipeline(understand.DefaultConfig())
//
//	crawler := integration.NewAdaptiveCrawler(client, pipe)
//	crawler.Crawl(ctx, []string{"https://shop.com"}, "find product listings")
package integration
