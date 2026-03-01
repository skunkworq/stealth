# Stealth Platform - Feature Parity TODO

Based on analysis of Scrapy and Scrapling frameworks.

## Priority 0 - Core Framework

### P0.1 Spider Framework
- [x] `brws/spider/spider.go` - Base Spider with callbacks
- [x] `brws/spider/scheduler.go` - Priority queue with disk persistence
- [x] `brws/spider/settings.go` - Settings interface with defaults
- [x] `brws/spider/crawl.go` - CrawlSpider with LinkExtractor rules
- [x] `brws/spider/sitemap.go` - SitemapSpider for sitemap-based crawling
- [ ] `brws/spider/response.go` - Response with CSS/XPath selectors

### P0.2 Item Pipeline
- [x] `brws/pipeline/manager.go` - Pipeline manager
- [x] `brws/pipeline/media.go` - Built-in media pipeline

---

## Priority 1 - Essential Components

### P1.1 Link Extraction
- [x] `brws/extractors/links.go` - LinkExtractor with CSS/XPath
- [x] `brws/extractors/sitemap.go` - Sitemap parsing

### P1.2 Middleware System
- [x] `brws/middleware/manager.go` - Middleware interfaces
- [x] `brws/middleware/common.go` - Retry, Redirect, UserAgent middlewares
- [x] `brws/middleware/cookies.go` - Cookie handling
- [x] `brws/middleware/robotstxt.go` - Robots.txt compliance

### P1.3 Settings System
- [x] `brws/spider/settings.go` - Priority-based settings
- [x] `brws/spider/settings.go` - Default configuration values

### P1.4 Request/Response Objects
- [ ] `brws/engine/request_advanced.go` - FormRequest, JsonRequest
- [ ] `brws/engine/response_types.go` - TextResponse, HtmlResponse

---

## Priority 2 - CLI & UX

### P2.1 Signals
- [x] `brws/signals/manager.go` - Event emitter system
- [x] `brws/signals/types.go` - Signal types

### P2.2 Commands
- [ ] `cmd/stealth/spider.go` - Spider command
- [ ] `cmd/stealth/shell.go` - Interactive shell
- [ ] `cmd/stealth/list.go` - List spiders

### P2.3 Data Export
- [x] `brws/export/exporter.go` - Exporter interface
- [x] `brws/export/json.go` - JSON exporter
- [x] `brws/export/csv.go` - CSV exporter

---

## Priority 3 - Advanced Features

### P3.1 Duplicate Filtering
- [x] `brws/filter/dupe.go` - Request deduplication

### P3.2 Extension System
- [x] `brws/extension/manager.go` - Extension loader

### P3.3 Adaptive Parsing (Scrapling Feature)
- [x] `brws/adaptive/tracker.go` - Element property tracking
- [x] `brws/adaptive/storage.go` - SQLite persistence

---

## Priority 4 - Nice to Have

### P4.1 No-Code Extraction
- [ ] `cmd/extract/main.go` - CLI extraction tool

### P4.2 Stealth Enhancements
- [ ] Cloudflare/antibot bypass integration
- [ ] Canvas noise generation
- [ ] WebRTC leak prevention
- [ ] Enhanced headless detection patches
