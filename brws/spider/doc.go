// Package spider provides a flexible web crawling framework.
//
// The spider package implements a Scrapy-inspired crawling architecture with:
//   - Concurrent request processing with configurable workers
//   - Priority-based URL scheduling with deduplication
//   - Middleware chain for request/response processing
//   - Item pipelines for data processing
//   - Built-in statistics tracking
//
// # Architecture
//
//	The spider framework follows this flow:
//
//	Spider.Start() → Request Queue → Workers → Response → Parse → New Requests
//	                   ↓                              ↓
//	               Scheduler                     Item Pipelines
//	                   ↓                              ↓
//	              Deduplication                  Middleware Chain
//
// # Quick Start
//
// Define a spider:
//
//	type MySpider struct {
//	    name string
//	}
//
//	func (s *MySpider) Name() string { return s.name }
//
//	func (s *MySpider) Start() []*spider.Request {
//	    return []*spider.Request{
//	        spider.NewRequest("https://example.com", s.Parse),
//	    }
//	}
//
//	func (s *MySpider) Parse(resp spider.Response) []*spider.Request {
//	    // Extract links
//	    links := resp.GetLinks()
//	    var requests []*spider.Request
//	    for _, link := range links {
//	        requests = append(requests, spider.NewRequest(link, s.Parse))
//	    }
//	    return requests
//	}
//
// Run the crawler:
//
//	s := &MySpider{name: "example"}
//	crawler := spider.NewCrawler(s,
//	    spider.WithConcurrentRequests(8),
//	    spider.WithMaxDepth(3),
//	)
//	if err := crawler.Run(); err != nil {
//	    log.Fatal(err)
//	}
//
// # Request and Response
//
// Create requests with callbacks:
//
//	req := spider.NewRequest("https://example.com", parseFunc).
//	    SetDepth(1).
//	    SetMeta("custom_key", customValue).
//	    SetErrCallback(func(err error, resp Response) {
//	        log.Printf("Error: %v", err)
//	    })
//
// Response provides extraction helpers:
//
//	func parse(resp spider.Response) []*spider.Request {
//	    // Get links
//	    links := resp.GetLinks()
//
//	    // Use CSS selectors
//	    titles := resp.Css("h1::text")
//
//	    // Use XPath
//	    prices := resp.XPath("//span[@class='price']/text()")
//
//	    // Extract text
//	    text := resp.Text
//
//	    return nil
//	}
//
// # Scheduler
//
// The scheduler handles URL prioritization and deduplication:
//
//	scheduler := spider.NewScheduler()
//
//	// Enqueue with priority
//	scheduler.Enqueue(req.WithPriority(10))
//
//	// Automatic deduplication by URL
//	scheduler.Enqueue(req1) // Added
//	scheduler.Enqueue(req1) // Skipped (same URL)
//
//	// Depth handling
//	scheduler.Enqueue(req.WithDepth(1))
//	scheduler.Enqueue(req.WithDepth(2))
//
// # Middleware
//
// Process requests and responses through middleware:
//
//	crawler.Middleware().Add(spider.RetryMiddleware{
//	    MaxRetries: 3,
//	    RetryCodes: []int{500, 502, 503},
//	})
//
//	crawler.Middleware().Add(spider.UserAgentMiddleware{
//	    UserAgent: "MyBot/1.0",
//	})
//
// Custom middleware:
//
//	type LogMiddleware struct{}
//
//	func (m LogMiddleware) ProcessRequest(req *spider.Request) []*spider.Request {
//	    log.Printf("Requesting: %s", req.URL)
//	    return nil // return nil to continue chain
//	}
//
//	func (m LogMiddleware) ProcessResponse(resp *spider.Response) []*spider.Request {
//	    log.Printf("Got response: %d bytes", len(resp.Body))
//	    return nil
//	}
//
// # Item Pipelines
//
// Process extracted items through pipelines:
//
//	crawler.Pipelines().Add(spider.JSONExporter{
//	    Path: "output.json",
//	})
//
//	crawler.Pipelines().Add(spider.CSVExporter{
//	    Path: "output.csv",
//	})
//
// Custom pipeline:
//
//	type ValidatePipeline struct{}
//
//	func (p ValidatePipeline) ProcessItem(item spider.Item) spider.Item {
//	    // Validate and transform item
//	    if item["url"] == "" {
//	        return nil // Drop item
//	    }
//	    item["validated"] = true
//	    return item
//	}
//
// # Settings
//
// Configure via settings:
//
//	settings := spider.NewSettings()
//	settings.Set("CONCURRENT_REQUESTS", 16)
//	settings.Set("DOWNLOAD_DELAY", "1s")
//	settings.Set("USER_AGENT", "MyBot/1.0")
//
//	crawler := spider.NewCrawler(spider,
//	    spider.WithSettings(settings),
//	)
//
// # Semantic Integration
//
// Use SemanticSpider for automatic extraction:
//
//	config := &semantic.PipelineConfig{
//	    LLMClient: llmClient,
//	}
//
//	spider := spider.NewSemanticSpider("crawler", startURLs, config,
//	    spider.WithSemanticMaxDepth(3),
//	    spider.WithAllowedDomains([]string{"example.com"}),
//	    spider.WithOnPage(func(url string, tree *semantic.SemanticTree) {
//	        log.Printf("Processed: %s → %d tokens", url, tree.CompressedTokenCount)
//	    }),
//	)
//
//	crawler := spider.NewCrawler(spider)
//	crawler.Run()
//
//	// Get results
//	trees := spider.GetAllSemanticTrees()
//	graph := spider.GetPageGraph()
//	stats := spider.GetStats()
//
// # Statistics
//
// Track crawler metrics:
//
//	stats := crawler.Stats()
//	stats.IncValue("pages_visited")
//	stats.GetValue("pages_visited")
//
// Built-in stats:
//   - scheduler/enqueued: URLs added to queue
//   - scheduler/dequeued: URLs removed from queue
//   - response_received: Successful responses
//   - error: Request errors
//   - response_status_count/200: Count by status code
//
// # Concurrency
//
// Control parallel execution:
//
//	crawler := spider.NewCrawler(spider,
//	    spider.WithConcurrentRequests(16),
//	    spider.WithDownloadDelay(500*time.Millisecond),
//	    spider.WithMaxDepth(3),
//	)
//
// # Error Handling
//
// Handle errors per-request:
//
//	req := spider.NewRequest(url, parseFunc).
//	    SetErrCallback(func(err error, resp spider.Response) {
//	        log.Printf("Failed: %s: %v", resp.Request.URL, err)
//	    })
//
// Or check stats after run:
//
//	crawler.Run()
//	if crawler.Stats().GetValue("error") > 0 {
//	    log.Printf("Had %d errors", crawler.Stats().GetValue("error"))
//	}
//
// # Engine Selection
//
// Choose between HTTP and browser engines:
//
//	crawler := spider.NewCrawler(spider,
//	    spider.WithEngine("native"),  // HTTP client (default)
//	    spider.WithEngine("chromium"), // Headless Chrome
//	)
//
//	// Via settings
//	settings.Set("ENGINE", "chromium")
//	settings.Set("STEALTH", true)
//	settings.Set("HTTP2_ENABLED", true)
//
// # Spider Interface
//
// Implement the Spider interface:
//
//	type Spider interface {
//	    Name() string
//	    Start() []*Request
//	    Parse(Response) []*Request
//	}
//
// # Request Types
//
// Create different request types:
//
//	// Simple GET
//	req := spider.NewRequest(url, callback)
//
//	// With metadata
//	req.SetMeta("key", value)
//
//	// With depth (for crawl limiting)
//	req.SetDepth(2)
//
//	// With priority
//	req.SetPriority(10)
//
// # Response Types
//
// Response provides multiple extraction methods:
//
//	resp.Css("a.link::attr(href)")     // CSS selector
//	resp.XPath("//a/@href")            // XPath expression
//	resp.GetLinks()                    // All links
//	resp.Text                          // Full text
//	resp.Body                          // Raw bytes
//	resp.Headers["Content-Type"]       // Headers
//	resp.Status                        // HTTP status
//
// # Advanced Usage
//
// Custom settings:
//
//	settings := spider.NewSettings()
//	settings.Set("CONCURRENT_REQUESTS_PER_DOMAIN", 8)
//	settings.Set("DOWNLOAD_TIMEOUT", "30s")
//	settings.Set("AUTOTHROTTLE_ENABLED", true)
//	settings.Set("AUTOTHROTTLE_START_DELAY", "1s")
//	settings.Set("AUTOTHROTTLE_MAX_DELAY", "30s")
//	settings.Set("HTTPCACHE_ENABLED", true)
//	settings.Set("HTTPCACHE_STORAGE", "sqlite")
//	settings.Set("HTTPCACHE_EXPIRATION", 86400)
//
// # Events and Signals
//
// Subscribe to crawler events (via signals package):
//
//	signals.Connect("spider_opened", func(spider Spider) {
//	    log.Println("Spider started")
//	})
//
//	signals.Connect("spider_closed", func(spider Spider, reason string) {
//	    log.Printf("Spider closed: %s", reason)
//	})
//
//	signals.Connect("request_scheduled", func(req *Request) {
//	    log.Printf("Scheduled: %s", req.URL)
//	})
//
// # Complete Example
//
// Full example with all features:
//
//	func main() {
//	    spider := &BlogSpider{name: "blog"}
//
//	    crawler := spider.NewCrawler(spider,
//	        spider.WithConcurrentRequests(8),
//	        spider.WithDownloadDelay(1*time.Second),
//	        spider.WithMaxDepth(3),
//	    )
//
//	    // Add middleware
//	    crawler.Middleware().Add(spider.RetryMiddleware{MaxRetries: 3})
//	    crawler.Middleware().Add(spider.UserAgentMiddleware{
//	        UserAgent: "BlogBot/1.0",
//	    })
//
//	    // Add pipelines
//	    crawler.Pipelines().Add(spider.JSONExporter{Path: "blog.json"})
//
//	    // Run
//	    if err := crawler.Run(); err != nil {
//	        log.Fatal(err)
//	    }
//
//	    // Check results
//	    log.Printf("Pages: %d, Errors: %d",
//	        crawler.Stats().GetValue("response_received"),
//	        crawler.Stats().GetValue("error"))
//	}
package spider
