package spider

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/skunkworq/stealth/brws/browser/engine"
	_ "github.com/skunkworq/stealth/brws/browser/engine/http/native"
)

type Crawler struct {
	spider    Spider
	settings  *Settings
	engine    engine.Engine
	mw        *MiddlewareManager
	pipelines *PipelineManager
	stats     *Stats
	scheduler *Scheduler
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup

	concurrentRequests int
	downloadDelay      time.Duration
	maxDepth           int
	closeSignal        chan struct{}
}

type CrawlerOption func(*Crawler)

func WithSettings(settings *Settings) CrawlerOption {
	return func(c *Crawler) {
		c.settings = settings
	}
}

func WithEngine(engineName string) CrawlerOption {
	return func(c *Crawler) {
		c.settings.Set("ENGINE", engineName)
	}
}

func WithConcurrentRequests(n int) CrawlerOption {
	return func(c *Crawler) {
		c.concurrentRequests = n
	}
}

func WithDownloadDelay(d time.Duration) CrawlerOption {
	return func(c *Crawler) {
		c.downloadDelay = d
	}
}

func WithMaxDepth(depth int) CrawlerOption {
	return func(c *Crawler) {
		c.maxDepth = depth
	}
}

func NewCrawler(spider Spider, opts ...CrawlerOption) *Crawler {
	settings := NewSettings()
	if settings == nil {
		settings = NewSettings()
	}

	c := &Crawler{
		spider:      spider,
		settings:    settings,
		stats:       NewStats(spider.Name()),
		mw:          NewMiddlewareManager(),
		pipelines:   NewPipelineManager(),
		scheduler:   NewScheduler(),
		closeSignal: make(chan struct{}),
	}

	for _, opt := range opts {
		opt(c)
	}

	c.concurrentRequests = settings.GetIntWithDefault("CONCURRENT_REQUESTS", 16)
	c.downloadDelay = settings.GetDuration("DOWNLOAD_DELAY")
	c.maxDepth = settings.GetIntWithDefault("MAX_DEPTH", 0)

	c.ctx, c.cancel = context.WithCancel(context.Background())

	return c
}

func (c *Crawler) Settings() *Settings {
	return c.settings
}

func (c *Crawler) Engine() engine.Engine {
	return c.engine
}

func (c *Crawler) Stats() *Stats {
	return c.stats
}

func (c *Crawler) Middleware() *MiddlewareManager {
	return c.mw
}

func (c *Crawler) Pipelines() *PipelineManager {
	return c.pipelines
}

func (c *Crawler) Scheduler() *Scheduler {
	return c.scheduler
}

func (c *Crawler) Open() error {
	engineName := c.settings.GetString("ENGINE")
	if engineName == "" {
		engineName = "native"
	}

	eng, err := engine.New(engineName, engine.Options{
		Stealth: c.settings.GetBoolWithDefault("STEALTH", true),
		Timeout: c.settings.GetDuration("DOWNLOAD_TIMEOUT"),
		HTTP2:   c.settings.GetBoolWithDefault("HTTP2_ENABLED", true),
		HTTP3:   c.settings.GetBoolWithDefault("HTTP3_ENABLED", false),
	})
	if err != nil {
		return fmt.Errorf("failed to create engine: %w", err)
	}
	c.engine = eng

	if err := c.mw.Open(c); err != nil {
		return fmt.Errorf("failed to open middleware: %w", err)
	}

	if err := c.pipelines.Open(c); err != nil {
		return fmt.Errorf("failed to open pipelines: %w", err)
	}

	return nil
}

func (c *Crawler) Close() error {
	c.cancel()

	if c.mw != nil {
		c.mw.Close()
	}

	if c.pipelines != nil {
		c.pipelines.Close()
	}

	if c.engine != nil {
		_ = c.engine.Close()
	}

	return nil
}

func (c *Crawler) Run() error {
	if err := c.Open(); err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Shutting down...")
		_ = c.Close()
	}()

	log.Printf("Starting crawl: %s", c.spider.Name())

	startRequests := c.spider.Start()
	for _, req := range startRequests {
		if c.maxDepth > 0 && req.Depth > c.maxDepth {
			continue
		}
		c.scheduler.Enqueue(req)
	}

	c.stats.IncValue("spider_started")

	activeRequests := 0
	requestChan := make(chan *Request, c.concurrentRequests)
	resultChan := make(chan *CrawlResult, 100)

	for i := 0; i < c.concurrentRequests; i++ {
		c.wg.Add(1)
		go c.worker(requestChan, resultChan)
	}

	go c.resultWorker(resultChan)

Loop:
	for {
		select {
		case <-c.closeSignal:
			break Loop
		default:
			req := c.scheduler.Dequeue()
			if req != nil {
				requestChan <- req
				activeRequests++
			} else if activeRequests == 0 && c.scheduler.Len() == 0 {
				time.Sleep(100 * time.Millisecond)
				if c.scheduler.Len() == 0 {
					break Loop
				}
			} else {
				time.Sleep(50 * time.Millisecond)
			}
		}
	}

	close(requestChan)
	c.wg.Wait()

	c.stats.IncValue("spider_closed")

	log.Printf("Crawl finished. Requests: %d, Responses: %d, Errors: %d",
		c.stats.GetValue("scheduler/enqueued"),
		c.stats.GetValue("response_received"),
		c.stats.GetValue("error"))

	return nil
}

func (c *Crawler) worker(requestChan <-chan *Request, resultChan chan<- *CrawlResult) {
	defer c.wg.Done()

	for req := range requestChan {
		result := c.executeRequest(req)
		resultChan <- result

		if c.downloadDelay > 0 {
			time.Sleep(c.downloadDelay)
		}
	}
}

func (c *Crawler) executeRequest(req *Request) *CrawlResult {
	c.stats.IncValue("scheduler/dequeued")

	engineReq := ToEngineRequest(req)

	resp, err := c.engine.Do(c.ctx, engineReq)
	if err != nil {
		c.stats.IncValue("error")
		c.stats.IncValue("error/" + err.Error())
		return &CrawlResult{
			Request: req,
			Error:   err,
		}
	}

	c.stats.IncValue("response_received")
	c.stats.IncValue("response_status_count/" + fmt.Sprintf("%d", resp.Status))

	spiderResp := Response{
		Request: req,
		Status:  resp.Status,
		Body:    resp.Body,
		Text:    string(resp.Body),
		URL:     resp.FinalURL,
		Headers: flattenHeaders(resp.Headers),
		Meta:    req.Meta,
		Engine:  c.engine.Name(),
		Timing:  resp.Timing.Total,
	}

	requests := c.mw.ProcessResponse(&spiderResp)
	if len(requests) == 0 {
		if req.Callback != nil {
			requests = req.Callback(spiderResp)
		} else {
			requests = c.spider.Parse(spiderResp)
		}
	}

	for _, newReq := range requests {
		if c.maxDepth > 0 && newReq.Depth > c.maxDepth {
			continue
		}
		if newReq.Meta == nil {
			newReq.Meta = make(map[string]interface{})
		}
		for k, v := range req.Meta {
			if _, exists := newReq.Meta[k]; !exists {
				newReq.Meta[k] = v
			}
		}
		c.scheduler.Enqueue(newReq)
		c.stats.IncValue("scheduler/enqueued")
	}

	return &CrawlResult{
		Request:  req,
		Response: &spiderResp,
		Requests: requests,
	}
}

func (c *Crawler) resultWorker(resultChan <-chan *CrawlResult) {
	for result := range resultChan {
		if result.Error != nil {
			if result.Request.ErrCallback != nil {
				result.Request.ErrCallback(result.Error, Response{})
			}
		}

		if result.Response != nil {
			_ = c.pipelines.ProcessItem(result.Response)
		}
	}
}

type CrawlResult struct {
	Request  *Request
	Response *Response
	Requests []*Request
	Error    error
}

func flattenHeaders(h map[string][]string) map[string]string {
	result := make(map[string]string)
	for k, v := range h {
		if len(v) > 0 {
			result[k] = v[0]
		}
	}
	return result
}
