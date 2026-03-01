package spider

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/stealth/brwslab/brws/engine"
	"github.com/stealth/brwslab/brws/middleware"
	"github.com/stealth/brwslab/brws/pipeline"
	"github.com/stealth/brwslab/brws/signals"
)

type Spider interface {
	Name() string
	StartRequests() []Request
	Parse(Response) []ParseResult
}

type Request struct {
	URL    string
	Method string
	Meta   map[string]any

	Callback    func(Response) []ParseResult
	ErrCallback func(error) error

	Headers map[string]string
	Body    []byte

	Cookies map[string]string

	Priority    int
	DontFilter  bool
	HeadersFunc func() map[string]string
}

type ParseResult struct {
	Request *Request
	Item    any
	Errors  []error
}

type Response struct {
	URL      string
	Status   int
	Headers  map[string][]string
	Body     []byte
	Protocol string
	FinalURL string

	Request *Request

	engineResp *engine.Response
}

func (r *Response) Text() string {
	return string(r.Body)
}

func (r *Response) Header(key string) string {
	if r.Headers == nil {
		return ""
	}
	v := r.Headers[key]
	if len(v) > 0 {
		return v[0]
	}
	return ""
}

func (r *Response) CSS(selector string) []Element {
	return nil
}

func (r *Response) XPath(selector string) []Element {
	return nil
}

type Element interface {
	Text() string
	Attr(key string) string
}

type Crawler struct {
	spider    Spider
	engine    engine.Engine
	settings  Settings
	pipelines pipeline.Manager
	mwManager *middleware.Manager
	signals   *signals.Manager

	scheduler *Scheduler

	mu       sync.Mutex
	started  bool
	closed   bool
	closeErr error
}

func New(spider Spider, opts ...Option) (*Crawler, error) {
	if spider == nil {
		return nil, errors.New("spider cannot be nil")
	}

	c := &Crawler{
		spider:    spider,
		scheduler: NewScheduler(),
	}

	for _, opt := range opts {
		opt(c)
	}

	if c.settings == nil {
		c.settings = DefaultSettings()
	}

	if c.pipelines == nil {
		c.pipelines = pipeline.NewManager(nil)
	}

	if c.mwManager == nil {
		c.mwManager = middleware.NewManager(nil)
	}

	if c.signals == nil {
		c.signals = signals.NewManager()
	}

	return c, nil
}

func (c *Crawler) Name() string {
	return c.spider.Name()
}

func (c *Crawler) Start() error {
	c.mu.Lock()
	if c.started {
		c.mu.Unlock()
		return errors.New("crawler already started")
	}
	c.started = true
	c.mu.Unlock()

	c.signals.Send(signals.CrawlerStarted{})

	if err := c.pipelines.Open(c.spider); err != nil {
		return fmt.Errorf("opening pipelines: %w", err)
	}

	ctx := context.Background()

	for _, req := range c.spider.StartRequests() {
		if err := c.scheduler.Enqueue(ctx, &req); err != nil {
			c.signals.Send(signals.RequestDropped{Request: &req, Reason: err})
		}
	}

	c.signals.Send(signals.SpiderOpened{})

	return c.run()
}

func (c *Crawler) run() error {
	for {
		req := c.scheduler.Next(context.Background())
		if req == nil {
			break
		}

		c.signals.Send(signals.RequestScheduled{Request: req})

		engineReq := &engine.Request{
			Method:  req.Method,
			URL:     req.URL,
			Headers: parseHeaders(req.Headers),
			Body:    req.Body,
		}

		resp, err := c.engine.Do(context.Background(), engineReq)
		if err != nil {
			if req.ErrCallback != nil {
				if newErr := req.ErrCallback(err); newErr != nil {
					c.scheduler.Retry(context.Background(), req, newErr)
				}
			}
			c.signals.Send(signals.RequestError{Request: req, Error: err})
			continue
		}

		c.signals.Send(signals.ResponseReceived{
			Request:  req,
			Response: resp,
		})

		sresp := &Response{
			URL:        resp.FinalURL,
			Status:     resp.Status,
			Headers:    resp.Headers,
			Body:       resp.Body,
			Protocol:   resp.Protocol,
			FinalURL:   resp.FinalURL,
			Request:    req,
			engineResp: resp,
		}

		if req.Callback != nil {
			results := req.Callback(*sresp)
			for _, result := range results {
				if result.Request != nil {
					if err := c.scheduler.Enqueue(context.Background(), result.Request); err != nil {
						c.signals.Send(signals.RequestDropped{Request: result.Request, Reason: err})
					}
				}
				if result.Item != nil {
					if _, err := c.pipelines.ProcessItem(result.Item, c.spider); err != nil {
						c.signals.Send(signals.ItemError{Item: result.Item, Error: err})
					} else {
						c.signals.Send(signals.ItemScraped{Item: result.Item})
					}
				}
			}
		}
	}

	c.signals.Send(signals.SpiderClosed{})
	c.pipelines.Close(c.spider)

	return c.closeErr
}

func (c *Crawler) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func parseHeaders(h map[string]string) map[string][]string {
	if h == nil {
		return nil
	}
	result := make(map[string][]string)
	for k, v := range h {
		result[k] = []string{v}
	}
	return result
}

type Option func(*Crawler)

func WithEngine(e engine.Engine) Option {
	return func(c *Crawler) {
		c.engine = e
	}
}

func WithSettings(s Settings) Option {
	return func(c *Crawler) {
		c.settings = s
	}
}

func WithPipelines(p pipeline.Manager) Option {
	return func(c *Crawler) {
		c.pipelines = p
	}
}

func WithMiddleware(m *middleware.Manager) Option {
	return func(c *Crawler) {
		c.mwManager = m
	}
}

func WithSignals(s *signals.Manager) Option {
	return func(c *Crawler) {
		c.signals = s
	}
}
