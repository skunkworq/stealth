package spider

import (
	"fmt"
	"sync"
)

type Middleware interface {
	ProcessRequest(req *Request) (*Request, error)
	ProcessResponse(resp *Response) []*Request
	ProcessError(err error, resp *Response) []*Request
}

type MiddlewareManager struct {
	requestMiddlewares  []RequestMiddleware
	responseMiddlewares []ResponseMiddleware
	errorMiddlewares    []ErrorMiddleware
	crawler             *Crawler
	mu                  sync.RWMutex
}

type RequestMiddleware func(req *Request) (*Request, error)
type ResponseMiddleware func(resp *Response) []*Request
type ErrorMiddleware func(err error, resp *Response) []*Request

func NewMiddlewareManager() *MiddlewareManager {
	return &MiddlewareManager{}
}

func (m *MiddlewareManager) Open(c *Crawler) error {
	m.crawler = c
	m.registerBuiltInMiddlewares()
	return nil
}

func (m *MiddlewareManager) registerBuiltInMiddlewares() {
}

func (m *MiddlewareManager) AddRequestMiddleware(mw RequestMiddleware) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requestMiddlewares = append(m.requestMiddlewares, mw)
}

func (m *MiddlewareManager) AddResponseMiddleware(mw ResponseMiddleware) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.responseMiddlewares = append(m.responseMiddlewares, mw)
}

func (m *MiddlewareManager) AddErrorMiddleware(mw ErrorMiddleware) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errorMiddlewares = append(m.errorMiddlewares, mw)
}

func (m *MiddlewareManager) ProcessRequest(req *Request) (*Request, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var err error
	currentReq := req
	for _, mw := range m.requestMiddlewares {
		currentReq, err = mw(currentReq)
		if err != nil {
			return currentReq, err
		}
	}
	return currentReq, nil
}

func (m *MiddlewareManager) ProcessResponse(resp *Response) []*Request {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var requests []*Request
	for _, mw := range m.responseMiddlewares {
		newRequests := mw(resp)
		if newRequests != nil {
			requests = newRequests
		}
	}
	return requests
}

func (m *MiddlewareManager) ProcessError(err error, resp *Response) []*Request {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var requests []*Request
	for _, mw := range m.errorMiddlewares {
		newRequests := mw(err, resp)
		if newRequests != nil {
			requests = newRequests
		}
	}
	return requests
}

func (m *MiddlewareManager) Close() {
}

type RetryMiddleware struct {
	maxRetries int
	retryCodes []int
	stats      *Stats
}

func NewRetryMiddleware(maxRetries int, retryCodes []int, stats *Stats) *RetryMiddleware {
	return &RetryMiddleware{
		maxRetries: maxRetries,
		retryCodes: retryCodes,
		stats:      stats,
	}
}

func (m *RetryMiddleware) ProcessRequest(req *Request) (*Request, error) {
	return req, nil
}

func (m *RetryMiddleware) ProcessResponse(resp *Response) []*Request {
	return nil
}

func (m *RetryMiddleware) ProcessError(err error, resp *Response) []*Request {
	if resp == nil {
		return nil
	}

	retryCount := 0
	if req := resp.Request; req != nil {
		if v, ok := req.Meta["retry_count"]; ok {
			if count, ok := v.(int); ok {
				retryCount = count
			}
		}
	}

	if retryCount >= m.maxRetries {
		return nil
	}

	for _, code := range m.retryCodes {
		if resp.Status == code {
			m.stats.IncValue("retry/count")
			newReq := *resp.Request
			newReq.Meta["retry_count"] = retryCount + 1
			return []*Request{&newReq}
		}
	}

	return nil
}

type UserAgentMiddleware struct {
	userAgent string
}

func NewUserAgentMiddleware(userAgent string) *UserAgentMiddleware {
	return &UserAgentMiddleware{userAgent: userAgent}
}

func (m *UserAgentMiddleware) ProcessRequest(req *Request) (*Request, error) {
	if req.Headers == nil {
		req.Headers = make(map[string]string)
	}
	if _, ok := req.Headers["User-Agent"]; !ok {
		req.Headers["User-Agent"] = m.userAgent
	}
	return req, nil
}

func (m *UserAgentMiddleware) ProcessResponse(resp *Response) []*Request {
	return nil
}

func (m *UserAgentMiddleware) ProcessError(err error, resp *Response) []*Request {
	return nil
}

type RedirectMiddleware struct {
	enabled  bool
	maxTimes int
	stats    *Stats
}

func NewRedirectMiddleware(enabled bool, maxTimes int, stats *Stats) *RedirectMiddleware {
	return &RedirectMiddleware{
		enabled:  enabled,
		maxTimes: maxTimes,
		stats:    stats,
	}
}

func (m *RedirectMiddleware) ProcessRequest(req *Request) (*Request, error) {
	return req, nil
}

func (m *RedirectMiddleware) ProcessResponse(resp *Response) []*Request {
	if !m.enabled {
		return nil
	}

	if resp.Status >= 300 && resp.Status < 400 {
		redirectCount := 0
		if v := resp.GetMeta("redirect_count"); v != nil {
			if count, ok := v.(int); ok {
				redirectCount = count
			}
		}

		if redirectCount >= m.maxTimes {
			return nil
		}

		location := resp.Headers["Location"]
		if location == "" {
			return nil
		}

		m.stats.IncValue("redirect")
		newReq := NewRequest(location, resp.Request.Callback)
		newReq.Meta["redirect_count"] = redirectCount + 1
		newReq.Meta["original_url"] = resp.Request.URL

		return []*Request{newReq}
	}

	return nil
}

func (m *RedirectMiddleware) ProcessError(err error, resp *Response) []*Request {
	return nil
}

func ValidateMiddleware(mw interface{}) error {
	_, hasProcessRequest := mw.(interface {
		ProcessRequest(*Request) (*Request, error)
	})
	_, hasProcessResponse := mw.(interface{ ProcessResponse(*Response) []*Request })
	_, hasProcessError := mw.(interface {
		ProcessError(error, *Response) []*Request
	})

	if !hasProcessRequest && !hasProcessResponse && !hasProcessError {
		return fmt.Errorf("middleware does not implement any process method")
	}

	return nil
}
