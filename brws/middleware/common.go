package middleware

import (
	"context"
	"math"
	"net/url"
	"time"

	"github.com/stealth/brwslab/brws/engine"
)

type RetryMiddleware struct {
	maxRetries int
	retryCodes []int
	delay      time.Duration
}

func NewRetryMiddleware(maxRetries int, retryCodes []int) *RetryMiddleware {
	return &RetryMiddleware{
		maxRetries: maxRetries,
		retryCodes: retryCodes,
		delay:      100 * time.Millisecond,
	}
}

func (r *RetryMiddleware) ProcessRequest(ctx context.Context, req *engine.Request) (*engine.Request, *Response) {
	return req, nil
}

func (r *RetryMiddleware) ProcessResponse(ctx context.Context, req *engine.Request, resp *engine.Response) (*engine.Response, *Response) {
	if resp == nil {
		return resp, nil
	}

	for _, code := range r.retryCodes {
		if resp.Status == code {
			delay := r.delay * time.Duration(math.Pow(2, 0))
			time.Sleep(delay)

			newReq := &engine.Request{
				Method:  req.Method,
				URL:     req.URL,
				Headers: req.Headers,
				Body:    req.Body,
			}

			return nil, &Response{
				Request:  newReq,
				Response: resp,
				Drop:     false,
			}
		}
	}

	return resp, nil
}

func (r *RetryMiddleware) ProcessException(ctx context.Context, req *engine.Request, err error) (*engine.Response, *Response) {
	return nil, nil
}

type RedirectMiddleware struct {
	maxRedirects int
}

func NewRedirectMiddleware(maxRedirects int) *RedirectMiddleware {
	return &RedirectMiddleware{
		maxRedirects: maxRedirects,
	}
}

func (r *RedirectMiddleware) ProcessRequest(ctx context.Context, req *engine.Request) (*engine.Request, *Response) {
	return req, nil
}

func (r *RedirectMiddleware) ProcessResponse(ctx context.Context, req *engine.Request, resp *engine.Response) (*engine.Response, *Response) {
	if resp == nil {
		return resp, nil
	}

	if resp.Status >= 300 && resp.Status <= 399 {
		location := ""
		for _, v := range resp.Headers["Location"] {
			location = v
			break
		}

		if location == "" {
			return resp, nil
		}

		parsedURL, err := url.Parse(req.URL)
		if err != nil {
			return resp, nil
		}

		redirectURL, err := parsedURL.Parse(location)
		if err != nil {
			return resp, nil
		}

		newReq := &engine.Request{
			Method:  "GET",
			URL:     redirectURL.String(),
			Headers: req.Headers,
		}

		return nil, &Response{
			Request: newReq,
			Drop:    true,
		}
	}

	return resp, nil
}

func (r *RedirectMiddleware) ProcessException(ctx context.Context, req *engine.Request, err error) (*engine.Response, *Response) {
	return nil, nil
}

type UserAgentMiddleware struct {
	userAgents []string
	index      int
}

func NewUserAgentMiddleware(userAgents ...string) *UserAgentMiddleware {
	if len(userAgents) == 0 {
		userAgents = []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		}
	}
	return &UserAgentMiddleware{
		userAgents: userAgents,
		index:      0,
	}
}

func (u *UserAgentMiddleware) ProcessRequest(ctx context.Context, req *engine.Request) (*engine.Request, *Response) {
	if req.Headers == nil {
		req.Headers = make(map[string][]string)
	}

	if _, ok := req.Headers["User-Agent"]; !ok {
		req.Headers["User-Agent"] = []string{u.userAgents[u.index%len(u.userAgents)]}
		u.index++
	}

	return req, nil
}

func (u *UserAgentMiddleware) ProcessResponse(ctx context.Context, req *engine.Request, resp *engine.Response) (*engine.Response, *Response) {
	return resp, nil
}

func (u *UserAgentMiddleware) ProcessException(ctx context.Context, req *engine.Request, err error) (*engine.Response, *Response) {
	return nil, nil
}
