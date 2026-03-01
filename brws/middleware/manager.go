package middleware

import (
	"context"
	"sync"

	"github.com/stealth/brwslab/brws/engine"
)

type DownloaderMiddleware interface {
	ProcessRequest(ctx context.Context, req *engine.Request) (*engine.Request, *Response)
	ProcessResponse(ctx context.Context, req *engine.Request, resp *engine.Response) (*engine.Response, *Response)
	ProcessException(ctx context.Context, req *engine.Request, err error) (*engine.Response, *Response)
}

type Response struct {
	Request  *engine.Request
	Response *engine.Response
	Error    error
	Drop     bool
}

type Manager struct {
	mu              sync.Mutex
	downloaders     []DownloaderMiddleware
	downloadersInit []MiddlewareInit
}

type MiddlewareInit func(ctx context.Context) error

func NewManager(mws []DownloaderMiddleware) *Manager {
	m := &Manager{
		downloaders: mws,
	}
	if m.downloaders == nil {
		m.downloaders = []DownloaderMiddleware{}
	}
	return m
}

func (m *Manager) ProcessRequest(ctx context.Context, req *engine.Request) (*engine.Request, *Response) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, mw := range m.downloaders {
		newReq, resp := mw.ProcessRequest(ctx, req)
		if resp != nil {
			return newReq, resp
		}
		if newReq != nil {
			req = newReq
		}
	}

	return req, nil
}

func (m *Manager) ProcessResponse(ctx context.Context, req *engine.Request, resp *engine.Response) (*engine.Response, *Response) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, mw := range m.downloaders {
		newResp, mwResp := mw.ProcessResponse(ctx, req, resp)
		if mwResp != nil {
			return newResp, mwResp
		}
		if newResp != nil {
			resp = newResp
		}
	}

	return resp, nil
}

func (m *Manager) ProcessException(ctx context.Context, req *engine.Request, err error) (*engine.Response, *Response) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, mw := range m.downloaders {
		newResp, mwResp := mw.ProcessException(ctx, req, err)
		if mwResp != nil {
			return newResp, mwResp
		}
		if newResp != nil {
			return newResp, nil
		}
	}

	return nil, nil
}

func (m *Manager) Add(mw DownloaderMiddleware) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.downloaders = append(m.downloaders, mw)
}
