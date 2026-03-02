package spider

import (
	"sync"
)

type Stats struct {
	mu    sync.RWMutex
	stats map[string]int64
}

func NewStats(spiderName string) *Stats {
	return &Stats{
		stats: make(map[string]int64),
	}
}

func (s *Stats) IncValue(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats[key]++
}

func (s *Stats) IncValueBy(key string, value int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats[key] += value
}

func (s *Stats) SetValue(key string, value int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats[key] = value
}

func (s *Stats) GetValue(key string) int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.stats[key]
}

func (s *Stats) GetAll() map[string]int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string]int64)
	for k, v := range s.stats {
		result[k] = v
	}
	return result
}

func (s *Stats) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats = make(map[string]int64)
}

type Pipeline interface {
	Open(*Crawler) error
	ProcessItem(*Response) error
	Close() error
}

type PipelineManager struct {
	pipelines []Pipeline
	crawler   *Crawler
	mu        sync.RWMutex
}

func NewPipelineManager() *PipelineManager {
	return &PipelineManager{}
}

func (m *PipelineManager) Open(c *Crawler) error {
	m.crawler = c

	for _, p := range m.pipelines {
		if err := p.Open(c); err != nil {
			return err
		}
	}
	return nil
}

func (m *PipelineManager) AddPipeline(p Pipeline) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pipelines = append(m.pipelines, p)
}

func (m *PipelineManager) ProcessItem(resp *Response) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, p := range m.pipelines {
		if err := p.ProcessItem(resp); err != nil {
			return err
		}
	}
	return nil
}

func (m *PipelineManager) Close() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, p := range m.pipelines {
		_ = p.Close()
	}
}

type ItemPipelineFunc func(*Response) error

type FuncPipeline struct {
	openFunc    func(*Crawler) error
	processFunc func(*Response) error
	closeFunc   func() error
}

func (p *FuncPipeline) Open(c *Crawler) error {
	if p.openFunc != nil {
		return p.openFunc(c)
	}
	return nil
}

func (p *FuncPipeline) ProcessItem(item *Response) error {
	if p.processFunc != nil {
		return p.processFunc(item)
	}
	return nil
}

func (p *FuncPipeline) Close() error {
	if p.closeFunc != nil {
		return p.closeFunc()
	}
	return nil
}

func NewPipeline(name string, open func(*Crawler) error, process func(*Response) error, close func() error) Pipeline {
	return &FuncPipeline{
		openFunc:    open,
		processFunc: process,
		closeFunc:   close,
	}
}

func PipelineFromFunc(process func(*Response) error) Pipeline {
	return &FuncPipeline{
		processFunc: process,
	}
}
