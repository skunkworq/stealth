package pipeline

import (
	"context"
	"fmt"
	"sync"
)

type Item interface{}

type Pipeline interface {
	Open(ctx context.Context) error
	ProcessItem(ctx context.Context, item Item) (Item, error)
	Close(ctx context.Context) error
}

type Manager interface {
	Open(spider any) error
	ProcessItem(item any, spider any) (any, error)
	Close(spider any) error
}

type manager struct {
	pipelines []Pipeline

	mu     sync.Mutex
	opened bool
	spider any
}

func NewManager(pipelines []Pipeline) Manager {
	m := &manager{
		pipelines: pipelines,
	}

	if m.pipelines == nil {
		m.pipelines = []Pipeline{}
	}

	return m
}

func (m *manager) Open(spider any) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.opened {
		return fmt.Errorf("pipelines already opened")
	}

	m.spider = spider
	m.opened = true

	for _, p := range m.pipelines {
		if err := p.Open(context.Background()); err != nil {
			return fmt.Errorf("pipeline %T open: %w", p, err)
		}
	}

	return nil
}

func (m *manager) ProcessItem(item any, spider any) (any, error) {
	var err error
	result := item

	for _, p := range m.pipelines {
		result, err = p.ProcessItem(context.Background(), result)
		if err != nil {
			return nil, err
		}
		if result == nil {
			return nil, nil
		}
	}

	return result, nil
}

func (m *manager) Close(spider any) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.opened {
		return nil
	}

	var lastErr error
	for i := len(m.pipelines) - 1; i >= 0; i-- {
		if err := m.pipelines[i].Close(context.Background()); err != nil {
			lastErr = err
		}
	}

	m.opened = false
	return lastErr
}

func AddPipeline(m Manager, p Pipeline) {
	if bm, ok := m.(*manager); ok {
		bm.pipelines = append(bm.pipelines, p)
	}
}
