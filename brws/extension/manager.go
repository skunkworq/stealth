package extension

import (
	"context"

	"github.com/stealth/brwslab/brws/signals"
)

type Extension interface {
	Initialize(ctx context.Context) error
	Shutdown(ctx context.Context) error
}

type Manager struct {
	extensions []Extension
	signals    *signals.Manager
}

func NewManager(signalsMgr *signals.Manager) *Manager {
	return &Manager{
		signals:    signalsMgr,
		extensions: make([]Extension, 0),
	}
}

func (m *Manager) Load(ext Extension) error {
	if err := ext.Initialize(context.Background()); err != nil {
		return err
	}
	m.extensions = append(m.extensions, ext)
	return nil
}

func (m *Manager) Unload() {
	for i := len(m.extensions) - 1; i >= 0; i-- {
		m.extensions[i].Shutdown(context.Background())
	}
	m.extensions = nil
}

func (m *Manager) List() []Extension {
	return m.extensions
}

type ObservabilityExtension struct {
	stats  StatsCollector
	tracer Tracer
}

type StatsCollector interface {
	IncCounter(name string, value int64)
	SetGauge(name string, value float64)
	RecordHistogram(name string, value float64)
}

type Tracer interface {
	StartSpan(name string) Span
	RecordMetric(name string, value float64)
}

type Span interface {
	End()
	SetAttribute(key string, value any)
	AddEvent(name string)
}

func NewObservabilityExtension() *ObservabilityExtension {
	return &ObservabilityExtension{
		stats:  NewStatsCollector(),
		tracer: NewTracer(),
	}
}

func (e *ObservabilityExtension) Initialize(ctx context.Context) error {
	return nil
}

func (e *ObservabilityExtension) Shutdown(ctx context.Context) error {
	return nil
}

type statsCollector struct{}

func NewStatsCollector() *statsCollector {
	return &statsCollector{}
}

func (s *statsCollector) IncCounter(name string, value int64)        {}
func (s *statsCollector) SetGauge(name string, value float64)        {}
func (s *statsCollector) RecordHistogram(name string, value float64) {}

type tracer struct{}

func NewTracer() *tracer {
	return &tracer{}
}

func (t *tracer) StartSpan(name string) Span {
	return &span{name: name}
}

func (t *tracer) RecordMetric(name string, value float64) {}

type span struct {
	name string
}

func (s *span) End()                               {}
func (s *span) SetAttribute(key string, value any) {}
func (s *span) AddEvent(name string)               {}

type CloseSpiderExtension struct {
	ItemCount    int
	RequestCount int
	ErrorCount   int
	Timeout      int
}

func NewCloseSpiderExtension() *CloseSpiderExtension {
	return &CloseSpiderExtension{}
}

func (e *CloseSpiderExtension) Initialize(ctx context.Context) error {
	return nil
}

func (e *CloseSpiderExtension) Shutdown(ctx context.Context) error {
	return nil
}
