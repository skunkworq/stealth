package spider

import (
	"context"

	"github.com/stealth/brwslab/brws/instrumentation"
	"github.com/stealth/brwslab/brws/signals"
)

type Observability struct {
	tracer  *instrumentation.Tracer
	metrics *Metrics
	enabled bool
}

type Metrics struct {
	counters   map[string]int64
	gauges     map[string]float64
	histograms map[string][]float64
}

func NewMetrics() *Metrics {
	return &Metrics{
		counters:   make(map[string]int64),
		gauges:     make(map[string]float64),
		histograms: make(map[string][]float64),
	}
}

func (m *Metrics) Inc(name string, value int64) {
	m.counters[name] += value
}

func (m *Metrics) SetGauge(name string, value float64) {
	m.gauges[name] = value
}

func (m *Metrics) RecordHistogram(name string, value float64) {
	m.histograms[name] = append(m.histograms[name], value)
	if len(m.histograms[name]) > 1000 {
		m.histograms[name] = m.histograms[name][1:]
	}
}

func (m *Metrics) GetCounter(name string) int64 {
	return m.counters[name]
}

func (m *Metrics) GetGauge(name string) float64 {
	return m.gauges[name]
}

func NewCrawlerObservability(enableTracing, enableMetrics bool) *Observability {
	if !enableTracing && !enableMetrics {
		return nil
	}

	return &Observability{
		tracer:  instrumentation.NewTracer(),
		metrics: NewMetrics(),
		enabled: true,
	}
}

func (o *Observability) StartSpan(ctx context.Context, name string) (context.Context, *instrumentation.Span) {
	if o == nil || !o.enabled || o.tracer == nil {
		return ctx, nil
	}
	return o.tracer.StartSpan(ctx, name, instrumentation.SpanKindInternal)
}

func (o *Observability) RecordMetric(name string, value float64) {
	if o == nil || !o.enabled || o.metrics == nil {
		return
	}
	o.metrics.RecordHistogram(name, value)
}

func (o *Observability) IncCounter(name string, value int64) {
	if o == nil || !o.enabled || o.metrics == nil {
		return
	}
	o.metrics.Inc(name, value)
}

func (o *Observability) GetTracer() *instrumentation.Tracer {
	if o == nil {
		return nil
	}
	return o.tracer
}

func (o *Observability) GetMetrics() *Metrics {
	if o == nil {
		return nil
	}
	return o.metrics
}

type CrawlerHooks struct {
	OnRequest  func(req *Request)
	OnResponse func(req *Request, resp *Response)
	OnItem     func(item any)
	OnError    func(err error)
}

func NewCrawlerHooks() *CrawlerHooks {
	return &CrawlerHooks{}
}

func (h *CrawlerHooks) Install(sm *signals.Manager) {
	sm.ConnectHandler("spider.RequestScheduled", func(sig signals.Signal) {
		if h.OnRequest != nil {
			if r, ok := sig.(signals.Signal); ok {
				_ = r
			}
		}
	})
}

type TracedScheduler struct {
	*Scheduler
	tracer *instrumentation.Tracer
	obs    *Observability
}

func NewTracedScheduler(s *Scheduler, obs *Observability) *TracedScheduler {
	return &TracedScheduler{
		Scheduler: s,
		tracer:    obs.GetTracer(),
		obs:       obs,
	}
}
