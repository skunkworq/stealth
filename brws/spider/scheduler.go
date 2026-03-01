package spider

import (
	"container/heap"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

type Scheduler struct {
	mu       sync.Mutex
	queue    *priorityQueue
	inflight map[string]*Request
	seen     map[string]bool

	options SchedulerOptions
}

type SchedulerOptions struct {
	DiskQueuePath string
	MaxMemorySize int
}

type priorityQueue struct {
	items []*queueItem
}

type queueItem struct {
	request  *Request
	priority int
	index    int
}

func (pq *priorityQueue) Len() int { return len(pq.items) }
func (pq *priorityQueue) Less(i, j int) bool {
	return pq.items[i].priority > pq.items[j].priority
}
func (pq *priorityQueue) Swap(i, j int) {
	pq.items[i], pq.items[j] = pq.items[j], pq.items[i]
	pq.items[i].index = i
	pq.items[j].index = j
}
func (pq *priorityQueue) Push(x any) {
	item := x.(*queueItem)
	item.index = len(pq.items)
	pq.items = append(pq.items, item)
}
func (pq *priorityQueue) Pop() any {
	old := pq.items
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	pq.items = old[0 : n-1]
	return item
}

func NewScheduler(opts ...SchedulerOption) *Scheduler {
	s := &Scheduler{
		inflight: make(map[string]*Request),
		seen:     make(map[string]bool),
		queue:    &priorityQueue{items: make([]*queueItem, 0)},
	}

	for _, opt := range opts {
		opt(&s.options)
	}

	heap.Init(s.queue)

	return s
}

func (s *Scheduler) Enqueue(ctx context.Context, req *Request) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if req != nil && !req.DontFilter {
		fp := s.fingerprint(req)
		if s.seen[fp] {
			return nil
		}
		s.seen[fp] = true
	}

	method := req.Method
	if method == "" {
		method = "GET"
	}

	heap.Push(s.queue, &queueItem{
		request:  req,
		priority: req.Priority,
	})

	return nil
}

func (s *Scheduler) Next(ctx context.Context) *Request {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.queue.Len() == 0 {
		return nil
	}

	item := heap.Pop(s.queue).(*queueItem)
	return item.request
}

func (s *Scheduler) Retry(ctx context.Context, req *Request, err error) {
	req.Priority--
	s.Enqueue(ctx, req)
}

func (s *Scheduler) HasPending(ctx context.Context) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.queue.Len() > 0 || len(s.inflight) > 0
}

func (s *Scheduler) fingerprint(req *Request) string {
	data := req.URL + req.Method
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (s *Scheduler) Close() error {
	return nil
}

type SchedulerOption func(*SchedulerOptions)

func WithDiskQueue(path string) SchedulerOption {
	return func(o *SchedulerOptions) {
		o.DiskQueuePath = path
	}
}

func WithMaxMemorySize(size int) SchedulerOption {
	return func(o *SchedulerOptions) {
		o.MaxMemorySize = size
	}
}
