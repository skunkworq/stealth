package spider

import (
	"container/heap"
	"sync"
)

type Scheduler struct {
	queue    *priorityQueue
	mu       sync.Mutex
	seen     map[string]bool
	seenLock sync.RWMutex
}

func NewScheduler() *Scheduler {
	return &Scheduler{
		queue: &priorityQueue{},
		seen:  make(map[string]bool),
	}
}

func (s *Scheduler) Enqueue(req *Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := s.fingerprint(req)
	if !req.DontFilter {
		s.seenLock.Lock()
		if s.seen[key] {
			s.seenLock.Unlock()
			return
		}
		s.seen[key] = true
		s.seenLock.Unlock()
	}

	heap.Push(s.queue, &priorityItem{
		priority: req.Priority,
		request:  req,
		index:    s.queue.Len(),
	})
}

func (s *Scheduler) Dequeue() *Request {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.queue.Len() == 0 {
		return nil
	}
	item := heap.Pop(s.queue).(*priorityItem)
	return item.request
}

func (s *Scheduler) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.queue.Len()
}

func (s *Scheduler) IsEmpty() bool {
	return s.Len() == 0
}

func (s *Scheduler) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queue = &priorityQueue{}
	s.seen = make(map[string]bool)
}

func (s *Scheduler) fingerprint(req *Request) string {
	return req.Method + ":" + req.URL
}

type priorityItem struct {
	priority int
	request  *Request
	index    int
}

type priorityQueue struct {
	items []*priorityItem
}

func (pq *priorityQueue) Len() int {
	return len(pq.items)
}

func (pq *priorityQueue) Less(i, j int) bool {
	return pq.items[i].priority > pq.items[j].priority
}

func (pq *priorityQueue) Swap(i, j int) {
	pq.items[i], pq.items[j] = pq.items[j], pq.items[i]
	pq.items[i].index = i
	pq.items[j].index = j
}

func (pq *priorityQueue) Push(x any) {
	item := x.(*priorityItem)
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
