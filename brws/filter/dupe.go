package filter

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"

	"github.com/stealth/brwslab/brws/spider"
)

type DupeFilter interface {
	Seen(req *spider.Request) bool
	Reset()
}

type RFPDupeFilter struct {
	mu    sync.Mutex
	seen  map[string]bool
	queue []string
}

func NewRFPDupeFilter() *RFPDupeFilter {
	return &RFPDupeFilter{
		seen: make(map[string]bool),
	}
}

func (f *RFPDupeFilter) Seen(req *spider.Request) bool {
	fp := f.fingerprint(req)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.seen[fp] {
		return true
	}
	f.seen[fp] = true
	f.queue = append(f.queue, fp)
	return false
}

func (f *RFPDupeFilter) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = make(map[string]bool)
	f.queue = nil
}

func (f *RFPDupeFilter) fingerprint(req *spider.Request) string {
	data := req.URL + req.Method
	if req.Body != nil {
		data += string(req.Body)
	}
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}
