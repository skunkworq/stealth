package session

import (
	"sync"
	"sync/atomic"

	"github.com/skunkworq/stealth/brws/types"
)

// FingerprintCache maps session IDs to their bound CompleteFingerprint.
// A session's fingerprint is generated once at creation and reused for
// every request in that session, ensuring consistent browser identity.
type FingerprintCache struct {
	entries sync.Map // map[string]*types.CompleteFingerprint
	size    atomic.Int64
}

var globalFingerprintCache = &FingerprintCache{}

// GlobalFingerprintCache returns the process-wide singleton cache.
func GlobalFingerprintCache() *FingerprintCache { return globalFingerprintCache }

// Store binds a fingerprint to a session ID.
func (c *FingerprintCache) Store(sessionID string, fp *types.CompleteFingerprint) {
	if _, loaded := c.entries.LoadOrStore(sessionID, fp); !loaded {
		c.size.Add(1)
	} else {
		c.entries.Store(sessionID, fp)
	}
}

// Load retrieves a session's fingerprint. Returns nil if not found.
func (c *FingerprintCache) Load(sessionID string) *types.CompleteFingerprint {
	v, ok := c.entries.Load(sessionID)
	if !ok {
		return nil
	}
	return v.(*types.CompleteFingerprint)
}

// Delete removes an entry (call on session deletion).
func (c *FingerprintCache) Delete(sessionID string) {
	if _, loaded := c.entries.LoadAndDelete(sessionID); loaded {
		c.size.Add(-1)
	}
}

// Size returns the number of cached entries.
func (c *FingerprintCache) Size() int {
	return int(c.size.Load())
}
