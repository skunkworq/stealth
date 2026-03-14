package session

import (
	"fmt"
	"sync"
	"testing"

	"github.com/skunkworq/stealth/brws/types"
)

func TestFingerprintCache_StoreAndLoad(t *testing.T) {
	c := &FingerprintCache{}
	fp := &types.CompleteFingerprint{ID: "test-fp"}
	c.Store("sess-1", fp)

	got := c.Load("sess-1")
	if got == nil {
		t.Fatal("expected fingerprint, got nil")
	}
	if got.ID != "test-fp" {
		t.Errorf("fingerprint ID = %s, want test-fp", got.ID)
	}
}

func TestFingerprintCache_LoadMissing(t *testing.T) {
	c := &FingerprintCache{}
	if got := c.Load("nonexistent"); got != nil {
		t.Errorf("expected nil for missing key, got %v", got)
	}
}

func TestFingerprintCache_Delete(t *testing.T) {
	c := &FingerprintCache{}
	c.Store("sess-1", &types.CompleteFingerprint{ID: "fp1"})
	c.Delete("sess-1")
	if got := c.Load("sess-1"); got != nil {
		t.Error("expected nil after delete")
	}
	if c.Size() != 0 {
		t.Errorf("size should be 0 after delete, got %d", c.Size())
	}
}

func TestFingerprintCache_Size(t *testing.T) {
	c := &FingerprintCache{}
	for i := 0; i < 10; i++ {
		c.Store(fmt.Sprintf("sess-%d", i), &types.CompleteFingerprint{ID: fmt.Sprintf("fp-%d", i)})
	}
	if c.Size() != 10 {
		t.Errorf("size = %d, want 10", c.Size())
	}
}

func TestFingerprintCache_ConcurrentAccess(t *testing.T) {
	c := &FingerprintCache{}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			id := fmt.Sprintf("sess-%d", n)
			c.Store(id, &types.CompleteFingerprint{ID: fmt.Sprintf("fp-%d", n)})
			_ = c.Load(id)
		}(i)
	}
	wg.Wait()
	if c.Size() != 100 {
		t.Errorf("size after concurrent stores = %d, want 100", c.Size())
	}
}
