// Package pool provides browser instance pooling for efficient resource reuse.
package instancepool

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/skunkworq/stealth/brws/core/constants"
	"github.com/skunkworq/stealth/brws/browser/engine"
)

// BrowserInstance represents a pooled browser instance
type BrowserInstance struct {
	Engine    engine.Engine
	ID        string
	CreatedAt time.Time
	LastUsed  time.Time
	Uses      int
}

// Pool manages a pool of browser instances
type Pool struct {
	config    *Config
	instances chan *BrowserInstance
	mu        sync.RWMutex
	factory   EngineFactory
	stats     PoolStats
}

// EngineFactory creates new engine instances
type EngineFactory func() (engine.Engine, error)

// Config for the pool
type Config struct {
	MaxSize     int           // Maximum number of instances
	MinSize     int           // Minimum number of instances (pre-created)
	MaxUses     int           // Maximum uses per instance before recycling
	MaxAge      time.Duration // Maximum age before recycling
	IdleTimeout time.Duration // Idle time before instance is recycled
}

// PoolStats tracks pool statistics.
//
//nolint:revive // Type name stuttering is intentional for clarity
type PoolStats struct {
	Created  int64
	Recycled int64
	Active   int64
	Requests int64
	Errors   int64
}

// DefaultConfig returns a default pool configuration
func DefaultConfig() *Config {
	return &Config{
		MaxSize:     10,
		MinSize:     2,
		MaxUses:     100,
		MaxAge:      10 * time.Minute,
		IdleTimeout: 5 * time.Minute,
	}
}

// New creates a new browser pool
func New(factory EngineFactory, cfg *Config) (*Pool, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// Apply defaults for zero values
	if cfg.MaxSize == 0 {
		cfg.MaxSize = 10
	}

	if cfg.MinSize == 0 {
		cfg.MinSize = 2
	}
	if cfg.MaxUses == 0 {
		cfg.MaxUses = 100
	}

	if cfg.MaxAge == 0 {
		cfg.MaxAge = 10 * time.Minute
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 5 * time.Minute
	}

	p := &Pool{
		config:    cfg,
		instances: make(chan *BrowserInstance, cfg.MaxSize),
		factory:   factory,
		stats:     PoolStats{},
	}

	// Pre-create minimum instances
	for i := 0; i < cfg.MinSize; i++ {
		inst, err := p.createInstance()
		if err != nil {
			return nil, fmt.Errorf("creating initial instance: %w", err)
		}

		p.instances <- inst
	}

	// Start cleanup goroutine
	go p.cleanupLoop()

	return p, nil
}

// createInstance creates a new browser instance
func (p *Pool) createInstance() (*BrowserInstance, error) {
	eng, err := p.factory()
	if err != nil {
		return nil, err
	}

	inst := &BrowserInstance{
		Engine:    eng,
		ID:        fmt.Sprintf("inst-%d", time.Now().UnixNano()),
		CreatedAt: time.Now(),
		LastUsed:  time.Now(),
		Uses:      0,
	}

	p.mu.Lock()
	p.stats.Created++
	p.mu.Unlock()

	return inst, nil
}

// Acquire gets an instance from the pool
func (p *Pool) Acquire(ctx context.Context) (*BrowserInstance, error) {
	select {
	case inst := <-p.instances:
		// Check if instance needs recycling
		if p.needsRecycle(inst) {
			_ = p.recycle(inst)
			newInst, err := p.createInstance()
			if err != nil {
				return nil, err
			}
			inst = newInst
		}

		inst.LastUsed = time.Now()
		inst.Uses++

		p.mu.Lock()
		p.stats.Requests++
		p.stats.Active++
		p.mu.Unlock()

		return inst, nil

	default:
		// Pool is empty, try to create a new one
		p.mu.Lock()
		if p.stats.Active >= int64(p.config.MaxSize) {
			p.mu.Unlock()
			// Wait for an instance
			select {
			case inst := <-p.instances:
				p.mu.Lock()
				p.stats.Active++
				p.mu.Unlock()
				return inst, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(constants.DefaultTimeout):
				return nil, fmt.Errorf("timeout waiting for available instance")
			}
		}
		p.mu.Unlock()

		inst, err := p.createInstance()
		if err != nil {
			p.mu.Lock()
			p.stats.Errors++
			p.mu.Unlock()
			return nil, err
		}
		p.mu.Lock()
		p.stats.Active++
		p.mu.Unlock()

		return inst, nil
	}
}

// Release returns an instance to the pool
func (p *Pool) Release(inst *BrowserInstance) {
	if inst == nil {
		return
	}

	p.mu.Lock()
	p.stats.Active--
	p.mu.Unlock()

	// Check if we should recycle
	if p.needsRecycle(inst) {
		_ = p.recycle(inst)
		inst = nil
	}

	// Return to pool if still valid
	if inst != nil {
		select {
		case p.instances <- inst:
		default:
			// Pool is full, close the instance
			_ = inst.Engine.Close()
		}
	}
}

// needsRecycle checks if an instance needs to be recycled
func (p *Pool) needsRecycle(inst *BrowserInstance) bool {
	if inst.Uses >= p.config.MaxUses {
		return true
	}
	if time.Since(inst.CreatedAt) >= p.config.MaxAge {
		return true
	}
	if time.Since(inst.LastUsed) >= p.config.IdleTimeout {
		return true
	}
	return false
}

// recycle recycles an instance
func (p *Pool) recycle(inst *BrowserInstance) error {
	_ = inst.Engine.Close()

	p.mu.Lock()
	p.stats.Recycled++
	p.mu.Unlock()

	return nil
}

// cleanupLoop periodically cleans up idle instances
func (p *Pool) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		p.mu.Lock()
		currentActive := p.stats.Active
		p.mu.Unlock()

		// If we have too many active instances, release some
		if currentActive > int64(p.config.MinSize) {
			select {
			case inst := <-p.instances:
				if time.Since(inst.LastUsed) >= p.config.IdleTimeout {
					_ = p.recycle(inst)
				} else {
					p.Release(inst)
				}
			default:
			}
		}
	}
}

// Stats returns current pool statistics
func (p *Pool) Stats() PoolStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.stats
}

// Close closes all instances in the pool
func (p *Pool) Close() error {
	close(p.instances)

	for inst := range p.instances {
		_ = inst.Engine.Close()
	}

	return nil
}

// PooledEngine wraps an engine with pool support
type PooledEngine struct {
	pool   *Pool
	inst   *BrowserInstance
	mu     sync.Mutex
	closed bool
}

// AcquireEngine acquires an engine from the pool
func AcquireEngine(ctx context.Context, pool *Pool) (*PooledEngine, error) {
	inst, err := pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}

	return &PooledEngine{
		pool: pool,
		inst: inst,
	}, nil
}

// Do executes a request using the pooled engine
func (pe *PooledEngine) Do(ctx context.Context, req *engine.Request) (*engine.Response, error) {
	pe.mu.Lock()
	closed := pe.closed
	pe.mu.Unlock()
	if closed {
		return nil, fmt.Errorf("engine already closed")
	}
	return pe.inst.Engine.Do(ctx, req)
}

// Release returns the engine to the pool
func (pe *PooledEngine) Release() {
	pe.mu.Lock()
	if pe.closed {
		pe.mu.Unlock()
		return
	}
	pe.closed = true
	pe.mu.Unlock()
	pe.pool.Release(pe.inst)
}

// Engine returns the underlying engine
func (pe *PooledEngine) Engine() engine.Engine {
	return pe.inst.Engine
}
