package auth

import (
	"strings"
	"sync"
	"sync/atomic"
)

// ConcurrencyLimiter manages per-auth concurrent request slots.
type ConcurrencyLimiter struct {
	mu     sync.Mutex
	counts map[string]*int32 // authID -> current count
}

// NewConcurrencyLimiter creates a new concurrency limiter.
func NewConcurrencyLimiter() *ConcurrencyLimiter {
	return &ConcurrencyLimiter{
		counts: make(map[string]*int32),
	}
}

// getLimit returns the effective concurrency limit for the auth.
// Priority: auth.MaxConcurrency > provider default > unlimited (0).
func (l *ConcurrencyLimiter) getLimit(auth *Auth) int {
	if auth == nil {
		return 0
	}
	if auth.MaxConcurrency > 0 {
		return auth.MaxConcurrency
	}
	// Hardcoded provider defaults
	switch strings.ToLower(auth.Provider) {
	case "iflow":
		return 1
	default:
		return 0 // unlimited
	}
}

// IsFull checks if the auth has reached its concurrency limit.
func (l *ConcurrencyLimiter) IsFull(auth *Auth) bool {
	if auth == nil {
		return false
	}
	limit := l.getLimit(auth)
	if limit <= 0 {
		return false
	}
	l.mu.Lock()
	counter := l.counts[auth.ID]
	l.mu.Unlock()
	if counter == nil {
		return false
	}
	return atomic.LoadInt32(counter) >= int32(limit)
}

// Acquire attempts to acquire a concurrency slot.
// Returns a release function on success, or nil if the limit is reached.
func (l *ConcurrencyLimiter) Acquire(auth *Auth) func() {
	if auth == nil {
		return func() {}
	}
	limit := l.getLimit(auth)
	if limit <= 0 {
		return func() {} // unlimited, return no-op release
	}

	l.mu.Lock()
	counter := l.counts[auth.ID]
	if counter == nil {
		var zero int32
		counter = &zero
		l.counts[auth.ID] = counter
	}
	l.mu.Unlock()

	current := atomic.AddInt32(counter, 1)
	if current > int32(limit) {
		atomic.AddInt32(counter, -1)
		return nil // acquisition failed
	}
	return func() {
		atomic.AddInt32(counter, -1)
	}
}
