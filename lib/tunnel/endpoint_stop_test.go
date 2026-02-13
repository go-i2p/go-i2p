package tunnel

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestEndpoint_StopWaitsForCleanupGoroutine verifies that Stop() blocks until the
// cleanup goroutine has finished, preventing shared state access after Stop returns.
func TestEndpoint_StopWaitsForCleanupGoroutine(t *testing.T) {
	ep := &Endpoint{
		tunnelID:        TunnelID(42),
		fragments:       make(map[uint32]*fragmentAssembler),
		fragmentTimeout: 60 * time.Second,
		stopChan:        make(chan struct{}),
	}

	// Track when cleanup goroutine exits
	var exited int32
	ep.wg.Add(1)
	go func() {
		defer ep.wg.Done()
		defer atomic.StoreInt32(&exited, 1)
		ep.cleanupFragments()
	}()

	// Give the goroutine time to start
	time.Sleep(10 * time.Millisecond)

	// Stop should block until the goroutine finishes
	ep.Stop()

	assert.Equal(t, int32(1), atomic.LoadInt32(&exited),
		"cleanup goroutine should have exited before Stop() returned")
}

// TestEndpoint_StopIdempotentSignal verifies Stop doesn't panic on a simple call.
func TestEndpoint_StopIdempotent(t *testing.T) {
	ep := &Endpoint{
		tunnelID:        TunnelID(99),
		fragments:       make(map[uint32]*fragmentAssembler),
		fragmentTimeout: 60 * time.Second,
		stopChan:        make(chan struct{}),
	}
	ep.wg.Add(1)
	go func() {
		defer ep.wg.Done()
		ep.cleanupFragments()
	}()

	assert.NotPanics(t, func() {
		ep.Stop()
	})
}

// TestEndpoint_StopDoubleCall verifies calling Stop() twice does not panic
// (previously panicked with "close of closed channel" before sync.Once fix).
func TestEndpoint_StopDoubleCall(t *testing.T) {
	ep := &Endpoint{
		tunnelID:        TunnelID(100),
		fragments:       make(map[uint32]*fragmentAssembler),
		fragmentTimeout: 60 * time.Second,
		stopChan:        make(chan struct{}),
	}
	ep.wg.Add(1)
	go func() {
		defer ep.wg.Done()
		ep.cleanupFragments()
	}()

	assert.NotPanics(t, func() {
		ep.Stop()
	}, "First Stop() should not panic")

	assert.NotPanics(t, func() {
		ep.Stop()
	}, "Second Stop() should not panic (sync.Once guards the close)")
}

// TestEndpoint_StopConcurrent verifies that concurrent Stop() calls are safe.
func TestEndpoint_StopConcurrent(t *testing.T) {
	ep := &Endpoint{
		tunnelID:        TunnelID(101),
		fragments:       make(map[uint32]*fragmentAssembler),
		fragmentTimeout: 60 * time.Second,
		stopChan:        make(chan struct{}),
	}
	ep.wg.Add(1)
	go func() {
		defer ep.wg.Done()
		ep.cleanupFragments()
	}()
	time.Sleep(10 * time.Millisecond)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assert.NotPanics(t, func() {
				ep.Stop()
			})
		}()
	}
	wg.Wait()
}
