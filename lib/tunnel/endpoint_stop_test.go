package tunnel

import (
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
