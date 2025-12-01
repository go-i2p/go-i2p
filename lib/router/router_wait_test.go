package router

import (
	"sync"
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/stretchr/testify/require"
)

// TestRouterWaitGroupSemantics tests the WaitGroup implementation directly
func TestRouterWaitGroupSemantics(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.DefaultRouterConfig()
	cfg.WorkingDir = tempDir

	router, err := FromConfig(cfg)
	require.NoError(t, err)

	// Simulate starting a goroutine
	router.wg.Add(1)

	// Create channel to track when Wait() completes
	waitDone := make(chan struct{})

	go func() {
		router.Wait()
		close(waitDone)
	}()

	// Wait should not complete immediately
	select {
	case <-waitDone:
		t.Error("Wait() should not complete while WaitGroup counter > 0")
	case <-time.After(50 * time.Millisecond):
		// Expected: Wait() is still blocking
	}

	// Signal goroutine completion
	router.wg.Done()

	// Wait() should now complete
	select {
	case <-waitDone:
		// Expected: Wait() completed after Done()
	case <-time.After(100 * time.Millisecond):
		t.Error("Wait() should complete after wg.Done() is called")
	}
}

// TestRouterMultipleGoroutines tests WaitGroup with multiple goroutines
func TestRouterMultipleGoroutines(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.DefaultRouterConfig()
	cfg.WorkingDir = tempDir

	router, err := FromConfig(cfg)
	require.NoError(t, err)

	const numGoroutines = 3
	var started sync.WaitGroup
	started.Add(numGoroutines)

	// Start multiple "goroutines"
	for i := 0; i < numGoroutines; i++ {
		router.wg.Add(1)
		go func() {
			started.Done()
			time.Sleep(50 * time.Millisecond)
			router.wg.Done()
		}()
	}

	// Wait for all to start
	started.Wait()

	// Now call Wait() - it should block until all Done()
	done := make(chan struct{})
	go func() {
		router.Wait()
		close(done)
	}()

	// Should complete within reasonable time (50ms sleep + overhead)
	select {
	case <-done:
		// Expected: All goroutines finished
	case <-time.After(200 * time.Millisecond):
		t.Error("Wait() should complete when all goroutines finish")
	}
}

// TestRouterMultipleWaiters tests that multiple goroutines can Wait()
func TestRouterMultipleWaiters(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.DefaultRouterConfig()
	cfg.WorkingDir = tempDir

	router, err := FromConfig(cfg)
	require.NoError(t, err)

	// Simulate one active goroutine
	router.wg.Add(1)

	// Start multiple waiters
	const numWaiters = 5
	waiters := make([]chan struct{}, numWaiters)
	for i := 0; i < numWaiters; i++ {
		waiters[i] = make(chan struct{})
		go func(ch chan struct{}) {
			router.Wait()
			close(ch)
		}(waiters[i])
	}

	// Give waiters time to block
	time.Sleep(50 * time.Millisecond)

	// Complete the goroutine
	router.wg.Done()

	// All waiters should complete
	for i, ch := range waiters {
		select {
		case <-ch:
			// Expected
		case <-time.After(100 * time.Millisecond):
			t.Errorf("Waiter %d did not complete", i)
		}
	}
}

// TestRouterWaitWithoutStart tests Wait() when nothing was started
func TestRouterWaitWithoutStart(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.DefaultRouterConfig()
	cfg.WorkingDir = tempDir

	router, err := FromConfig(cfg)
	require.NoError(t, err)

	// Call Wait() without ever adding to WaitGroup
	done := make(chan struct{})
	go func() {
		router.Wait()
		close(done)
	}()

	// Wait should complete immediately since counter is 0
	select {
	case <-done:
		// Expected: Wait() completes immediately
	case <-time.After(100 * time.Millisecond):
		t.Error("Wait() should complete immediately when WaitGroup counter is 0")
	}
}
