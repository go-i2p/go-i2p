package nat

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestPortMapperManager_CreateAndStop tests basic lifecycle.
func TestPortMapperManager_CreateAndStop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cfg := &PortMapperConfig{
		Network:        "udp",
		InternalPort:   9001,
		InitialBackoff: 50 * time.Millisecond,
		MaxBackoff:     1 * time.Second,
		BackoffFactor:  2.0,
		Context:        ctx,
	}

	pmm := NewPortMapperManager(cfg)
	assert.NotNil(t, pmm, "manager should be created")

	// Wait briefly to let retry goroutine start
	time.Sleep(100 * time.Millisecond)

	// Stop the manager
	err := pmm.Stop()
	assert.NoError(t, err, "Stop should not return error")
}

// TestPortMapperManager_GetExternalPort_NoMapping tests that GetExternalPort
// returns 0 when no mapping is active.
func TestPortMapperManager_GetExternalPort_NoMapping(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately to prevent retry loop from doing anything

	cfg := &PortMapperConfig{
		Network:      "udp",
		InternalPort: 9001,
		Context:      ctx,
	}

	pmm := NewPortMapperManager(cfg)
	port := pmm.GetExternalPort()
	assert.Equal(t, 0, port, "should return 0 when no mapping active")

	_ = pmm.Stop()
}

// TestPortMapperManager_GetExternalIP_NoMapping tests that GetExternalIP
// returns empty string when no mapping is active.
func TestPortMapperManager_GetExternalIP_NoMapping(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately to prevent retry loop from doing anything

	cfg := &PortMapperConfig{
		Network:      "udp",
		InternalPort: 9001,
		Context:      ctx,
	}

	pmm := NewPortMapperManager(cfg)
	ip := pmm.GetExternalIP()
	assert.Equal(t, "", ip, "should return empty string when no mapping active")

	_ = pmm.Stop()
}

// TestPortMapperManager_StopTwice_Idempotent tests that calling Stop() twice is safe.
func TestPortMapperManager_StopTwice_Idempotent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cfg := &PortMapperConfig{
		Network:        "udp",
		InternalPort:   9001,
		InitialBackoff: 50 * time.Millisecond,
		Context:        ctx,
	}

	pmm := NewPortMapperManager(cfg)

	// First stop
	err := pmm.Stop()
	assert.NoError(t, err, "first Stop should not return error")

	// Second stop should be idempotent
	err = pmm.Stop()
	assert.NoError(t, err, "second Stop should be idempotent and not error")
}

// TestPortMapperManager_ContextCancellation tests that the retry goroutine
// exits when the context is cancelled.
func TestPortMapperManager_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	cfg := &PortMapperConfig{
		Network:        "udp",
		InternalPort:   9001,
		InitialBackoff: 50 * time.Millisecond,
		MaxBackoff:     1 * time.Second,
		Context:        ctx,
	}

	pmm := NewPortMapperManager(cfg)

	// Wait briefly to let retry goroutine start
	time.Sleep(100 * time.Millisecond)

	// Cancel the context
	cancel()

	// Wait for goroutine to exit
	done := make(chan struct{})
	go func() {
		pmm.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Goroutine exited as expected
	case <-time.After(2 * time.Second):
		t.Fatal("retry goroutine did not exit after context cancellation")
	}

	// Clean up
	_ = pmm.Stop()
}

// TestPortMapperManager_ConcurrentGetExternalPort tests concurrent access to GetExternalPort.
func TestPortMapperManager_ConcurrentGetExternalPort(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cfg := &PortMapperConfig{
		Network:        "udp",
		InternalPort:   9001,
		InitialBackoff: 50 * time.Millisecond,
		Context:        ctx,
	}

	pmm := NewPortMapperManager(cfg)
	defer pmm.Stop()

	// Spawn multiple goroutines calling GetExternalPort concurrently
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_ = pmm.GetExternalPort()
			}
			done <- struct{}{}
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestPortMapperManager_StopDuringRetry tests calling Stop() while retry is active.
func TestPortMapperManager_StopDuringRetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg := &PortMapperConfig{
		Network:        "udp",
		InternalPort:   9001,
		InitialBackoff: 100 * time.Millisecond,
		MaxBackoff:     5 * time.Second,
		Context:        ctx,
	}

	pmm := NewPortMapperManager(cfg)

	// Wait briefly to ensure retry loop is active
	time.Sleep(150 * time.Millisecond)

	// Stop should cleanly shut down even if retry is ongoing
	start := time.Now()
	err := pmm.Stop()
	elapsed := time.Since(start)

	assert.NoError(t, err, "Stop should not error")
	assert.Less(t, elapsed, 6*time.Second, "Stop should not block for too long")
}
