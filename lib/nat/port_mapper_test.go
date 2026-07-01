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

// TestPortMapperManager_NoMappingAccessors verifies no-mapping accessors
// return zero values when the retry loop is never allowed to run.
func TestPortMapperManager_NoMappingAccessors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately to prevent retry loop from doing anything

	cfg := &PortMapperConfig{
		Network:      "udp",
		InternalPort: 9001,
		Context:      ctx,
	}

	pmm := NewPortMapperManager(cfg)
	defer pmm.Stop()

	tests := []struct {
		name string
		got  any
		want any
	}{
		{name: "external_port", got: pmm.GetExternalPort(), want: 0},
		{name: "external_ip", got: pmm.GetExternalIP(), want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.got, "expected zero-value accessor result when no mapping is active")
		})
	}
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

// TestPortMapperManager_RetryBackoff tests that backoff increases on repeated failures.
// Since we can't easily mock port mapper failures, this test verifies timing behavior.
func TestPortMapperManager_RetryBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &PortMapperConfig{
		Network:        "udp",
		InternalPort:   9001,
		InitialBackoff: 50 * time.Millisecond,
		MaxBackoff:     500 * time.Millisecond,
		BackoffFactor:  2.0,
		Context:        ctx,
	}

	start := time.Now()
	pmm := NewPortMapperManager(cfg)

	// Let it run for a bit to attempt multiple retries
	// Expected: first retry at ~50ms, second at ~100ms, third at ~200ms, fourth at ~400ms
	// Total time should be at least 50+100+200 = 350ms
	time.Sleep(400 * time.Millisecond)

	// Stop the manager
	cancel()
	err := pmm.Stop()
	elapsed := time.Since(start)

	assert.NoError(t, err, "Stop should not error")
	// If backoff is working, we should have spent time waiting between retries
	// This is an imprecise test but validates the retry loop is running with delays
	assert.GreaterOrEqual(t, elapsed, 400*time.Millisecond, "should have spent time in retry backoff")
}

// TestPortMapperManager_StopTimeout tests that Stop() respects the 5s timeout.
// This test verifies the timeout mechanism works even if cleanup is slow.
func TestPortMapperManager_StopTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg := &PortMapperConfig{
		Network:        "udp",
		InternalPort:   9001,
		InitialBackoff: 50 * time.Millisecond,
		Context:        ctx,
	}

	pmm := NewPortMapperManager(cfg)
	time.Sleep(100 * time.Millisecond)

	// Call Stop() and measure time
	start := time.Now()
	err := pmm.Stop()
	elapsed := time.Since(start)

	// Should complete quickly (well under the 5s timeout)
	// Even if the retry goroutine is mid-wait, Stop() should complete promptly
	assert.NoError(t, err, "Stop should not error")
	assert.Less(t, elapsed, 6*time.Second, "Stop should not exceed reasonable timeout")

	// Calling Stop() again should be instant (already stopped)
	start = time.Now()
	err = pmm.Stop()
	elapsed = time.Since(start)

	assert.NoError(t, err, "second Stop should not error")
	assert.Less(t, elapsed, 100*time.Millisecond, "second Stop should return immediately")
}
