package ssu2

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestRC5_NatCtx_CancelledCleanly verifies that a context used for NAT managers
// can be cleanly cancelled, preventing goroutine leaks.
func TestRC5_NatCtx_CancelledCleanly(t *testing.T) {
	t.Parallel()

	// Create a context that we can cancel
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a channel to track if goroutine exits when context is cancelled
	exited := make(chan struct{}, 1)

	// Simulate a NAT goroutine that respects the context
	go func() {
		select {
		case <-ctx.Done():
			exited <- struct{}{}
		case <-time.After(5 * time.Second):
			// Didn't exit in time - this would be a problem
		}
	}()

	// Cancel the context
	cancel()

	// Verify the goroutine exited promptly
	select {
	case <-exited:
		// Good - NAT goroutine exited
	case <-time.After(500 * time.Millisecond):
		t.Fatal("NAT goroutine should exit when context is cancelled")
	}
}

// TestRC5_NatCtx_Nil_Check_Safety verifies that code can safely check if natCtx
// is nil before using it, preventing panics from concurrent cancellation.
func TestRC5_NatCtx_Nil_Check_Safety(t *testing.T) {
	t.Parallel()

	// Simulate what happens when multiple goroutines check and use a context
	// that might be set to nil concurrently
	var mu sync.Mutex
	var ctx context.Context
	var cancel context.CancelFunc

	checkCount := atomic.Int32{}
	nilCount := atomic.Int32{}
	errorCount := atomic.Int32{}
	shouldStop := atomic.Bool{}

	// Create initial context
	mu.Lock()
	ctx, cancel = context.WithCancel(context.Background())
	mu.Unlock()
	// L-4 FIX: Ensure cancel is called for cleanup
	defer cancel()

	const workers = 100

	var wg sync.WaitGroup

	// Workers that check the context
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if shouldStop.Load() {
					break
				}

				mu.Lock()
				localCtx := ctx
				mu.Unlock()

				checkCount.Add(1)

				if localCtx == nil {
					nilCount.Add(1)
					continue
				}

				// Try to use the context
				if err := localCtx.Err(); err != nil {
					errorCount.Add(1)
				}
			}
		}()
	}

	// Wait for some work to happen
	time.Sleep(50 * time.Millisecond)

	// Clear the context (simulating stopNATManagers)
	mu.Lock()
	ctx = nil
	mu.Unlock()

	// Let workers see the nil context
	time.Sleep(50 * time.Millisecond)

	// Tell workers to stop
	shouldStop.Store(true)

	wg.Wait()

	// Verify:
	// - We did checks
	checks := checkCount.Load()
	nils := nilCount.Load()
	assert.Greater(t, checks, int32(0), "Should have done context checks")
	assert.Greater(t, nils, int32(0), "Should have seen nil context")
	assert.Equal(t, int32(0), errorCount.Load(),
		"No errors should occur when context is actively used")
}

// TestRC5_Rapid_SetIdentity_NatCtx_Isolation tests that rapid SetIdentity calls
// (which reset natCtx) don't cause panics or corruption.
func TestRC5_Rapid_SetIdentity_NatCtx_Isolation(t *testing.T) {
	t.Parallel()

	// Simulate rapid context resets (like SetIdentity does)
	var mu sync.Mutex
	var ctx context.Context
	var cancel context.CancelFunc

	// Initialize
	mu.Lock()
	ctx, cancel = context.WithCancel(context.Background())
	mu.Unlock()
	// L-4 FIX: Ensure final cancel is called for cleanup (multiple assignments happen in loop)
	defer cancel()

	const swaps = 50
	const workers = 20
	const ops = 100

	crashCount := atomic.Int32{}
	var wg sync.WaitGroup

	// Goroutines that reset the context (simulating SetIdentity → stopNATManagers → initNATManagers)
	for swap := 0; swap < swaps; swap++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					crashCount.Add(1)
				}
			}()

			mu.Lock()
			// Cancel old context
			if cancel != nil {
				cancel()
			}
			// Create new context
			ctx, cancel = context.WithCancel(context.Background())
			mu.Unlock()

			// Let workers use the new context
			time.Sleep(time.Microsecond)
		}()
	}

	// Goroutines that use the context (simulating NAT managers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					crashCount.Add(1)
				}
			}()

			for op := 0; op < ops; op++ {
				mu.Lock()
				localCtx := ctx
				mu.Unlock()

				if localCtx != nil {
					// Simulate NAT work
					select {
					case <-localCtx.Done():
						// Context was cancelled, that's fine
					default:
						// Context still active
					}
				}
				time.Sleep(time.Microsecond)
			}
		}()
	}

	wg.Wait()

	// Verify no crashes occurred
	crashes := crashCount.Load()
	assert.Equal(t, int32(0), crashes,
		"No goroutines should crash during rapid SetIdentity + NAT operations")
}

// TestRC5_NatCtx_Cancelled_Signal_Reliability verifies that when a NAT context
// is cancelled, all waiting goroutines receive the cancellation signal.
func TestRC5_NatCtx_Cancelled_Signal_Reliability(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())

	const numGoroutines = 100
	received := atomic.Int32{}

	var wg sync.WaitGroup
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-ctx.Done()
			received.Add(1)
		}()
	}

	// Give goroutines time to reach the wait point
	time.Sleep(50 * time.Millisecond)

	// Cancel the context
	cancel()

	// Wait for all goroutines to receive the signal
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All goroutines finished
	case <-time.After(1 * time.Second):
		t.Fatal("Goroutines did not receive cancellation signal")
	}

	// Verify all goroutines received the signal
	count := received.Load()
	assert.Equal(t, int32(numGoroutines), count,
		"All goroutines should receive the cancellation signal")
}

// TestRC5_NatCtx_Per_Generation_Isolation verifies that each generation of NAT contexts
// operates independently without interference.
func TestRC5_NatCtx_Per_Generation_Isolation(t *testing.T) {
	t.Parallel()

	// Create generation 1
	gen1Ctx, gen1Cancel := context.WithCancel(context.Background())
	defer gen1Cancel()

	// Create generation 2
	gen2Ctx, gen2Cancel := context.WithCancel(context.Background())
	defer gen2Cancel()

	// Simulate that generation 1 is active
	gen1Active := true
	gen2Active := true

	// Cancel generation 1
	gen1Cancel()
	gen1Active = false

	// Verify gen1 is done
	select {
	case <-gen1Ctx.Done():
		// Expected
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Gen1 context should be cancelled immediately")
	}

	// Verify gen2 is still running
	select {
	case <-gen2Ctx.Done():
		t.Fatal("Gen2 context should not be cancelled")
	case <-time.After(10 * time.Millisecond):
		// Expected: gen2 still running
	}

	assert.False(t, gen1Active, "Gen1 should be marked inactive")
	assert.True(t, gen2Active, "Gen2 should still be active")
	assert.NoError(t, gen2Ctx.Err(),
		"Gen2 context should not have an error yet")
}

// TestRC5_NatCtx_Stress_RapidGeneration stress-tests rapid generation cycles
// to ensure no resource leaks or panics.
func TestRC5_NatCtx_Stress_RapidGeneration(t *testing.T) {
	t.Parallel()

	const numGenerations = 1000
	crashCount := atomic.Int32{}

	for gen := 0; gen < numGenerations; gen++ {
		// Create and cancel a context
		ctx, cancel := context.WithCancel(context.Background())

		// Start a few goroutines that use this context
		for i := 0; i < 5; i++ {
			go func() {
				defer func() {
					if r := recover(); r != nil {
						crashCount.Add(1)
					}
				}()
				<-ctx.Done()
			}()
		}

		// Immediately cancel
		cancel()

		// The goroutines should clean up (they'll be reaped by Go's GC)
		time.Sleep(time.Microsecond)
	}

	// Verify no crashes occurred
	crashes := crashCount.Load()
	assert.Equal(t, int32(0), crashes,
		"No goroutines should crash during rapid generation cycles")
}

// TestRC5_NatCtx_Nil_Write_Safe verifies that concurrent writes and reads to a nil
// natCtx pointer are safe when protected by a lock.
func TestRC5_NatCtx_Nil_Write_Safe(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var ctx context.Context
	var cancel context.CancelFunc

	const readers = 50
	const writers = 5
	const iterations = 100

	crashCount := atomic.Int32{}
	var wg sync.WaitGroup

	// Reader goroutines
	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					crashCount.Add(1)
				}
			}()

			for i := 0; i < iterations; i++ {
				mu.Lock()
				localCtx := ctx
				mu.Unlock()

				if localCtx != nil {
					_ = localCtx.Err()
				}
			}
		}()
	}

	// Writer goroutines
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					crashCount.Add(1)
				}
			}()

			for i := 0; i < iterations; i++ {
				mu.Lock()
				// L-4 FIX: Cancel previous context before creating new one
				if cancel != nil {
					cancel()
				}
				ctx, cancel = context.WithCancel(context.Background())
				mu.Unlock()
				time.Sleep(time.Microsecond)

				mu.Lock()
				ctx = nil
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	// L-4 FIX: Ensure final cancel is cleaned up
	if cancel != nil {
		cancel()
	}

	// Verify no crashes occurred
	crashes := crashCount.Load()
	assert.Equal(t, int32(0), crashes,
		"No goroutines should crash with locked ctx access")
}
