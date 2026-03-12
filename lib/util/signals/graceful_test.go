package signals

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// resetPreShutdownHandlers saves and clears preShutdownHandlers, restoring them
// via t.Cleanup. If restoreTimeout is true, gracefulTimeout is also saved/restored.
func resetPreShutdownHandlers(t *testing.T, restoreTimeout bool) {
	t.Helper()
	originalHandlers := preShutdownHandlers
	var originalTimeout time.Duration
	if restoreTimeout {
		originalTimeout = gracefulTimeout
	}
	t.Cleanup(func() {
		preShutdownMu.Lock()
		preShutdownHandlers = originalHandlers
		if restoreTimeout {
			gracefulTimeout = originalTimeout
		}
		preShutdownMu.Unlock()
	})
	preShutdownMu.Lock()
	preShutdownHandlers = nil
	preShutdownMu.Unlock()
}

// =============================================================================
// Pre-Shutdown Handler Registration Tests
// =============================================================================

// TestRegisterPreShutdownHandler verifies pre-shutdown handler registration.
func TestRegisterPreShutdownHandler(t *testing.T) {
	resetPreShutdownHandlers(t, false)

	called := false
	RegisterPreShutdownHandler(func() {
		called = true
	})

	preShutdownMu.RLock()
	count := len(preShutdownHandlers)
	preShutdownMu.RUnlock()

	if count != 1 {
		t.Errorf("expected 1 pre-shutdown handler registered, got %d", count)
	}

	handlePreShutdown()

	if !called {
		t.Error("pre-shutdown handler was not called")
	}
}

// TestRegisterPreShutdownHandler_Nil verifies nil handlers are ignored.
func TestRegisterPreShutdownHandler_Nil(t *testing.T) {
	resetPreShutdownHandlers(t, false)

	RegisterPreShutdownHandler(nil)

	preShutdownMu.RLock()
	count := len(preShutdownHandlers)
	preShutdownMu.RUnlock()

	if count != 0 {
		t.Errorf("nil handler should not be registered, got %d handlers", count)
	}
}

// TestPreShutdownHandlers_CalledInOrder verifies FIFO order.
func TestPreShutdownHandlers_CalledInOrder(t *testing.T) {
	resetPreShutdownHandlers(t, false)
	assertHandlersCalledInOrder(t, func(f func()) { RegisterPreShutdownHandler(f) }, func() { handlePreShutdown() })
}

// TestPreShutdownHandlers_Empty verifies empty handler list returns true.
func TestPreShutdownHandlers_Empty(t *testing.T) {
	resetPreShutdownHandlers(t, false)

	if !handlePreShutdown() {
		t.Error("expected true for empty handler list")
	}
}

// TestPreShutdownHandlers_ReturnsTrue verifies success return when all handlers complete.
func TestPreShutdownHandlers_ReturnsTrue(t *testing.T) {
	resetPreShutdownHandlers(t, true)

	RegisterPreShutdownHandler(func() {
		// fast handler
	})

	if !handlePreShutdown() {
		t.Error("expected true when handlers complete within timeout")
	}
}

// TestPreShutdownHandlers_Timeout verifies timeout behavior.
func TestPreShutdownHandlers_Timeout(t *testing.T) {
	resetPreShutdownHandlers(t, true)

	SetGracefulTimeout(2 * time.Second)

	RegisterPreShutdownHandler(func() {
		time.Sleep(10 * time.Second) // Exceeds per-handler timeout
	})

	if handlePreShutdown() {
		t.Error("expected false when handlers exceed timeout")
	}
}

// TestPreShutdownHandlers_HungHandlerDoesNotBlockChain verifies that a hung
// handler does not prevent subsequent handlers from running (BUG #4 fix).
func TestPreShutdownHandlers_HungHandlerDoesNotBlockChain(t *testing.T) {
	resetPreShutdownHandlers(t, true)

	// 4 seconds total / 2 handlers = 2 seconds per handler
	SetGracefulTimeout(4 * time.Second)

	secondCalled := false

	// First handler hangs forever
	RegisterPreShutdownHandler(func() {
		select {} // block indefinitely
	})
	// Second handler (e.g., zero-address DatabaseStore) must still execute
	RegisterPreShutdownHandler(func() {
		secondCalled = true
	})

	result := handlePreShutdown()

	if result {
		t.Error("expected false when first handler hangs")
	}
	if !secondCalled {
		t.Error("second handler should have been called despite first handler hanging")
	}
}

// TestDeregisterPreShutdownHandler verifies pre-shutdown handler deregistration.
func TestDeregisterPreShutdownHandler(t *testing.T) {
	resetPreShutdownHandlers(t, false)

	assertDeregisterRemovesHandler(t,
		RegisterPreShutdownHandler,
		DeregisterPreShutdownHandler,
		func() { handlePreShutdown() },
		func() int { preShutdownMu.RLock(); defer preShutdownMu.RUnlock(); return len(preShutdownHandlers) },
	)
}

// TestPreShutdownHandlers_PanicRecovery verifies panic recovery in pre-shutdown handlers.
func TestPreShutdownHandlers_PanicRecovery(t *testing.T) {
	resetPreShutdownHandlers(t, false)

	var result bool
	assertPanicRecovery(t, RegisterPreShutdownHandler, func() {
		result = handlePreShutdown()
	})

	if !result {
		t.Error("expected true even with panicking handler (others completed)")
	}
}

// =============================================================================
// SetGracefulTimeout Tests
// =============================================================================

// TestSetGracefulTimeout verifies timeout configuration for various inputs.
func TestSetGracefulTimeout(t *testing.T) {
	tests := []struct {
		name     string
		input    time.Duration
		expected time.Duration
	}{
		{"Positive", 10 * time.Second, 10 * time.Second},
		{"Zero", 0, defaultGracefulTimeout},
		{"Negative", -5 * time.Second, defaultGracefulTimeout},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			originalTimeout := gracefulTimeout
			t.Cleanup(func() {
				preShutdownMu.Lock()
				gracefulTimeout = originalTimeout
				preShutdownMu.Unlock()
			})

			SetGracefulTimeout(tc.input)

			preShutdownMu.RLock()
			timeout := gracefulTimeout
			preShutdownMu.RUnlock()

			if timeout != tc.expected {
				t.Errorf("expected %s timeout, got %s", tc.expected, timeout)
			}
		})
	}
}

// =============================================================================
// Concurrent Registration Tests
// =============================================================================

// TestPreShutdownConcurrentRegistration verifies thread-safe handler registration.
func TestPreShutdownConcurrentRegistration(t *testing.T) {
	resetPreShutdownHandlers(t, false)

	var wg sync.WaitGroup
	numGoroutines := 50
	var callCount int64

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			RegisterPreShutdownHandler(func() {
				atomic.AddInt64(&callCount, 1)
			})
		}()
	}
	wg.Wait()

	preShutdownMu.RLock()
	count := len(preShutdownHandlers)
	preShutdownMu.RUnlock()

	if count != numGoroutines {
		t.Errorf("expected %d handlers, got %d", numGoroutines, count)
	}

	handlePreShutdown()

	if atomic.LoadInt64(&callCount) != int64(numGoroutines) {
		t.Errorf("expected %d handlers called, got %d", numGoroutines, atomic.LoadInt64(&callCount))
	}
}

// =============================================================================
// Integration: Pre-shutdown runs before interrupt
// =============================================================================

// TestPreShutdownRunsBeforeInterrupt verifies that in a simulated shutdown,
// pre-shutdown handlers complete before interrupt handlers start.
func TestPreShutdownRunsBeforeInterrupt(t *testing.T) {
	resetPreShutdownHandlers(t, false)
	originalInterrupters := interrupters
	t.Cleanup(func() {
		mu.Lock()
		interrupters = originalInterrupters
		mu.Unlock()
	})
	mu.Lock()
	interrupters = nil
	mu.Unlock()

	var orderMu sync.Mutex
	order := make([]string, 0, 2)

	RegisterPreShutdownHandler(func() {
		orderMu.Lock()
		order = append(order, "pre-shutdown")
		orderMu.Unlock()
	})
	RegisterInterruptHandler(func() {
		orderMu.Lock()
		order = append(order, "interrupt")
		orderMu.Unlock()
	})

	// Simulate the shutdown sequence (same as unix.go / windows.go)
	handlePreShutdown()
	handleInterrupted()

	orderMu.Lock()
	defer orderMu.Unlock()

	if len(order) != 2 {
		t.Fatalf("expected 2 events, got %d", len(order))
	}
	if order[0] != "pre-shutdown" {
		t.Errorf("expected pre-shutdown first, got %s", order[0])
	}
	if order[1] != "interrupt" {
		t.Errorf("expected interrupt second, got %s", order[1])
	}
}
