package signals

import (
	"bytes"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// =============================================================================
// Pre-Shutdown Handler Registration Tests
// =============================================================================

// TestRegisterPreShutdownHandler verifies pre-shutdown handler registration.
func TestRegisterPreShutdownHandler(t *testing.T) {
	originalHandlers := preShutdownHandlers
	defer func() {
		preShutdownMu.Lock()
		preShutdownHandlers = originalHandlers
		preShutdownMu.Unlock()
	}()

	preShutdownMu.Lock()
	preShutdownHandlers = nil
	preShutdownMu.Unlock()

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
	originalHandlers := preShutdownHandlers
	defer func() {
		preShutdownMu.Lock()
		preShutdownHandlers = originalHandlers
		preShutdownMu.Unlock()
	}()

	preShutdownMu.Lock()
	preShutdownHandlers = nil
	preShutdownMu.Unlock()

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
	originalHandlers := preShutdownHandlers
	defer func() {
		preShutdownMu.Lock()
		preShutdownHandlers = originalHandlers
		preShutdownMu.Unlock()
	}()

	preShutdownMu.Lock()
	preShutdownHandlers = nil
	preShutdownMu.Unlock()

	var mu sync.Mutex
	order := make([]int, 0, 3)

	for i := 0; i < 3; i++ {
		idx := i
		RegisterPreShutdownHandler(func() {
			mu.Lock()
			order = append(order, idx)
			mu.Unlock()
		})
	}

	handlePreShutdown()

	mu.Lock()
	defer mu.Unlock()

	if len(order) != 3 {
		t.Fatalf("expected 3 handlers called, got %d", len(order))
	}
	for i := 0; i < 3; i++ {
		if order[i] != i {
			t.Errorf("expected handler %d at position %d, got %d", i, i, order[i])
		}
	}
}

// TestPreShutdownHandlers_Empty verifies empty handler list returns true.
func TestPreShutdownHandlers_Empty(t *testing.T) {
	originalHandlers := preShutdownHandlers
	defer func() {
		preShutdownMu.Lock()
		preShutdownHandlers = originalHandlers
		preShutdownMu.Unlock()
	}()

	preShutdownMu.Lock()
	preShutdownHandlers = nil
	preShutdownMu.Unlock()

	if !handlePreShutdown() {
		t.Error("expected true for empty handler list")
	}
}

// TestPreShutdownHandlers_ReturnsTrue verifies success return when all handlers complete.
func TestPreShutdownHandlers_ReturnsTrue(t *testing.T) {
	originalHandlers := preShutdownHandlers
	originalTimeout := gracefulTimeout
	defer func() {
		preShutdownMu.Lock()
		preShutdownHandlers = originalHandlers
		gracefulTimeout = originalTimeout
		preShutdownMu.Unlock()
	}()

	preShutdownMu.Lock()
	preShutdownHandlers = nil
	preShutdownMu.Unlock()

	RegisterPreShutdownHandler(func() {
		// fast handler
	})

	if !handlePreShutdown() {
		t.Error("expected true when handlers complete within timeout")
	}
}

// TestPreShutdownHandlers_Timeout verifies timeout behavior.
func TestPreShutdownHandlers_Timeout(t *testing.T) {
	originalHandlers := preShutdownHandlers
	originalTimeout := gracefulTimeout
	defer func() {
		preShutdownMu.Lock()
		preShutdownHandlers = originalHandlers
		gracefulTimeout = originalTimeout
		preShutdownMu.Unlock()
	}()

	preShutdownMu.Lock()
	preShutdownHandlers = nil
	preShutdownMu.Unlock()

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
	originalHandlers := preShutdownHandlers
	originalTimeout := gracefulTimeout
	defer func() {
		preShutdownMu.Lock()
		preShutdownHandlers = originalHandlers
		gracefulTimeout = originalTimeout
		preShutdownMu.Unlock()
	}()

	preShutdownMu.Lock()
	preShutdownHandlers = nil
	preShutdownMu.Unlock()

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
	originalHandlers := preShutdownHandlers
	defer func() {
		preShutdownMu.Lock()
		preShutdownHandlers = originalHandlers
		preShutdownMu.Unlock()
	}()

	preShutdownMu.Lock()
	preShutdownHandlers = nil
	preShutdownMu.Unlock()

	called := false
	id := RegisterPreShutdownHandler(func() { called = true })

	DeregisterPreShutdownHandler(id)

	preShutdownMu.RLock()
	count := len(preShutdownHandlers)
	preShutdownMu.RUnlock()

	if count != 0 {
		t.Errorf("Expected 0 handlers after deregistration, got %d", count)
	}

	handlePreShutdown()

	if called {
		t.Error("Deregistered handler should not have been called")
	}
}

// TestPreShutdownHandlers_PanicRecovery verifies panic recovery in pre-shutdown handlers.
func TestPreShutdownHandlers_PanicRecovery(t *testing.T) {
	originalHandlers := preShutdownHandlers
	defer func() {
		preShutdownMu.Lock()
		preShutdownHandlers = originalHandlers
		preShutdownMu.Unlock()
	}()

	preShutdownMu.Lock()
	preShutdownHandlers = nil
	preShutdownMu.Unlock()

	calledAfterPanic := false

	RegisterPreShutdownHandler(func() {
		panic("test panic in pre-shutdown")
	})
	RegisterPreShutdownHandler(func() {
		calledAfterPanic = true
	})

	// Capture stderr output
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	result := handlePreShutdown()

	w.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	b := make([]byte, 1024)
	n, _ := r.Read(b)
	buf.Write(b[:n])

	if !result {
		t.Error("expected true even with panicking handler (others completed)")
	}
	if !calledAfterPanic {
		t.Error("handler after panicking handler was not called")
	}
	if buf.Len() == 0 {
		t.Error("expected panic to be logged to stderr")
	}
}

// =============================================================================
// SetGracefulTimeout Tests
// =============================================================================

// TestSetGracefulTimeout_Positive verifies setting a positive timeout.
func TestSetGracefulTimeout_Positive(t *testing.T) {
	originalTimeout := gracefulTimeout
	defer func() {
		preShutdownMu.Lock()
		gracefulTimeout = originalTimeout
		preShutdownMu.Unlock()
	}()

	SetGracefulTimeout(10 * time.Second)

	preShutdownMu.RLock()
	timeout := gracefulTimeout
	preShutdownMu.RUnlock()

	if timeout != 10*time.Second {
		t.Errorf("expected 10s timeout, got %s", timeout)
	}
}

// TestSetGracefulTimeout_Zero verifies zero defaults to 30 seconds.
func TestSetGracefulTimeout_Zero(t *testing.T) {
	originalTimeout := gracefulTimeout
	defer func() {
		preShutdownMu.Lock()
		gracefulTimeout = originalTimeout
		preShutdownMu.Unlock()
	}()

	SetGracefulTimeout(0)

	preShutdownMu.RLock()
	timeout := gracefulTimeout
	preShutdownMu.RUnlock()

	if timeout != defaultGracefulTimeout {
		t.Errorf("expected default timeout %s, got %s", defaultGracefulTimeout, timeout)
	}
}

// TestSetGracefulTimeout_Negative verifies negative defaults to 30 seconds.
func TestSetGracefulTimeout_Negative(t *testing.T) {
	originalTimeout := gracefulTimeout
	defer func() {
		preShutdownMu.Lock()
		gracefulTimeout = originalTimeout
		preShutdownMu.Unlock()
	}()

	SetGracefulTimeout(-5 * time.Second)

	preShutdownMu.RLock()
	timeout := gracefulTimeout
	preShutdownMu.RUnlock()

	if timeout != defaultGracefulTimeout {
		t.Errorf("expected default timeout %s, got %s", defaultGracefulTimeout, timeout)
	}
}

// =============================================================================
// Concurrent Registration Tests
// =============================================================================

// TestPreShutdownConcurrentRegistration verifies thread-safe handler registration.
func TestPreShutdownConcurrentRegistration(t *testing.T) {
	originalHandlers := preShutdownHandlers
	defer func() {
		preShutdownMu.Lock()
		preShutdownHandlers = originalHandlers
		preShutdownMu.Unlock()
	}()

	preShutdownMu.Lock()
	preShutdownHandlers = nil
	preShutdownMu.Unlock()

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
	originalHandlers := preShutdownHandlers
	originalInterrupters := interrupters
	defer func() {
		preShutdownMu.Lock()
		preShutdownHandlers = originalHandlers
		preShutdownMu.Unlock()
		mu.Lock()
		interrupters = originalInterrupters
		mu.Unlock()
	}()

	preShutdownMu.Lock()
	preShutdownHandlers = nil
	preShutdownMu.Unlock()
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
