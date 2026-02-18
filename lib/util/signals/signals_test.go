package signals

import (
	"bytes"
	"os"
	"sync"
	"testing"
)

// =============================================================================
// Signal Handler Registration Tests
// =============================================================================

// TestRegisterReloadHandler verifies reload handler registration.
func TestRegisterReloadHandler(t *testing.T) {
	// Save original state
	originalReloaders := reloaders
	defer func() { reloaders = originalReloaders }()

	// Reset state
	reloaders = nil

	called := false
	handler := func() {
		called = true
	}

	RegisterReloadHandler(handler)

	if len(reloaders) != 1 {
		t.Errorf("Expected 1 reloader registered, got %d", len(reloaders))
	}

	// Trigger the handler
	handleReload()

	if !called {
		t.Error("Reload handler was not called")
	}
}

// TestRegisterInterruptHandler verifies interrupt handler registration.
func TestRegisterInterruptHandler(t *testing.T) {
	// Save original state
	originalInterrupters := interrupters
	defer func() { interrupters = originalInterrupters }()

	// Reset state
	interrupters = nil

	called := false
	handler := func() {
		called = true
	}

	RegisterInterruptHandler(handler)

	if len(interrupters) != 1 {
		t.Errorf("Expected 1 interrupter registered, got %d", len(interrupters))
	}

	// Trigger the handler
	handleInterrupted()

	if !called {
		t.Error("Interrupt handler was not called")
	}
}

// TestMultipleReloadHandlers verifies multiple reload handlers are all called.
func TestMultipleReloadHandlers(t *testing.T) {
	// Save original state
	originalReloaders := reloaders
	defer func() { reloaders = originalReloaders }()

	// Reset state
	reloaders = nil

	callCount := 0
	var mu sync.Mutex

	for i := 0; i < 5; i++ {
		RegisterReloadHandler(func() {
			mu.Lock()
			callCount++
			mu.Unlock()
		})
	}

	if len(reloaders) != 5 {
		t.Errorf("Expected 5 reloaders registered, got %d", len(reloaders))
	}

	handleReload()

	mu.Lock()
	if callCount != 5 {
		t.Errorf("Expected all 5 handlers to be called, got %d", callCount)
	}
	mu.Unlock()
}

// TestMultipleInterruptHandlers verifies multiple interrupt handlers are all called.
func TestMultipleInterruptHandlers(t *testing.T) {
	// Save original state
	originalInterrupters := interrupters
	defer func() { interrupters = originalInterrupters }()

	// Reset state
	interrupters = nil

	callCount := 0
	var mu sync.Mutex

	for i := 0; i < 5; i++ {
		RegisterInterruptHandler(func() {
			mu.Lock()
			callCount++
			mu.Unlock()
		})
	}

	if len(interrupters) != 5 {
		t.Errorf("Expected 5 interrupters registered, got %d", len(interrupters))
	}

	handleInterrupted()

	mu.Lock()
	if callCount != 5 {
		t.Errorf("Expected all 5 handlers to be called, got %d", callCount)
	}
	mu.Unlock()
}

// TestHandlersCalledInOrder verifies handlers are called in registration order.
func TestHandlersCalledInOrder(t *testing.T) {
	// Save original state
	originalReloaders := reloaders
	defer func() { reloaders = originalReloaders }()

	// Reset state
	reloaders = nil

	order := make([]int, 0, 3)
	var mu sync.Mutex

	for i := 0; i < 3; i++ {
		idx := i
		RegisterReloadHandler(func() {
			mu.Lock()
			order = append(order, idx)
			mu.Unlock()
		})
	}

	handleReload()

	mu.Lock()
	defer mu.Unlock()

	if len(order) != 3 {
		t.Fatalf("Expected 3 handlers called, got %d", len(order))
	}
	for i := 0; i < 3; i++ {
		if order[i] != i {
			t.Errorf("Expected handler %d at position %d, got %d", i, i, order[i])
		}
	}
}

// TestEmptyHandlerList verifies empty handler lists don't cause panic.
func TestEmptyHandlerList(t *testing.T) {
	// Save original state
	originalReloaders := reloaders
	originalInterrupters := interrupters
	defer func() {
		reloaders = originalReloaders
		interrupters = originalInterrupters
	}()

	// Reset state
	reloaders = nil
	interrupters = nil

	// Should not panic
	handleReload()
	handleInterrupted()
}

// TestNilHandlerBehavior verifies that nil handlers are silently rejected
// by RegisterReloadHandler and RegisterInterruptHandler.
func TestNilHandlerBehavior(t *testing.T) {
	// Save original state
	originalReloaders := reloaders
	originalInterrupters := interrupters
	defer func() {
		reloaders = originalReloaders
		interrupters = originalInterrupters
	}()

	// Reset state
	reloaders = nil
	interrupters = nil

	// Registering nil handlers should be silently ignored
	RegisterReloadHandler(nil)
	RegisterInterruptHandler(nil)

	if len(reloaders) != 0 {
		t.Errorf("nil reload handler should not be registered, got %d handlers", len(reloaders))
	}
	if len(interrupters) != 0 {
		t.Errorf("nil interrupt handler should not be registered, got %d handlers", len(interrupters))
	}

	// Should not panic with empty lists
	handleReload()
	handleInterrupted()
}

// =============================================================================
// Signal Channel Tests
// =============================================================================

// TestSigChanInitialized verifies the signal channel is initialized.
func TestSigChanInitialized(t *testing.T) {
	if sigChan == nil {
		t.Error("sigChan should be initialized")
	}
}

// TestSigChanIsBuffered verifies channel is buffered to avoid missing signals.
func TestSigChanIsBuffered(t *testing.T) {
	// The channel is buffered (capacity 1) so that signal.Notify
	// does not drop signals when no receiver is ready.
	if cap(sigChan) != 1 {
		t.Errorf("Expected buffered channel with capacity 1, got capacity %d", cap(sigChan))
	}
}

// =============================================================================
// Panic Recovery Tests
// =============================================================================

// TestReloadHandlerPanicRecovery verifies that a panicking reload handler
// is recovered and remaining handlers still execute.
func TestReloadHandlerPanicRecovery(t *testing.T) {
	originalReloaders := reloaders
	defer func() { reloaders = originalReloaders }()
	reloaders = nil

	calledAfterPanic := false

	RegisterReloadHandler(func() {
		panic("test panic in reload handler")
	})
	RegisterReloadHandler(func() {
		calledAfterPanic = true
	})

	// Capture stderr to verify panic is logged
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	handleReload()

	w.Close()
	os.Stderr = oldStderr
	var buf bytes.Buffer
	b := make([]byte, 1024)
	n, _ := r.Read(b)
	buf.Write(b[:n])
	stderrOutput := buf.String()

	if !calledAfterPanic {
		t.Error("Handler after panicking handler was not called")
	}
	if len(stderrOutput) == 0 {
		t.Error("Expected panic to be logged to stderr")
	}
}

// TestInterruptHandlerPanicRecovery verifies that a panicking interrupt handler
// is recovered and remaining handlers still execute.
func TestInterruptHandlerPanicRecovery(t *testing.T) {
	originalInterrupters := interrupters
	defer func() { interrupters = originalInterrupters }()
	interrupters = nil

	calledAfterPanic := false

	RegisterInterruptHandler(func() {
		panic("test panic in interrupt handler")
	})
	RegisterInterruptHandler(func() {
		calledAfterPanic = true
	})

	// Capture stderr to verify panic is logged
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	handleInterrupted()

	w.Close()
	os.Stderr = oldStderr
	var buf bytes.Buffer
	b := make([]byte, 1024)
	n, _ := r.Read(b)
	buf.Write(b[:n])
	stderrOutput := buf.String()

	if !calledAfterPanic {
		t.Error("Handler after panicking handler was not called")
	}
	if len(stderrOutput) == 0 {
		t.Error("Expected panic to be logged to stderr")
	}
}

// TestConcurrentRegistration verifies thread-safe registration of handlers.
func TestConcurrentRegistration(t *testing.T) {
	originalReloaders := reloaders
	originalInterrupters := interrupters
	defer func() {
		mu.Lock()
		reloaders = originalReloaders
		interrupters = originalInterrupters
		mu.Unlock()
	}()
	mu.Lock()
	reloaders = nil
	interrupters = nil
	mu.Unlock()

	var wg sync.WaitGroup
	numGoroutines := 50

	for i := 0; i < numGoroutines; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			RegisterReloadHandler(func() {})
		}()
		go func() {
			defer wg.Done()
			RegisterInterruptHandler(func() {})
		}()
	}

	wg.Wait()

	mu.RLock()
	reloadCount := len(reloaders)
	interruptCount := len(interrupters)
	mu.RUnlock()

	if reloadCount != numGoroutines {
		t.Errorf("Expected %d reload handlers, got %d", numGoroutines, reloadCount)
	}
	if interruptCount != numGoroutines {
		t.Errorf("Expected %d interrupt handlers, got %d", numGoroutines, interruptCount)
	}
}

// =============================================================================
// Deregistration Tests (GAP #8 fix)
// =============================================================================

// TestDeregisterReloadHandler verifies individual reload handler deregistration.
func TestDeregisterReloadHandler(t *testing.T) {
	originalReloaders := reloaders
	defer func() {
		mu.Lock()
		reloaders = originalReloaders
		mu.Unlock()
	}()
	mu.Lock()
	reloaders = nil
	mu.Unlock()

	called1, called2 := false, false
	id1 := RegisterReloadHandler(func() { called1 = true })
	_ = RegisterReloadHandler(func() { called2 = true })

	DeregisterReloadHandler(id1)

	mu.RLock()
	count := len(reloaders)
	mu.RUnlock()

	if count != 1 {
		t.Errorf("Expected 1 handler after deregistration, got %d", count)
	}

	handleReload()

	if called1 {
		t.Error("Deregistered handler should not have been called")
	}
	if !called2 {
		t.Error("Remaining handler should have been called")
	}
}

// TestDeregisterInterruptHandler verifies individual interrupt handler deregistration.
func TestDeregisterInterruptHandler(t *testing.T) {
	originalInterrupters := interrupters
	defer func() {
		mu.Lock()
		interrupters = originalInterrupters
		mu.Unlock()
	}()
	mu.Lock()
	interrupters = nil
	mu.Unlock()

	called := false
	id := RegisterInterruptHandler(func() { called = true })

	DeregisterInterruptHandler(id)

	mu.RLock()
	count := len(interrupters)
	mu.RUnlock()

	if count != 0 {
		t.Errorf("Expected 0 handlers after deregistration, got %d", count)
	}

	handleInterrupted()

	if called {
		t.Error("Deregistered handler should not have been called")
	}
}

// TestDeregisterInvalidID verifies that deregistering an invalid ID is a no-op.
func TestDeregisterInvalidID(t *testing.T) {
	originalReloaders := reloaders
	defer func() {
		mu.Lock()
		reloaders = originalReloaders
		mu.Unlock()
	}()
	mu.Lock()
	reloaders = nil
	mu.Unlock()

	RegisterReloadHandler(func() {})
	DeregisterReloadHandler(999) // non-existent ID

	mu.RLock()
	count := len(reloaders)
	mu.RUnlock()

	if count != 1 {
		t.Errorf("Expected 1 handler (invalid ID should be no-op), got %d", count)
	}
}
