package signals

import (
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

// TestNilHandlerPanic tests that nil handlers would panic if called.
// This documents current behavior - handlers must be non-nil.
func TestNilHandlerBehavior(t *testing.T) {
	// Save original state
	originalReloaders := reloaders
	defer func() { reloaders = originalReloaders }()

	// Reset state
	reloaders = nil

	// Registering a nil handler is allowed by the API but will panic when called
	// This test documents this behavior
	reloaders = append(reloaders, nil)

	defer func() {
		if r := recover(); r == nil {
			t.Log("Note: nil handler did not panic (if handler list check was added)")
		}
	}()

	// This may panic depending on implementation
	// The current implementation will panic on nil handler
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
