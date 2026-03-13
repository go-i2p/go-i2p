package signals

import (
	"bytes"
	"os"
	"sync"
	"testing"
)

// assertHandlersCalledInOrder verifies that handlers registered via registerFn
// are called in FIFO order when handleFn is invoked. Consolidates the repeated
// order-verification pattern from graceful_test.go and signals_test.go.
func assertHandlersCalledInOrder(t *testing.T, registerFn func(func()), handleFn func()) {
	t.Helper()

	var mu sync.Mutex
	order := make([]int, 0, 3)

	for i := 0; i < 3; i++ {
		idx := i
		registerFn(func() {
			mu.Lock()
			order = append(order, idx)
			mu.Unlock()
		})
	}

	handleFn()

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

// assertDeregisterRemovesHandler verifies that deregistering a handler prevents
// it from being called. Consolidates the repeated deregistration pattern.
func assertDeregisterRemovesHandler(t *testing.T, register func(Handler) HandlerID, deregister func(HandlerID), trigger func(), getCount func() int) {
	t.Helper()
	called := false
	id := register(func() { called = true })
	deregister(id)
	if count := getCount(); count != 0 {
		t.Errorf("Expected 0 handlers after deregistration, got %d", count)
	}
	trigger()
	if called {
		t.Error("Deregistered handler should not have been called")
	}
}

// assertPanicRecovery registers a panicking handler and a follow-up handler via
// registerFn, invokes triggerFn, and verifies the follow-up ran and stderr output
// was produced.
func assertPanicRecovery(t *testing.T, registerFn func(Handler) HandlerID, triggerFn func()) {
	t.Helper()

	calledAfterPanic := false
	registerFn(func() { panic("test panic in handler") })
	registerFn(func() { calledAfterPanic = true })

	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	triggerFn()

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
