package i2pcontrol

import (
	"context"
	"sync"
	"testing"
	"time"
)

// panicReseedControl panics when a reseed is invoked, simulating a panic deep
// in the reseed path (e.g. parsing an untrusted SU3 response).
type panicReseedControl struct{}

func (panicReseedControl) Stop() { panic("Stop should not be called by reseed test") }

func (panicReseedControl) ReseedWithContext(context.Context) error {
	panic("injected panic in reseed")
}

// TestReseedRecoversPanicAndClearsState verifies that a panic raised inside the
// asynchronous reseed goroutine is recovered AND still clears reseedRunning.
// Without the recovery seam the panic would crash the router; with recovery but
// no finalization, reseedRunning would stay true forever and the handler would
// report a perpetually in-flight reseed.
func TestReseedRecoversPanicAndClearsState(t *testing.T) {
	var wg sync.WaitGroup
	h := NewRouterManagerHandler(context.Background(), &wg, panicReseedControl{})

	// Mirror the real handleReseed flow: tryBeginReseed sets reseedRunning=true,
	// then executeReseedAsync launches the goroutine that must recover the panic
	// and clear the flag.
	if !h.tryBeginReseed() {
		t.Fatal("tryBeginReseed failed to begin")
	}

	// executeReseedAsync must not let the panic escape to the test process.
	h.executeReseedAsync()

	// Wait for the goroutine to finalize (reseedRunning flips back to false).
	deadline := time.Now().Add(2 * time.Second)
	for {
		h.reseedMu.Lock()
		running := h.reseedRunning
		status := h.reseedStatus
		h.reseedMu.Unlock()

		if !running {
			if status != "failed" {
				t.Fatalf("expected reseed status %q after recovered panic, got %q", "failed", status)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("reseedRunning never cleared after recovered panic (state stuck)")
		}
		time.Sleep(10 * time.Millisecond)
	}

	wg.Wait()
}

// TestSafeGoRecoversPanic verifies the i2pcontrol safeGo seam contains a panic
// raised on its goroutine instead of crashing the process.
func TestSafeGoRecoversPanic(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(2)

	safeGo("test.panic", func() {
		defer wg.Done()
		panic("injected panic in safeGo")
	})
	safeGo("test.after", func() {
		defer wg.Done()
	})

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("safeGo goroutines did not complete; panic may have escaped")
	}
}
