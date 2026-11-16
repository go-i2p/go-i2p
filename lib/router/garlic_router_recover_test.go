package router

import (
	"testing"
	"time"
)

// TestRecoverGoroutine_CatchesPanic proves the recoverGoroutine primitive used
// by the garlic router's long-lived loops: a panic in a guarded region is
// caught and logged rather than crashing the process.
func TestRecoverGoroutine_CatchesPanic(t *testing.T) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		func() {
			defer recoverGoroutine("test.recoverGoroutine")
			panic("boom")
		}()
		// Reaching this line proves the panic was recovered, not propagated.
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("recoverGoroutine did not let the guarded goroutine finish")
	}
}

// TestLoopSurvivesPanicViaRecoverGoroutine proves the property the garlic
// router's long-lived loops rely on: when recoverGoroutine is deferred inside
// a loop iteration, a panic in one iteration is contained and the loop keeps
// running. This is exactly the structure of drainWorker / processPendingMessages
// after the C3 fix — a single bad remote message must not crash the router or
// wedge the loop.
func TestLoopSurvivesPanicViaRecoverGoroutine(t *testing.T) {
	var iterations int
	done := make(chan struct{})

	go func() {
		defer close(done)
		for i := 0; i < 3; i++ {
			// Each iteration is guarded exactly like the router loops: a panic
			// here unwinds only this iteration, then the loop continues.
			func() {
				defer recoverGoroutine("test.loop")
				iterations++
				if i == 1 {
					panic("bad message on iteration 1")
				}
			}()
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("loop did not survive the panic")
	}

	if iterations != 3 {
		t.Fatalf("loop stopped early: ran %d iterations, want 3 (panic on iteration 1 must not stop the loop)", iterations)
	}
}
