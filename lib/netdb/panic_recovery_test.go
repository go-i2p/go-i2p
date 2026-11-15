package netdb

import (
	"sync"
	"testing"
	"time"
)

// TestSafeGoRecoversPanic verifies that safeGo contains a panic raised on its
// goroutine: the panic must not propagate to (and crash) the test process, and
// a subsequent safeGo must still run. This is the seam that keeps a panic in
// untrusted netdb network-handling code from taking down the whole router.
func TestSafeGoRecoversPanic(t *testing.T) {
	var panicked, ran sync.WaitGroup
	panicked.Add(1)
	ran.Add(1)

	safeGo("test.panic", func() {
		defer panicked.Done()
		panic("injected panic in safeGo")
	})

	// If the panic above escaped to the top of its goroutine, the process would
	// abort before this second goroutine ran.
	safeGo("test.after", func() {
		defer ran.Done()
	})

	done := make(chan struct{})
	go func() {
		panicked.Wait()
		ran.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Both goroutines completed without crashing the process.
	case <-time.After(2 * time.Second):
		t.Fatal("safeGo goroutines did not complete; panic may have escaped")
	}
}

// TestRunPublishActionRecovers verifies that a panic in one publisher action is
// recovered so the periodic publish loop survives to the next tick. The action
// must run (side effect observed) and the panic must not escape the helper.
func TestRunPublishActionRecovers(t *testing.T) {
	p := NewPublisher(nil, nil, nil, nil, DefaultPublisherConfig())
	defer p.Stop()

	ran := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("runPublishAction let a panic escape: %v", r)
			}
		}()
		p.runPublishAction(func() {
			ran = true
			panic("injected panic in publisher action")
		})
	}()

	if !ran {
		t.Fatal("publisher action did not run before the panic")
	}

	// A subsequent action must still execute, proving the loop can continue.
	continued := false
	p.runPublishAction(func() { continued = true })
	if !continued {
		t.Fatal("publisher action did not run after a recovered panic")
	}
}
