package router

import (
	"context"
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/config"
)

// stoppedTestRouter builds a minimally initialized Router that can be stopped
// without the full subsystem set. stopAllSubsystems is nil-safe for every
// component, so a bare running router is enough to exercise the stop path.
func stoppedTestRouter() *Router {
	const dir = "/tmp/go-i2p-router-stop-test"
	r := new(Router)
	r.cfg = &config.RouterConfig{BaseDir: dir, WorkingDir: dir}
	r.running = true
	r.armStoppedChannel()
	return r
}

// TestRouterStopped_SignalClosedByStop proves that a plain Stop() notifies
// observers. This is what lets lib/embedded notice an I2PControl RPC shutdown,
// which calls Router.Stop() directly and never goes through the supervisor.
func TestRouterStopped_SignalClosedByStop(t *testing.T) {
	r := stoppedTestRouter()

	ch := r.Stopped()
	if ch == nil {
		t.Fatal("Stopped() returned nil after the channel was armed")
	}

	select {
	case <-ch:
		t.Fatal("stopped channel must not be closed before Stop()")
	default:
	}

	r.Stop()

	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("RESULT: DEADLOCK — Stop() completed but never signalled observers")
	}
}

// TestRouterStopped_SignalClosedByStopWithContext covers the hard-stop path.
func TestRouterStopped_SignalClosedByStopWithContext(t *testing.T) {
	r := stoppedTestRouter()
	ch := r.Stopped()

	if err := r.StopWithContext(context.Background()); err != nil {
		t.Fatalf("StopWithContext failed: %v", err)
	}

	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("StopWithContext completed but never signalled observers")
	}
}

// TestRouterStopped_SignalledBeforeGoroutineJoin is the ordering that actually
// matters. Transport session readers and tunnel-build retries are tracked on the
// router WaitGroup and only drain once Close() closes the transports, so a
// notification emitted after the join would arrive too late: the supervisor
// would still be parked. This test keeps a goroutine outstanding so the join
// blocks, and asserts the signal is already out.
func TestRouterStopped_SignalledBeforeGoroutineJoin(t *testing.T) {
	r := stoppedTestRouter()
	r.wg.Add(1)
	defer r.wg.Done() // release the join so the test can clean up

	stopped := make(chan struct{})
	go func() {
		r.Stop()
		close(stopped)
	}()

	select {
	case <-r.Stopped():
		// Expected: the supervisor can now proceed to Close(), which drains the
		// outstanding goroutine and lets Stop() return.
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() did not signal until its goroutine join completed — " +
			"a supervisor waiting on this can never reach Close()")
	}

	select {
	case <-stopped:
		t.Fatal("Stop() returned while a tracked goroutine was still running")
	default:
	}
}

// TestRouterStopped_SignalledByStopWithContext covers the hard-stop path, which
// must notify on the same terms even when the join times out.
func TestRouterStopped_SignalledByStopWithContext(t *testing.T) {
	r := stoppedTestRouter()
	r.wg.Add(1)
	defer r.wg.Done()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if err := r.StopWithContext(ctx); err == nil {
		t.Fatal("expected context deadline error when a goroutine is still running")
	}

	select {
	case <-r.Stopped():
	case <-time.After(2 * time.Second):
		t.Fatal("timed-out stop must still notify the supervisor so it can Close()")
	}
}

// TestRouterStopped_ConcurrentStopsSignalOnce guards against the double-close
// panic that would crash the router if two shutdown paths raced.
func TestRouterStopped_ConcurrentStopsSignalOnce(t *testing.T) {
	r := stoppedTestRouter()

	done := make(chan struct{})
	go func() {
		defer close(done)
		r.Stop()
	}()
	r.Stop()
	<-done

	// A third stop after the run is over must be a no-op, not a panic.
	r.Stop()

	select {
	case <-r.Stopped():
	case <-time.After(2 * time.Second):
		t.Fatal("stopped channel was not closed")
	}
}

// TestRouterStopped_StartReArmsChannel ensures a restart gets a fresh signal,
// so a watcher from the previous run cannot report the new run as stopped.
func TestRouterStopped_StartReArmsChannel(t *testing.T) {
	r := stoppedTestRouter()
	first := r.Stopped()
	r.Stop()

	<-first

	// Re-arm the way Start() does; the previous channel must stay closed while
	// the new one is open.
	r.runMux.Lock()
	r.running = true
	r.armStoppedChannel()
	second := r.stoppedCh
	r.runMux.Unlock()

	if first == second {
		t.Fatal("expected a fresh stopped channel for the new run")
	}
	select {
	case <-second:
		t.Fatal("new run's stopped channel must start open")
	default:
	}

	r.Stop()
	select {
	case <-second:
	case <-time.After(2 * time.Second):
		t.Fatal("second run did not signal its stop")
	}
}

// TestRouterStopped_NilBeforeStart documents the pre-start behaviour that
// lib/embedded relies on when it type-asserts the notifier.
func TestRouterStopped_NilBeforeStart(t *testing.T) {
	r := new(Router)
	if r.Stopped() != nil {
		t.Fatal("Stopped() must be nil before the router has started")
	}
}
