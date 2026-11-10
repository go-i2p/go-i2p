package embedded

import (
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/router"
)

// selfStoppingRouter is a router.Lifecycle that reports its own stop, mimicking
// what *router.Router does when the I2PControl RPC shutdown path calls
// Router.Stop() directly without the supervisor being involved.
type selfStoppingRouter struct {
	MockRouter

	// stopped mirrors Router.Stopped(): closed once the stop has finished.
	stopped chan struct{}
}

func newSelfStoppingRouter() *selfStoppingRouter {
	return &selfStoppingRouter{stopped: make(chan struct{})}
}

// Stopped implements the same notification contract as *router.Router, which is
// what makes the embedded façade observe this router's self-initiated stops.
func (s *selfStoppingRouter) Stopped() <-chan struct{} {
	return s.stopped
}

func (s *selfStoppingRouter) Stop() {
	s.MockRouter.Stop()
	close(s.stopped)
}

var (
	_ router.Lifecycle = (*selfStoppingRouter)(nil)
	_ stoppedNotifier  = (*selfStoppingRouter)(nil)
)

func embeddedStopTestConfig() *config.RouterConfig {
	const dir = "/tmp/go-i2p-embedded-stop-test"
	return &config.RouterConfig{BaseDir: dir, WorkingDir: dir}
}

// TestWait_UnblockedByRouterInitiatedStop is the embedded half of the I2P-003
// impact. Fixing the self-join deadlock made Router.Stop() complete, but
// Run()/Wait() still blocked forever afterwards because only the supervisor's
// own Stop() closed the done channel — so a remote shutdown still required
// SIGKILL.
func TestWait_UnblockedByRouterInitiatedStop(t *testing.T) {
	self := newSelfStoppingRouter()
	e, err := NewStandardEmbeddedRouterWith(self, embeddedStopTestConfig())
	if err != nil {
		t.Fatalf("NewStandardEmbeddedRouterWith: %v", err)
	}
	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	waitDone := make(chan struct{})
	go func() {
		e.Wait()
		close(waitDone)
	}()

	// The router is stopped from the inside; the supervisor is never asked.
	go self.Stop()

	select {
	case <-waitDone:
	case <-time.After(5 * time.Second):
		t.Fatal("RESULT: DEADLOCK — Wait() still blocked after the router reported its own stop")
	}

	if e.IsRunning() {
		t.Error("embedded router should report not running after a router-initiated stop")
	}

	// Close() must be permitted: this is what Run() does after Wait() returns.
	if err := e.Close(); err != nil {
		t.Errorf("Close after router-initiated stop failed: %v", err)
	}
}

// TestWait_SupervisorStopNotDoubleClosed confirms the normal path still works
// and that a router notification racing the supervisor's own Stop() cannot
// double-close the completion signal (which would panic and take a healthy
// shutdown down).
func TestWait_SupervisorStopNotDoubleClosed(t *testing.T) {
	self := newSelfStoppingRouter()
	e, err := NewStandardEmbeddedRouterWith(self, embeddedStopTestConfig())
	if err != nil {
		t.Fatalf("NewStandardEmbeddedRouterWith: %v", err)
	}
	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	waitDone := make(chan struct{})
	go func() {
		e.Wait()
		close(waitDone)
	}()

	// Supervisor-initiated stop: e.Stop() calls router.Stop(), which fires the
	// notification while Stop() is also closing the completion signal.
	if err := e.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	select {
	case <-waitDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Wait() did not return after supervisor Stop()")
	}

	if err := e.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

// TestWait_RestartIsolatedFromStaleWatcher covers the per-run completion object:
// a watcher started for one run must not be able to mark a later run finished,
// and a re-armed run must not inherit a spent one-shot.
func TestWait_RestartIsolatedFromStaleWatcher(t *testing.T) {
	first := newSelfStoppingRouter()
	e, err := NewStandardEmbeddedRouterWith(first, embeddedStopTestConfig())
	if err != nil {
		t.Fatalf("NewStandardEmbeddedRouterWith: %v", err)
	}
	if err := e.Start(); err != nil {
		t.Fatalf("Start run 1: %v", err)
	}

	// End run 1 the way a router-initiated stop does. Run 1's watcher fires and
	// closes run 1's completion.
	go first.Stop()
	e.Wait()

	second := newSelfStoppingRouter()
	e.mu.Lock()
	e.router = second
	e.running = false
	e.mu.Unlock()

	if err := e.Start(); err != nil {
		t.Fatalf("Start run 2: %v", err)
	}

	waitDone := make(chan struct{})
	go func() {
		e.Wait()
		close(waitDone)
	}()

	// Run 2 must stay up. If the completion signal were shared across runs, its
	// once would already be spent and Wait() would hang; if a stale watcher
	// could act on it, Wait() would return here instead.
	select {
	case <-waitDone:
		t.Fatal("run 2 Wait() returned immediately — completion signal is not isolated per run")
	case <-time.After(300 * time.Millisecond):
	}

	// Run 2 ends normally when its own router stops.
	go second.Stop()

	select {
	case <-waitDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Wait() did not return after run 2's router stopped")
	}
}
