package i2pcontrol

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// I2P-003 regression coverage: the RouterManager Shutdown/Restart RPC drove the
// router's stop sequence from a goroutine registered on the I2PControl server's
// own WaitGroup. Because Router.Stop() shuts the I2PControl server down as one
// of its subsystems, that goroutine waited for itself inside
// Server.Stop() -> s.wg.Wait(). sync.Once then stranded every later Stop().

// reentrantStopControl mimics *router.Router: its Stop() tears the I2PControl
// server down as part of subsystem shutdown, re-entering Server.Stop().
type reentrantStopControl struct {
	server atomic.Pointer[Server]
	calls  int32
	done   chan struct{}
	once   sync.Once
}

func (c *reentrantStopControl) Stop() {
	atomic.AddInt32(&c.calls, 1)
	if s := c.server.Load(); s != nil {
		s.Stop()
	}
	c.once.Do(func() { close(c.done) })
}

func (c *reentrantStopControl) ReseedWithContext(context.Context) error { return nil }

func (c *reentrantStopControl) stopCount() int {
	return int(atomic.LoadInt32(&c.calls))
}

// reentrantStatsProvider serves a reentrantStopControl through GetRouterControl,
// exactly as routerStatsProvider does in production.
type reentrantStatsProvider struct {
	mockServerStatsProvider
	control RouterController
}

func (p *reentrantStatsProvider) GetRouterControl() interface {
	Stop()
	ReseedWithContext(context.Context) error
} {
	return p.control
}

// newReentrantServer starts an I2PControl server whose RouterManager shutdown
// path re-enters Server.Stop() — the production shape that deadlocked.
func newReentrantServer(t *testing.T) (*Server, *reentrantStopControl, string) {
	t.Helper()

	port, err := getFreePort()
	require.NoError(t, err)

	cfg := testConfig(port)
	control := &reentrantStopControl{done: make(chan struct{})}
	stats := &reentrantStatsProvider{
		mockServerStatsProvider: mockServerStatsProvider{running: true},
		control:                 control,
	}

	server, err := NewServer(cfg, stats)
	require.NoError(t, err)
	control.server.Store(server)
	require.NoError(t, server.Start())

	url := "http://" + cfg.Address + "/jsonrpc"
	token := authenticateTestServer(t, "http://"+cfg.Address, cfg.Password)
	t.Cleanup(func() {
		// Drive the shutdown through the RPC-independent path so a regression
		// surfaces as a test failure, not a hung test binary.
		server.Stop()
	})
	return server, control, url + "?Token=" + token
}

// splitToken extracts the auth token carried in the test URL's query string.
func splitToken(url string) (endpoint, token string) {
	endpoint, token, _ = strings.Cut(url, "?Token=")
	return endpoint, token
}

// postShutdownRPC issues a RouterManager operation over JSON-RPC.
func postShutdownRPC(t *testing.T, url, op string) Response {
	t.Helper()

	endpoint, token := splitToken(url)
	body, err := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "RouterManager",
		"params":  map[string]interface{}{"Token": token, op: nil},
	})
	require.NoError(t, err)

	resp, err := http.Post(endpoint, "application/json", strings.NewReader(string(body)))
	require.NoError(t, err)
	defer resp.Body.Close()

	var out Response
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return out
}

// TestRouterManagerShutdown_DoesNotDeadlockServerStop is the I2P-003 repro: the
// RPC-triggered router stop re-enters Server.Stop(), which must complete rather
// than join the WaitGroup that still counts its own dispatch goroutine.
func TestRouterManagerShutdown_DoesNotDeadlockServerStop(t *testing.T) {
	server, control, url := newReentrantServer(t)

	resp := postShutdownRPC(t, url, "Shutdown")
	require.Nil(t, resp.Error, "shutdown RPC must be accepted: %+v", resp.Error)

	// The dispatch goroutine calls RouterControl.Stop() -> Server.Stop();
	// with the bug it blocks forever in s.wg.Wait().
	select {
	case <-control.done:
	case <-time.After(5 * time.Second):
		t.Fatal("RESULT: DEADLOCK — RPC-triggered Stop() never returned (I2P-003 self-join)")
	}

	require.Equal(t, 1, control.stopCount(), "shutdown RPC must drive exactly one router stop")

	// stopOnce must not be stranded: an explicit second Stop() still returns.
	stopped := make(chan struct{})
	go func() {
		server.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("RESULT: DEADLOCK — subsequent Server.Stop() is stranded by sync.Once")
	}
}

// TestRouterManagerStopOperations_DoNotDeadlockServerStop covers the
// Restart/ShutdownGraceful/RestartGraceful variants, which share the dispatch.
func TestRouterManagerStopOperations_DoNotDeadlockServerStop(t *testing.T) {
	for _, op := range []string{"Restart", "ShutdownGraceful", "RestartGraceful"} {
		op := op
		t.Run(op, func(t *testing.T) {
			_, control, url := newReentrantServer(t)

			resp := postShutdownRPC(t, url, op)
			require.Nil(t, resp.Error, "%s RPC must be accepted: %+v", op, resp.Error)

			select {
			case <-control.done:
			case <-time.After(5 * time.Second):
				t.Fatalf("RESULT: DEADLOCK — %s-triggered Stop() never returned (I2P-003)", op)
			}
		})
	}
}

// blockingStopControl signals when Stop() is entered and blocks until released.
type blockingStopControl struct {
	blocked chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *blockingStopControl) Stop() {
	c.once.Do(func() { close(c.blocked) })
	<-c.release
}

func (c *blockingStopControl) ReseedWithContext(context.Context) error { return nil }

// TestRouterManagerShutdown_NotRegisteredOnServerWaitGroup pins the mechanism
// of the fix directly: while the router-stop goroutine is blocked inside
// RouterControl.Stop(), the server WaitGroup it must NOT be counted on drains
// immediately — and the handler's own tracking still accounts for it.
func TestRouterManagerShutdown_NotRegisteredOnServerWaitGroup(t *testing.T) {
	var serverWG sync.WaitGroup

	blocked := make(chan struct{})
	release := make(chan struct{})
	control := &blockingStopControl{blocked: blocked, release: release}

	handler := NewRouterManagerHandler(context.Background(), &serverWG, control)
	resultMap := invokeHandler(t, handler, `{"Shutdown": null}`)
	require.Contains(t, resultMap, "Shutdown")

	// Stop() is now running and parked inside RouterControl.Stop().
	select {
	case <-blocked:
	case <-time.After(2 * time.Second):
		t.Fatal("router stop did not start")
	}

	// The server's shutdown barrier must be able to drain while that goroutine
	// is still in flight — this is precisely what used to hang.
	wgDone := make(chan struct{})
	go func() {
		serverWG.Wait()
		close(wgDone)
	}()
	select {
	case <-wgDone:
	case <-time.After(2 * time.Second):
		t.Fatal("router-stop goroutine is registered on the server WaitGroup (I2P-003)")
	}

	close(release)
	handlerDone := make(chan struct{})
	go func() {
		handler.routerStopWg.Wait()
		close(handlerDone)
	}()
	select {
	case <-handlerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("router stop goroutine never finished after release")
	}
}

// TestStopServer_BoundedWaitOnStuckGoroutine verifies the backstop: a
// non-cooperative goroutine on the server WaitGroup can no longer hold
// Server.Stop() (and therefore Router.Stop()) open indefinitely.
func TestStopServer_BoundedWaitOnStuckGoroutine(t *testing.T) {
	orig := goroutineDrainTimeout
	goroutineDrainTimeout = 200 * time.Millisecond
	t.Cleanup(func() { goroutineDrainTimeout = orig })

	port, err := getFreePort()
	require.NoError(t, err)

	cfg := testConfig(port)
	server, err := NewServer(cfg, &mockServerStatsProvider{running: true})
	require.NoError(t, err)
	require.NoError(t, server.Start())

	// A goroutine that ignores context cancellation, as a wedged reseed would.
	stuck := make(chan struct{})
	server.wg.Add(1)
	go func() {
		defer server.wg.Done()
		<-stuck
	}()

	returned := make(chan struct{})
	go func() {
		server.Stop()
		close(returned)
	}()

	select {
	case <-returned:
	case <-time.After(3 * time.Second):
		t.Fatal("Server.Stop() blocked forever on a non-cooperative goroutine")
	}

	close(stuck)
}

// TestStopServer_JoinsCooperativeGoroutine makes sure the bounded wait still
// does its job in the normal case: a cooperative handler goroutine on the
// server WaitGroup is joined before Stop() returns.
func TestStopServer_JoinsCooperativeGoroutine(t *testing.T) {
	port, err := getFreePort()
	require.NoError(t, err)

	cfg := testConfig(port)
	server, err := NewServer(cfg, &mockServerStatsProvider{running: true})
	require.NoError(t, err)
	require.NoError(t, server.Start())

	server.wg.Add(1)
	var finished atomic.Bool
	go func() {
		defer server.wg.Done()
		<-server.ctx.Done()
		// Small delay past cancellation to prove the join actually waited.
		time.Sleep(50 * time.Millisecond)
		finished.Store(true)
	}()

	server.Stop()
	require.True(t, finished.Load(), "Stop() returned before joining a cooperative goroutine")
}
