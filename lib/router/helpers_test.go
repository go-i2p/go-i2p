package router

import (
	"context"
	"runtime"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/i2cp"
	ntcp "github.com/go-i2p/go-i2p/lib/transport/ntcp2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Router lifecycle helpers ---

// assertRouterRunning checks the running state under the runMux lock.
func assertRouterRunning(t *testing.T, router *Router, expected bool, msg string) {
	t.Helper()
	router.runMux.RLock()
	defer router.runMux.RUnlock()
	if expected {
		assert.True(t, router.running, msg)
	} else {
		assert.False(t, router.running, msg)
	}
}

// assertResourcesNilAfterClose asserts all router subsystem pointers are nil.
func assertResourcesNilAfterClose(t *testing.T, router *Router) {
	t.Helper()
	assert.Nil(t, router.TransportMuxer, "TransportMuxer should be nil after Close()")
	assert.Nil(t, router.messageRouter, "messageRouter should be nil after Close()")
	assert.Nil(t, router.garlicRouter, "garlicRouter should be nil after Close()")
	assert.Nil(t, router.tunnelManager, "tunnelManager should be nil after Close()")
	assert.Nil(t, router.RouterInfoKeystore, "RouterInfoKeystore should be nil after Close()")
	assert.Nil(t, router.StdNetDB, "StdNetDB should be nil after Close()")
	assert.Nil(t, router.closeChnl, "closeChnl should be nil after Close()")
}

// --- Context helpers ---

// getRouterCtx reads the router context under lock and requires it to be non-nil.
func getRouterCtx(t *testing.T, router *Router) context.Context {
	t.Helper()
	router.runMux.RLock()
	ctx := router.ctx
	router.runMux.RUnlock()
	require.NotNil(t, ctx, "Router context should not be nil")
	return ctx
}

// assertContextCancelled checks that ctx is cancelled within the given timeout.
func assertContextCancelled(t *testing.T, ctx context.Context, timeout time.Duration) {
	t.Helper()
	select {
	case <-ctx.Done():
		assert.Error(t, ctx.Err())
	case <-time.After(timeout):
		t.Error("Context should be cancelled within timeout")
	}
}

// assertContextActive checks that ctx has NOT been cancelled.
func assertContextActive(t *testing.T, ctx context.Context) {
	t.Helper()
	select {
	case <-ctx.Done():
		t.Error("Context should not be cancelled")
	default:
	}
}

// startStopAndAssertCancelled starts the router, retrieves its context, stops it,
// and asserts that the context is cancelled within the given timeout.
func startStopAndAssertCancelled(t *testing.T, router *Router, timeout time.Duration) context.Context {
	t.Helper()
	router.Start()
	time.Sleep(50 * time.Millisecond)
	ctx := getRouterCtx(t, router)
	router.Stop()
	assertContextCancelled(t, ctx, timeout)
	return ctx
}

// assertCloseReleasesResources calls Close on the router, asserts no error,
// and verifies all resources are nil.
func assertCloseReleasesResources(t *testing.T, router *Router) {
	t.Helper()
	err := router.Close()
	assert.NoError(t, err)
	assertResourcesNilAfterClose(t, router)
}

// --- Router construction helpers ---

// newTestRouterForWait creates a Router via FromConfig with DefaultRouterConfig.
func newTestRouterForWait(t *testing.T) *Router {
	t.Helper()
	cfg := config.DefaultRouterConfig()
	cfg.WorkingDir = t.TempDir()
	router, err := FromConfig(cfg)
	require.NoError(t, err)
	return router
}

// createTestRouterConfig creates a minimal router configuration for testing.
func createTestRouterConfig(tmpDir string) *config.RouterConfig {
	return &config.RouterConfig{
		WorkingDir: tmpDir,
		I2CP: &config.I2CPConfig{
			Enabled: false,
		},
		NetDb: &config.NetDbConfig{
			Path: tmpDir + "/netdb",
		},
		Bootstrap: &config.BootstrapConfig{
			LowPeerThreshold: 0,
		},
	}
}

// waitForRouterReady waits for the router to complete asynchronous initialization.
func waitForRouterReady(router *Router, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if router.GetTunnelManager() != nil && router.GetGarlicRouter() != nil {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// createReadyTestRouter creates, starts, and waits for a router to be ready.
// Router is stopped via t.Cleanup.
func createReadyTestRouter(t *testing.T) *Router {
	t.Helper()
	cfg := createTestRouterConfig(t.TempDir())
	router, err := CreateRouter(cfg)
	require.NoError(t, err, "Failed to create router")
	require.NotNil(t, router, "Router should not be nil")
	t.Cleanup(func() { router.Stop() })
	router.Start()
	require.True(t, waitForRouterReady(router, 2*time.Second), "Router should complete initialization")
	return router
}

// --- Garlic message routing helpers ---

// newTestGarlicRouterWithMock creates a GarlicMessageRouter backed by a mock NetDB.
// The router is stopped via t.Cleanup.
func newTestGarlicRouterWithMock(t *testing.T) (*GarlicMessageRouter, *mockLeaseSetNetDB) {
	t.Helper()
	ndb := newMockLeaseSetNetDB()
	router := NewGarlicMessageRouter(ndb, nil, nil, common.Hash{})
	t.Cleanup(func() { router.Stop() })
	return router, ndb
}

// assertPendingCount checks the pending message count for a destination.
func assertPendingCount(t *testing.T, router *GarlicMessageRouter, destHash common.Hash, expected int, msg string) {
	t.Helper()
	router.pendingMutex.RLock()
	pending := router.pendingMsgs[destHash]
	router.pendingMutex.RUnlock()
	assert.Len(t, pending, expected, msg)
}

// --- E2E integration helpers ---

// sendAndReceiveE2E performs a full send→wait→extract→process→receive cycle
// and asserts payload equality.
func sendAndReceiveE2E(t *testing.T, env *e2eTestEnvironment, payload []byte) {
	t.Helper()
	err := env.SendMessageFromClient(env.senderSession, env.receiverDestHash, env.receiverPubKey, payload)
	require.NoError(t, err)

	env.WaitForOutboundTransmission(t, 2*time.Second)
	garlicMsg := env.ExtractSentGarlicMessage(t)
	require.NotNil(t, garlicMsg)

	err = env.ProcessInboundMessage(garlicMsg, payload)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	receivedMsg, err := env.ReceiveMessageAtClient(ctx, env.receiverSession)
	require.NoError(t, err)
	assert.Equal(t, payload, receivedMsg.Payload)
}

// --- Stress test helpers ---

// assertMemoryGrowthBelow runs GC, reads MemStats, and asserts growth is below maxMB.
func assertMemoryGrowthBelow(t *testing.T, initialMem *runtime.MemStats, maxMB float64, label string) {
	t.Helper()
	runtime.GC()
	var afterMem runtime.MemStats
	runtime.ReadMemStats(&afterMem)

	memGrowthMB := (float64(afterMem.Alloc) - float64(initialMem.Alloc)) / 1024 / 1024
	t.Logf("%s memory growth: %.2f MB (initial: %.2f MB, current: %.2f MB)",
		label, memGrowthMB,
		float64(initialMem.Alloc)/1024/1024,
		float64(afterMem.Alloc)/1024/1024)
	assert.Less(t, memGrowthMB, maxMB, "Excessive memory growth detected for "+label)
}

// --- Congestion monitor helpers ---

// feedSamples sets the ratio on a mock collector and takes n samples on the monitor.
func feedSamples(collector *mockMetricsCollector, monitor *CongestionMonitor, ratio float64, n int) {
	collector.SetRatio(ratio)
	for i := 0; i < n; i++ {
		monitor.takeSample()
	}
}

// resetCongestionMonitor clears samples and resets the flag to None.
func resetCongestionMonitor(monitor *CongestionMonitor) {
	monitor.mu.Lock()
	monitor.samples = nil
	monitor.currentFlag = config.CongestionFlagNone
	monitor.mu.Unlock()
}

// --- Inbound handler helpers ---

// setupInboundHandlerWithSession creates an InboundMessageHandler with a session.
// Returns the handler, session ID, and a mock decryptor.
func setupInboundHandlerWithSession(t *testing.T) (*InboundMessageHandler, uint16, *mockTunnelEncryptor) {
	t.Helper()
	sessionManager := i2cp.NewSessionManager()
	handler := NewInboundMessageHandler(sessionManager)
	session, err := sessionManager.CreateSession(nil, i2cp.DefaultSessionConfig())
	require.NoError(t, err)
	return handler, session.ID(), &mockTunnelEncryptor{}
}

// --- Session helpers ---

// addAndAssertSession adds a session to the router and verifies retrieval.
func addAndAssertSession(t *testing.T, router *Router, hash common.Hash, session *ntcp.NTCP2Session) {
	t.Helper()
	router.addSession(hash, session)
	retrieved, err := router.getSessionByHash(hash)
	require.NoError(t, err, "Should retrieve existing session without error")
	assert.Equal(t, session, retrieved, "Should retrieve the correct session")
}
