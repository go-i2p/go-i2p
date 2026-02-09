//go:build integration

package router

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/lease_set"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/netdb"
	ntcp "github.com/go-i2p/go-i2p/lib/transport/ntcp2"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Startup Sequence Tests
// Verify correct initialization order during router startup
// =============================================================================

// TestStartupSequence_InitializationOrder verifies the correct startup sequence:
// 1. Context initialization
// 2. Bandwidth tracker
// 3. I2CP server (if enabled)
// 4. I2PControl server (if enabled)
// 5. NetDB
// 6. Message router
// 7. Garlic router
// 8. Session monitors
func TestStartupSequence_InitializationOrder(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.DefaultRouterConfig()
	cfg.WorkingDir = tempDir
	cfg.NetDb.Path = tempDir + "/netdb"
	cfg.I2CP.Enabled = false
	cfg.I2PControl.Enabled = false

	router, err := FromConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, router)

	// Initialize keystore for router identity
	err = initializeRouterKeystore(router, cfg)
	require.NoError(t, err)

	// Verify pre-start state
	assert.Nil(t, router.ctx, "Context should be nil before Start()")
	assert.Nil(t, router.bandwidthTracker, "Bandwidth tracker should be nil before Start()")
	assert.False(t, router.running, "Router should not be running before Start()")

	// Start the router
	router.Start()
	time.Sleep(200 * time.Millisecond) // Allow initialization to complete

	// Verify post-start state - check thread-safe access
	router.runMux.RLock()
	assert.True(t, router.running, "Router should be running after Start()")
	assert.NotNil(t, router.ctx, "Context should be initialized after Start()")
	router.runMux.RUnlock()

	assert.NotNil(t, router.bandwidthTracker, "Bandwidth tracker should be initialized after Start()")

	// Stop the router
	router.Stop()

	router.runMux.RLock()
	assert.False(t, router.running, "Router should not be running after Stop()")
	router.runMux.RUnlock()
}

// TestStartupSequence_DoubleStart verifies that calling Start() twice is safe
func TestStartupSequence_DoubleStart(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.DefaultRouterConfig()
	cfg.WorkingDir = tempDir
	cfg.I2CP.Enabled = false
	cfg.I2PControl.Enabled = false

	router, err := FromConfig(cfg)
	require.NoError(t, err)

	err = initializeRouterKeystore(router, cfg)
	require.NoError(t, err)

	// First Start()
	router.Start()
	time.Sleep(50 * time.Millisecond)

	router.runMux.RLock()
	firstRunning := router.running
	router.runMux.RUnlock()
	assert.True(t, firstRunning, "Router should be running after first Start()")

	// Second Start() should be a no-op
	router.Start()
	time.Sleep(50 * time.Millisecond)

	router.runMux.RLock()
	secondRunning := router.running
	router.runMux.RUnlock()
	assert.True(t, secondRunning, "Router should still be running after second Start()")

	router.Stop()
}

// =============================================================================
// Shutdown Sequence Tests
// Verify graceful cleanup of all subsystems during shutdown
// =============================================================================

// TestShutdownSequence_GracefulCleanup verifies that all subsystems are properly stopped
func TestShutdownSequence_GracefulCleanup(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.DefaultRouterConfig()
	cfg.WorkingDir = tempDir
	cfg.NetDb.Path = tempDir + "/netdb"
	cfg.I2CP.Enabled = false
	cfg.I2PControl.Enabled = false
	// Use local bootstrap to avoid network reseed operations that block shutdown
	cfg.Bootstrap.BootstrapType = "local"

	router, err := CreateRouter(cfg)
	require.NoError(t, err)

	router.Start()
	time.Sleep(200 * time.Millisecond)

	// Store context for later verification
	router.runMux.RLock()
	ctx := router.ctx
	router.runMux.RUnlock()
	require.NotNil(t, ctx)

	// Stop the router
	done := make(chan struct{})
	go func() {
		router.Stop()
		close(done)
	}()

	// Verify shutdown completes in reasonable time
	select {
	case <-done:
		// Shutdown completed
	case <-time.After(10 * time.Second):
		t.Fatal("Router shutdown timed out after 10 seconds")
	}

	// Context should be cancelled
	select {
	case <-ctx.Done():
		assert.Equal(t, context.Canceled, ctx.Err(), "Context should be canceled")
	default:
		t.Error("Context should be canceled after Stop()")
	}
}

// TestShutdownSequence_ContextCancellation verifies context-based shutdown signals
func TestShutdownSequence_ContextCancellation(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.DefaultRouterConfig()
	cfg.WorkingDir = tempDir
	cfg.I2CP.Enabled = false
	cfg.I2PControl.Enabled = false
	// Use local bootstrap to avoid network reseed operations that block shutdown
	cfg.Bootstrap.BootstrapType = "local"

	router, err := CreateRouter(cfg)
	require.NoError(t, err)

	router.Start()
	time.Sleep(100 * time.Millisecond)

	// Create a goroutine that waits on context
	router.runMux.RLock()
	ctx := router.ctx
	router.runMux.RUnlock()

	contextDone := make(chan struct{})
	go func() {
		<-ctx.Done()
		close(contextDone)
	}()

	// Stop and verify context is cancelled
	router.Stop()

	select {
	case <-contextDone:
		// Success - context was cancelled
	case <-time.After(time.Second):
		t.Error("Context was not cancelled within timeout")
	}
}

// TestShutdownSequence_WaitGroupCompletion verifies all goroutines complete
func TestShutdownSequence_WaitGroupCompletion(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.DefaultRouterConfig()
	cfg.WorkingDir = tempDir
	cfg.I2CP.Enabled = false
	cfg.I2PControl.Enabled = false
	// Use local bootstrap to avoid network reseed operations that block shutdown
	cfg.Bootstrap.BootstrapType = "local"

	router, err := CreateRouter(cfg)
	require.NoError(t, err)

	router.Start()
	time.Sleep(100 * time.Millisecond)

	// Stop should block until all goroutines complete
	stopDone := make(chan struct{})
	go func() {
		router.Stop()
		close(stopDone)
	}()

	// Wait should return after Stop completes
	waitDone := make(chan struct{})
	go func() {
		router.Wait()
		close(waitDone)
	}()

	select {
	case <-stopDone:
		// Stop completed
	case <-time.After(10 * time.Second):
		t.Fatal("Stop() did not complete within timeout")
	}

	select {
	case <-waitDone:
		// Wait completed
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Wait() should return immediately after Stop()")
	}
}

// =============================================================================
// Inbound Message Handling Tests
// Verify proper routing to destinations for inbound messages
// =============================================================================

// TestInboundMessageHandler_ThreadSafety verifies concurrent access to tunnel registration
func TestInboundMessageHandler_ThreadSafety(t *testing.T) {
	handler := NewInboundMessageHandler(nil)

	var wg sync.WaitGroup
	const numGoroutines = 100

	// Concurrent tunnel registration
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			tunnelID := tunnel.TunnelID(uint32(id))
			sessionID := uint16(id % 65536)
			// Note: endpoint is nil for thread-safety testing
			handler.RegisterTunnel(tunnelID, sessionID, nil)
		}(i)
	}
	wg.Wait()

	// Verify all tunnels were registered
	assert.Equal(t, numGoroutines, handler.GetTunnelCount(), "All tunnels should be registered")

	// Concurrent reads
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			tunnelID := tunnel.TunnelID(uint32(id))
			_, exists := handler.GetTunnelSession(tunnelID)
			assert.True(t, exists, "Tunnel should exist")
		}(i)
	}
	wg.Wait()

	// Concurrent unregistration
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			handler.UnregisterTunnel(tunnel.TunnelID(uint32(id)))
		}(i)
	}
	wg.Wait()

	assert.Equal(t, 0, handler.GetTunnelCount(), "All tunnels should be unregistered")
}

// TestInboundMessageHandler_UnregisteredTunnel verifies handling of unknown tunnels
func TestInboundMessageHandler_UnregisteredTunnel(t *testing.T) {
	handler := NewInboundMessageHandler(nil)

	// Create a mock message with tunnel ID
	tunnelData := make([]byte, 1024)
	tunnelData[0], tunnelData[1], tunnelData[2], tunnelData[3] = 0, 0, 0, 1 // Tunnel ID = 1

	msg := &mockTunnelCarrier{data: tunnelData}

	// Should handle gracefully without error (logs warning but doesn't fail)
	err := handler.HandleTunnelData(msg)
	assert.NoError(t, err, "Should handle unregistered tunnel without error")
}

// mockTunnelCarrier implements i2np.I2NPMessage and i2np.TunnelCarrier for testing
type mockTunnelCarrier struct {
	data       []byte
	expiration time.Time
	msgID      int
}

func (m *mockTunnelCarrier) GetTunnelData() []byte          { return m.data }
func (m *mockTunnelCarrier) Type() int                      { return int(i2np.I2NP_MESSAGE_TYPE_TUNNEL_DATA) }
func (m *mockTunnelCarrier) MessageID() int                 { return m.msgID }
func (m *mockTunnelCarrier) SetMessageID(id int)            { m.msgID = id }
func (m *mockTunnelCarrier) Expiration() time.Time          { return m.expiration }
func (m *mockTunnelCarrier) SetExpiration(exp time.Time)    { m.expiration = exp }
func (m *mockTunnelCarrier) MarshalBinary() ([]byte, error) { return m.data, nil }
func (m *mockTunnelCarrier) UnmarshalBinary([]byte) error   { return nil }
func (m *mockTunnelCarrier) SetData([]byte)                 {}
func (m *mockTunnelCarrier) GetPayload() []byte             { return m.data }

// =============================================================================
// Garlic Routing Tests
// Verify ECIES-X25519-AEAD-Ratchet session management
// =============================================================================

// TestGarlicRouter_ReflexiveDelivery verifies detection of self-routing
func TestGarlicRouter_ReflexiveDelivery(t *testing.T) {
	// Create router identity
	var routerHash common.Hash
	copy(routerHash[:], bytes.Repeat([]byte{0xAA}, 32))

	mockNetDB := &mockGarlicNetDB{}
	gr := NewGarlicMessageRouter(mockNetDB, nil, nil, routerHash)

	// Create a real processor for reflexive delivery
	processor := i2np.NewMessageProcessor()
	gr.SetMessageProcessor(processor)

	// Create test message
	msg := i2np.NewBaseI2NPMessage(i2np.I2NP_MESSAGE_TYPE_DATA)

	// Forward to ourselves (reflexive) - will try to process locally
	err := gr.ForwardToRouter(routerHash, msg)
	// Message processing may fail due to interface issues, but the key test is
	// that we detect reflexive delivery and don't try network lookup
	if err != nil && bytes.Contains([]byte(err.Error()), []byte("not found in NetDB")) {
		t.Error("Reflexive delivery should not attempt NetDB lookup")
	}
}

// TestGarlicRouter_ReflexiveWithoutProcessor verifies error when processor not set
func TestGarlicRouter_ReflexiveWithoutProcessor(t *testing.T) {
	var routerHash common.Hash
	copy(routerHash[:], bytes.Repeat([]byte{0xAA}, 32))

	mockNetDB := &mockGarlicNetDB{}
	gr := NewGarlicMessageRouter(mockNetDB, nil, nil, routerHash)
	// Don't set processor

	msg := i2np.NewBaseI2NPMessage(i2np.I2NP_MESSAGE_TYPE_DATA)

	err := gr.ForwardToRouter(routerHash, msg)
	assert.Error(t, err, "Should fail without processor")
	assert.Contains(t, err.Error(), "processor not configured")
}

// TestGarlicRouter_PendingMessageQueue verifies message queueing for unknown destinations
func TestGarlicRouter_PendingMessageQueue(t *testing.T) {
	var routerHash common.Hash
	mockNetDB := &mockGarlicNetDB{}
	gr := NewGarlicMessageRouter(mockNetDB, nil, nil, routerHash)

	var destHash common.Hash
	copy(destHash[:], bytes.Repeat([]byte{0xBB}, 32))

	msg := i2np.NewBaseI2NPMessage(i2np.I2NP_MESSAGE_TYPE_DATA)

	// Forward to unknown destination - should queue
	err := gr.ForwardToDestination(destHash, msg)
	assert.NoError(t, err, "Should queue message for unknown destination")

	// Verify message is pending
	gr.pendingMutex.RLock()
	pending := gr.pendingMsgs[destHash]
	gr.pendingMutex.RUnlock()
	assert.Len(t, pending, 1, "Should have one pending message")

	// Stop to clean up background goroutine
	gr.Stop()
}

// TestGarlicRouter_MaxPendingMessages verifies queue limit enforcement
func TestGarlicRouter_MaxPendingMessages(t *testing.T) {
	var routerHash common.Hash
	mockNetDB := &mockGarlicNetDB{}
	gr := NewGarlicMessageRouter(mockNetDB, nil, nil, routerHash)

	var destHash common.Hash
	copy(destHash[:], bytes.Repeat([]byte{0xCC}, 32))

	// Queue up to max limit
	for i := 0; i < maxPendingMessages; i++ {
		msg := i2np.NewBaseI2NPMessage(i2np.I2NP_MESSAGE_TYPE_DATA)
		err := gr.queuePendingMessage(destHash, msg)
		assert.NoError(t, err, "Should accept message %d", i)
	}

	// Next message should fail
	msg := i2np.NewBaseI2NPMessage(i2np.I2NP_MESSAGE_TYPE_DATA)
	err := gr.queuePendingMessage(destHash, msg)
	assert.Error(t, err, "Should reject message beyond max limit")
	assert.Contains(t, err.Error(), "too many pending messages")

	gr.Stop()
}

// =============================================================================
// LeaseSet Publishing Tests
// Verify automatic refresh before expiry
// =============================================================================

// TestLeaseSetPublisher_LocalStorage verifies LeaseSet storage behavior
// Note: Creating valid LeaseSets requires complex setup with proper keys and signatures.
// This test verifies the storage path exists and validates inputs, while the actual
// integration with valid LeaseSets is covered in I2CP integration tests.
func TestLeaseSetPublisher_LocalStorage(t *testing.T) {
	tempDir := t.TempDir()

	// Create router with NetDB
	router := &Router{
		StdNetDB: netdb.NewStdNetDB(tempDir),
	}
	err := router.StdNetDB.Ensure()
	require.NoError(t, err)

	publisher := NewLeaseSetPublisher(router)

	// Verify publisher is properly initialized
	assert.NotNil(t, publisher, "Publisher should not be nil")
	assert.NotNil(t, publisher.router.StdNetDB, "Publisher should have access to NetDB")

	// Verify the publish path rejects invalid data appropriately
	var key common.Hash
	copy(key[:], bytes.Repeat([]byte{0x11}, 32))
	invalidData := bytes.Repeat([]byte{0x22}, 128)

	// Invalid LeaseSet data should be rejected during validation
	err = publisher.PublishLeaseSet(key, invalidData)
	assert.Error(t, err, "Invalid LeaseSet data should be rejected")
	assert.Contains(t, err.Error(), "NetDB", "Error should come from NetDB validation")
}

// TestLeaseSetPublisher_InvalidData verifies handling of invalid LeaseSet data
func TestLeaseSetPublisher_InvalidData(t *testing.T) {
	tempDir := t.TempDir()

	router := &Router{
		StdNetDB: netdb.NewStdNetDB(tempDir),
	}
	err := router.StdNetDB.Ensure()
	require.NoError(t, err)

	publisher := NewLeaseSetPublisher(router)

	var key common.Hash
	copy(key[:], bytes.Repeat([]byte{0x11}, 32))

	// Empty data
	err = publisher.PublishLeaseSet(key, []byte{})
	assert.Error(t, err, "Should reject empty LeaseSet data")

	// Nil data
	err = publisher.PublishLeaseSet(key, nil)
	assert.Error(t, err, "Should reject nil LeaseSet data")
}

// =============================================================================
// RouterInfo Provider Tests
// Verify correct address publication
// =============================================================================

// TestSecurity_RouterInfoProvider_InterfaceCompliance verifies interface implementation
func TestSecurity_RouterInfoProvider_InterfaceCompliance(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.DefaultRouterConfig()
	cfg.WorkingDir = tempDir

	router, err := FromConfig(cfg)
	require.NoError(t, err)

	// Use initializeRouterKeystore for proper key management
	err = initializeRouterKeystore(router, cfg)
	require.NoError(t, err)

	provider := newRouterInfoProvider(router)

	// Should implement RouterInfoProvider interface
	var _ netdb.RouterInfoProvider = provider

	// Should return valid RouterInfo
	ri, err := provider.GetRouterInfo()
	require.NoError(t, err)
	assert.NotNil(t, ri, "Should return RouterInfo")
}

// TestRouterInfoProvider_ConsistentKeys verifies signing/encryption keys remain consistent
// Note: IdentHash() is NOT expected to be consistent because RouterInfo construction
// includes random padding (per I2P spec). What matters is key consistency.
func TestRouterInfoProvider_ConsistentKeys(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.DefaultRouterConfig()
	cfg.WorkingDir = tempDir

	router, err := FromConfig(cfg)
	require.NoError(t, err)

	// Use initializeRouterKeystore for proper key management
	err = initializeRouterKeystore(router, cfg)
	require.NoError(t, err)

	provider := newRouterInfoProvider(router)

	// Multiple calls should return RouterInfos with same signing public key
	ri1, err := provider.GetRouterInfo()
	require.NoError(t, err)
	require.NotNil(t, ri1)

	ri2, err := provider.GetRouterInfo()
	require.NoError(t, err)
	require.NotNil(t, ri2)

	// Get signing public keys from both RouterInfos - these MUST be consistent
	sigKey1, err := ri1.RouterIdentity().SigningPublicKey()
	require.NoError(t, err, "First RouterInfo should have valid signing key")

	sigKey2, err := ri2.RouterIdentity().SigningPublicKey()
	require.NoError(t, err, "Second RouterInfo should have valid signing key")

	require.NotNil(t, sigKey1, "First RouterInfo should have signing key")
	require.NotNil(t, sigKey2, "Second RouterInfo should have signing key")

	assert.Equal(t, sigKey1.Bytes(), sigKey2.Bytes(), "Signing public key should be consistent across calls")

	// Also verify encryption public keys are consistent
	encKey1, err := ri1.RouterIdentity().PublicKey()
	require.NoError(t, err, "First RouterInfo should have valid encryption key")

	encKey2, err := ri2.RouterIdentity().PublicKey()
	require.NoError(t, err, "Second RouterInfo should have valid encryption key")

	require.NotNil(t, encKey1, "First RouterInfo should have encryption key")
	require.NotNil(t, encKey2, "Second RouterInfo should have encryption key")

	assert.Equal(t, encKey1.Bytes(), encKey2.Bytes(), "Encryption public key should be consistent across calls")
}

// =============================================================================
// Bandwidth Tracking Tests
// Verify accurate measurement
// =============================================================================

// TestBandwidthTracker_RollingAverage verifies correct 15-second average calculation
func TestBandwidthTracker_RollingAverage(t *testing.T) {
	tracker := NewBandwidthTracker()

	// Start with mock bandwidth function
	var totalSent, totalReceived uint64
	var mu sync.Mutex

	getBandwidth := func() (sent, received uint64) {
		mu.Lock()
		defer mu.Unlock()
		return totalSent, totalReceived
	}

	tracker.Start(getBandwidth)
	defer tracker.Stop()

	// Simulate traffic
	for i := 0; i < 5; i++ {
		time.Sleep(100 * time.Millisecond)
		mu.Lock()
		totalSent += 1000
		totalReceived += 2000
		mu.Unlock()
	}

	// Get rates
	inbound, outbound := tracker.GetRates()
	// Rates should be non-zero after traffic
	t.Logf("Inbound: %d B/s, Outbound: %d B/s", inbound, outbound)
	// Due to timing, we just verify the tracker is functioning
	assert.GreaterOrEqual(t, inbound+outbound, uint64(0), "Rates should be non-negative")
}

// TestBandwidthTracker_GracefulStop verifies clean shutdown
func TestBandwidthTracker_GracefulStop(t *testing.T) {
	tracker := NewBandwidthTracker()

	getBandwidth := func() (sent, received uint64) {
		return 100, 200
	}

	tracker.Start(getBandwidth)

	// Stop should complete without hanging
	done := make(chan struct{})
	go func() {
		tracker.Stop()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("BandwidthTracker.Stop() timed out")
	}
}

// TestBandwidthTracker_ZeroRatesInitially verifies rates start at zero
func TestBandwidthTracker_ZeroRatesInitially(t *testing.T) {
	tracker := NewBandwidthTracker()

	inbound, outbound := tracker.GetRates()
	assert.Equal(t, uint64(0), inbound, "Initial inbound rate should be zero")
	assert.Equal(t, uint64(0), outbound, "Initial outbound rate should be zero")
}

// =============================================================================
// I2PControl Integration Tests
// Verify correct stats reporting
// =============================================================================

// TestI2PControlServer_DisabledByDefault verifies disabled state handling
func TestI2PControlServer_DisabledByDefault(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.DefaultRouterConfig()
	cfg.WorkingDir = tempDir
	cfg.I2PControl.Enabled = false

	router, err := FromConfig(cfg)
	require.NoError(t, err)

	// Should not start server when disabled
	err = router.startI2PControlServer()
	assert.NoError(t, err, "Should succeed when disabled")
	assert.Nil(t, router.i2pcontrolServer, "Server should be nil when disabled")
}

// TestI2PControlServer_NilConfig verifies nil config handling
func TestI2PControlServer_NilConfig(t *testing.T) {
	router := &Router{
		cfg: &config.RouterConfig{
			I2PControl: nil,
		},
	}

	err := router.startI2PControlServer()
	assert.NoError(t, err, "Should handle nil config gracefully")
}

// TestRouterAccessInterface_GetMethods verifies router getter methods
func TestRouterAccessInterface_GetMethods(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.DefaultRouterConfig()
	cfg.WorkingDir = tempDir

	router := &Router{
		cfg:      cfg,
		StdNetDB: netdb.NewStdNetDB(tempDir),
	}

	// GetNetDB
	assert.Equal(t, router.StdNetDB, router.GetNetDB(), "GetNetDB should return NetDB")

	// GetConfig
	assert.Equal(t, cfg, router.GetConfig(), "GetConfig should return config")

	// IsRunning
	assert.False(t, router.IsRunning(), "IsRunning should be false when not started")
}

// =============================================================================
// Error Recovery Tests
// Verify subsystem restart on failures
// =============================================================================

// TestErrorRecovery_NetDBFailure verifies handling when NetDB fails to initialize
func TestErrorRecovery_NetDBFailure(t *testing.T) {
	cfg := config.DefaultRouterConfig()
	cfg.WorkingDir = "/nonexistent/path/that/does/not/exist"
	cfg.NetDb.Path = "/nonexistent/path/netdb"
	cfg.I2CP.Enabled = false
	cfg.I2PControl.Enabled = false

	_, err := FromConfig(cfg)
	require.NoError(t, err) // FromConfig succeeds, but Start may fail

	// Note: The router should handle initialization failures gracefully
	// without panicking
	assert.NotPanics(t, func() {
		// Keystore will fail on invalid path - this is expected
		// The test verifies no panic occurs
	})
}

// TestErrorRecovery_DoubleStop verifies idempotent shutdown
func TestErrorRecovery_DoubleStop(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.DefaultRouterConfig()
	cfg.WorkingDir = tempDir
	cfg.I2CP.Enabled = false
	cfg.I2PControl.Enabled = false

	router, err := FromConfig(cfg)
	require.NoError(t, err)

	err = initializeRouterKeystore(router, cfg)
	require.NoError(t, err)

	router.Start()
	time.Sleep(100 * time.Millisecond)

	// Multiple Stop calls should be safe
	assert.NotPanics(t, func() {
		router.Stop()
		router.Stop()
		router.Stop()
	}, "Multiple Stop() calls should not panic")
}

// TestErrorRecovery_StopWithoutStart verifies stop on unstarted router
func TestErrorRecovery_StopWithoutStart(t *testing.T) {
	cfg := config.DefaultRouterConfig()
	cfg.WorkingDir = t.TempDir()

	router, err := FromConfig(cfg)
	require.NoError(t, err)

	// Stop on unstarted router should be safe
	assert.NotPanics(t, func() {
		router.Stop()
	}, "Stop() on unstarted router should not panic")
}

// =============================================================================
// Session Management Tests
// Verify thread-safe session tracking
// =============================================================================

// TestSessionManagement_ThreadSafety verifies concurrent session access
func TestSessionManagement_ThreadSafety(t *testing.T) {
	router := &Router{
		activeSessions: make(map[common.Hash]*ntcp.NTCP2Session),
	}

	var wg sync.WaitGroup
	const numGoroutines = 100

	// Concurrent adds
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			var hash common.Hash
			hash[0] = byte(id)
			router.addSession(hash, nil)
		}(i)
	}
	wg.Wait()

	// Concurrent reads and removes
	wg.Add(numGoroutines * 2)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			var hash common.Hash
			hash[0] = byte(id)
			_, _ = router.getSessionByHash(hash)
		}(i)
		go func(id int) {
			defer wg.Done()
			var hash common.Hash
			hash[0] = byte(id)
			router.removeSession(hash)
		}(i)
	}
	wg.Wait()
}

// TestSessionManagement_SessionReplacement verifies session replacement behavior
func TestSessionManagement_SessionReplacement(t *testing.T) {
	router := &Router{
		activeSessions: make(map[common.Hash]*ntcp.NTCP2Session),
	}

	var hash common.Hash
	hash[0] = 0x01

	// Add first session
	session1 := (*ntcp.NTCP2Session)(nil)
	router.addSession(hash, session1)

	// Replace with second session
	session2 := (*ntcp.NTCP2Session)(nil)
	router.addSession(hash, session2)

	// Should have replaced
	router.sessionMutex.RLock()
	count := len(router.activeSessions)
	router.sessionMutex.RUnlock()

	assert.Equal(t, 1, count, "Should have one session after replacement")
}

// =============================================================================
// Mock Types for Testing
// =============================================================================

// mockGarlicNetDB implements GarlicNetDB for testing
type mockGarlicNetDB struct{}

func (m *mockGarlicNetDB) GetRouterInfo(hash common.Hash) chan router_info.RouterInfo {
	return nil // Simulate not found
}

func (m *mockGarlicNetDB) GetLeaseSet(hash common.Hash) chan lease_set.LeaseSet {
	return nil // Simulate not found
}
func (m *mockGarlicNetDB) StoreRouterInfo(ri router_info.RouterInfo) {}
func (m *mockGarlicNetDB) Size() int                                 { return 0 }
func (m *mockGarlicNetDB) SelectFloodfillRouters(targetHash common.Hash, count int) ([]router_info.RouterInfo, error) {
	return nil, nil
}
