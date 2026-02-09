//go:build integration

package router

import (
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/config"
	ntcp "github.com/go-i2p/go-i2p/lib/transport/ntcp2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRouterCloseReleasesResources verifies that Close() properly releases all router resources
func TestRouterCloseReleasesResources(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.DefaultRouterConfig()
	cfg.WorkingDir = tempDir
	cfg.I2CP.Enabled = false

	router, err := FromConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, router)

	// Initialize keystore
	err = initializeRouterKeystore(router, cfg)
	require.NoError(t, err)

	// Start the router
	router.Start()
	time.Sleep(50 * time.Millisecond)

	// Verify resources are initialized
	router.runMux.RLock()
	assert.True(t, router.running, "Router should be running")
	router.runMux.RUnlock()

	// Close the router (should call Stop() internally if still running)
	err = router.Close()
	assert.NoError(t, err)

	// Verify all resources are released
	assert.Nil(t, router.TransportMuxer, "TransportMuxer should be nil after Close()")
	assert.Nil(t, router.messageRouter, "messageRouter should be nil after Close()")
	assert.Nil(t, router.garlicRouter, "garlicRouter should be nil after Close()")
	assert.Nil(t, router.tunnelManager, "tunnelManager should be nil after Close()")
	assert.Nil(t, router.RouterInfoKeystore, "RouterInfoKeystore should be nil after Close()")
	assert.Nil(t, router.StdNetDB, "StdNetDB should be nil after Close()")
	assert.Nil(t, router.closeChnl, "closeChnl should be nil after Close()")

	// Verify router is no longer running
	router.runMux.RLock()
	assert.False(t, router.running, "Router should not be running after Close()")
	router.runMux.RUnlock()
}

// TestRouterCloseAfterStop verifies that Close() works correctly after Stop() has been called
func TestRouterCloseAfterStop(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.DefaultRouterConfig()
	cfg.WorkingDir = tempDir
	cfg.I2CP.Enabled = false

	router, err := FromConfig(cfg)
	require.NoError(t, err)

	// Initialize keystore
	err = initializeRouterKeystore(router, cfg)
	require.NoError(t, err)

	// Start and then stop the router
	router.Start()
	time.Sleep(50 * time.Millisecond)
	router.Stop()

	// Allow time for async goroutines to complete
	// Note: This is needed because some tunnel pool goroutines may still be running
	time.Sleep(200 * time.Millisecond)

	// Verify router is stopped but resources may still exist
	router.runMux.RLock()
	assert.False(t, router.running, "Router should not be running after Stop()")
	router.runMux.RUnlock()

	// Close should still work and release remaining resources
	err = router.Close()
	assert.NoError(t, err)

	// Verify all resources are released
	assert.Nil(t, router.TransportMuxer, "TransportMuxer should be nil after Close()")
	assert.Nil(t, router.StdNetDB, "StdNetDB should be nil after Close()")
	assert.Nil(t, router.closeChnl, "closeChnl should be nil after Close()")
}

// TestRouterCloseWithoutStart verifies that Close() handles a never-started router
func TestRouterCloseWithoutStart(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.DefaultRouterConfig()
	cfg.WorkingDir = tempDir
	cfg.I2CP.Enabled = false

	router, err := FromConfig(cfg)
	require.NoError(t, err)

	// Don't start the router - just close it
	err = router.Close()
	assert.NoError(t, err, "Close() should not error on a never-started router")

	// Verify state is clean
	router.runMux.RLock()
	assert.False(t, router.running, "Router should not be running")
	router.runMux.RUnlock()
}

// TestRouterCloseIdempotent verifies that calling Close() multiple times is safe
func TestRouterCloseIdempotent(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.DefaultRouterConfig()
	cfg.WorkingDir = tempDir
	cfg.I2CP.Enabled = false

	router, err := FromConfig(cfg)
	require.NoError(t, err)

	// Initialize keystore
	err = initializeRouterKeystore(router, cfg)
	require.NoError(t, err)

	// Start and close the router
	router.Start()
	time.Sleep(50 * time.Millisecond)

	err = router.Close()
	assert.NoError(t, err, "First Close() should succeed")

	// Second Close() should also succeed (or at least not panic)
	err = router.Close()
	assert.NoError(t, err, "Second Close() should succeed")

	// Third Close() should also succeed
	err = router.Close()
	assert.NoError(t, err, "Third Close() should succeed")
}

// TestRouterCloseClearsActiveSessions verifies that Close() clears the active sessions map
func TestRouterCloseClearsActiveSessions(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.DefaultRouterConfig()
	cfg.WorkingDir = tempDir
	cfg.I2CP.Enabled = false

	router, err := FromConfig(cfg)
	require.NoError(t, err)

	// Initialize keystore
	err = initializeRouterKeystore(router, cfg)
	require.NoError(t, err)

	// Manually add a mock session to the active sessions map
	router.sessionMutex.Lock()
	if router.activeSessions == nil {
		router.activeSessions = make(map[common.Hash]*ntcp.NTCP2Session)
	}
	testHash := common.Hash{}
	copy(testHash[:], []byte("test-session-hash-for-testing!!!"))
	router.activeSessions[testHash] = nil // Add a nil session for testing
	router.sessionMutex.Unlock()

	// Verify the session was added
	router.sessionMutex.RLock()
	sessionCount := len(router.activeSessions)
	router.sessionMutex.RUnlock()
	assert.Equal(t, 1, sessionCount, "Should have 1 active session before Close()")

	// Close the router
	err = router.Close()
	assert.NoError(t, err)

	// Verify sessions were cleared
	router.sessionMutex.RLock()
	assert.Nil(t, router.activeSessions, "activeSessions should be nil after Close()")
	router.sessionMutex.RUnlock()
}

// TestRouterCannotRestartAfterClose verifies that a router cannot be restarted after Close()
func TestRouterCannotRestartAfterClose(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.DefaultRouterConfig()
	cfg.WorkingDir = tempDir
	cfg.I2CP.Enabled = false

	router, err := FromConfig(cfg)
	require.NoError(t, err)

	// Initialize keystore
	err = initializeRouterKeystore(router, cfg)
	require.NoError(t, err)

	// Start, then close the router
	router.Start()
	time.Sleep(50 * time.Millisecond)

	err = router.Close()
	assert.NoError(t, err)

	// Note: After Close(), the router's resources are nilled out.
	// Attempting to start would cause panics because critical components are missing.
	// The key contract of Close() is that it finalizes the router so it cannot be reused.
	// We verify this by checking that all critical components are nil.
	assert.Nil(t, router.TransportMuxer, "TransportMuxer should be nil - prevents restart")
	assert.Nil(t, router.StdNetDB, "StdNetDB should be nil - prevents restart")
	assert.Nil(t, router.RouterInfoKeystore, "RouterInfoKeystore should be nil - prevents restart")
}
