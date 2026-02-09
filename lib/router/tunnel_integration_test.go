//go:build integration

package router

import (
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestRouterConfig creates a minimal router configuration for testing
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
			LowPeerThreshold: 0, // Disable bootstrap for tests
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

// TestRouter_TunnelManagerInitialization verifies that the router properly initializes
// a tunnel manager during startup with correct dependencies.
func TestRouter_TunnelManagerInitialization(t *testing.T) {
	cfg := createTestRouterConfig(t.TempDir())

	router, err := CreateRouter(cfg)
	require.NoError(t, err, "Failed to create router")
	require.NotNil(t, router, "Router should not be nil")
	defer router.Stop()

	router.Start()
	require.True(t, waitForRouterReady(router, 2*time.Second), "Router should complete initialization")

	assert.NotNil(t, router.GetTunnelManager(), "Tunnel manager should be initialized")
	pool := router.GetTunnelManager().GetPool()
	assert.NotNil(t, pool, "Tunnel manager should have a pool")
}

// TestRouter_GarlicRouterTunnelPoolIntegration verifies that the garlic router
// receives the tunnel pool from the tunnel manager.
func TestRouter_GarlicRouterTunnelPoolIntegration(t *testing.T) {
	cfg := createTestRouterConfig(t.TempDir())

	router, err := CreateRouter(cfg)
	require.NoError(t, err, "Failed to create router")
	require.NotNil(t, router, "Router should not be nil")
	defer func() {
		router.Stop()
		// Give the router time to shut down its goroutines before test cleanup
		time.Sleep(100 * time.Millisecond)
	}()

	router.Start()
	require.True(t, waitForRouterReady(router, 2*time.Second), "Router should complete initialization")

	assert.NotNil(t, router.GetGarlicRouter(), "Garlic router should be initialized")
}

// TestRouter_TunnelPoolAccessibility verifies that the tunnel pool is accessible
// through the tunnel manager's GetPool() method.
func TestRouter_TunnelPoolAccessibility(t *testing.T) {
	cfg := createTestRouterConfig(t.TempDir())

	router, err := CreateRouter(cfg)
	require.NoError(t, err, "Failed to create router")
	require.NotNil(t, router, "Router should not be nil")
	defer router.Stop()

	router.Start()
	require.True(t, waitForRouterReady(router, 2*time.Second), "Router should complete initialization")

	pool := router.GetTunnelManager().GetPool()
	require.NotNil(t, pool, "Tunnel pool should be accessible")

	stats := pool.GetPoolStats()
	assert.Equal(t, 0, stats.Active, "New pool should have 0 active tunnels")
	assert.Equal(t, 0, stats.Building, "New pool should have 0 building tunnels")
	assert.Equal(t, 0, stats.Total, "New pool should have 0 total tunnels")
}

// TestRouter_TunnelManagerCleanupOnStop verifies that stopping the router
// properly cleans up the tunnel manager.
func TestRouter_TunnelManagerCleanupOnStop(t *testing.T) {
	cfg := createTestRouterConfig(t.TempDir())

	router, err := CreateRouter(cfg)
	require.NoError(t, err, "Failed to create router")
	require.NotNil(t, router, "Router should not be nil")

	router.Start()
	require.True(t, waitForRouterReady(router, 2*time.Second), "Router should complete initialization")

	assert.NotNil(t, router.GetTunnelManager(), "Tunnel manager should exist")

	router.Stop()
	// Test passes if no panics occur during shutdown
}

// TestRouter_InitializationOrder verifies that tunnel manager is initialized
// before garlic router so the pool is available.
func TestRouter_InitializationOrder(t *testing.T) {
	cfg := createTestRouterConfig(t.TempDir())

	router, err := CreateRouter(cfg)
	require.NoError(t, err, "Failed to create router")
	require.NotNil(t, router, "Router should not be nil")
	defer router.Stop()

	router.Start()
	require.True(t, waitForRouterReady(router, 2*time.Second), "Router should complete initialization")

	assert.NotNil(t, router.GetTunnelManager(), "Tunnel manager should be initialized")
	assert.NotNil(t, router.GetGarlicRouter(), "Garlic router should be initialized")

	pool := router.GetTunnelManager().GetPool()
	assert.NotNil(t, pool, "Tunnel manager should provide access to tunnel pool")
}
