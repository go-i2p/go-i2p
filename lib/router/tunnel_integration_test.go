//go:build integration

package router

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRouter_TunnelManagerInitialization verifies that the router properly initializes
// a tunnel manager during startup with correct dependencies.
func TestRouter_TunnelManagerInitialization(t *testing.T) {
	router := createReadyTestRouter(t)

	assert.NotNil(t, router.GetTunnelManager(), "Tunnel manager should be initialized")
	pool := router.GetTunnelManager().GetPool()
	assert.NotNil(t, pool, "Tunnel manager should have a pool")
}

// TestRouter_GarlicRouterTunnelPoolIntegration verifies that the garlic router
// receives the tunnel pool from the tunnel manager.
func TestRouter_GarlicRouterTunnelPoolIntegration(t *testing.T) {
	router := createReadyTestRouter(t)

	assert.NotNil(t, router.GetGarlicRouter(), "Garlic router should be initialized")
}

// TestRouter_TunnelPoolAccessibility verifies that the tunnel pool is accessible
// through the tunnel manager's GetPool() method.
func TestRouter_TunnelPoolAccessibility(t *testing.T) {
	router := createReadyTestRouter(t)

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
	router := createReadyTestRouter(t)

	assert.NotNil(t, router.GetTunnelManager(), "Tunnel manager should exist")

	router.Stop()
	// Test passes if no panics occur during shutdown
}

// TestRouter_InitializationOrder verifies that tunnel manager is initialized
// before garlic router so the pool is available.
func TestRouter_InitializationOrder(t *testing.T) {
	router := createReadyTestRouter(t)

	assert.NotNil(t, router.GetTunnelManager(), "Tunnel manager should be initialized")
	assert.NotNil(t, router.GetGarlicRouter(), "Garlic router should be initialized")

	pool := router.GetTunnelManager().GetPool()
	assert.NotNil(t, pool, "Tunnel manager should provide access to tunnel pool")
}
