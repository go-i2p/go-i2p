//go:build integration

package router

import (
	"testing"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/stretchr/testify/require"
)

// createTestRouter creates a Router with a temp working dir, I2CP disabled, and returns it.
func createTestRouter(t *testing.T) *Router {
	t.Helper()
	tempDir := t.TempDir()
	cfg := config.DefaultRouterConfig()
	cfg.WorkingDir = tempDir
	cfg.I2CP.Enabled = false

	router, err := FromConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, router)
	return router
}

// createTestRouterWithKeystore creates a Router and initializes its keystore.
func createTestRouterWithKeystore(t *testing.T) *Router {
	t.Helper()
	router := createTestRouter(t)
	err := initializeRouterKeystore(router, router.cfg)
	require.NoError(t, err)
	return router
}
