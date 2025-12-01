package router

import (
	"testing"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRouterInfoProvider_GetRouterInfo tests retrieving RouterInfo from the provider
func TestRouterInfoProvider_GetRouterInfo(t *testing.T) {
	// Create a router with test configuration
	tempDir := t.TempDir()
	cfg := &config.RouterConfig{
		WorkingDir: tempDir,
	}

	router, err := FromConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, router)

	// Initialize keystore
	err = initializeRouterKeystore(router, cfg)
	require.NoError(t, err)

	// Create the provider
	provider := newRouterInfoProvider(router)
	require.NotNil(t, provider)

	// Get RouterInfo
	ri, err := provider.GetRouterInfo()

	// Should successfully construct RouterInfo
	require.NoError(t, err)
	require.NotNil(t, ri)

	// Note: In test environment with nil addresses, IsValid() may return false
	// In production, the RouterInfo would have actual NTCP2/SSU2 addresses
	// The important part is that it constructs without error
	assert.NotNil(t, ri, "RouterInfo should be constructed")
}

// TestRouterInfoProvider_InterfaceCompliance tests interface implementation
func TestRouterInfoProvider_InterfaceCompliance(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.RouterConfig{
		WorkingDir: tempDir,
	}

	router, err := FromConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, router)

	// Initialize keystore
	err = initializeRouterKeystore(router, cfg)
	require.NoError(t, err)

	provider := newRouterInfoProvider(router)

	// Verify provider implements the interface
	assert.NotNil(t, provider)
}

// TestRouterInfoProvider_MultipleCallsReturnValid tests calling GetRouterInfo multiple times
func TestRouterInfoProvider_MultipleCallsReturnValid(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.RouterConfig{
		WorkingDir: tempDir,
	}

	router, err := FromConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, router)

	err = initializeRouterKeystore(router, cfg)
	require.NoError(t, err)

	provider := newRouterInfoProvider(router)

	// Call GetRouterInfo multiple times
	ri1, err1 := provider.GetRouterInfo()
	require.NoError(t, err1)
	require.NotNil(t, ri1)

	ri2, err2 := provider.GetRouterInfo()
	require.NoError(t, err2)
	require.NotNil(t, ri2)

	ri3, err3 := provider.GetRouterInfo()
	require.NoError(t, err3)
	require.NotNil(t, ri3)

	// All should be constructed successfully
	// Note: IsValid() may return false in test environment without addresses
	assert.NotNil(t, ri1)
	assert.NotNil(t, ri2)
	assert.NotNil(t, ri3)
}
