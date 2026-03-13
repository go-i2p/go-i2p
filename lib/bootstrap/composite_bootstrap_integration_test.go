package bootstrap

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetPeers_FileOnlyWithoutPath verifies that BootstrapType "file"
// without a configured ReseedFilePath returns a clear error.
func TestGetPeers_FileOnlyWithoutPath(t *testing.T) {
	cb := newTestCompositeBootstrap(t, "file", "", nil)

	peers, err := cb.GetPeers(context.Background(), 5)
	require.Error(t, err)
	assert.Nil(t, peers)
	assert.Contains(t, err.Error(), "no reseed file path is configured")
}

// TestGetPeers_FileOnlyWithPath verifies that BootstrapType "file"
// dispatches to file-only bootstrap (which will fail because the file
// doesn't exist, but it should NOT fall back to reseed or local).
func TestGetPeers_FileOnlyWithPath(t *testing.T) {
	cb := newTestCompositeBootstrap(t, "file", "/nonexistent/test-data.su3", nil)

	peers, err := cb.GetPeers(context.Background(), 5)
	// Should fail because file doesn't exist
	require.Error(t, err)
	assert.Nil(t, peers)
	// Error should be about file bootstrap, not about netDb
	assert.Contains(t, err.Error(), "file bootstrap failed")
	// Should NOT contain netDb errors (no fallback occurred)
	assert.NotContains(t, err.Error(), "netDb")
	// Should NOT contain "all bootstrap methods" (no auto fallback)
	assert.NotContains(t, err.Error(), "all bootstrap methods")
}

// TestGetPeers_ReseedOnly verifies that BootstrapType "reseed"
// only attempts reseed bootstrap. The error should be reseed-specific.
func TestGetPeers_ReseedOnly(t *testing.T) {
	cb := newTestCompositeBootstrap(t, "reseed", "/some/file.su3", newTestInvalidReseedServers())

	peers, err := cb.GetPeers(context.Background(), 5)
	// Should fail because the reseed server is invalid
	require.Error(t, err)
	assert.Nil(t, peers)
	// Error should be about reseed, not file or netDb
	assert.Contains(t, err.Error(), "reseed bootstrap failed")
	assert.NotContains(t, err.Error(), "file bootstrap")
	assert.NotContains(t, err.Error(), "netDb")
}

// TestGetPeers_LocalOnly verifies that BootstrapType "local"
// only attempts local netDb bootstrap.
func TestGetPeers_LocalOnly(t *testing.T) {
	cb := newTestCompositeBootstrap(t, "local", "/some/file.su3", newTestInvalidReseedServers())

	peers, err := cb.GetPeers(context.Background(), 5)
	// Local netDb may succeed (returns empty) or fail depending on environment.
	// Either way, it should NOT try reseed or file.
	if err != nil {
		assert.Contains(t, err.Error(), "local netDb bootstrap")
		assert.NotContains(t, err.Error(), "reseed")
		assert.NotContains(t, err.Error(), "file bootstrap")
	}
	// If it succeeds with 0 peers, that's also acceptable for local-only
	_ = peers
}

// TestGetPeers_AutoFallback verifies that BootstrapType "auto"
// tries all methods and produces an aggregated error when all fail.
func TestGetPeers_AutoFallback(t *testing.T) {
	cb := newTestCompositeBootstrap(t, "auto", testNonExistentFilePath, newTestInvalidReseedServers())

	peers, err := cb.GetPeers(context.Background(), 5)
	if err != nil {
		// If all methods fail, should produce aggregated error
		errMsg := err.Error()
		assert.True(t, strings.Contains(errMsg, "all bootstrap methods failed"),
			"expected aggregated error, got: %s", errMsg)
	} else {
		// Local netDb may succeed if I2P dirs exist on this machine
		assert.NotNil(t, peers, "auto mode returned nil peers without error")
	}
}

// TestGetPeers_EmptyTypeDefaultsToAuto verifies that an empty
// BootstrapType defaults to "auto" (the full fallback chain).
func TestGetPeers_EmptyTypeDefaultsToAuto(t *testing.T) {
	cb := newTestCompositeBootstrap(t, "", testNonExistentFilePath, newTestInvalidReseedServers())

	// Empty type should behave identically to "auto"
	peersEmpty, errEmpty := cb.GetPeers(context.Background(), 5)

	cbAuto := newTestCompositeBootstrap(t, "auto", testNonExistentFilePath, newTestInvalidReseedServers())
	peersAuto, errAuto := cbAuto.GetPeers(context.Background(), 5)

	// Both should either succeed or fail
	if errEmpty != nil {
		require.Error(t, errAuto, "empty and auto should both fail")
	} else {
		require.NoError(t, errAuto, "empty and auto should both succeed")
		assert.Equal(t, len(peersEmpty), len(peersAuto),
			"empty and auto should return same number of peers")
	}
}

// TestGetPeers_UnknownTypeDefaultsToAuto verifies that an unrecognized
// BootstrapType falls through to auto mode.
func TestGetPeers_UnknownTypeDefaultsToAuto(t *testing.T) {
	cb := newTestCompositeBootstrap(t, "unknown_type", testNonExistentFilePath, newTestInvalidReseedServers())

	peers, err := cb.GetPeers(context.Background(), 5)
	if err != nil {
		// Unknown type should fall back to auto behavior with aggregated error
		assert.Contains(t, err.Error(), "all bootstrap methods failed")
	} else {
		// Local netDb may succeed
		assert.NotNil(t, peers)
	}
}

// TestGetPeers_ContextCancellation verifies that GetPeers respects
// context cancellation regardless of bootstrap type.
func TestGetPeers_ContextCancellation(t *testing.T) {
	cb := newTestCompositeBootstrap(t, "auto", "", newTestInvalidReseedServers())

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	peers, err := cb.GetPeers(ctx, 5)
	// Should fail quickly due to cancelled context
	require.Error(t, err)
	assert.Nil(t, peers)
}

// TestCompositeBootstrap_FallbackToLocalNetDb verifies the composite bootstrap
// fallback behavior when reseed servers are unavailable.
func TestCompositeBootstrap_FallbackToLocalNetDb(t *testing.T) {
	// Create a bootstrap config with no reseed servers (so reseed will fail)
	cfg := &config.BootstrapConfig{
		LowPeerThreshold: testLowPeerThreshold,
		ReseedServers:    []*config.ReseedConfig{},
		LocalNetDbPaths:  []string{"/tmp/non-existent-for-test"},
	}

	cb := NewCompositeBootstrap(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// This should fail because both reseed and local netDb will fail
	// (we explicitly set non-existent paths)
	peers, err := cb.GetPeers(ctx, 10)

	// Note: If user has an actual netDb on their system, the default paths
	// might succeed. So we only check that error contains our expected message
	// when we get an error.
	if err != nil {
		assert.Contains(t, err.Error(), "all bootstrap methods failed")
		assert.Nil(t, peers)
	} else {
		// If it succeeded, it means it found a real netDb somewhere
		t.Log("Local netDb was found on the system - test adapted to this case")
		assert.NotNil(t, peers)
	}
}
