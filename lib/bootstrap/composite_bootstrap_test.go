package bootstrap

import (
	"context"
	"strings"
	"testing"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetPeers_FileOnlyWithoutPath verifies that BootstrapType "file"
// without a configured ReseedFilePath returns a clear error.
func TestGetPeers_FileOnlyWithoutPath(t *testing.T) {
	cfg := &config.BootstrapConfig{
		LowPeerThreshold: 10,
		BootstrapType:    "file",
		ReseedFilePath:   "", // no file path
	}
	cb := NewCompositeBootstrap(cfg)
	require.NotNil(t, cb)

	peers, err := cb.GetPeers(context.Background(), 5)
	require.Error(t, err)
	assert.Nil(t, peers)
	assert.Contains(t, err.Error(), "no reseed file path is configured")
}

// TestGetPeers_FileOnlyWithPath verifies that BootstrapType "file"
// dispatches to file-only bootstrap (which will fail because the file
// doesn't exist, but it should NOT fall back to reseed or local).
func TestGetPeers_FileOnlyWithPath(t *testing.T) {
	cfg := &config.BootstrapConfig{
		LowPeerThreshold: 10,
		BootstrapType:    "file",
		ReseedFilePath:   "/nonexistent/test-data.su3",
	}
	cb := NewCompositeBootstrap(cfg)
	require.NotNil(t, cb)

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
	cfg := &config.BootstrapConfig{
		LowPeerThreshold: 10,
		BootstrapType:    "reseed",
		ReseedFilePath:   "/some/file.su3", // should be ignored
		ReseedServers: []*config.ReseedConfig{
			{
				Url:            "https://localhost:1/invalid",
				SU3Fingerprint: "test.crt",
			},
		},
	}
	cb := NewCompositeBootstrap(cfg)
	require.NotNil(t, cb)

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
	cfg := &config.BootstrapConfig{
		LowPeerThreshold: 10,
		BootstrapType:    "local",
		ReseedFilePath:   "/some/file.su3", // should be ignored
		ReseedServers: []*config.ReseedConfig{
			{
				Url:            "https://localhost:1/invalid",
				SU3Fingerprint: "test.crt",
			},
		},
	}
	cb := NewCompositeBootstrap(cfg)
	require.NotNil(t, cb)

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
	cfg := &config.BootstrapConfig{
		LowPeerThreshold: 10,
		BootstrapType:    "auto",
		ReseedFilePath:   "/nonexistent/test.su3", // will fail
		ReseedServers: []*config.ReseedConfig{
			{
				Url:            "https://localhost:1/invalid",
				SU3Fingerprint: "test.crt",
			},
		},
	}
	cb := NewCompositeBootstrap(cfg)
	require.NotNil(t, cb)

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
	cfg := &config.BootstrapConfig{
		LowPeerThreshold: 10,
		BootstrapType:    "", // empty defaults to auto
		ReseedFilePath:   "/nonexistent/test.su3",
		ReseedServers: []*config.ReseedConfig{
			{
				Url:            "https://localhost:1/invalid",
				SU3Fingerprint: "test.crt",
			},
		},
	}
	cb := NewCompositeBootstrap(cfg)
	require.NotNil(t, cb)

	// Empty type should behave identically to "auto"
	peersEmpty, errEmpty := cb.GetPeers(context.Background(), 5)

	cfgAuto := &config.BootstrapConfig{
		LowPeerThreshold: 10,
		BootstrapType:    "auto",
		ReseedFilePath:   "/nonexistent/test.su3",
		ReseedServers: []*config.ReseedConfig{
			{
				Url:            "https://localhost:1/invalid",
				SU3Fingerprint: "test.crt",
			},
		},
	}
	cbAuto := NewCompositeBootstrap(cfgAuto)
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
	cfg := &config.BootstrapConfig{
		LowPeerThreshold: 10,
		BootstrapType:    "unknown_type",
		ReseedFilePath:   "/nonexistent/test.su3",
		ReseedServers: []*config.ReseedConfig{
			{
				Url:            "https://localhost:1/invalid",
				SU3Fingerprint: "test.crt",
			},
		},
	}
	cb := NewCompositeBootstrap(cfg)
	require.NotNil(t, cb)

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
	cfg := &config.BootstrapConfig{
		LowPeerThreshold: 10,
		BootstrapType:    "auto",
		ReseedServers: []*config.ReseedConfig{
			{
				Url:            "https://localhost:1/invalid",
				SU3Fingerprint: "test.crt",
			},
		},
	}
	cb := NewCompositeBootstrap(cfg)
	require.NotNil(t, cb)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	peers, err := cb.GetPeers(ctx, 5)
	// Should fail quickly due to cancelled context
	require.Error(t, err)
	assert.Nil(t, peers)
}
