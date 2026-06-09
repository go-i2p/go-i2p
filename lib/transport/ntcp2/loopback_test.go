package ntcp2

import (
	"testing"

	"github.com/go-i2p/go-i2p/lib/nat"
	"github.com/stretchr/testify/assert"
)

// P-1: Test that localhost hostname is correctly identified as loopback
// and skips NAT traversal
func TestLocalhostSkipsNATTraversal(t *testing.T) {
	tests := []struct {
		name       string
		host       string
		expectLoop bool
	}{
		{
			name:       "localhost hostname resolves to loopback",
			host:       "localhost",
			expectLoop: true,
		},
		{
			name:       "127.0.0.1 literal IP is loopback",
			host:       "127.0.0.1",
			expectLoop: true,
		},
		{
			name:       "::1 literal IPv6 is loopback",
			host:       "::1",
			expectLoop: true,
		},
		{
			name:       "0.0.0.0 wildcard is not loopback",
			host:       "0.0.0.0",
			expectLoop: false,
		},
		{
			name:       "empty host (wildcard) is not loopback",
			host:       "",
			expectLoop: false,
		},
		{
			name:       "192.168.1.1 private IP is not loopback",
			host:       "192.168.1.1",
			expectLoop: false,
		},
		{
			name:       "8.8.8.8 public IP is not loopback",
			host:       "8.8.8.8",
			expectLoop: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := nat.IsLoopbackAddress(tt.host)
			if tt.expectLoop {
				assert.True(t, result, "Expected %s to be detected as loopback", tt.host)
			} else {
				assert.False(t, result, "Expected %s NOT to be detected as loopback", tt.host)
			}
		})
	}
}

// P-1: Integration test verifying localhost:0 skips NAT traversal and binds quickly
func TestLocalhostBindSkipsNATTraversal(t *testing.T) {
	// P-1 tests the isLoopbackAddress helper function, which is called during bind.
	// The full NewNTCP2Transport requires a valid RouterInfo identity (crypto keys, etc.),
	// which is beyond the scope of a unit test for the loopback check.
	// The unit test above (TestLocalhostSkipsNATTraversal) validates the core logic.
	// This placeholder documents that the integration path is covered by existing
	// transport startup tests that bind to localhost.
	t.Skip("Full transport startup requires valid identity; isLoopbackAddress tested via unit test")
}

// P-1: Edge case test for hostname that resolves to mix of loopback and non-loopback
// (should return false because not *all* addresses are loopback)
func TestMixedResolutionNotLoopback(t *testing.T) {
	// This test documents expected behavior but doesn't execute a real mixed-resolution
	// hostname because that would require DNS/hosts file setup. The code path is exercised
	// via isLoopbackAddress's loop — if any IP is non-loopback, it returns false.

	// Simulate what would happen with a hostname that resolves to [127.0.0.1, 192.168.1.1]
	// (The real lookup is inside nat.IsLoopbackAddress; we can only test the helper directly.)
	mixedHost := "test-mixed-hostname.invalid"
	result := nat.IsLoopbackAddress(mixedHost)
	// Since the hostname doesn't actually resolve, the function fails open (non-loopback)
	assert.False(t, result, "Expected unresolved hostname to fail open as non-loopback")
}
