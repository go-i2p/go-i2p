package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Unit Tests for reseed_servers.go — KnownReseedServers, strategy constants
// =============================================================================

func TestKnownReseedServers_NotEmpty(t *testing.T) {
	require.NotEmpty(t, KnownReseedServers, "KnownReseedServers should not be empty")
}

func TestKnownReseedServers_MinimumCount(t *testing.T) {
	assert.GreaterOrEqual(t, len(KnownReseedServers), 10, "expected at least 10 known reseed servers")
}

func TestKnownReseedServers_ValidURLs(t *testing.T) {
	for i, server := range KnownReseedServers {
		t.Run(server.Url, func(t *testing.T) {
			assert.NotEmpty(t, server.Url, "server %d has empty URL", i)
			assert.True(t, strings.HasPrefix(server.Url, "https://"), "server %d URL should use HTTPS: %s", i, server.Url)
			assert.True(t, strings.HasSuffix(server.Url, "/"), "server %d URL should end with /: %s", i, server.Url)
		})
	}
}

func TestKnownReseedServers_ValidFingerprints(t *testing.T) {
	for i, server := range KnownReseedServers {
		t.Run(server.Url, func(t *testing.T) {
			assert.NotEmpty(t, server.SU3Fingerprint, "server %d has empty SU3Fingerprint", i)
			assert.True(t, strings.HasSuffix(server.SU3Fingerprint, ".crt"),
				"server %d SU3Fingerprint should end with .crt: %s", i, server.SU3Fingerprint)
		})
	}
}

func TestKnownReseedServers_NoDuplicateURLs(t *testing.T) {
	seen := make(map[string]bool)
	for _, server := range KnownReseedServers {
		assert.False(t, seen[server.Url], "duplicate URL found: %s", server.Url)
		seen[server.Url] = true
	}
}

func TestKnownReseedServers_ContainsI2pGitOrg(t *testing.T) {
	found := false
	for _, server := range KnownReseedServers {
		if strings.Contains(server.Url, "reseed.i2pgit.org") {
			found = true
			break
		}
	}
	assert.True(t, found, "reseed.i2pgit.org should be in KnownReseedServers")
}

func TestReseedStrategyConstants(t *testing.T) {
	assert.Equal(t, "union", string(ReseedStrategyUnion), "ReseedStrategyUnion")
	assert.Equal(t, "intersection", string(ReseedStrategyIntersection), "ReseedStrategyIntersection")
	assert.Equal(t, "random", string(ReseedStrategyRandom), "ReseedStrategyRandom")
}

func TestValidReseedStrategies(t *testing.T) {
	strategies := ValidReseedStrategies()
	assert.Len(t, strategies, 3, "expected 3 valid strategies")

	expected := map[string]bool{"union": true, "intersection": true, "random": true}
	for _, strategy := range strategies {
		assert.True(t, expected[strategy], "unexpected strategy in list: %s", strategy)
	}
}

func TestIsValidReseedStrategy(t *testing.T) {
	tests := []struct {
		strategy string
		valid    bool
	}{
		{"union", true},
		{"intersection", true},
		{"random", true},
		{"", false},
		{"invalid", false},
		{"UNION", false},
		{"Union", false},
	}

	for _, tc := range tests {
		t.Run(tc.strategy, func(t *testing.T) {
			assert.Equal(t, tc.valid, IsValidReseedStrategy(tc.strategy),
				"IsValidReseedStrategy(%q)", tc.strategy)
		})
	}
}

func TestDefaultMinReseedServers(t *testing.T) {
	assert.Equal(t, 2, DefaultMinReseedServers, "DefaultMinReseedServers should be 2 for Java I2P parity")
}
