package config

import (
	"strings"
	"testing"
)

func TestKnownReseedServers_NotEmpty(t *testing.T) {
	if len(KnownReseedServers) == 0 {
		t.Fatal("KnownReseedServers should not be empty")
	}
}

func TestKnownReseedServers_MinimumCount(t *testing.T) {
	// Should have at least 10 servers per PLAN.md
	if len(KnownReseedServers) < 10 {
		t.Errorf("expected at least 10 known reseed servers, got %d", len(KnownReseedServers))
	}
}

func TestKnownReseedServers_ValidURLs(t *testing.T) {
	for i, server := range KnownReseedServers {
		t.Run(server.Url, func(t *testing.T) {
			if server.Url == "" {
				t.Errorf("server %d has empty URL", i)
			}
			if !strings.HasPrefix(server.Url, "https://") {
				t.Errorf("server %d URL should use HTTPS: %s", i, server.Url)
			}
			if !strings.HasSuffix(server.Url, "/") {
				t.Errorf("server %d URL should end with /: %s", i, server.Url)
			}
		})
	}
}

func TestKnownReseedServers_ValidFingerprints(t *testing.T) {
	for i, server := range KnownReseedServers {
		t.Run(server.Url, func(t *testing.T) {
			if server.SU3Fingerprint == "" {
				t.Errorf("server %d has empty SU3Fingerprint", i)
			}
			if !strings.HasSuffix(server.SU3Fingerprint, ".crt") {
				t.Errorf("server %d SU3Fingerprint should end with .crt: %s", i, server.SU3Fingerprint)
			}
		})
	}
}

func TestKnownReseedServers_NoDuplicateURLs(t *testing.T) {
	seen := make(map[string]bool)
	for _, server := range KnownReseedServers {
		if seen[server.Url] {
			t.Errorf("duplicate URL found: %s", server.Url)
		}
		seen[server.Url] = true
	}
}

func TestKnownReseedServers_ContainsI2pGitOrg(t *testing.T) {
	// The go-i2p dev team server should always be present
	found := false
	for _, server := range KnownReseedServers {
		if strings.Contains(server.Url, "reseed.i2pgit.org") {
			found = true
			break
		}
	}
	if !found {
		t.Error("reseed.i2pgit.org should be in KnownReseedServers")
	}
}

func TestReseedStrategyConstants(t *testing.T) {
	if ReseedStrategyUnion != "union" {
		t.Errorf("ReseedStrategyUnion should be 'union', got %s", ReseedStrategyUnion)
	}
	if ReseedStrategyIntersection != "intersection" {
		t.Errorf("ReseedStrategyIntersection should be 'intersection', got %s", ReseedStrategyIntersection)
	}
	if ReseedStrategyRandom != "random" {
		t.Errorf("ReseedStrategyRandom should be 'random', got %s", ReseedStrategyRandom)
	}
}

func TestValidReseedStrategies(t *testing.T) {
	strategies := ValidReseedStrategies()
	if len(strategies) != 3 {
		t.Errorf("expected 3 valid strategies, got %d", len(strategies))
	}

	expected := map[string]bool{
		"union":        true,
		"intersection": true,
		"random":       true,
	}

	for _, strategy := range strategies {
		if !expected[strategy] {
			t.Errorf("unexpected strategy in list: %s", strategy)
		}
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
		{"UNION", false}, // case sensitive
		{"Union", false},
	}

	for _, tc := range tests {
		t.Run(tc.strategy, func(t *testing.T) {
			result := IsValidReseedStrategy(tc.strategy)
			if result != tc.valid {
				t.Errorf("IsValidReseedStrategy(%q) = %v, want %v", tc.strategy, result, tc.valid)
			}
		})
	}
}

func TestDefaultMinReseedServers(t *testing.T) {
	// Should be 1 for backward compatibility
	if DefaultMinReseedServers != 1 {
		t.Errorf("DefaultMinReseedServers should be 1 for backward compatibility, got %d", DefaultMinReseedServers)
	}
}
