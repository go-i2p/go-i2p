// Tests for router bandwidth tier resolution. Validates that the router
// classifies its bandwidth into the right tier from its settings.
package router

import (
	"testing"

	"github.com/go-i2p/go-i2p/lib/config"
)

func TestResolveRouterBandwidthTier_ExplicitOverridesAuto(t *testing.T) {
	cfg := &config.RouterConfig{
		BandwidthTier:  "x",
		MaxBandwidth:   64 * 1024,
		MaxConnections: 128,
		Transport: &config.TransportDefaults{
			NTCP2MaxConnections: 128,
		},
	}

	got := resolveRouterBandwidthTier(cfg)
	if got != "X" {
		t.Fatalf("resolveRouterBandwidthTier() = %q, want %q", got, "X")
	}
}

func TestResolveRouterBandwidthTier_DerivesFromUnlimitedAndSessions(t *testing.T) {
	tests := []struct {
		name      string
		maxConn   int
		ntcp2Conn int
		wantTier  string
	}{
		{name: "very high session limit -> X", maxConn: 5000, ntcp2Conn: 5000, wantTier: "X"},
		{name: "high session limit -> P", maxConn: 1200, ntcp2Conn: 1200, wantTier: "P"},
		{name: "moderate session limit -> O", maxConn: 300, ntcp2Conn: 300, wantTier: "O"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.RouterConfig{
				MaxBandwidth:   0,
				MaxConnections: tt.maxConn,
				Transport: &config.TransportDefaults{
					NTCP2MaxConnections: tt.ntcp2Conn,
				},
			}
			got := resolveRouterBandwidthTier(cfg)
			if got != tt.wantTier {
				t.Fatalf("resolveRouterBandwidthTier() = %q, want %q", got, tt.wantTier)
			}
		})
	}
}

func TestResolveRouterBandwidthTier_DerivesFromBandwidthAndPromotesBySessions(t *testing.T) {
	cfg := &config.RouterConfig{
		MaxBandwidth:   40 * 1024,
		MaxConnections: 1500,
		Transport: &config.TransportDefaults{
			NTCP2MaxConnections: 1500,
		},
	}

	got := resolveRouterBandwidthTier(cfg)
	if got != "P" {
		t.Fatalf("resolveRouterBandwidthTier() = %q, want %q", got, "P")
	}
}

func TestResolveRouterBandwidthTier_UsesEffectiveSessionBottleneck(t *testing.T) {
	cfg := &config.RouterConfig{
		MaxBandwidth:   0,
		MaxConnections: 2000,
		Transport: &config.TransportDefaults{
			NTCP2MaxConnections: 300,
		},
	}

	got := resolveRouterBandwidthTier(cfg)
	if got != "O" {
		t.Fatalf("resolveRouterBandwidthTier() = %q, want %q", got, "O")
	}
}

// TestEffectiveSessionLimit_IncludesMaxConcurrentSessions is the C1 guard for
// router.max_concurrent_sessions: it must participate in the session-limit floor
// that derives the advertised bandwidth tier. Before this fix the field was
// validated but never read, so a lower max_concurrent_sessions than
// max_connections had no effect on the tier.
func TestEffectiveSessionLimit_IncludesMaxConcurrentSessions(t *testing.T) {
	// max_concurrent_sessions is the tightest bound; it must win the floor.
	cfg := &config.RouterConfig{
		MaxConnections:        2000,
		MaxConcurrentSessions: 300,
		Transport: &config.TransportDefaults{
			NTCP2MaxConnections: 3000,
		},
	}
	if got := effectiveSessionLimit(cfg); got != 300 {
		t.Fatalf("effectiveSessionLimit() = %d, want 300 (max_concurrent_sessions must be the floor)", got)
	}

	// Zero max_concurrent_sessions must not lower the floor (falls back to the
	// other bounds), so a default/unset value is behavior-neutral.
	cfg2 := &config.RouterConfig{
		MaxConnections:        2000,
		MaxConcurrentSessions: 0,
		Transport: &config.TransportDefaults{
			NTCP2MaxConnections: 3000,
		},
	}
	if got := effectiveSessionLimit(cfg2); got != 2000 {
		t.Fatalf("effectiveSessionLimit() = %d, want 2000 (zero max_concurrent_sessions must not lower the floor)", got)
	}
}
