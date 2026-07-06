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
