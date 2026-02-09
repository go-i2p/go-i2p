package router

import (
	"testing"

	"github.com/go-i2p/go-i2p/lib/config"
)

// TestDefaultRouterConfig_HasExpectedDefaults verifies the default RouterConfig values
// for MaxBandwidth, MaxConnections, and AcceptTunnels.
func TestDefaultRouterConfig_HasExpectedDefaults(t *testing.T) {
	cfg := config.DefaultRouterConfig()

	if cfg.MaxBandwidth != 1024*1024 {
		t.Errorf("MaxBandwidth = %d, want %d (1 MB/s)", cfg.MaxBandwidth, 1024*1024)
	}
	if cfg.MaxConnections != 200 {
		t.Errorf("MaxConnections = %d, want 200", cfg.MaxConnections)
	}
	if !cfg.AcceptTunnels {
		t.Error("AcceptTunnels should be true by default")
	}
}

// TestGetMaxBandwidth_UsesConfig verifies getMaxBandwidth reads from config.
func TestGetMaxBandwidth_UsesConfig(t *testing.T) {
	tests := []struct {
		name      string
		cfg       *config.RouterConfig
		wantBytes uint64
	}{
		{
			name:      "default config",
			cfg:       config.DefaultRouterConfig(),
			wantBytes: 1024 * 1024,
		},
		{
			name: "custom 5 MB/s",
			cfg: &config.RouterConfig{
				MaxBandwidth: 5 * 1024 * 1024,
			},
			wantBytes: 5 * 1024 * 1024,
		},
		{
			name:      "nil config uses default",
			cfg:       nil,
			wantBytes: 1024 * 1024,
		},
		{
			name: "zero config uses default",
			cfg: &config.RouterConfig{
				MaxBandwidth: 0,
			},
			wantBytes: 1024 * 1024,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Router{cfg: tt.cfg}
			got := r.getMaxBandwidth()
			if got != tt.wantBytes {
				t.Errorf("getMaxBandwidth() = %d, want %d", got, tt.wantBytes)
			}
		})
	}
}

// TestGetMaxConnections_UsesConfig verifies getMaxConnections reads from config.
func TestGetMaxConnections_UsesConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.RouterConfig
		want int
	}{
		{
			name: "default config",
			cfg:  config.DefaultRouterConfig(),
			want: 200,
		},
		{
			name: "custom 500 connections",
			cfg: &config.RouterConfig{
				MaxConnections: 500,
			},
			want: 500,
		},
		{
			name: "nil config uses default",
			cfg:  nil,
			want: 200,
		},
		{
			name: "zero config uses default",
			cfg: &config.RouterConfig{
				MaxConnections: 0,
			},
			want: 200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Router{cfg: tt.cfg}
			got := r.getMaxConnections()
			if got != tt.want {
				t.Errorf("getMaxConnections() = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestIsAcceptingTunnels_UsesConfig verifies isAcceptingTunnels reads from config.
func TestIsAcceptingTunnels_UsesConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.RouterConfig
		want bool
	}{
		{
			name: "default config accepts tunnels",
			cfg:  config.DefaultRouterConfig(),
			want: true,
		},
		{
			name: "disabled tunnels",
			cfg: &config.RouterConfig{
				AcceptTunnels: false,
			},
			want: false,
		},
		{
			name: "nil config uses default",
			cfg:  nil,
			want: true,
		},
		{
			name: "explicit true",
			cfg: &config.RouterConfig{
				AcceptTunnels: true,
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Router{cfg: tt.cfg}
			got := r.isAcceptingTunnels()
			if got != tt.want {
				t.Errorf("isAcceptingTunnels() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestConfigIntegration_CongestionMonitorUsesConfig verifies the congestion monitor
// picks up the config values through the router method references.
func TestConfigIntegration_CongestionMonitorUsesConfig(t *testing.T) {
	cfg := &config.RouterConfig{
		MaxBandwidth:   10 * 1024 * 1024, // 10 MB/s
		MaxConnections: 500,
		AcceptTunnels:  false,
	}
	r := &Router{cfg: cfg}

	// The congestion monitor uses these as function references
	// Verify they return config values
	if r.getMaxBandwidth() != 10*1024*1024 {
		t.Errorf("getMaxBandwidth() = %d, want %d", r.getMaxBandwidth(), 10*1024*1024)
	}
	if r.getMaxConnections() != 500 {
		t.Errorf("getMaxConnections() = %d, want 500", r.getMaxConnections())
	}
	if r.isAcceptingTunnels() {
		t.Error("isAcceptingTunnels() should be false when AcceptTunnels=false")
	}
}
