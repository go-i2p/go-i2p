package router

import (
	"testing"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/stretchr/testify/assert"
)

// TestRouterBandwidthProvider_ConfiguredLimit verifies that the provider
// returns the router's MaxBandwidth config value.
func TestRouterBandwidthProvider_ConfiguredLimit(t *testing.T) {
	cfg := config.DefaultRouterConfig()
	// Default is 1 MB/s = 1048576
	bp := &routerBandwidthProvider{cfg: cfg}
	in, out := bp.GetBandwidthLimits()
	assert.Equal(t, uint32(1024*1024), in, "inbound should match MaxBandwidth")
	assert.Equal(t, uint32(1024*1024), out, "outbound should match MaxBandwidth")
}

// TestRouterBandwidthProvider_CustomLimit verifies custom bandwidth config.
func TestRouterBandwidthProvider_CustomLimit(t *testing.T) {
	cfg := config.DefaultRouterConfig()
	cfg.MaxBandwidth = 500000 // 500 KB/s
	bp := &routerBandwidthProvider{cfg: cfg}
	in, out := bp.GetBandwidthLimits()
	assert.Equal(t, uint32(500000), in)
	assert.Equal(t, uint32(500000), out)
}

// TestRouterBandwidthProvider_Unlimited verifies that zero MaxBandwidth
// (unlimited) returns max uint32.
func TestRouterBandwidthProvider_Unlimited(t *testing.T) {
	cfg := config.DefaultRouterConfig()
	cfg.MaxBandwidth = 0
	bp := &routerBandwidthProvider{cfg: cfg}
	in, out := bp.GetBandwidthLimits()
	assert.Equal(t, ^uint32(0), in, "unlimited should return max uint32")
	assert.Equal(t, ^uint32(0), out, "unlimited should return max uint32")
}

// TestRouterBandwidthProvider_LargeValue verifies that values exceeding
// uint32 range clamp to max uint32.
func TestRouterBandwidthProvider_LargeValue(t *testing.T) {
	cfg := config.DefaultRouterConfig()
	cfg.MaxBandwidth = 1 << 40 // 1 TB/s, exceeds uint32
	bp := &routerBandwidthProvider{cfg: cfg}
	in, out := bp.GetBandwidthLimits()
	assert.Equal(t, ^uint32(0), in, "should clamp to max uint32")
	assert.Equal(t, ^uint32(0), out, "should clamp to max uint32")
}
