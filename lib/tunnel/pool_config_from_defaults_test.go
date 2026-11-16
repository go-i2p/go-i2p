package tunnel

import (
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/stretchr/testify/assert"
)

// TestPoolConfigFromTunnelDefaults_HonorsOperatorKnobs is the C1 mutation guard:
// before this fix, NewTunnelManager built every pool from DefaultPoolConfig() and
// silently ignored the operator's tunnel.* settings, so min/max_pool_size, length,
// lifetime, build_retries, replace_before_expiration and maintenance_interval were
// dead knobs. This pins that each documented knob now reaches PoolConfig.
func TestPoolConfigFromTunnelDefaults_HonorsOperatorKnobs(t *testing.T) {
	cfg := config.TunnelDefaults{
		MinPoolSize:             2,
		MaxPoolSize:             5,
		TunnelLength:            4,
		TunnelLifetime:          20 * time.Minute,
		ReplaceBeforeExpiration: 3 * time.Minute,
		BuildRetries:            7,
		MaintenanceInterval:     45 * time.Second,
	}

	pc := PoolConfigFromTunnelDefaults(cfg)

	assert.Equal(t, 2, pc.MinTunnels, "tunnel.min_pool_size must reach MinTunnels")
	assert.Equal(t, 5, pc.MaxTunnels, "tunnel.max_pool_size must reach MaxTunnels")
	assert.Equal(t, 4, pc.HopCount, "tunnel.length must reach HopCount")
	assert.Equal(t, 7, pc.MaxBuildRetries, "tunnel.build_retries must reach MaxBuildRetries")
	assert.Equal(t, 3*time.Minute, pc.RebuildThreshold, "tunnel.replace_before_expiration must reach RebuildThreshold")
	assert.Equal(t, 45*time.Second, pc.MaintenanceInterval, "tunnel.maintenance_interval must reach MaintenanceInterval")

	// Lifetime is mapped with the same headroom DefaultPoolConfig uses, so the
	// pool's internal replacement age stays above the wire expiry.
	headroom := poolTunnelLifetime - defaultParticipantLifetime
	assert.Equal(t, 20*time.Minute+headroom, pc.TunnelLifetime,
		"tunnel.lifetime must reach TunnelLifetime with the built-in headroom preserved")
}

// TestPoolConfigFromTunnelDefaults_ZeroFallsBackToDefaults proves a partially
// populated config never disables a bound: every zero-valued field falls back to
// the built-in pool default rather than to 0.
func TestPoolConfigFromTunnelDefaults_ZeroFallsBackToDefaults(t *testing.T) {
	pc := PoolConfigFromTunnelDefaults(config.TunnelDefaults{})
	def := DefaultPoolConfig()

	assert.Equal(t, def.MinTunnels, pc.MinTunnels)
	assert.Equal(t, def.MaxTunnels, pc.MaxTunnels)
	assert.Equal(t, def.HopCount, pc.HopCount)
	assert.Equal(t, def.TunnelLifetime, pc.TunnelLifetime)
	assert.Equal(t, def.RebuildThreshold, pc.RebuildThreshold)
	assert.Equal(t, def.MaxBuildRetries, pc.MaxBuildRetries)
	assert.Equal(t, def.MaintenanceInterval, pc.MaintenanceInterval)
}

// TestPoolConfigFromTunnelDefaults_DefaultsMatchBuiltInHeadroom pins that the
// operator default lifetime (config.Defaults().Tunnel.TunnelLifetime) maps to the
// exact poolTunnelLifetime DefaultPoolConfig uses, so wiring the config through
// does not change behavior for a default-configured router.
func TestPoolConfigFromTunnelDefaults_DefaultsMatchBuiltInHeadroom(t *testing.T) {
	pc := PoolConfigFromTunnelDefaults(config.Defaults().Tunnel)
	assert.Equal(t, poolTunnelLifetime, pc.TunnelLifetime,
		"default config lifetime must map to poolTunnelLifetime (no behavior change)")
}
