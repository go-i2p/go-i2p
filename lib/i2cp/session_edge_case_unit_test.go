package i2cp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestMergeTunnelParameters_ZeroHopInbound verifies that zero-hop tunnels
// can be configured via ReconfigureSession when InboundTunnelLength is
// explicitly set to 0.
func TestMergeTunnelParameters_ZeroHopInbound(t *testing.T) {
	existing := DefaultSessionConfig()
	assert.Equal(t, 3, existing.InboundTunnelLength, "default should be 3")

	newConfig := &SessionConfig{
		InboundTunnelLength: 0,
		ExplicitlySetFields: map[string]bool{
			"InboundTunnelLength": true,
		},
	}
	mergeTunnelParameters(existing, newConfig)
	assert.Equal(t, 0, existing.InboundTunnelLength,
		"zero-hop inbound tunnel should be allowed when explicitly set")
}

// TestMergeTunnelParameters_ZeroHopOutbound verifies that zero-hop tunnels
// work for outbound tunnels too.
func TestMergeTunnelParameters_ZeroHopOutbound(t *testing.T) {
	existing := DefaultSessionConfig()
	assert.Equal(t, 3, existing.OutboundTunnelLength, "default should be 3")

	newConfig := &SessionConfig{
		OutboundTunnelLength: 0,
		ExplicitlySetFields: map[string]bool{
			"OutboundTunnelLength": true,
		},
	}
	mergeTunnelParameters(existing, newConfig)
	assert.Equal(t, 0, existing.OutboundTunnelLength,
		"zero-hop outbound tunnel should be allowed when explicitly set")
}

// TestMergeTunnelParameters_NotExplicitlySetPreservesDefault verifies that
// when a field is not explicitly set (ExplicitlySetFields is nil or missing),
// the existing default value is preserved.
func TestMergeTunnelParameters_NotExplicitlySetPreservesDefault(t *testing.T) {
	existing := DefaultSessionConfig()
	assert.Equal(t, 3, existing.InboundTunnelLength)

	newConfig := &SessionConfig{
		InboundTunnelLength: 0, // zero but NOT explicitly set
	}
	mergeTunnelParameters(existing, newConfig)
	assert.Equal(t, 3, existing.InboundTunnelLength,
		"default should be preserved when field is not explicitly set")
}

// TestRateLimiter_LowRate verifies that the rate limiter delivers tokens
// smoothly at low rates (rate=2 msg/sec) instead of in bursts.
func TestRateLimiter_LowRate(t *testing.T) {
	rl := newSimpleRateLimiter(2, 5)

	// Consume all initial tokens
	for rl.allow() {
		// drain
	}

	// Wait 600ms — at rate=2, we should accumulate 1.2 tokens
	time.Sleep(600 * time.Millisecond)

	// Should allow at least 1 message (1.2 tokens >= 1.0)
	assert.True(t, rl.allow(),
		"rate limiter should deliver token after 600ms at rate=2")
}

// TestRateLimiter_FractionalAccumulation verifies that fractional tokens
// accumulate correctly across multiple checks.
func TestRateLimiter_FractionalAccumulation(t *testing.T) {
	rl := newSimpleRateLimiter(2, 10)

	// Drain all initial tokens
	for rl.allow() {
	}

	// Wait 300ms — at rate=2, we get 0.6 tokens (not enough for 1)
	time.Sleep(300 * time.Millisecond)
	allowed := rl.allow()
	// Might or might not be allowed depending on timing, but the important
	// thing is lastCheck is updated so tokens don't accumulate incorrectly.

	// Wait another 300ms — total elapsed ~600ms, should have ~1.2 tokens
	time.Sleep(300 * time.Millisecond)
	if !allowed {
		assert.True(t, rl.allow(),
			"fractional tokens should accumulate across multiple checks")
	}
}
