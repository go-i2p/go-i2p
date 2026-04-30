package tunnel

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStartupGate_OutboundBlockedUntilGate verifies that an outbound pool's
// maintenanceLoop does not call its tunnel builder before the startup gate is
// closed. This directly tests the BUG-1 fix in maintenanceLoop.
func TestStartupGate_OutboundBlockedUntilGate(t *testing.T) {
	cfg := DefaultPoolConfig()
	cfg.IsInbound = false
	cfg.HopCount = 1

	builder := &MockTunnelBuilder{
		completionChan: make(chan struct{}, 4),
	}
	gate := make(chan struct{})

	pool := NewTunnelPoolWithConfig(&MockPeerSelector{}, cfg)
	defer pool.Stop()
	pool.SetTunnelBuilder(builder)
	pool.SetStartupGate(gate)

	require.NoError(t, pool.StartMaintenance())

	// Give the goroutine a moment to start and block on the gate.
	time.Sleep(100 * time.Millisecond)

	assert.Equal(t, 0, builder.GetBuildCount(),
		"outbound pool must not dispatch builds before startup gate is closed")

	// Close the gate; allow maintenance to proceed.
	close(gate)

	// Wait for builder to be invoked (or timeout).
	select {
	case <-builder.completionChan:
		// Build was dispatched after gate opened — expected.
	case <-time.After(3 * time.Second):
		t.Log("no build dispatched after gate open (acceptable: no peers available)")
	}
}

// TestRunMaintenanceNow_ZeroHopInboundBuilt verifies that after
// TriggerAutoFallbackCheck switches an inbound pool to 0-hop, a subsequent
// RunMaintenanceNow call invokes the builder (i.e., maintenance actually fires).
// The underlying BuilderInterface is responsible for registering the tunnel;
// we verify the builder was called.
func TestRunMaintenanceNow_ZeroHopInboundBuilt(t *testing.T) {
	cfg := DefaultPoolConfig()
	cfg.IsInbound = true
	cfg.HopCount = 3

	noAddr := func() bool { return true }

	pool := NewTunnelPoolWithConfig(&emptyPeerSelector{}, cfg)
	defer pool.Stop()
	pool.SetAutoFallbackCheck(noAddr)

	builder := &MockTunnelBuilder{
		completionChan: make(chan struct{}, 4),
		callbackPool:   pool, // builder adds tunnel to pool on success
	}
	pool.SetTunnelBuilder(builder)

	pool.TriggerAutoFallbackCheck()
	assert.Equal(t, 0, pool.HopCount(), "pool must be in 0-hop mode after fallback")

	pool.RunMaintenanceNow() // synchronous call to maintainPool

	// Drain async goroutine if launched.
	select {
	case <-builder.completionChan:
	case <-time.After(2 * time.Second):
	}

	assert.GreaterOrEqual(t, builder.GetBuildCount(), 1,
		"builder must be invoked at least once via RunMaintenanceNow")
	assert.NotEmpty(t, pool.GetActiveTunnels(),
		"pool must have at least one active tunnel after builder adds it")
}

// TestStartupGate_FallbackEnforcedBeforeRelease verifies the full timeout flow:
// trigger fallback + run maintenance on inbound, then close the gate only after
// the builder has produced an active tunnel. Outbound must not see an empty inbound pool.
func TestStartupGate_FallbackEnforcedBeforeRelease(t *testing.T) {
	inboundCfg := DefaultPoolConfig()
	inboundCfg.IsInbound = true
	inboundCfg.HopCount = 3
	noAddr := func() bool { return true }

	inbound := NewTunnelPoolWithConfig(&emptyPeerSelector{}, inboundCfg)
	defer inbound.Stop()
	inbound.SetAutoFallbackCheck(noAddr)

	inboundBuilder := &MockTunnelBuilder{
		completionChan: make(chan struct{}, 4),
		callbackPool:   inbound,
	}
	inbound.SetTunnelBuilder(inboundBuilder)

	gate := make(chan struct{})

	outboundCfg := DefaultPoolConfig()
	outboundCfg.IsInbound = false
	outboundCfg.HopCount = 1
	outboundBuilder := &MockTunnelBuilder{completionChan: make(chan struct{}, 4)}
	outbound := NewTunnelPoolWithConfig(&MockPeerSelector{}, outboundCfg)
	defer outbound.Stop()
	outbound.SetTunnelBuilder(outboundBuilder)
	outbound.SetStartupGate(gate)

	require.NoError(t, outbound.StartMaintenance())

	// Simulate the watcher goroutine timeout handler.
	inbound.TriggerAutoFallbackCheck()
	inbound.RunMaintenanceNow()

	// Drain async build goroutine.
	select {
	case <-inboundBuilder.completionChan:
	case <-time.After(2 * time.Second):
	}

	// Verify inbound has a tunnel before releasing the gate.
	activeBefore := inbound.GetActiveTunnels()
	assert.NotEmpty(t, activeBefore, "inbound must have active tunnel before gate release")

	close(gate) // release outbound after pre-condition is met
}
