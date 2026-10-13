// Tests for the client-session tunnel readiness gate.
//
// checkTunnelReadiness is the predicate that monitorTunnelsAndRequestLeaseSet
// polls once per second for up to two minutes. It is the exact code path that
// produced issue #55's "timeout_waiting_for_tunnels" symptom: while it returns
// false, the session never receives RequestVariableLeaseSet (type 37), never
// publishes a LeaseSet, and the destination does not exist to the network.
//
// The gate requires BOTH directions to have at least one active tunnel. These
// tests pin that requirement in both directions, including the asymmetric cases
// that are easy to get wrong.

package i2cp

import (
	"testing"

	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newReadyPool(baseID int, gatewayPrefix string, count int) *tunnel.Pool {
	pool := tunnel.NewTunnelPool(&mockPeerSelector{})
	addTestTunnelsToPool(pool, baseID, gatewayPrefix, count)
	return pool
}

func TestCheckTunnelReadiness_BothDirectionsReady(t *testing.T) {
	session := newBaseTestSession()
	session.SetInboundPool(newReadyPool(100, "in", 1))
	session.SetOutboundPool(newReadyPool(200, "out", 1))
	defer session.InboundPool().Stop()
	defer session.OutboundPool().Stop()

	result, ready := checkTunnelReadiness(session)

	require.True(t, ready, "one active tunnel in each direction must satisfy the gate")
	assert.Len(t, result.inboundTunnels, 1)
	assert.Len(t, result.outboundTunnels, 1)
}

// TestCheckTunnelReadiness_NilPoolsIsNotReady covers the state immediately after
// SESSION CREATE, before initializeSessionTunnelPools has wired anything. The
// monitor must keep waiting rather than sending a type 37 with no leases.
func TestCheckTunnelReadiness_NilPoolsIsNotReady(t *testing.T) {
	session := newBaseTestSession()

	result, ready := checkTunnelReadiness(session)

	assert.False(t, ready, "uninitialised pools must not report ready")
	assert.Empty(t, result.inboundTunnels)
	assert.Empty(t, result.outboundTunnels)
}

func TestCheckTunnelReadiness_EmptyPoolsIsNotReady(t *testing.T) {
	session := newBaseTestSession()
	session.SetInboundPool(tunnel.NewTunnelPool(&mockPeerSelector{}))
	session.SetOutboundPool(tunnel.NewTunnelPool(&mockPeerSelector{}))
	defer session.InboundPool().Stop()
	defer session.OutboundPool().Stop()

	_, ready := checkTunnelReadiness(session)

	assert.False(t, ready, "pools with zero active tunnels must not report ready")
}

// TestCheckTunnelReadiness_InboundOnlyIsNotReady is the asymmetric case that
// matters most for #55: inbound tunnels can succeed while every outbound build
// fails. Reporting ready here would publish a LeaseSet the client cannot use to
// send anything.
func TestCheckTunnelReadiness_InboundOnlyIsNotReady(t *testing.T) {
	session := newBaseTestSession()
	session.SetInboundPool(newReadyPool(100, "in", 3))
	session.SetOutboundPool(tunnel.NewTunnelPool(&mockPeerSelector{}))
	defer session.InboundPool().Stop()
	defer session.OutboundPool().Stop()

	_, ready := checkTunnelReadiness(session)

	assert.False(t, ready, "outbound tunnels are required; inbound alone must not pass the gate")
}

func TestCheckTunnelReadiness_OutboundOnlyIsNotReady(t *testing.T) {
	session := newBaseTestSession()
	session.SetInboundPool(tunnel.NewTunnelPool(&mockPeerSelector{}))
	session.SetOutboundPool(newReadyPool(200, "out", 3))
	defer session.InboundPool().Stop()
	defer session.OutboundPool().Stop()

	_, ready := checkTunnelReadiness(session)

	assert.False(t, ready, "inbound tunnels are required; outbound alone must not pass the gate")
}

// TestCheckTunnelReadiness_TransitionsToReadyOnceOutboundLands models the real
// convergence sequence: the pool starts empty, the first successful outbound
// build flips the gate. This is the state change that issue #55 reported as
// never happening.
func TestCheckTunnelReadiness_TransitionsToReadyOnceOutboundLands(t *testing.T) {
	session := newBaseTestSession()
	session.SetInboundPool(newReadyPool(100, "in", 1))
	outbound := tunnel.NewTunnelPool(&mockPeerSelector{})
	session.SetOutboundPool(outbound)
	defer session.InboundPool().Stop()
	defer outbound.Stop()

	_, ready := checkTunnelReadiness(session)
	require.False(t, ready, "not ready while outbound is still building")

	addTestTunnelsToPool(outbound, 200, "out", 1)

	result, ready := checkTunnelReadiness(session)
	assert.True(t, ready, "adding the first active outbound tunnel must flip the gate")
	assert.Len(t, result.outboundTunnels, 1)
}
