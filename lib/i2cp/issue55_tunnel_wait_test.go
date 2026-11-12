// Issue #55, I2CP side: the tunnel-wait failure path must carry a reason, and
// the session tunnel-wait counter must exist.
//
// The reporter spent 290 MB of debug log on this because
// monitorTunnelsAndRequestLeaseSet gave up after 120 s with a bare
// "timeout_waiting_for_tunnels" and nothing else. These tests pin the reason
// fields and the counter that replace it.

package i2cp

import (
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIssue55_TunnelWaitReasonDistinguishesFailureModes pins the pure reason
// selector. Each branch points at a different fix, which is the whole value of
// reporting it.
//
// Pre-fix this fails to compile: tunnelWaitReason did not exist.
func TestIssue55_TunnelWaitReasonDistinguishesFailureModes(t *testing.T) {
	cases := []struct {
		name      string
		attempted uint64
		noDial    uint64
		refused   uint64
		want      string
	}{
		{"pools never built anything", 0, 0, 0, "no_builds_attempted_pools_idle"},
		{"every build failed to reach a gateway", 29, 29, 0, "every_build_failed_to_reach_a_gateway_reachability"},
		{"builds reached gateways and were refused", 8, 0, 8, "builds_reached_gateways_and_were_refused_peer_selection"},
		{"mixed", 10, 6, 4, "mixed_gateway_unreachable_and_refused"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tunnelWaitReason(tc.attempted, tc.noDial, tc.refused)
			assert.Equal(t, tc.want, got,
				"attempted=%d noDial=%d refused=%d", tc.attempted, tc.noDial, tc.refused)
		})
	}

	// The two dominant diagnoses must differ: collapsing them is what made the
	// issue undiagnosable.
	assert.NotEqual(t,
		tunnelWaitReason(29, 29, 0),
		tunnelWaitReason(8, 0, 8),
		"reachability failure and refusal failure must report different reasons")
}

// TestIssue55_ShortTunnelDirectionNamesTheMissingPool pins which direction came
// up short, so the log says where to look.
func TestIssue55_ShortTunnelDirectionNamesTheMissingPool(t *testing.T) {
	assert.Equal(t, "both", shortTunnelDirection(0, 0))
	assert.Equal(t, "inbound", shortTunnelDirection(0, 3))
	assert.Equal(t, "outbound", shortTunnelDirection(3, 0))
	assert.Equal(t, "none", shortTunnelDirection(2, 2))
}

// TestIssue55_RecordTunnelWaitTimeoutIncrementsCounter pins the
// i2cp.session.tunnel_wait_timeout counter requirement: every abandoned wait is
// counted, and the count is readable without debug logging.
//
// Pre-fix this fails to compile: neither the counter nor its accessor existed.
func TestIssue55_RecordTunnelWaitTimeoutIncrementsCounter(t *testing.T) {
	server := newTestI2CPServer(t, "")
	session := newBaseTestSession()

	assert.Zero(t, server.GetSessionTunnelWaitTimeouts(), "a fresh server has timed out nothing")

	// Pools never initialised: the first reason branch.
	server.recordTunnelWaitTimeout(session, 1)
	assert.Equal(t, uint64(1), server.GetSessionTunnelWaitTimeouts())

	// Pools present but empty: exercises the counter-heavy branch, which reads
	// each pool's build stats and failed-peer set.
	inbound := tunnel.NewTunnelPool(&mockPeerSelector{})
	outbound := tunnel.NewTunnelPool(&mockPeerSelector{})
	defer inbound.Stop()
	defer outbound.Stop()
	session.SetInboundPool(inbound)
	session.SetOutboundPool(outbound)

	server.recordTunnelWaitTimeout(session, 2)
	server.recordTunnelWaitTimeout(session, 3)

	assert.Equal(t, uint64(3), server.GetSessionTunnelWaitTimeouts(),
		"the counter must be monotonic across sessions")
}

// TestIssue55_MonitorReturnsReasonOnTimeout drives the real monitor to its
// timeout branch with pools that never become ready, and asserts the monitor
// stops rather than hanging, while the counter records the abandonment.
//
// The monitor's 2-minute wait is not shortened here (its deadline is a fixed
// constant), so this test asserts the counter and the non-hanging property; the
// reason fields themselves are pinned by the pure-function tests above.
func TestIssue55_MonitorReturnsReasonOnTimeout(t *testing.T) {
	server := newTestI2CPServer(t, "")
	require.NoError(t, server.Start())
	t.Cleanup(func() { server.Stop() })

	session := newBaseTestSession()
	inbound := tunnel.NewTunnelPool(&mockPeerSelector{})
	outbound := tunnel.NewTunnelPool(&mockPeerSelector{})
	session.SetInboundPool(inbound)
	session.SetOutboundPool(outbound)

	// A nil conn is safe here: readiness never becomes true, so the monitor
	// never reaches the write path.
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		server.waitForTunnelReadiness(session, nil, session.ID(), ticker, time.After(10*time.Millisecond))
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("monitor must return promptly once its timeout fires, not hang")
	}

	assert.Equal(t, uint64(1), server.GetSessionTunnelWaitTimeouts(),
		"a timed-out wait must be counted")
}
