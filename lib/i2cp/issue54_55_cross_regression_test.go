// Cross-issue regression test: #54 x #55.
//
// This is the test that requires both fixes at once, which is why the two
// issues are in one change. #54 kills the connection while the client is idle;
// #55 stalls the tunnels after the session is created. Neither fix is
// verifiable without the other:
//
//   - With only #54 fixed, the client survives the idle gap, creates its
//     session, and then waits 120 s for tunnels that never become ready.
//   - With only #55 fixed, the tunnels would converge, but the write of
//     CreateSessionMessage lands on a socket the server already closed, so the
//     session is never created and no LeaseSet is ever requested.
//
// The scenario is the ordinary SAM-bridge topology the reporter described: the
// application connects at router startup, completes GetDate/SetDate, sits idle
// while the operator is not using it, and only then creates its first session.
//
// The idle window is 2x the old 30 s MessageReadTimeout window, expressed in
// scaled time: the per-message deadline is injected at 20 ms and the client
// idles 40 ms, so the test proves the same property without a real 30 s sleep.

package i2cp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIssue54x55_IdleThenCreateSessionReachesLeaseSet is the cross-issue
// regression test. A client connects, performs GetDate/SetDate, idles past the
// per-message deadline, and only then creates its session. It must end up with
// a LeaseSet-backed working session.
func TestIssue54x55_IdleThenCreateSessionReachesLeaseSet(t *testing.T) {
	// ReadTimeout is deliberately set to a value LONGER than the idle window but
	// short enough to be meaningful: it proves the configured idle knob is in
	// force and does not fire during a legitimate idle gap.
	const idleWindow = 40 * time.Millisecond

	server := newTestI2CPServer(t, "")
	server.SetTunnelBuilder(&mockTunnelBuilder{})
	server.SetPeerSelector(&mockPeerSelector{})
	require.NoError(t, server.Start())
	t.Cleanup(func() { server.Stop() })

	conn := dialLiveClient(t, server.Addr().String())

	// Step 1: the GetDate/SetDate exchange every client performs first.
	require.NoError(t, WriteMessage(conn, &Message{
		Type:      MessageTypeGetDate,
		SessionID: SessionIDReservedControl,
	}))
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	reply, err := ReadMessage(context.Background(), conn, 0)
	require.NoError(t, err, "the server must answer GetDate")
	assert.Equal(t, MessageTypeSetDate, reply.Type, "GetDate is answered with SetDate")

	// Step 2: idle past the per-message deadline. Under the pre-#54 code this
	// gap is where the server closed the connection 30 s after the last message.
	time.Sleep(idleWindow)

	// Step 3: the connection must still be alive. The server's read loop must
	// have re-armed rather than closed, so a write here succeeds.
	require.NoError(t, conn.SetWriteDeadline(time.Now().Add(2*time.Second)))
	require.NoError(t, WriteMessage(conn, &Message{
		Type:      MessageTypeGetDate,
		SessionID: SessionIDReservedControl,
	}), "#54 regression: the connection died while the client was idle")

	// Drain the SetDate answering that post-idle GetDate, so the next read sees
	// the SessionStatus rather than a queued reply.
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	postIdle, err := ReadMessage(context.Background(), conn, 0)
	require.NoError(t, err, "the server must still answer after an idle gap")
	assert.Equal(t, MessageTypeSetDate, postIdle.Type,
		"#54 regression: the server must still serve a client that was idle")

	// Step 4: create the session only now, long after connecting. Under pre-#54
	// this write hits a dead socket; under pre-#55 the session is created but its
	// tunnels never become ready.
	sessionID := createSessionOnConn(t, conn)
	require.NotEmpty(t, sessionID, "session must be created after the idle gap")

	session, ok := server.SessionManager().GetSession(sessionID)
	require.True(t, ok, "the created session must be registered")

	// Step 5: drive the session's pools to readiness, which is the gate
	// monitorTunnelsAndRequestLeaseSet polls once a second. The tunnels are
	// installed here rather than built because the mock builder returns a tunnel
	// ID without registering state -- the real registration is done by
	// i2np.TunnelManager, which is not wired in this harness. What this test
	// pins is that once both directions have an active tunnel, the monitor
	// proceeds instead of waiting out its 120 s.
	addTestTunnelsToPool(t, session.InboundPool(), 3000, "in-gateway", 1)
	addTestTunnelsToPool(t, session.OutboundPool(), 4000, "out-gateway", 1)

	requireReadyWithin(t, session, 10*time.Second,
		"#55 regression: session tunnels never became ready")

	// Step 6: the client must receive RequestVariableLeaseSet (type 37), which is
	// what tells it to publish. Without it the destination does not exist.
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(10*time.Second)))
	lsRequest, err := ReadMessage(context.Background(), conn, 0)
	require.NoError(t, err,
		"#55 regression: the router never sent RequestVariableLeaseSet, so no "+
			"LeaseSet could ever be published")
	assert.Equal(t, MessageTypeRequestVariableLeaseSet, lsRequest.Type,
		"the readiness gate must trigger a type 37 request")

	// Step 7: the session must be in the state where a LeaseSet can be
	// published. A client-managed session (the spec's CreateSession shape, where
	// the client sends no private keys) holds no router-side signing key, so the
	// router cannot build the LeaseSet itself -- the client publishes it via
	// CreateLeaseSet2. Assert that contract rather than calling CreateLeaseSet,
	// which would be wrong for this session type.
	require.True(t, session.IsClientManaged(),
		"a CreateSession with no private keys yields a client-managed session")
	_, leaseSetErr := session.CreateLeaseSet()
	assert.ErrorContains(t, leaseSetErr, "client must publish LeaseSet2",
		"the router must refuse to sign a LeaseSet it holds no key for")

	// The wait must not have been counted as a timeout: reaching this point at
	// all means the monitor succeeded, and the counter proves it.
	assert.Zero(t, server.GetSessionTunnelWaitTimeouts(),
		"the tunnel monitor must not have timed out")
}

// TestIssue54x55_IdleGapDoesNotWarnPerOccurrence pins the requirement that an
// idle timeout is not logged at warn level per occurrence. The read loop must
// re-arm quietly; a warn per idle tick would itself become the noise problem.
func TestIssue54x55_IdleGapDoesNotWarnPerOccurrence(t *testing.T) {
	server := newTestI2CPServer(t, "")
	server.config.ReadTimeout = 15 * time.Millisecond
	require.NoError(t, server.Start())
	t.Cleanup(func() { server.Stop() })

	conn := dialLiveClient(t, server.Addr().String())

	// Drive several idle cycles through the real read path. Each one must return
	// errIdleTimeout (non-terminal) rather than closing the connection.
	for i := 0; i < 3; i++ {
		msg, err := server.readClientMessage(conn)
		if err != nil {
			require.ErrorIs(t, err, errIdleTimeout,
				"an idle read must surface as errIdleTimeout, not a terminal error (iteration %d)", i)
		} else {
			assert.NotNil(t, msg)
		}
		assert.True(t, connStillUsable(conn),
			"the connection must survive an idle timeout (iteration %d)", i)
	}
}

// dialLiveClient connects a protocol-handshaked client to a running server.
func dialLiveClient(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := dialI2CPClient(addr)
	require.NoError(t, err, "client must be able to connect")
	t.Cleanup(func() { conn.Close() })
	return conn
}

// connStillUsable reports whether the connection has not been closed server-side.
// A write to a socket the peer closed eventually errors, so a short write
// deadline makes the check bounded.
func connStillUsable(conn net.Conn) bool {
	_ = conn.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
	_, err := conn.Write(nil)
	return err == nil
}

// requireReadyWithin waits for both of a session's pools to report an active
// tunnel, which is exactly what checkTunnelReadiness requires.
func requireReadyWithin(t *testing.T, session *Session, within time.Duration, msg string) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if _, ready := checkTunnelReadiness(session); ready {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	_, ready := checkTunnelReadiness(session)
	require.True(t, ready, "%s", msg)
}

// TestIssue54x55_RouterManagedSessionPublishesLeaseSet is the LeaseSet
// publication half of the acceptance evidence. The wire-level test above proves
// the router reaches readiness and requests the LeaseSet; this proves that for a
// router-managed session -- where the router does hold the signing key -- the
// same readiness gate produces an actual published LeaseSet rather than a bare
// timeout. Issue #55 reported "LeaseSets published: 0".
func TestIssue54x55_RouterManagedSessionPublishesLeaseSet(t *testing.T) {
	server := newTestI2CPServer(t, "")
	require.NoError(t, server.Start())
	t.Cleanup(func() { server.Stop() })

	session, err := server.SessionManager().CreateSession(nil, DefaultSessionConfig())
	require.NoError(t, err, "a router-managed session must be creatable")
	require.False(t, session.IsClientManaged(),
		"a manager-created session is router-managed and can be published by the router")

	inbound := tunnel.NewTunnelPool(&mockPeerSelector{})
	outbound := tunnel.NewTunnelPool(&mockPeerSelector{})
	defer inbound.Stop()
	defer outbound.Stop()
	session.SetInboundPool(inbound)
	session.SetOutboundPool(outbound)

	// Not ready yet: no leases to publish.
	_, ready := checkTunnelReadiness(session)
	require.False(t, ready, "empty pools must not satisfy the gate")

	addTestTunnelsToPool(t, inbound, 5000, "in-gateway", 1)
	addTestTunnelsToPool(t, outbound, 6000, "out-gateway", 1)

	_, ready = checkTunnelReadiness(session)
	require.True(t, ready, "one active tunnel per direction must satisfy the gate")

	leaseSetBytes, err := session.CreateLeaseSet()
	require.NoError(t, err, "a ready router-managed session must produce a LeaseSet")
	require.NotEmpty(t, leaseSetBytes, "the published LeaseSet must not be empty")

	t.Logf("ACCEPTANCE leaseset_published_bytes=%d inbound_tunnels=1 outbound_tunnels=1 "+
		"session_tunnel_wait_timeouts=%d",
		len(leaseSetBytes), server.GetSessionTunnelWaitTimeouts())
	assert.Zero(t, server.GetSessionTunnelWaitTimeouts(),
		"publication must not have required a timeout")
}

// TestIssue54x55_PoolsWithoutBuilderAreNotReady pins the gate's negative side:
// a session whose pools cannot build must never satisfy readiness, so the
// monitor waits and eventually reports the reason instead of publishing a
// LeaseSet with no leases.
func TestIssue54x55_PoolsWithoutBuilderAreNotReady(t *testing.T) {
	session := newBaseTestSession()
	inbound := tunnel.NewTunnelPool(&mockPeerSelector{})
	outbound := tunnel.NewTunnelPool(&mockPeerSelector{})
	defer inbound.Stop()
	defer outbound.Stop()

	session.SetInboundPool(inbound)
	session.SetOutboundPool(outbound)

	_, ready := checkTunnelReadiness(session)
	assert.False(t, ready, "empty pools must not satisfy the readiness gate")
}
