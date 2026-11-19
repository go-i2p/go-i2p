// Regression test for Issue 7: the NTCP2 outbound reuse race must release a
// reserved session slot exactly once. When an outbound dial completes but the
// peer already has a session/acceptedConn, setupSession closes the redundant
// session and releases the reservation itself, then returns nil. finalizeOutboundSession
// must NOT release the slot a second time on that nil path — the double-decrement
// that drove sessionCount negative (the "would go negative" CRITICAL log).
//
// The DecrementCountSafe force-reset masks a negative count at 0, so this test
// keeps a separate live session in the map: the stray second decrement would
// wrongly drop that session's count, which the fixed code preserves.
package ntcp2

import (
	"testing"
	"time"

	gontcp2 "github.com/go-i2p/go-noise/ntcp2"
	transportpkg "github.com/go-i2p/go-i2p/lib/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFinalizeOutboundSession_ReuseRaceReleasesSlotOnce drives the exact race:
// a live session for the peer already occupies the map (here an acceptedConn
// marker owned by Accept), an outbound dial reserves a slot, and setupSession
// must release that reservation exactly once when it abandons the redundant
// dial. A second live session pins the count above zero so a stray extra
// decrement is observable rather than hidden by the force-reset safety net.
func TestFinalizeOutboundSession_ReuseRaceReleasesSlotOnce(t *testing.T) {
	transport := newNilListenerTestTransport(t, 100)
	peerHash := newTestPeerHash("issue7-outbound-reuse-race")

	// A separate live session that legitimately holds a slot. Reserve its slot
	// first (registerTestSession mirrors setupSession, which assumes the slot is
	// already reserved), then register it. Its count keeps the counter above zero
	// during the race, so a double-decrement surfaces instead of being hidden by
	// the force-reset safety net.
	require.NoError(t, transport.checkSessionLimit(), "reserve live session slot")
	liveConn := newMockSetupConn() // Read blocks until Close, so the session stays live
	liveSession := registerTestSession(t, transport, liveConn, newTestPeerHash("issue7-live-peer"))
	_ = liveSession
	require.Equal(t, int32(1), transport.GetSessionCount(), "one live session counted")

	// The peer we will dial already has an acceptedConn owned by Accept. Store
	// the marker without counting it (Accept owns that reservation).
	transport.sessionRegistry.Store(peerHash, &transportpkg.AcceptedConn{Value: newAcceptMockConn("10.0.0.1:7002")})

	// Reserve a slot for the outbound dial (mimics createOutboundSession).
	require.NoError(t, transport.checkSessionLimit(), "reserve outbound slot")
	require.Equal(t, int32(2), transport.GetSessionCount(), "live session + reserved outbound slot")

	// Drive the race through finalizeOutboundSession with a real data-phase conn.
	ic, _ := wireHandshakePair(t)
	t.Cleanup(func() { _ = ic.Close() })

	_, err := transport.finalizeOutboundSession(ic, peerHash, peerHash.Bytes(), time.Now())
	require.Error(t, err, "redundant outbound dial against an acceptedConn is abandoned")

	// Exactly one net release for the reservation: the live session's slot must
	// survive. Before the fix, finalizeOutboundSession double-decremented and
	// the count would have dropped to 0 (or tripped the negative guard).
	assert.Equal(t, int32(1), transport.GetSessionCount(),
		"outbound reuse race must release the reserved slot exactly once, preserving the live session's count")
}

// TestSetupSession_ReuseRaceReportsSlotReleased asserts setupSession's contract
// directly: on every nil return it reports that it already released the
// reservation, so the caller never releases it twice.
func TestSetupSession_ReuseRaceReportsSlotReleased(t *testing.T) {
	transport := newNilListenerTestTransport(t, 100)
	peerHash := newTestPeerHash("issue7-setupslot-released")

	// Peer already has an acceptedConn; reserve a slot for the outbound dial.
	transport.sessionRegistry.Store(peerHash, &transportpkg.AcceptedConn{Value: newAcceptMockConn("10.0.0.1:7003")})
	require.NoError(t, transport.checkSessionLimit())
	require.Equal(t, int32(1), transport.GetSessionCount())

	ic, _ := wireHandshakePair(t)
	t.Cleanup(func() { _ = ic.Close() })

	session, slotReleased := transport.setupSession(ic, peerHash)
	assert.Nil(t, session, "redundant dial against an acceptedConn returns no session")
	assert.True(t, slotReleased, "setupSession must report it already released the reservation")

	// setupSession released the single reservation; count is back to 0.
	assert.Equal(t, int32(0), transport.GetSessionCount(),
		"setupSession releases the reserved slot exactly once on the reuse path")
}

// compile-time guard: the test relies on the real go-noise conn type.
var _ = func(*gontcp2.Conn) {}
