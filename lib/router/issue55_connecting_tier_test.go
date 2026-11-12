// Issue #55 requirement 1, router side: the "session already connecting" tier
// must actually exist, and a dial failure must be distinguishable from a build
// refusal by the time it reaches the tunnel pool.
//
// Tier 2 was empty-by-construction before this: activeSessions receives a peer
// only after its handshake completes, so a peer being dialled right now was
// invisible to selection.

package router

import (
	"errors"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/transport"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func peerHash(seed byte) common.Hash {
	var h common.Hash
	for i := range h {
		h[i] = seed
	}
	return h
}

// TestIssue55_ConnectingTrackerIsWired asserts the tier-2 provider is installed
// during construction. Like the connected provider it is nil-tolerant, so a
// dropped wiring call would otherwise degrade silently -- the failure mode that
// made #55 hard to catch.
func TestIssue55_ConnectingTrackerIsWired(t *testing.T) {
	cfg := createTestRouterConfig(t.TempDir())
	router, err := CreateRouter(cfg)
	require.NoError(t, err, "CreateRouter should succeed for a valid config")
	t.Cleanup(func() { router.Stop() })

	db := router.GetNetDB()
	require.NotNil(t, db, "NetDB should be initialised by CreateRouter")
	assert.True(t, db.HasConnectingPeerProvider(),
		"the connecting-peer provider must be wired at startup; without it the "+
			"second reachability tier is empty by construction (issue #55)")
}

// TestIssue55_ConnectingTrackerTracksInFlightDials pins the tracker contract:
// mark claims a slot, snapshot reports it, release clears it.
func TestIssue55_ConnectingTrackerTracksInFlightDials(t *testing.T) {
	tracker := newConnectingTracker()

	assert.Nil(t, tracker.snapshot(), "a fresh tracker reports nothing connecting")

	peer := peerHash(0x11)
	require.True(t, tracker.mark(peer), "first mark must claim the slot")
	_, present := tracker.snapshot()[peer]
	assert.True(t, present, "a marked peer must appear in the snapshot")

	assert.False(t, tracker.mark(peer),
		"a second mark for a live attempt must not claim the slot again")

	tracker.release(peer)
	assert.Nil(t, tracker.snapshot(), "release must clear the entry")
}

// TestIssue55_ConnectingTrackerExpiresStaleEntries proves the set cannot grow
// without bound when a dial hangs: an entry past its TTL is dropped on read
// rather than pinned forever.
func TestIssue55_ConnectingTrackerExpiresStaleEntries(t *testing.T) {
	tracker := newConnectingTracker()
	peer := peerHash(0x22)

	tracker.mark(peer)
	// Force the entry into the past without waiting out the real TTL.
	tracker.mu.Lock()
	tracker.attempt[peer] = time.Now().Add(-time.Second)
	tracker.mu.Unlock()

	assert.Nil(t, tracker.snapshot(),
		"an expired entry must be dropped on read, not reported as connecting")

	tracker.mu.Lock()
	_, stillPresent := tracker.attempt[peer]
	tracker.mu.Unlock()
	assert.False(t, stillPresent, "the expired entry must be removed, not just hidden")

	// A stale entry must not block a fresh dial to the same peer.
	assert.True(t, tracker.mark(peer), "an expired attempt must not block a new one")
}

// TestIssue55_ConnectingTrackerIsBounded proves the cap holds: inserting past
// maxConnectingPeers evicts rather than growing, so a dial storm cannot leak.
func TestIssue55_ConnectingTrackerIsBounded(t *testing.T) {
	tracker := newConnectingTracker()

	for i := 0; i < maxConnectingPeers+64; i++ {
		var h common.Hash
		h[0] = byte(i)
		h[1] = byte(i >> 8)
		tracker.mark(h)
	}

	tracker.mu.Lock()
	size := len(tracker.attempt)
	tracker.mu.Unlock()

	assert.LessOrEqual(t, size, maxConnectingPeers,
		"the tracker must stay bounded regardless of dial fan-out; got %d", size)
}

// TestIssue55_ConnectingPeerHashesNilTrackerIsSafe pins the nil guard: a Router
// built without the tracker (bare struct in unit tests) must not panic when the
// provider is invoked.
func TestIssue55_ConnectingPeerHashesNilTrackerIsSafe(t *testing.T) {
	router := &Router{}
	assert.Nil(t, router.connectingPeerHashes(),
		"a router with no tracker must report nothing connecting, not panic")
}

// TestIssue55_DialFailureCarriesGatewaySentinel is the boundary test for
// requirement 2: when the muxer cannot dial, the error that reaches the tunnel
// pool must wrap tunnel.ErrGatewayUnreachable, so the pool classifies it with
// errors.Is instead of matching prose.
//
// This drives the real establishOutboundSession against a muxer with no
// transports, which is the cheapest way to get a genuine
// transport.ErrNoTransportAvailable out of the transport layer.
//
// Pre-fix this fails: establishOutboundSession wrapped the transport error with
// no sentinel, so errors.Is(err, tunnel.ErrGatewayUnreachable) was false and the
// failure was indistinguishable from a downstream refusal.
func TestIssue55_DialFailureCarriesGatewaySentinel(t *testing.T) {
	router := &Router{}
	// A muxer with zero transports cannot produce a session, so GetSession
	// returns the real ErrNoTransportAvailable rather than a stand-in.
	router.transports.Store(transport.Mux())

	ri := router_info.RouterInfo{}
	_, err := router.establishOutboundSession(peerHash(0x33), &ri)

	require.Error(t, err, "a muxer with no transports cannot establish a session")
	require.True(t, errors.Is(err, transport.ErrNoTransportAvailable),
		"the transport sentinel must survive the router's wrap, got %v", err)
	require.True(t, errors.Is(err, tunnel.ErrGatewayUnreachable),
		"the tunnel sentinel must be attached at the boundary so the pool can "+
			"classify with errors.Is, got %v", err)

	assert.True(t, tunnel.IsGatewayUnreachable(err),
		"the pool must classify this as a failure to reach the gateway")
	assert.False(t, tunnel.IsBuildRefused(err),
		"a dial failure is not a refusal and must not be treated as one")
}

// TestIssue55_MissingMuxerGetsNoGatewaySentinel checks the other side of the
// boundary: a failure that is not ErrNoTransportAvailable must not be relabelled
// as gateway-unreachability, or the distinction requirement 2 asks for would be
// meaningless.
func TestIssue55_MissingMuxerGetsNoGatewaySentinel(t *testing.T) {
	router := &Router{}
	// transports left nil: validateTransportMuxer fails before any dial.

	ri := router_info.RouterInfo{}
	_, err := router.establishOutboundSession(peerHash(0x44), &ri)

	require.Error(t, err, "a router with no muxer cannot establish a session")
	assert.False(t, errors.Is(err, transport.ErrNoTransportAvailable))
	assert.False(t, errors.Is(err, tunnel.ErrGatewayUnreachable),
		"only a transport-availability failure may carry the gateway sentinel")
}
