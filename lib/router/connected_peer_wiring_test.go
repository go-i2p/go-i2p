// Startup wiring guard for tunnel-build convergence.
//
// Tunnel peer selection biases toward peers with an established transport
// session, which is what lets client tunnel pools converge instead of
// repeatedly committing builds to peers that cannot be dialled (issue #55).
//
// The bias is installed by a single call in initializeNetDBAndTransports:
//
//	r.netdb.SetConnectedPeerProvider(r.connectedPeerHashes)
//
// Both SetConnectedPeerProvider and its consumer are deliberately nil-tolerant,
// so deleting or reordering that call would NOT fail any build or any other
// test — the router would silently revert to the pre-fix behaviour and tunnels
// would stop becoming ready. These tests assert the wiring is present after
// construction so that regression becomes a test failure instead of a live
// network outage.

package router

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCreateRouter_WiresConnectedPeerProvider is the regression guard: a
// constructed router must have installed the connected-peer provider on its
// NetDB.
func TestCreateRouter_WiresConnectedPeerProvider(t *testing.T) {
	// The provider is installed by initializeNetDBAndTransports, which runs
	// inside CreateRouter, so construction alone is enough to assert the wiring;
	// starting the router would only add bootstrap latency to the suite.
	cfg := createTestRouterConfig(t.TempDir())
	router, err := CreateRouter(cfg)
	require.NoError(t, err, "CreateRouter should succeed for a valid config")
	t.Cleanup(func() { router.Stop() })

	db := router.GetNetDB()
	require.NotNil(t, db, "NetDB should be initialised by CreateRouter")
	assert.True(t, db.HasConnectedPeerProvider(),
		"connected-peer provider must be wired at startup; without it tunnel "+
			"builds never converge (issue #55)")
}

// TestConnectedPeerHashes_EmptyRouterReturnsNil pins the provider's contract at
// startup: with no sessions yet it reports nothing connected, which makes
// SelectPeers fall back to reachability heuristics rather than selecting from an
// empty set. Cold start must degrade, not fail.
func TestConnectedPeerHashes_EmptyRouterReturnsNil(t *testing.T) {
	// connectedPeerHashes only reads session state, so a bare Router is enough;
	// standing up a real router here would only slow the suite down.
	router := &Router{}

	assert.Nil(t, router.connectedPeerHashes(),
		"a router with no active sessions should report no connected peers")
}

// TestConnectedPeerHashes_ReflectsActiveSessions verifies the provider actually
// reads live session state, so the bias follows connections as they come and go
// instead of being computed once at startup.
func TestConnectedPeerHashes_ReflectsActiveSessions(t *testing.T) {
	// Only session state is read, so a bare Router with a seeded session map is
	// enough to pin the provider's behaviour without a full startup.
	router := &Router{activeSessions: make(map[common.Hash]transport.TransportSession)}

	var peer common.Hash
	peer[0] = 0x5A
	router.sessionMutex.Lock()
	router.activeSessions[peer] = nil
	router.sessionMutex.Unlock()
	defer func() {
		router.sessionMutex.Lock()
		delete(router.activeSessions, peer)
		router.sessionMutex.Unlock()
	}()

	hashes := router.connectedPeerHashes()
	require.NotNil(t, hashes, "provider should report the connected peer")
	assert.Contains(t, hashes, peer)
}
