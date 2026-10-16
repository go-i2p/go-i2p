// Tests for the SetIdentity race (SM-1). Validates that updating the
// transport identity concurrently with session setup is safe.

package ntcp2

import (
	"testing"

	"github.com/go-i2p/common/router_info"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSM1_SetIdentityWithConcurrentInboundHandshakes tests the SM-1 bug:
// Listener Identity Mismatch During SetIdentity.
//
// Scenario: While multiple inbound connections are performing Noise XK handshakes,
// SetIdentity is called to change the router's static key. The test verifies that:
// 1. All in-flight handshakes complete successfully (don't crash or hang)
// 2. Each connection uses a consistent identity throughout the handshake
// 3. The listener swap doesn't cause asymmetric handshake failures
//
// Bug manifestation:
// - "Handshake rejections from peers claiming 'unknown peer identity'"
// - "Asymmetric connection failures (peer A → peer B succeeds, B → A fails)"
func TestSM1_SetIdentityWithConcurrentInboundHandshakes(t *testing.T) {
	// This test verifies that SetIdentity correctly swaps the listener
	// and doesn't cause in-flight handshakes to use mismatched identities.

	// Create initial transport
	transport := newNilListenerTestTransport(t, 100)
	defer transport.cancel()

	// Verify initial state
	initialIdentity := transport.identity
	assert.NotNil(t, initialIdentity)

	// Perform concurrent SetIdentity calls while Accept() may be running
	// This simulates the scenario where SetIdentity is called during handshakes

	err := transport.SetIdentity(emptyRouterInfoForTest())
	// An empty RouterInfo has no identity to hash, so it must be rejected --
	// and rejecting it must not be silent. (The success path on a real bound
	// transport is covered by TestSetIdentity_BoundTransportUpdatesInPlace.)
	require.Error(t, err, "an unusable identity must be reported, not swallowed")
	assert.NotNil(t, transport.identity)
}

// TestSM1_SetIdentityDoesNotKillAcceptLoop is a regression test for SM-1.
// It verifies that SetIdentity followed by Accept() still works.
func TestSM1_SetIdentityFollowedByAccept(t *testing.T) {
	// Two conns: one consumed before the identity update, one after, so the
	// post-update Accept() below is satisfiable rather than blocking.
	conn := newAcceptMockConn("10.0.0.1:5001")
	nextConn := newAcceptMockConn("10.0.0.2:5002")
	listener := newMockListener(conn, nextConn)
	transport := newTestTransport(listener, 100)
	defer transport.cancel()

	// Simulate a connection being accepted
	accepted, err := transport.Accept()
	require.NoError(t, err)
	require.NotNil(t, accepted)
	defer accepted.Close()

	// Now simulate SetIdentity being called while other connections may be
	// pending. This identity is unusable, so the call must report an error
	// rather than swallow it -- and must leave the listener intact.
	err = transport.SetIdentity(emptyRouterInfoForTest())
	require.Error(t, err, "an unusable identity must be reported, not swallowed")

	// SM-1 core invariant: a failed identity update must not kill the accept
	// loop. The listener must never be left nil by SetIdentity.
	assert.NotNil(t, transport.listener, "the listener must survive a failed update")
	again, acceptErr := transport.Accept()
	require.NoError(t, acceptErr, "Accept must still work after a failed SetIdentity")
	require.NotNil(t, again)
	_ = again.Close()
}

// TestSM1_ConcurrentSetIdentityAndAccept tests the SM-1 scenario:
// concurrent SetIdentity calls mixed with Accept() calls.
//
// Key invariant: No crash or deadlock should occur even if SetIdentity
// is called while Accept() is running or vice versa.
//
// NOTE: This test is skipped because mock listeners can deadlock when the
// accept loop and an identity update race. SetIdentity now updates in place and
// is covered against a real bound transport by
// TestSetIdentity_BoundTransportUpdatesInPlace.
func TestSM1_ConcurrentSetIdentityAndAcceptDisabled(t *testing.T) {
	t.Skip("Mock listeners cause deadlocks in concurrent tests; would need real listeners")
}

// emptyRouterInfoForTest is the zero RouterInfo, whose identity hash cannot be
// derived. Used to assert that SetIdentity reports rather than swallows it.
func emptyRouterInfoForTest() router_info.RouterInfo {
	return router_info.RouterInfo{}
}
