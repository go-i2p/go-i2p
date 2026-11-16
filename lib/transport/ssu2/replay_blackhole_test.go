package ssu2

import (
	"testing"

	"github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTrackInboundConnection_ReplayDoesNotBlackHolePeerHash is the I2P-C-1
// regression guard. When an inbound SSU2 connection is rejected by the
// anti-replay check, the transport must remove the registry entry it just
// inserted for that peer. Before the fix the replay branch only decremented the
// session count and closed the connection, leaving the dead connection parked
// under the peer hash. Every later inbound connection from that peer then hit
// the "duplicate" path and was rejected — permanently black-holing an
// inbound-only peer until an outbound dial happened to overwrite the entry.
//
// The test drives the real trackInboundConnection path with a real handshaked
// go-noise responder connection (so the replay check has genuine replay
// material), forces the replay branch by pre-seeding the handler's replay cache
// with that connection's token, and asserts the peer hash is free afterward so
// the next connection from that peer is not misread as a duplicate.
func TestTrackInboundConnection_ReplayDoesNotBlackHolePeerHash(t *testing.T) {
	tr := makeMinimalTransport()
	require.NotNil(t, tr.handler, "transport must have a replay handler")

	// A real handshaked responder connection carries a non-empty replay token,
	// which is what checkConnectionReplay consults.
	pair, err := attemptLoopbackPair(t)
	require.NoError(t, err, "must establish a real SSU2 pair to obtain replay material")
	inbound := pair.server
	require.NotEmpty(t, inbound.GetReplayToken(),
		"a handshaked responder must expose replay material for the anti-replay check")

	peerHash := tr.extractPeerHash(inbound)
	require.NotEqual(t, data.Hash{}, peerHash, "peer hash must be non-zero")

	// Mirror the real inbound flow: the session slot is reserved before tracking.
	require.NoError(t, tr.checkSessionLimit(), "must reserve a session slot")

	// Force the replay branch: mark this connection's replay token as already
	// seen, exactly as a genuine replayed handshake presents a recorded token.
	tr.handler.CheckReplay(replayTokenToReplayKey(inbound.GetReplayToken()))

	// The connection arrives: it is inserted under the peer hash, then rejected
	// by the anti-replay check. trackInboundConnection reports isFresh=false for
	// a rejected (replayed) connection.
	_, isFresh := tr.trackInboundConnection(inbound)
	require.False(t, isFresh,
		"the replayed connection must be rejected (isFresh=false)")

	// I2P-C-1: after the replay rejection the peer hash must be free again, so a
	// subsequent connection from the same peer is not misread as a duplicate.
	_, stillPresent := tr.sessionRegistry.Load(peerHash)
	assert.False(t, stillPresent,
		"a replay-rejected inbound connection must not leave its peer hash registered (I2P-C-1 black-holing)")

	// The reserved slot must be released (back to zero).
	assert.EqualValues(t, 0, tr.sessionRegistry.Count(),
		"the replay rejection must release the reserved session slot")

	// The peer hash must be free so the next inbound connection from this peer is
	// treated as fresh rather than rejected as a duplicate.
	_, loaded := tr.sessionRegistry.LoadOrStore(peerHash, &SSU2Session{})
	assert.False(t, loaded,
		"the peer hash must be free so the next inbound connection is treated as fresh")
}
