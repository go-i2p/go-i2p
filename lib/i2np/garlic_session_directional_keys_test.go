package i2np

import (
	"github.com/go-i2p/crypto/types"
	"testing"

	"github.com/go-i2p/crypto/ecies"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDeriveDirectionalKeys_ProducesDistinctKeys verifies that the send and
// receive keys derived from the same base key are different from each other.
func TestDeriveDirectionalKeys_ProducesDistinctKeys(t *testing.T) {
	baseKey := types.SHA256([]byte("test base key for direction isolation"))

	sendKey, recvKey := deriveDirectionalKeys(baseKey, true)

	assert.NotEqual(t, sendKey, recvKey,
		"Send and receive keys must be distinct")
	assert.NotEqual(t, sendKey, baseKey,
		"Send key must differ from the base key")
	assert.NotEqual(t, recvKey, baseKey,
		"Receive key must differ from the base key")
}

// TestDeriveDirectionalKeys_InitiatorResponderSymmetry verifies that the
// initiator's send key equals the responder's receive key, and vice versa.
// This is required so that both sides of the session can decrypt each other's messages.
func TestDeriveDirectionalKeys_InitiatorResponderSymmetry(t *testing.T) {
	baseKey := types.SHA256([]byte("shared secret derived key"))

	initSend, initRecv := deriveDirectionalKeys(baseKey, true)
	respSend, respRecv := deriveDirectionalKeys(baseKey, false)

	assert.Equal(t, initSend, respRecv,
		"Initiator's send key must equal responder's receive key")
	assert.Equal(t, initRecv, respSend,
		"Initiator's receive key must equal responder's send key")
}

// TestDeriveDirectionalKeys_Deterministic verifies that repeated calls with
// the same inputs produce the same outputs.
func TestDeriveDirectionalKeys_Deterministic(t *testing.T) {
	baseKey := types.SHA256([]byte("deterministic test"))

	send1, recv1 := deriveDirectionalKeys(baseKey, true)
	send2, recv2 := deriveDirectionalKeys(baseKey, true)

	assert.Equal(t, send1, send2, "Send keys must be deterministic")
	assert.Equal(t, recv1, recv2, "Receive keys must be deterministic")
}

// TestDeriveDirectionalKeys_DifferentBaseKeys verifies that different base keys
// produce entirely different directional keys.
func TestDeriveDirectionalKeys_DifferentBaseKeys(t *testing.T) {
	baseKey1 := types.SHA256([]byte("base key 1"))
	baseKey2 := types.SHA256([]byte("base key 2"))

	send1, recv1 := deriveDirectionalKeys(baseKey1, true)
	send2, recv2 := deriveDirectionalKeys(baseKey2, true)

	assert.NotEqual(t, send1, send2,
		"Different base keys must produce different send keys")
	assert.NotEqual(t, recv1, recv2,
		"Different base keys must produce different receive keys")
}

// TestCreateGarlicSession_DirectionalKeyIsolation verifies that a session
// created as initiator has different send and receive ratchet keys.
func TestCreateGarlicSession_DirectionalKeyIsolation(t *testing.T) {
	_, bobPubBytes, err := ecies.GenerateKeyPair()
	require.NoError(t, err)

	alicePrivBytes, _, err := ecies.GenerateKeyPair()
	require.NoError(t, err)

	var alicePriv, bobPub [32]byte
	copy(alicePriv[:], alicePrivBytes)
	copy(bobPub[:], bobPubBytes)

	rootKey := types.SHA256([]byte("test root key"))
	tagKey := types.SHA256([]byte("test tag key"))

	session := createGarlicSession(bobPub, &sessionKeys{
		rootKey: rootKey,
		symKey:  [32]byte{},
		tagKey:  tagKey,
	}, alicePriv, true)

	// Generate tags from both ratchets and verify they differ
	sendTag, err := session.TagRatchet.GenerateNextTag()
	require.NoError(t, err)

	recvTag, err := session.RecvTagRatchet.GenerateNextTag()
	require.NoError(t, err)

	assert.NotEqual(t, sendTag, recvTag,
		"Send and receive tag ratchets must produce different tags")
}

// TestCreateGarlicSession_InitiatorResponderTagIsolation verifies that when
// Alice (initiator) and Bob (responder) create sessions with the same keys,
// Alice's send tags match Bob's receive tags and vice versa. This ensures
// proper bidirectional communication.
func TestCreateGarlicSession_InitiatorResponderTagIsolation(t *testing.T) {
	alicePrivBytes, alicePubBytes, err := ecies.GenerateKeyPair()
	require.NoError(t, err)

	bobPrivBytes, bobPubBytes, err := ecies.GenerateKeyPair()
	require.NoError(t, err)

	var alicePriv, alicePub, bobPriv, bobPub [32]byte
	copy(alicePriv[:], alicePrivBytes)
	copy(alicePub[:], alicePubBytes)
	copy(bobPriv[:], bobPrivBytes)
	copy(bobPub[:], bobPubBytes)

	// Both sides derive the same session keys from the shared secret
	keys := &sessionKeys{
		rootKey: types.SHA256([]byte("shared root")),
		symKey:  types.SHA256([]byte("shared sym")),
		tagKey:  types.SHA256([]byte("shared tag")),
	}

	// Alice creates an outbound (initiator) session
	aliceSession := createGarlicSession(bobPub, keys, alicePriv, true)

	// Bob creates an inbound (responder) session
	bobSession := createGarlicSession(alicePub, keys, bobPriv, false)

	// Alice's send tags should match Bob's receive tags
	aliceSendTag, err := aliceSession.TagRatchet.GenerateNextTag()
	require.NoError(t, err)

	bobRecvTag, err := bobSession.RecvTagRatchet.GenerateNextTag()
	require.NoError(t, err)

	assert.Equal(t, aliceSendTag, bobRecvTag,
		"Alice's send tag must match Bob's receive tag")

	// Bob's send tags should match Alice's receive tags
	bobSendTag, err := bobSession.TagRatchet.GenerateNextTag()
	require.NoError(t, err)

	aliceRecvTag, err := aliceSession.RecvTagRatchet.GenerateNextTag()
	require.NoError(t, err)

	assert.Equal(t, bobSendTag, aliceRecvTag,
		"Bob's send tag must match Alice's receive tag")

	// Send and receive should NOT match within the same session
	assert.NotEqual(t, aliceSendTag, aliceRecvTag,
		"Alice's send and receive tags must differ")
	assert.NotEqual(t, bobSendTag, bobRecvTag,
		"Bob's send and receive tags must differ")
}

// TestCreateGarlicSession_SymmetricRatchetIsolation verifies that send and
// receive symmetric ratchets produce different message keys.
func TestCreateGarlicSession_SymmetricRatchetIsolation(t *testing.T) {
	_, bobPubBytes, err := ecies.GenerateKeyPair()
	require.NoError(t, err)

	alicePrivBytes, _, err := ecies.GenerateKeyPair()
	require.NoError(t, err)

	var alicePriv, bobPub [32]byte
	copy(alicePriv[:], alicePrivBytes)
	copy(bobPub[:], bobPubBytes)

	rootKey := types.SHA256([]byte("sym ratchet test root"))
	tagKey := types.SHA256([]byte("sym ratchet test tag"))

	session := createGarlicSession(bobPub, &sessionKeys{
		rootKey: rootKey,
		symKey:  [32]byte{},
		tagKey:  tagKey,
	}, alicePriv, true)

	// Verify the chain keys of send and receive symmetric ratchets differ
	sendChainKey := session.SymmetricRatchet.GetChainKey()
	recvChainKey := session.RecvSymmetricRatchet.GetChainKey()

	assert.NotEqual(t, sendChainKey, recvChainKey,
		"Send and receive symmetric ratchets must have different chain keys")
}
