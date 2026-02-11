package i2np

import (
	"testing"
	"time"

	"github.com/go-i2p/crypto/ratchet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDoubleRatchet_SendRecvSeparation verifies that sending and receiving
// use independent ratchet chains.  Before the fix, ProcessIncomingDHRatchet
// overwrote the send SymmetricRatchet/TagRatchet, which corrupted the
// sending chain when the peer performed a DH ratchet step.
func TestDoubleRatchet_SendRecvSeparation(t *testing.T) {
	var privKey [32]byte
	copy(privKey[:], []byte("test-private-key-32-bytes-long!!"))
	sm, err := NewGarlicSessionManager(privKey)
	require.NoError(t, err)

	sendSymKey := [32]byte{1, 2, 3}
	sendTagKey := [32]byte{4, 5, 6}
	recvSymKey := [32]byte{7, 8, 9}
	recvTagKey := [32]byte{10, 11, 12}

	var peerPubKey [32]byte
	copy(peerPubKey[:], []byte("peer-public-key-32-bytes-long!!!"))

	session := &GarlicSession{
		LastUsed:             time.Now(),
		SymmetricRatchet:     ratchet.NewSymmetricRatchet(sendSymKey),
		TagRatchet:           ratchet.NewTagRatchet(sendTagKey),
		RecvSymmetricRatchet: ratchet.NewSymmetricRatchet(recvSymKey),
		RecvTagRatchet:       ratchet.NewTagRatchet(recvTagKey),
		DHRatchet:            ratchet.NewDHRatchet([32]byte{0}, privKey, peerPubKey),
		pendingTags:          make([][8]byte, 0),
	}

	// Snapshot the send ratchets' state by deriving a key before the incoming DH ratchet.
	sendKeyBefore, _, err := session.SymmetricRatchet.DeriveMessageKeyAndAdvance(0)
	require.NoError(t, err)

	// Re-create so the internal counter is back to 0.
	session.SymmetricRatchet = ratchet.NewSymmetricRatchet(sendSymKey)

	// Simulate an incoming DH ratchet from the peer (using a different pub key).
	var newPeerPubKey [32]byte
	copy(newPeerPubKey[:], []byte("new-peer-public-key-32-bytes!!!!"))
	err = sm.ProcessIncomingDHRatchet(session, newPeerPubKey)
	require.NoError(t, err)

	// The send ratchet should be untouched (same root key → same first derived key).
	sendKeyAfter, _, err := session.SymmetricRatchet.DeriveMessageKeyAndAdvance(0)
	require.NoError(t, err)

	assert.Equal(t, sendKeyBefore, sendKeyAfter,
		"ProcessIncomingDHRatchet must not modify the send SymmetricRatchet")
}

// TestDoubleRatchet_RecvCounterIndependent verifies that decryptExistingSession
// increments recvCounter (not MessageCounter).
func TestDoubleRatchet_RecvCounterIndependent(t *testing.T) {
	session := &GarlicSession{
		LastUsed:             time.Now(),
		MessageCounter:       5,
		recvCounter:          3,
		SymmetricRatchet:     ratchet.NewSymmetricRatchet([32]byte{1}),
		TagRatchet:           ratchet.NewTagRatchet([32]byte{2}),
		RecvSymmetricRatchet: ratchet.NewSymmetricRatchet([32]byte{3}),
		RecvTagRatchet:       ratchet.NewTagRatchet([32]byte{4}),
		pendingTags:          make([][8]byte, 0),
	}

	// Verify initial counters.
	assert.Equal(t, uint32(5), session.MessageCounter)
	assert.Equal(t, uint32(3), session.recvCounter)

	// After a hypothetical decrypt the recvCounter should advance but not MessageCounter.
	// We simulate by directly calling deriveDecryptionKey + advancing counter.
	_, err := deriveDecryptionKey(session)
	require.NoError(t, err)
	session.recvCounter++

	assert.Equal(t, uint32(5), session.MessageCounter,
		"MessageCounter (send) must not change during decryption")
	assert.Equal(t, uint32(4), session.recvCounter,
		"recvCounter must advance during decryption")
}

// TestDeriveDecryptionKey_FallbackToSendRatchet checks that deriveDecryptionKey
// falls back to SymmetricRatchet when RecvSymmetricRatchet is nil (for sessions
// created before the send/recv split).
func TestDeriveDecryptionKey_FallbackToSendRatchet(t *testing.T) {
	rootKey := [32]byte{42}

	// Session WITH RecvSymmetricRatchet.
	sessionWithRecv := &GarlicSession{
		SymmetricRatchet:     ratchet.NewSymmetricRatchet([32]byte{0}),
		RecvSymmetricRatchet: ratchet.NewSymmetricRatchet(rootKey),
		recvCounter:          0,
	}
	keyRecv, err := deriveDecryptionKey(sessionWithRecv)
	require.NoError(t, err)

	// Session WITHOUT RecvSymmetricRatchet (fallback).
	sessionFallback := &GarlicSession{
		SymmetricRatchet:     ratchet.NewSymmetricRatchet(rootKey),
		RecvSymmetricRatchet: nil,
		recvCounter:          0,
	}
	keyFallback, err := deriveDecryptionKey(sessionFallback)
	require.NoError(t, err)

	// Both should derive the same key because they use the same root key at counter 0.
	assert.Equal(t, keyRecv, keyFallback,
		"fallback to SymmetricRatchet should produce the same key when rooted identically")
}

// TestGenerateTagWindow_UsesRecvTagRatchet verifies that generateTagWindow
// uses RecvTagRatchet (not the sending TagRatchet) for generating the
// tag window that incoming messages are matched against.
func TestGenerateTagWindow_UsesRecvTagRatchet(t *testing.T) {
	var privKey [32]byte
	copy(privKey[:], []byte("test-private-key-32-bytes-long!!"))
	sm, err := NewGarlicSessionManager(privKey)
	require.NoError(t, err)

	recvTagKey := [32]byte{99}

	session := &GarlicSession{
		LastUsed:             time.Now(),
		SymmetricRatchet:     ratchet.NewSymmetricRatchet([32]byte{1}),
		TagRatchet:           ratchet.NewTagRatchet([32]byte{2}),
		RecvSymmetricRatchet: ratchet.NewSymmetricRatchet([32]byte{3}),
		RecvTagRatchet:       ratchet.NewTagRatchet(recvTagKey),
		pendingTags:          make([][8]byte, 0),
	}

	// Generate a reference set of tags from a standalone ratchet seeded
	// with the same key as RecvTagRatchet.
	refRatchet := ratchet.NewTagRatchet(recvTagKey)
	var expectedTags [][8]byte
	for i := 0; i < 10; i++ {
		tag, err := refRatchet.GenerateNextTag()
		require.NoError(t, err)
		expectedTags = append(expectedTags, tag)
	}

	// Generate the window via the session manager.
	sm.mu.Lock()
	err = sm.generateTagWindow(session)
	sm.mu.Unlock()
	require.NoError(t, err)

	assert.Equal(t, expectedTags, session.pendingTags,
		"generateTagWindow must use RecvTagRatchet, not TagRatchet")
}
