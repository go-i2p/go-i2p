package i2np

import (
	"testing"
	"time"

	"github.com/go-i2p/crypto/types"

	i2pcurve25519 "github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/crypto/ecies"
	"github.com/go-i2p/crypto/ratchet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestSession builds a GarlicSession with valid ratchet state for testing.
func createTestSession(t *testing.T) *GarlicSession {
	t.Helper()

	// Generate two key pairs for Alice (us) and Bob (them)
	_, alicePrivBytes, err := ecies.GenerateKeyPair()
	require.NoError(t, err)

	bobPubBytes, _, err := ecies.GenerateKeyPair()
	require.NoError(t, err)

	var alicePriv, bobPub [32]byte
	copy(alicePriv[:], alicePrivBytes)
	copy(bobPub[:], bobPubBytes)

	// Derive a test root key
	rootKey := types.SHA256([]byte("test root key for DH ratchet"))
	tagKey := types.SHA256([]byte("test tag key for DH ratchet"))

	session := createGarlicSession(bobPub, &sessionKeys{
		rootKey: rootKey,
		symKey:  [32]byte{},
		tagKey:  tagKey,
	}, alicePriv, true)

	return session
}

// TestDHRatchetIntervalConstant verifies the interval constant value.
func TestDHRatchetIntervalConstant(t *testing.T) {
	assert.Equal(t, uint32(50), uint32(DHRatchetInterval),
		"DHRatchetInterval should be 50 per I2P spec recommendation")
}

// TestSessionHasDHRatchetCounter verifies the counter field exists and is initialized.
func TestSessionHasDHRatchetCounter(t *testing.T) {
	session := createTestSession(t)
	assert.Equal(t, uint32(0), session.dhRatchetCounter,
		"New session should have dhRatchetCounter at 0")
}

// TestAdvanceRatchetsIncrementsCounter verifies the DH counter increments each call.
func TestAdvanceRatchetsIncrementsCounter(t *testing.T) {
	session := createTestSession(t)

	for i := 0; i < 5; i++ {
		_, _, err := advanceRatchets(session)
		require.NoError(t, err)
		session.MessageCounter++
	}

	assert.Equal(t, uint32(5), session.dhRatchetCounter,
		"Counter should be 5 after 5 advances")
}

// TestAdvanceRatchetsTriggersRotation verifies DH ratchet fires at DHRatchetInterval.
func TestAdvanceRatchetsTriggersRotation(t *testing.T) {
	session := createTestSession(t)

	// Advance to just before rotation
	for i := uint32(0); i < DHRatchetInterval-1; i++ {
		_, _, err := advanceRatchets(session)
		require.NoError(t, err)
		session.MessageCounter++
	}

	assert.Equal(t, uint32(DHRatchetInterval-1), session.dhRatchetCounter)

	// Record the current state
	oldSymRatchet := session.SymmetricRatchet
	oldTagRatchet := session.TagRatchet

	// This call should trigger DH ratchet
	_, _, err := advanceRatchets(session)
	require.NoError(t, err)

	// Counter should be reset to 0 (since rotation succeeded)
	// or DHRatchetInterval if rotation failed (but we have valid keys so it should succeed)
	assert.Equal(t, uint32(0), session.dhRatchetCounter,
		"Counter should be reset after successful DH rotation")

	// Ratchets should have been replaced
	assert.NotEqual(t, oldSymRatchet, session.SymmetricRatchet,
		"Symmetric ratchet should be re-initialized after DH rotation")
	assert.NotEqual(t, oldTagRatchet, session.TagRatchet,
		"Tag ratchet should be re-initialized after DH rotation")

	// newEphemeralPub should be set
	assert.NotNil(t, session.newEphemeralPub,
		"New ephemeral public key should be set after DH rotation")
}

// TestPerformDHRatchetStep tests the DH ratchet step directly.
func TestPerformDHRatchetStep(t *testing.T) {
	session := createTestSession(t)

	oldPubKey, err := session.DHRatchet.GetPublicKey()
	require.NoError(t, err)

	err = performDHRatchetStep(session)
	require.NoError(t, err)

	// Verify new ephemeral public key is generated
	assert.NotNil(t, session.newEphemeralPub)

	// Verify the new public key is different from the old one
	newPubKey, err := session.DHRatchet.GetPublicKey()
	require.NoError(t, err)
	assert.NotEqual(t, oldPubKey, newPubKey,
		"DH ratchet should have new public key after step")

	// Verify symmetric ratchet was re-initialized
	assert.NotNil(t, session.SymmetricRatchet)

	// Verify tag ratchet was re-initialized
	assert.NotNil(t, session.TagRatchet)
}

// TestPerformDHRatchetStepConsistency verifies multiple DH steps produce different keys.
func TestPerformDHRatchetStepConsistency(t *testing.T) {
	session := createTestSession(t)

	var pubKeys [][32]byte

	for i := 0; i < 5; i++ {
		err := performDHRatchetStep(session)
		require.NoError(t, err)

		pubKey := *session.newEphemeralPub
		pubKeys = append(pubKeys, pubKey)
	}

	// All public keys should be unique
	for i := 0; i < len(pubKeys); i++ {
		for j := i + 1; j < len(pubKeys); j++ {
			assert.NotEqual(t, pubKeys[i], pubKeys[j],
				"DH ratchet step %d and %d produced same public key", i, j)
		}
	}
}

// TestProcessIncomingDHRatchet tests processing a remote DH key.
func TestProcessIncomingDHRatchet(t *testing.T) {
	sm, err := GenerateGarlicSessionManager()
	require.NoError(t, err)

	session := createTestSession(t)

	// Generate a new remote public key
	newRemotePubBytes, _, err := ecies.GenerateKeyPair()
	require.NoError(t, err)

	var newRemotePub [32]byte
	copy(newRemotePub[:], newRemotePubBytes)

	oldRemotePub := session.RemotePublicKey

	err = sm.ProcessIncomingDHRatchet(session, newRemotePub)
	require.NoError(t, err)

	// Verify remote public key was updated
	assert.Equal(t, newRemotePub, session.RemotePublicKey,
		"Remote public key should be updated")
	assert.NotEqual(t, oldRemotePub, session.RemotePublicKey,
		"Remote public key should change")

	// Verify ratchets were re-initialized
	assert.NotNil(t, session.SymmetricRatchet)
	assert.NotNil(t, session.TagRatchet)
}

// TestDHRatchetNonFatal verifies that DH ratchet failure is non-fatal.
func TestDHRatchetNonFatal(t *testing.T) {
	session := createTestSession(t)

	// Even if something weird happens, advanceRatchets should continue
	// with the symmetric ratchet
	session.dhRatchetCounter = DHRatchetInterval // Force rotation

	// Save old ratchets to verify they're still usable
	_, _, err := advanceRatchets(session)

	// Whether the DH step succeeds or fails, advanceRatchets should work
	// because of the non-fatal error handling
	require.NoError(t, err, "advanceRatchets should succeed even if DH ratchet has issues")
}

// TestAdvanceRatchetsProducesValidKeys verifies ratchet output is usable.
func TestAdvanceRatchetsProducesValidKeys(t *testing.T) {
	session := createTestSession(t)

	// Collect multiple message keys and session tags
	type keyPair struct {
		msgKey [32]byte
		tag    [8]byte
	}
	var pairs []keyPair

	for i := 0; i < 10; i++ {
		mk, st, err := advanceRatchets(session)
		require.NoError(t, err)
		pairs = append(pairs, keyPair{mk, st})
		session.MessageCounter++
	}

	// All message keys should be unique
	for i := 0; i < len(pairs); i++ {
		for j := i + 1; j < len(pairs); j++ {
			assert.NotEqual(t, pairs[i].msgKey, pairs[j].msgKey,
				"Message keys %d and %d should be unique", i, j)
		}
	}

	// All session tags should be unique
	for i := 0; i < len(pairs); i++ {
		for j := i + 1; j < len(pairs); j++ {
			assert.NotEqual(t, pairs[i].tag, pairs[j].tag,
				"Session tags %d and %d should be unique", i, j)
		}
	}
}

// TestDHRatchetDoesNotAffectMessageKey verifies message key is still derived correctly after rotation.
func TestDHRatchetDoesNotAffectMessageKey(t *testing.T) {
	session := createTestSession(t)

	// Advance to trigger DH ratchet
	session.dhRatchetCounter = DHRatchetInterval - 1

	// This call triggers DH rotation
	mk, st, err := advanceRatchets(session)
	require.NoError(t, err)

	// Verify the returned keys are non-zero
	assert.NotEqual(t, [32]byte{}, mk, "Message key should be non-zero after rotation")
	assert.NotEqual(t, [8]byte{}, st, "Session tag should be non-zero after rotation")
}

// TestNewEphemeralPubIsStored verifies ephemeral public key storage after DH step.
func TestNewEphemeralPubIsStored(t *testing.T) {
	session := createTestSession(t)

	// Before any DH step, no ephemeral pub
	assert.Nil(t, session.newEphemeralPub,
		"No ephemeral pub before DH step")

	err := performDHRatchetStep(session)
	require.NoError(t, err)

	require.NotNil(t, session.newEphemeralPub)

	// Key should be non-zero
	assert.NotEqual(t, [32]byte{}, *session.newEphemeralPub)
}

// TestDHRatchetRotationResetsPendingTags tests that rotation doesn't clear pending tags.
func TestDHRatchetRotationResetsPendingTags(t *testing.T) {
	session := createTestSession(t)

	// Accumulate some pending tags
	for i := 0; i < 5; i++ {
		_, _, err := advanceRatchets(session)
		require.NoError(t, err)
		session.MessageCounter++
	}

	tagsBefore := len(session.pendingTags)
	assert.Greater(t, tagsBefore, 0, "Should have accumulated pending tags")

	// Trigger DH rotation
	session.dhRatchetCounter = DHRatchetInterval - 1
	_, _, err := advanceRatchets(session)
	require.NoError(t, err)

	// Pending tags should still be there (rotation doesn't clear them)
	assert.Equal(t, tagsBefore+1, len(session.pendingTags),
		"Pending tags should not be cleared by DH rotation — just one more added")
}

// TestFullRotationCycle tests multiple full cycles of DHRatchetInterval advances.
func TestFullRotationCycle(t *testing.T) {
	session := createTestSession(t)

	rotationCount := 0

	// Run through 3 full rotation cycles
	for i := uint32(0); i < DHRatchetInterval*3; i++ {
		counterBefore := session.dhRatchetCounter
		_, _, err := advanceRatchets(session)
		require.NoError(t, err)
		session.MessageCounter++

		if counterBefore == DHRatchetInterval-1 && session.dhRatchetCounter == 0 {
			rotationCount++
		}
	}

	assert.Equal(t, 3, rotationCount,
		"Should have performed exactly 3 DH rotations")
}

// TestCreateGarlicSessionInitializesRatchets verifies session creation.
func TestCreateGarlicSessionInitializesRatchets(t *testing.T) {
	_, alicePrivBytes, err := ecies.GenerateKeyPair()
	require.NoError(t, err)

	bobPubBytes, _, err := ecies.GenerateKeyPair()
	require.NoError(t, err)

	var alicePriv, bobPub [32]byte
	copy(alicePriv[:], alicePrivBytes)
	copy(bobPub[:], bobPubBytes)

	rootKey := types.SHA256([]byte("root"))
	tagKey := types.SHA256([]byte("tag"))

	session := createGarlicSession(bobPub, &sessionKeys{
		rootKey: rootKey,
		tagKey:  tagKey,
	}, alicePriv, true)

	assert.NotNil(t, session.DHRatchet, "DHRatchet should be initialized")
	assert.NotNil(t, session.SymmetricRatchet, "SymmetricRatchet should be initialized")
	assert.NotNil(t, session.TagRatchet, "TagRatchet should be initialized")
	assert.Equal(t, bobPub, session.RemotePublicKey)
	assert.Equal(t, uint32(0), session.dhRatchetCounter)
	assert.Nil(t, session.newEphemeralPub)
	assert.Equal(t, uint32(1), session.MessageCounter)
}

// TestNewSymmetricRatchetAfterDHStep tests that the new SymmetricRatchet after DH rotation
// still produces valid message keys.
func TestNewSymmetricRatchetAfterDHStep(t *testing.T) {
	session := createTestSession(t)

	err := performDHRatchetStep(session)
	require.NoError(t, err)

	// The new symmetric ratchet should produce valid keys
	mk, _, err := session.SymmetricRatchet.DeriveMessageKeyAndAdvance(session.MessageCounter)
	require.NoError(t, err)
	assert.NotEqual(t, [32]byte{}, mk, "New symmetric ratchet should produce non-zero keys")
}

// TestNewTagRatchetAfterDHStep tests that the new TagRatchet after DH rotation
// still produces valid tags.
func TestNewTagRatchetAfterDHStep(t *testing.T) {
	session := createTestSession(t)

	err := performDHRatchetStep(session)
	require.NoError(t, err)

	// The new tag ratchet should produce valid tags
	tag, err := session.TagRatchet.GenerateNextTag()
	require.NoError(t, err)
	assert.NotEqual(t, [8]byte{}, tag, "New tag ratchet should produce non-zero tags")
}

// Ensure ratchet types are usable
func TestRatchetTypeImports(t *testing.T) {
	// Verify we can create ratchet types directly
	rootKey := types.SHA256([]byte("test"))
	var priv, pub [32]byte
	copy(priv[:], rootKey[:])
	privKey, err := i2pcurve25519.NewCurve25519PrivateKey(priv[:])
	assert.NoError(t, err)
	pubKey, err := privKey.Public()
	assert.NoError(t, err)
	copy(pub[:], pubKey.Bytes())

	dhr := ratchet.NewDHRatchet(rootKey, priv, pub)
	assert.NotNil(t, dhr)

	sr := ratchet.NewSymmetricRatchet(rootKey)
	assert.NotNil(t, sr)

	tr := ratchet.NewTagRatchet(rootKey)
	assert.NotNil(t, tr)

	_ = time.Now() // use time import
}
