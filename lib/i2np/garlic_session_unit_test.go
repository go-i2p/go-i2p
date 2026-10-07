package i2np

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/go-i2p/crypto/ecies"
	"github.com/go-i2p/crypto/types"
	noiseratchet "github.com/go-i2p/go-noise/ratchet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// completeGarlicHandshake performs the NS + NSR handshake between sender and
// receiver, leaving both session managers ready for existing-session messages.
// Returns the receiver's public key and destination hash.
func completeGarlicHandshake(t *testing.T, senderSM, receiverSM *GarlicSessionManager, destPubKey [32]byte) [32]byte {
	t.Helper()

	destHash := types.SHA256(destPubKey[:])

	builder1, _ := NewGarlicBuilderWithDefaults()
	dataMsg1 := NewDataMessage([]byte("handshake"))
	builder1.AddLocalDeliveryClove(dataMsg1, 1)
	ct1, err := EncryptGarlicWithBuilder(senderSM, builder1, destHash, destPubKey)
	require.NoError(t, err, "NS encrypt")
	_, _, sessionHash, err := receiverSM.DecryptGarlicMessage(ct1)
	require.NoError(t, err, "NS decrypt")
	require.NotNil(t, sessionHash, "sessionHash must be non-nil for New Session")

	nsrPayload, err := noiseratchet.BuildNSPayload([]byte("nsr"))
	require.NoError(t, err, "build NSR payload")
	nsrMsg, err := receiverSM.EncryptNewSessionReply(*sessionHash, nsrPayload)
	require.NoError(t, err, "encrypt NSR")
	_, _, _, err = senderSM.DecryptGarlicMessage(nsrMsg)
	require.NoError(t, err, "sender process NSR")

	return destHash
}

// setupGarlicSenderReceiver creates a sender and receiver GarlicSessionManager pair
// along with the receiver's public key for use in garlic encryption tests.
func setupGarlicSenderReceiver(t *testing.T) (senderSM, receiverSM *GarlicSessionManager, receiverPubKey [32]byte) {
	t.Helper()
	senderSM, err := GenerateGarlicSessionManager()
	require.NoError(t, err, "generate sender session manager")

	receiverPubBytes, receiverPrivBytes, err := ecies.GenerateKeyPair()
	require.NoError(t, err, "generate receiver key pair")

	var receiverPrivKey [32]byte
	copy(receiverPubKey[:], receiverPubBytes)
	copy(receiverPrivKey[:], receiverPrivBytes)

	receiverSM, err = NewGarlicSessionManager(receiverPrivKey)
	require.NoError(t, err, "create receiver session manager")

	return senderSM, receiverSM, receiverPubKey
}

// TestSessionManagerCreation tests creating a new session manager.
func TestSessionManagerCreation(t *testing.T) {
	sm, err := GenerateGarlicSessionManager()
	require.NoError(t, err)
	require.NotNil(t, sm)
	assert.Equal(t, 0, sm.GetSessionCount())
}

// TestNewSessionManagerWithKey tests creating a session manager with a specific key.
func TestNewSessionManagerWithKey(t *testing.T) {
	_, privBytes, err := ecies.GenerateKeyPair()
	require.NoError(t, err)

	var privKey [32]byte
	copy(privKey[:], privBytes)

	sm, err := NewGarlicSessionManager(privKey)
	require.NoError(t, err)
	require.NotNil(t, sm)
}

// TestNewSessionEncryption tests encrypting a garlic message for a new session.
func TestNewSessionEncryption(t *testing.T) {
	sm, destPubKey, destHash := setupNewGarlicSession(t)

	builder, err := NewGarlicBuilderWithDefaults()
	require.NoError(t, err)

	dataMsg := NewDataMessage([]byte("test payload"))
	require.NoError(t, builder.AddLocalDeliveryClove(dataMsg, 1))

	ciphertext, err := EncryptGarlicWithBuilder(sm, builder, destHash, destPubKey)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext)

	assert.Equal(t, 1, sm.GetSessionCount(), "session count after encryption")

	plaintext, err := builder.BuildAndSerialize()
	require.NoError(t, err)
	assert.False(t, bytes.Equal(ciphertext, plaintext), "ciphertext should not equal plaintext")
}

// TestNewSessionDecryption tests decrypting a new session garlic message.
func TestNewSessionDecryption(t *testing.T) {
	senderSM, receiverSM, receiverPubKey := setupGarlicSenderReceiver(t)

	destHash := types.SHA256(receiverPubKey[:])

	builder, err := NewGarlicBuilderWithDefaults()
	require.NoError(t, err)

	testPayload := []byte("secret test data")
	dataMsg := NewDataMessage(testPayload)
	require.NoError(t, builder.AddLocalDeliveryClove(dataMsg, 1))

	originalPlaintext, err := builder.BuildAndSerialize()
	require.NoError(t, err)

	ciphertext, err := EncryptGarlicWithBuilder(senderSM, builder, destHash, receiverPubKey)
	require.NoError(t, err)

	decryptedAll, sessionTag, _, err := receiverSM.DecryptGarlicMessage(ciphertext)
	require.NoError(t, err)
	require.NotEmpty(t, decryptedAll, "decrypt must return at least one clove")

	assert.Equal(t, [8]byte{}, sessionTag, "expected empty session tag for new session")
	assert.Equal(t, originalPlaintext, decryptedAll[0], "decrypted plaintext should match original")
}

// TestExistingSessionEncryptDecrypt tests encrypt/decrypt round-trip via existing session.
func TestExistingSessionEncryptDecrypt(t *testing.T) {
	senderSM, receiverSM, receiverPubKey := setupGarlicSenderReceiver(t)

	destHash := completeGarlicHandshake(t, senderSM, receiverSM, receiverPubKey)

	builder2, _ := NewGarlicBuilderWithDefaults()
	dataMsg2 := NewDataMessage([]byte("second message"))
	builder2.AddLocalDeliveryClove(dataMsg2, 2)
	original2, _ := builder2.BuildAndSerialize()

	ct2, err := EncryptGarlicWithBuilder(senderSM, builder2, destHash, receiverPubKey)
	require.NoError(t, err, "second encrypt")

	dec2All, tag2, _, err := receiverSM.DecryptGarlicMessage(ct2)
	require.NoError(t, err, "second decrypt")
	require.NotEmpty(t, dec2All, "decrypt must return at least one clove")

	assert.NotEqual(t, [8]byte{}, tag2, "expected non-empty session tag for existing session")
	assert.True(t, bytes.Equal(dec2All[0], original2), "decrypted plaintext should match for existing session")
}

// TestMultipleDestinations tests encrypting for different destinations.
func TestMultipleDestinations(t *testing.T) {
	sm, err := GenerateGarlicSessionManager()
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		destPubBytes, _, err := ecies.GenerateKeyPair()
		require.NoError(t, err, "key pair %d", i)

		var destPubKey [32]byte
		copy(destPubKey[:], destPubBytes)
		destHash := types.SHA256(destPubKey[:])

		builder, _ := NewGarlicBuilderWithDefaults()
		dataMsg := NewDataMessage([]byte("multi-dest"))
		builder.AddLocalDeliveryClove(dataMsg, i)

		_, err = EncryptGarlicWithBuilder(sm, builder, destHash, destPubKey)
		require.NoError(t, err, "encrypt for destination %d", i)
	}

	assert.Equal(t, 5, sm.GetSessionCount())
}

// TestWrapInGarlicMessage tests wrapping encrypted data in I2NP Garlic message.
// Verifies that the spec-required 4-byte length prefix is prepended (F459/F461).
func TestWrapInGarlicMessage(t *testing.T) {
	encryptedData := []byte("encrypted garlic payload data")

	msg, err := WrapInGarlicMessage(encryptedData)
	require.NoError(t, err)

	assert.Equal(t, I2NPMessageTypeGarlic, msg.Type(), "message type")

	// Verify the 4-byte length prefix is present (F459/F461 fix)
	assert.GreaterOrEqual(t, len(msg.data), 4, "msg.data must have at least 4-byte length prefix")

	// Extract and verify the length prefix
	lengthPrefix := binary.BigEndian.Uint32(msg.data[0:4])
	assert.Equal(t, uint32(len(encryptedData)), lengthPrefix,
		"4-byte length prefix should match encrypted data length")

	// Verify the encrypted data follows the prefix
	assert.Equal(t, len(encryptedData)+4, len(msg.data),
		"msg.data should be 4-byte prefix + encrypted data")
	assert.True(t, bytes.Equal(msg.data[4:], encryptedData),
		"encrypted data should match after 4-byte prefix")

	assert.NotZero(t, msg.MessageID(), "message ID should not be zero")
	assert.True(t, msg.Expiration().After(time.Now()), "expiration should be in the future")
}

// TestWrapInGarlicMessage_EmptyData tests error handling for empty data.
func TestWrapInGarlicMessage_EmptyData(t *testing.T) {
	_, err := WrapInGarlicMessage([]byte{})
	assert.Error(t, err, "expected error when wrapping empty data")
}

// TestGarlicCloveSerializationFormat verifies spec-compliant garlic clove format (F048, F093, F458, F461).
// Per ecies.rst, clove format must be:
// [DeliveryInstructions(variable)] + [type(1)] + [msgID(4)] + [expiration(4, seconds)] + [body]
func TestGarlicCloveSerializationFormat(t *testing.T) {
	builder, err := NewGarlicBuilderWithDefaults()
	require.NoError(t, err)

	// Create a simple test message
	testPayload := []byte("test clove payload")
	msg := NewDataMessage(testPayload)
	msgID := 12345
	msg.SetMessageID(msgID)
	expiration := time.Unix(1234567890, 0)
	msg.SetExpiration(expiration)

	// Add as local delivery clove (simplest delivery type)
	require.NoError(t, builder.AddLocalDeliveryClove(msg, 1))

	// Serialize the garlic
	payload, err := builder.BuildAndSerialize()
	require.NoError(t, err)

	// Parse the serialized garlic manually to verify format
	offset := 0

	// First byte should be clove count (1)
	assert.Equal(t, byte(1), payload[offset], "clove count should be 1")
	offset++

	// Next byte is delivery instructions flag (LOCAL = 0x00)
	assert.Equal(t, byte(0x00), payload[offset], "LOCAL delivery flag")
	offset++

	// Next byte should be I2NP message type (Data = 20)
	msgType := payload[offset]
	assert.Equal(t, byte(I2NPMessageTypeData), msgType, "message type should be Data (20)")
	offset++

	// Next 4 bytes should be message ID in big-endian
	extractedMsgID := binary.BigEndian.Uint32(payload[offset : offset+4])
	assert.Equal(t, uint32(msgID), extractedMsgID, "message ID mismatch")
	offset += 4

	// Next 4 bytes should be expiration (Unix seconds, not milliseconds)
	extractedExpiration := binary.BigEndian.Uint32(payload[offset : offset+4])
	assert.Equal(t, uint32(expiration.Unix()), extractedExpiration,
		"expiration should be Unix seconds (4 bytes), not milliseconds")
	offset += 4

	// Remaining bytes should be the message body (without 16-byte standard I2NP header)
	// At minimum, should have some body data
	assert.Greater(t, len(payload)-offset, 0, "clove should have message body")
}

// TestNewSessionMessageFormat tests that New Session messages follow the correct format.
func TestNewSessionMessageFormat(t *testing.T) {
	sm, destPubKey, destHash := setupNewGarlicSession(t)

	builder, _ := NewGarlicBuilderWithDefaults()
	dataMsg := NewDataMessage([]byte("format test"))
	builder.AddLocalDeliveryClove(dataMsg, 1)

	ciphertext, err := EncryptGarlicWithBuilder(sm, builder, destHash, destPubKey)
	require.NoError(t, err)

	// New Session format: [ephemeralPubKey(32)] + [nonce(12)] + [ciphertext(N)] + [tag(16)]
	minLen := 32 + 12 + 16
	assert.GreaterOrEqual(t, len(ciphertext), minLen, "New Session message length")

	ephemeralKey := ciphertext[:32]
	allZero := true
	for _, b := range ephemeralKey {
		if b != 0 {
			allZero = false
			break
		}
	}
	assert.False(t, allZero, "ephemeral public key should not be all zeros")
}

// TestExistingSessionMessageFormat tests that Existing Session messages follow the correct format.
func TestExistingSessionMessageFormat(t *testing.T) {
	sm, err := GenerateGarlicSessionManager()
	require.NoError(t, err)

	receiverSM, err := GenerateGarlicSessionManager()
	require.NoError(t, err)

	destPubKey := receiverSM.GetPublicKey()
	destHash := completeGarlicHandshake(t, sm, receiverSM, destPubKey)

	builder2, _ := NewGarlicBuilderWithDefaults()
	dataMsg2 := NewDataMessage([]byte("second"))
	builder2.AddLocalDeliveryClove(dataMsg2, 2)
	ciphertext2, err := EncryptGarlicWithBuilder(sm, builder2, destHash, destPubKey)
	require.NoError(t, err, "second encrypt")

	// Existing Session: [sessionTag(8)] + [nonce(12)] + [ciphertext(N)] + [tag(16)]
	minLen := 8 + 12 + 16
	assert.GreaterOrEqual(t, len(ciphertext2), minLen, "Existing Session message length")

	sessionTag := ciphertext2[0:8]
	allZero := true
	for _, b := range sessionTag {
		if b != 0 {
			allZero = false
			break
		}
	}
	assert.False(t, allZero, "session tag should not be all zeros")
}
