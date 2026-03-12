package i2np

import (
	"bytes"
	"testing"
	"time"

	"github.com/go-i2p/crypto/ecies"
	"github.com/go-i2p/crypto/types"
	noiseratchet "github.com/go-i2p/go-noise/ratchet"
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
	if err != nil {
		t.Fatalf("NS encrypt failed: %v", err)
	}
	_, _, sessionHash, err := receiverSM.DecryptGarlicMessage(ct1)
	if err != nil {
		t.Fatalf("NS decrypt failed: %v", err)
	}
	if sessionHash == nil {
		t.Fatal("sessionHash must be non-nil for New Session")
	}

	nsrPayload, err := noiseratchet.BuildNSPayload([]byte("nsr"))
	if err != nil {
		t.Fatalf("Failed to build NSR payload: %v", err)
	}
	nsrMsg, err := receiverSM.EncryptNewSessionReply(*sessionHash, nsrPayload)
	if err != nil {
		t.Fatalf("Failed to encrypt NSR: %v", err)
	}
	_, _, _, err = senderSM.DecryptGarlicMessage(nsrMsg)
	if err != nil {
		t.Fatalf("Sender failed to process NSR: %v", err)
	}

	return destHash
}

// setupGarlicSenderReceiver creates a sender and receiver GarlicSessionManager pair
// along with the receiver's public key for use in garlic encryption tests.
func setupGarlicSenderReceiver(t *testing.T) (senderSM, receiverSM *GarlicSessionManager, receiverPubKey [32]byte) {
	t.Helper()
	senderSM, err := GenerateGarlicSessionManager()
	if err != nil {
		t.Fatalf("Failed to generate sender session manager: %v", err)
	}

	receiverPubBytes, receiverPrivBytes, err := ecies.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate receiver key pair: %v", err)
	}

	var receiverPrivKey [32]byte
	copy(receiverPubKey[:], receiverPubBytes)
	copy(receiverPrivKey[:], receiverPrivBytes)

	receiverSM, err = NewGarlicSessionManager(receiverPrivKey)
	if err != nil {
		t.Fatalf("Failed to create receiver session manager: %v", err)
	}

	return senderSM, receiverSM, receiverPubKey
}

// TestSessionManagerCreation tests creating a new session manager.
func TestSessionManagerCreation(t *testing.T) {
	sm, err := GenerateGarlicSessionManager()
	if err != nil {
		t.Fatalf("Failed to generate session manager: %v", err)
	}

	if sm == nil {
		t.Fatal("Session manager is nil")
	}

	if sm.GetSessionCount() != 0 {
		t.Errorf("Expected 0 sessions, got %d", sm.GetSessionCount())
	}
}

// TestNewSessionManagerWithKey tests creating a session manager with a specific key.
func TestNewSessionManagerWithKey(t *testing.T) {
	_, privBytes, err := ecies.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	var privKey [32]byte
	copy(privKey[:], privBytes)

	sm, err := NewGarlicSessionManager(privKey)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	if sm == nil {
		t.Fatal("Session manager is nil")
	}
}

// TestNewSessionEncryption tests encrypting a garlic message for a new session.
func TestNewSessionEncryption(t *testing.T) {
	sm, err := GenerateGarlicSessionManager()
	if err != nil {
		t.Fatalf("Failed to generate session manager: %v", err)
	}

	destPubBytes, _, err := ecies.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate destination key pair: %v", err)
	}

	var destPubKey [32]byte
	copy(destPubKey[:], destPubBytes)
	destHash := types.SHA256(destPubKey[:])

	builder, err := NewGarlicBuilderWithDefaults()
	if err != nil {
		t.Fatalf("Failed to create garlic builder: %v", err)
	}

	dataMsg := NewDataMessage([]byte("test payload"))
	err = builder.AddLocalDeliveryClove(dataMsg, 1)
	if err != nil {
		t.Fatalf("Failed to add clove: %v", err)
	}

	ciphertext, err := EncryptGarlicWithBuilder(sm, builder, destHash, destPubKey)
	if err != nil {
		t.Fatalf("Failed to encrypt garlic message: %v", err)
	}

	if len(ciphertext) == 0 {
		t.Fatal("Encrypted garlic message is empty")
	}

	if sm.GetSessionCount() != 1 {
		t.Errorf("Expected 1 session after encryption, got %d", sm.GetSessionCount())
	}

	plaintext, err := builder.BuildAndSerialize()
	if err != nil {
		t.Fatalf("Failed to serialize garlic: %v", err)
	}

	if bytes.Equal(ciphertext, plaintext) {
		t.Error("Ciphertext should not equal plaintext")
	}
}

// TestNewSessionDecryption tests decrypting a new session garlic message.
func TestNewSessionDecryption(t *testing.T) {
	senderSM, receiverSM, receiverPubKey := setupGarlicSenderReceiver(t)

	destHash := types.SHA256(receiverPubKey[:])

	builder, err := NewGarlicBuilderWithDefaults()
	if err != nil {
		t.Fatalf("Failed to create garlic builder: %v", err)
	}

	testPayload := []byte("secret test data")
	dataMsg := NewDataMessage(testPayload)
	err = builder.AddLocalDeliveryClove(dataMsg, 1)
	if err != nil {
		t.Fatalf("Failed to add clove: %v", err)
	}

	originalPlaintext, err := builder.BuildAndSerialize()
	if err != nil {
		t.Fatalf("Failed to serialize original garlic: %v", err)
	}

	ciphertext, err := EncryptGarlicWithBuilder(senderSM, builder, destHash, receiverPubKey)
	if err != nil {
		t.Fatalf("Failed to encrypt garlic message: %v", err)
	}

	decryptedPlaintext, sessionTag, _, err := receiverSM.DecryptGarlicMessage(ciphertext)
	if err != nil {
		t.Fatalf("Failed to decrypt garlic message: %v", err)
	}

	emptyTag := [8]byte{}
	if sessionTag != emptyTag {
		t.Error("Expected empty session tag for new session")
	}

	if !bytes.Equal(decryptedPlaintext, originalPlaintext) {
		t.Errorf("Decrypted plaintext does not match original.\nExpected: %x\nGot: %x",
			originalPlaintext, decryptedPlaintext)
	}
}

// TestExistingSessionEncryptDecrypt tests encrypt/decrypt round-trip via existing session.
func TestExistingSessionEncryptDecrypt(t *testing.T) {
	senderSM, receiverSM, receiverPubKey := setupGarlicSenderReceiver(t)

	destHash := completeGarlicHandshake(t, senderSM, receiverSM, receiverPubKey)

	// Second message (Existing Session)
	builder2, _ := NewGarlicBuilderWithDefaults()
	dataMsg2 := NewDataMessage([]byte("second message"))
	builder2.AddLocalDeliveryClove(dataMsg2, 2)
	original2, _ := builder2.BuildAndSerialize()

	ct2, err := EncryptGarlicWithBuilder(senderSM, builder2, destHash, receiverPubKey)
	if err != nil {
		t.Fatalf("Second encrypt failed: %v", err)
	}

	dec2, tag2, _, err := receiverSM.DecryptGarlicMessage(ct2)
	if err != nil {
		t.Fatalf("Second decrypt failed: %v", err)
	}

	if tag2 == ([8]byte{}) {
		t.Error("Expected non-empty session tag for existing session")
	}

	if !bytes.Equal(dec2, original2) {
		t.Error("Decrypted plaintext doesn't match for existing session")
	}
}

// TestMultipleDestinations tests encrypting for different destinations.
func TestMultipleDestinations(t *testing.T) {
	sm, err := GenerateGarlicSessionManager()
	if err != nil {
		t.Fatalf("Failed to generate session manager: %v", err)
	}

	for i := 0; i < 5; i++ {
		destPubBytes, _, err := ecies.GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair %d: %v", i, err)
		}

		var destPubKey [32]byte
		copy(destPubKey[:], destPubBytes)
		destHash := types.SHA256(destPubKey[:])

		builder, _ := NewGarlicBuilderWithDefaults()
		dataMsg := NewDataMessage([]byte("multi-dest"))
		builder.AddLocalDeliveryClove(dataMsg, i)

		_, err = EncryptGarlicWithBuilder(sm, builder, destHash, destPubKey)
		if err != nil {
			t.Fatalf("Encrypt for destination %d failed: %v", i, err)
		}
	}

	if sm.GetSessionCount() != 5 {
		t.Errorf("Expected 5 sessions, got %d", sm.GetSessionCount())
	}
}

// TestWrapInGarlicMessage tests wrapping encrypted data in I2NP Garlic message.
func TestWrapInGarlicMessage(t *testing.T) {
	encryptedData := []byte("encrypted garlic payload data")

	msg, err := WrapInGarlicMessage(encryptedData)
	if err != nil {
		t.Fatalf("Failed to wrap garlic message: %v", err)
	}

	if msg.Type() != I2NP_MESSAGE_TYPE_GARLIC {
		t.Errorf("Expected message type %d, got %d", I2NP_MESSAGE_TYPE_GARLIC, msg.Type())
	}

	if !bytes.Equal(msg.data, encryptedData) {
		t.Error("Message payload does not match encrypted data")
	}

	if msg.MessageID() == 0 {
		t.Error("Message ID should not be zero")
	}

	if msg.Expiration().Before(time.Now()) {
		t.Error("Message expiration should be in the future")
	}
}

// TestWrapInGarlicMessage_EmptyData tests error handling for empty data.
func TestWrapInGarlicMessage_EmptyData(t *testing.T) {
	_, err := WrapInGarlicMessage([]byte{})
	if err == nil {
		t.Error("Expected error when wrapping empty data")
	}
}

// TestNewSessionMessageFormat tests that New Session messages follow the correct format.
func TestNewSessionMessageFormat(t *testing.T) {
	sm, err := GenerateGarlicSessionManager()
	if err != nil {
		t.Fatalf("Failed to generate session manager: %v", err)
	}

	destPubBytes, _, err := ecies.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate destination key pair: %v", err)
	}

	var destPubKey [32]byte
	copy(destPubKey[:], destPubBytes)
	destHash := types.SHA256(destPubKey[:])

	builder, _ := NewGarlicBuilderWithDefaults()
	dataMsg := NewDataMessage([]byte("format test"))
	builder.AddLocalDeliveryClove(dataMsg, 1)

	ciphertext, err := EncryptGarlicWithBuilder(sm, builder, destHash, destPubKey)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// New Session format: [ephemeralPubKey(32)] + [nonce(12)] + [ciphertext(N)] + [tag(16)]
	minLen := 32 + 12 + 16
	if len(ciphertext) < minLen {
		t.Errorf("New Session message too short: got %d bytes, expected at least %d", len(ciphertext), minLen)
	}

	// Ephemeral public key should not be all zeros
	ephemeralKey := ciphertext[:32]
	allZero := true
	for _, b := range ephemeralKey {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Ephemeral public key should not be all zeros")
	}
}

// TestExistingSessionMessageFormat tests that Existing Session messages follow the correct format.
func TestExistingSessionMessageFormat(t *testing.T) {
	sm, err := GenerateGarlicSessionManager()
	if err != nil {
		t.Fatalf("Failed to generate session manager: %v", err)
	}

	receiverSM, err := GenerateGarlicSessionManager()
	if err != nil {
		t.Fatalf("Failed to generate receiver session manager: %v", err)
	}

	destPubKey := receiverSM.GetPublicKey()
	destHash := completeGarlicHandshake(t, sm, receiverSM, destPubKey)

	// Second message uses existing session (handshake complete)
	builder2, _ := NewGarlicBuilderWithDefaults()
	dataMsg2 := NewDataMessage([]byte("second"))
	builder2.AddLocalDeliveryClove(dataMsg2, 2)
	ciphertext2, err := EncryptGarlicWithBuilder(sm, builder2, destHash, destPubKey)
	if err != nil {
		t.Fatalf("Failed to encrypt second message: %v", err)
	}

	// Existing Session: [sessionTag(8)] + [nonce(12)] + [ciphertext(N)] + [tag(16)]
	minLen := 8 + 12 + 16
	if len(ciphertext2) < minLen {
		t.Errorf("Existing Session message too short: got %d bytes, expected at least %d", len(ciphertext2), minLen)
	}

	// Session tag should not be all zeros
	sessionTag := ciphertext2[0:8]
	allZero := true
	for _, b := range sessionTag {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Session tag should not be all zeros")
	}
}
