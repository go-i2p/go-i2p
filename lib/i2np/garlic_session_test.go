package i2np

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/go-i2p/crypto/ecies"
)

// TestSessionManagerCreation tests creating a new session manager
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

// TestNewSessionEncryption tests encrypting a garlic message for a new session
func TestNewSessionEncryption(t *testing.T) {
	// Create session manager
	sm, err := GenerateGarlicSessionManager()
	if err != nil {
		t.Fatalf("Failed to generate session manager: %v", err)
	}

	// Generate destination key pair
	destPubBytes, _, err := ecies.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate destination key pair: %v", err)
	}

	var destPubKey [32]byte
	copy(destPubKey[:], destPubBytes)

	// Create destination hash
	destHash := sha256.Sum256(destPubKey[:])

	// Create a simple garlic message
	builder, err := NewGarlicBuilderWithDefaults()
	if err != nil {
		t.Fatalf("Failed to create garlic builder: %v", err)
	}

	// Add a simple data message
	dataMsg := NewDataMessage([]byte("test payload"))
	err = builder.AddLocalDeliveryClove(dataMsg, 1)
	if err != nil {
		t.Fatalf("Failed to add clove: %v", err)
	}

	// Encrypt garlic message
	ciphertext, err := EncryptGarlicWithBuilder(sm, builder, destHash, destPubKey)
	if err != nil {
		t.Fatalf("Failed to encrypt garlic message: %v", err)
	}

	// Verify ciphertext is not empty
	if len(ciphertext) == 0 {
		t.Fatal("Encrypted garlic message is empty")
	}

	// Verify session was created
	if sm.GetSessionCount() != 1 {
		t.Errorf("Expected 1 session after encryption, got %d", sm.GetSessionCount())
	}

	// Verify ciphertext is different from plaintext
	plaintext, err := builder.BuildAndSerialize()
	if err != nil {
		t.Fatalf("Failed to serialize garlic: %v", err)
	}

	if bytes.Equal(ciphertext, plaintext) {
		t.Error("Ciphertext should not equal plaintext")
	}
}

// TestNewSessionDecryption tests decrypting a new session garlic message
func TestNewSessionDecryption(t *testing.T) {
	// Create sender session manager
	senderSM, err := GenerateGarlicSessionManager()
	if err != nil {
		t.Fatalf("Failed to generate sender session manager: %v", err)
	}

	// Generate receiver key pair
	receiverPubBytes, receiverPrivBytes, err := ecies.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate receiver key pair: %v", err)
	}

	var receiverPubKey, receiverPrivKey [32]byte
	copy(receiverPubKey[:], receiverPubBytes)
	copy(receiverPrivKey[:], receiverPrivBytes)

	// Create receiver session manager with known private key
	receiverSM, err := NewGarlicSessionManager(receiverPrivKey)
	if err != nil {
		t.Fatalf("Failed to create receiver session manager: %v", err)
	}

	// Create destination hash
	destHash := sha256.Sum256(receiverPubKey[:])

	// Create garlic message
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

	// Get original plaintext
	originalPlaintext, err := builder.BuildAndSerialize()
	if err != nil {
		t.Fatalf("Failed to serialize original garlic: %v", err)
	}

	// Encrypt
	ciphertext, err := EncryptGarlicWithBuilder(senderSM, builder, destHash, receiverPubKey)
	if err != nil {
		t.Fatalf("Failed to encrypt garlic message: %v", err)
	}

	// Decrypt
	decryptedPlaintext, sessionTag, err := receiverSM.DecryptGarlicMessage(ciphertext)
	if err != nil {
		t.Fatalf("Failed to decrypt garlic message: %v", err)
	}

	// Verify session tag is empty for new session
	emptyTag := [8]byte{}
	if sessionTag != emptyTag {
		t.Error("Expected empty session tag for new session")
	}

	// Verify decrypted plaintext matches original
	if !bytes.Equal(decryptedPlaintext, originalPlaintext) {
		t.Errorf("Decrypted plaintext does not match original.\nExpected: %x\nGot: %x",
			originalPlaintext, decryptedPlaintext)
	}
}

// TestSessionCleanup tests that expired sessions are properly cleaned up
func TestSessionCleanup(t *testing.T) {
	// Create session manager
	sm, err := GenerateGarlicSessionManager()
	if err != nil {
		t.Fatalf("Failed to generate session manager: %v", err)
	}

	// Set short timeout for testing
	sm.sessionTimeout = 100 * time.Millisecond

	// Generate destination key pair
	destPubBytes, _, err := ecies.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate destination key pair: %v", err)
	}

	var destPubKey [32]byte
	copy(destPubKey[:], destPubBytes)
	destHash := sha256.Sum256(destPubKey[:])

	// Create a session
	builder, err := NewGarlicBuilderWithDefaults()
	if err != nil {
		t.Fatalf("Failed to create garlic builder: %v", err)
	}

	dataMsg := NewDataMessage([]byte("test"))
	err = builder.AddLocalDeliveryClove(dataMsg, 1)
	if err != nil {
		t.Fatalf("Failed to add clove: %v", err)
	}

	_, err = EncryptGarlicWithBuilder(sm, builder, destHash, destPubKey)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Verify session exists
	if sm.GetSessionCount() != 1 {
		t.Errorf("Expected 1 session, got %d", sm.GetSessionCount())
	}

	// Wait for session to expire
	time.Sleep(150 * time.Millisecond)

	// Cleanup expired sessions
	removed := sm.CleanupExpiredSessions()
	if removed != 1 {
		t.Errorf("Expected to remove 1 session, removed %d", removed)
	}

	// Verify session was removed
	if sm.GetSessionCount() != 0 {
		t.Errorf("Expected 0 sessions after cleanup, got %d", sm.GetSessionCount())
	}
}

// TestWrapInGarlicMessage tests wrapping encrypted data in I2NP Garlic message
func TestWrapInGarlicMessage(t *testing.T) {
	encryptedData := []byte("encrypted garlic payload data")

	msg, err := WrapInGarlicMessage(encryptedData)
	if err != nil {
		t.Fatalf("Failed to wrap garlic message: %v", err)
	}

	// Verify message type
	if msg.Type() != I2NP_MESSAGE_TYPE_GARLIC {
		t.Errorf("Expected message type %d, got %d", I2NP_MESSAGE_TYPE_GARLIC, msg.Type())
	}

	// Verify payload
	if !bytes.Equal(msg.data, encryptedData) {
		t.Error("Message payload does not match encrypted data")
	}

	// Verify message ID was set
	if msg.MessageID() == 0 {
		t.Error("Message ID should not be zero")
	}

	// Verify expiration is in the future
	if msg.Expiration().Before(time.Now()) {
		t.Error("Message expiration should be in the future")
	}
}

// TestWrapInGarlicMessage_EmptyData tests error handling for empty data
func TestWrapInGarlicMessage_EmptyData(t *testing.T) {
	_, err := WrapInGarlicMessage([]byte{})
	if err == nil {
		t.Error("Expected error when wrapping empty data")
	}
}
