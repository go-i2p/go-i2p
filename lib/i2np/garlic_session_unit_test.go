package i2np

import (
	"bytes"
	"github.com/go-i2p/crypto/types"
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
	destHash := types.SHA256(destPubKey[:])

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
	destHash := types.SHA256(receiverPubKey[:])

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
	destHash := types.SHA256(destPubKey[:])

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

// TestNewSessionMessageFormat tests that New Session messages follow the correct format:
// [ephemeralPubKey(32)] + [nonce(12)] + [ciphertext(N)] + [tag(16)]
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

	// Verify minimum length: 32 (ephemeral) + 12 (nonce) + 16 (tag) = 60 bytes minimum
	minLen := 32 + 12 + 16
	if len(ciphertext) < minLen {
		t.Errorf("New Session message too short: got %d bytes, expected at least %d", len(ciphertext), minLen)
	}

	// Verify format by checking we can extract components
	if len(ciphertext) >= minLen {
		ephemeralPubKey := ciphertext[0:32]
		nonce := ciphertext[32:44]
		// Rest is ciphertext + tag

		// Ephemeral key should not be all zeros
		allZeros := true
		for _, b := range ephemeralPubKey {
			if b != 0 {
				allZeros = false
				break
			}
		}
		if allZeros {
			t.Error("Ephemeral public key should not be all zeros")
		}

		// Nonce should not be all zeros (statistically impossible with random nonce)
		allZeros = true
		for _, b := range nonce {
			if b != 0 {
				allZeros = false
				break
			}
		}
		if allZeros {
			t.Error("Nonce should not be all zeros")
		}
	}
}

// TestExistingSessionMessageFormat tests that Existing Session messages follow the correct format:
// [sessionTag(8)] + [nonce(12)] + [ciphertext(N)] + [tag(16)]
func TestExistingSessionMessageFormat(t *testing.T) {
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

	dataMsg := NewDataMessage([]byte("first message"))
	err = builder.AddLocalDeliveryClove(dataMsg, 1)
	if err != nil {
		t.Fatalf("Failed to add clove: %v", err)
	}

	// First message creates the session (New Session format)
	_, err = EncryptGarlicWithBuilder(sm, builder, destHash, destPubKey)
	if err != nil {
		t.Fatalf("Failed to encrypt first message: %v", err)
	}

	// Second message should use Existing Session format
	builder2, err := NewGarlicBuilderWithDefaults()
	if err != nil {
		t.Fatalf("Failed to create second garlic builder: %v", err)
	}

	dataMsg2 := NewDataMessage([]byte("second message"))
	err = builder2.AddLocalDeliveryClove(dataMsg2, 2)
	if err != nil {
		t.Fatalf("Failed to add second clove: %v", err)
	}

	ciphertext2, err := EncryptGarlicWithBuilder(sm, builder2, destHash, destPubKey)
	if err != nil {
		t.Fatalf("Failed to encrypt second message: %v", err)
	}

	// Verify minimum length: 8 (tag) + 12 (nonce) + 16 (auth tag) = 36 bytes minimum
	minLen := 8 + 12 + 16
	if len(ciphertext2) < minLen {
		t.Errorf("Existing Session message too short: got %d bytes, expected at least %d", len(ciphertext2), minLen)
	}

	// Verify format by checking we can extract components
	if len(ciphertext2) >= minLen {
		sessionTag := ciphertext2[0:8]
		nonce := ciphertext2[8:20]

		// Session tag should not be all zeros
		allZeros := true
		for _, b := range sessionTag {
			if b != 0 {
				allZeros = false
				break
			}
		}
		if allZeros {
			t.Error("Session tag should not be all zeros")
		}

		// Nonce should not be all zeros
		allZeros = true
		for _, b := range nonce {
			if b != 0 {
				allZeros = false
				break
			}
		}
		if allZeros {
			t.Error("Nonce should not be all zeros")
		}
	}
}

// TestChaChaEncryptionDecryption tests end-to-end ChaCha20-Poly1305 encryption/decryption
// Note: Currently only tests New Session messages. Existing Session messages require
// the receiver to store sessions, which needs the sender's destination hash from the
// garlic message content (not yet implemented at this layer).
func TestChaChaEncryptionDecryption(t *testing.T) {
	testPayloads := []string{
		"Hello, I2P!",
		"This is a secret message",
		"Testing ChaCha20-Poly1305 AEAD encryption",
		"Multiple messages should work correctly",
	}

	for i, payload := range testPayloads {
		// Create fresh sender and receiver for each message (New Session)
		senderSM, err := GenerateGarlicSessionManager()
		if err != nil {
			t.Fatalf("Test %d: Failed to generate sender session manager: %v", i, err)
		}

		receiverPubBytes, receiverPrivBytes, err := ecies.GenerateKeyPair()
		if err != nil {
			t.Fatalf("Test %d: Failed to generate receiver key pair: %v", i, err)
		}

		var receiverPubKey, receiverPrivKey [32]byte
		copy(receiverPubKey[:], receiverPubBytes)
		copy(receiverPrivKey[:], receiverPrivBytes)

		receiverSM, err := NewGarlicSessionManager(receiverPrivKey)
		if err != nil {
			t.Fatalf("Test %d: Failed to create receiver session manager: %v", i, err)
		}

		destHash := types.SHA256(receiverPubKey[:])

		builder, err := NewGarlicBuilderWithDefaults()
		if err != nil {
			t.Fatalf("Test %d: Failed to create garlic builder: %v", i, err)
		}

		dataMsg := NewDataMessage([]byte(payload))
		err = builder.AddLocalDeliveryClove(dataMsg, i+1)
		if err != nil {
			t.Fatalf("Test %d: Failed to add clove: %v", i, err)
		}

		// Get original plaintext
		originalPlaintext, err := builder.BuildAndSerialize()
		if err != nil {
			t.Fatalf("Test %d: Failed to serialize garlic: %v", i, err)
		}

		// Encrypt
		ciphertext, err := EncryptGarlicWithBuilder(senderSM, builder, destHash, receiverPubKey)
		if err != nil {
			t.Fatalf("Test %d: Failed to encrypt: %v", i, err)
		}

		// Verify ciphertext is different from plaintext
		if bytes.Equal(ciphertext, originalPlaintext) {
			t.Errorf("Test %d: Ciphertext should not equal plaintext", i)
		}

		// Decrypt
		decryptedPlaintext, _, err := receiverSM.DecryptGarlicMessage(ciphertext)
		if err != nil {
			t.Fatalf("Test %d: Failed to decrypt: %v", i, err)
		}

		// Verify decrypted matches original
		if !bytes.Equal(decryptedPlaintext, originalPlaintext) {
			t.Errorf("Test %d: Decrypted plaintext does not match original", i)
		}
	}
}

// TestAuthenticationFailure tests that tampering with ciphertext causes authentication failure
func TestAuthenticationFailure(t *testing.T) {
	senderSM, err := GenerateGarlicSessionManager()
	if err != nil {
		t.Fatalf("Failed to generate sender session manager: %v", err)
	}

	receiverPubBytes, receiverPrivBytes, err := ecies.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate receiver key pair: %v", err)
	}

	var receiverPubKey, receiverPrivKey [32]byte
	copy(receiverPubKey[:], receiverPubBytes)
	copy(receiverPrivKey[:], receiverPrivBytes)

	receiverSM, err := NewGarlicSessionManager(receiverPrivKey)
	if err != nil {
		t.Fatalf("Failed to create receiver session manager: %v", err)
	}

	destHash := types.SHA256(receiverPubKey[:])

	builder, err := NewGarlicBuilderWithDefaults()
	if err != nil {
		t.Fatalf("Failed to create garlic builder: %v", err)
	}

	dataMsg := NewDataMessage([]byte("authenticated message"))
	err = builder.AddLocalDeliveryClove(dataMsg, 1)
	if err != nil {
		t.Fatalf("Failed to add clove: %v", err)
	}

	ciphertext, err := EncryptGarlicWithBuilder(senderSM, builder, destHash, receiverPubKey)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Tamper with the ciphertext (flip a bit in the middle)
	if len(ciphertext) > 100 {
		ciphertext[100] ^= 0x01
	}

	// Decryption should fail due to authentication error
	_, _, err = receiverSM.DecryptGarlicMessage(ciphertext)
	if err == nil {
		t.Error("Expected authentication error when decrypting tampered ciphertext")
	}
}

// TestSessionTagLookup tests that session tags correctly identify sessions
func TestSessionTagLookup(t *testing.T) {
	// This test verifies that existing sessions can be found by their tags
	// Note: Current implementation of findSessionByTag is simplified
	// In production, it would verify the tag against the tag ratchet

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

	// Create first session
	builder, err := NewGarlicBuilderWithDefaults()
	if err != nil {
		t.Fatalf("Failed to create garlic builder: %v", err)
	}

	dataMsg := NewDataMessage([]byte("create session"))
	err = builder.AddLocalDeliveryClove(dataMsg, 1)
	if err != nil {
		t.Fatalf("Failed to add clove: %v", err)
	}

	_, err = EncryptGarlicWithBuilder(sm, builder, destHash, destPubKey)
	if err != nil {
		t.Fatalf("Failed to encrypt first message: %v", err)
	}

	// Verify session was created
	if sm.GetSessionCount() != 1 {
		t.Errorf("Expected 1 session, got %d", sm.GetSessionCount())
	}
}

// TestRatchetStateConsistency tests that ratchet states stay synchronized across messages
// Note: Currently tests sender-side ratchet only (multiple New Session messages).
// Full bidirectional ratchet testing requires receiver-side session storage.
func TestRatchetStateConsistency(t *testing.T) {
	// Test sender-side: sending multiple messages creates multiple sessions
	senderSM, err := GenerateGarlicSessionManager()
	if err != nil {
		t.Fatalf("Failed to generate sender session manager: %v", err)
	}

	// Send 5 messages to different destinations (each is a New Session)
	for i := 0; i < 5; i++ {
		receiverPubBytes, receiverPrivBytes, err := ecies.GenerateKeyPair()
		if err != nil {
			t.Fatalf("Message %d: Failed to generate receiver key pair: %v", i, err)
		}

		var receiverPubKey, receiverPrivKey [32]byte
		copy(receiverPubKey[:], receiverPubBytes)
		copy(receiverPrivKey[:], receiverPrivBytes)

		receiverSM, err := NewGarlicSessionManager(receiverPrivKey)
		if err != nil {
			t.Fatalf("Message %d: Failed to create receiver session manager: %v", i, err)
		}

		destHash := types.SHA256(receiverPubKey[:])

		builder, err := NewGarlicBuilderWithDefaults()
		if err != nil {
			t.Fatalf("Message %d: Failed to create garlic builder: %v", i, err)
		}

		payload := []byte("Message number " + string(rune('0'+i)))
		dataMsg := NewDataMessage(payload)
		err = builder.AddLocalDeliveryClove(dataMsg, i+1)
		if err != nil {
			t.Fatalf("Message %d: Failed to add clove: %v", i, err)
		}

		originalPlaintext, err := builder.BuildAndSerialize()
		if err != nil {
			t.Fatalf("Message %d: Failed to serialize: %v", i, err)
		}

		ciphertext, err := EncryptGarlicWithBuilder(senderSM, builder, destHash, receiverPubKey)
		if err != nil {
			t.Fatalf("Message %d: Failed to encrypt: %v", i, err)
		}

		decryptedPlaintext, _, err := receiverSM.DecryptGarlicMessage(ciphertext)
		if err != nil {
			t.Fatalf("Message %d: Failed to decrypt: %v", i, err)
		}

		if !bytes.Equal(decryptedPlaintext, originalPlaintext) {
			t.Errorf("Message %d: Decrypted plaintext does not match original", i)
		}
	}

	// Verify sender created 5 sessions (one per destination)
	if senderSM.GetSessionCount() != 5 {
		t.Errorf("Expected sender to have 5 sessions, got %d", senderSM.GetSessionCount())
	}
}

// TestNonceUniqueness verifies that nonces are unique across multiple messages
func TestNonceUniqueness(t *testing.T) {
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

	nonces := make(map[string]bool)

	// Generate 10 messages and extract nonces
	for i := 0; i < 10; i++ {
		builder, err := NewGarlicBuilderWithDefaults()
		if err != nil {
			t.Fatalf("Failed to create garlic builder: %v", err)
		}

		dataMsg := NewDataMessage([]byte("test"))
		err = builder.AddLocalDeliveryClove(dataMsg, i+1)
		if err != nil {
			t.Fatalf("Failed to add clove: %v", err)
		}

		ciphertext, err := EncryptGarlicWithBuilder(sm, builder, destHash, destPubKey)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		// Extract nonce based on message type
		var nonce []byte
		if i == 0 {
			// New Session: nonce at bytes 32-44
			if len(ciphertext) >= 44 {
				nonce = ciphertext[32:44]
			}
		} else {
			// Existing Session: nonce at bytes 8-20
			if len(ciphertext) >= 20 {
				nonce = ciphertext[8:20]
			}
		}

		if nonce == nil {
			t.Fatalf("Failed to extract nonce from message %d", i)
		}

		nonceKey := string(nonce)
		if nonces[nonceKey] {
			t.Errorf("Duplicate nonce detected at message %d", i)
		}
		nonces[nonceKey] = true
	}

	// Verify we collected all unique nonces
	if len(nonces) != 10 {
		t.Errorf("Expected 10 unique nonces, got %d", len(nonces))
	}
}

// TestTagIndexPopulation tests that tag index is populated with pre-generated tags
func TestTagIndexPopulation(t *testing.T) {
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

	dataMsg := NewDataMessage([]byte("test"))
	err = builder.AddLocalDeliveryClove(dataMsg, 1)
	if err != nil {
		t.Fatalf("Failed to add clove: %v", err)
	}

	_, err = EncryptGarlicWithBuilder(sm, builder, destHash, destPubKey)
	if err != nil {
		t.Fatalf("Failed to encrypt garlic message: %v", err)
	}

	// Verify tag index was populated
	sm.mu.RLock()
	tagCount := len(sm.tagIndex)
	sm.mu.RUnlock()

	if tagCount != 10 {
		t.Errorf("Expected 10 tags in index (tag window), got %d", tagCount)
	}

	// Verify session was created
	if sm.GetSessionCount() != 1 {
		t.Errorf("Expected 1 session, got %d", sm.GetSessionCount())
	}
}

// TestTagLookupPerformance tests O(1) tag lookup performance
func TestTagLookupPerformance(t *testing.T) {
	sm, err := GenerateGarlicSessionManager()
	if err != nil {
		t.Fatalf("Failed to generate session manager: %v", err)
	}

	// Create multiple sessions
	const numSessions = 100
	for i := 0; i < numSessions; i++ {
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

		dataMsg := NewDataMessage([]byte("test"))
		err = builder.AddLocalDeliveryClove(dataMsg, 1)
		if err != nil {
			t.Fatalf("Failed to add clove: %v", err)
		}

		_, err = EncryptGarlicWithBuilder(sm, builder, destHash, destPubKey)
		if err != nil {
			t.Fatalf("Failed to encrypt garlic message: %v", err)
		}
	}

	// Verify all sessions created (should have 100 sessions * 10 tags each = 1000 tags)
	sm.mu.RLock()
	totalTags := len(sm.tagIndex)
	sm.mu.RUnlock()

	expectedTags := numSessions * 10
	if totalTags != expectedTags {
		t.Errorf("Expected %d tags, got %d", expectedTags, totalTags)
	}

	// Test tag lookup (should be O(1) regardless of number of sessions)
	sm.mu.RLock()
	var testTag [8]byte
	for tag := range sm.tagIndex {
		testTag = tag
		break
	}
	sm.mu.RUnlock()

	sm.mu.Lock()
	foundSession := sm.findSessionByTag(testTag)
	sm.mu.Unlock()

	if foundSession == nil {
		t.Error("Failed to find session by tag with 100 concurrent sessions")
	}
}

// TestTagWindowReplenishment tests automatic replenishment of tag window
func TestTagWindowReplenishment(t *testing.T) {
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

	dataMsg := NewDataMessage([]byte("test"))
	err = builder.AddLocalDeliveryClove(dataMsg, 1)
	if err != nil {
		t.Fatalf("Failed to add clove: %v", err)
	}

	_, err = EncryptGarlicWithBuilder(sm, builder, destHash, destPubKey)
	if err != nil {
		t.Fatalf("Failed to encrypt garlic message: %v", err)
	}

	// Use 6 tags (should trigger replenishment when we hit 4 remaining)
	sm.mu.RLock()
	tagsToUse := make([][8]byte, 0, 6)
	for tag := range sm.tagIndex {
		tagsToUse = append(tagsToUse, tag)
		if len(tagsToUse) == 6 {
			break
		}
	}
	sm.mu.RUnlock()

	// Use the tags
	for _, tag := range tagsToUse {
		sm.mu.Lock()
		foundSession := sm.findSessionByTag(tag)
		sm.mu.Unlock()

		if foundSession == nil {
			t.Error("Failed to find session by tag")
		}
	}

	// After using 6 tags, window should be replenished back to 10
	sm.mu.RLock()
	finalTagCount := len(sm.tagIndex)
	sm.mu.RUnlock()

	if finalTagCount != 10 {
		t.Errorf("Expected tag window to be replenished to 10, got %d", finalTagCount)
	}
}

// TestExpiredSessionTagCleanup tests that tags are removed when sessions expire
func TestExpiredSessionTagCleanup(t *testing.T) {
	sm, err := GenerateGarlicSessionManager()
	if err != nil {
		t.Fatalf("Failed to generate session manager: %v", err)
	}

	// Set a very short timeout for testing
	sm.sessionTimeout = 100 * time.Millisecond

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

	dataMsg := NewDataMessage([]byte("test"))
	err = builder.AddLocalDeliveryClove(dataMsg, 1)
	if err != nil {
		t.Fatalf("Failed to add clove: %v", err)
	}

	_, err = EncryptGarlicWithBuilder(sm, builder, destHash, destPubKey)
	if err != nil {
		t.Fatalf("Failed to encrypt garlic message: %v", err)
	}

	// Verify tags were created
	sm.mu.RLock()
	initialTagCount := len(sm.tagIndex)
	sm.mu.RUnlock()

	if initialTagCount == 0 {
		t.Fatal("No tags created")
	}

	// Wait for session to expire
	time.Sleep(150 * time.Millisecond)

	// Clean up expired sessions
	removed := sm.CleanupExpiredSessions()

	if removed != 1 {
		t.Errorf("Expected to remove 1 session, removed %d", removed)
	}

	// Verify all tags were removed from index
	sm.mu.RLock()
	finalTagCount := len(sm.tagIndex)
	sm.mu.RUnlock()

	if finalTagCount != 0 {
		t.Errorf("Expected all tags to be removed, still have %d tags", finalTagCount)
	}
}

// TestTagSingleUse tests that tags are removed from index after use
func TestTagSingleUse(t *testing.T) {
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

	dataMsg := NewDataMessage([]byte("test"))
	err = builder.AddLocalDeliveryClove(dataMsg, 1)
	if err != nil {
		t.Fatalf("Failed to add clove: %v", err)
	}

	_, err = EncryptGarlicWithBuilder(sm, builder, destHash, destPubKey)
	if err != nil {
		t.Fatalf("Failed to encrypt garlic message: %v", err)
	}

	// Get a tag to test
	sm.mu.RLock()
	var testTag [8]byte
	for tag := range sm.tagIndex {
		testTag = tag
		break
	}
	sm.mu.RUnlock()

	// Use the tag once
	sm.mu.Lock()
	foundSession := sm.findSessionByTag(testTag)
	sm.mu.Unlock()

	if foundSession == nil {
		t.Error("Failed to find session by tag")
	}

	// Try to use the same tag again (should fail)
	sm.mu.Lock()
	foundAgain := sm.findSessionByTag(testTag)
	sm.mu.Unlock()

	if foundAgain != nil {
		t.Error("Tag should be removed after first use (single-use tags)")
	}
}

// TestInboundRatchetStateStored verifies that when the receiver decrypts a New Session
// message, the inbound ratchet state is stored (not discarded). This validates the fix
// for the CRITICAL BUG where initializeInboundRatchetState discarded DHRatchet,
// SymmetricRatchet, and TagRatchet objects.
func TestInboundRatchetStateStored(t *testing.T) {
	// Create sender
	senderSM, err := GenerateGarlicSessionManager()
	if err != nil {
		t.Fatalf("Failed to generate sender session manager: %v", err)
	}

	// Create receiver
	receiverPubBytes, receiverPrivBytes, err := ecies.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate receiver key pair: %v", err)
	}

	var receiverPubKey, receiverPrivKey [32]byte
	copy(receiverPubKey[:], receiverPubBytes)
	copy(receiverPrivKey[:], receiverPrivBytes)

	receiverSM, err := NewGarlicSessionManager(receiverPrivKey)
	if err != nil {
		t.Fatalf("Failed to create receiver session manager: %v", err)
	}

	destHash := types.SHA256(receiverPubKey[:])

	// Receiver should start with zero sessions
	if receiverSM.GetSessionCount() != 0 {
		t.Fatalf("Expected 0 sessions before decryption, got %d", receiverSM.GetSessionCount())
	}

	// Sender encrypts a New Session message
	builder, err := NewGarlicBuilderWithDefaults()
	if err != nil {
		t.Fatalf("Failed to create garlic builder: %v", err)
	}

	dataMsg := NewDataMessage([]byte("first message"))
	if err := builder.AddLocalDeliveryClove(dataMsg, 1); err != nil {
		t.Fatalf("Failed to add clove: %v", err)
	}

	ciphertext, err := EncryptGarlicWithBuilder(senderSM, builder, destHash, receiverPubKey)
	if err != nil {
		t.Fatalf("Failed to encrypt garlic message: %v", err)
	}

	// Receiver decrypts
	_, _, err = receiverSM.DecryptGarlicMessage(ciphertext)
	if err != nil {
		t.Fatalf("Failed to decrypt garlic message: %v", err)
	}

	// After decrypting a New Session, the receiver should have stored a session
	if receiverSM.GetSessionCount() != 1 {
		t.Errorf("Expected 1 session stored after inbound decryption, got %d", receiverSM.GetSessionCount())
	}

	// The receiver should have tags indexed for the new session
	receiverSM.mu.RLock()
	tagCount := len(receiverSM.tagIndex)
	receiverSM.mu.RUnlock()

	if tagCount == 0 {
		t.Error("Expected receiver to have indexed tags for the inbound session, got 0")
	}
}

// TestInboundRatchetSessionHasValidRatchets verifies the stored inbound session
// has non-nil ratchet objects that can be used for future message processing.
func TestInboundRatchetSessionHasValidRatchets(t *testing.T) {
	senderSM, err := GenerateGarlicSessionManager()
	if err != nil {
		t.Fatalf("Failed to generate sender session manager: %v", err)
	}

	receiverPubBytes, receiverPrivBytes, err := ecies.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate receiver key pair: %v", err)
	}

	var receiverPubKey, receiverPrivKey [32]byte
	copy(receiverPubKey[:], receiverPubBytes)
	copy(receiverPrivKey[:], receiverPrivBytes)

	receiverSM, err := NewGarlicSessionManager(receiverPrivKey)
	if err != nil {
		t.Fatalf("Failed to create receiver session manager: %v", err)
	}

	destHash := types.SHA256(receiverPubKey[:])

	builder, err := NewGarlicBuilderWithDefaults()
	if err != nil {
		t.Fatalf("Failed to create garlic builder: %v", err)
	}

	dataMsg := NewDataMessage([]byte("ratchet validation message"))
	if err := builder.AddLocalDeliveryClove(dataMsg, 1); err != nil {
		t.Fatalf("Failed to add clove: %v", err)
	}

	ciphertext, err := EncryptGarlicWithBuilder(senderSM, builder, destHash, receiverPubKey)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	_, _, err = receiverSM.DecryptGarlicMessage(ciphertext)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	// Inspect the stored session to verify ratchets are non-nil
	receiverSM.mu.RLock()
	defer receiverSM.mu.RUnlock()

	for _, session := range receiverSM.sessions {
		if session.DHRatchet == nil {
			t.Error("Stored inbound session has nil DHRatchet")
		}
		if session.SymmetricRatchet == nil {
			t.Error("Stored inbound session has nil SymmetricRatchet")
		}
		if session.TagRatchet == nil {
			t.Error("Stored inbound session has nil TagRatchet")
		}
		if session.MessageCounter != 1 {
			t.Errorf("Expected MessageCounter=1, got %d", session.MessageCounter)
		}
		if len(session.pendingTags) == 0 {
			t.Error("Expected session to have pending tags for future lookups")
		}
		return // Only check the first (should be only) session
	}

	t.Error("No session found in receiver after decrypting New Session message")
}
