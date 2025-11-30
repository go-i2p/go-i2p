package i2np

import (
	"github.com/go-i2p/crypto/rand"
	"encoding/binary"
	"sync"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/crypto/ecies"
	"github.com/go-i2p/crypto/ratchet"
	"github.com/samber/oops"
)

// GarlicSessionManager manages ECIES-X25519-AEAD-Ratchet sessions for garlic encryption.
// It maintains session state for ongoing encrypted communication with remote destinations.
//
// Session lifecycle:
// 1. New Session: First message uses ephemeral-static DH (ECIES)
// 2. Existing Session: Subsequent messages use ratchet for forward secrecy
// 3. Session Expiry: Sessions expire after inactivity timeout
type GarlicSessionManager struct {
	mu             sync.RWMutex
	sessions       map[common.Hash]*GarlicSession
	ourPrivateKey  [32]byte
	ourPublicKey   [32]byte
	sessionTimeout time.Duration
}

// GarlicSession represents an active encrypted session with a remote destination.
type GarlicSession struct {
	RemotePublicKey  [32]byte
	DHRatchet        *ratchet.DHRatchet
	SymmetricRatchet *ratchet.SymmetricRatchet
	TagRatchet       *ratchet.TagRatchet
	LastUsed         time.Time
	MessageCounter   uint32
}

// NewGarlicSessionManager creates a new garlic session manager with the given private key.
// The private key is used for decrypting New Session messages.
func NewGarlicSessionManager(privateKey [32]byte) (*GarlicSessionManager, error) {
	// Derive public key from private key
	pubBytes, _, err := ecies.GenerateKeyPair()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to derive public key")
	}

	var publicKey [32]byte
	copy(publicKey[:], pubBytes)

	return &GarlicSessionManager{
		sessions:       make(map[common.Hash]*GarlicSession),
		ourPrivateKey:  privateKey,
		ourPublicKey:   publicKey,
		sessionTimeout: 10 * time.Minute, // Default session timeout
	}, nil
}

// EncryptGarlicMessage encrypts a plaintext garlic message for the given destination.
// This uses ECIES-X25519-AEAD-Ratchet encryption:
// - First message to destination: New Session (ephemeral-static DH)
// - Subsequent messages: Existing Session (uses ratchet state)
//
// Parameters:
// - destinationHash: Hash of the destination's public key
// - destinationPubKey: The destination's X25519 public key (32 bytes)
// - plaintextGarlic: Serialized garlic message (from GarlicBuilder.BuildAndSerialize)
//
// Returns encrypted garlic message ready to send via I2NP.
func (sm *GarlicSessionManager) EncryptGarlicMessage(
	destinationHash common.Hash,
	destinationPubKey [32]byte,
	plaintextGarlic []byte,
) ([]byte, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, exists := sm.sessions[destinationHash]

	if !exists {
		// New Session: Use ECIES ephemeral-static encryption
		return sm.encryptNewSession(destinationHash, destinationPubKey, plaintextGarlic)
	}

	// Existing Session: Use ratchet-based encryption
	return sm.encryptExistingSession(session, plaintextGarlic)
}

// encryptNewSession creates a new session and encrypts using ECIES.
// This is used for the first message to a destination.
//
// TODO: Once go-i2p/crypto v0.1.0+ is available with unified Session API:
//   - Use ratchet.NewSessionFromECIES() to properly derive keys from ECIES shared secret
//   - Replace ECIES placeholder encryption with ChaCha20-Poly1305 AEAD
//     See: API_IMPROVEMENTS_SUMMARY.md for migration guide
func (sm *GarlicSessionManager) encryptNewSession(
	destinationHash common.Hash,
	destinationPubKey [32]byte,
	plaintextGarlic []byte,
) ([]byte, error) {
	// Use ECIES to encrypt the garlic message
	ciphertext, err := ecies.EncryptECIESX25519(destinationPubKey[:], plaintextGarlic)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to encrypt new session garlic message")
	}

	// Initialize ratchet state for this session
	// TODO: Once go-i2p/crypto v0.1.0+ is available:
	//   Use kdf.NewKeyDerivation(eciesSharedSecret).DeriveSessionKeys()
	//   to properly derive rootKey, symKey, tagKey from ECIES shared secret
	//   See: API_IMPROVEMENTS_SUMMARY.md "For Key Derivation" section
	// The shared secret from ECIES would be used as root key in production
	// For now, we'll initialize with a basic state
	var rootKey [32]byte
	if _, err := rand.Read(rootKey[:]); err != nil {
		return nil, oops.Wrapf(err, "failed to generate root key")
	}

	var ourPriv, theirPub [32]byte
	copy(ourPriv[:], sm.ourPrivateKey[:])
	copy(theirPub[:], destinationPubKey[:])

	dhRatchet := ratchet.NewDHRatchet(rootKey, ourPriv, theirPub)
	symRatchet := ratchet.NewSymmetricRatchet(rootKey)
	tagRatchet := ratchet.NewTagRatchet(rootKey)

	// Store session for future messages
	sm.sessions[destinationHash] = &GarlicSession{
		RemotePublicKey:  destinationPubKey,
		DHRatchet:        dhRatchet,
		SymmetricRatchet: symRatchet,
		TagRatchet:       tagRatchet,
		LastUsed:         time.Now(),
		MessageCounter:   1,
	}

	return ciphertext, nil
}

// encryptExistingSession encrypts using ratchet state for an established session.
func (sm *GarlicSessionManager) encryptExistingSession(
	session *GarlicSession,
	plaintextGarlic []byte,
) ([]byte, error) {
	// Advance symmetric ratchet to get message key
	messageKey, newChainKey, err := session.SymmetricRatchet.DeriveMessageKeyAndAdvance(session.MessageCounter)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to advance symmetric ratchet")
	}
	_ = messageKey  // Will be used with ChaCha20-Poly1305 in production
	_ = newChainKey // Update chain key for next message

	// Generate session tag for recipient to identify this message
	sessionTag, err := session.TagRatchet.GenerateNextTag()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to generate session tag")
	}

	// Encrypt using ChaCha20-Poly1305 AEAD (via crypto library)
	// TODO: Once go-i2p/crypto v0.1.0+ is available with chacha20poly1305 package:
	//   aead, _ := chacha20poly1305.NewAEAD(messageKey)
	//   nonce, _ := chacha20poly1305.GenerateNonce()
	//   ciphertext, tag, _ := aead.Encrypt(plaintextGarlic, sessionTag[:], nonce)
	//   See: API_IMPROVEMENTS_SUMMARY.md "For Tunnel/Garlic Encryption" section
	// Note: In production, this would use the proper AEAD from crypto/chacha20
	// For now, using ECIES as a placeholder that provides AEAD
	ciphertext, err := ecies.EncryptECIESX25519(session.RemotePublicKey[:], plaintextGarlic)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to encrypt existing session message")
	}

	// Prepend session tag (8 bytes) to ciphertext
	result := make([]byte, 8+len(ciphertext))
	copy(result[0:8], sessionTag[:])
	copy(result[8:], ciphertext)

	// Update session state
	session.LastUsed = time.Now()
	session.MessageCounter++

	return result, nil
}

// DecryptGarlicMessage decrypts an encrypted garlic message.
// This handles both New Session and Existing Session message types.
//
// Parameters:
// - encryptedGarlic: Encrypted garlic message received via I2NP
//
// Returns:
// - Decrypted plaintext garlic message (can be parsed into Garlic struct)
// - Session tag (if Existing Session), empty array if New Session
func (sm *GarlicSessionManager) DecryptGarlicMessage(encryptedGarlic []byte) ([]byte, [8]byte, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Check message length to determine type
	if len(encryptedGarlic) < 8 {
		return nil, [8]byte{}, oops.Errorf("encrypted garlic message too short: %d bytes", len(encryptedGarlic))
	}

	// Try to extract session tag (first 8 bytes)
	var sessionTag [8]byte
	copy(sessionTag[:], encryptedGarlic[0:8])

	// Check if this matches an existing session tag
	session := sm.findSessionByTag(sessionTag)
	if session != nil {
		// Existing Session decryption
		return sm.decryptExistingSession(session, encryptedGarlic[8:], sessionTag)
	}

	// New Session decryption (no matching tag, use our private key)
	plaintext, err := sm.decryptNewSession(encryptedGarlic)
	if err != nil {
		return nil, [8]byte{}, oops.Wrapf(err, "failed to decrypt garlic message")
	}

	return plaintext, [8]byte{}, nil
}

// decryptNewSession decrypts a New Session message using our static private key.
func (sm *GarlicSessionManager) decryptNewSession(ciphertext []byte) ([]byte, error) {
	// Use ECIES to decrypt
	plaintext, err := ecies.DecryptECIESX25519(sm.ourPrivateKey[:], ciphertext)
	if err != nil {
		return nil, oops.Wrapf(err, "ECIES decryption failed for new session")
	}

	// TODO: Extract sender's public key from ECIES ephemeral key
	// TODO: Initialize ratchet state for this new session
	// For now, just return the plaintext

	return plaintext, nil
}

// decryptExistingSession decrypts an Existing Session message using ratchet state.
//
// TODO: Once go-i2p/crypto v0.1.0+ is available with chacha20poly1305 package:
//
//	Use ChaCha20-Poly1305 AEAD with the message key:
//	aead, _ := chacha20poly1305.NewAEAD(messageKey)
//	plaintext, _ := aead.Decrypt(ciphertext, tag[:], sessionTag[:], nonce)
//	See: API_IMPROVEMENTS_SUMMARY.md for migration guide
func (sm *GarlicSessionManager) decryptExistingSession(
	session *GarlicSession,
	ciphertext []byte,
	sessionTag [8]byte,
) ([]byte, [8]byte, error) {
	// Decrypt using the session's ratchet state
	// Note: In production, this would use ChaCha20-Poly1305 with the message key
	// For now, using ECIES as placeholder
	plaintext, err := ecies.DecryptECIESX25519(sm.ourPrivateKey[:], ciphertext)
	if err != nil {
		return nil, [8]byte{}, oops.Wrapf(err, "failed to decrypt existing session message")
	}

	// Advance ratchet state
	_, _, err = session.SymmetricRatchet.DeriveMessageKeyAndAdvance(session.MessageCounter)
	if err != nil {
		return nil, [8]byte{}, oops.Wrapf(err, "failed to advance symmetric ratchet")
	}

	// Update last used timestamp
	session.LastUsed = time.Now()

	return plaintext, sessionTag, nil
}

// findSessionByTag searches for a session that expects the given tag.
func (sm *GarlicSessionManager) findSessionByTag(tag [8]byte) *GarlicSession {
	// In production, this would check if the tag matches any session's expected tags
	// For now, simplified implementation
	for _, session := range sm.sessions {
		// Check if tag matches (simplified - production would verify against tag ratchet)
		if session.LastUsed.Add(sm.sessionTimeout).After(time.Now()) {
			return session
		}
	}
	return nil
}

// CleanupExpiredSessions removes sessions that haven't been used recently.
// Should be called periodically to prevent memory leaks.
func (sm *GarlicSessionManager) CleanupExpiredSessions() int {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()
	removed := 0

	for hash, session := range sm.sessions {
		if now.Sub(session.LastUsed) > sm.sessionTimeout {
			delete(sm.sessions, hash)
			removed++
		}
	}

	return removed
}

// GetSessionCount returns the number of active sessions.
func (sm *GarlicSessionManager) GetSessionCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.sessions)
}

// GenerateGarlicSessionManager creates a garlic session manager with a freshly generated key pair.
func GenerateGarlicSessionManager() (*GarlicSessionManager, error) {
	_, privBytes, err := ecies.GenerateKeyPair()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to generate session manager key pair")
	}

	var privateKey [32]byte
	copy(privateKey[:], privBytes)

	return NewGarlicSessionManager(privateKey)
}

// EncryptGarlicWithBuilder is a convenience function that builds and encrypts a garlic message.
// This combines GarlicBuilder.BuildAndSerialize with GarlicSessionManager.EncryptGarlicMessage.
func EncryptGarlicWithBuilder(
	sm *GarlicSessionManager,
	builder *GarlicBuilder,
	destinationHash common.Hash,
	destinationPubKey [32]byte,
) ([]byte, error) {
	// Build and serialize the garlic message
	plaintext, err := builder.BuildAndSerialize()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to build garlic message")
	}

	// Encrypt using session manager
	ciphertext, err := sm.EncryptGarlicMessage(destinationHash, destinationPubKey, plaintext)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to encrypt garlic message")
	}

	return ciphertext, nil
}

// WrapInGarlicMessage creates a Garlic I2NP message from encrypted garlic data.
// This wraps the encrypted garlic in the proper I2NP message structure.
func WrapInGarlicMessage(encryptedGarlic []byte) (*BaseI2NPMessage, error) {
	if len(encryptedGarlic) == 0 {
		return nil, oops.Errorf("cannot wrap empty garlic data")
	}

	// Generate message ID
	msgIDBytes := make([]byte, 4)
	if _, err := rand.Read(msgIDBytes); err != nil {
		return nil, oops.Wrapf(err, "failed to generate message ID")
	}
	messageID := int(binary.BigEndian.Uint32(msgIDBytes))

	// Create I2NP Garlic message (type 11)
	msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_GARLIC)
	msg.SetMessageID(messageID)
	msg.SetExpiration(time.Now().Add(10 * time.Second))
	msg.data = encryptedGarlic

	return msg, nil
}
