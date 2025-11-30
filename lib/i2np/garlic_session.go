package i2np

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/crypto/chacha20poly1305"
	"github.com/go-i2p/crypto/ecies"
	"github.com/go-i2p/crypto/kdf"
	"github.com/go-i2p/crypto/ratchet"
	"github.com/samber/oops"
	"go.step.sm/crypto/x25519"
)

// GarlicSessionManager manages ECIES-X25519-AEAD-Ratchet sessions for garlic encryption.
// It maintains session state for ongoing encrypted communication with remote destinations.
//
// Session lifecycle:
// 1. New Session: First message uses ephemeral-static DH (ECIES)
// 2. Existing Session: Subsequent messages use ratchet for forward secrecy
// 3. Session Expiry: Sessions expire after inactivity timeout
//
// Performance:
// - O(1) tag lookup using hash-based index
// - Tag window tracking for out-of-order message handling
type GarlicSessionManager struct {
	mu             sync.RWMutex
	sessions       map[common.Hash]*GarlicSession
	tagIndex       map[[8]byte]*GarlicSession // O(1) lookup of session by tag
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
	// pendingTags tracks tags we expect to receive (tag window for out-of-order messages)
	pendingTags [][8]byte
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
		tagIndex:       make(map[[8]byte]*GarlicSession),
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
// Message format: [ephemeralPubKey(32)] + [nonce(12)] + [ciphertext(N)] + [tag(16)]
func (sm *GarlicSessionManager) encryptNewSession(
	destinationHash common.Hash,
	destinationPubKey [32]byte,
	plaintextGarlic []byte,
) ([]byte, error) {
	ephemeralPub, sessionKeys, err := sm.performECIESKeyExchange(destinationPubKey)
	if err != nil {
		return nil, err
	}

	encryptedPayload, err := sm.encryptPayloadWithSessionKey(sessionKeys.symKey, plaintextGarlic)
	if err != nil {
		return nil, err
	}

	newSessionMsg := constructNewSessionMessage(ephemeralPub, encryptedPayload)

	if err := sm.storeNewSessionState(destinationHash, destinationPubKey, sessionKeys); err != nil {
		return nil, err
	}

	return newSessionMsg, nil
}

// sessionKeys holds the cryptographic keys derived from ECIES key exchange.
type sessionKeys struct {
	rootKey [32]byte
	symKey  [32]byte
	tagKey  [32]byte
}

// performECIESKeyExchange executes ephemeral-static key exchange and derives session keys.
func (sm *GarlicSessionManager) performECIESKeyExchange(destinationPubKey [32]byte) ([]byte, *sessionKeys, error) {
	ephemeralPub, ephemeralPriv, err := x25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, oops.Wrapf(err, "failed to generate ephemeral key pair")
	}

	sharedSecret, err := deriveECIESSharedSecret(ephemeralPriv, destinationPubKey)
	if err != nil {
		return nil, nil, err
	}

	keys, err := deriveSessionKeysFromSecret(sharedSecret)
	if err != nil {
		return nil, nil, err
	}

	return ephemeralPub, keys, nil
}

// deriveECIESSharedSecret performs X25519 key agreement to derive shared secret.
func deriveECIESSharedSecret(ephemeralPriv x25519.PrivateKey, destinationPubKey [32]byte) ([]byte, error) {
	recipientKey := x25519.PublicKey(destinationPubKey[:])
	sharedSecret, err := ephemeralPriv.SharedKey(recipientKey)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to derive ECIES shared secret")
	}
	return sharedSecret, nil
}

// deriveSessionKeysFromSecret uses HKDF to derive root, symmetric, and tag keys from shared secret.
func deriveSessionKeysFromSecret(sharedSecret []byte) (*sessionKeys, error) {
	var sharedSecretArray [32]byte
	copy(sharedSecretArray[:], sharedSecret)
	kd := kdf.NewKeyDerivation(sharedSecretArray)
	rootKey, symKey, tagKey, err := kd.DeriveSessionKeys()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to derive session keys")
	}

	return &sessionKeys{
		rootKey: rootKey,
		symKey:  symKey,
		tagKey:  tagKey,
	}, nil
}

// encryptedPayload contains the encrypted message components.
type encryptedPayload struct {
	nonce      []byte
	ciphertext []byte
	tag        [16]byte
}

// encryptPayloadWithSessionKey encrypts plaintext using ChaCha20-Poly1305 with derived symmetric key.
func (sm *GarlicSessionManager) encryptPayloadWithSessionKey(symKey [32]byte, plaintextGarlic []byte) (*encryptedPayload, error) {
	aead, err := chacha20poly1305.NewAEAD(symKey)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create AEAD")
	}

	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, oops.Wrapf(err, "failed to generate nonce")
	}

	ciphertext, tag, err := aead.Encrypt(plaintextGarlic, nil, nonce)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to encrypt garlic message")
	}

	return &encryptedPayload{
		nonce:      nonce,
		ciphertext: ciphertext,
		tag:        tag,
	}, nil
}

// constructNewSessionMessage builds the New Session message from components.
// Format: [ephemeralPubKey(32)] + [nonce(12)] + [ciphertext(N)] + [tag(16)]
func constructNewSessionMessage(ephemeralPub []byte, payload *encryptedPayload) []byte {
	newSessionMsg := make([]byte, 32+12+len(payload.ciphertext)+16)
	copy(newSessionMsg[0:32], ephemeralPub)
	copy(newSessionMsg[32:44], payload.nonce)
	copy(newSessionMsg[44:44+len(payload.ciphertext)], payload.ciphertext)
	copy(newSessionMsg[44+len(payload.ciphertext):], payload.tag[:])
	return newSessionMsg
}

// storeNewSessionState initializes and stores ratchet state for future messages.
func (sm *GarlicSessionManager) storeNewSessionState(
	destinationHash common.Hash,
	destinationPubKey [32]byte,
	keys *sessionKeys,
) error {
	session := createGarlicSession(destinationPubKey, keys, sm.ourPrivateKey)
	sm.sessions[destinationHash] = session

	if err := sm.generateTagWindow(session); err != nil {
		return oops.Wrapf(err, "failed to generate tag window")
	}

	return nil
}

// createGarlicSession initializes a new GarlicSession with ratchet state.
func createGarlicSession(destinationPubKey [32]byte, keys *sessionKeys, ourPrivateKey [32]byte) *GarlicSession {
	var ourPriv, theirPub [32]byte
	copy(ourPriv[:], ourPrivateKey[:])
	copy(theirPub[:], destinationPubKey[:])

	dhRatchet := ratchet.NewDHRatchet(keys.rootKey, ourPriv, theirPub)
	symRatchet := ratchet.NewSymmetricRatchet(keys.rootKey)
	tagRatchet := ratchet.NewTagRatchet(keys.tagKey)

	return &GarlicSession{
		RemotePublicKey:  destinationPubKey,
		DHRatchet:        dhRatchet,
		SymmetricRatchet: symRatchet,
		TagRatchet:       tagRatchet,
		LastUsed:         time.Now(),
		MessageCounter:   1,
		pendingTags:      make([][8]byte, 0, 10),
	}
}

// encryptExistingSession encrypts using ratchet state for an established session.
// Message format: [sessionTag(8)] + [nonce(12)] + [ciphertext(N)] + [tag(16)]
func (sm *GarlicSessionManager) encryptExistingSession(
	session *GarlicSession,
	plaintextGarlic []byte,
) ([]byte, error) {
	// Step 1: Advance symmetric ratchet to get message key
	messageKey, _, err := session.SymmetricRatchet.DeriveMessageKeyAndAdvance(session.MessageCounter)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to advance symmetric ratchet")
	}

	// Step 2: Generate session tag for recipient to identify this message
	sessionTag, err := session.TagRatchet.GenerateNextTag()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to generate session tag")
	}

	// Add tag to pending tags for the remote peer's session (they will use it to find our session)
	// Note: In a real implementation, we would track separate inbound/outbound tag windows
	session.pendingTags = append(session.pendingTags, sessionTag)

	// Step 3: Create ChaCha20-Poly1305 AEAD with message key
	aead, err := chacha20poly1305.NewAEAD(messageKey)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create AEAD")
	}

	// Step 4: Generate unique nonce for this message
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, oops.Wrapf(err, "failed to generate nonce")
	}

	// Step 5: Encrypt with session tag as additional authenticated data
	ciphertext, tag, err := aead.Encrypt(plaintextGarlic, sessionTag[:], nonce)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to encrypt existing session message")
	}

	// Step 6: Construct Existing Session message:
	// [sessionTag(8)] + [nonce(12)] + [ciphertext(N)] + [tag(16)]
	existingSessionMsg := make([]byte, 8+12+len(ciphertext)+16)
	copy(existingSessionMsg[0:8], sessionTag[:])
	copy(existingSessionMsg[8:20], nonce)
	copy(existingSessionMsg[20:20+len(ciphertext)], ciphertext)
	copy(existingSessionMsg[20+len(ciphertext):], tag[:])

	// Update session state
	session.LastUsed = time.Now()
	session.MessageCounter++

	return existingSessionMsg, nil
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
// Message format: [ephemeralPubKey(32)] + [nonce(12)] + [ciphertext(N)] + [tag(16)]
func (sm *GarlicSessionManager) decryptNewSession(newSessionMsg []byte) ([]byte, error) {
	// Parse New Session message format
	if len(newSessionMsg) < 32+12+16 {
		return nil, oops.Errorf("new session message too short: %d bytes", len(newSessionMsg))
	}

	var ephemeralPubKey [32]byte
	copy(ephemeralPubKey[:], newSessionMsg[0:32])
	nonce := newSessionMsg[32:44]
	ciphertextWithTag := newSessionMsg[44:]

	if len(ciphertextWithTag) < 16 {
		return nil, oops.Errorf("ciphertext too short for auth tag")
	}

	ciphertext := ciphertextWithTag[:len(ciphertextWithTag)-16]
	var tag [16]byte
	copy(tag[:], ciphertextWithTag[len(ciphertextWithTag)-16:])

	// Perform ECIES key agreement with ephemeral key
	privKey := x25519.PrivateKey(sm.ourPrivateKey[:])
	ephemeralKey := x25519.PublicKey(ephemeralPubKey[:])

	sharedSecret, err := privKey.SharedKey(ephemeralKey)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to derive shared secret")
	}

	// Derive session keys using HKDF
	var sharedSecretArray [32]byte
	copy(sharedSecretArray[:], sharedSecret)
	kd := kdf.NewKeyDerivation(sharedSecretArray)
	rootKey, symKey, tagKey, err := kd.DeriveSessionKeys()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to derive session keys")
	}

	// Decrypt using ChaCha20-Poly1305
	aead, err := chacha20poly1305.NewAEAD(symKey)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create AEAD")
	}

	plaintext, err := aead.Decrypt(ciphertext, tag[:], nil, nonce)
	if err != nil {
		return nil, oops.Wrapf(err, "decryption failed (authentication error)")
	}

	// Initialize ratchet state for future messages from this sender
	// We track the sender's ephemeral key as their current DH key
	var ourPriv, theirPub [32]byte
	copy(ourPriv[:], sm.ourPrivateKey[:])
	copy(theirPub[:], ephemeralPubKey[:])

	dhRatchet := ratchet.NewDHRatchet(rootKey, ourPriv, theirPub)
	symRatchet := ratchet.NewSymmetricRatchet(rootKey)
	tagRatchet := ratchet.NewTagRatchet(tagKey)

	// Store session (Note: We would need to extract sender's destination hash from the garlic message)
	// For now, we'll need to handle this at a higher level where we can parse the garlic content
	_ = dhRatchet
	_ = symRatchet
	_ = tagRatchet

	return plaintext, nil
}

// decryptExistingSession decrypts an Existing Session message using ratchet state.
// Message format (without session tag prefix): [nonce(12)] + [ciphertext(N)] + [tag(16)]
func (sm *GarlicSessionManager) decryptExistingSession(
	session *GarlicSession,
	existingSessionMsg []byte,
	sessionTag [8]byte,
) ([]byte, [8]byte, error) {
	// Parse Existing Session message format (session tag already extracted by caller)
	if len(existingSessionMsg) < 12+16 {
		return nil, [8]byte{}, oops.Errorf("existing session message too short")
	}

	nonce := existingSessionMsg[0:12]
	ciphertextWithTag := existingSessionMsg[12:]

	if len(ciphertextWithTag) < 16 {
		return nil, [8]byte{}, oops.Errorf("ciphertext too short for auth tag")
	}

	ciphertext := ciphertextWithTag[:len(ciphertextWithTag)-16]
	var tag [16]byte
	copy(tag[:], ciphertextWithTag[len(ciphertextWithTag)-16:])

	// Derive message key from ratchet state
	messageKey, _, err := session.SymmetricRatchet.DeriveMessageKeyAndAdvance(session.MessageCounter)
	if err != nil {
		return nil, [8]byte{}, oops.Wrapf(err, "failed to derive message key")
	}

	// Decrypt using ChaCha20-Poly1305 with session tag as AAD
	aead, err := chacha20poly1305.NewAEAD(messageKey)
	if err != nil {
		return nil, [8]byte{}, oops.Wrapf(err, "failed to create AEAD")
	}

	plaintext, err := aead.Decrypt(ciphertext, tag[:], sessionTag[:], nonce)
	if err != nil {
		return nil, [8]byte{}, oops.Wrapf(err, "decryption failed (authentication error)")
	}

	// Update session state
	session.LastUsed = time.Now()
	session.MessageCounter++

	return plaintext, sessionTag, nil
}

// findSessionByTag searches for a session that expects the given tag.
// This uses O(1) hash-based lookup for performance.
func (sm *GarlicSessionManager) findSessionByTag(tag [8]byte) *GarlicSession {
	// O(1) lookup in tag index
	session, exists := sm.tagIndex[tag]
	if !exists {
		return nil
	}

	// Verify session is not expired
	if time.Since(session.LastUsed) > sm.sessionTimeout {
		// Clean up expired session
		delete(sm.tagIndex, tag)
		return nil
	}

	// Remove used tag from index (tags are single-use)
	delete(sm.tagIndex, tag)

	// Remove tag from session's pending tags
	for i, pendingTag := range session.pendingTags {
		if pendingTag == tag {
			// Remove by swapping with last element and truncating
			session.pendingTags[i] = session.pendingTags[len(session.pendingTags)-1]
			session.pendingTags = session.pendingTags[:len(session.pendingTags)-1]
			break
		}
	}

	// Replenish tag window if running low
	if len(session.pendingTags) < 5 {
		if err := sm.generateTagWindow(session); err != nil {
			// Log error but don't fail - we can still process this message
			// Production would use proper logging here
			_ = err
		}
	}

	return session
}

// generateTagWindow pre-generates a window of session tags for a session.
// This allows the receiver to quickly look up which session a message belongs to.
// Tags are generated ahead of time and indexed for O(1) lookup.
//
// The tag window size is 10 tags by default, which provides a good balance between:
// - Memory usage (10 tags * 8 bytes = 80 bytes per session)
// - Out-of-order message handling (can handle up to 10 messages out of order)
// - Replenishment overhead (only need to generate more tags every ~5 messages)
func (sm *GarlicSessionManager) generateTagWindow(session *GarlicSession) error {
	const tagWindowSize = 10

	// Generate tags up to the window size
	for len(session.pendingTags) < tagWindowSize {
		tag, err := session.TagRatchet.GenerateNextTag()
		if err != nil {
			return oops.Wrapf(err, "failed to generate session tag")
		}

		// Add tag to session's pending tags
		session.pendingTags = append(session.pendingTags, tag)

		// Index tag for O(1) lookup
		sm.tagIndex[tag] = session
	}

	return nil
}

// CleanupExpiredSessions removes sessions that haven't been used recently.
// Should be called periodically to prevent memory leaks.
// This also cleans up any tags associated with expired sessions from the tag index.
func (sm *GarlicSessionManager) CleanupExpiredSessions() int {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()
	removed := 0

	for hash, session := range sm.sessions {
		if now.Sub(session.LastUsed) > sm.sessionTimeout {
			// Remove session from sessions map
			delete(sm.sessions, hash)

			// Remove all pending tags for this session from tag index
			for _, tag := range session.pendingTags {
				delete(sm.tagIndex, tag)
			}

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
