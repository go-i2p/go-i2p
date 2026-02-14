package i2np

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/go-i2p/crypto/rand"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/crypto/chacha20poly1305"
	"github.com/go-i2p/crypto/ecies"
	"github.com/go-i2p/crypto/kdf"
	"github.com/go-i2p/crypto/ratchet"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
	"go.step.sm/crypto/x25519"
	"golang.org/x/crypto/curve25519"
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
	mu               sync.Mutex // protects session state during crypto operations
	RemotePublicKey  [32]byte
	DHRatchet        *ratchet.DHRatchet
	SymmetricRatchet *ratchet.SymmetricRatchet // sending chain
	TagRatchet       *ratchet.TagRatchet       // sending tags
	// RecvSymmetricRatchet is the receiving chain ratchet. A proper Double Ratchet
	// protocol requires separate sending and receiving chain states so that
	// ProcessIncomingDHRatchet does not overwrite the sending ratchet.
	RecvSymmetricRatchet *ratchet.SymmetricRatchet
	// RecvTagRatchet is the receiving tag ratchet (separate from the send tag ratchet).
	RecvTagRatchet *ratchet.TagRatchet
	LastUsed       time.Time
	MessageCounter uint32
	// recvCounter tracks the number of messages received (for symmetric ratchet advancement)
	recvCounter uint32
	// pendingTags tracks tags we expect to receive (tag window for out-of-order messages)
	pendingTags [][8]byte
	// dhRatchetCounter tracks messages since last DH ratchet rotation
	dhRatchetCounter uint32
	// consecutiveDHFailures tracks how many DH ratchet steps have failed in a row.
	// When this exceeds MaxConsecutiveDHFailures, the session should be reset
	// to restore forward secrecy.
	consecutiveDHFailures uint32
	// newEphemeralPub holds the new ephemeral public key to send to the peer
	// when a DH ratchet step has occurred but the peer hasn't acknowledged it yet
	newEphemeralPub *[32]byte
}

const (
	// DHRatchetInterval is the number of messages between DH ratchet rotations.
	// After this many messages, a DH ratchet step is performed to rotate keys,
	// providing forward secrecy: compromise of current keys cannot reveal past messages.
	DHRatchetInterval = 50

	// MaxConsecutiveDHFailures is the maximum number of consecutive DH ratchet
	// failures before the session is considered degraded and should be reset.
	// This prevents silent forward secrecy degradation.
	MaxConsecutiveDHFailures = 3
)

// NewGarlicSessionManager creates a new garlic session manager with the given private key.
// The private key is used for decrypting New Session messages.
func NewGarlicSessionManager(privateKey [32]byte) (*GarlicSessionManager, error) {
	log.WithFields(logger.Fields{
		"at": "NewGarlicSessionManager",
	}).Debug("Creating new garlic session manager")

	// Derive public key from private key using X25519 scalar multiplication
	// publicKey = privateKey * basepoint (standard X25519 key derivation)
	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	log.WithFields(logger.Fields{
		"at":              "NewGarlicSessionManager",
		"session_timeout": 10 * time.Minute,
	}).Debug("Garlic session manager created successfully")

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
	log.WithFields(logger.Fields{
		"at":             "EncryptGarlicMessage",
		"plaintext_size": len(plaintextGarlic),
		"dest_hash":      destinationHash.String(),
	}).Debug("Encrypting garlic message")

	// Look up session under read lock only
	sm.mu.RLock()
	session, exists := sm.sessions[destinationHash]
	sm.mu.RUnlock()

	if !exists {
		// Double-checked locking: acquire write lock and re-check to prevent
		// two goroutines from both creating a session for the same destination.
		sm.mu.Lock()
		session, exists = sm.sessions[destinationHash]
		if exists {
			sm.mu.Unlock()
			log.WithFields(logger.Fields{
				"at":              "EncryptGarlicMessage",
				"dest_hash":       destinationHash.String(),
				"message_counter": session.MessageCounter,
			}).Debug("Session found after double-check, using existing session")
			return sm.encryptExistingSession(session, plaintextGarlic)
		}
		sm.mu.Unlock()

		log.WithFields(logger.Fields{
			"at":        "EncryptGarlicMessage",
			"dest_hash": destinationHash.String(),
		}).Debug("No existing session found, creating new session")
		// New Session: Use ECIES ephemeral-static encryption
		// encryptNewSession acquires write lock internally to store session state
		return sm.encryptNewSession(destinationHash, destinationPubKey, plaintextGarlic)
	}

	log.WithFields(logger.Fields{
		"at":              "EncryptGarlicMessage",
		"dest_hash":       destinationHash.String(),
		"message_counter": session.MessageCounter,
	}).Debug("Using existing session for encryption")
	// Existing Session: Use ratchet-based encryption
	// Crypto is performed without holding the session manager lock
	return sm.encryptExistingSession(session, plaintextGarlic)
}

// encryptNewSession creates a new session and encrypts using ECIES.
// This is used for the first message to a destination.
// Crypto (key exchange + encryption) is performed without the session manager lock.
// The lock is only acquired to store the new session state.
//
// Message format: [ephemeralPubKey(32)] + [nonce(12)] + [ciphertext(N)] + [tag(16)]
func (sm *GarlicSessionManager) encryptNewSession(
	destinationHash common.Hash,
	destinationPubKey [32]byte,
	plaintextGarlic []byte,
) ([]byte, error) {
	log.WithFields(logger.Fields{
		"at":        "encryptNewSession",
		"dest_hash": destinationHash.String(),
	}).Debug("Encrypting with new session")

	ephemeralPub, sessionKeys, err := sm.performECIESKeyExchange(destinationPubKey)
	if err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":        "encryptNewSession",
			"dest_hash": destinationHash.String(),
		}).Error("ECIES key exchange failed")
		return nil, err
	}

	encryptedPayload, err := sm.encryptPayloadWithSessionKey(sessionKeys.symKey, plaintextGarlic)
	if err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":        "encryptNewSession",
			"dest_hash": destinationHash.String(),
		}).Error("Failed to encrypt payload with session key")
		return nil, err
	}

	newSessionMsg := constructNewSessionMessage(ephemeralPub, encryptedPayload)

	if err := sm.storeNewSessionState(destinationHash, destinationPubKey, sessionKeys); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":        "encryptNewSession",
			"dest_hash": destinationHash.String(),
		}).Error("Failed to store new session state")
		return nil, err
	}

	log.WithFields(logger.Fields{
		"at":           "encryptNewSession",
		"dest_hash":    destinationHash.String(),
		"message_size": len(newSessionMsg),
	}).Debug("New session encrypted successfully")

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
		log.WithError(err).Error("Failed to generate ephemeral key pair")
		return nil, nil, oops.Wrapf(err, "failed to generate ephemeral key pair")
	}

	sharedSecret, err := deriveECIESSharedSecret(ephemeralPriv, destinationPubKey)
	if err != nil {
		log.WithError(err).Error("Failed to derive ECIES shared secret")
		return nil, nil, err
	}

	keys, err := deriveSessionKeysFromSecret(sharedSecret)
	if err != nil {
		log.WithError(err).Error("Failed to derive session keys from shared secret")
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
// Acquires the session manager write lock to modify the sessions and tagIndex maps.
func (sm *GarlicSessionManager) storeNewSessionState(
	destinationHash common.Hash,
	destinationPubKey [32]byte,
	keys *sessionKeys,
) error {
	session := createGarlicSession(destinationPubKey, keys, sm.ourPrivateKey)

	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.sessions[destinationHash] = session

	if err := sm.generateTagWindow(session); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":        "storeNewSessionState",
			"dest_hash": destinationHash.String(),
		}).Error("Failed to generate tag window")
		return oops.Wrapf(err, "failed to generate tag window")
	}

	log.WithFields(logger.Fields{
		"at":            "storeNewSessionState",
		"dest_hash":     destinationHash.String(),
		"session_count": len(sm.sessions),
	}).Debug("New session state stored successfully")

	return nil
}

// createGarlicSession initializes a new GarlicSession with ratchet state.
// Both send and receive ratchets are initialized from the same root key;
// they diverge once the first DH ratchet step occurs.
func createGarlicSession(destinationPubKey [32]byte, keys *sessionKeys, ourPrivateKey [32]byte) *GarlicSession {
	var ourPriv, theirPub [32]byte
	copy(ourPriv[:], ourPrivateKey[:])
	copy(theirPub[:], destinationPubKey[:])

	dhRatchet := ratchet.NewDHRatchet(keys.rootKey, ourPriv, theirPub)
	symRatchet := ratchet.NewSymmetricRatchet(keys.rootKey)
	tagRatchet := ratchet.NewTagRatchet(keys.tagKey)
	recvSymRatchet := ratchet.NewSymmetricRatchet(keys.rootKey)
	recvTagRatchet := ratchet.NewTagRatchet(keys.tagKey)

	return &GarlicSession{
		RemotePublicKey:      destinationPubKey,
		DHRatchet:            dhRatchet,
		SymmetricRatchet:     symRatchet,
		TagRatchet:           tagRatchet,
		RecvSymmetricRatchet: recvSymRatchet,
		RecvTagRatchet:       recvTagRatchet,
		LastUsed:             time.Now(),
		MessageCounter:       1,
		pendingTags:          make([][8]byte, 0, 10),
	}
}

// encryptExistingSession encrypts using ratchet state for an established session.
// Message format: [sessionTag(8)] + [nonce(12)] + [ciphertext(N)] + [tag(16)]
// The session's own mutex is held during ratchet advancement and state update,
// but the session manager lock is NOT held — allowing concurrent encryption to
// different destinations.
func (sm *GarlicSessionManager) encryptExistingSession(
	session *GarlicSession,
	plaintextGarlic []byte,
) ([]byte, error) {
	session.mu.Lock()
	defer session.mu.Unlock()

	log.WithFields(logger.Fields{
		"at":              "encryptExistingSession",
		"message_counter": session.MessageCounter,
	}).Debug("Encrypting with existing session")

	messageKey, sessionTag, err := advanceRatchets(session)
	if err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":              "encryptExistingSession",
			"message_counter": session.MessageCounter,
		}).Error("Failed to advance ratchets")
		return nil, err
	}

	ciphertext, tag, nonce, err := encryptWithSessionKey(messageKey, plaintextGarlic, sessionTag)
	if err != nil {
		log.WithError(err).Error("Failed to encrypt with session key")
		return nil, err
	}

	existingSessionMsg := buildExistingSessionMessage(sessionTag, nonce, ciphertext, tag)

	// Update session state
	session.LastUsed = time.Now()
	session.MessageCounter++

	log.WithFields(logger.Fields{
		"at":              "encryptExistingSession",
		"message_counter": session.MessageCounter,
		"message_size":    len(existingSessionMsg),
	}).Debug("Existing session encrypted successfully")

	return existingSessionMsg, nil
}

// advanceRatchets advances the symmetric and tag ratchets to generate message key and session tag.
// Periodically performs a DH ratchet step for forward secrecy.
func advanceRatchets(session *GarlicSession) (messageKey [32]byte, sessionTag [8]byte, err error) {
	if err := attemptDHRatchetRotation(session); err != nil {
		return [32]byte{}, [8]byte{}, err
	}

	messageKey, err = deriveMessageKey(session)
	if err != nil {
		return [32]byte{}, [8]byte{}, err
	}

	sessionTag, err = generateAndTrackSessionTag(session)
	if err != nil {
		return [32]byte{}, [8]byte{}, err
	}

	return messageKey, sessionTag, nil
}

// attemptDHRatchetRotation checks whether a DH ratchet step is due and
// performs it if needed. Returns a fatal error only when consecutive DH
// failures exceed MaxConsecutiveDHFailures.
func attemptDHRatchetRotation(session *GarlicSession) error {
	session.dhRatchetCounter++
	if session.dhRatchetCounter < DHRatchetInterval {
		return nil
	}

	if err := performDHRatchetStep(session); err != nil {
		session.consecutiveDHFailures++
		if session.consecutiveDHFailures >= MaxConsecutiveDHFailures {
			log.WithFields(logger.Fields{
				"at":                   "advanceRatchets",
				"consecutive_failures": session.consecutiveDHFailures,
				"max_failures":         MaxConsecutiveDHFailures,
				"reason":               "forward secrecy degraded, session should be reset",
			}).Error("DH ratchet failed too many times, session forward secrecy compromised")
			return oops.Wrapf(err,
				"DH ratchet failed %d consecutive times (max %d), forward secrecy compromised",
				session.consecutiveDHFailures, MaxConsecutiveDHFailures)
		}
		log.WithError(err).WithField("consecutive_failures", session.consecutiveDHFailures).
			Warn("DH ratchet rotation failed, continuing with symmetric ratchet")
	} else {
		session.dhRatchetCounter = 0
		session.consecutiveDHFailures = 0
	}
	return nil
}

// deriveMessageKey advances the symmetric ratchet to produce the next
// message encryption key.
func deriveMessageKey(session *GarlicSession) ([32]byte, error) {
	messageKey, _, err := session.SymmetricRatchet.DeriveMessageKeyAndAdvance(session.MessageCounter)
	if err != nil {
		return [32]byte{}, oops.Wrapf(err, "failed to advance symmetric ratchet")
	}
	return messageKey, nil
}

// generateAndTrackSessionTag generates the next session tag from the tag
// ratchet and appends it to the pending tags list for the remote peer.
func generateAndTrackSessionTag(session *GarlicSession) ([8]byte, error) {
	sessionTag, err := session.TagRatchet.GenerateNextTag()
	if err != nil {
		return [8]byte{}, oops.Wrapf(err, "failed to generate session tag")
	}
	session.pendingTags = append(session.pendingTags, sessionTag)
	return sessionTag, nil
}

// performDHRatchetStep performs a Diffie-Hellman ratchet step for forward secrecy.
// This generates a new ephemeral key pair, performs the DH exchange, and derives
// fresh symmetric and tag ratchet keys. After this step, compromise of previous
// keys cannot decrypt future messages.
//
// DH ratchet flow:
// 1. Generate new ephemeral key pair (updates internal private key)
// 2. Perform DH ratchet: DH(newPrivKey, theirPubKey) → new rootKey + sendingChainKey
// 3. Re-initialize symmetric ratchet with new sending chain key
// 4. Re-initialize tag ratchet with key derived from new root key
// 5. Store new ephemeral public key for transmission to peer
func performDHRatchetStep(session *GarlicSession) error {
	// Step 1: Generate new ephemeral key pair
	newPubKey, err := session.DHRatchet.GenerateNewKeyPair()
	if err != nil {
		return oops.Wrapf(err, "failed to generate new ephemeral key pair")
	}

	// Step 2: Perform DH ratchet — derives new root key and sending chain key
	sendingChainKey, _, err := session.DHRatchet.PerformRatchet()
	if err != nil {
		return oops.Wrapf(err, "failed to perform DH ratchet")
	}

	// Step 3: Re-initialize symmetric ratchet with fresh sending chain key
	session.SymmetricRatchet = ratchet.NewSymmetricRatchet(sendingChainKey)

	// Step 4: Derive a new tag key from the sending chain key
	// Use a simple derivation: SHA-256 of the chain key with a domain separator
	tagKeyInput := sha256.Sum256(append(sendingChainKey[:], []byte("TagRatchetKey")...))
	session.TagRatchet = ratchet.NewTagRatchet(tagKeyInput)

	// Step 5: Store new ephemeral public key to send to peer
	session.newEphemeralPub = &newPubKey

	log.WithFields(logger.Fields{
		"at":              "performDHRatchetStep",
		"message_counter": session.MessageCounter,
		"new_pub_key":     fmt.Sprintf("%x", newPubKey[:8]),
	}).Debug("DH ratchet rotation completed")

	return nil
}

// ProcessIncomingDHRatchet processes a DH ratchet key received from a peer.
// This updates the peer's public key in our DH ratchet and derives fresh
// receiving chain keys.
func (sm *GarlicSessionManager) ProcessIncomingDHRatchet(session *GarlicSession, newRemotePubKey [32]byte) error {
	session.mu.Lock()
	defer session.mu.Unlock()

	// Update the remote party's public key
	if err := session.DHRatchet.UpdateKeys(newRemotePubKey[:]); err != nil {
		return oops.Wrapf(err, "failed to update remote DH public key")
	}

	// Perform DH ratchet from our side to derive receiving chain key
	_, receivingChainKey, err := session.DHRatchet.PerformRatchet()
	if err != nil {
		return oops.Wrapf(err, "failed to perform receiving DH ratchet")
	}

	// Re-initialize receiving symmetric ratchet (NOT the sending one)
	session.RecvSymmetricRatchet = ratchet.NewSymmetricRatchet(receivingChainKey)

	// Re-initialize receiving tag ratchet (NOT the sending one)
	tagKeyInput := sha256.Sum256(append(receivingChainKey[:], []byte("TagRatchetKey")...))
	session.RecvTagRatchet = ratchet.NewTagRatchet(tagKeyInput)

	// Update remote public key
	session.RemotePublicKey = newRemotePubKey

	log.WithFields(logger.Fields{
		"at":              "ProcessIncomingDHRatchet",
		"message_counter": session.MessageCounter,
	}).Debug("Processed incoming DH ratchet from peer")

	return nil
}

// encryptWithSessionKey encrypts plaintext using ChaCha20-Poly1305 with the message key.
func encryptWithSessionKey(messageKey [32]byte, plaintextGarlic []byte, sessionTag [8]byte) (ciphertext []byte, tag [16]byte, nonce []byte, err error) {
	// Step 3: Create ChaCha20-Poly1305 AEAD with message key
	aead, err := chacha20poly1305.NewAEAD(messageKey)
	if err != nil {
		return nil, [16]byte{}, nil, oops.Wrapf(err, "failed to create AEAD")
	}

	// Step 4: Generate unique nonce for this message
	nonce = make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, [16]byte{}, nil, oops.Wrapf(err, "failed to generate nonce")
	}

	// Step 5: Encrypt with session tag as additional authenticated data
	ciphertext, tag, err = aead.Encrypt(plaintextGarlic, sessionTag[:], nonce)
	if err != nil {
		return nil, [16]byte{}, nil, oops.Wrapf(err, "failed to encrypt existing session message")
	}

	return ciphertext, tag, nonce, nil
}

// buildExistingSessionMessage constructs the Existing Session message format.
func buildExistingSessionMessage(sessionTag [8]byte, nonce, ciphertext []byte, tag [16]byte) []byte {
	// Step 6: Construct Existing Session message:
	// [sessionTag(8)] + [nonce(12)] + [ciphertext(N)] + [tag(16)]
	existingSessionMsg := make([]byte, 8+12+len(ciphertext)+16)
	copy(existingSessionMsg[0:8], sessionTag[:])
	copy(existingSessionMsg[8:20], nonce)
	copy(existingSessionMsg[20:20+len(ciphertext)], ciphertext)
	copy(existingSessionMsg[20+len(ciphertext):], tag[:])
	return existingSessionMsg
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
	log.WithFields(logger.Fields{
		"at":           "DecryptGarlicMessage",
		"message_size": len(encryptedGarlic),
	}).Debug("Decrypting garlic message")

	// Check message length (no lock needed for stateless validation)
	if len(encryptedGarlic) < 8 {
		log.WithFields(logger.Fields{
			"at":           "DecryptGarlicMessage",
			"message_size": len(encryptedGarlic),
		}).Error("Encrypted garlic message too short")
		return nil, [8]byte{}, oops.Errorf("encrypted garlic message too short: %d bytes", len(encryptedGarlic))
	}

	// Try to extract session tag (first 8 bytes)
	var sessionTag [8]byte
	copy(sessionTag[:], encryptedGarlic[0:8])

	// Look up session by tag under write lock (findSessionByTag modifies tag index)
	sm.mu.Lock()
	session := sm.findSessionByTag(sessionTag)
	sm.mu.Unlock()

	if session != nil {
		log.WithFields(logger.Fields{
			"at": "DecryptGarlicMessage",
		}).Debug("Found existing session for tag")
		// Existing Session decryption — crypto performed outside the lock
		return sm.decryptExistingSession(session, encryptedGarlic[8:], sessionTag)
	}

	log.WithFields(logger.Fields{
		"at": "DecryptGarlicMessage",
	}).Debug("No session found for tag, attempting new session decryption")
	// New Session decryption (no matching tag, use our private key)
	// decryptNewSession acquires write lock internally to store inbound ratchet state
	plaintext, err := sm.decryptNewSession(encryptedGarlic)
	if err != nil {
		log.WithError(err).Error("Failed to decrypt garlic message")
		return nil, [8]byte{}, oops.Wrapf(err, "failed to decrypt garlic message")
	}

	log.WithFields(logger.Fields{
		"at":             "DecryptGarlicMessage",
		"plaintext_size": len(plaintext),
	}).Debug("Garlic message decrypted successfully")

	return plaintext, [8]byte{}, nil
}

// decryptNewSession decrypts a New Session message using our static private key.
// Message format: [ephemeralPubKey(32)] + [nonce(12)] + [ciphertext(N)] + [tag(16)]
func (sm *GarlicSessionManager) decryptNewSession(newSessionMsg []byte) ([]byte, error) {
	log.WithFields(logger.Fields{
		"at":           "decryptNewSession",
		"message_size": len(newSessionMsg),
	}).Debug("Decrypting new session message")

	parsedMsg, err := parseNewSessionMessage(newSessionMsg)
	if err != nil {
		log.WithError(err).Error("Failed to parse new session message")
		return nil, err
	}

	sharedSecret, err := sm.deriveSharedSecretFromEphemeral(parsedMsg.ephemeralPubKey)
	if err != nil {
		log.WithError(err).Error("Failed to derive shared secret from ephemeral key")
		return nil, err
	}

	sessionKeys, err := deriveKeysFromSharedSecret(sharedSecret)
	if err != nil {
		log.WithError(err).Error("Failed to derive session keys")
		return nil, err
	}

	plaintext, err := decryptWithSessionKeys(parsedMsg, sessionKeys.symKey)
	if err != nil {
		log.WithError(err).Error("Failed to decrypt with session keys")
		return nil, err
	}

	if err := sm.initializeInboundRatchetState(parsedMsg.ephemeralPubKey, sessionKeys); err != nil {
		log.WithError(err).Error("Failed to initialize inbound ratchet state")
		return nil, err
	}

	log.WithFields(logger.Fields{
		"at":             "decryptNewSession",
		"plaintext_size": len(plaintext),
	}).Debug("New session decrypted successfully")

	return plaintext, nil
}

// newSessionMessageComponents holds the parsed components of a New Session message.
type newSessionMessageComponents struct {
	ephemeralPubKey [32]byte
	nonce           []byte
	ciphertext      []byte
	tag             [16]byte
}

// parseNewSessionMessage extracts components from a New Session message.
// Message format: [ephemeralPubKey(32)] + [nonce(12)] + [ciphertext(N)] + [tag(16)]
func parseNewSessionMessage(newSessionMsg []byte) (*newSessionMessageComponents, error) {
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

	return &newSessionMessageComponents{
		ephemeralPubKey: ephemeralPubKey,
		nonce:           nonce,
		ciphertext:      ciphertext,
		tag:             tag,
	}, nil
}

// deriveSharedSecretFromEphemeral performs X25519 key agreement with ephemeral public key.
func (sm *GarlicSessionManager) deriveSharedSecretFromEphemeral(ephemeralPubKey [32]byte) ([]byte, error) {
	privKey := x25519.PrivateKey(sm.ourPrivateKey[:])
	ephemeralKey := x25519.PublicKey(ephemeralPubKey[:])

	sharedSecret, err := privKey.SharedKey(ephemeralKey)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to derive shared secret")
	}

	return sharedSecret, nil
}

// deriveKeysFromSharedSecret derives cryptographic keys from shared secret using HKDF.
func deriveKeysFromSharedSecret(sharedSecret []byte) (*sessionKeys, error) {
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

// decryptWithSessionKeys decrypts ciphertext using ChaCha20-Poly1305 with session symmetric key.
func decryptWithSessionKeys(parsedMsg *newSessionMessageComponents, symKey [32]byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewAEAD(symKey)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create AEAD")
	}

	plaintext, err := aead.Decrypt(parsedMsg.ciphertext, parsedMsg.tag[:], nil, parsedMsg.nonce)
	if err != nil {
		return nil, oops.Wrapf(err, "decryption failed (authentication error)")
	}

	return plaintext, nil
}

// initializeInboundRatchetState creates and stores ratchet state for future messages
// from a sender whose New Session message we just decrypted. Since the sender's
// destination hash is not known until the garlic content is parsed, we key the session
// by the SHA-256 hash of the ephemeral public key used in the handshake. The session
// is also indexed by its pre-generated tags for O(1) lookup on subsequent messages.
// Acquires the session manager write lock to modify the sessions and tagIndex maps.
func (sm *GarlicSessionManager) initializeInboundRatchetState(ephemeralPubKey [32]byte, keys *sessionKeys) error {
	session := createGarlicSession(ephemeralPubKey, keys, sm.ourPrivateKey)

	// Key the session by the hash of the ephemeral public key, since we do not yet
	// know the sender's destination hash (it is inside the encrypted garlic payload).
	sessionHash := common.Hash(sha256.Sum256(ephemeralPubKey[:]))

	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.sessions[sessionHash] = session

	if err := sm.generateTagWindow(session); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at": "initializeInboundRatchetState",
		}).Error("Failed to generate inbound tag window")
		return oops.Wrapf(err, "failed to generate inbound tag window")
	}

	log.WithFields(logger.Fields{
		"at":            "initializeInboundRatchetState",
		"session_count": len(sm.sessions),
		"tag_count":     len(sm.tagIndex),
	}).Debug("Inbound ratchet session stored successfully")

	return nil
}

// decryptExistingSession decrypts an Existing Session message using ratchet state.
// Message format (without session tag prefix): [nonce(12)] + [ciphertext(N)] + [tag(16)]
// The session's own mutex is held during ratchet advancement and state update,
// but the session manager lock is NOT held.
func (sm *GarlicSessionManager) decryptExistingSession(
	session *GarlicSession,
	existingSessionMsg []byte,
	sessionTag [8]byte,
) ([]byte, [8]byte, error) {
	session.mu.Lock()
	defer session.mu.Unlock()

	log.WithFields(logger.Fields{
		"at":              "decryptExistingSession",
		"message_counter": session.MessageCounter,
	}).Debug("Decrypting existing session message")

	nonce, ciphertext, tag, err := parseExistingSessionMessage(existingSessionMsg)
	if err != nil {
		log.WithError(err).Error("Failed to parse existing session message")
		return nil, [8]byte{}, err
	}

	messageKey, err := deriveDecryptionKey(session)
	if err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":              "decryptExistingSession",
			"message_counter": session.MessageCounter,
		}).Error("Failed to derive decryption key")
		return nil, [8]byte{}, err
	}

	plaintext, err := decryptWithSessionTag(messageKey, ciphertext, tag, sessionTag, nonce)
	if err != nil {
		log.WithError(err).Error("Failed to decrypt with session tag")
		return nil, [8]byte{}, err
	}

	// Update session state — increment recvCounter (not MessageCounter, which
	// tracks the sending chain) so that send and receive advance independently.
	session.LastUsed = time.Now()
	session.recvCounter++

	log.WithFields(logger.Fields{
		"at":              "decryptExistingSession",
		"message_counter": session.recvCounter,
		"plaintext_size":  len(plaintext),
	}).Debug("Existing session decrypted successfully")

	return plaintext, sessionTag, nil
}

// parseExistingSessionMessage parses the Existing Session message format.
func parseExistingSessionMessage(existingSessionMsg []byte) (nonce, ciphertext []byte, tag [16]byte, err error) {
	if len(existingSessionMsg) < 12+16 {
		return nil, nil, [16]byte{}, oops.Errorf("existing session message too short")
	}

	nonce = existingSessionMsg[0:12]
	ciphertextWithTag := existingSessionMsg[12:]

	if len(ciphertextWithTag) < 16 {
		return nil, nil, [16]byte{}, oops.Errorf("ciphertext too short for auth tag")
	}

	ciphertext = ciphertextWithTag[:len(ciphertextWithTag)-16]
	copy(tag[:], ciphertextWithTag[len(ciphertextWithTag)-16:])

	return nonce, ciphertext, tag, nil
}

// deriveDecryptionKey derives the message key from the session's receiving ratchet state.
// Uses RecvSymmetricRatchet (with fallback to SymmetricRatchet for sessions created
// before the send/recv separation) and recvCounter to keep decryption independent
// of the sending chain.
func deriveDecryptionKey(session *GarlicSession) ([32]byte, error) {
	recvRatchet := session.RecvSymmetricRatchet
	if recvRatchet == nil {
		recvRatchet = session.SymmetricRatchet
	}
	messageKey, _, err := recvRatchet.DeriveMessageKeyAndAdvance(session.recvCounter)
	if err != nil {
		return [32]byte{}, oops.Wrapf(err, "failed to derive message key")
	}
	return messageKey, nil
}

// decryptWithSessionTag decrypts ciphertext using ChaCha20-Poly1305 with session tag as AAD.
func decryptWithSessionTag(messageKey [32]byte, ciphertext []byte, tag [16]byte, sessionTag [8]byte, nonce []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewAEAD(messageKey)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create AEAD")
	}

	plaintext, err := aead.Decrypt(ciphertext, tag[:], sessionTag[:], nonce)
	if err != nil {
		return nil, oops.Wrapf(err, "decryption failed (authentication error)")
	}

	return plaintext, nil
}

// findSessionByTag searches for a session that expects the given tag.
// This uses O(1) hash-based lookup for performance.
func (sm *GarlicSessionManager) findSessionByTag(tag [8]byte) *GarlicSession {
	session, exists := sm.tagIndex[tag]
	if !exists {
		return nil
	}

	// Hold session.mu while reading and modifying session-level state
	// (LastUsed, pendingTags, TagRatchet) to prevent races with
	// encryptExistingSession which also holds session.mu.
	// Lock ordering: sm.mu (held by caller) → session.mu (acquired here)
	// is safe because encryptExistingSession only acquires session.mu.
	session.mu.Lock()
	defer session.mu.Unlock()

	if !sm.isSessionValid(session) {
		sm.cleanupExpiredTag(tag)
		return nil
	}

	sm.consumeTag(tag, session)
	sm.replenishTagWindowIfNeeded(session)

	return session
}

// isSessionValid checks if a session has not expired.
func (sm *GarlicSessionManager) isSessionValid(session *GarlicSession) bool {
	return time.Since(session.LastUsed) <= sm.sessionTimeout
}

// cleanupExpiredTag removes an expired tag from the index.
func (sm *GarlicSessionManager) cleanupExpiredTag(tag [8]byte) {
	delete(sm.tagIndex, tag)
}

// consumeTag removes a used tag from the index and session's pending tags.
// Tags are single-use for security.
func (sm *GarlicSessionManager) consumeTag(tag [8]byte, session *GarlicSession) {
	delete(sm.tagIndex, tag)
	sm.removeTagFromPendingList(tag, session)
}

// removeTagFromPendingList removes a tag from session's pending tags list.
func (sm *GarlicSessionManager) removeTagFromPendingList(tag [8]byte, session *GarlicSession) {
	for i, pendingTag := range session.pendingTags {
		if pendingTag == tag {
			session.pendingTags[i] = session.pendingTags[len(session.pendingTags)-1]
			session.pendingTags = session.pendingTags[:len(session.pendingTags)-1]
			break
		}
	}
}

// replenishTagWindowIfNeeded generates more tags if the window is running low.
func (sm *GarlicSessionManager) replenishTagWindowIfNeeded(session *GarlicSession) {
	if len(session.pendingTags) < 5 {
		if err := sm.generateTagWindow(session); err != nil {
			// Log error but don't fail - we can still process this message
			// Tag window replenishment is non-critical; message processing can continue
			log.WithFields(logger.Fields{
				"at":              "replenishTagWindowIfNeeded",
				"remote_pubkey":   fmt.Sprintf("%x", session.RemotePublicKey[:8]),
				"pending_tags":    len(session.pendingTags),
				"message_counter": session.MessageCounter,
				"error":           err.Error(),
			}).Warn("Failed to replenish session tag window")
		}
	}
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

	log.WithFields(logger.Fields{
		"at":                   "generateTagWindow",
		"current_pending_tags": len(session.pendingTags),
		"target_window_size":   tagWindowSize,
	}).Debug("Generating session tag window")

	// Generate tags up to the window size using the receiving tag ratchet.
	// Tags are generated from RecvTagRatchet (not the sending TagRatchet) so
	// that the peer's sent tags match our expected receiving tags.
	tagRatchet := session.RecvTagRatchet
	if tagRatchet == nil {
		// Fallback for sessions created before the send/recv split.
		tagRatchet = session.TagRatchet
	}
	for len(session.pendingTags) < tagWindowSize {
		tag, err := tagRatchet.GenerateNextTag()
		if err != nil {
			log.WithError(err).Error("Failed to generate session tag")
			return oops.Wrapf(err, "failed to generate session tag")
		}

		// Add tag to session's pending tags
		session.pendingTags = append(session.pendingTags, tag)

		// Index tag for O(1) lookup
		sm.tagIndex[tag] = session
	}

	log.WithFields(logger.Fields{
		"at":                 "generateTagWindow",
		"generated_tags":     len(session.pendingTags),
		"total_indexed_tags": len(sm.tagIndex),
	}).Debug("Tag window generated successfully")

	return nil
}

// CleanupExpiredSessions removes sessions that haven't been used recently.
// Should be called periodically to prevent memory leaks.
// This also cleans up any tags associated with expired sessions from the tag index.
func (sm *GarlicSessionManager) CleanupExpiredSessions() int {
	log.WithFields(logger.Fields{
		"at":            "CleanupExpiredSessions",
		"session_count": len(sm.sessions),
	}).Debug("Cleaning up expired sessions")

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

	if removed > 0 {
		log.WithFields(logger.Fields{
			"at":                     "CleanupExpiredSessions",
			"removed_sessions":       removed,
			"remaining_sessions":     len(sm.sessions),
			"remaining_indexed_tags": len(sm.tagIndex),
		}).Info("Expired sessions cleaned up")
	}

	return removed
}

// GetSessionCount returns the number of active sessions.
func (sm *GarlicSessionManager) GetSessionCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.sessions)
}

// StartCleanupLoop starts a background goroutine that periodically cleans up
// expired sessions and their associated tag index entries. The loop runs every
// 2 minutes and stops when the provided context is cancelled.
// This prevents unbounded growth of the session and tag index maps.
func (sm *GarlicSessionManager) StartCleanupLoop(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				sm.CleanupExpiredSessions()
			case <-ctx.Done():
				return
			}
		}
	}()

	log.WithFields(logger.Fields{
		"at":       "GarlicSessionManager.StartCleanupLoop",
		"interval": "2m",
	}).Debug("Started garlic session cleanup loop")
}

// GenerateGarlicSessionManager creates a garlic session manager with a freshly generated key pair.
func GenerateGarlicSessionManager() (*GarlicSessionManager, error) {
	log.WithFields(logger.Fields{
		"at": "GenerateGarlicSessionManager",
	}).Debug("Generating new garlic session manager with fresh key pair")

	_, privBytes, err := ecies.GenerateKeyPair()
	if err != nil {
		log.WithError(err).Error("Failed to generate session manager key pair")
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
	messageID := int(binary.BigEndian.Uint32(msgIDBytes) & 0x7FFFFFFF)

	// Create I2NP Garlic message (type 11)
	msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_GARLIC)
	msg.SetMessageID(messageID)
	msg.SetExpiration(time.Now().Add(10 * time.Second))
	msg.data = encryptedGarlic

	return msg, nil
}
