package i2np

import (
	"context"
	"encoding/binary"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/crypto/rand"
	noiseratchet "github.com/go-i2p/go-noise/ratchet"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// GarlicSessionManager is a thin adapter around go-noise/ratchet.SessionManager.
// It translates between the go-i2p common.Hash type used in the I2NP layer and the
// [32]byte type used in the go-noise ratchet layer.
//
// All cryptographic operations (ECIES key exchange, ratchet advancement, encryption,
// and decryption) are delegated to the underlying ratchet.SessionManager.
//
// Session lifecycle:
//  1. New Session: First message uses ephemeral-static DH (ECIES)
//  2. Existing Session: Subsequent messages use ratchet for forward secrecy
//  3. Session Expiry: Sessions expire after inactivity timeout
type GarlicSessionManager struct {
	inner *noiseratchet.SessionManager
}

// NewGarlicSessionManager creates a new garlic session manager with the given private key.
// The private key is used for decrypting New Session messages.
func NewGarlicSessionManager(privateKey [32]byte) (*GarlicSessionManager, error) {
	log.WithFields(logger.Fields{
		"at": "NewGarlicSessionManager",
	}).Debug("Creating new garlic session manager")

	inner, err := noiseratchet.NewSessionManager(privateKey)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create session manager")
	}

	return &GarlicSessionManager{inner: inner}, nil
}

// GenerateGarlicSessionManager creates a session manager with a fresh key pair.
func GenerateGarlicSessionManager() (*GarlicSessionManager, error) {
	log.WithFields(logger.Fields{
		"at": "GenerateGarlicSessionManager",
	}).Debug("Generating new garlic session manager with fresh key pair")

	inner, err := noiseratchet.GenerateSessionManager()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to generate session manager")
	}

	return &GarlicSessionManager{inner: inner}, nil
}

// EncryptGarlicMessage encrypts a plaintext garlic message for the given destination.
// This translates the common.Hash destinationHash to [32]byte and delegates to
// the underlying ratchet.SessionManager.
//
// Parameters:
//   - destinationHash: Hash of the destination's public key (common.Hash)
//   - destinationPubKey: The destination's X25519 public key (32 bytes)
//   - plaintextGarlic: Serialized garlic message (from GarlicBuilder.BuildAndSerialize)
//
// Returns encrypted garlic message ready to send via I2NP.
func (sm *GarlicSessionManager) EncryptGarlicMessage(
	destinationHash common.Hash,
	destinationPubKey [32]byte,
	plaintextGarlic []byte,
) ([]byte, error) {
	var hashArr [32]byte = [32]byte(destinationHash)

	return sm.inner.EncryptGarlicMessage(hashArr, destinationPubKey, plaintextGarlic)
}

// DecryptGarlicMessage decrypts an encrypted garlic message.
// Handles both New Session and Existing Session message types.
func (sm *GarlicSessionManager) DecryptGarlicMessage(encryptedGarlic []byte) ([]byte, [8]byte, error) {
	return sm.inner.DecryptGarlicMessage(encryptedGarlic)
}

// ProcessIncomingDHRatchet processes a DH ratchet key received from a peer.
// The session is found by tag lookup using the sessionTag parameter.
func (sm *GarlicSessionManager) ProcessIncomingDHRatchet(sessionTag [8]byte, newRemotePubKey [32]byte) error {
	return sm.inner.ProcessIncomingDHRatchet(sessionTag, newRemotePubKey)
}

// GetSessionCount returns the number of active sessions.
func (sm *GarlicSessionManager) GetSessionCount() int {
	return sm.inner.GetSessionCount()
}

// CleanupExpiredSessions removes sessions that haven't been used recently.
func (sm *GarlicSessionManager) CleanupExpiredSessions() int {
	return sm.inner.CleanupExpiredSessions()
}

// StartCleanupLoop starts periodic cleanup of expired sessions.
func (sm *GarlicSessionManager) StartCleanupLoop(ctx context.Context) {
	sm.inner.StartCleanupLoop(ctx)
}

// EncryptGarlicWithBuilder is a convenience function that builds and encrypts a garlic message.
// This combines GarlicBuilder.BuildAndSerialize with GarlicSessionManager.EncryptGarlicMessage.
func EncryptGarlicWithBuilder(
	sm *GarlicSessionManager,
	builder *GarlicBuilder,
	destinationHash common.Hash,
	destinationPubKey [32]byte,
) ([]byte, error) {
	plaintext, err := builder.BuildAndSerialize()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to build garlic message")
	}

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

	msgIDBytes := make([]byte, 4)
	if _, err := rand.Read(msgIDBytes); err != nil {
		return nil, oops.Wrapf(err, "failed to generate message ID")
	}
	messageID := int(binary.BigEndian.Uint32(msgIDBytes) & 0x7FFFFFFF)

	msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_GARLIC)
	msg.SetMessageID(messageID)
	msg.SetExpiration(time.Now().Add(10 * time.Second))
	msg.data = encryptedGarlic

	return msg, nil
}
