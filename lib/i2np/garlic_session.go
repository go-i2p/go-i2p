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
// The raw garlic bytes are automatically wrapped in the ECIES-X25519-AEAD-Ratchet
// payload format (DateTime + GarlicClove blocks) required by the go-noise library.
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

	// Wrap raw garlic bytes in the ratchet payload format required by go-noise.
	// BuildNSPayload prepends a DateTime block and wraps the data as a GarlicClove block.
	// This format is required for New Session messages (ratchet.md §1b) and is also
	// valid for Existing Session messages (which accept any payload).
	payload, err := noiseratchet.BuildNSPayload(plaintextGarlic)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to build ratchet payload")
	}

	return sm.inner.EncryptGarlicMessage(hashArr, destinationPubKey, payload)
}

// DecryptGarlicMessage decrypts an encrypted garlic message.
// Handles both New Session and Existing Session message types.
//
// Returns:
//   - plaintext: the decrypted garlic payload
//   - sessionTag: the 8-byte tag used to identify the session (zero for NS and NSR)
//   - sessionHash: SHA-256(initiatorStaticPub) for New Session messages; nil otherwise.
//     Callers that need to send a New Session Reply must pass the dereferenced
//     value to EncryptNewSessionReply.
func (sm *GarlicSessionManager) DecryptGarlicMessage(encryptedGarlic []byte) ([]byte, [8]byte, *[32]byte, error) {
	payload, sessionTag, sessionHash, err := sm.inner.DecryptGarlicMessage(encryptedGarlic)
	if err != nil {
		return nil, [8]byte{}, nil, err
	}

	// Extract raw garlic bytes from the ratchet payload format.
	// Parse the payload blocks and return the first GarlicClove block's data.
	garlicData, err := extractGarlicFromPayload(payload)
	if err != nil {
		return nil, [8]byte{}, nil, oops.Wrapf(err, "failed to extract garlic from ratchet payload")
	}

	return garlicData, sessionTag, sessionHash, nil
}

// extractGarlicFromPayload parses a ratchet payload and returns the data from
// the first GarlicClove block. Returns an error if no GarlicClove block is found.
func extractGarlicFromPayload(payload []byte) ([]byte, error) {
	blocks, err := noiseratchet.ParsePayload(payload)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to parse ratchet payload")
	}

	for _, block := range blocks {
		if block.Type == noiseratchet.BlockGarlicClove {
			return block.Data, nil
		}
	}

	return nil, oops.Errorf("ratchet payload contains no GarlicClove block")
}

// ProcessIncomingDHRatchet processes a DH ratchet key received from a peer.
// The session is found by tag lookup using the sessionTag parameter.
func (sm *GarlicSessionManager) ProcessIncomingDHRatchet(sessionTag [8]byte, newRemotePubKey [32]byte) error {
	return sm.inner.ProcessIncomingDHRatchet(sessionTag, newRemotePubKey)
}

// GetPublicKey returns this session manager's X25519 public key.
func (sm *GarlicSessionManager) GetPublicKey() [32]byte {
	return sm.inner.GetPublicKey()
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

// EncryptNewSessionReply constructs a New Session Reply (NSR) for a session
// established by a received New Session message. The responder calls this
// to complete the Noise IK handshake and transition to Existing Session encryption.
//
// sessionHash is the [32]byte value returned by DecryptGarlicMessage (dereference
// the *[32]byte). payload is the reply plaintext.
func (sm *GarlicSessionManager) EncryptNewSessionReply(sessionHash [32]byte, payload []byte) ([]byte, error) {
	return sm.inner.EncryptNewSessionReply(sessionHash, payload)
}

// Close stops the cleanup loop, removes all sessions, and zeroes key material.
// It is safe to call Close multiple times.
func (sm *GarlicSessionManager) Close() error {
	return sm.inner.Close()
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

	msg := NewBaseI2NPMessage(I2NPMessageTypeGarlic)
	msg.SetMessageID(messageID)
	msg.SetExpiration(time.Now().Add(10 * time.Second))
	msg.data = encryptedGarlic

	return msg, nil
}
