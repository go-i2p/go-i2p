package i2np

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
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

	// oneTimeDiag mirrors one-time tag registrations for diagnostics only.
	// It helps correlate inbound garlic tags with registration activity.
	oneTimeDiagMu sync.Mutex
	oneTimeDiag   map[[8]byte]struct{}
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

	return &GarlicSessionManager{inner: inner, oneTimeDiag: make(map[[8]byte]struct{})}, nil
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

	return &GarlicSessionManager{inner: inner, oneTimeDiag: make(map[[8]byte]struct{})}, nil
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
	hashArr := [32]byte(destinationHash)

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
//   - cloves: all GarlicClove payloads from the ratchet payload. A spec-compliant
//     payload may contain more than one GarlicClove block; all are returned so that
//     every clove's delivery instructions are executed rather than silently dropped.
//   - sessionTag: the 8-byte tag used to identify the session (zero for NS and NSR)
//   - sessionHash: SHA-256(initiatorStaticPub) for New Session messages; nil otherwise.
//     Callers that need to send a New Session Reply must pass the dereferenced
//     value to EncryptNewSessionReply.
func (sm *GarlicSessionManager) DecryptGarlicMessage(encryptedGarlic []byte) ([][]byte, [8]byte, *[32]byte, error) {
	incomingTag := sm.extractIncomingTag(encryptedGarlic)
	oneTimeTagRegistered, oneTimeTagMapSizeBefore := sm.getOneTimeTagDiagnostics(incomingTag)

	sm.logDecryptStart(incomingTag, oneTimeTagRegistered, oneTimeTagMapSizeBefore, len(encryptedGarlic))

	payload, sessionTag, sessionHash, err := sm.inner.DecryptGarlicMessage(encryptedGarlic)

	oneTimeTagMapSizeAfter := sm.cleanupOneTimeTag(incomingTag, oneTimeTagRegistered)

	if err != nil {
		sm.logDecryptFailure(incomingTag, oneTimeTagRegistered, oneTimeTagMapSizeAfter, err)
		return nil, [8]byte{}, nil, err
	}

	sm.logDecryptSuccess(incomingTag, oneTimeTagRegistered, oneTimeTagMapSizeAfter, sessionTag)

	garlicData, err := extractGarlicFromPayload(payload)
	if err != nil {
		return nil, [8]byte{}, nil, oops.Wrapf(err, "failed to extract garlic from ratchet payload")
	}

	return garlicData, sessionTag, sessionHash, nil
}

// extractIncomingTag extracts the 8-byte session tag from the encrypted message.
func (sm *GarlicSessionManager) extractIncomingTag(encryptedGarlic []byte) [8]byte {
	var incomingTag [8]byte
	if len(encryptedGarlic) >= 8 {
		copy(incomingTag[:], encryptedGarlic[:8])
	}
	return incomingTag
}

// getOneTimeTagDiagnostics retrieves diagnostic information about a one-time tag.
func (sm *GarlicSessionManager) getOneTimeTagDiagnostics(incomingTag [8]byte) (bool, int) {
	sm.oneTimeDiagMu.Lock()
	defer sm.oneTimeDiagMu.Unlock()
	_, oneTimeTagRegistered := sm.oneTimeDiag[incomingTag]
	return oneTimeTagRegistered, len(sm.oneTimeDiag)
}

// cleanupOneTimeTag removes a one-time tag if it was registered and returns the current map size.
func (sm *GarlicSessionManager) cleanupOneTimeTag(incomingTag [8]byte, oneTimeTagRegistered bool) int {
	sm.oneTimeDiagMu.Lock()
	defer sm.oneTimeDiagMu.Unlock()
	if oneTimeTagRegistered {
		delete(sm.oneTimeDiag, incomingTag)
	}
	return len(sm.oneTimeDiag)
}

// logDecryptStart logs diagnostics at the start of decryption.
func (sm *GarlicSessionManager) logDecryptStart(incomingTag [8]byte, oneTimeTagRegistered bool, mapSize, encryptedSize int) {
	if encryptedSize >= 8 {
		ourPubKey := sm.GetPublicKey()
		ourPubKeyHex := fmt.Sprintf("%x", ourPubKey[:8])

		log.WithFields(logger.Fields{
			"at":                           "DecryptGarlicMessage",
			"incoming_tag":                 fmt.Sprintf("%x", incomingTag),
			"one_time_tag_registered":      oneTimeTagRegistered,
			"one_time_tag_map_size_before": mapSize,
			"encrypted_size":               encryptedSize,
			"our_public_key":               ourPubKeyHex,
			"session_count":                sm.GetSessionCount(),
		}).Debug("Garlic decrypt starting - checking key compatibility")
	}
}

// logDecryptFailure logs diagnostics when decryption fails.
// CONTEXT: Noise IK authentication failures are EXPECTED when:
//  1. Peers have cached OLD RouterInfo with different X25519 key
//  2. Our router restarted/regenerated keys but hasn't republished yet
//  3. Network hasn't converged on newest RouterInfo version
//
// Solution: RouterInfo republish is handled by publisher.ForceRouterInfoRepublish()
func (sm *GarlicSessionManager) logDecryptFailure(incomingTag [8]byte, oneTimeTagRegistered bool, mapSize int, err error) {
	ourPubKey := sm.GetPublicKey()
	ourPubKeyHex := fmt.Sprintf("%x", ourPubKey[:8])

	errStr := fmt.Sprintf("%v", err)
	isNoiseError := strings.Contains(errStr, "chacha20poly1305") || strings.Contains(errStr, "Noise IK")

	// Log as INFO (not WARN) for expected Noise IK failures from old RouterInfo cached at peers
	logLevel := "Info"
	if isNoiseError {
		logLevel = "Info (expected from old cached RouterInfo at peers)"
	}

	log.WithFields(logger.Fields{
		"at":                          "DecryptGarlicMessage",
		"incoming_tag":                fmt.Sprintf("%x", incomingTag),
		"one_time_tag_registered":     oneTimeTagRegistered,
		"one_time_tag_map_size_after": mapSize,
		"our_public_key":              ourPubKeyHex,
		"session_count":               sm.GetSessionCount(),
		"error":                       err,
		"is_crypto_error":             isNoiseError,
		"log_level":                   logLevel,
		"mitigation":                  "call publisher.ForceRouterInfoRepublish() to propagate current key",
	}).Info("Garlic decrypt failed - likely cause is peers have old cached RouterInfo with different X25519 key")
}

// logDecryptSuccess logs diagnostics when decryption succeeds.
func (sm *GarlicSessionManager) logDecryptSuccess(incomingTag [8]byte, oneTimeTagRegistered bool, mapSize int, sessionTag [8]byte) {
	log.WithFields(logger.Fields{
		"at":                          "DecryptGarlicMessage",
		"incoming_tag":                fmt.Sprintf("%x", incomingTag),
		"one_time_tag_registered":     oneTimeTagRegistered,
		"one_time_tag_map_size_after": mapSize,
		"session_tag":                 fmt.Sprintf("%x", sessionTag),
	}).Debug("Garlic decrypt succeeded")
}

// extractGarlicFromPayload parses a ratchet payload and returns the data from
// all GarlicClove blocks. A spec-compliant ECIES-X25519-AEAD-Ratchet payload may
// contain more than one GarlicClove block; returning only the first would silently
// drop the remaining cloves' delivery instructions.
// Returns an error if no GarlicClove block is found.
func extractGarlicFromPayload(payload []byte) ([][]byte, error) {
	log.WithFields(logger.Fields{
		"at":          "extractGarlicFromPayload",
		"payload_len": len(payload),
		"payload_hex": fmt.Sprintf("%x", payload[:min(len(payload), 64)]),
	}).Debug("Extracting garlic from ratchet payload")

	blocks, err := noiseratchet.ParsePayload(payload)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to parse ratchet payload")
	}

	log.WithFields(logger.Fields{
		"at":          "extractGarlicFromPayload",
		"block_count": len(blocks),
	}).Debug("Parsed ratchet payload blocks")

	var cloves [][]byte
	for i, block := range blocks {
		log.WithFields(logger.Fields{
			"at":         "extractGarlicFromPayload",
			"block_idx":  i,
			"block_type": block.Type,
			"data_len":   len(block.Data),
			"data_hex":   fmt.Sprintf("%x", block.Data[:min(len(block.Data), 32)]),
		}).Debug("Ratchet payload block")

		if block.Type == noiseratchet.BlockGarlicClove {
			log.WithFields(logger.Fields{
				"at":        "extractGarlicFromPayload",
				"clove_idx": len(cloves),
				"data_len":  len(block.Data),
				"data_head": fmt.Sprintf("%x", block.Data[:min(len(block.Data), 32)]),
			}).Debug("Found GarlicClove block")
			cloves = append(cloves, block.Data)
		}
	}

	if len(cloves) == 0 {
		return nil, oops.Errorf("ratchet payload contains no GarlicClove block")
	}

	log.WithFields(logger.Fields{
		"at":          "extractGarlicFromPayload",
		"clove_count": len(cloves),
	}).Debug("Extracted GarlicClove blocks from ratchet payload")

	return cloves, nil
}

// ProcessIncomingDHRatchet processes a DH ratchet key received from a peer.
// The session is found by tag lookup using the sessionTag parameter.
func (sm *GarlicSessionManager) ProcessIncomingDHRatchet(sessionTag [8]byte, newRemotePubKey [32]byte) error {
	return sm.inner.ProcessIncomingDHRatchet(sessionTag, newRemotePubKey)
}

// RegisterOneTimeGarlicKey registers a one-time symmetric garlic key derived
// from a STBM Noise transcript hash via HKDF("AttachLayerEncryption"). The
// OBEP uses this key to wrap the ShortTunnelBuildReply garlic; it is consumed
// on first use and never reused.
//
// tag is garlicKeyMaterial[24:32], key is garlicKeyMaterial[0:32].
func (sm *GarlicSessionManager) RegisterOneTimeGarlicKey(tag [8]byte, key [32]byte) {
	sm.oneTimeDiagMu.Lock()
	// M-NEW-1 FIX: Cap the diagnostic map to prevent unbounded growth from
	// failed/dropped tunnel builds whose tags are never consumed.
	// When at capacity, evict an arbitrary existing entry before inserting.
	const maxOneTimeDiagEntries = 10_000
	if len(sm.oneTimeDiag) >= maxOneTimeDiagEntries {
		for oldest := range sm.oneTimeDiag {
			delete(sm.oneTimeDiag, oldest)
			break
		}
	}
	sm.oneTimeDiag[tag] = struct{}{}
	oneTimeTagMapSize := len(sm.oneTimeDiag)
	sm.oneTimeDiagMu.Unlock()

	log.WithFields(logger.Fields{
		"at":                    "RegisterOneTimeGarlicKey",
		"tag":                   fmt.Sprintf("%x", tag),
		"one_time_tag_map_size": oneTimeTagMapSize,
	}).Debug("Registered one-time garlic key (diagnostic mirror)")

	sm.inner.RegisterOneTimeKey(tag, key)
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
