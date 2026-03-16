package i2np

import (
	"fmt"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/go-noise/ratchet"
	"github.com/samber/oops"
)

// BuildRecordCrypto provides encryption/decryption for tunnel build records.
// This is a thin adapter that delegates to go-noise/ratchet.BuildRecordCrypto
// while handling I2P-specific type conversions (SessionKey, BuildResponseRecord,
// BuildRequestRecord, RouterInfo).
type BuildRecordCrypto struct {
	inner *ratchet.BuildRecordCrypto
}

// NewBuildRecordCrypto creates a new build record crypto handler.
func NewBuildRecordCrypto() *BuildRecordCrypto {
	return &BuildRecordCrypto{
		inner: ratchet.NewBuildRecordCrypto(),
	}
}

// EncryptReplyRecord encrypts a BuildResponseRecord using the reply key and IV.
// Serializes the record to bytes, converts SessionKey to [32]byte, then
// delegates to go-noise/ratchet.
func (c *BuildRecordCrypto) EncryptReplyRecord(
	record BuildResponseRecord,
	replyKey session_key.SessionKey,
	replyIV [16]byte,
) ([]byte, error) {
	// Serialize the record to raw bytes
	cleartext := ratchet.SerializeResponseRecord(record.Hash, record.RandomData, record.Reply)

	// Convert SessionKey to [32]byte
	var key [32]byte
	copy(key[:], replyKey[:])

	return c.inner.EncryptReplyRecord(cleartext, key, replyIV)
}

// DecryptReplyRecord decrypts an encrypted BuildResponseRecord.
// Delegates to go-noise/ratchet for decryption, then parses and verifies
// the result using I2P-specific types.
func (c *BuildRecordCrypto) DecryptReplyRecord(
	encryptedData []byte,
	replyKey session_key.SessionKey,
	replyIV [16]byte,
) (BuildResponseRecord, error) {
	// Convert SessionKey to [32]byte
	var key [32]byte
	copy(key[:], replyKey[:])

	// Delegate decryption to go-noise
	cleartext, err := c.inner.DecryptReplyRecord(encryptedData, key, replyIV)
	if err != nil {
		return BuildResponseRecord{}, err
	}

	// Parse the decrypted record
	record, err := ReadBuildResponseRecord(cleartext)
	if err != nil {
		return BuildResponseRecord{}, fmt.Errorf("failed to parse decrypted record: %w", err)
	}

	// Verify the hash
	if err := ratchet.VerifyResponseRecordHash(record.Hash, record.RandomData, record.Reply); err != nil {
		return BuildResponseRecord{}, fmt.Errorf("hash verification failed: %w", err)
	}

	log.Debug("Decrypted and verified build response record")
	return record, nil
}

// CreateBuildResponseRecord creates a new BuildResponseRecord with proper hash.
//
// Parameters:
//   - reply: Status code (0=accept, non-zero=reject reason)
//   - randomData: 495 bytes of random data (should be cryptographically random)
//
// Returns a BuildResponseRecord with the SHA-256 hash properly computed.
func CreateBuildResponseRecord(reply byte, randomData [495]byte) BuildResponseRecord {
	hash := ratchet.CreateBuildResponseRecordRaw(reply, randomData)
	return BuildResponseRecord{
		Hash:       hash,
		RandomData: randomData,
		Reply:      reply,
	}
}

// EncryptBuildRequestRecord encrypts a BuildRequestRecord using ECIES-X25519-AEAD.
//
// This adapter extracts the recipient's public key and identity hash from
// RouterInfo, serializes the BuildRequestRecord, then delegates ECIES
// encryption to go-noise/ratchet.
func EncryptBuildRequestRecord(record BuildRequestRecord, recipientRouterInfo router_info.RouterInfo) ([528]byte, error) {
	var encrypted [528]byte

	// Serialize the cleartext record (222 bytes)
	cleartext := record.Bytes()
	if len(cleartext) != 222 {
		return encrypted, oops.Errorf("invalid cleartext size: expected 222 bytes, got %d", len(cleartext))
	}

	// Extract recipient's X25519 public key from RouterInfo
	recipientPubKey, err := extractEncryptionPublicKey(recipientRouterInfo)
	if err != nil {
		return encrypted, oops.Wrapf(err, "failed to extract encryption public key")
	}

	// Calculate identity hash from RouterInfo
	identityHash, err := calculateIdentityHash(recipientRouterInfo)
	if err != nil {
		return encrypted, oops.Wrapf(err, "failed to calculate identity hash")
	}

	// Convert pubkey to [32]byte
	var pubKeyArr [32]byte
	copy(pubKeyArr[:], recipientPubKey)

	// Delegate ECIES encryption to go-noise
	crypto := ratchet.NewBuildRecordCrypto()
	return crypto.EncryptBuildRequest(cleartext, pubKeyArr, identityHash)
}

// DecryptBuildRequestRecord decrypts an encrypted BuildRequestRecord using ECIES-X25519-AEAD.
//
// This adapter delegates ECIES decryption to go-noise/ratchet, then parses
// the resulting 222-byte cleartext into a BuildRequestRecord.
func DecryptBuildRequestRecord(encrypted [528]byte, privateKey []byte) (BuildRequestRecord, error) {
	// Delegate ECIES decryption to go-noise
	crypto := ratchet.NewBuildRecordCrypto()
	cleartext, err := crypto.DecryptBuildRequest(encrypted, privateKey)
	if err != nil {
		return BuildRequestRecord{}, oops.Wrapf(err, "ECIES decryption failed")
	}

	// Parse the cleartext into BuildRequestRecord
	record, err := ReadBuildRequestRecord(cleartext)
	if err != nil {
		return BuildRequestRecord{}, oops.Wrapf(err, "failed to parse decrypted record")
	}

	log.WithField("record_size", 528).
		WithField("cleartext_size", len(cleartext)).
		Debug("BuildRequestRecord decrypted successfully")

	return record, nil
}

// extractEncryptionPublicKey retrieves the X25519 public encryption key from a RouterInfo.
func extractEncryptionPublicKey(routerInfo router_info.RouterInfo) ([]byte, error) {
	identity := routerInfo.RouterIdentity()
	if identity == nil {
		return nil, oops.Errorf("RouterInfo has nil RouterIdentity")
	}

	keysAndCert := identity.KeysAndCert
	if keysAndCert == nil {
		return nil, oops.Errorf("RouterIdentity has nil KeysAndCert")
	}

	pubKey, err := keysAndCert.PublicKey()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to get PublicKey from KeysAndCert")
	}
	if pubKey == nil {
		return nil, oops.Errorf("KeysAndCert has nil PublicKey")
	}

	pubKeyBytes := pubKey.Bytes()
	if len(pubKeyBytes) != 32 {
		return nil, oops.Errorf("invalid public key size: expected 32 bytes (X25519), got %d", len(pubKeyBytes))
	}

	return pubKeyBytes, nil
}

// calculateIdentityHash computes the SHA-256 hash of a RouterIdentity.
func calculateIdentityHash(routerInfo router_info.RouterInfo) ([32]byte, error) {
	identity := routerInfo.RouterIdentity()
	if identity == nil {
		return [32]byte{}, fmt.Errorf("RouterInfo has nil RouterIdentity")
	}
	if identity.KeysAndCert == nil {
		return [32]byte{}, fmt.Errorf("RouterIdentity has nil KeysAndCert")
	}
	identityBytes, err := identity.KeysAndCert.Bytes()
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to serialize RouterIdentity: %w", err)
	}
	return types.SHA256(identityBytes), nil
}

// VerifyIdentityHash checks if an encrypted BuildRequestRecord is intended for us.
// This adapter extracts the identity hash from RouterInfo, then delegates
// the byte comparison to go-noise/ratchet.
func VerifyIdentityHash(encrypted [528]byte, ourRouterInfo router_info.RouterInfo) bool {
	ourHash, err := calculateIdentityHash(ourRouterInfo)
	if err != nil {
		log.WithError(err).Warn("Failed to calculate identity hash for verification")
		return false
	}

	crypto := ratchet.NewBuildRecordCrypto()
	return crypto.VerifyIdentityHash(encrypted, ourHash)
}

// ExtractIdentityHashPrefix returns the first 16 bytes of an encrypted record
// as a common.Hash (remaining bytes zero).
func ExtractIdentityHashPrefix(encrypted [528]byte) common.Hash {
	raw := ratchet.ExtractIdentityHashPrefixRaw(encrypted)
	var hash common.Hash
	copy(hash[:], raw[:])
	return hash
}
