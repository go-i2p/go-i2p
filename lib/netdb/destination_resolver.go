package netdb

import (
	"fmt"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/lease_set"
	"github.com/go-i2p/common/lease_set2"
	"github.com/go-i2p/logger"
)

// DestinationResolver resolves I2P destinations to their encryption public keys.
// It looks up LeaseSets from the NetDB and extracts the appropriate encryption key
// based on the destination's key type (ElGamal for legacy, X25519 for modern).
type DestinationResolver struct {
	netdb interface {
		GetLeaseSet(hash common.Hash) chan lease_set.LeaseSet
		GetLeaseSetBytes(hash common.Hash) ([]byte, error)
	}
}

// NewDestinationResolver creates a new destination resolver with the given NetDB.
// The netdb parameter must implement GetLeaseSet and GetLeaseSetBytes methods.
func NewDestinationResolver(netdb interface {
	GetLeaseSet(hash common.Hash) chan lease_set.LeaseSet
	GetLeaseSetBytes(hash common.Hash) ([]byte, error)
},
) *DestinationResolver {
	return &DestinationResolver{
		netdb: netdb,
	}
}

// ResolveDestination looks up a destination by its hash and returns the encryption public key.
// This supports both legacy LeaseSets (with ElGamal keys) and modern LeaseSet2 (with X25519 keys).
//
// The resolution process:
// 1. Look up the LeaseSet from NetDB using the destination hash
// 2. Extract the encryption key based on the LeaseSet type
// 3. Return the key in [32]byte format suitable for ECIES-X25519-AEAD encryption
//
// Returns:
// - publicKey: The X25519 public key for garlic encryption (32 bytes)
// - error: Non-nil if the destination cannot be resolved or has an unsupported key type
func (dr *DestinationResolver) ResolveDestination(destHash common.Hash) ([32]byte, error) {
	log.WithFields(logger.Fields{
		"at":               "DestinationResolver.ResolveDestination",
		"reason":           "lookup_requested",
		"destination_hash": fmt.Sprintf("%x...", destHash[:8]),
	}).Debug("resolving destination")

	// Try to get LeaseSet from NetDB
	lsChan := dr.netdb.GetLeaseSet(destHash)

	if lsChan == nil {
		log.WithFields(logger.Fields{
			"at":               "ResolveDestination",
			"destination_hash": fmt.Sprintf("%x", destHash[:8]),
			"reason":           "not found in netdb",
		}).Error("Destination lookup failed")
		return [32]byte{}, fmt.Errorf("destination %x not found in netdb", destHash[:8])
	}

	// Read from channel
	ls, ok := <-lsChan
	if !ok {
		log.WithFields(logger.Fields{
			"at":               "ResolveDestination",
			"destination_hash": fmt.Sprintf("%x", destHash[:8]),
			"reason":           "channel closed",
		}).Error("Failed to retrieve LeaseSet")
		return [32]byte{}, fmt.Errorf("failed to retrieve LeaseSet for destination %x", destHash[:8])
	}

	// Try to extract key from LeaseSet2 first (modern format)
	if key, err := dr.extractKeyFromLeaseSet2(destHash); err == nil {
		return key, nil
	}

	// Fall back to legacy LeaseSet format
	return dr.extractKeyFromLegacyLeaseSet(ls)
}

// extractKeyFromLeaseSet2 attempts to extract X25519 encryption key from LeaseSet2.
// LeaseSet2 can have multiple encryption keys with different types.
// We prefer X25519 (type 4) for ECIES-X25519-AEAD encryption.
func (dr *DestinationResolver) extractKeyFromLeaseSet2(destHash common.Hash) ([32]byte, error) {
	lsBytes, err := dr.fetchLeaseSetBytes(destHash)
	if err != nil {
		return [32]byte{}, err
	}

	ls2, err := dr.parseLeaseSet2(lsBytes)
	if err != nil {
		return [32]byte{}, err
	}

	return dr.findX25519KeyInLeaseSet2(ls2, destHash)
}

// fetchLeaseSetBytes retrieves raw LeaseSet bytes from NetDB.
func (dr *DestinationResolver) fetchLeaseSetBytes(destHash common.Hash) ([]byte, error) {
	lsBytes, err := dr.netdb.GetLeaseSetBytes(destHash)
	if err != nil {
		return nil, err
	}
	return lsBytes, nil
}

// parseLeaseSet2 validates and parses LeaseSet2 format bytes.
// Returns error if the data is not a valid LeaseSet2.
func (dr *DestinationResolver) parseLeaseSet2(lsBytes []byte) (lease_set2.LeaseSet2, error) {
	if err := dr.validateLeaseSet2Format(lsBytes); err != nil {
		return lease_set2.LeaseSet2{}, err
	}

	ls2, _, err := lease_set2.ReadLeaseSet2(lsBytes)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":     "parseLeaseSet2",
			"reason": "invalid LeaseSet2 data",
		}).WithError(err).Debug("LeaseSet2 parse failed")
		return lease_set2.LeaseSet2{}, fmt.Errorf("failed to parse LeaseSet2: %w", err)
	}

	return ls2, nil
}

// validateLeaseSet2Format checks if bytes could represent a valid LeaseSet2.
// The raw bytes from GetLeaseSetBytes do not contain a type prefix byte;
// they are the direct serialization of the LeaseSet structure (starting with
// the destination). We only check that data is non-empty here and rely on
// ReadLeaseSet2 for full format validation.
func (dr *DestinationResolver) validateLeaseSet2Format(lsBytes []byte) error {
	if len(lsBytes) == 0 {
		return fmt.Errorf("empty lease set data")
	}
	return nil
}

// findX25519KeyInLeaseSet2 searches for and extracts an X25519 encryption key.
// Returns the first X25519 key found, or an error if none exists.
func (dr *DestinationResolver) findX25519KeyInLeaseSet2(ls2 lease_set2.LeaseSet2, destHash common.Hash) ([32]byte, error) {
	encKeys := ls2.EncryptionKeys()

	for _, encKey := range encKeys {
		if encKey.KeyType == key_certificate.KEYCERT_CRYPTO_X25519 {
			return dr.extractValidX25519Key(encKey, destHash)
		}
	}

	log.WithFields(logger.Fields{
		"at":               "findX25519KeyInLeaseSet2",
		"destination_hash": fmt.Sprintf("%x", destHash[:8]),
		"reason":           "no X25519 encryption key found",
	}).Error("Encryption key not found in LeaseSet2")
	return [32]byte{}, fmt.Errorf("x25519 encryption key not found in lease set")
}

// extractValidX25519Key validates and extracts a 32-byte X25519 key from encryption key data.
func (dr *DestinationResolver) extractValidX25519Key(encKey lease_set2.EncryptionKey, destHash common.Hash) ([32]byte, error) {
	if len(encKey.KeyData) != 32 {
		log.WithFields(logger.Fields{
			"at":       "validateX25519KeyLength",
			"expected": 32,
			"actual":   len(encKey.KeyData),
			"reason":   "invalid key length",
		}).Error("X25519 key validation failed")
		return [32]byte{}, fmt.Errorf("invalid X25519 key length: %d", len(encKey.KeyData))
	}

	var pubKey [32]byte
	copy(pubKey[:], encKey.KeyData)

	log.WithField("destination_hash", fmt.Sprintf("%x", destHash[:8])).
		Debug("Extracted X25519 key from LeaseSet2")
	return pubKey, nil
}

// extractKeyFromLegacyLeaseSet extracts the encryption key from a legacy LeaseSet.
// Legacy LeaseSets use ElGamal encryption, which is incompatible with ECIES-X25519-AEAD.
// This returns an error indicating the destination uses unsupported encryption.
//
// Note: In a full implementation, we would need to support ElGamal for backward compatibility,
// but the current garlic encryption system only supports ECIES-X25519-AEAD.
func (dr *DestinationResolver) extractKeyFromLegacyLeaseSet(ls lease_set.LeaseSet) ([32]byte, error) {
	dest, err := ls.Destination()
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to get destination from LeaseSet: %w", err)
	}

	// Check if destination uses X25519 via key certificate
	if dest.KeyCertificate != nil {
		return dr.extractX25519KeyFromCertificate(dest)
	}

	// Legacy ElGamal key - not supported by current ECIES-X25519-AEAD implementation
	return [32]byte{}, fmt.Errorf("elgamal encryption not supported by ecies-x25519-aead")
}

// extractX25519KeyFromCertificate extracts an X25519 key from a destination's key certificate.
// Returns the X25519 key if the destination uses X25519 encryption, otherwise returns an error.
func (dr *DestinationResolver) extractX25519KeyFromCertificate(dest destination.Destination) ([32]byte, error) {
	certData, err := dest.KeyCertificate.Data()
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to read key certificate data: %w", err)
	}

	if len(certData) < 4 {
		return [32]byte{}, fmt.Errorf("key certificate data too short: expected at least 1 byte, got %d", len(certData))
	}

	// First 2 bytes are signing key type, next 2 are crypto key type
	cryptoType := uint16(certData[2])<<8 | uint16(certData[3])
	if cryptoType != key_certificate.KEYCERT_CRYPTO_X25519 {
		return [32]byte{}, fmt.Errorf("destination uses crypto type %d, not X25519", cryptoType)
	}

	return dr.extractX25519KeyBytes(dest)
}

// extractX25519KeyBytes extracts the X25519 key bytes from a destination's receiving public key.
func (dr *DestinationResolver) extractX25519KeyBytes(dest destination.Destination) ([32]byte, error) {
	pubKeyBytes := dest.ReceivingPublic.Bytes()
	if len(pubKeyBytes) != 32 {
		return [32]byte{}, fmt.Errorf("invalid X25519 key length in destination: %d", len(pubKeyBytes))
	}

	var key [32]byte
	copy(key[:], pubKeyBytes)

	log.WithFields(logger.Fields{
		"at":     "extractX25519KeyFromLegacyLeaseSet",
		"reason": "legacy_leaseset_x25519_dest",
	}).Debug("extracted X25519 key from legacy LeaseSet")
	return key, nil
}
