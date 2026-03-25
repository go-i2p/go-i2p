package netdb

import (
	"fmt"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/encrypted_leaseset"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/lease_set"
	"github.com/go-i2p/common/lease_set2"
	"github.com/go-i2p/common/meta_leaseset"
	"github.com/go-i2p/logger"
)

// DestinationResolver resolves I2P destinations to their encryption public keys.
// It looks up LeaseSets from the NetDB and extracts the appropriate encryption key
// based on the destination's key type (ElGamal for legacy, X25519 for modern).
//
// The resolver tries LeaseSet2 first (modern default since I2P 0.9.38), then falls
// back to classic LeaseSet. EncryptedLeaseSets are supported via
// ResolveEncryptedDestination, which requires the original destination and derives
// the blinded hash, subcredential, and decrypts the inner LeaseSet2.
// MetaLeaseSets are supported via ResolveMetaDestination, which fetches the
// MetaLeaseSet, selects the best entry by cost, and resolves the referenced LeaseSet.
type DestinationResolver struct {
	netdb interface {
		GetLeaseSet(hash common.Hash) chan lease_set.LeaseSet
		GetLeaseSetBytes(hash common.Hash) ([]byte, error)
		GetLeaseSet2Bytes(hash common.Hash) ([]byte, error)
		GetEncryptedLeaseSetBytes(hash common.Hash) ([]byte, error)
		GetMetaLeaseSetBytes(hash common.Hash) ([]byte, error)
	}
}

// NewDestinationResolver creates a new destination resolver with the given NetDB.
func NewDestinationResolver(netdb interface {
	GetLeaseSet(hash common.Hash) chan lease_set.LeaseSet
	GetLeaseSetBytes(hash common.Hash) ([]byte, error)
	GetLeaseSet2Bytes(hash common.Hash) ([]byte, error)
	GetEncryptedLeaseSetBytes(hash common.Hash) ([]byte, error)
	GetMetaLeaseSetBytes(hash common.Hash) ([]byte, error)
},
) *DestinationResolver {
	return &DestinationResolver{
		netdb: netdb,
	}
}

// ResolveDestination looks up a destination by its hash and returns the encryption public key.
// This supports both legacy LeaseSets (with ElGamal keys) and modern LeaseSet2 (with X25519 keys).
//
// The resolution process tries LeaseSet2 first (the modern default since I2P 0.9.38),
// then falls back to classic LeaseSet:
// 1. Try to get LeaseSet2 bytes from NetDB and extract X25519 key
// 2. If LeaseSet2 not found, try classic LeaseSet bytes parsed as LeaseSet2
// 3. If that also fails, try classic LeaseSet lookup and extract from legacy format
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

	// Try LeaseSet2 first (modern default since I2P 0.9.38)
	if key, err := dr.extractKeyFromLeaseSet2Direct(destHash); err == nil {
		return key, nil
	}

	// Try classic LeaseSet bytes parsed as LeaseSet2 (some stores may use classic bytes bucket)
	if key, err := dr.extractKeyFromLeaseSet2(destHash); err == nil {
		return key, nil
	}

	// Fall back to classic LeaseSet lookup
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

	// Extract key from legacy LeaseSet format
	return dr.extractKeyFromLegacyLeaseSet(ls)
}

// extractKeyFromLeaseSet2Direct attempts to extract X25519 encryption key from LeaseSet2
// using the dedicated GetLeaseSet2Bytes method. This is the preferred path since
// LeaseSet2 is the modern default (since I2P 0.9.38) and is stored separately in NetDB.
func (dr *DestinationResolver) extractKeyFromLeaseSet2Direct(destHash common.Hash) ([32]byte, error) {
	lsBytes, err := dr.netdb.GetLeaseSet2Bytes(destHash)
	if err != nil {
		return [32]byte{}, err
	}

	ls2, err := dr.parseLeaseSet2(lsBytes)
	if err != nil {
		return [32]byte{}, err
	}

	return dr.findX25519KeyInLeaseSet2(ls2, destHash)
}

// extractKeyFromLeaseSet2 attempts to extract X25519 encryption key from LeaseSet2.
// This uses classic GetLeaseSetBytes as a fallback — some stores may keep LeaseSet2 data
// in the classic bytes bucket.
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
// Note: This router intentionally supports only ECIES-X25519-AEAD destinations.
// ElGamal/AES+SessionTag is not and will not be implemented (see GAPS.md).
func (dr *DestinationResolver) extractKeyFromLegacyLeaseSet(ls lease_set.LeaseSet) ([32]byte, error) {
	dest := ls.Destination()

	// Check if destination uses X25519 via key certificate
	if dest.KeyCertificate != nil {
		return dr.extractX25519KeyFromCertificate(dest)
	}

	// Legacy ElGamal key — intentionally unsupported; this router only supports ECIES-X25519-AEAD
	return [32]byte{}, fmt.Errorf("destination uses ElGamal encryption which is intentionally unsupported; this router only supports ECIES-X25519-AEAD destinations (see GAPS.md)")
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

// ResolveEncryptedDestination resolves an I2P destination that publishes an
// EncryptedLeaseSet. The caller must supply the original (unblinded) destination
// so that the blinded lookup hash and subcredential can be derived.
//
// The resolution process:
//  1. Derive the blinded public key from the destination for today's date
//  2. Hash the blinded public key to get the NetDB lookup key
//  3. Retrieve the EncryptedLeaseSet from NetDB
//  4. Derive the subcredential from the original signing key and blinded key
//  5. Decrypt the inner LeaseSet2 using the subcredential
//  6. Extract the X25519 encryption key from the inner LeaseSet2
//
// Parameters:
//   - dest: The original (unblinded) destination. Must use Ed25519 signing key.
//   - secret: The per-destination secret used for blinding (may be nil for default).
//
// Returns:
//   - publicKey: The X25519 public key for garlic encryption (32 bytes)
//   - error: Non-nil if resolution fails at any step
func (dr *DestinationResolver) ResolveEncryptedDestination(dest destination.Destination, secret []byte) ([32]byte, error) {
	log.WithFields(logger.Fields{
		"at":     "DestinationResolver.ResolveEncryptedDestination",
		"reason": "encrypted_lookup_requested",
	}).Debug("resolving encrypted destination")

	// Step 1: Derive blinded public key for today
	blindedDest, err := encrypted_leaseset.CreateBlindedDestination(dest, secret, time.Now())
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to derive blinded destination: %w", err)
	}

	// Step 2: Hash blinded public key to get NetDB lookup key
	blindedSigningKey, err := blindedDest.SigningPublicKey()
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to get blinded signing key: %w", err)
	}
	lookupHash := common.HashData(blindedSigningKey.Bytes())

	log.WithFields(logger.Fields{
		"at":          "ResolveEncryptedDestination",
		"lookup_hash": fmt.Sprintf("%x...", lookupHash[:8]),
	}).Debug("looking up EncryptedLeaseSet")

	// Step 3: Retrieve EncryptedLeaseSet from NetDB
	elsBytes, err := dr.netdb.GetEncryptedLeaseSetBytes(lookupHash)
	if err != nil {
		return [32]byte{}, fmt.Errorf("EncryptedLeaseSet not found for blinded hash %x: %w", lookupHash[:8], err)
	}

	els, _, err := encrypted_leaseset.ReadEncryptedLeaseSet(elsBytes)
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to parse EncryptedLeaseSet: %w", err)
	}

	// Step 4: Derive subcredential from original signing key + blinded key
	origSigningKey, err := dest.SigningPublicKey()
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to get original signing key: %w", err)
	}
	subcredential := encrypted_leaseset.DeriveSubcredential(
		origSigningKey.Bytes(),
		els.BlindedPublicKey(),
	)

	// Step 5: Decrypt the inner LeaseSet2
	innerLS2, err := els.DecryptInnerData(subcredential)
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to decrypt EncryptedLeaseSet inner data: %w", err)
	}

	// Step 6: Extract X25519 encryption key from inner LeaseSet2
	destHash, err := dest.Hash()
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to hash destination: %w", err)
	}
	return dr.findX25519KeyInLeaseSet2(*innerLS2, destHash)
}

// maxMetaRecursionDepth limits how deep nested MetaLeaseSet resolution can go,
// preventing infinite recursion from circular references.
const maxMetaRecursionDepth = 3

// ResolveMetaDestination resolves a destination that publishes a MetaLeaseSet (type 7).
// A MetaLeaseSet is a directory of other LeaseSets; each entry references a
// LeaseSet by its hash and includes a cost metric for load balancing.
//
// The resolution process:
//  1. Retrieve the MetaLeaseSet from NetDB by destHash
//  2. Sort entries by cost (lowest first) and filter out expired entries
//  3. For each entry, attempt to resolve the referenced LeaseSet (LS2 or classic)
//  4. Return the X25519 key from the first successfully resolved entry
//
// Returns:
//   - publicKey: The X25519 public key from the best available component LeaseSet
//   - error: Non-nil if no component LeaseSet can be resolved
func (dr *DestinationResolver) ResolveMetaDestination(destHash common.Hash) ([32]byte, error) {
	return dr.resolveMetaDestinationWithDepth(destHash, 0)
}

// resolveMetaDestinationWithDepth is the depth-limited implementation of ResolveMetaDestination.
func (dr *DestinationResolver) resolveMetaDestinationWithDepth(destHash common.Hash, depth int) ([32]byte, error) {
	if depth >= maxMetaRecursionDepth {
		return [32]byte{}, fmt.Errorf("MetaLeaseSet recursion depth exceeded (%d)", maxMetaRecursionDepth)
	}

	log.WithFields(logger.Fields{
		"at":               "DestinationResolver.ResolveMetaDestination",
		"reason":           "meta_lookup_requested",
		"destination_hash": fmt.Sprintf("%x...", destHash[:8]),
		"depth":            depth,
	}).Debug("resolving MetaLeaseSet destination")

	mls, err := dr.fetchMetaLeaseSet(destHash)
	if err != nil {
		return [32]byte{}, err
	}

	validEntries := filterValidMetaEntries(mls.SortEntriesByCost())
	if len(validEntries) == 0 {
		return [32]byte{}, fmt.Errorf("all MetaLeaseSet entries are expired")
	}

	log.WithFields(logger.Fields{
		"at":            "ResolveMetaDestination",
		"valid_entries": len(validEntries),
	}).Debug("found valid MetaLeaseSet entries")

	return dr.resolveFirstValidEntry(validEntries, depth)
}

// fetchMetaLeaseSet retrieves and parses a MetaLeaseSet from the NetDB.
func (dr *DestinationResolver) fetchMetaLeaseSet(destHash common.Hash) (meta_leaseset.MetaLeaseSet, error) {
	mlsBytes, err := dr.netdb.GetMetaLeaseSetBytes(destHash)
	if err != nil {
		return meta_leaseset.MetaLeaseSet{}, fmt.Errorf("MetaLeaseSet not found for hash %x: %w", destHash[:8], err)
	}
	mls, _, err := meta_leaseset.ReadMetaLeaseSet(mlsBytes)
	if err != nil {
		return meta_leaseset.MetaLeaseSet{}, fmt.Errorf("failed to parse MetaLeaseSet: %w", err)
	}
	return mls, nil
}

// filterValidMetaEntries returns only the entries that have not expired.
func filterValidMetaEntries(entries []meta_leaseset.MetaLeaseSetEntry) []meta_leaseset.MetaLeaseSetEntry {
	now := time.Now()
	var valid []meta_leaseset.MetaLeaseSetEntry
	for _, entry := range entries {
		if entry.ExpiresTime().After(now) {
			valid = append(valid, entry)
		}
	}
	return valid
}

// resolveFirstValidEntry tries each entry in order and returns the first successful resolution.
func (dr *DestinationResolver) resolveFirstValidEntry(entries []meta_leaseset.MetaLeaseSetEntry, depth int) ([32]byte, error) {
	for _, entry := range entries {
		entryHash := entry.Hash()
		key, err := dr.resolveMetaEntryWithDepth(entryHash, entry.Type(), depth)
		if err == nil {
			return key, nil
		}
		log.WithFields(logger.Fields{
			"at":         "ResolveMetaDestination",
			"entry_hash": fmt.Sprintf("%x...", entryHash[:8]),
			"entry_type": entry.Type(),
			"error":      err.Error(),
		}).Debug("MetaLeaseSet entry resolution failed, trying next")
	}
	return [32]byte{}, fmt.Errorf("no resolvable component LeaseSet found in MetaLeaseSet")
}

// resolveMetaEntryWithDepth attempts to resolve a single MetaLeaseSet entry by its hash
// and type. Supports LeaseSet (1), LeaseSet2 (3), EncryptedLeaseSet (5), and
// recursive MetaLeaseSet (7) per the I2P MetaLeaseSet specification.
func (dr *DestinationResolver) resolveMetaEntryWithDepth(entryHash [32]byte, entryType uint8, depth int) ([32]byte, error) {
	hash := common.Hash(entryHash)

	switch entryType {
	case 1: // Classic LeaseSet
		return dr.extractKeyFromLeaseSet2(hash)
	case 3: // LeaseSet2
		return dr.extractKeyFromLeaseSet2Direct(hash)
	case 5: // EncryptedLeaseSet - requires decryption, fall back to LS2 lookup
		if key, err := dr.extractKeyFromLeaseSet2Direct(hash); err == nil {
			return key, nil
		}
		return dr.extractKeyFromLeaseSet2(hash)
	case 7: // Nested MetaLeaseSet (recursive, depth-limited)
		return dr.resolveMetaDestinationWithDepth(hash, depth+1)
	default: // type 0 (unknown) — try LS2 then classic
		if key, err := dr.extractKeyFromLeaseSet2Direct(hash); err == nil {
			return key, nil
		}
		return dr.extractKeyFromLeaseSet2(hash)
	}
}
