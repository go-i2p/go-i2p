package keys

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/crypto/ed25519"
)

// Persisted key file format v2 (all fields are fixed-size):
//
//   [4 bytes]  magic: "DKS\x02" (DestinationKeyStore v2)
//   [4 bytes]  signing private key length (big-endian uint32)
//   [N bytes]  signing private key (Ed25519, typically 64 bytes)
//   [4 bytes]  encryption private key length (big-endian uint32)
//   [M bytes]  encryption private key (X25519, typically 32 bytes)
//   [4 bytes]  padding length (big-endian uint32)
//   [P bytes]  identity padding bytes
//
// v1 format ("DKS\x01") is still readable for backward compatibility
// but v2 is always written to preserve identity stability.
//
// On load, the destination (public keys + KeysAndCert) is reconstructed
// deterministically from the private keys and persisted padding,
// ensuring a stable .b32.i2p address.
//
// All files are written with 0600 permissions. Directories use 0700.

var destinationKeyStoreMagicV1 = []byte("DKS\x01")
var destinationKeyStoreMagicV2 = []byte("DKS\x02")

// StoreKeys persists the destination key store to disk at the given path.
// The file contains the signing private key, encryption private key, and
// the full serialized destination (KeysAndCert), allowing exact reconstruction
// on load — preserving the same .b32.i2p address across restarts.
func (dks *DestinationKeyStore) StoreKeys(dir, name string) error {
	log.WithFields(map[string]interface{}{
		"at":   "DestinationKeyStore.StoreKeys",
		"dir":  dir,
		"name": name,
	}).Debug("Storing destination keys to disk")

	if err := ensureDirectoryExists(dir); err != nil {
		return fmt.Errorf("failed to create key directory: %w", err)
	}

	data, err := dks.marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal destination keys: %w", err)
	}

	filename := filepath.Join(dir, name+".dest.key")
	if err := os.WriteFile(filename, data, 0o600); err != nil {
		log.WithError(err).Error("Failed to write destination key file")
		return fmt.Errorf("failed to write destination key file: %w", err)
	}

	log.WithFields(map[string]interface{}{
		"at":   "DestinationKeyStore.StoreKeys",
		"file": filename,
	}).Debug("Successfully stored destination keys")
	return nil
}

// LoadDestinationKeyStore loads a previously persisted DestinationKeyStore from disk.
// Returns the reconstructed key store with the same destination identity (same .b32.i2p address).
func LoadDestinationKeyStore(dir, name string) (*DestinationKeyStore, error) {
	log.WithFields(map[string]interface{}{
		"at":   "LoadDestinationKeyStore",
		"dir":  dir,
		"name": name,
	}).Debug("Loading destination keys from disk")

	filename := filepath.Join(dir, name+".dest.key")
	data, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("destination key file not found: %s", filename)
		}
		return nil, fmt.Errorf("failed to read destination key file: %w", err)
	}

	dks, err := unmarshalDestinationKeyStore(data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal destination keys: %w", err)
	}

	log.WithField("at", "LoadDestinationKeyStore").Debug("Successfully loaded destination keys")
	return dks, nil
}

// LoadOrCreateDestinationKeyStore attempts to load an existing key store from disk.
// If no file exists, it creates a new key store with fresh keys and persists it.
// If the file exists but is corrupted or unreadable, an error is returned
// instead of silently generating a new identity (which would cause identity loss).
// This is the primary entry point for services that need a stable destination identity.
func LoadOrCreateDestinationKeyStore(dir, name string) (*DestinationKeyStore, error) {
	log.WithFields(map[string]interface{}{
		"at":   "LoadOrCreateDestinationKeyStore",
		"dir":  dir,
		"name": name,
	}).Debug("Loading or creating destination key store")

	dks, err := LoadDestinationKeyStore(dir, name)
	if err == nil {
		log.Debug("Loaded existing destination key store")
		return dks, nil
	}

	// Only create new keys if the file does not exist.
	// Any other error (corrupt file, permission denied) should be returned
	// to prevent silent identity loss.
	filename := filepath.Join(dir, name+".dest.key")
	if _, statErr := os.Stat(filename); statErr == nil || !os.IsNotExist(statErr) {
		// File exists but couldn't be loaded (corrupt/unreadable), or stat itself
		// failed (permission denied). Do NOT silently replace the identity.
		if statErr == nil {
			return nil, fmt.Errorf("destination key file exists but could not be loaded (refusing to overwrite — would cause identity loss): %w", err)
		}
		// statErr is non-nil but also not "not exist" — e.g. permission denied
		return nil, fmt.Errorf("cannot verify destination key file status: %w", statErr)
	}

	// File truly does not exist — safe to create fresh keys
	log.WithField("reason", err.Error()).Debug("Creating new destination key store")
	dks, err = NewDestinationKeyStore()
	if err != nil {
		return nil, fmt.Errorf("failed to create destination key store: %w", err)
	}

	if err := dks.StoreKeys(dir, name); err != nil {
		return nil, fmt.Errorf("failed to persist new destination key store: %w", err)
	}

	return dks, nil
}

// marshal serializes the DestinationKeyStore's private keys and padding into
// a byte slice using the DKS v2 format. Padding is included to ensure the
// destination identity hash remains stable across store/load cycles.
func (dks *DestinationKeyStore) marshal() ([]byte, error) {
	// Get raw bytes from the signing private key via type assertion
	sigPrivConcrete, ok := dks.signingPrivKey.(interface{ Bytes() []byte })
	if !ok {
		return nil, fmt.Errorf("signing private key does not support Bytes()")
	}
	sigPrivBytes := sigPrivConcrete.Bytes()

	encPrivBytes := dks.encryptionPrivKey.Bytes()

	paddingBytes := dks.padding
	if paddingBytes == nil {
		paddingBytes = []byte{}
	}

	// Calculate total size: magic + 3 x (4-byte length + field data)
	totalSize := len(destinationKeyStoreMagicV2) +
		4 + len(sigPrivBytes) +
		4 + len(encPrivBytes) +
		4 + len(paddingBytes)

	buf := make([]byte, 0, totalSize)

	// Magic (v2)
	buf = append(buf, destinationKeyStoreMagicV2...)

	// Signing private key
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(sigPrivBytes)))
	buf = append(buf, lenBuf...)
	buf = append(buf, sigPrivBytes...)

	// Encryption private key
	binary.BigEndian.PutUint32(lenBuf, uint32(len(encPrivBytes)))
	buf = append(buf, lenBuf...)
	buf = append(buf, encPrivBytes...)

	// Padding
	binary.BigEndian.PutUint32(lenBuf, uint32(len(paddingBytes)))
	buf = append(buf, lenBuf...)
	buf = append(buf, paddingBytes...)

	return buf, nil
}

// unmarshalDestinationKeyStore deserializes private keys (and padding if v2)
// and reconstructs the full DestinationKeyStore including the destination.
func unmarshalDestinationKeyStore(data []byte) (*DestinationKeyStore, error) {
	version, offset, err := detectFormatVersion(data)
	if err != nil {
		return nil, err
	}

	sigPrivBytes, encPrivBytes, err := readPrivateKeyFields(data, offset)
	if err != nil {
		return nil, err
	}

	var padding []byte
	if version == 2 {
		// Read past private key fields to find padding offset
		_, afterKeys, err := readPrivateKeyFieldsWithOffset(data, offset)
		if err != nil {
			return nil, err
		}
		padding, _, err = readLengthPrefixedField(data, afterKeys, "padding")
		if err != nil {
			return nil, err
		}
	}

	sigPrivKey, encPrivKey, err := reconstructPrivateKeys(sigPrivBytes, encPrivBytes)
	if err != nil {
		return nil, err
	}

	dest, err := reconstructDestinationWithPadding(sigPrivKey, encPrivKey, padding)
	if err != nil {
		return nil, err
	}

	return &DestinationKeyStore{
		destination:       dest,
		signingPrivKey:    sigPrivKey,
		encryptionPrivKey: encPrivKey,
		padding:           padding,
	}, nil
}

// detectFormatVersion checks the magic header and returns the version (1 or 2)
// and the offset past the header.
func detectFormatVersion(data []byte) (version int, offset int, err error) {
	if len(data) < 4 {
		return 0, 0, fmt.Errorf("data too short for magic header")
	}
	if matchesMagic(data, destinationKeyStoreMagicV2) {
		return 2, len(destinationKeyStoreMagicV2), nil
	}
	if matchesMagic(data, destinationKeyStoreMagicV1) {
		return 1, len(destinationKeyStoreMagicV1), nil
	}
	return 0, 0, fmt.Errorf("invalid magic header: not a destination key file")
}

// matchesMagic checks if data starts with the given magic bytes.
func matchesMagic(data, magic []byte) bool {
	if len(data) < len(magic) {
		return false
	}
	for i, b := range magic {
		if data[i] != b {
			return false
		}
	}
	return true
}

// readPrivateKeyFields reads the signing and encryption private key fields
// from the serialized data starting at the given offset.
func readPrivateKeyFields(data []byte, offset int) (sigPrivBytes, encPrivBytes []byte, err error) {
	sigPrivBytes, newOffset, err := readLengthPrefixedField(data, offset, "signing private key")
	if err != nil {
		return nil, nil, err
	}
	encPrivBytes, _, err = readLengthPrefixedField(data, newOffset, "encryption private key")
	if err != nil {
		return nil, nil, err
	}
	return sigPrivBytes, encPrivBytes, nil
}

// readPrivateKeyFieldsWithOffset is like readPrivateKeyFields but also returns
// the offset past both key fields, allowing callers to read additional fields.
func readPrivateKeyFieldsWithOffset(data []byte, offset int) (sigPrivBytes []byte, endOffset int, err error) {
	_, newOffset, err := readLengthPrefixedField(data, offset, "signing private key")
	if err != nil {
		return nil, 0, err
	}
	_, finalOffset, err := readLengthPrefixedField(data, newOffset, "encryption private key")
	if err != nil {
		return nil, 0, err
	}
	return nil, finalOffset, nil
}

// reconstructPrivateKeys rebuilds the private key objects from raw byte slices.
func reconstructPrivateKeys(sigPrivBytes, encPrivBytes []byte) (ed25519.Ed25519PrivateKey, *curve25519.Curve25519PrivateKey, error) {
	sigPrivKey, err := ed25519.NewEd25519PrivateKey(sigPrivBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to reconstruct signing private key: %w", err)
	}
	encPrivKey, err := curve25519.NewCurve25519PrivateKey(encPrivBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to reconstruct encryption private key: %w", err)
	}
	return sigPrivKey, encPrivKey, nil
}

// reconstructDestinationWithPadding rebuilds the full Destination from private keys
// using the provided padding bytes. If padding is nil (v1 format), fresh padding
// is generated per Proposal 161.
func reconstructDestinationWithPadding(sigPrivKey ed25519.Ed25519PrivateKey, encPrivKey *curve25519.Curve25519PrivateKey, padding []byte) (*destination.Destination, error) {
	sigPubKey, receivingPubKey, err := derivePublicKeys(sigPrivKey, encPrivKey)
	if err != nil {
		return nil, err
	}

	if padding != nil {
		return buildDestinationFromPublicKeysWithPadding(receivingPubKey, sigPubKey, padding)
	}
	return buildDestinationFromPublicKeys(receivingPubKey, sigPubKey)
}

// maxPrivateKeyFieldLength is the maximum allowed length for a private key field
// in the DKS format. Private keys should never exceed a few hundred bytes.
// This prevents OOM from crafted DKS files with large length fields.
const maxPrivateKeyFieldLength = 1024

// readLengthPrefixedField reads a 4-byte big-endian length followed by that many bytes.
func readLengthPrefixedField(data []byte, offset int, fieldName string) ([]byte, int, error) {
	if offset+4 > len(data) {
		return nil, 0, fmt.Errorf("data too short for %s length", fieldName)
	}
	length := int(binary.BigEndian.Uint32(data[offset : offset+4]))
	offset += 4

	if length > maxPrivateKeyFieldLength {
		return nil, 0, fmt.Errorf("%s length %d exceeds maximum allowed %d", fieldName, length, maxPrivateKeyFieldLength)
	}

	if offset+length > len(data) {
		return nil, 0, fmt.Errorf("data too short for %s data (need %d, have %d)", fieldName, length, len(data)-offset)
	}
	field := make([]byte, length)
	copy(field, data[offset:offset+length])
	offset += length

	return field, offset, nil
}
