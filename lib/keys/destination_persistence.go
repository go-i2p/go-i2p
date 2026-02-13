package keys

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/crypto/ed25519"
	"github.com/go-i2p/crypto/types"
)

// Persisted key file format (all fields are fixed-size):
//
//   [4 bytes]  magic: "DKS\x01" (DestinationKeyStore v1)
//   [4 bytes]  signing private key length (big-endian uint32)
//   [N bytes]  signing private key (Ed25519, typically 64 bytes)
//   [4 bytes]  encryption private key length (big-endian uint32)
//   [M bytes]  encryption private key (X25519, typically 32 bytes)
//
// On load, the destination (public keys + KeysAndCert) is reconstructed
// deterministically from the private keys, ensuring a stable .b32.i2p address.
//
// All files are written with 0600 permissions. Directories use 0700.

var destinationKeyStoreMagic = []byte("DKS\x01")

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

// marshal serializes the DestinationKeyStore's private keys into a byte slice.
// Only private keys are stored; the destination is reconstructed from them on load.
func (dks *DestinationKeyStore) marshal() ([]byte, error) {
	// Get raw bytes from the signing private key via type assertion
	sigPrivConcrete, ok := dks.signingPrivKey.(interface{ Bytes() []byte })
	if !ok {
		return nil, fmt.Errorf("signing private key does not support Bytes()")
	}
	sigPrivBytes := sigPrivConcrete.Bytes()

	encPrivBytes := dks.encryptionPrivKey.Bytes()

	// Calculate total size: magic + 2 x (4-byte length + key data)
	totalSize := len(destinationKeyStoreMagic) +
		4 + len(sigPrivBytes) +
		4 + len(encPrivBytes)

	buf := make([]byte, 0, totalSize)

	// Magic
	buf = append(buf, destinationKeyStoreMagic...)

	// Signing private key
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(sigPrivBytes)))
	buf = append(buf, lenBuf...)
	buf = append(buf, sigPrivBytes...)

	// Encryption private key
	binary.BigEndian.PutUint32(lenBuf, uint32(len(encPrivBytes)))
	buf = append(buf, lenBuf...)
	buf = append(buf, encPrivBytes...)

	return buf, nil
}

// unmarshalDestinationKeyStore deserializes private keys and reconstructs
// the full DestinationKeyStore including the destination (public keys + KeysAndCert).
func unmarshalDestinationKeyStore(data []byte) (*DestinationKeyStore, error) {
	if len(data) < len(destinationKeyStoreMagic) {
		return nil, fmt.Errorf("data too short for magic header")
	}

	// Verify magic
	for i, b := range destinationKeyStoreMagic {
		if data[i] != b {
			return nil, fmt.Errorf("invalid magic header: not a destination key file")
		}
	}
	offset := len(destinationKeyStoreMagic)

	// Read signing private key
	sigPrivBytes, newOffset, err := readLengthPrefixedField(data, offset, "signing private key")
	if err != nil {
		return nil, err
	}
	offset = newOffset

	// Read encryption private key
	encPrivBytes, _, err := readLengthPrefixedField(data, offset, "encryption private key")
	if err != nil {
		return nil, err
	}

	// Reconstruct private keys from raw bytes
	sigPrivKey, err := ed25519.NewEd25519PrivateKey(sigPrivBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct signing private key: %w", err)
	}
	encPrivKey, err := curve25519.NewCurve25519PrivateKey(encPrivBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct encryption private key: %w", err)
	}

	// Derive public keys from private keys
	sigPubKey, err := sigPrivKey.Public()
	if err != nil {
		return nil, fmt.Errorf("failed to derive signing public key: %w", err)
	}
	encPubKey, err := encPrivKey.Public()
	if err != nil {
		return nil, fmt.Errorf("failed to derive encryption public key: %w", err)
	}

	// Convert to the types expected by assembleKeysAndCert
	receivingPubKey, ok := encPubKey.(types.ReceivingPublicKey)
	if !ok {
		return nil, fmt.Errorf("encryption public key does not implement ReceivingPublicKey")
	}

	// Reconstruct the destination using the same assembly path as NewDestinationKeyStore
	keyCert, err := createKeyCertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to create key certificate: %w", err)
	}

	padding, err := calculateKeyPadding()
	if err != nil {
		return nil, fmt.Errorf("failed to calculate key padding: %w", err)
	}

	keysAndCert, err := assembleKeysAndCert(keyCert, receivingPubKey, padding, sigPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to assemble keys and cert: %w", err)
	}

	dest := &destination.Destination{
		KeysAndCert: keysAndCert,
	}

	return &DestinationKeyStore{
		destination:       dest,
		signingPrivKey:    sigPrivKey,
		encryptionPrivKey: encPrivKey,
	}, nil
}

// readLengthPrefixedField reads a 4-byte big-endian length followed by that many bytes.
func readLengthPrefixedField(data []byte, offset int, fieldName string) ([]byte, int, error) {
	if offset+4 > len(data) {
		return nil, 0, fmt.Errorf("data too short for %s length", fieldName)
	}
	length := int(binary.BigEndian.Uint32(data[offset : offset+4]))
	offset += 4

	if offset+length > len(data) {
		return nil, 0, fmt.Errorf("data too short for %s data (need %d, have %d)", fieldName, length, len(data)-offset)
	}
	field := make([]byte, length)
	copy(field, data[offset:offset+length])
	offset += length

	return field, offset, nil
}
