package keys

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/logger"
)

// KeyStore is an interface for storing and retrieving keys
type KeyStore interface {
	KeyID() string
	// GetKeys returns the public and private keys
	GetKeys() (publicKey types.PublicKey, privateKey types.PrivateKey, err error)
	// StoreKeys stores the keys
	StoreKeys() error
}

type KeyStoreImpl struct {
	dir        string
	name       string
	privateKey types.PrivateKey

	// cachedKeyID stores the computed KeyID to ensure deterministic behavior
	cachedKeyID     string
	cachedKeyIDOnce sync.Once
}

func NewKeyStoreImpl(dir, name string, privateKey types.PrivateKey) *KeyStoreImpl {
	log.WithFields(logger.Fields{
		"at":   "NewKeyStoreImpl",
		"dir":  dir,
		"name": name,
	}).Debug("Creating new KeyStore implementation")
	return &KeyStoreImpl{
		dir:        dir,
		name:       name,
		privateKey: privateKey,
	}
}

func (ks *KeyStoreImpl) KeyID() string {
	// Use sync.Once to ensure deterministic KeyID across multiple calls
	ks.cachedKeyIDOnce.Do(func() {
		ks.cachedKeyID = ks.computeKeyID()
	})
	return ks.cachedKeyID
}

// computeKeyID generates a deterministic, filesystem-safe key identifier
func (ks *KeyStoreImpl) computeKeyID() string {
	if ks.name == "" {
		log.WithField("at", "computeKeyID").Debug("Generating KeyID from public key")
		public, err := ks.privateKey.Public()
		if err != nil {
			log.WithError(err).Warn("Failed to get public key, generating fallback ID")
			// Generate a deterministic fallback ID using the private key bytes
			// to ensure the same key always maps to the same file, even across restarts.
			pkBytes := ks.privateKey.Bytes()
			if len(pkBytes) > 10 {
				pkBytes = pkBytes[:10]
			}
			fallbackID := "unknown-" + hex.EncodeToString(pkBytes)
			log.WithField("fallback_id", fallbackID).Debug("Generated fallback KeyID")
			return fallbackID
		}
		// Use hex encoding to create a filesystem-safe identifier
		// Raw binary bytes can contain null bytes, path separators, or other unsafe characters
		keyBytes := public.Bytes()
		if len(keyBytes) > 10 {
			keyBytes = keyBytes[:10]
		}
		hexID := hex.EncodeToString(keyBytes)
		log.WithField("key_id", hexID).Debug("Generated hex-encoded KeyID from public key")
		return hexID
	}
	log.WithField("key_id", ks.name).Debug("Using configured KeyID")
	return ks.name
}

func (ks *KeyStoreImpl) GetKeys() (types.PublicKey, types.PrivateKey, error) {
	log.WithField("at", "GetKeys").Debug("Retrieving key pair")
	public, err := ks.privateKey.Public()
	if err != nil {
		log.WithError(err).Error("Failed to derive public key from private key")
		return nil, nil, err
	}
	log.WithField("at", "GetKeys").Debug("Successfully retrieved key pair")
	return public, ks.privateKey, nil
}

func (ks *KeyStoreImpl) StoreKeys() error {
	log.WithFields(logger.Fields{
		"at":  "StoreKeys",
		"dir": ks.dir,
	}).Debug("Storing keys to filesystem")

	// make sure the directory exists
	if _, err := os.Stat(ks.dir); os.IsNotExist(err) {
		log.WithField("dir", ks.dir).Debug("Creating keystore directory")
		// Use 0700 to protect private key material from other users
		err := os.MkdirAll(ks.dir, 0o700)
		if err != nil {
			log.WithError(err).WithField("dir", ks.dir).Error("Failed to create keystore directory")
			return err
		}
	}
	// on the disk somewhere
	filename := fmt.Sprintf("private-%s.key", ks.KeyID())
	fullPath := filepath.Join(ks.dir, filename)
	log.WithField("path", fullPath).Debug("Writing private key to file")
	err := os.WriteFile(fullPath, ks.privateKey.Bytes(), 0o600)
	if err != nil {
		log.WithError(err).WithField("path", fullPath).Error("Failed to write private key file")
		return err
	}
	log.WithField("path", fullPath).Info("Successfully stored private key")
	return nil
}

// Close zeroes private key material from memory. After calling Close,
// the key store must not be used. This implements defense-in-depth key
// hygiene per cryptographic best practices.
func (ks *KeyStoreImpl) Close() {
	log.WithField("at", "Close").Debug("Zeroing private key material from memory")
	if ks.privateKey != nil {
		ks.privateKey.Zero()
	}
}
