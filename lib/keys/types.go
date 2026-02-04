package keys

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

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
	if ks.name == "" {
		log.WithField("at", "KeyID").Debug("Generating KeyID from public key")
		public, err := ks.privateKey.Public()
		if err != nil {
			log.WithError(err).Warn("Failed to get public key, generating fallback ID")
			// Generate a random fallback ID to avoid file collisions
			// Use a timestamp-based approach similar to RouterInfoKeystore
			nowTime := time.Now().UnixNano()
			fallbackID := fmt.Sprintf("unknown-%d-%d", os.Getpid(), int(nowTime%1000000))
			log.WithField("fallback_id", fallbackID).Debug("Generated fallback KeyID")
			return fallbackID
		}
		if len(public.Bytes()) > 10 {
			return string(public.Bytes()[:10])
		} else {
			return string(public.Bytes())
		}
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
