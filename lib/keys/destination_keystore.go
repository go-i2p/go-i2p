package keys

import (
	"fmt"

	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/crypto/ed25519"
	"github.com/go-i2p/crypto/types"
)

// DestinationKeyStore stores both encryption and signing private keys
// for an I2P destination, enabling LeaseSet2 creation and message encryption.
// Uses modern cryptography: Ed25519 for signing and X25519 for encryption.
type DestinationKeyStore struct {
	destination       *destination.Destination
	encryptionPrivKey types.PrivateEncryptionKey // X25519 private key (32 bytes)
	signingPrivKey    types.SigningPrivateKey    // Ed25519 private key (32 bytes)
}

// NewDestinationKeyStore creates a new key store with generated Ed25519/X25519 keys.
// This generates a new destination with fresh keys suitable for creating LeaseSet2s
// using modern I2P cryptography (ECIES-X25519-AEAD-Ratchet compatible).
func NewDestinationKeyStore() (*DestinationKeyStore, error) {
	log.WithField("at", "NewDestinationKeyStore").Debug("Creating new destination keystore")

	signingPubKey, signingPrivKey, err := generateSigningKeyPair()
	if err != nil {
		log.WithError(err).Error("Failed to generate signing key pair")
		return nil, err
	}

	encryptionPubKey, encryptionPrivKey, err := generateEncryptionKeyPair()
	if err != nil {
		log.WithError(err).Error("Failed to generate encryption key pair")
		return nil, err
	}

	keyCert, err := createKeyCertificate()
	if err != nil {
		log.WithError(err).Error("Failed to create key certificate")
		return nil, err
	}

	padding, err := calculateKeyPadding()
	if err != nil {
		log.WithError(err).Error("Failed to calculate key padding")
		return nil, err
	}

	keysAndCert, err := assembleKeysAndCert(keyCert, encryptionPubKey, padding, signingPubKey)
	if err != nil {
		log.WithError(err).Error("Failed to assemble keys and cert")
		return nil, err
	}

	dest := &destination.Destination{
		KeysAndCert: keysAndCert,
	}

	log.WithField("at", "NewDestinationKeyStore").Debug("Successfully created destination keystore")

	return &DestinationKeyStore{
		destination:       dest,
		encryptionPrivKey: encryptionPrivKey,
		signingPrivKey:    signingPrivKey,
	}, nil
}

// generateSigningKeyPair creates a new Ed25519 signing key pair.
func generateSigningKeyPair() (types.SigningPublicKey, types.SigningPrivateKey, error) {
	signingPubKey, signingPrivKey, err := ed25519.GenerateEd25519KeyPair()
	if err != nil {
		log.WithError(err).Error("Ed25519 key generation failed")
		return nil, nil, fmt.Errorf("failed to generate Ed25519 key pair: %w", err)
	}
	return signingPubKey, signingPrivKey, nil
}

// generateEncryptionKeyPair creates a new X25519 encryption key pair for LeaseSet2.
func generateEncryptionKeyPair() (types.ReceivingPublicKey, types.PrivateEncryptionKey, error) {
	encryptionPubKey, encryptionPrivKey, err := curve25519.GenerateKeyPair()
	if err != nil {
		log.WithError(err).Error("X25519 key generation failed")
		return nil, nil, fmt.Errorf("failed to generate X25519 key: %w", err)
	}
	return encryptionPubKey, encryptionPrivKey, nil
}

// createKeyCertificate creates a KeyCertificate for Ed25519/X25519.
func createKeyCertificate() (*key_certificate.KeyCertificate, error) {
	keyCert, err := key_certificate.NewEd25519X25519KeyCertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to create KeyCertificate: %w", err)
	}
	return keyCert, nil
}

// calculateKeyPadding computes padding needed to reach KEYS_AND_CERT_DATA_SIZE.
func calculateKeyPadding() ([]byte, error) {
	sizes, err := key_certificate.GetKeySizes(
		key_certificate.KEYCERT_SIGN_ED25519,
		key_certificate.KEYCERT_CRYPTO_X25519,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get key sizes: %w", err)
	}

	paddingSize := keys_and_cert.KEYS_AND_CERT_DATA_SIZE - (sizes.CryptoPublicKeySize + sizes.SigningPublicKeySize)
	if paddingSize < 0 {
		return nil, fmt.Errorf("invalid key sizes: padding would be negative")
	}

	return make([]byte, paddingSize), nil
}

// assembleKeysAndCert constructs the KeysAndCert structure for the destination.
func assembleKeysAndCert(keyCert *key_certificate.KeyCertificate, encryptionPubKey types.ReceivingPublicKey, padding []byte, signingPubKey types.SigningPublicKey) (*keys_and_cert.KeysAndCert, error) {
	keysAndCert, err := keys_and_cert.NewKeysAndCert(
		keyCert,
		encryptionPubKey,
		padding,
		signingPubKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create KeysAndCert: %w", err)
	}
	return keysAndCert, nil
}

// Destination returns the public destination
func (dks *DestinationKeyStore) Destination() *destination.Destination {
	log.WithField("at", "Destination").Debug("Returning destination")
	return dks.destination
}

// SigningPrivateKey returns the signing private key for creating LeaseSets
func (dks *DestinationKeyStore) SigningPrivateKey() types.SigningPrivateKey {
	log.WithField("at", "SigningPrivateKey").Debug("Returning signing private key")
	return dks.signingPrivKey
}

// EncryptionPrivateKey returns the encryption private key for decrypting messages
func (dks *DestinationKeyStore) EncryptionPrivateKey() types.PrivateEncryptionKey {
	log.WithField("at", "EncryptionPrivateKey").Debug("Returning encryption private key")
	return dks.encryptionPrivKey
}

// SigningPublicKey returns the signing public key
func (dks *DestinationKeyStore) SigningPublicKey() (types.SigningPublicKey, error) {
	log.WithField("at", "SigningPublicKey").Debug("Retrieving signing public key")
	key, err := dks.destination.SigningPublicKey()
	if err != nil {
		log.WithError(err).WithField("at", "SigningPublicKey").Error("Failed to get signing public key")
		return nil, err
	}
	return key, nil
}

// EncryptionPublicKey returns the encryption public key
func (dks *DestinationKeyStore) EncryptionPublicKey() (types.ReceivingPublicKey, error) {
	log.WithField("at", "EncryptionPublicKey").Debug("Retrieving encryption public key")
	key, err := dks.destination.PublicKey()
	if err != nil {
		log.WithError(err).WithField("at", "EncryptionPublicKey").Error("Failed to get encryption public key")
		return nil, err
	}
	return key, nil
}

// Close zeroes all private key material from memory. After calling Close,
// the key store must not be used for signing or encryption operations.
// This implements defense-in-depth key hygiene per cryptographic best practices.
func (dks *DestinationKeyStore) Close() {
	log.WithField("at", "Close").Debug("Zeroing destination private key material from memory")
	if dks.encryptionPrivKey != nil {
		dks.encryptionPrivKey.Zero()
	}
	// SigningPrivateKey interface doesn't require Zero(), but concrete Ed25519
	// types implement it. Use type assertion to zero if possible.
	if z, ok := dks.signingPrivKey.(interface{ Zero() }); ok {
		z.Zero()
	}
}
