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
	// Generate Ed25519 signing key pair
	signingPrivKeyRaw, err := ed25519.GenerateEd25519Key()
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
	}

	signingPrivKey, ok := signingPrivKeyRaw.(ed25519.Ed25519PrivateKey)
	if !ok {
		return nil, fmt.Errorf("generated key is not Ed25519PrivateKey type")
	}

	signingPubKeyRaw, err := signingPrivKey.Public()
	if err != nil {
		return nil, fmt.Errorf("failed to derive Ed25519 public key: %w", err)
	}

	signingPubKey := signingPubKeyRaw

	// Generate X25519 (Curve25519) encryption key pair for LeaseSet2
	encryptionPubKey, encryptionPrivKey, err := curve25519.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate X25519 key: %w", err)
	}

	// Create default KeyCertificate for Ed25519/X25519
	keyCert, err := key_certificate.NewEd25519X25519KeyCertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to create KeyCertificate: %w", err)
	}

	// Calculate padding size: KEYS_AND_CERT_DATA_SIZE - (crypto_key_size + signing_key_size)
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
	padding := make([]byte, paddingSize)

	// Create KeysAndCert for the destination
	keysAndCert, err := keys_and_cert.NewKeysAndCert(
		keyCert,          // KeyCertificate specifying key types
		encryptionPubKey, // ReceivingPublicKey
		padding,          // padding to reach KEYS_AND_CERT_DATA_SIZE
		signingPubKey,    // SigningPublicKey
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create KeysAndCert: %w", err)
	}

	// Create destination
	dest := &destination.Destination{
		KeysAndCert: keysAndCert,
	}

	return &DestinationKeyStore{
		destination:       dest,
		encryptionPrivKey: encryptionPrivKey,
		signingPrivKey:    signingPrivKey,
	}, nil
}

// Destination returns the public destination
func (dks *DestinationKeyStore) Destination() *destination.Destination {
	return dks.destination
}

// SigningPrivateKey returns the signing private key for creating LeaseSets
func (dks *DestinationKeyStore) SigningPrivateKey() types.SigningPrivateKey {
	return dks.signingPrivKey
}

// EncryptionPrivateKey returns the encryption private key for decrypting messages
func (dks *DestinationKeyStore) EncryptionPrivateKey() types.PrivateEncryptionKey {
	return dks.encryptionPrivKey
}

// SigningPublicKey returns the signing public key
func (dks *DestinationKeyStore) SigningPublicKey() types.SigningPublicKey {
	return dks.destination.SigningPublicKey()
}

// EncryptionPublicKey returns the encryption public key
func (dks *DestinationKeyStore) EncryptionPublicKey() types.ReceivingPublicKey {
	return dks.destination.PublicKey()
}
