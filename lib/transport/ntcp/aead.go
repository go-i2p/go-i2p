package ntcp

import (
	"encoding/binary"

	"github.com/samber/oops"
	"golang.org/x/crypto/chacha20poly1305"
)

// AEADOperator defines the interface for AEAD operations in the NTCP2 protocol
type AEADOperator interface {
	// EncryptWithAssociatedData encrypts data using the provided key and associated data
	EncryptWithAssociatedData(key, data, associatedData []byte, nonceCounter uint64) ([]byte, error)

	// DecryptWithAssociatedData decrypts data using the provided key and associated data
	DecryptWithAssociatedData(key, data, associatedData []byte, nonceCounter uint64) ([]byte, error)

	// EncryptWithDerivedKey encrypts data, deriving the key from raw key material first
	EncryptWithDerivedKey(keyMaterial, data, associatedData []byte, nonceCounter uint64) ([]byte, error)

	// DecryptWithDerivedKey decrypts data, deriving the key from raw key material first
	DecryptWithDerivedKey(keyMaterial, data, associatedData []byte, nonceCounter uint64) ([]byte, error)
}

var _ AEADOperator = (*NTCP2Session)(nil)

// PerformAEADOperation handles both encryption and decryption using ChaCha20-Poly1305
func (c *NTCP2Session) PerformAEADOperation(
	keyMaterial []byte, // Raw key material to derive key from
	data []byte, // Data to encrypt/decrypt
	associatedData []byte, // Associated data for AEAD
	nonceCounter uint64, // Nonce counter (0 for first message)
	encrypt bool, // true for encrypt, false for decrypt
) ([]byte, error) {
	// 1. Derive key
	key, err := c.deriveChacha20Key(keyMaterial)
	if err != nil {
		return nil, oops.Errorf("failed to derive ChaCha20 key: %w", err)
	}

	// 2. Create cipher
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, oops.Errorf("failed to create AEAD cipher: %w", err)
	}

	// 3. Create nonce (all zeros for first message, otherwise based on counter)
	nonce := make([]byte, 12)
	if nonceCounter > 0 {
		binary.BigEndian.PutUint64(nonce[4:], nonceCounter)
	}

	// 4. Perform operation
	var result []byte
	var opErr error

	if encrypt {
		result = aead.Seal(nil, nonce, data, associatedData)
	} else {
		result, opErr = aead.Open(nil, nonce, data, associatedData)
		if opErr != nil {
			return nil, oops.Errorf("AEAD authentication failed: %w", opErr)
		}
	}

	return result, nil
}

// EncryptWithAssociatedData encrypts data using ChaCha20-Poly1305 with the provided key and associated data
func (c *NTCP2Session) EncryptWithAssociatedData(
	key []byte,
	data []byte,
	associatedData []byte,
	nonceCounter uint64,
) ([]byte, error) {
	return c.PerformAEADOperation(key, data, associatedData, nonceCounter, true)
}

// DecryptWithAssociatedData decrypts data using ChaCha20-Poly1305 with the provided key and associated data
func (c *NTCP2Session) DecryptWithAssociatedData(
	key []byte,
	data []byte,
	associatedData []byte,
	nonceCounter uint64,
) ([]byte, error) {
	return c.PerformAEADOperation(key, data, associatedData, nonceCounter, false)
}

// PerformAEADWithDerivedKey performs AEAD operation, deriving the key from raw key material first
func (c *NTCP2Session) PerformAEADWithDerivedKey(
	keyMaterial []byte, // Raw key material to derive key from
	data []byte,
	associatedData []byte,
	nonceCounter uint64,
	encrypt bool,
) ([]byte, error) {
	// 1. Derive key using KDF
	key, err := c.deriveChacha20Key(keyMaterial)
	if err != nil {
		return nil, oops.Errorf("failed to derive ChaCha20 key: %w", err)
	}

	// 2. Perform the AEAD operation
	return c.PerformAEADOperation(key, data, associatedData, nonceCounter, encrypt)
}

// EncryptWithDerivedKey encrypts data, deriving the key from raw key material first
func (c *NTCP2Session) EncryptWithDerivedKey(
	keyMaterial []byte,
	data []byte,
	associatedData []byte,
	nonceCounter uint64,
) ([]byte, error) {
	return c.PerformAEADWithDerivedKey(keyMaterial, data, associatedData, nonceCounter, true)
}

// DecryptWithDerivedKey decrypts data, deriving the key from raw key material first
func (c *NTCP2Session) DecryptWithDerivedKey(
	keyMaterial []byte,
	data []byte,
	associatedData []byte,
	nonceCounter uint64,
) ([]byte, error) {
	return c.PerformAEADWithDerivedKey(keyMaterial, data, associatedData, nonceCounter, false)
}
