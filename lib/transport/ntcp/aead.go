package ntcp

import (
	"encoding/binary"

	"github.com/samber/oops"
	"golang.org/x/crypto/chacha20poly1305"
)

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
