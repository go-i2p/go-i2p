package curve25519

import (
	"bytes"
	"crypto/sha256"

	"github.com/samber/oops"
	x25519 "go.step.sm/crypto/x25519"
)

type Curve25519Decrypter struct {
	privateKey x25519.PrivateKey
}

// Decrypt implements Decrypter.
func (c *Curve25519Decrypter) Decrypt(data []byte) ([]byte, error) {
	log.WithField("data_length", len(data)).Debug("Decrypting data with Curve25519")

	if len(data) != 514 && len(data) != 512 {
		return nil, oops.Errorf("invalid data length for curve25519 decryption: got %d bytes", len(data))
	}

	// Handle zero padding if present
	offset := 0
	if len(data) == 514 {
		offset = 2 // Adjust for padding
	}

	// Extract the ephemeral public key (should be 32 bytes for X25519)
	if offset+32 > len(data) {
		return nil, oops.Errorf("data too short to extract ephemeral key")
	}
	ephemeralPub := data[offset : offset+32]

	// Skip one byte separator and extract encrypted data
	if offset+33 >= len(data) {
		return nil, oops.Errorf("data too short to extract encrypted content")
	}
	encryptedData := data[offset+33:]

	// Perform X25519 key exchange using smallstep's implementation
	shared, err := c.privateKey.SharedKey(ephemeralPub)
	if err != nil {
		return nil, oops.Errorf("curve25519 key exchange failed: %w", err)
	}

	// Decrypt the data using the shared secret
	decrypted := make([]byte, len(encryptedData))
	for i := 0; i < len(encryptedData); i++ {
		decrypted[i] = encryptedData[i] ^ shared[i%32]
	}

	// Verify the SHA256 hash in the decrypted data
	if len(decrypted) < 33 {
		return nil, oops.Errorf("decrypted data too short to verify hash")
	}

	hash := sha256.Sum256(decrypted[33:])
	if !bytes.Equal(hash[:], decrypted[1:33]) {
		return nil, oops.Errorf("invalid hash in decrypted data")
	}

	log.Debug("Data decrypted successfully")
	return decrypted[33:], nil
}
