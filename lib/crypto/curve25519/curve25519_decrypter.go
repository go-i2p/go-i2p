package curve25519

import (
	"bytes"
	"crypto/sha256"

	"github.com/samber/oops"
	curve25519 "go.step.sm/crypto/x25519"
)

type Curve25519Decrypter struct {
	privateKey Curve25519PrivateKey
}

// Decrypt implements Decrypter.
func (c *Curve25519Decrypter) Decrypt(data []byte) ([]byte, error) {
	log.WithField("data_length", len(data)).Debug("Decrypting data with Curve25519")

	if len(data) != 514 && len(data) != 512 {
		return nil, oops.Errorf("invalid data length for curve25519 decryption")
	}

	// Handle zero padding if present
	offset := 0
	if len(data) == 514 {
		offset = 1
	}

	// Extract the ephemeral public key and encrypted data
	ephemeralPub := data[offset : offset+256]
	encryptedData := data[offset+257:]

	// Convert private key to the correct format
	var privKey [32]byte
	copy(privKey[:], c.privateKey)

	// Perform X25519 key exchange
	var shared [32]byte
	curve25519.X25519(&shared, &privKey, ephemeralPub)

	// Decrypt the data using the shared secret
	decrypted := make([]byte, len(encryptedData))
	for i := 0; i < len(encryptedData); i++ {
		decrypted[i] = encryptedData[i] ^ shared[i%32]
	}

	// Verify the SHA256 hash in the decrypted data
	hash := sha256.Sum256(decrypted[33:])
	if !bytes.Equal(hash[:], decrypted[1:33]) {
		return nil, oops.Errorf("invalid hash in decrypted data")
	}

	log.Debug("Data decrypted successfully")
	return decrypted[33:], nil
}
