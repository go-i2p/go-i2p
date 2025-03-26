package ed25519

import (
	"bytes"
	"crypto/sha256"
	"math/big"

	"github.com/samber/oops"
)

type Ed25519Decrypter struct {
	privateKey Ed25519PrivateKey
}

func (d *Ed25519Decrypter) Decrypt(data []byte) ([]byte, error) {
	return d.DecryptPadding(data, true)
}

func (d *Ed25519Decrypter) DecryptPadding(data []byte, zeroPadding bool) ([]byte, error) {
	if len(data) != 514 && len(data) != 512 {
		return nil, oops.Errorf("invalid ciphertext length")
	}

	// Extract components based on padding
	var aBytes, bBytes []byte
	if zeroPadding {
		aBytes = data[1:258]
		bBytes = data[258:]
	} else {
		aBytes = data[0:256]
		bBytes = data[256:]
	}

	// Convert to big integers
	a := new(big.Int).SetBytes(aBytes)
	b := new(big.Int).SetBytes(bBytes)

	// Compute p = 2^255 - 19
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))

	// Use private key to decrypt
	m := new(big.Int).ModInverse(a, p)
	if m == nil {
		return nil, oops.Errorf("decryption failed: modular inverse does not exist")
	}

	decrypted := new(big.Int).Mod(new(big.Int).Mul(b, m), p).Bytes()

	// Remove padding and validate hash
	if len(decrypted) < 33 {
		return nil, oops.Errorf("decryption failed: result too short")
	}

	hashBytes := decrypted[1:33]
	message := decrypted[33:]

	// Verify hash
	actualHash := sha256.Sum256(message)
	if !bytes.Equal(hashBytes, actualHash[:]) {
		return nil, oops.Errorf("decryption failed: hash verification failed")
	}

	return message, nil
}
