package aes

import "github.com/go-i2p/go-i2p/lib/crypto/types"

// AESSymmetricKey represents a symmetric key for AES encryption/decryption
type AESSymmetricKey struct {
	Key []byte // AES key (must be 16, 24, or 32 bytes for AES-128, AES-192, AES-256)
	IV  []byte // Initialization Vector (must be 16 bytes for AES)
}

// NewEncrypter creates a new AESSymmetricEncrypter
func (k *AESSymmetricKey) NewEncrypter() (types.Encrypter, error) {
	log.Debug("Creating new AESSymmetricEncrypter")
	return &AESSymmetricEncrypter{
		Key: k.Key,
		IV:  k.IV,
	}, nil
}

// Len returns the length of the key
func (k *AESSymmetricKey) Len() int {
	return len(k.Key)
}

// NewDecrypter creates a new AESSymmetricDecrypter
func (k *AESSymmetricKey) NewDecrypter() (types.Decrypter, error) {
	return &AESSymmetricDecrypter{
		Key: k.Key,
		IV:  k.IV,
	}, nil
}
