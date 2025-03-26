package aes

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/samber/oops"
)

// AESSymmetricEncrypter implements the Encrypter interface using AES
type AESSymmetricEncrypter struct {
	Key []byte
	IV  []byte
}

// Encrypt encrypts data using AES-CBC with PKCS#7 padding
func (e *AESSymmetricEncrypter) Encrypt(data []byte) ([]byte, error) {
	log.WithField("data_length", len(data)).Debug("Encrypting data")

	block, err := aes.NewCipher(e.Key)
	if err != nil {
		log.WithError(err).Error("Failed to create AES cipher")
		return nil, err
	}

	plaintext := pkcs7Pad(data, aes.BlockSize)
	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, e.IV)
	mode.CryptBlocks(ciphertext, plaintext)

	log.WithField("ciphertext_length", len(ciphertext)).Debug("Data encrypted successfully")
	return ciphertext, nil
}

// EncryptNoPadding encrypts data using AES-CBC without padding
func (e *AESSymmetricEncrypter) EncryptNoPadding(data []byte) ([]byte, error) {
	if len(data)%aes.BlockSize != 0 {
		return nil, oops.Errorf("data length must be a multiple of block size")
	}

	block, err := aes.NewCipher(e.Key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(data))
	mode := cipher.NewCBCEncrypter(block, e.IV)
	mode.CryptBlocks(ciphertext, data)

	return ciphertext, nil
}
