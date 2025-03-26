package aes

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

var log = logger.GetGoI2PLogger()

// AESSymmetricDecrypter implements the Decrypter interface using AES
type AESSymmetricDecrypter struct {
	Key []byte
	IV  []byte
}

// Decrypt decrypts data using AES-CBC with PKCS#7 padding
func (d *AESSymmetricDecrypter) Decrypt(data []byte) ([]byte, error) {
	log.WithField("data_length", len(data)).Debug("Decrypting data")

	block, err := aes.NewCipher(d.Key)
	if err != nil {
		log.WithError(err).Error("Failed to create AES cipher")
		return nil, err
	}

	if len(data)%aes.BlockSize != 0 {
		log.Error("Ciphertext is not a multiple of the block size")
		return nil, oops.Errorf("ciphertext is not a multiple of the block size")
	}

	plaintext := make([]byte, len(data))
	mode := cipher.NewCBCDecrypter(block, d.IV)
	mode.CryptBlocks(plaintext, data)

	plaintext, err = pkcs7Unpad(plaintext)
	if err != nil {
		log.WithError(err).Error("Failed to unpad plaintext")
		return nil, err
	}

	log.WithField("plaintext_length", len(plaintext)).Debug("Data decrypted successfully")
	return plaintext, nil
}

// DecryptNoPadding decrypts data using AES-CBC without padding
func (d *AESSymmetricDecrypter) DecryptNoPadding(data []byte) ([]byte, error) {
	if len(data)%aes.BlockSize != 0 {
		return nil, oops.Errorf("data length must be a multiple of block size")
	}

	block, err := aes.NewCipher(d.Key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(data))
	mode := cipher.NewCBCDecrypter(block, d.IV)
	mode.CryptBlocks(plaintext, data)

	return plaintext, nil
}

func NewCipher(c []byte) (cipher.Block, error) {
	return aes.NewCipher(c)
}
