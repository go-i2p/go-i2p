package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/go-i2p/go-i2p/lib/util/logger"
	"github.com/sirupsen/logrus"
)

var log = logger.GetGoI2PLogger()

// AESSymmetricKey represents a symmetric key for AES encryption/decryption
type AESSymmetricKey struct {
	Key []byte // AES key (must be 16, 24, or 32 bytes for AES-128, AES-192, AES-256)
	IV  []byte // Initialization Vector (must be 16 bytes for AES)
}

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
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
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

// NewEncrypter creates a new AESSymmetricEncrypter
func (k *AESSymmetricKey) NewEncrypter() (Encrypter, error) {
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
func (k *AESSymmetricKey) NewDecrypter() (Decrypter, error) {
	return &AESSymmetricDecrypter{
		Key: k.Key,
		IV:  k.IV,
	}, nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	log.WithFields(logrus.Fields{
		"data_length": len(data),
		"block_size":  blockSize,
	}).Debug("Applying PKCS#7 padding")

	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	padded := append(data, padText...)

	log.WithField("padded_length", len(padded)).Debug("PKCS#7 padding applied")
	return append(data, padText...)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	log.WithField("data_length", len(data)).Debug("Removing PKCS#7 padding")

	length := len(data)
	if length == 0 {
		log.Error("Data is empty")
		return nil, fmt.Errorf("data is empty")
	}
	padding := int(data[length-1])
	if padding == 0 || padding > aes.BlockSize {
		log.WithField("padding", padding).Error("Invalid padding")
		return nil, fmt.Errorf("invalid padding")
	}
	paddingStart := length - padding
	for i := paddingStart; i < length; i++ {
		if data[i] != byte(padding) {
			log.Error("Invalid padding")
			return nil, fmt.Errorf("invalid padding")
		}
	}

	unpadded := data[:paddingStart]
	log.WithField("unpadded_length", len(unpadded)).Debug("PKCS#7 padding removed")
	return unpadded, nil
}

// EncryptNoPadding encrypts data using AES-CBC without padding
func (e *AESSymmetricEncrypter) EncryptNoPadding(data []byte) ([]byte, error) {
	if len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("data length must be a multiple of block size")
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

// DecryptNoPadding decrypts data using AES-CBC without padding
func (d *AESSymmetricDecrypter) DecryptNoPadding(data []byte) ([]byte, error) {
	if len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("data length must be a multiple of block size")
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
