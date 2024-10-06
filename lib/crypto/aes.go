package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

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
	block, err := aes.NewCipher(e.Key)
	if err != nil {
		return nil, err
	}

	plaintext := pkcs7Pad(data, aes.BlockSize)
	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, e.IV)
	mode.CryptBlocks(ciphertext, plaintext)
	return ciphertext, nil
}

// AESSymmetricDecrypter implements the Decrypter interface using AES
type AESSymmetricDecrypter struct {
	Key []byte
	IV  []byte
}

// Decrypt decrypts data using AES-CBC with PKCS#7 padding
func (d *AESSymmetricDecrypter) Decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(d.Key)
	if err != nil {
		return nil, err
	}

	if len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	plaintext := make([]byte, len(data))
	mode := cipher.NewCBCDecrypter(block, d.IV)
	mode.CryptBlocks(plaintext, data)

	plaintext, err = pkcs7Unpad(plaintext)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// NewEncrypter creates a new AESSymmetricEncrypter
func (k *AESSymmetricKey) NewEncrypter() (Encrypter, error) {
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
	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, fmt.Errorf("data is empty")
	}
	padding := int(data[length-1])
	if padding == 0 || padding > aes.BlockSize {
		return nil, fmt.Errorf("invalid padding")
	}
	paddingStart := length - padding
	for i := paddingStart; i < length; i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	return data[:paddingStart], nil
}
