package ntcp

import (
	"fmt"

	"github.com/go-i2p/go-i2p/lib/crypto"
)

// ObfuscateEphemeralKey encrypts the ephemeral public key in the message using AES-256-CBC without padding
func ObfuscateEphemeralKey(message []byte, aesKey *crypto.AESSymmetricKey) ([]byte, error) {
	if len(message) < 32 {
		return nil, fmt.Errorf("message is too short to contain ephemeral public key")
	}

	// Extract the ephemeral public key (first 32 bytes)
	ephemeralPubKey := message[:32]

	// Create AES encrypter
	encrypter := &crypto.AESSymmetricEncrypter{
		Key: aesKey.Key,
		IV:  aesKey.IV,
	}

	// Encrypt the ephemeral public key without padding
	encryptedKey, err := encrypter.EncryptNoPadding(ephemeralPubKey)
	if err != nil {
		return nil, err
	}

	// Replace the ephemeral public key in the message with the encrypted key
	obfuscatedMessage := append(encryptedKey, message[32:]...)

	return obfuscatedMessage, nil
}

// DeobfuscateEphemeralKey decrypts the ephemeral public key in the message using AES-256-CBC without padding
func DeobfuscateEphemeralKey(message []byte, aesKey *crypto.AESSymmetricKey) ([]byte, error) {
	if len(message) < 32 {
		return nil, fmt.Errorf("message is too short to contain ephemeral public key")
	}

	// Extract the encrypted ephemeral public key (first 32 bytes)
	encryptedKey := message[:32]

	// Create AES decrypter
	decrypter := &crypto.AESSymmetricDecrypter{
		Key: aesKey.Key,
		IV:  aesKey.IV,
	}

	// Decrypt the ephemeral public key without padding
	decryptedKey, err := decrypter.DecryptNoPadding(encryptedKey)
	if err != nil {
		return nil, err
	}

	// Replace the encrypted ephemeral key in the message with the decrypted key
	deobfuscatedMessage := append(decryptedKey, message[32:]...)

	return deobfuscatedMessage, nil
}
