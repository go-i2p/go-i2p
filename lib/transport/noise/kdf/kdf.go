package kdf

import (
	"crypto/hmac"
	"crypto/sha256"

	"github.com/samber/oops"
)

// NoiseKDF handles key derivation functions for Noise protocols
type NoiseKDF struct {
	chainingKey   []byte
	handshakeHash []byte
}

// NewNoiseKDF creates a new KDF instance with the protocol name
func NewNoiseKDF(protocolName []byte) *NoiseKDF {
	h := sha256.New()
	h.Write(protocolName)
	initialHash := h.Sum(nil)

	return &NoiseKDF{
		chainingKey:   initialHash,
		handshakeHash: initialHash,
	}
}

// MixKey derives a new key from the chaining key and input material
func (k *NoiseKDF) MixKey(input []byte) ([]byte, error) {
	if len(input) != 32 {
		return nil, oops.Errorf("invalid input length: %d", len(input))
	}

	tempKey := hmac.New(sha256.New, k.chainingKey)
	if _, err := tempKey.Write(input); err != nil {
		return nil, err
	}
	tempKeyBytes := tempKey.Sum(nil)

	hmacChain := hmac.New(sha256.New, tempKeyBytes)
	if _, err := hmacChain.Write([]byte{0x01}); err != nil {
		return nil, err
	}
	k.chainingKey = hmacChain.Sum(nil)

	outputKey := hmac.New(sha256.New, tempKeyBytes)
	if _, err := outputKey.Write([]byte{0x02}); err != nil {
		return nil, err
	}

	return outputKey.Sum(nil), nil
}

// MixHash updates the handshake hash with new data
func (k *NoiseKDF) MixHash(data []byte) error {
	h := sha256.New()
	if _, err := h.Write(k.handshakeHash); err != nil {
		return err
	}
	if _, err := h.Write(data); err != nil {
		return err
	}
	k.handshakeHash = h.Sum(nil)
	return nil
}

// GetHandshakeHash returns the current handshake hash
func (k *NoiseKDF) GetHandshakeHash() []byte {
	return append([]byte{}, k.handshakeHash...)
}

// DeriveSessionKeys derives transport keys from the KDF state
func (k *NoiseKDF) DeriveSessionKeys() (sendKey, recvKey []byte, err error) {
	// Create a reusable HMAC instance
	hmacInstance := hmac.New(sha256.New, k.chainingKey)
	if _, err := hmacInstance.Write([]byte{0x00}); err != nil {
		return nil, nil, oops.Errorf("failed to generate temp key: %w", err)
	}
	tempKeyBytes := hmacInstance.Sum(nil)

	// Derive sending key (constant 0x01)
	hmacInstance.Reset()
	hmacInstance.Write(tempKeyBytes)
	hmacInstance.Write([]byte{0x01})
	sendKey = hmacInstance.Sum(nil)

	// Derive receiving key (constant 0x02)
	hmacInstance.Reset()
	hmacInstance.Write(tempKeyBytes)
	hmacInstance.Write([]byte{0x02})
	recvKey = hmacInstance.Sum(nil)

	// Update chaining key for potential future derivations.
	// Note: This will overwrite the existing chainingKey, which means
	// calling this function multiple times will result in a new chainingKey
	// being derived each time. Ensure this behavior aligns with the intended
	// protocol design.
	chainHmac := hmac.New(sha256.New, tempKeyBytes)
	if _, err := chainHmac.Write([]byte{0x03}); err != nil {
		return nil, nil, oops.Errorf("failed to update chaining key: %w", err)
	}
	k.chainingKey = chainHmac.Sum(nil)
	return sendKey, recvKey, nil
}

func (k *NoiseKDF) SetHash(hash []byte) {
	k.handshakeHash = hash
}
