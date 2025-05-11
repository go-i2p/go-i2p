package kdf

import (
	"crypto/hmac"
	"crypto/sha256"

	"github.com/samber/oops"
)

// NTCP2KDF handles key derivation functions for the NTCP2 protocol
// according to the Noise_XK_25519_ChaChaPoly_SHA256 specification with
// I2P-specific customizations.
type NTCP2KDF struct {
	// ChainingKey is used in the key derivation chain
	ChainingKey []byte
	// HandshakeHash is the cumulative hash of handshake data
	HandshakeHash []byte
}

// NewNTCP2KDF creates a new KDF context for NTCP2 with initial
// protocol name as defined in the I2P spec.
func NewNTCP2KDF() *NTCP2KDF {
	// Initialize with protocol name as per Noise protocol
	protocolName := []byte("Noise_XK_25519_ChaChaPoly_SHA256")
	h := sha256.New()
	h.Write(protocolName)
	initialHash := h.Sum(nil)

	return &NTCP2KDF{
		ChainingKey:   initialHash,
		HandshakeHash: initialHash,
	}
}

// MixKey derives a new chaining key and encryption key from DH output
// following the Noise protocol specification.
func (k *NTCP2KDF) MixKey(dhOutput []byte) (encryptionKey []byte, err error) {
	if len(dhOutput) != 32 {
		return nil, oops.Errorf("invalid DH output length: expected 32, got %d", len(dhOutput))
	}

	// Generate a temp key from the chaining key and DH result
	tempKey := hmac.New(sha256.New, k.ChainingKey)
	if _, err := tempKey.Write(dhOutput); err != nil {
		return nil, oops.Errorf("HMAC write failed: %w", err)
	}
	tempKeyBytes := tempKey.Sum(nil)

	// Set new chaining key (output 1)
	ckMac := hmac.New(sha256.New, tempKeyBytes)
	if _, err := ckMac.Write([]byte{0x01}); err != nil {
		return nil, oops.Errorf("HMAC write failed: %w", err)
	}
	k.ChainingKey = ckMac.Sum(nil)

	// Generate encryption key (output 2)
	keyMac := hmac.New(sha256.New, tempKeyBytes)
	if _, err := keyMac.Write([]byte{0x02}); err != nil {
		return nil, oops.Errorf("HMAC write failed: %w", err)
	}
	encryptionKey = keyMac.Sum(nil)

	return encryptionKey, nil
}

// MixHash updates the handshake hash with new data
// according to the Noise protocol pattern.
func (k *NTCP2KDF) MixHash(data []byte) error {
	h := sha256.New()
	if _, err := h.Write(k.HandshakeHash); err != nil {
		return oops.Errorf("hash update failed: %w", err)
	}
	if _, err := h.Write(data); err != nil {
		return oops.Errorf("hash update failed: %w", err)
	}
	k.HandshakeHash = h.Sum(nil)
	return nil
}

// DeriveKeys performs Split() operation to derive final session keys
// for bidirectional communication.
func (k *NTCP2KDF) DeriveKeys() (keyAB, keyBA []byte, err error) {
	// Generate key for Alice->Bob
	keyABMac := hmac.New(sha256.New, k.ChainingKey)
	if _, err := keyABMac.Write([]byte{0x01}); err != nil {
		return nil, nil, oops.Errorf("HMAC write failed: %w", err)
	}
	keyAB = keyABMac.Sum(nil)

	// Generate key for Bob->Alice
	keyBAMac := hmac.New(sha256.New, k.ChainingKey)
	if _, err := keyBAMac.Write([]byte{0x02}); err != nil {
		return nil, nil, oops.Errorf("HMAC write failed: %w", err)
	}
	keyBA = keyBAMac.Sum(nil)

	return keyAB, keyBA, nil
}

// DeriveHandshakeMessageKey derives a key for a specific handshake message
// used during the different phases of the NTCP2 handshake.
func (k *NTCP2KDF) DeriveHandshakeMessageKey(messageNum uint8) ([]byte, error) {
	mac := hmac.New(sha256.New, k.ChainingKey)
	if _, err := mac.Write([]byte{messageNum}); err != nil {
		return nil, oops.Errorf("HMAC write failed: %w", err)
	}
	return mac.Sum(nil), nil
}

// DeriveSipHashKey derives a key for SipHash length obfuscation
// used specifically in NTCP2 for frame length obfuscation.
func (k *NTCP2KDF) DeriveSipHashKey() ([]byte, error) {
	// "ask" key derivation for SipHash
	askMac := hmac.New(sha256.New, k.ChainingKey)
	if _, err := askMac.Write([]byte("ask")); err != nil {
		return nil, oops.Errorf("HMAC write failed: %w", err)
	}
	if _, err := askMac.Write([]byte{0x01}); err != nil {
		return nil, oops.Errorf("HMAC write failed: %w", err)
	}
	askMaster := askMac.Sum(nil)

	// SipHash key derivation
	tempMac := hmac.New(sha256.New, askMaster)
	if _, err := tempMac.Write(k.HandshakeHash); err != nil {
		return nil, oops.Errorf("HMAC write failed: %w", err)
	}
	if _, err := tempMac.Write([]byte("siphash")); err != nil {
		return nil, oops.Errorf("HMAC write failed: %w", err)
	}
	tempKey := tempMac.Sum(nil)

	sipMac := hmac.New(sha256.New, tempKey)
	if _, err := sipMac.Write([]byte{0x01}); err != nil {
		return nil, oops.Errorf("HMAC write failed: %w", err)
	}

	// SipHash requires 16 bytes (128 bits)
	return sipMac.Sum(nil)[:16], nil
}

// DeriveFramingKey derives the key used for frame obfuscation
// in the data phase of NTCP2.
func (k *NTCP2KDF) DeriveFramingKey() ([]byte, error) {
	// Frame key derivation
	frameMac := hmac.New(sha256.New, k.ChainingKey)
	if _, err := frameMac.Write([]byte("frame")); err != nil {
		return nil, oops.Errorf("HMAC write failed: %w", err)
	}

	return frameMac.Sum(nil), nil
}
