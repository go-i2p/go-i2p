package chacha20

import (
	"crypto/rand"
	"io"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

var log = logger.GetGoI2PLogger()

// Key sizes
const (
	KeySize   = 32
	NonceSize = 12 // ChaCha20-Poly1305 standard nonce size
	TagSize   = 16 // Poly1305 authentication tag size
)

// Error definitions
var (
	ErrInvalidKeySize   = oops.Errorf("invalid ChaCha20 key size")
	ErrInvalidNonceSize = oops.Errorf("invalid ChaCha20 nonce size")
	ErrEncryptFailed    = oops.Errorf("ChaCha20 encryption failed")
	ErrDecryptFailed    = oops.Errorf("ChaCha20 decryption failed")
	ErrAuthFailed       = oops.Errorf("ChaCha20-Poly1305 authentication failed")
)

// ChaCha20Key is a 256-bit key for ChaCha20
type ChaCha20Key [KeySize]byte

// ChaCha20Nonce is a 96-bit nonce for ChaCha20
type ChaCha20Nonce [NonceSize]byte

// NewRandomNonce generates a cryptographically secure random nonce
func NewRandomNonce() (ChaCha20Nonce, error) {
	var nonce ChaCha20Nonce
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return ChaCha20Nonce{}, oops.Errorf("failed to generate random nonce: %w", err)
	}
	return nonce, nil
}
