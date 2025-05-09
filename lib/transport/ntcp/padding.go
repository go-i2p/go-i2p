package ntcp

import (
	"crypto/rand"
	"io"
	mrand "math/rand"
	"net"

	"github.com/samber/oops"
)

const (
	MaxPaddingSize    = 64
	MinPaddingSize    = 1
	DefaultMinSize    = 128
	DefaultMinPadding = 1
	DefaultMaxExtra   = 30
)

// GenerateRandomPadding creates a byte slice of random data with the given length
func GenerateRandomPadding(length int) ([]byte, error) {
	if length <= 0 {
		return []byte{}, nil
	}

	padding := make([]byte, length)
	if _, err := rand.Read(padding); err != nil {
		return nil, oops.Errorf("failed to generate padding: %w", err)
	}

	return padding, nil
}

// ReadAndValidatePadding reads padding from a connection and validates its length
func ReadAndValidatePadding(conn net.Conn, paddingLen int) error {
	// Check reasonable padding size to prevent DoS
	if paddingLen > MaxPaddingSize {
		return oops.Errorf("excessive padding size: %d bytes", paddingLen)
	}

	if paddingLen <= 0 {
		return nil
	}

	padding := make([]byte, paddingLen)
	n, err := io.ReadFull(conn, padding)
	if err != nil {
		if err == io.ErrUnexpectedEOF {
			return oops.Errorf("incomplete padding: got %d bytes, expected %d", n, paddingLen)
		}
		return oops.Errorf("failed to read padding: %w", err)
	}

	return nil
}

// CalculatePaddingLength determines padding length based on content size and randomness
func CalculatePaddingLength(contentSize int, minSize int, minPadding int, maxExtraPadding int) int {
	// Use defaults if parameters are invalid
	if minSize <= 0 {
		minSize = DefaultMinSize
	}
	if minPadding <= 0 {
		minPadding = DefaultMinPadding
	}
	if maxExtraPadding <= 0 {
		maxExtraPadding = DefaultMaxExtra
	}

	padding := 0
	if contentSize < minSize {
		padding = minSize - contentSize
	}

	// Add random additional padding
	padding += mrand.Intn(maxExtraPadding) + minPadding

	return padding
}
