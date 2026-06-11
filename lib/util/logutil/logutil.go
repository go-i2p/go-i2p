// Package logutil provides logging utility functions for the go-i2p router.
package logutil

import (
	"fmt"

	common "github.com/go-i2p/common/data"
)

// HashPrefix returns a hex string prefix of the given hash for safe anonymity-aware logging.
// It returns the first 8 bytes (16 hex characters) of the hash formatted as lowercase hex,
// followed by "..." to indicate truncation.
// This is the canonical function for anonymity-safe hash truncation across the codebase.
//
// Example: HashPrefix([32]byte{...}) → "a1b2c3d4..." (first 16 hex chars + "...")
func HashPrefix(h [32]byte) string {
	return fmt.Sprintf("%x...", h[:8])
}

// HashPrefixPlain returns a hex string prefix of the given hash without the "..." suffix.
// Use this when you need just the hex without the ellipsis.
//
// Example: HashPrefixPlain([32]byte{...}) → "a1b2c3d4" (first 16 hex chars)
func HashPrefixPlain(h [32]byte) string {
	return fmt.Sprintf("%x", h[:8])
}

// HashPrefixFromHash returns a hex prefix from a common.Hash pointer.
// If h is nil, it returns "nil".
func HashPrefixFromHash(h *common.Hash) string {
	if h == nil {
		return "nil"
	}
	return HashPrefix(*h)
}

// BytePrefix returns a hex string prefix of the given byte slice for logging.
// It takes the first 8 bytes and formats as lowercase hex.
// If the slice is shorter than 8 bytes, it formats whatever is available.
//
// Example: BytePrefix([]byte{...}) → "a1b2c3d4ef" (up to 16 hex chars)
func BytePrefix(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	if len(b) > 8 {
		return fmt.Sprintf("%x", b[:8])
	}
	return fmt.Sprintf("%x", b)
}
