package data

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
)

/*
[I2P Hash]
Accurate for version 0.9.49

Description
Represents the SHA256 of some data. Used throughout I2P for data verification
and identity representation. Must be compared using constant-time operations
to prevent timing attacks.

Contents
32 bytes representing a SHA256 hash value
*/

var (
	ErrInvalidHashSize = errors.New("invalid hash size")
	ErrNilReader      = errors.New("nil reader")
)

// Hash is the representation of an I2P Hash.
// It is always exactly 32 bytes containing a SHA256 sum.
// 
// https://geti2p.net/spec/common-structures#hash
type Hash [32]byte

// Bytes returns a copy of the Hash as a 32-byte array.
// This prevents modification of the original hash value.
func (h Hash) Bytes() [32]byte {
	return h
}

// Equal compares two hashes in constant time.
// Returns true if the hashes are identical.
func (h Hash) Equal(other Hash) bool {
	return subtle.ConstantTimeCompare(h[:], other[:]) == 1
}

// IsZero returns true if the hash is all zeros.
func (h Hash) IsZero() bool {
	var zero Hash
	return h.Equal(zero)
}

// HashData returns the SHA256 sum of a []byte input as Hash.
// Never returns an error as SHA256 operates on any input length.
func HashData(data []byte) Hash {
	if data == nil {
		data = []byte{} // Handle nil input gracefully
	}
	return sha256.Sum256(data)
}

// HashReader returns the SHA256 sum from all data read from an io.Reader.
// Returns an error if one occurs while reading from reader or if reader is nil.
func HashReader(r io.Reader) (Hash, error) {
	var h Hash
	
	if r == nil {
		return h, ErrNilReader
	}

	sha := sha256.New()
	_, err := io.Copy(sha, r)
	if err != nil {
		return h, err
	}
	
	sum := sha.Sum(nil)
	copy(h[:], sum)
	return h, nil
}