package data

import (
	"bytes"
	"crypto/sha256"
	"io"
)

/*
[I2P Hash]
Accurate for version 0.9.49

Description
Represents the SHA256 of some data.

Contents
32 bytes

[I2P Hash]:
*/

// Hash is the represenation of an I2P Hash.
//
// https://geti2p.net/spec/common-structures#hash
type Hash [32]byte

func (h Hash) Bytes() [32]byte {
	return h
}

// HashData returns the SHA256 sum of a []byte input as Hash.
func HashData(data []byte) (h Hash) {
	// log.Println("Hashing Data:", data)
	h = sha256.Sum256(data)
	return
}

func (h Hash) Equals(other Hash) bool {
	return bytes.Equal(h[:], other[:])
}

// HashReader returns the SHA256 sum from all data read from an io.Reader.
// return error if one occurs while reading from reader
func HashReader(r io.Reader) (h Hash, err error) {
	sha := sha256.New()
	_, err = io.Copy(sha, r)
	if err == nil {
		d := sha.Sum(nil)
		copy(h[:], d)
	}
	return
}
