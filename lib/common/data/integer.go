package data

import (
	"encoding/binary"
	"errors"
)

// MAX_INTEGER_SIZE is the maximum length of an I2P integer in bytes.
const MAX_INTEGER_SIZE = 8

/*
[I2P Integer]
Accurate for version 0.9.49

Description
Represents a non-negative integer.

Contents
1 to 8 bytes in network byte order (big endian) representing an unsigned integer.
*/

// Integer is the represenation of an I2P Integer.
//
// https://geti2p.net/spec/common-structures#integer
type Integer []byte

// Bytes returns the raw []byte content of an Integer.
func (i Integer) Bytes() []byte {
	return i
}

// Int returns the Integer as a Go integer
func (i Integer) Int() int {
	return intFromBytes(i)
}

// ReadInteger returns an Integer from a []byte of specified length.
// The remaining bytes after the specified length are also returned.
func ReadInteger(bytes []byte, size int) (Integer, []byte) {
	if size <= 0 || size > len(bytes) {
		return Integer{}, bytes
	}
	return Integer(bytes[:size]), bytes[size:]
}

// NewInteger creates a new Integer from []byte using ReadInteger.
// Limits the length of the created Integer to MAX_INTEGER_SIZE.
// Returns a pointer to Integer unlike ReadInteger.
func NewInteger(bytes []byte, size int) (*Integer, []byte, error) {
	if size <= 0 || size > MAX_INTEGER_SIZE {
		return nil, bytes, errors.New("invalid integer size")
	}
	if len(bytes) < size {
		return nil, bytes, errors.New("insufficient data")
	}

	integer, remainder := ReadInteger(bytes, size)
	return &integer, remainder, nil
}

// NewIntegerFromInt creates a new Integer from a Go integer of a specified []byte length.
func NewIntegerFromInt(value int, size int) (*Integer, error) {
	if size <= 0 || size > MAX_INTEGER_SIZE {
		return nil, errors.New("invalid integer size")
	}

	buf := make([]byte, MAX_INTEGER_SIZE)
	binary.BigEndian.PutUint64(buf, uint64(value))

	data := buf[MAX_INTEGER_SIZE-size:]
	integer := Integer(data)
	return &integer, nil
}

// Interpret a slice of bytes from length 0 to length 8 as a big-endian
// integer and return an int representation.
func intFromBytes(number []byte) int {
	if len(number) == 0 {
		return 0
	}
	padded := make([]byte, MAX_INTEGER_SIZE)
	copy(padded[MAX_INTEGER_SIZE-len(number):], number)
	return int(binary.BigEndian.Uint64(padded))
}
