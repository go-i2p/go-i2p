package data

import (
	"encoding/binary"
	"errors"
	"math"
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

var (
	// ErrInvalidSize indicates the requested integer size is invalid (<=0 or >MAX_INTEGER_SIZE)
	ErrInvalidSize = errors.New("invalid integer size")
	// ErrInsufficientData indicates there isn't enough data to read the requested size
	ErrInsufficientData = errors.New("insufficient data")
	// ErrNegativeValue indicates an attempt to create an Integer from a negative value
	ErrNegativeValue = errors.New("negative values not allowed")
	// ErrIntegerOverflow indicates the value exceeds the maximum allowed size
	ErrIntegerOverflow = errors.New("integer overflow")
)

// Integer is the representation of an I2P Integer.
// It contains 1 to 8 bytes in network byte order (big endian)
// representing an unsigned integer value.
type Integer []byte

// Bytes returns the raw []byte content of an Integer.
// This represents the big-endian encoded form of the integer.
func (i Integer) Bytes() []byte {
	return i
}

// Int returns the Integer as a Go integer.
// Returns an error if the value would overflow on the current platform
// or if the encoding is invalid.
func (i Integer) Int() int {
	val, _ := intFromBytes(i)
	return val
}

// ReadInteger returns an Integer from a []byte of specified length.
// The remaining bytes after the specified length are also returned.
// Returns an error if size is invalid or there isn't enough data.
func ReadInteger(bytes []byte, size int) (Integer, []byte, error) {
	if size <= 0 {
		return nil, bytes, ErrInvalidSize
	}
	if size > len(bytes) {
		return nil, bytes, ErrInsufficientData
	}
	return Integer(bytes[:size]), bytes[size:], nil
}

// NewInteger creates a new Integer from []byte using ReadInteger.
// Limits the length of the created Integer to MAX_INTEGER_SIZE.
// Returns a pointer to Integer and the remaining bytes.
// Returns an error if size is invalid or there isn't enough data.
func NewInteger(bytes []byte, size int) (*Integer, []byte, error) {
	if size <= 0 || size > MAX_INTEGER_SIZE {
		return nil, bytes, ErrInvalidSize
	}
	if len(bytes) < size {
		return nil, bytes, ErrInsufficientData
	}

	integer, remainder, err := ReadInteger(bytes, size)
	if err != nil {
		return nil, bytes, err
	}
	return &integer, remainder, nil
}

// NewIntegerFromInt creates a new Integer from a Go integer of a specified []byte length.
// The value must be non-negative and fit within the specified number of bytes.
// Returns an error if the size is invalid or the value cannot be represented.
func NewIntegerFromInt(value int, size int) (*Integer, error) {
	if size <= 0 || size > MAX_INTEGER_SIZE {
		return nil, ErrInvalidSize
	}
	if value < 0 {
		return nil, ErrNegativeValue
	}

	// Check if value fits in specified size
	maxVal := int(math.Pow(2, float64(size*8))) - 1
	if value > maxVal {
		return nil, ErrIntegerOverflow
	}

	buf := make([]byte, MAX_INTEGER_SIZE)
	binary.BigEndian.PutUint64(buf, uint64(value))

	data := buf[MAX_INTEGER_SIZE-size:]
	integer := Integer(data)
	return &integer, nil
}

// intFromBytes interprets a slice of bytes from length 0 to length 8 as a big-endian
// integer and returns an int representation.
// Returns an error if the value would overflow on the current platform
// or if the input is invalid.
func intFromBytes(number []byte) (int, error) {
	if len(number) == 0 {
		return 0, nil
	}
	if len(number) > MAX_INTEGER_SIZE {
		return 0, ErrInvalidSize
	}
	
	padded := make([]byte, MAX_INTEGER_SIZE)
	copy(padded[MAX_INTEGER_SIZE-len(number):], number)
	
	val := int64(binary.BigEndian.Uint64(padded))
	if val > math.MaxInt32 || val < math.MinInt32 {
		return 0, ErrIntegerOverflow
	}
	
	return int(val), nil
}