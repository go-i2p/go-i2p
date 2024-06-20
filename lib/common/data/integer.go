package data

import (
	"encoding/binary"
	"fmt"
)

// MAX_INTEGER_SIZE is the maximum length of an I2P integer in bytes.
const MAX_INTEGER_SIZE = 8

/*
[I2P Hash]
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
	return i[:]
}

// Int returns the Date as a Go integer
func (i Integer) Int() int {
	return intFromBytes(i.Bytes())
}

// ReadInteger returns an Integer from a []byte of specified length.
// The remaining bytes after the specified length are also returned.
func ReadInteger(bytes []byte, size int) (Integer, []byte) {
	if len(bytes) < size {
		return bytes[:size], bytes[len(bytes):]
	}
	return bytes[:size], bytes[size:]
}

// NewInteger creates a new Integer from []byte using ReadInteger.
// Limits the length of the created Integer to MAX_INTEGER_SIZE.
// Returns a pointer to Integer unlike ReadInteger.
func NewInteger(bytes []byte, size int) (integer *Integer, remainder []byte, err error) {
	integerSize := MAX_INTEGER_SIZE
	if size < MAX_INTEGER_SIZE {
		integerSize = size
	}
	intBytes := bytes[:integerSize]
	fmt.Println("IntegerSize: ", integerSize, "IntegerBytes:", bytes)
	i, remainder := ReadInteger(intBytes, integerSize)
	integer = &i
	return
}

// NewIntegerFromInt creates a new Integer from a Go integer of a specified []byte length.
func NewIntegerFromInt(value int, size int) (integer *Integer, err error) {
	bytes := make([]byte, MAX_INTEGER_SIZE)
	binary.BigEndian.PutUint64(bytes, uint64(value))
	integerSize := MAX_INTEGER_SIZE
	if size < MAX_INTEGER_SIZE {
		integerSize = size
	}
	objinteger, _, err := NewInteger(bytes[MAX_INTEGER_SIZE-integerSize:], integerSize)
	integer = objinteger
	return
}

// Interpret a slice of bytes from length 0 to length 8 as a big-endian
// integer and return an int representation.
func intFromBytes(number []byte) (value int) {
	num_len := len(number)
	if num_len < MAX_INTEGER_SIZE {
		number = append(
			make([]byte, MAX_INTEGER_SIZE-num_len),
			number...,
		)
	}
	value = int(binary.BigEndian.Uint64(number))
	return
}
