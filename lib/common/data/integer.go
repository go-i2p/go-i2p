package data

/*
I2P Integer
https://geti2p.net/spec/common-structures#integer
Accurate for version 0.9.24

Description

Represents a non-negative integer.

Contents

1 to 8 bytes in network byte order (big endian) representing an unsigned integer.

*/

import (
	"encoding/binary"
)

// Total byte length of an I2P integer
const (
	MAX_INTEGER_SIZE = 8
)

type Integer []byte

func (i Integer) Bytes() []byte {
	return i[:]
}

func (i Integer) Int() int {
	return intFromBytes(i.Bytes())
}

func ReadInteger(bytes []byte, size int) (Integer, []byte) {
	if len(bytes) < size {
		return bytes[:size], bytes[len(bytes):]
	}
	return bytes[:size], bytes[size:]
}

func NewInteger(bytes []byte, size int) (integer *Integer, remainder []byte, err error) {
	integerSize := MAX_INTEGER_SIZE
	if size < MAX_INTEGER_SIZE {
		integerSize = size
	}
	i, remainder := ReadInteger(bytes, integerSize)
	integer = &i
	return
}

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

//
// Interpret a slice of bytes from length 0 to length 8 as a big-endian
// integer and return an int representation.
//
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
