package common

/*
I2P Integer
https://geti2p.net/spec/common-structures#integer
Accurate for version 0.9.24
*/

import (
	"encoding/binary"
	"errors"

	log "github.com/sirupsen/logrus"
)

// Total byte length of an I2P integer
const (
	INTEGER_SIZE = 8
)

type Integer []byte

func (i Integer) Bytes() []byte {
	return i[:]
}

func (i Integer) Int() int {
	return intFromBytes(i.Bytes())
}

func ReadInteger(bytes []byte) (Integer, []byte, error) {
	if len(bytes) < INTEGER_SIZE {
		log.WithFields(log.Fields{
			"bytes": bytes,
		}).Error("ReadInteger: bytes is too short")
		return Integer(bytes), nil, errors.New("ReadInteger: bytes is too short")
	}
	return bytes[:INTEGER_SIZE], bytes[INTEGER_SIZE:], nil
}

func NewInteger(bytes []byte) (integer *Integer, remainder []byte, err error) {
	i, remainder, err := ReadInteger(bytes)
	integer = &i
	return
}

func NewIntegerFromInt(value int) (integer *Integer, err error) {
	bytes := make([]byte, INTEGER_SIZE)
	binary.BigEndian.PutUint64(bytes, uint64(value))
	objinteger, _, err := NewInteger(bytes)
	integer = objinteger
	return
}

//
// Interpret a slice of bytes from length 0 to length 8 as a big-endian
// integer and return an int representation.
//
func intFromBytes(number []byte) (value int) {
	num_len := len(number)
	if num_len < INTEGER_SIZE {
		number = append(
			make([]byte, INTEGER_SIZE-num_len),
			number...,
		)
	}
	value = int(binary.BigEndian.Uint64(number))
	return
}
