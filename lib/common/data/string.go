package data

import (
	"errors"

	log "github.com/sirupsen/logrus"
)

// STRING_MAX_SIZE is the maximum number of bytes that can be stored in an I2P string
const STRING_MAX_SIZE = 255

/*
[I2P String]
Accurate for version 0.9.49

Description
Represents a UTF-8 encoded string.

Contents
1 or more bytes where the first byte is the number of bytes (not characters!) in the string
and the remaining 0-255 bytes are the non-null terminated UTF-8 encoded character array.
Length limit is 255 bytes (not characters). Length may be 0.
*/

// I2PString is the represenation of an I2P String.
//
// https://geti2p.net/spec/common-structures#string
type I2PString []byte

// Length returns the length specified in the first byte.
// Returns error if the specified does not match the actual length or the string is otherwise invalid.
func (str I2PString) Length() (length int, err error) {
	if len(str) == 0 {
		log.WithFields(log.Fields{
			"at":     "(I2PString) Length",
			"reason": "no data",
		}).Error("error parsing string")
		err = errors.New("error parsing string: zero length")
		return
	}
	l, _, _ := NewInteger(str, 1)
	length = l.Int()
	str_len := len(str) - 1
	if length != str_len {
		log.WithFields(log.Fields{
			"at":                  "(I2PString) Length",
			"string_bytes_length": str_len,
			"string_length_field": length,
			"reason":              "data less than specified by length",
		}).Error("string format warning")
		err = errors.New("string parsing warning: string data is shorter than specified by length")
	}
	return
}

// Data returns the I2PString content as a string trimmed to the specified length and not including the length byte.
// Returns error encountered by Length.
func (str I2PString) Data() (data string, err error) {
	length, err := str.Length()
	if err != nil {
		switch err.Error() {
		case "error parsing string: zero length":
			return
		case "string parsing warning: string data is shorter than specified by length":
			data = string(str[1:])
			return
		case "string parsing warning: string contains data beyond length":
			data = string(str[1:])
			return
		}
	}
	if length == 0 {
		return
	}
	data = string(str[1 : length+1])
	return
}

// ToI2PString converts a Go string to an I2PString.
// Returns error if the string exceeds STRING_MAX_SIZE.
func ToI2PString(data string) (str I2PString, err error) {
	data_len := len(data)
	if data_len > STRING_MAX_SIZE {
		log.WithFields(log.Fields{
			"at":         "ToI2PI2PString",
			"string_len": data_len,
			"max_len":    STRING_MAX_SIZE,
			"reason":     "too much data",
		}).Error("cannot create I2P string")
		err = errors.New("cannot store that much data in I2P string")
		return
	}
	i2p_string := []byte{byte(data_len)}
	i2p_string = append(i2p_string, []byte(data)...)
	str = I2PString(i2p_string)
	return
}

//
// Read a string from a slice of bytes, returning any extra data on the end
// of the slice and any errors encountered parsing the I2PString.
//

// ReadI2PString returns I2PString from a []byte.
// The remaining bytes after the specified length are also returned.
// Returns a list of errors that occurred during parsing.
func ReadI2PString(data []byte) (str I2PString, remainder []byte, err error) {
	length, _, err := NewInteger(data, 1)
	if err != nil {
		return
	}
	data_len := length.Int()
	str = data[:data_len+1]
	remainder = data[data_len+1:]
	_, err = str.Length()
	return
}

// NewI2PString creates a new *I2PString from []byte using ReadI2PString.
// Returns a pointer to I2PString unlike ReadI2PString.
func NewI2PString(data []byte) (str *I2PString, remainder []byte, err error) {
	objstr, remainder, err := ReadI2PString(data)
	str = &objstr
	return
}
