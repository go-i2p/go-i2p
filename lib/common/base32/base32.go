// Package base32 implements utilities for encoding and decoding text using I2P's alphabet
package base32

import (
	b32 "encoding/base32"
)

// I2PEncodeAlphabet is the base32 encoding used throughout I2P.
// RFC 3548 using lowercase characters.
const I2PEncodeAlphabet = "abcdefghijklmnopqrstuvwxyz234567"

// I2PEncoding is the standard base32 encoding used through I2P.
var I2PEncoding *b32.Encoding = b32.NewEncoding(I2PEncodeAlphabet)

// EncodeToString encodes []byte to a base32 string using I2PEncoding
func EncodeToString(data []byte) string {
	return I2PEncoding.EncodeToString(data)
}

// DecodeString decodes base32 string to []byte I2PEncoding
func DecodeString(data string) ([]byte, error) {
	return I2PEncoding.DecodeString(data)
}
