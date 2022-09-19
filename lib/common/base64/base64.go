// Package base64 implmenets  utilities for encoding and decoding text using I2P's alphabet
package base64

import (
	b64 "encoding/base64"
)

// I2PEncodeAlphabet is the base64 encoding used throughout I2P.
// RFC 4648 with "/"" replaced with "~", and "+" replaced with "-".
const I2PEncodeAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~"

// I2PEncoding is the standard base64 encoding used through I2P.
var I2PEncoding *b64.Encoding = b64.NewEncoding(I2PEncodeAlphabet)

// I2PEncoding is the standard base64 encoding used through I2P.
func EncodeToString(data []byte) string {
	return I2PEncoding.EncodeToString(data)
}

// DecodeString decodes base64 string to []byte I2PEncoding
func DecodeString(str string) ([]byte, error) {
	return I2PEncoding.DecodeString(str)
}
