package common

/*
I2P Destination
https://geti2p.net/spec/common-structures#destination
Accurate for version 0.9.24

Identical to KeysAndCert
*/

import (
	"github.com/go-i2p/go-i2p/lib/common/base32"
	"github.com/go-i2p/go-i2p/lib/common/base64"
	"github.com/go-i2p/go-i2p/lib/crypto"
	"strings"
)

//
// A Destination is a KeysAndCert with functionallity
// for generating base32 and base64 addresses.
//
type Destination struct {
	KeysAndCert
}

func (destination Destination) PublicKey() (crypto.PublicKey, error) {
	return destination.KeysAndCert.GetPublicKey()
}

func (destination Destination) SigningPublicKey() (crypto.SigningPublicKey, error) {
	return destination.KeysAndCert.GetSigningPublicKey()
}

func (destination Destination) Certificate() (Certificate, error) {
	return destination.KeysAndCert.GetCertificate()
}

func ReadDestination(data []byte) (destination Destination, remainder []byte, err error) {
	keys_and_cert, remainder, err := ReadKeysAndCert(data)
	destination.KeysAndCert = keys_and_cert
	return
}

//
// Generate the I2P base32 address for this Destination.
//
func (destination Destination) Base32Address() (str string) {
	hash := crypto.SHA256(destination.Cert())
	str = strings.Trim(base32.EncodeToString(hash[:]), "=")
	str = str + ".b32.i2p"
	return
}

//
// Generate the I2P base64 address for this Destination.
//
func (destination Destination) Base64() string {
	return base64.EncodeToString(destination.Cert())
}
