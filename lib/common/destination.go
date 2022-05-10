package common

/*
I2P Destination
https://geti2p.net/spec/common-structures#destination
Accurate for version 0.9.24

Identical to KeysAndCert
*/

import (
	"strings"

	"github.com/go-i2p/go-i2p/lib/common/base32"
	"github.com/go-i2p/go-i2p/lib/common/base64"
	"github.com/go-i2p/go-i2p/lib/crypto"
)

//
// A Destination is a KeysAndCert with functionallity
// for generating base32 and base64 addresses.
//
type Destination struct {
	KeysAndCert *KeysAndCert
}

//[]byte

func (destination Destination) PublicKey() crypto.PublicKey {
	//return KeysAndCert(destination).PublicKey()
	return destination.KeysAndCert.PublicKey()
}

func (destination Destination) SigningPublicKey() crypto.SigningPublicKey {
	//return KeysAndCert(destination).SigningPublicKey()
	return destination.KeysAndCert.SigningPublicKey()
}

func (destination Destination) Certificate() *Certificate {
	//return KeysAndCert(destination).Certificate()
	return destination.KeysAndCert.Certificate()
}

func ReadDestination(data []byte) (destination Destination, remainder []byte, err error) {
	keys_and_cert, remainder, err := NewKeysAndCert(data)
	destination = Destination{
		KeysAndCert: keys_and_cert,
	}
	//Destination(keys_and_cert)
	return
}

func NewDestination(data []byte) (destination *Destination, remainder []byte, err error) {
	objdestination, remainder, err := ReadDestination(data)
	destination = &objdestination
	return destination, remainder, err
}

//
// Generate the I2P base32 address for this Destination.
//
func (destination Destination) Base32Address() (str string) {
	dest := destination.KeysAndCert.KeyCertificate.Bytes()
	hash := crypto.SHA256(dest)
	str = strings.Trim(base32.EncodeToString(hash[:]), "=")
	str = str + ".b32.i2p"
	return
}

//
// Generate the I2P base64 address for this Destination.
//
func (destination Destination) Base64() string {
	dest := destination.KeysAndCert.KeyCertificate.Bytes()
	return base64.EncodeToString(dest)
}
