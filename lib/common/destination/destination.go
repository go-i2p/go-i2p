// Package destination implements the I2P Destination common data structure
package destination

import (
	"strings"

	. "github.com/go-i2p/go-i2p/lib/common/keys_and_cert"

	"github.com/go-i2p/go-i2p/lib/common/base32"
	"github.com/go-i2p/go-i2p/lib/common/base64"
	"github.com/go-i2p/go-i2p/lib/crypto"
)

/*
[Destination]
Accurate for version 0.9.49

Description
A Destination defines a particular endpoint to which messages can be directed for secure delivery.

Contents
Identical to KeysAndCert.
*/

// Destination is the represenation of an I2P Destination.
//
// https://geti2p.net/spec/common-structures#destination
type Destination struct {
	KeysAndCert
}

// Base32Address returns the I2P base32 address for this Destination.
func (destination Destination) Base32Address() (str string) {
	dest := destination.KeysAndCert.KeyCertificate.Bytes()
	hash := crypto.SHA256(dest)
	str = strings.Trim(base32.EncodeToString(hash[:]), "=")
	str = str + ".b32.i2p"
	return
}

// Base64 returns the I2P base64 address for this Destination.
func (destination Destination) Base64() string {
	dest := destination.KeysAndCert.KeyCertificate.Bytes()
	return base64.EncodeToString(dest)
}

// ReadDestination returns Destination from a []byte.
// The remaining bytes after the specified length are also returned.
// Returns a list of errors that occurred during parsing.
func ReadDestination(data []byte) (destination Destination, remainder []byte, err error) {
	keys_and_cert, remainder, err := ReadKeysAndCert(data)
	destination = Destination{
		keys_and_cert,
	}
	return
}
