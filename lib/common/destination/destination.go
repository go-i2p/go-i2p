// Package destination implements the I2P Destination common data structure
package destination

import (
	"strings"

	"github.com/go-i2p/logger"
	"github.com/sirupsen/logrus"

	. "github.com/go-i2p/go-i2p/lib/common/keys_and_cert"

	"github.com/go-i2p/go-i2p/lib/common/base32"
	"github.com/go-i2p/go-i2p/lib/common/base64"
	"github.com/go-i2p/go-i2p/lib/crypto"
)

var log = logger.GetGoI2PLogger()

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
	*KeysAndCert
}

// Base32Address returns the I2P base32 address for this Destination.
func (destination Destination) Base32Address() (str string) {
	log.Debug("Generating Base32 address for Destination")

	cert := destination.KeysAndCert.Certificate()
	dest := cert.Bytes()
	hash := crypto.SHA256(dest)
	str = strings.Trim(base32.EncodeToString(hash[:]), "=")
	str = str + ".b32.i2p"

	log.WithFields(logrus.Fields{
		"base32_address": str,
	}).Debug("Generated Base32 address for Destination")

	return
}

// Base64 returns the I2P base64 address for this Destination.
func (destination Destination) Base64() string {
	log.Debug("Generating Base64 address for Destination")

	cert := destination.KeysAndCert.Certificate()
	dest := cert.Bytes()
	base64Address := base64.EncodeToString(dest)

	log.WithFields(logrus.Fields{
		"base64_address_length": len(base64Address),
	}).Debug("Generated Base64 address for Destination")

	return base64Address
}

// ReadDestination returns Destination from a []byte.
// The remaining bytes after the specified length are also returned.
// Returns a list of errors that occurred during parsing.
func ReadDestination(data []byte) (destination Destination, remainder []byte, err error) {
	log.WithFields(logrus.Fields{
		"input_length": len(data),
	}).Debug("Reading Destination from bytes")

	keys_and_cert, remainder, err := ReadKeysAndCert(data)
	destination = Destination{
		keys_and_cert,
	}

	log.WithFields(logrus.Fields{
		"remainder_length": len(remainder),
	}).Debug("Successfully read Destination from bytes")

	return
}
