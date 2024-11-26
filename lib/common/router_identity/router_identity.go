// Package router_identity implements the I2P RouterIdentity common data structure
package router_identity

import (
	"github.com/go-i2p/go-i2p/lib/common/certificate"
	"github.com/go-i2p/go-i2p/lib/common/destination"
	"github.com/go-i2p/go-i2p/lib/common/key_certificate"
	. "github.com/go-i2p/go-i2p/lib/common/keys_and_cert"
	"github.com/go-i2p/go-i2p/lib/crypto"
	"github.com/go-i2p/go-i2p/lib/util/logger"
	"github.com/sirupsen/logrus"
)

var log = logger.GetGoI2PLogger()

/*
[RouterIdentity]
Accurate for version 0.9.49

Description
Defines the way to uniquely identify a particular router

Contents
Identical to KeysAndCert.
*/

// RouterIdentity is the represenation of an I2P RouterIdentity.
//
// https://geti2p.net/spec/common-structures#routeridentity
type RouterIdentity struct {
	KeysAndCert
}

// ReadRouterIdentity returns RouterIdentity from a []byte.
// The remaining bytes after the specified length are also returned.
// Returns a list of errors that occurred during parsing.
func ReadRouterIdentity(data []byte) (router_identity RouterIdentity, remainder []byte, err error) {
	log.WithFields(logrus.Fields{
		"input_length": len(data),
	}).Debug("Reading RouterIdentity from data")
	keys_and_cert, remainder, err := ReadKeysAndCert(data)
	if err != nil {
		log.WithError(err).Error("Failed to read KeysAndCert for RouterIdentity")
		return
	}
	router_identity = RouterIdentity{
		keys_and_cert,
	}
	log.WithFields(logrus.Fields{
		"remainder_length": len(remainder),
	}).Debug("Successfully read RouterIdentity")
	return
}

func NewRouterIdentity(publicKey crypto.PublicKey, signingPublicKey crypto.SigningPublicKey, cert certificate.Certificate, padding []byte) (*RouterIdentity, error) {
	log.Debug("Creating new RouterIdentity")

	// Step 1: Create keyCertificate from the provided certificate.
	// Assuming NewKeyCertificate is a constructor that takes a Certificate and returns a keyCertificate.
	keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
	if err != nil {
		log.WithError(err).Error("KeyCertificateFromCertificate failed.")
		return nil, err
	}

	// Step 2: Create KeysAndCert instance.
	keysAndCert, err := NewKeysAndCert(keyCert, publicKey, padding, signingPublicKey)
	if err != nil {
		log.WithError(err).Error("NewKeysAndCert failed.")
		return nil, err
	}

	// Step 3: Initialize RouterIdentity with KeysAndCert.
	routerIdentity := RouterIdentity{
		KeysAndCert: *keysAndCert,
	}

	log.WithFields(logrus.Fields{
		"public_key_type":         keyCert.PublicKeyType(),
		"signing_public_key_type": keyCert.SigningPublicKeyType(),
		"padding_length":          len(padding),
	}).Debug("Successfully created RouterIdentity")

	return &routerIdentity, nil
}

func (router_identity *RouterIdentity) AsDestination() destination.Destination {
	return destination.Destination{
		KeysAndCert: router_identity.KeysAndCert,
	}
}
