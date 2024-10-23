// Package router_identity implements the I2P RouterIdentity common data structure
package router_identity

import (
	. "github.com/go-i2p/go-i2p/lib/common/keys_and_cert"
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
