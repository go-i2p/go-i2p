package common

/*
I2P RouterIdentity
https://geti2p.net/spec/common-structures#routeridentity
Accurate for version 0.9.24

Identical to KeysAndCert
*/

import (
	"github.com/go-i2p/go-i2p/lib/crypto"
)

//
// A RouterIdentity is identical to KeysAndCert.
//
type RouterIdentity struct {
	KeysAndCert
}

func (router_identity RouterIdentity) PublicKey() (crypto.PublicKey, error) {
	return router_identity.PublicKey()
}

func (router_identity RouterIdentity) SigningPublicKey() (crypto.SigningPublicKey, error) {
	return router_identity.SigningPublicKey()
}

func (router_identity RouterIdentity) Certificate() (Certificate, error) {
	return router_identity.Certificate()
}

func ReadRouterIdentity(data []byte) (router_identity RouterIdentity, remainder []byte, err error) {
	keys_and_cert, remainder, err := ReadKeysAndCert(data)
	if err != nil {
		return
	}
	router_identity.KeysAndCert = keys_and_cert
	return
}
