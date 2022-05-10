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
	KeysAndCert *KeysAndCert
}

//[]byte

func (router_identity *RouterIdentity) PublicKey() crypto.PublicKey {
	return router_identity.KeysAndCert.PublicKey()
}

func (router_identity *RouterIdentity) SigningPublicKey() crypto.SigningPublicKey {
	return router_identity.KeysAndCert.SigningPublicKey()
}

func (router_identity *RouterIdentity) Certificate() *Certificate {
	return router_identity.KeysAndCert.Certificate()
}

func ReadRouterIdentity(data []byte) (router_identity RouterIdentity, remainder []byte, err error) {
	keys_and_cert, remainder, err := NewKeysAndCert(data)
	router_identity = RouterIdentity{
		KeysAndCert: keys_and_cert,
	} //(keys_and_cert)
	return
}

func NewRouterIdentity(data []byte) (router_identity *RouterIdentity, remainder []byte, err error) {
	objrouter_identity, remainder, err := ReadRouterIdentity(data)
	router_identity = &objrouter_identity
	return
}
