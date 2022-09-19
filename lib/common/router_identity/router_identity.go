// Package router_identity implements the I2P RouterIdentity common data structure
package router_identity

import (
	. "github.com/go-i2p/go-i2p/lib/common/keys_and_cert"
)

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
	*KeysAndCert
}

// ReadRouterIdentity returns RouterIdentity from a []byte.
// The remaining bytes after the specified length are also returned.
// Returns a list of errors that occurred during parsing.
func ReadRouterIdentity(data []byte) (router_identity RouterIdentity, remainder []byte, err error) {
	keys_and_cert, remainder, err := NewKeysAndCert(data)
	router_identity = RouterIdentity{
		keys_and_cert,
	}
	return
}

// NewRouterIdentity creates a new *RouterIdentity from []byte using ReadRouterIdentity.
// Returns a pointer to RouterIdentity unlike ReadRouterIdentity.
func NewRouterIdentity(data []byte) (router_identity *RouterIdentity, remainder []byte, err error) {
	objrouter_identity, remainder, err := ReadRouterIdentity(data)
	router_identity = &objrouter_identity
	return
}
