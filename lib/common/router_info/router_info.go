// Package router_info implements the I2P RouterInfo common data structure
package router_info

import (
	"errors"
	"strings"

	. "github.com/go-i2p/go-i2p/lib/common/data"
	. "github.com/go-i2p/go-i2p/lib/common/router_address"
	. "github.com/go-i2p/go-i2p/lib/common/router_identity"
	. "github.com/go-i2p/go-i2p/lib/common/signature"
	log "github.com/sirupsen/logrus"
)

const ROUTER_INFO_MIN_SIZE = 439

/*
[RouterInfo]
Accurate for version 0.9.49

Description
Defines all of the data that a router wants to public for the network to see. The
RouterInfo is one of two structures stored in the network database (the other being
LeaseSet), and is keyed under the SHA256 of the contained RouterIdentity.

Contents
RouterIdentity followed by the Date, when the entry was published

+----+----+----+----+----+----+----+----+
| router_ident                          |
+                                       +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| published                             |
+----+----+----+----+----+----+----+----+
|size| RouterAddress 0                  |
+----+                                  +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| RouterAddress 1                       |
+                                       +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| RouterAddress ($size-1)               |
+                                       +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+-//-+----+----+----+
|psiz| options                          |
+----+----+----+----+-//-+----+----+----+
| signature                             |
+                                       +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+

router_ident :: RouterIdentity
                length -> >= 387 bytes

published :: Date
             length -> 8 bytes

size :: Integer
        length -> 1 byte
        The number of RouterAddresses to follow, 0-255

addresses :: [RouterAddress]
             length -> varies

peer_size :: Integer
             length -> 1 byte
             The number of peer Hashes to follow, 0-255, unused, always zero
             value -> 0

options :: Mapping

signature :: Signature
             length -> 40 bytes
*/

// RouterInfo is the represenation of an I2P RouterInfo.
//
// https://geti2p.net/spec/common-structures#routerinfo
type RouterInfo struct {
	router_identity *RouterIdentity
	published       *Date
	size            *Integer
	addresses       []*RouterAddress
	peer_size       *Integer
	options         *Mapping
	signature       *Signature
}

// Bytes returns the RouterInfo as a []byte suitable for writing to a stream.
func (router_info RouterInfo) Bytes() ([]byte, error) {
	var err error
	var bytes []byte
	bytes = append(bytes, router_info.router_identity.KeysAndCert.Bytes()...)
	bytes = append(bytes, router_info.published.Bytes()...)
	bytes = append(bytes, router_info.size.Bytes()...)
	for _, router_address := range router_info.addresses {
		bytes = append(bytes, router_address.Bytes()...)
	}
	bytes = append(bytes, router_info.peer_size.Bytes()...)
	bytes = append(bytes, router_info.options.Data()...)
	//bytes = append(bytes, []byte(*router_info.signature)...)

	return bytes, err
}

// RouterIdentity returns the router identity as *RouterIdentity.
func (router_info *RouterInfo) RouterIdentity() *RouterIdentity {
	return router_info.router_identity
}

// IndentHash returns the identity hash (sha256 sum) for this RouterInfo.
func (router_info *RouterInfo) IdentHash() Hash {
	ri := router_info.RouterIdentity()
	h := HashData(ri.KeysAndCert.Certificate().Data())
	return h
}

// Published returns the date this RouterInfo was published as an I2P Date.
func (router_info *RouterInfo) Published() *Date {
	return router_info.published
}

// RouterAddressCount returns the count of RouterAddress in this RouterInfo as a Go integer.
func (router_info *RouterInfo) RouterAddressCount() int {
	return router_info.size.Int()
}

// RouterAddresses returns all RouterAddresses for this RouterInfo as []*RouterAddress.
func (router_info *RouterInfo) RouterAddresses() []*RouterAddress {
	return router_info.addresses
}

// PeerSize returns the peer size as a Go integer.
func (router_info *RouterInfo) PeerSize() int {
	// Peer size is unused:
	// https://geti2p.net/spec/common-structures#routeraddress
	return 0
}

// Options returns the options for this RouterInfo as an I2P Mapping.
func (router_info RouterInfo) Options() (mapping Mapping) {
	return *router_info.options
}

//
// Return the signature of this router info
//

// Signature returns the signature for this RouterInfo as an I2P Signature.
func (router_info RouterInfo) Signature() (signature Signature) {
	return *router_info.signature
}

//
// Used during parsing to determine where in the RouterInfo the Mapping data begins.
//
/*func (router_info RouterInfo) optionsLocation() (location int) {
	data, remainder, err := ReadRouterIdentity(router_info)
	if err != nil {
		return
	}
	location += len(data)

	remainder_len := len(remainder)
	if remainder_len < 9 {
		log.WithFields(log.Fields{
			"at":           "(RouterInfo) optionsLocation",
			"data_len":     remainder_len,
			"required_len": 9,
			"reason":       "not enough data",
		}).Error("error parsing router info")
		err = errors.New("error parsing router addresses: not enough data")
		return
	}
	location += 9

	remaining := remainder[9:]
	var router_address RouterAddress
	var router_addresses []RouterAddress
	addr_count, cerr := router_info.RouterAddressCount()
	if cerr != nil {
		err = cerr
		return
	}
	for i := 0; i < addr_count; i++ {
		router_address, remaining, err = ReadRouterAddress(remaining)
		if err == nil {
			location += len(router_address)
			router_addresses = append(router_addresses, router_address)
		}
	}
	location += 1
	return
}*/

//
// Used during parsing to determine the size of the options in the RouterInfo.
//
/*func (router_info RouterInfo) optionsSize() (size int) {
	head := router_info.optionsLocation()
	s := Integer(router_info[head : head+2])
	size = s.Int() + 2
	return
}*/

// ReadRouterInfo returns RouterInfo from a []byte.
// The remaining bytes after the specified length are also returned.
// Returns a list of errors that occurred during parsing.
func ReadRouterInfo(bytes []byte) (info RouterInfo, remainder []byte, err error) {
	identity, remainder, err := NewRouterIdentity(bytes)
	log.Println("Remainder of RouterIdentity", remainder)
	info.router_identity = identity
	if err != nil {
		log.WithFields(log.Fields{
			"at":           "(RouterInfo) ReadRouterInfo",
			"data_len":     len(bytes),
			"required_len": ROUTER_INFO_MIN_SIZE,
			"reason":       "not enough data",
		}).Error("error parsing router info")
		err = errors.New("error parsing router info: not enough data")
	}
	date, remainder, err := NewDate(remainder)
	info.published = date
	if err != nil {
		log.WithFields(log.Fields{
			"at":           "(RouterInfo) ReadRouterInfo",
			"data_len":     len(remainder),
			"required_len": DATE_SIZE,
			"reason":       "not enough data",
		}).Error("error parsing router info")
		err = errors.New("error parsing router info: not enough data")
	}
	size, remainder, err := NewInteger(remainder, 1)
	if err != nil {
		log.WithFields(log.Fields{
			"at":           "(RouterInfo) ReadRouterInfo",
			"data_len":     len(remainder),
			"required_len": size.Int(),
			"reason":       "read error",
		}).Error("error parsing router info size")
	}
	info.size = size
	if err != nil {
		log.WithFields(log.Fields{
			"at":           "(RouterInfo) ReadRouterInfo",
			"data_len":     len(remainder),
			"required_len": size.Int(),
			"reason":       "not enough data",
		}).Error("error parsing router info")
		err = errors.New("error parsing router info: not enough data")
	}
	log.Println("Address Count:", size.Int())
	for i := 0; i < size.Int(); i++ {
		address, more, err := NewRouterAddress(remainder)
		remainder = more
		if err != nil {
			log.WithFields(log.Fields{
				"at":       "(RouterInfo) ReadRouterInfo",
				"data_len": len(remainder),
				//"required_len": ROUTER_ADDRESS_SIZE,
				"reason": "not enough data",
			}).Error("error parsing router address")
			err = errors.New("error parsing router info: not enough data")
		}
		//log.Println("Address Remainder:", string(remainder))
		info.addresses = append(info.addresses, address)
	}
	info.peer_size, remainder, err = NewInteger(remainder, 1)
	log.Println("Peer Size:", info.peer_size, "Peer size Remainder:", string(remainder))
	var errs []error
	info.options, remainder, errs = NewMapping(remainder)
	if len(errs) != 0 {
		log.WithFields(log.Fields{
			"at":       "(RouterInfo) ReadRouterInfo",
			"data_len": len(remainder),
			//"required_len": MAPPING_SIZE,
			"reason": "not enough data",
		}).Error("error parsing router info")
		estring := ""
		for _, e := range errs {
			estring += e.Error() + " "
		}
		err = errors.New("error parsing router info: " + estring)
	}
	if err != nil {
		log.WithFields(log.Fields{
			"at":       "(RouterInfo) ReadRouterInfo",
			"data_len": len(remainder),
			//"required_len": MAPPING_SIZE,
			"reason": "not enough data",
		}).Error("error parsing router info")
		err = errors.New("error parsing router info: not enough data")
	}
	return
}

func (router_info *RouterInfo) RouterCapabilities() string {
	str, err := ToI2PString("caps")
	if err != nil {
		return ""
	}
	return string(router_info.options.Values().Get(str))
}

func (router_info *RouterInfo) UnCongested() bool  {
	caps := router_info.RouterCapabilities()
	if strings.Contains(caps, "K"){
		return false
	}
	if strings.Contains(caps, "G"){
		return false
	}
	if strings.Contains(caps, "E"){
		return false
	}
	return true
}

func (router_info *RouterInfo) Reachable() bool {
	caps := router_info.RouterCapabilities()
	if strings.Contains(caps, "U") {
		return false
	}
	return strings.Contains(caps, "R")
}

// NewRouterInfo creates a new *RouterInfo from []byte using ReadRouterInfo.
// Returns a pointer to RouterInfo unlike ReadRouterInfo.
func NewRouterInfo(data []byte) (router_info *RouterInfo, remainder []byte, err error) {
	routerInfo, remainder, err := ReadRouterInfo(data)
	router_info = &routerInfo
	return
}
