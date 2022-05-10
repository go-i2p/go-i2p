package common

/*
I2P RouterInfo
https://geti2p.net/spec/common-structures#routerinfo
Accurate for version 0.9.24

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

import (
	"errors"

	log "github.com/sirupsen/logrus"
)

const ROUTER_INFO_MIN_SIZE = 439

type RouterInfo struct {
	router_identity *RouterIdentity
	published       *Date
	size            *Integer
	addresses       []*RouterAddress
	peer_size       *Integer
	options         *Mapping
	signature       *Signature
}

//[]byte

//
// Read a RouterIdentity from the RouterInfo, returning the RouterIdentity and any errors
// encountered parsing the RouterIdentity.
//
func (router_info *RouterInfo) RouterIdentity() *RouterIdentity {
	return router_info.router_identity
}

//
// Calculate this RouterInfo's Identity Hash (the sha256 of the RouterIdentity)
// returns error if the RouterIdentity is malformed
//
func (router_info *RouterInfo) IdentHash() Hash {
	ri := router_info.RouterIdentity()
	h := HashData(ri.KeysAndCert.Certificate().Data())
	return h
}

//
// Return the Date the RouterInfo was published and any errors encountered parsing the RouterInfo.
//
func (router_info *RouterInfo) Published() *Date {
	return router_info.published
}

//
// Return the Integer representing the number of RouterAddresses that are contained in this RouterInfo.
//
func (router_info *RouterInfo) RouterAddressCount() int {
	return router_info.size.Int()
}

//
// Read the RouterAddresses inside this RouterInfo and return them in a slice, returning
// a partial list if data is missing.
//
func (router_info *RouterInfo) RouterAddresses() []*RouterAddress {
	return router_info.addresses
}

//
// Return the PeerSize value, currently unused and always zero.
//
func (router_info *RouterInfo) PeerSize() int {
	// Peer size is unused:
	// https://geti2p.net/spec/common-structures#routeraddress
	return 0
}

//
// Return the Options Mapping inside this RouterInfo.
//
func (router_info RouterInfo) Options() (mapping Mapping) {
	return *router_info.options
}

//
// Return the signature of this router info
//
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

func ReadRouterInfo(bytes []byte) (info RouterInfo, remainder []byte, err error) {
	identity, remainder, err := NewRouterIdentity(bytes)
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
	size, remainder, err := NewInteger(remainder)
	info.size = size
	if err != nil {
		log.WithFields(log.Fields{
			"at":           "(RouterInfo) ReadRouterInfo",
			"data_len":     len(remainder),
			"required_len": INTEGER_SIZE,
			"reason":       "not enough data",
		}).Error("error parsing router info")
		err = errors.New("error parsing router info: not enough data")
	}
	addresses := make([]*RouterAddress, size.Int())
	for i := 0; i < size.Int(); i++ {
		address, remainder, err := NewRouterAddress(remainder)
		if err != nil {
			log.WithFields(log.Fields{
				"at":       "(RouterInfo) ReadRouterInfo",
				"data_len": len(remainder),
				//"required_len": ROUTER_ADDRESS_SIZE,
				"reason": "not enough data",
			}).Error("error parsing router info")
			err = errors.New("error parsing router info: not enough data")
		}
		addresses = append(addresses, address)
	}
	info.addresses = addresses
	peer_size := Integer(remainder[:1])
	info.peer_size = &peer_size
	remainder = remainder[1:]
	options, remainder, err := NewMapping(remainder)
	info.options = options
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
