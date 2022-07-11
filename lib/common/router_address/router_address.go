package common

/*
I2P RouterAddress
https://geti2p.net/spec/common-structures#routeraddress
Accurate for version 0.9.24

+----+----+----+----+----+----+----+----+
|cost|           expiration
+----+----+----+----+----+----+----+----+
     |        transport_style           |
+----+----+----+----+-//-+----+----+----+
|                                       |
+                                       +
|               options                 |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+

cost :: Integer
        length -> 1 byte

        case 0 -> free
        case 255 -> expensive

expiration :: Date (must be all zeros, see notes below)
              length -> 8 bytes

              case null -> never expires

transport_style :: String
                   length -> 1-256 bytes

options :: Mapping
*/

import (
	"errors"

	. "github.com/go-i2p/go-i2p/lib/common/data"
	log "github.com/sirupsen/logrus"
)

// Minimum number of bytes in a valid RouterAddress
const (
	ROUTER_ADDRESS_MIN_SIZE = 9
)

type RouterAddress struct {
	cost            *Integer
	expiration      *Date
	transport_style *I2PString
	options         *Mapping
	parserErr       error
}

//[]byte

//
// Return the cost integer for this RouterAddress and any errors encountered
// parsing the RouterAddress.
//
func (router_address RouterAddress) Cost() int {
	return router_address.cost.Int()
}

//
// Return the Date this RouterAddress expires and any errors encountered
// parsing the RouterAddress.
//
func (router_address RouterAddress) Expiration() Date {
	return *router_address.expiration
}

//
// Return the Transport type for this RouterAddress and any errors encountered
// parsing the RouterAddress.
//
func (router_address RouterAddress) TransportStyle() I2PString {
	return *router_address.transport_style
}

//
// Return the Mapping containing the options for this RouterAddress and any
// errors encountered parsing the RouterAddress.
//
func (router_address RouterAddress) Options() Mapping {
	return *router_address.options
}

//
// Check if the RouterAddress is empty or if it is too small to contain valid data.
//
func (router_address RouterAddress) checkValid() (err error, exit bool) {
	/*addr_len := len(router_address)
	exit = false
	if addr_len == 0 {
		log.WithFields(log.Fields{
			"at":     "(RouterAddress) checkValid",
			"reason": "no data",
		}).Error("invalid router address")
		err = errors.New("error parsing RouterAddress: no data")
		exit = true
	} else if addr_len < ROUTER_ADDRESS_MIN_SIZE {
		log.WithFields(log.Fields{
			"at":     "(RouterAddress) checkValid",
			"reason": "data too small (len < ROUTER_ADDRESS_MIN_SIZE)",
		}).Warn("router address format warning")
		err = errors.New("warning parsing RouterAddress: data too small")
	}*/
	if router_address.parserErr != nil {
		exit = true
	}
	return
}

//
// Given a slice of bytes, read a RouterAddress, returning the remaining bytes and any
// errors encountered parsing the RouterAddress.
//

func ReadRouterAddress(data []byte) (router_address RouterAddress, remainder []byte, err error) {
	if data == nil || len(data) == 0 {
		log.WithField("at", "(RouterAddress) ReadRouterAddress").Error("no data")
		err = errors.New("error parsing RouterAddress: no data")
		router_address.parserErr = err
		return
	}
	cost, remainder, err := NewInteger([]byte{data[0]})
	router_address.cost = cost
	if err != nil {
		log.WithFields(log.Fields{
			"at":     "(RouterAddress) ReadNewRouterAddress",
			"reason": "error parsing cost",
		}).Warn("error parsing RouterAddress")
		router_address.parserErr = err
	}
	expiration, remainder, err := NewDate(remainder)
	router_address.expiration = expiration
	if err != nil {
		log.WithFields(log.Fields{
			"at":     "(RouterAddress) ReadNewRouterAddress",
			"reason": "error parsing expiration",
		}).Error("error parsing RouterAddress")
		router_address.parserErr = err
	}
	transport_style, remainder, err := NewI2PString(remainder)
	router_address.transport_style = transport_style
	if err != nil {
		log.WithFields(log.Fields{
			"at":     "(RouterAddress) ReadNewRouterAddress",
			"reason": "error parsing transport_style",
		}).Error("error parsing RouterAddress")
		router_address.parserErr = err
	}
	options, remainder, err := NewMapping(remainder)
	router_address.options = options
	if err != nil {
		log.WithFields(log.Fields{
			"at":     "(RouterAddress) ReadNewRouterAddress",
			"reason": "error parsing options",
		}).Error("error parsing RouterAddress")
		router_address.parserErr = err
	}
	return
}

func NewRouterAddress(data []byte) (router_address *RouterAddress, remainder []byte, err error) {
	objrouteraddress, remainder, err := ReadRouterAddress(data)
	router_address = &objrouteraddress
	return
}
