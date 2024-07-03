// Package router_address implements the I2P RouterAddress common data structure
package router_address

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	. "github.com/go-i2p/go-i2p/lib/common/data"
	log "github.com/sirupsen/logrus"
)

// Minimum number of bytes in a valid RouterAddress
const (
	ROUTER_ADDRESS_MIN_SIZE = 9
)

/*
[RouterAddress]
Accurate for version 0.9.49

Description
This structure defines the means to contact a router through a transport protocol.

Contents
1 byte Integer defining the relative cost of using the address, where 0 is free and 255 is
expensive, followed by the expiration Date after which the address should not be used,
of if null, the address never expires. After that comes a String defining the transport
protocol this router address uses. Finally there is a Mapping containing all of the
transport specific options necessary to establish the connection, such as IP address,
port number, email address, URL, etc.


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

// RouterAddress is the represenation of an I2P RouterAddress.
//
// https://geti2p.net/spec/common-structures#routeraddress
type RouterAddress struct {
	TransportCost    *Integer
	ExpirationDate   *Date
	TransportType    *I2PString
	TransportOptions *Mapping
}

// Network implements net.Addr. It returns the transport type
func (router_address *RouterAddress) Network() string {
	if router_address.TransportType == nil {
		return ""
	}
	str, err := router_address.TransportType.Data()
	if err != nil {
		return ""
	}
	return string(str)
}

func (router_address *RouterAddress) UDP() bool {
	return strings.HasPrefix(strings.ToLower(router_address.Network()), "ssu")
}

// String implements net.Addr. It returns the IP address, followed by the options
func (router_address *RouterAddress) String() string {
	var rv []string
	rv = append(rv, string(router_address.HostString()))
	rv = append(rv, string(router_address.PortString()))
	rv = append(rv, string(router_address.StaticKeyString()))
	rv = append(rv, string(router_address.InitializationVectorString()))
	rv = append(rv, string(router_address.ProtocolVersionString()))
	if router_address.UDP() {
		rv = append(rv, string(router_address.IntroducerHashString(0)))
		rv = append(rv, string(router_address.IntroducerExpirationString(0)))
		rv = append(rv, string(router_address.IntroducerTagString(0)))
		rv = append(rv, string(router_address.IntroducerHashString(1)))
		rv = append(rv, string(router_address.IntroducerExpirationString(1)))
		rv = append(rv, string(router_address.IntroducerTagString(1)))
		rv = append(rv, string(router_address.IntroducerHashString(2)))
		rv = append(rv, string(router_address.IntroducerExpirationString(2)))
		rv = append(rv, string(router_address.IntroducerTagString(2)))
	}
	return strings.TrimSpace(strings.Join(rv, " "))
}

var ex_addr net.Addr = &RouterAddress{}

// Bytes returns the router address as a []byte.
func (router_address RouterAddress) Bytes() []byte {
	bytes := make([]byte, 0)
	bytes = append(bytes, router_address.TransportCost.Bytes()...)
	bytes = append(bytes, router_address.ExpirationDate.Bytes()...)
	strData, err := router_address.TransportType.Data()
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("RouterAddress.Bytes: error getting transport_style bytes")
	} else {
		bytes = append(bytes, strData...)
	}
	bytes = append(bytes, router_address.TransportOptions.Data()...)
	return bytes
}

// Cost returns the cost for this RouterAddress as a Go integer.
func (router_address RouterAddress) Cost() int {
	return router_address.TransportCost.Int()
}

// Expiration returns the expiration for this RouterAddress as an I2P Date.
func (router_address RouterAddress) Expiration() Date {
	return *router_address.ExpirationDate
}

// TransportStyle returns the transport style for this RouterAddress as an I2PString.
func (router_address RouterAddress) TransportStyle() I2PString {
	return *router_address.TransportType
}

// GetOption returns the value of the option specified by the key
func (router_address RouterAddress) GetOption(key I2PString) I2PString {
	return router_address.Options().Values().Get(key)
}

func (router_address RouterAddress) HostString() I2PString {
	host, _ := ToI2PString("host")
	return router_address.GetOption(host)
}

func (router_address RouterAddress) PortString() I2PString {
	host, _ := ToI2PString("port")
	return router_address.GetOption(host)
}

func (router_address RouterAddress) StaticKeyString() I2PString {
	sk, _ := ToI2PString("s")
	return router_address.GetOption(sk)
}

func (router_address RouterAddress) InitializationVectorString() I2PString {
	iv, _ := ToI2PString("i")
	return router_address.GetOption(iv)
}

func (router_address RouterAddress) ProtocolVersionString() I2PString {
	v, _ := ToI2PString("v")
	return router_address.GetOption(v)
}

func (router_address RouterAddress) IntroducerHashString(num int) I2PString {
	if num >= 0 && num <= 2 {
		val := strconv.Itoa(num)
		v, _ := ToI2PString("ih" + val)
		return router_address.GetOption(v)
	}
	v, _ := ToI2PString("ih0")
	return router_address.GetOption(v)
}
func (router_address RouterAddress) IntroducerExpirationString(num int) I2PString {
	if num >= 0 && num <= 2 {
		val := strconv.Itoa(num)
		v, _ := ToI2PString("iexp" + val)
		return router_address.GetOption(v)
	}
	v, _ := ToI2PString("iexp0")
	return router_address.GetOption(v)
}
func (router_address RouterAddress) IntroducerTagString(num int) I2PString {
	if num >= 0 && num <= 2 {
		val := strconv.Itoa(num)
		v, _ := ToI2PString("itag" + val)
		return router_address.GetOption(v)
	}
	v, _ := ToI2PString("itag0")
	return router_address.GetOption(v)
}

func (router_address RouterAddress) Host() (net.Addr, error) {
	host := router_address.HostString()
	hostBytes, err := host.Data()
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(hostBytes)
	if ip == nil {
		return nil, fmt.Errorf("null host error")
	}
	return net.ResolveIPAddr("", ip.String())
}

func (router_address RouterAddress) Port() (string, error) {
	port := router_address.PortString()
	portBytes, err := port.Data()
	if err != nil {
		return "", err
	}
	val, err := strconv.Atoi(portBytes)
	if err != nil {
		return "", err
	}
	return strconv.Itoa(val), nil
}

func (router_address RouterAddress) StaticKey() ([32]byte, error) {
	sk := router_address.StaticKeyString()
	if len([]byte(sk)) != 32 {
		return [32]byte{}, fmt.Errorf("error: invalid static key")
	}
	return [32]byte(sk), nil

}

func (router_address RouterAddress) InitializationVector() ([32]byte, error) {
	iv := router_address.InitializationVectorString()
	if len([]byte(iv)) != 32 {
		return [32]byte{}, fmt.Errorf("error: invalid static key")
	}
	return [32]byte(iv), nil
}

func (router_address RouterAddress) ProtocolVersion() (string, error) {
	return router_address.ProtocolVersionString().Data()
}

// Options returns the options for this RouterAddress as an I2P Mapping.
func (router_address RouterAddress) Options() Mapping {
	return *router_address.TransportOptions
}

// Check if the RouterAddress is empty or if it is too small to contain valid data.
func (router_address RouterAddress) checkValid() (err error, exit bool) {
	return
}

// ReadRouterAddress returns RouterAddress from a []byte.
// The remaining bytes after the specified length are also returned.
// Returns a list of errors that occurred during parsing.
func ReadRouterAddress(data []byte) (router_address RouterAddress, remainder []byte, err error) {
	if len(data) == 0 {
		log.WithField("at", "(RouterAddress) ReadRouterAddress").Error("error parsing RouterAddress: no data")
		err = errors.New("error parsing RouterAddress: no data")
		return
	}
	router_address.TransportCost, remainder, err = NewInteger(data, 1)
	if err != nil {
		log.WithFields(log.Fields{
			"at":     "(RouterAddress) ReadNewRouterAddress",
			"reason": "error parsing cost",
		}).Warn("error parsing RouterAddress")
	}
	router_address.ExpirationDate, remainder, err = NewDate(remainder)
	if err != nil {
		log.WithFields(log.Fields{
			"at":     "(RouterAddress) ReadNewRouterAddress",
			"reason": "error parsing expiration",
		}).Error("error parsing RouterAddress")
	}
	router_address.TransportType, remainder, err = NewI2PString(remainder)
	if err != nil {
		log.WithFields(log.Fields{
			"at":     "(RouterAddress) ReadNewRouterAddress",
			"reason": "error parsing transport_style",
		}).Error("error parsing RouterAddress")
	}
	var errs []error
	router_address.TransportOptions, remainder, errs = NewMapping(remainder)
	for _, err := range errs {
		log.WithFields(log.Fields{
			"at":     "(RouterAddress) ReadNewRouterAddress",
			"reason": "error parsing options",
			"error":  err,
		}).Error("error parsing RozuterAddress")
	}
	return
}

// NewRouterAddress creates a new *RouterAddress from []byte using ReadRouterAddress.
// Returns a pointer to RouterAddress unlike ReadRouterAddress.
func NewRouterAddress(data []byte) (router_address *RouterAddress, remainder []byte, err error) {
	objrouteraddress, remainder, err := ReadRouterAddress(data)
	router_address = &objrouteraddress
	return
}
