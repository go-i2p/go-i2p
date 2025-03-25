// Package router_address implements the I2P RouterAddress common data structure
package router_address

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
	"github.com/sirupsen/logrus"

	. "github.com/go-i2p/go-i2p/lib/common/data"
)

// Minimum number of bytes in a valid RouterAddress
const (
	ROUTER_ADDRESS_MIN_SIZE = 9
)

var log = logger.GetGoI2PLogger()

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
	TransportType    I2PString
	TransportOptions *Mapping
}

// Network implements net.Addr. It returns the transport type plus 4 or 6
func (router_address *RouterAddress) Network() string {
	log.Debug("Getting network for RouterAddress")
	if router_address.TransportType == nil {
		log.Warn("TransportType is nil in RouterAddress")
		return ""
	}
	str, err := router_address.TransportType.Data()
	if err != nil {
		log.WithError(err).Error("Failed to get TransportType data")
		return ""
	}
	network := string(str) + router_address.IPVersion()
	log.WithField("network", network).Debug("Retrieved network for RouterAddress")
	return network
}

// IPVersion returns a string "4" for IPv4 or 6 for IPv6
func (router_address *RouterAddress) IPVersion() string {
	log.Debug("Getting IP version for RouterAddress")
	str, err := router_address.CapsString().Data()
	if err != nil {
		log.WithError(err).Error("Failed to get CapsString data")
		return ""
	}
	if strings.HasSuffix(str, "6") {
		log.Debug("IP version is IPv6")
		return "6"
	}
	log.Debug("IP version is IPv4")
	return "4"
}

func (router_address *RouterAddress) UDP() bool {
	// return strings.HasPrefix(strings.ToLower(router_address.Network()), "ssu")
	log.Debug("Checking if RouterAddress is UDP")
	isUDP := strings.HasPrefix(strings.ToLower(router_address.Network()), "ssu")
	log.WithField("is_udp", isUDP).Debug("Checked if RouterAddress is UDP")
	return isUDP
}

// String implements net.Addr. It returns the IP address, followed by the options
func (router_address *RouterAddress) String() string {
	log.Debug("Converting RouterAddress to string")
	var rv []string
	rv = append(rv, string(router_address.TransportStyle()))
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
	str := strings.TrimSpace(strings.Join(rv, " "))
	log.WithField("router_address_string", str).Debug("Converted RouterAddress to string")
	return str
}

var ex_addr net.Addr = &RouterAddress{}

// Bytes returns the router address as a []byte.
func (router_address RouterAddress) Bytes() []byte {
	log.Debug("Converting RouterAddress to bytes")
	bytes := make([]byte, 0)
	bytes = append(bytes, router_address.TransportCost.Bytes()...)
	bytes = append(bytes, router_address.ExpirationDate.Bytes()...)
	bytes = append(bytes, router_address.TransportType...)
	bytes = append(bytes, router_address.TransportOptions.Data()...)
	log.WithField("bytes_length", len(bytes)).Debug("Converted RouterAddress to bytes")
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
	return router_address.TransportType
}

// GetOption returns the value of the option specified by the key
func (router_address RouterAddress) GetOption(key I2PString) I2PString {
	return router_address.Options().Values().Get(key)
}

func (router_address RouterAddress) HasOption(key I2PString) bool {
	opt := router_address.GetOption(key)
	return opt != nil
}

func (router_address RouterAddress) CheckOption(key string) bool {
	keyv, _ := ToI2PString(key)
	return router_address.HasOption(keyv)
}

func (router_address RouterAddress) HostString() I2PString {
	host, _ := ToI2PString("host")
	return router_address.GetOption(host)
}

func (router_address RouterAddress) PortString() I2PString {
	port, _ := ToI2PString("port")
	return router_address.GetOption(port)
}

func (router_address RouterAddress) CapsString() I2PString {
	caps, _ := ToI2PString("caps")
	return router_address.GetOption(caps)
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
	log.Debug("Getting host from RouterAddress")
	host := router_address.HostString()
	hostBytes, err := host.Data()
	if err != nil {
		log.WithError(err).Error("Failed to get host data")
		return nil, err
	}
	ip := net.ParseIP(hostBytes)
	if ip == nil {
		log.Error("Failed to parse IP address")
		return nil, oops.Errorf("null host error")
	}
	// return net.ResolveIPAddr("", ip.String())
	addr, err := net.ResolveIPAddr("", ip.String())
	if err != nil {
		log.WithError(err).Error("Failed to resolve IP address")
	} else {
		log.WithField("addr", addr).Debug("Retrieved host from RouterAddress")
	}
	return addr, err
}

func (router_address RouterAddress) Port() (string, error) {
	log.Debug("Getting port from RouterAddress")
	port := router_address.PortString()
	portBytes, err := port.Data()
	if err != nil {
		log.WithError(err).Error("Failed to get port data")
		return "", err
	}
	val, err := strconv.Atoi(portBytes)
	if err != nil {
		log.WithError(err).Error("Failed to convert port to integer")
		return "", err
	}
	// return strconv.Itoa(val), nil
	portStr := strconv.Itoa(val)
	log.WithField("port", portStr).Debug("Retrieved port from RouterAddress")
	return portStr, nil
}

func (routerAddress RouterAddress) StaticKey() ([32]byte, error) {
	sk := routerAddress.StaticKeyString()
	if sk == nil {
		return [32]byte{}, oops.Errorf("error: static key not found")
	}

	skBytes := []byte(sk)
	if len(skBytes) != 32 {
		return [32]byte{}, oops.Errorf("error: invalid static key length: %d, expected 32", len(skBytes))
	}

	var result [32]byte
	copy(result[:], skBytes)
	return result, nil
}

func (router_address RouterAddress) InitializationVector() ([16]byte, error) {
	iv := router_address.InitializationVectorString()
	if len([]byte(iv)) != 16 {
		return [16]byte{}, oops.Errorf("error: invalid IV")
	}
	return [16]byte(iv), nil
}

func (router_address RouterAddress) ProtocolVersion() (string, error) {
	return router_address.ProtocolVersionString().Data()
}

// Options returns the options for this RouterAddress as an I2P Mapping.
func (routerAddress RouterAddress) Options() Mapping {
	if routerAddress.TransportOptions == nil {
		log.Warn("TransportOptions is nil in RouterAddress")
		return Mapping{}
	}
	return *routerAddress.TransportOptions
}

// Check if the RouterAddress is empty or if it is too small to contain valid data.
func (routerAddress RouterAddress) checkValid() (err error, exit bool) {
	if routerAddress.TransportType == nil {
		return oops.Errorf("invalid router address: nil transport type"), true
	}
	if routerAddress.TransportOptions == nil {
		return oops.Errorf("invalid router address: nil transport options"), true
	}
	return nil, false
}

// ReadRouterAddress returns RouterAddress from a []byte.
// The remaining bytes after the specified length are also returned.
// Returns a list of errors that occurred during parsing.
func ReadRouterAddress(data []byte) (router_address RouterAddress, remainder []byte, err error) {
	log.WithField("data_length", len(data)).Debug("Reading RouterAddress from data")
	if len(data) == 0 {
		log.WithField("at", "(RouterAddress) ReadRouterAddress").Error("error parsing RouterAddress: no data")
		err = oops.Errorf("error parsing RouterAddress: no data")
		return
	}
	router_address.TransportCost, remainder, err = NewInteger(data, 1)
	if err != nil {
		log.WithFields(logrus.Fields{
			"at":     "(RouterAddress) ReadNewRouterAddress",
			"reason": "error parsing cost",
		}).Warn("error parsing RouterAddress")
	}
	router_address.ExpirationDate, remainder, err = NewDate(remainder)
	if err != nil {
		log.WithFields(logrus.Fields{
			"at":     "(RouterAddress) ReadNewRouterAddress",
			"reason": "error parsing expiration",
		}).Error("error parsing RouterAddress")
	}
	router_address.TransportType, remainder, err = ReadI2PString(remainder)
	if err != nil {
		log.WithFields(logrus.Fields{
			"at":     "(RouterAddress) ReadNewRouterAddress",
			"reason": "error parsing transport_style",
		}).Error("error parsing RouterAddress")
	}
	var errs []error
	router_address.TransportOptions, remainder, errs = NewMapping(remainder)
	for _, err := range errs {
		log.WithFields(logrus.Fields{
			"at":     "(RouterAddress) ReadNewRouterAddress",
			"reason": "error parsing options",
			"error":  err,
		}).Error("error parsing RozuterAddress")
	}
	return
}

// NewRouterAddress creates a new RouterAddress with the provided parameters.
// Returns a pointer to RouterAddress.
func NewRouterAddress(cost uint8, expiration time.Time, transportType string, options map[string]string) (*RouterAddress, error) {
	log.Debug("Creating new RouterAddress")

	// Create TransportCost as an Integer (1 byte)
	transportCost, err := NewIntegerFromInt(int(cost), 1)
	if err != nil {
		log.WithError(err).Error("Failed to create TransportCost Integer")
		return nil, err
	}

	// Create ExpirationDate as a Date
	millis := expiration.UnixNano() / int64(time.Millisecond)
	dateBytes := make([]byte, DATE_SIZE)
	binary.BigEndian.PutUint64(dateBytes, uint64(millis))
	expirationDate, _, err := NewDate(dateBytes)
	if err != nil {
		log.WithError(err).Error("Failed to create ExpirationDate")
		return nil, err
	}

	// Create TransportType as an I2PString
	transportTypeStr, err := ToI2PString(transportType)
	if err != nil {
		log.WithError(err).Error("Failed to create TransportType I2PString")
		return nil, err
	}

	// Create TransportOptions as a Mapping
	transportOptions, err := GoMapToMapping(options)
	if err != nil {
		log.WithError(err).Error("Failed to create TransportOptions Mapping")
		return nil, err
	}

	// Create RouterAddress
	ra := &RouterAddress{
		TransportCost:    transportCost,
		ExpirationDate:   expirationDate,
		TransportType:    transportTypeStr,
		TransportOptions: transportOptions,
	}

	log.WithFields(logrus.Fields{
		"cost":          cost,
		"expiration":    expiration,
		"transportType": transportType,
		"options":       options,
	}).Debug("Successfully created new RouterAddress")

	return ra, nil
}
