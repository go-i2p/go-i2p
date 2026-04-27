package ntcp2

import (
	"fmt"
	"net"
	"time"

	i2pbase64 "github.com/go-i2p/common/base64"
	"github.com/samber/oops"

	"github.com/go-i2p/common/router_address"
	i2pcurve25519 "github.com/go-i2p/crypto/curve25519"
	nattraversal "github.com/go-i2p/go-nat-listener"
	ntcp2noise "github.com/go-i2p/go-noise/ntcp2"
	"github.com/go-i2p/logger"
)

// logConversionStart logs the start of transport to RouterAddress conversion.
func logConversionStart() {
	log.WithFields(logger.Fields{
		"at":     "ConvertToRouterAddress",
		"reason": "converting_transport_to_router_address",
		"phase":  "startup",
		"step":   1,
	}).Debug("converting NTCP2Transport to RouterAddress")
}

// logNilTransportError logs an error when transport is nil.
func logNilTransportError() {
	log.WithFields(logger.Fields{
		"at":     "ConvertToRouterAddress",
		"reason": "nil_transport",
		"phase":  "startup",
	}).Error("cannot convert nil transport to RouterAddress")
}

// logAddressExtractionError logs an error during address extraction.
func logAddressExtractionError(err error) {
	log.WithFields(logger.Fields{
		"at":     "ConvertToRouterAddress",
		"reason": "address_extraction_failed",
		"phase":  "startup",
		"step":   2,
		"error":  err.Error(),
	}).Error("failed to extract transport address")
}

// logStaticKeyError logs an error during static key validation.
func logStaticKeyError(err error) {
	log.WithFields(logger.Fields{
		"at":     "ConvertToRouterAddress",
		"reason": "static_key_validation_failed",
		"phase":  "startup",
		"step":   3,
		"error":  err.Error(),
	}).Error("failed to validate and extract static key")
}

// logOptionsBuildError logs an error during router address options building.
func logOptionsBuildError(err error) {
	log.WithFields(logger.Fields{
		"at":     "ConvertToRouterAddress",
		"reason": "options_build_failed",
		"phase":  "startup",
		"step":   4,
		"error":  err.Error(),
	}).Error("failed to build router address options")
}

// logRouterAddressCreationError logs an error when creating RouterAddress fails.
func logRouterAddressCreationError(err error) {
	log.WithFields(logger.Fields{
		"at":     "ConvertToRouterAddress",
		"reason": "router_address_creation_failed",
		"phase":  "startup",
		"step":   5,
		"error":  err.Error(),
	}).Error("failed to create RouterAddress")
}

// logConversionSuccess logs successful conversion of transport to RouterAddress.
func logConversionSuccess(host, port string) {
	log.WithFields(logger.Fields{
		"at":     "ConvertToRouterAddress",
		"reason": "conversion_successful",
		"phase":  "startup",
		"host":   host,
		"port":   port,
	}).Info("successfully converted NTCP2Transport to RouterAddress")
}

// ConvertToRouterAddress converts an NTCP2Transport's listening address to a RouterAddress
// suitable for publishing in RouterInfo. This enables other routers to connect to this transport.
//
// The function extracts:
// - Host IP address from the transport's listener
// - Port number from the transport's listener
// - Static public key from the NTCP2 configuration
// - Initialization vector (IV) for AES obfuscation
//
// Returns a RouterAddress with transport style "NTCP2" and all required options,
// or an error if address extraction or conversion fails.
func ConvertToRouterAddress(transport *NTCP2Transport) (*router_address.RouterAddress, error) {
	logConversionStart()

	if transport == nil {
		logNilTransportError()
		return nil, oops.Errorf("transport cannot be nil")
	}

	host, port, err := extractTransportAddress(transport)
	if err != nil {
		logAddressExtractionError(err)
		return nil, err
	}

	staticKey, err := validateAndExtractStaticKey(transport)
	if err != nil {
		logStaticKeyError(err)
		return nil, err
	}

	options, err := buildRouterAddressOptions(host, port, staticKey, transport.config.NTCP2Config)
	if err != nil {
		logOptionsBuildError(err)
		return nil, err
	}

	routerAddress, err := router_address.NewRouterAddress(10, time.Time{}, router_address.NTCP2_TRANSPORT_STYLE, options)
	if err != nil {
		logRouterAddressCreationError(err)
		return nil, oops.Wrapf(err, "failed to create RouterAddress")
	}

	logConversionSuccess(host, port)
	return routerAddress, nil
}

// detectExternalIP returns the best routable local IP address to advertise when
// the listener is bound to an unspecified address (:: or 0.0.0.0). It prefers
// globally-routable IPv4 addresses, then any non-loopback non-link-local address.
// Returns "" if no suitable address is found.
func detectExternalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.WithError(err).Warn("detectExternalIP: failed to enumerate interface addresses")
		return ""
	}
	var fallback string
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil && ip.IsGlobalUnicast() {
			return ip4.String()
		}
		if fallback == "" {
			fallback = ip.String()
		}
	}
	return fallback
}

// extractTransportAddress extracts and validates the host and port from the transport's listening address.
// Returns the host IP string, port string, and any error encountered during extraction.
func extractTransportAddress(transport *NTCP2Transport) (string, string, error) {
	addr := transport.Addr()
	if addr == nil {
		log.WithFields(logger.Fields{"at": "extractTransportAddress"}).Error("Transport has no listening address")
		return "", "", oops.Errorf("transport has no listening address")
	}

	// Handle *ntcp2.NTCP2Addr (wrapped), *net.TCPAddr (direct), and *nattraversal.NATAddr
	var host, port string
	switch typedAddr := addr.(type) {
	case *ntcp2noise.NTCP2Addr:
		// Extract underlying address from NTCP2Addr wrapper
		underlying := typedAddr.UnderlyingAddr()
		var err error
		host, port, err = extractHostPort(underlying)
		if err != nil {
			log.Errorf("NTCP2Addr underlying address extraction failed: %v", err)
			return "", "", oops.Wrapf(err, "NTCP2Addr underlying address extraction failed")
		}
	case *net.TCPAddr:
		ip := typedAddr.IP
		if ip == nil || ip.IsUnspecified() {
			if ext := detectExternalIP(); ext != "" {
				host = ext
			} else {
				host = ip.String()
			}
		} else {
			host = ip.String()
		}
		port = fmt.Sprintf("%d", typedAddr.Port)
	case *nattraversal.NATAddr:
		var err error
		host, port, err = net.SplitHostPort(typedAddr.ExternalAddr())
		if err != nil {
			return "", "", oops.Wrapf(err, "failed to parse NATAddr external address %q", typedAddr.ExternalAddr())
		}
		if parsedIP := net.ParseIP(host); parsedIP != nil && parsedIP.IsUnspecified() {
			if ext := detectExternalIP(); ext != "" {
				host = ext
			}
		}
	default:
		log.Errorf("Expected *net.TCPAddr, *ntcp2.NTCP2Addr, or *nattraversal.NATAddr, got %T", addr)
		return "", "", oops.Errorf("unsupported address type %T", addr)
	}

	return host, port, nil
}

// extractHostPort extracts host and port from an address that may be *net.TCPAddr or *nattraversal.NATAddr.
func extractHostPort(addr net.Addr) (string, string, error) {
	switch a := addr.(type) {
	case *net.TCPAddr:
		ip := a.IP
		if ip == nil || ip.IsUnspecified() {
			if ext := detectExternalIP(); ext != "" {
				return ext, fmt.Sprintf("%d", a.Port), nil
			}
		}
		return a.IP.String(), fmt.Sprintf("%d", a.Port), nil
	case *nattraversal.NATAddr:
		host, port, err := net.SplitHostPort(a.ExternalAddr())
		if err != nil {
			return "", "", oops.Wrapf(err, "failed to parse NATAddr external address %q", a.ExternalAddr())
		}
		if parsedIP := net.ParseIP(host); parsedIP != nil && parsedIP.IsUnspecified() {
			if ext := detectExternalIP(); ext != "" {
				host = ext
			}
		}
		return host, port, nil
	default:
		return "", "", oops.Errorf("unsupported underlying address type %T", addr)
	}
}

// validateAndExtractStaticKey validates the NTCP2 configuration and extracts the base64-encoded
// static PUBLIC key for publication in RouterAddress.
//
// IMPORTANT: The NTCP2Config.StaticKey contains the X25519 PRIVATE key (used internally
// by the Noise handshake). The NTCP2 spec requires publishing the corresponding PUBLIC
// key as the 's=' parameter. This function derives the public key via X25519 scalar
// base multiplication before encoding.
//
// Returns the base64-encoded static public key string and any validation error encountered.
func validateAndExtractStaticKey(transport *NTCP2Transport) (string, error) {
	if transport.config == nil || transport.config.NTCP2Config == nil {
		log.WithFields(logger.Fields{"at": "validateAndExtractStaticKey"}).Error("Transport NTCP2 configuration is not initialized")
		return "", oops.Errorf("transport NTCP2 configuration is not initialized")
	}

	ntcp2Config := transport.config.NTCP2Config

	if len(ntcp2Config.StaticKey) != 32 {
		log.WithField("length", len(ntcp2Config.StaticKey)).Error("Invalid static key length")
		return "", oops.Errorf("invalid static key length: expected 32 bytes, got %d", len(ntcp2Config.StaticKey))
	}

	// Derive the X25519 public key from the private key.
	// StaticKey is the private key; the published 's=' must be the public key.
	privKey, err := i2pcurve25519.NewCurve25519PrivateKey(ntcp2Config.StaticKey)
	if err != nil {
		log.WithError(err).Error("Failed to create Curve25519 private key")
		return "", oops.Wrapf(err, "failed to create private key")
	}
	pubKey, err := privKey.Public()
	if err != nil {
		log.WithError(err).Error("Failed to derive public key from static private key")
		return "", oops.Wrapf(err, "failed to derive public key")
	}
	publicKey := pubKey.Bytes()

	staticKeyB64 := i2pbase64.I2PEncoding.EncodeToString(publicKey)
	return staticKeyB64, nil
}

// buildRouterAddressOptions constructs the options map for the RouterAddress with all required
// NTCP2 parameters including host, port, static key, and IV.
//
// Per I2P specification (https://geti2p.net/spec/ntcp2#published-addresses):
// - Static key 's': 32 bytes binary (X25519 public key), 44 bytes I2P base64-encoded
// - IV 'i': 16 bytes binary (big-endian), 24 bytes I2P base64-encoded
//
// Returns the options map and an error if validation fails.
func buildRouterAddressOptions(host, port, staticKey string, ntcp2Config *ntcp2noise.NTCP2Config) (map[string]string, error) {
	// Validate IV length (required per spec: 16 bytes binary -> 24 bytes Base64)
	if len(ntcp2Config.ObfuscationIV) != 16 {
		return nil, oops.Errorf("invalid IV length: expected 16 bytes, got %d", len(ntcp2Config.ObfuscationIV))
	}

	// Encode IV to I2P base64 (same alphabet as other I2P addresses: - and ~ instead of + and /)
	// Note: The ObfuscationIV is already in the correct byte order from go-noise library
	ivB64 := i2pbase64.I2PEncoding.EncodeToString(ntcp2Config.ObfuscationIV)

	options := map[string]string{
		"host": host,
		"port": port,
		"s":    staticKey, // Static key (already validated and Base64-encoded in validateAndExtractStaticKey)
		"i":    ivB64,     // IV for AES obfuscation (big-endian, Base64-encoded)
		"v":    "2",       // NTCP2 protocol version
	}

	return options, nil
}
