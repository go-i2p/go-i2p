package ntcp2

import (
	"encoding/base64"
	"fmt"
	"net"
	"time"

	"github.com/go-i2p/common/router_address"
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
// Returns a RouterAddress with transport style "ntcp2" and all required options,
// or an error if address extraction or conversion fails.
func ConvertToRouterAddress(transport *NTCP2Transport) (*router_address.RouterAddress, error) {
	logConversionStart()

	if transport == nil {
		logNilTransportError()
		return nil, fmt.Errorf("transport cannot be nil")
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

	expiration := time.Now().Add(2 * time.Hour)
	routerAddress, err := router_address.NewRouterAddress(10, expiration, "ntcp2", options)
	if err != nil {
		logRouterAddressCreationError(err)
		return nil, fmt.Errorf("failed to create RouterAddress: %w", err)
	}

	logConversionSuccess(host, port)
	return routerAddress, nil
}

// extractTransportAddress extracts and validates the host and port from the transport's listening address.
// Returns the host IP string, port string, and any error encountered during extraction.
func extractTransportAddress(transport *NTCP2Transport) (string, string, error) {
	addr := transport.Addr()
	if addr == nil {
		log.Error("Transport has no listening address")
		return "", "", fmt.Errorf("transport has no listening address")
	}

	// Handle both *ntcp2.NTCP2Addr (wrapped) and *net.TCPAddr (direct)
	var tcpAddr *net.TCPAddr
	if ntcpAddr, ok := addr.(*ntcp2noise.NTCP2Addr); ok {
		// Extract underlying TCP address from NTCP2Addr wrapper
		underlying := ntcpAddr.UnderlyingAddr()
		var ok2 bool
		tcpAddr, ok2 = underlying.(*net.TCPAddr)
		if !ok2 {
			log.Errorf("NTCP2Addr underlying address is not *net.TCPAddr, got %T", underlying)
			return "", "", fmt.Errorf("NTCP2Addr underlying address is not *net.TCPAddr, got %T", underlying)
		}
	} else if directTCP, ok := addr.(*net.TCPAddr); ok {
		tcpAddr = directTCP
	} else {
		log.Errorf("Expected *net.TCPAddr or *ntcp2.NTCP2Addr, got %T", addr)
		return "", "", fmt.Errorf("expected *net.TCPAddr or *ntcp2.NTCP2Addr, got %T", addr)
	}

	host := tcpAddr.IP.String()
	port := fmt.Sprintf("%d", tcpAddr.Port)

	return host, port, nil
}

// validateAndExtractStaticKey validates the NTCP2 configuration and extracts the base64-encoded static key.
// Returns the base64-encoded static key string and any validation error encountered.
func validateAndExtractStaticKey(transport *NTCP2Transport) (string, error) {
	if transport.config == nil || transport.config.NTCP2Config == nil {
		log.Error("Transport NTCP2 configuration is not initialized")
		return "", fmt.Errorf("transport NTCP2 configuration is not initialized")
	}

	ntcp2Config := transport.config.NTCP2Config

	if len(ntcp2Config.StaticKey) != 32 {
		log.WithField("length", len(ntcp2Config.StaticKey)).Error("Invalid static key length")
		return "", fmt.Errorf("invalid static key length: expected 32 bytes, got %d", len(ntcp2Config.StaticKey))
	}

	staticKey := base64.StdEncoding.EncodeToString(ntcp2Config.StaticKey)
	return staticKey, nil
}

// buildRouterAddressOptions constructs the options map for the RouterAddress with all required
// NTCP2 parameters including host, port, static key, and IV.
//
// Per I2P specification (https://geti2p.net/spec/ntcp2#published-addresses):
// - Static key 's': 32 bytes binary (little-endian X25519), 44 bytes Base64-encoded
// - IV 'i': 16 bytes binary (big-endian), 24 bytes Base64-encoded
//
// Returns the options map and an error if validation fails.
func buildRouterAddressOptions(host, port, staticKey string, ntcp2Config *ntcp2noise.NTCP2Config) (map[string]string, error) {
	// Validate IV length (required per spec: 16 bytes binary -> 24 bytes Base64)
	if len(ntcp2Config.ObfuscationIV) != 16 {
		return nil, fmt.Errorf("invalid IV length: expected 16 bytes, got %d", len(ntcp2Config.ObfuscationIV))
	}

	// Encode IV to Base64 (big-endian per spec)
	// Note: The ObfuscationIV is already in the correct byte order from go-noise library
	ivB64 := base64.StdEncoding.EncodeToString(ntcp2Config.ObfuscationIV)

	options := map[string]string{
		"host": host,
		"port": port,
		"s":    staticKey, // Static key (already validated and Base64-encoded in validateAndExtractStaticKey)
		"i":    ivB64,     // IV for AES obfuscation (big-endian, Base64-encoded)
		"v":    "2",       // NTCP2 protocol version
	}

	return options, nil
}
