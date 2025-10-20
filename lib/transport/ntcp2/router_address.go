package ntcp2

import (
	"encoding/base64"
	"fmt"
	"net"
	"time"

	"github.com/go-i2p/common/router_address"
	ntcp2noise "github.com/go-i2p/go-noise/ntcp2"
)

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
	if transport == nil {
		return nil, fmt.Errorf("transport cannot be nil")
	}

	host, port, err := extractTransportAddress(transport)
	if err != nil {
		return nil, err
	}

	staticKey, err := validateAndExtractStaticKey(transport)
	if err != nil {
		return nil, err
	}

	options, err := buildRouterAddressOptions(host, port, staticKey, transport.config.NTCP2Config)
	if err != nil {
		return nil, err
	}

	expiration := time.Now().Add(2 * time.Hour)
	routerAddress, err := router_address.NewRouterAddress(
		10, // cost
		expiration,
		"ntcp2", // transport type
		options,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create RouterAddress: %w", err)
	}

	return routerAddress, nil
}

// extractTransportAddress extracts and validates the host and port from the transport's listening address.
// Returns the host IP string, port string, and any error encountered during extraction.
func extractTransportAddress(transport *NTCP2Transport) (string, string, error) {
	addr := transport.Addr()
	if addr == nil {
		return "", "", fmt.Errorf("transport has no listening address")
	}

	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		return "", "", fmt.Errorf("expected *net.TCPAddr, got %T", addr)
	}

	host := tcpAddr.IP.String()
	port := fmt.Sprintf("%d", tcpAddr.Port)

	return host, port, nil
}

// validateAndExtractStaticKey validates the NTCP2 configuration and extracts the base64-encoded static key.
// Returns the base64-encoded static key string and any validation error encountered.
func validateAndExtractStaticKey(transport *NTCP2Transport) (string, error) {
	if transport.config == nil || transport.config.NTCP2Config == nil {
		return "", fmt.Errorf("transport NTCP2 configuration is not initialized")
	}

	ntcp2Config := transport.config.NTCP2Config

	if len(ntcp2Config.StaticKey) != 32 {
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
