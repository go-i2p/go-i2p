package ntcp2

import (
	"encoding/base64"
	"fmt"
	"net"
	"time"

	"github.com/go-i2p/common/router_address"
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

	// Get the listening address from transport
	addr := transport.Addr()
	if addr == nil {
		return nil, fmt.Errorf("transport has no listening address")
	}

	// Extract host and port from TCP address
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("expected *net.TCPAddr, got %T", addr)
	}

	host := tcpAddr.IP.String()
	port := fmt.Sprintf("%d", tcpAddr.Port)

	// Get NTCP2 configuration for static key and IV
	if transport.config == nil || transport.config.NTCP2Config == nil {
		return nil, fmt.Errorf("transport NTCP2 configuration is not initialized")
	}

	ntcp2Config := transport.config.NTCP2Config

	// Extract static key (required for NTCP2)
	if len(ntcp2Config.StaticKey) != 32 {
		return nil, fmt.Errorf("invalid static key length: expected 32 bytes, got %d", len(ntcp2Config.StaticKey))
	}
	staticKey := base64.StdEncoding.EncodeToString(ntcp2Config.StaticKey)

	// Build options map for RouterAddress
	options := map[string]string{
		"host": host,
		"port": port,
		"s":    staticKey, // 's' is the standard key for static key in I2P RouterAddress
		"v":    "2",       // NTCP2 protocol version
	}

	// Add initialization vector if configured (optional but recommended)
	if len(ntcp2Config.ObfuscationIV) == 16 {
		iv := base64.StdEncoding.EncodeToString(ntcp2Config.ObfuscationIV)
		options["i"] = iv // 'i' is the standard key for IV in I2P RouterAddress
	}

	// Create RouterAddress with standard parameters
	// Cost: 10 (arbitrary default, can be adjusted based on network conditions)
	// Expiration: 2 hours from now (standard I2P practice)
	// Transport: "ntcp2"
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
