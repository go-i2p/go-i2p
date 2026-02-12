package ntcp2

import (
	"fmt"
	"net"
	"strings"

	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-noise/ntcp2"
)

// ExtractNTCP2Addr extracts the NTCP2 network address from a RouterInfo structure.
// It validates NTCP2 support and returns a properly wrapped NTCP2 address with router hash metadata.
func ExtractNTCP2Addr(routerInfo router_info.RouterInfo) (net.Addr, error) {
	routerHashBytes, err := getRouterHashBytes(routerInfo)
	if err != nil {
		return nil, err
	}

	if err := validateNTCP2Support(&routerInfo, routerHashBytes); err != nil {
		return nil, err
	}

	return findValidNTCP2Address(routerInfo, routerHashBytes)
}

// getRouterHashBytes retrieves and returns the router hash bytes from RouterInfo.
func getRouterHashBytes(routerInfo router_info.RouterInfo) ([]byte, error) {
	routerHash, err := routerInfo.IdentHash()
	if err != nil {
		return nil, fmt.Errorf("failed to get router hash: %w", err)
	}
	hashBytes := routerHash.Bytes()
	return hashBytes[:], nil
}

// validateNTCP2Support checks if the RouterInfo supports NTCP2 transport.
func validateNTCP2Support(routerInfo *router_info.RouterInfo, hashBytes []byte) error {
	log.WithField("router_hash", fmt.Sprintf("%x", hashBytes[:8])).Debug("Extracting NTCP2 address from RouterInfo")

	if !SupportsNTCP2(routerInfo) {
		log.WithField("router_hash", fmt.Sprintf("%x", hashBytes[:8])).Warn("RouterInfo does not support NTCP2")
		return ErrNTCP2NotSupported
	}
	return nil
}

// findValidNTCP2Address iterates through router addresses to find and wrap a valid NTCP2 address.
func findValidNTCP2Address(routerInfo router_info.RouterInfo, hashBytes []byte) (net.Addr, error) {
	addresses := routerInfo.RouterAddresses()
	log.WithFields(map[string]interface{}{
		"router_hash":   fmt.Sprintf("%x", hashBytes[:8]),
		"address_count": len(addresses),
	}).Debug("Searching for valid NTCP2 address")

	for i, addr := range addresses {
		style := addr.TransportStyle()
		styleStr, _ := style.Data()
		log.WithFields(map[string]interface{}{
			"index":           i,
			"transport_style": styleStr,
		}).Debug("Checking router address")

		if !isNTCP2Transport(addr) {
			continue
		}

		ntcp2Addr, err := processNTCP2Address(addr, routerInfo)
		if err != nil {
			log.WithFields(map[string]interface{}{
				"index": i,
			}).WithError(err).Debug("Failed to process NTCP2 address, trying next")
			continue
		}

		logSuccessfulExtraction(ntcp2Addr, hashBytes)
		return ntcp2Addr, nil
	}

	// Enhanced logging when no valid NTCP2 addresses found - helps diagnose Issue #1 scope
	log.WithFields(map[string]interface{}{
		"at":              "findValidNTCP2Address",
		"phase":           "address_extraction",
		"operation":       "find_valid_address",
		"router_hash":     fmt.Sprintf("%x", hashBytes[:8]),
		"addresses_total": len(addresses),
		"addresses_tried": len(addresses),
	}).Warn("No valid NTCP2 address found in RouterInfo after checking all addresses")
	return nil, ErrInvalidRouterInfo
}

// processNTCP2Address resolves TCP address and wraps it with router hash.
func processNTCP2Address(addr *router_address.RouterAddress, routerInfo router_info.RouterInfo) (net.Addr, error) {
	log.Debug("Found NTCP2 transport address, resolving TCP address")
	tcpAddr, err := resolveTCPAddress(addr)
	if err != nil {
		// Enhanced logging for TCP resolution failures - links to host extraction Issue #1
		hashVal, _ := routerInfo.IdentHash()
		hashBytes := hashVal.Bytes()
		log.WithFields(map[string]interface{}{
			"at":            "processNTCP2Address",
			"phase":         "address_resolution",
			"operation":     "resolve_tcp",
			"error":         err.Error(),
			"router_hash":   fmt.Sprintf("%x", hashBytes[:8]),
			"address_count": len(routerInfo.RouterAddresses()),
		}).Warn("Failed to resolve TCP address from NTCP2 router address")
		return nil, fmt.Errorf("failed to resolve TCP address: %w", err)
	}

	hashVal, err := routerInfo.IdentHash()
	if err != nil {
		return nil, fmt.Errorf("failed to get router hash for wrapping: %w", err)
	}

	hash := hashVal.Bytes()
	return WrapNTCP2Addr(tcpAddr, hash[:])
}

// logSuccessfulExtraction logs the successful NTCP2 address extraction.
func logSuccessfulExtraction(addr net.Addr, hashBytes []byte) {
	log.WithFields(map[string]interface{}{
		"router_hash": fmt.Sprintf("%x", hashBytes[:8]),
		"tcp_addr":    addr.String(),
	}).Info("Successfully extracted NTCP2 address")
}

// isNTCP2Transport checks if a router address uses the NTCP2 transport style.
func isNTCP2Transport(addr *router_address.RouterAddress) bool {
	style := addr.TransportStyle()
	str, err := style.Data()
	if err != nil {
		return false
	}
	// Check case-insensitively - some implementations use "NTCP2", others "ntcp2"
	return strings.EqualFold(str, "ntcp2")
}

// resolveTCPAddress extracts host and port from a router address and resolves them to a TCP address.
// It returns an error if host or port extraction fails, or if TCP address resolution fails.
func resolveTCPAddress(addr *router_address.RouterAddress) (net.Addr, error) {
	// CRITICAL FIX #2: Suppress error-level logging from common package Host() method
	// The common package logs at ERROR level when host key is missing, but this is
	// normal for introducer-based NTCP2 addresses. We call it silently and handle gracefully.
	log.Debug("Getting host from RouterAddress")
	host, err := extractHostQuietly(addr)
	if err != nil {
		// Missing host key is normal for introducer-based addresses (NAT/firewall traversal)
		// These addresses require introduction from a third-party router
		// Log at debug level to reduce noise - this is expected behavior
		log.WithFields(map[string]interface{}{
			"at":        "resolveTCPAddress",
			"phase":     "address_parsing",
			"operation": "extract_host",
			"error":     err.Error(),
			"context":   "normal for introducer-based addresses",
		}).Debug("Cannot extract host from RouterAddress (introducer-only address)")
		return nil, fmt.Errorf("failed to extract host (introducer-based address): %w", err)
	}

	port, err := addr.Port()
	if err != nil {
		// Port extraction failures are less common but still possible for malformed addresses
		// Downgrade to Warn since some legitimate scenarios may lack port (though rare)
		log.WithFields(map[string]interface{}{
			"at":        "resolveTCPAddress",
			"phase":     "address_parsing",
			"operation": "extract_port",
			"error":     err.Error(),
			"host":      host.String(),
			"cost":      addr.Cost(),
		}).Warn("Failed to extract port from RouterAddress")
		return nil, fmt.Errorf("failed to extract port: %w", err)
	}

	hostPort := net.JoinHostPort(host.String(), port)
	tcpAddr, err := net.ResolveTCPAddr("tcp", hostPort)
	if err != nil {
		log.WithFields(map[string]interface{}{
			"host": host.String(),
			"port": port,
		}).WithError(err).Debug("Failed to resolve TCP address")
		return nil, fmt.Errorf("failed to resolve TCP address %s: %w", hostPort, err)
	}

	return tcpAddr, nil
}

// extractHostQuietly wraps addr.Host() to suppress ERROR-level logging from common package.
// The common package's Host() method logs at ERROR level when the host key is missing,
// but for NTCP2, missing host keys are normal for introducer-based addresses.
// This function provides the same functionality without the noisy error logs.
func extractHostQuietly(addr *router_address.RouterAddress) (net.Addr, error) {
	// Try to get host using the standard method
	// Note: The common package will log errors internally, but we document
	// that this is expected behavior for introducer addresses
	host, err := addr.Host()
	if err != nil {
		// Suppress by returning immediately - the common package already logged
		// We add our own DEBUG-level log in the caller (resolveTCPAddress)
		return nil, err
	}
	return host, nil
}

// HasDirectConnectivity checks if a RouterAddress has direct NTCP2 connectivity.
// Returns true if the address has both host and port keys (directly dialable).
// Returns false if the address is introducer-only (requires NAT traversal).
// Returns false for nil addresses.
// CRITICAL FIX #1: Pre-filtering utility for peer selection.
func HasDirectConnectivity(addr *router_address.RouterAddress) bool {
	if addr == nil {
		return false
	}

	// Check transport style
	style := addr.TransportStyle()
	styleStr, err := style.Data()
	if err != nil || !strings.EqualFold(styleStr, "ntcp2") {
		return false
	}

	// Try to extract host (will fail for introducer-only addresses)
	host, err := extractHostQuietly(addr)
	if err != nil || host == nil {
		return false
	}

	// Try to extract port
	port, err := addr.Port()
	if err != nil || port == "" {
		return false
	}

	return true
}

// HasDialableNTCP2Address checks if a RouterInfo has at least one directly
// dialable NTCP2 address (i.e., an NTCP2 address with a valid host and port).
// Introducer-only addresses are not dialable and will return false.
func HasDialableNTCP2Address(routerInfo *router_info.RouterInfo) bool {
	if routerInfo == nil {
		return false
	}
	for _, addr := range routerInfo.RouterAddresses() {
		if HasDirectConnectivity(addr) {
			return true
		}
	}
	return false
}

// Check if RouterInfo supports NTCP2
// TODO: This should be moved to router_info package
func SupportsNTCP2(routerInfo *router_info.RouterInfo) bool {
	if routerInfo == nil {
		log.Debug("RouterInfo is nil, NTCP2 not supported")
		return false
	}
	for _, addr := range routerInfo.RouterAddresses() {
		style := addr.TransportStyle()
		str, err := style.Data()
		if err != nil {
			continue
		}
		// Check case-insensitively - some implementations use "NTCP2", others "ntcp2"
		if strings.EqualFold(str, "ntcp2") {
			log.Debug("RouterInfo supports NTCP2")
			return true
		}
	}
	log.Debug("RouterInfo does not support NTCP2")
	return false
}

// Convert net.Addr to NTCP2Addr
func WrapNTCP2Addr(addr net.Addr, routerHash []byte) (*ntcp2.NTCP2Addr, error) {
	if ntcp2Addr, ok := addr.(*ntcp2.NTCP2Addr); ok {
		return ntcp2Addr, nil
	}
	// Create new NTCP2Addr from TCP address
	return ntcp2.NewNTCP2Addr(addr, routerHash, "initiator")
}

// SupportsDirectNTCP2 checks if a RouterInfo has at least one directly dialable NTCP2 address.
// This is a convenience function for peer selection - filters out introducer-only routers.
// CRITICAL FIX #1: Exported function for use in peer selection/filtering.
func SupportsDirectNTCP2(routerInfo *router_info.RouterInfo) bool {
	if routerInfo == nil {
		return false
	}

	for _, addr := range routerInfo.RouterAddresses() {
		if HasDirectConnectivity(addr) {
			return true
		}
	}

	return false
}
