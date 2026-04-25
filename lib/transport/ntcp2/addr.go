package ntcp2

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-noise/ntcp2"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// ipv6Once ensures the IPv6 connectivity probe runs exactly once per process.
var (
	ipv6Once       sync.Once
	hasIPv6Support bool
)

// hasGlobalUnicastIPv6OnIface returns true if the given network interface has
// at least one globally reachable IPv6 address.
func hasGlobalUnicastIPv6OnIface(iface net.Interface) bool {
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip != nil && ip.To4() == nil && ip.IsGlobalUnicast() {
			return true
		}
	}
	return false
}

// probeIPv6 returns true if the host has at least one non-loopback, globally
// unicast IPv6 interface. The result is cached after the first call.
func probeIPv6() bool {
	ipv6Once.Do(func() {
		ifaces, err := net.Interfaces()
		if err != nil {
			return
		}
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			if hasGlobalUnicastIPv6OnIface(iface) {
				hasIPv6Support = true
				return
			}
		}
	})
	return hasIPv6Support
}

// isIPv4RouterAddress returns true if a RouterAddress host is a plain IPv4 address.
func isIPv4RouterAddress(addr *router_address.RouterAddress) bool {
	host, err := addr.Host()
	if err != nil {
		return false
	}
	ip := net.ParseIP(host.String())
	return ip != nil && ip.To4() != nil
}

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
		return nil, oops.Wrapf(err, "failed to get router hash")
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

	// Two-pass: prefer IPv4 NTCP2 addresses; fall back to IPv6 only when
	// IPv6 connectivity is available (AUDIT P4 + P1/RC-3).
	var ipv6Fallback net.Addr
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

		if isIPv4RouterAddress(addr) {
			// IPv4 – return immediately (preferred path).
			logSuccessfulExtraction(ntcp2Addr, hashBytes)
			return ntcp2Addr, nil
		}
		// IPv6 – keep as fallback, continue looking for IPv4.
		if ipv6Fallback == nil {
			ipv6Fallback = ntcp2Addr
		}
	}

	if ipv6Fallback != nil {
		logSuccessfulExtraction(ipv6Fallback, hashBytes)
		return ipv6Fallback, nil
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
// Returns an error for IPv6 addresses when the local host has no IPv6
// connectivity (AUDIT P1/RC-3), causing callers to skip to the next address.
func processNTCP2Address(addr *router_address.RouterAddress, routerInfo router_info.RouterInfo) (net.Addr, error) {
	log.WithFields(logger.Fields{"at": "processNTCP2Address"}).Debug("Found NTCP2 transport address, resolving TCP address")
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
		return nil, oops.Wrapf(err, "failed to resolve TCP address")
	}

	// Skip IPv6 peer addresses when the local host has no IPv6 connectivity.
	if concrete, ok := tcpAddr.(*net.TCPAddr); ok {
		if concrete.IP.To4() == nil && !probeIPv6() {
			log.WithFields(map[string]interface{}{
				"at":      "processNTCP2Address",
				"address": tcpAddr.String(),
			}).Debug("Skipping IPv6 NTCP2 address: no local IPv6 connectivity")
			return nil, oops.Errorf("skip IPv6 address %s: no local IPv6 connectivity", tcpAddr)
		}
	}

	hashVal, err := routerInfo.IdentHash()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to get router hash for wrapping")
	}

	return WrapNTCP2Addr(tcpAddr, hashVal)
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
	log.WithFields(logger.Fields{"at": "resolveTCPAddress"}).Debug("Getting host from RouterAddress")
	host, err := addr.Host()
	if err != nil {
		// Missing host key is normal for introducer-based addresses (NAT traversal).
		log.WithFields(logger.Fields{"at": "resolveTCPAddress"}).Debug("Cannot extract host from RouterAddress (introducer-only address)")
		return nil, oops.Wrapf(err, "failed to extract host (introducer-based address)")
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
		return nil, oops.Wrapf(err, "failed to extract port")
	}

	hostPort := net.JoinHostPort(host.String(), port)
	tcpAddr, err := net.ResolveTCPAddr("tcp", hostPort)
	if err != nil {
		log.WithFields(map[string]interface{}{
			"host": host.String(),
			"port": port,
		}).WithError(err).Debug("Failed to resolve TCP address")
		return nil, oops.Wrapf(err, "failed to resolve TCP address %s", hostPort)
	}

	return tcpAddr, nil
}

// HasDirectConnectivity checks if a RouterAddress has direct NTCP2 connectivity.
// Returns true if the address has both host and port keys (directly dialable).
// Returns false if the address is introducer-only (requires NAT traversal).
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
	host, err := addr.Host()
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
// dialable NTCP2 address (i.e., an NTCP2 address with both host and port).
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

// SupportsNTCP2 checks if RouterInfo has an NTCP2 transport address.
func SupportsNTCP2(routerInfo *router_info.RouterInfo) bool {
	if routerInfo == nil {
		log.WithFields(logger.Fields{"at": "SupportsNTCP2"}).Debug("RouterInfo is nil, NTCP2 not supported")
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
			log.WithFields(logger.Fields{"at": "SupportsNTCP2"}).Debug("RouterInfo supports NTCP2")
			return true
		}
	}
	log.WithFields(logger.Fields{"at": "SupportsNTCP2"}).Debug("RouterInfo does not support NTCP2")
	return false
}

// Convert net.Addr to NTCP2Addr
func WrapNTCP2Addr(addr net.Addr, routerHash data.Hash) (*ntcp2.NTCP2Addr, error) {
	if ntcp2Addr, ok := addr.(*ntcp2.NTCP2Addr); ok {
		return ntcp2Addr, nil
	}
	// Create new NTCP2Addr from TCP address
	return ntcp2.NewNTCP2Addr(addr, routerHash, "initiator")
}

// SupportsDirectNTCP2 checks if a RouterInfo has at least one directly dialable NTCP2 address.
// Convenience function for peer selection; filters out introducer-only routers.
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
