package ntcp2

import (
	"fmt"
	"net"

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
	for _, addr := range routerInfo.RouterAddresses() {
		if !isNTCP2Transport(addr) {
			continue
		}

		ntcp2Addr, err := processNTCP2Address(addr, routerInfo)
		if err != nil {
			log.WithError(err).Warn("Failed to process NTCP2 address")
			continue
		}

		logSuccessfulExtraction(ntcp2Addr, hashBytes)
		return ntcp2Addr, nil
	}

	log.WithField("router_hash", fmt.Sprintf("%x", hashBytes[:8])).Error("No valid NTCP2 address found in RouterInfo")
	return nil, ErrInvalidRouterInfo
}

// processNTCP2Address resolves TCP address and wraps it with router hash.
func processNTCP2Address(addr *router_address.RouterAddress, routerInfo router_info.RouterInfo) (net.Addr, error) {
	log.Debug("Found NTCP2 transport address, resolving TCP address")
	tcpAddr, err := resolveTCPAddress(addr)
	if err != nil {
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
	return str == "ntcp2"
}

// resolveTCPAddress extracts host and port from a router address and resolves them to a TCP address.
// It returns an error if host or port extraction fails, or if TCP address resolution fails.
func resolveTCPAddress(addr *router_address.RouterAddress) (net.Addr, error) {
	host, err := addr.Host()
	if err != nil {
		return nil, err
	}

	port, err := addr.Port()
	if err != nil {
		return nil, err
	}

	return net.ResolveTCPAddr("tcp", net.JoinHostPort(host.String(), port))
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
		if str == "ntcp2" {
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
	return nil, ErrInvalidRouterInfo
}
