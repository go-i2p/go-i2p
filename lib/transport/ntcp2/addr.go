package ntcp2

import (
	"net"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-noise/ntcp2"
)

// Extract NTCP2 address from RouterInfo
func ExtractNTCP2Addr(routerInfo router_info.RouterInfo) (net.Addr, error) {
	if !SupportsNTCP2(&routerInfo) {
		return nil, ErrNTCP2NotSupported
	}
	for _, addr := range routerInfo.RouterAddresses() {
		style := addr.TransportStyle()
		str, err := style.Data()
		if err != nil {
			continue
		}
		if str == "ntcp2" {
			// Extract host and port from RouterAddress options
			host, err := addr.Host()
			if err != nil {
				continue
			}
			port, err := addr.Port()
			if err != nil {
				continue
			}

			// Create a proper TCP address
			tcpAddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(host.String(), port))
			if err != nil {
				continue
			}

			// Now wrap the TCP address with NTCP2 metadata
			hash := routerInfo.IdentHash().Bytes()
			return WrapNTCP2Addr(tcpAddr, hash[:])
		}
	}
	return nil, ErrInvalidRouterInfo
}

// Check if RouterInfo supports NTCP2
// TODO: This should be moved to router_info package
func SupportsNTCP2(routerInfo *router_info.RouterInfo) bool {
	if routerInfo == nil {
		return false
	}
	for _, addr := range routerInfo.RouterAddresses() {
		style := addr.TransportStyle()
		str, err := style.Data()
		if err != nil {
			continue
		}
		if str == "ntcp2" {
			return true
		}
	}
	return false
}

// Convert net.Addr to NTCP2Addr
func WrapNTCP2Addr(addr net.Addr, routerHash []byte) (*ntcp2.NTCP2Addr, error) {
	if ntcp2Addr, ok := addr.(*ntcp2.NTCP2Addr); ok {
		return ntcp2Addr, nil
	}
	return nil, ErrInvalidRouterInfo
}
