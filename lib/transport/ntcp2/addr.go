package ntcp2

import (
	"net"

	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-noise/ntcp2"
)

// ExtractNTCP2Addr extracts the NTCP2 network address from a RouterInfo structure.
// It validates NTCP2 support and returns a properly wrapped NTCP2 address with router hash metadata.
func ExtractNTCP2Addr(routerInfo router_info.RouterInfo) (net.Addr, error) {
	if !SupportsNTCP2(&routerInfo) {
		return nil, ErrNTCP2NotSupported
	}

	for _, addr := range routerInfo.RouterAddresses() {
		if !isNTCP2Transport(addr) {
			continue
		}

		tcpAddr, err := resolveTCPAddress(addr)
		if err != nil {
			continue
		}

		hash := routerInfo.IdentHash().Bytes()
		return WrapNTCP2Addr(tcpAddr, hash[:])
	}

	return nil, ErrInvalidRouterInfo
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
