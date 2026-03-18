package ssu2

import (
	"fmt"
	"net"

	"github.com/go-i2p/common/router_info"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
)

// ExtractSSU2NoiseAddr extracts an SSU2 noise-level address from a RouterInfo.
// It returns a *ssu2noise.SSU2Addr suitable for use with the go-noise/ssu2 package.
func ExtractSSU2NoiseAddr(routerInfo router_info.RouterInfo) (*ssu2noise.SSU2Addr, error) {
	routerHash, err := routerInfo.IdentHash()
	if err != nil {
		return nil, fmt.Errorf("failed to get router hash: %w", err)
	}

	udpAddr, err := ExtractSSU2Addr(routerInfo)
	if err != nil {
		return nil, err
	}

	connID, err := ssu2noise.GenerateConnectionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate connection ID: %w", err)
	}

	hashBytes := routerHash.Bytes()
	ssu2Addr, err := ssu2noise.NewSSU2Addr(udpAddr, hashBytes[:], connID, "initiator")
	if err != nil {
		return nil, WrapSSU2Error(err, "creating SSU2 address")
	}

	return ssu2Addr, nil
}

// WrapSSU2Addr wraps an existing net.Addr as an SSU2Addr with associated router hash metadata.
func WrapSSU2Addr(addr net.Addr, routerHash []byte) (*ssu2noise.SSU2Addr, error) {
	if ssu2Addr, ok := addr.(*ssu2noise.SSU2Addr); ok {
		return ssu2Addr, nil
	}

	connID, err := ssu2noise.GenerateConnectionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate connection ID: %w", err)
	}

	return ssu2noise.NewSSU2Addr(addr, routerHash, connID, "initiator")
}
