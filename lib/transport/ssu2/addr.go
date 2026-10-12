package ssu2

import (
	"net"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/samber/oops"
)

// ExtractSSU2NoiseAddr extracts an SSU2 noise-level address from a RouterInfo.
// It returns a *ssu2noise.SSU2Addr suitable for use with the go-noise/ssu2 package.
// It generates a fresh connection ID and marks the address as an initiator,
// which is the role this router plays when dialing the peer.
// See [I2P Spec: SSU2](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ssu2.rst) for the protocol.
// See also [ExtractSSU2Addr] and [WrapSSU2Addr].
func ExtractSSU2NoiseAddr(routerInfo router_info.RouterInfo) (*ssu2noise.SSU2Addr, error) {
	routerHash, err := routerInfo.IdentHash()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to get router hash")
	}

	udpAddr, err := ExtractSSU2Addr(routerInfo)
	if err != nil {
		return nil, err
	}

	connID, err := ssu2noise.GenerateConnectionID()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to generate connection ID")
	}

	ssu2Addr, err := ssu2noise.NewSSU2Addr(udpAddr, routerHash, connID, "initiator")
	if err != nil {
		return nil, WrapSSU2Error(err, "creating SSU2 address")
	}

	return ssu2Addr, nil
}

// WrapSSU2Addr wraps an existing net.Addr as an SSU2Addr with associated router hash metadata.
// It is used when a raw UDP address is available but the SSU2 connection ID and
// router hash have not yet been attached. If the address is already an SSU2Addr,
// it is returned unchanged. See also [ExtractSSU2NoiseAddr].
func WrapSSU2Addr(addr net.Addr, routerHash data.Hash) (*ssu2noise.SSU2Addr, error) {
	if ssu2Addr, ok := addr.(*ssu2noise.SSU2Addr); ok {
		return ssu2Addr, nil
	}

	connID, err := ssu2noise.GenerateConnectionID()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to generate connection ID")
	}

	return ssu2noise.NewSSU2Addr(addr, routerHash, connID, "initiator")
}
