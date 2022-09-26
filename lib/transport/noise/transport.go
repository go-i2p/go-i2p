package noise

/**
 * NoiseTransport is an unused transport which is used only for testing the
 * transport interfaces. I2P adds obfuscation to NOISE with the NTCP2 protocol
 * which is one of the transports which we use in practice.
**/

import (
	"errors"
	"fmt"
	"net"

	"github.com/go-i2p/go-i2p/lib/common/data"
	"github.com/go-i2p/go-i2p/lib/common/router_identity"
	"github.com/go-i2p/go-i2p/lib/common/router_info"
	"github.com/go-i2p/go-i2p/lib/transport"
)

type NoiseTransport struct {
	routerIdentity  router_identity.RouterIdentity
	peerConnections map[data.Hash]transport.TransportSession
	netSocket       net.Listener
}

var exampleNoiseTransport transport.Transport = &NoiseTransport{}

func (noopt *NoiseTransport) Name() string {
	return "noise"
}

// Set the router identity for this transport.
// will bind if the underlying socket is not already
// if the underlying socket is already bound update the RouterIdentity
// returns any errors that happen if they do
func (noopt *NoiseTransport) SetIdentity(ident router_identity.RouterIdentity) (err error) {
	noopt.routerIdentity = ident
	if noopt.netSocket == nil {
		noopt.netSocket, err = net.ListenTCP()
	}
	return nil
}

// Obtain a transport session with a router given its RouterInfo.
// If a session with this router is NOT already made attempt to create one and block until made or until an error happens
// returns an established TransportSession and nil on success
// returns nil and an error on error
func (noopt *NoiseTransport) GetSession(routerInfo router_info.RouterInfo) (transport.TransportSession, error) {
	var err error
	hash := routerInfo.IdentHash()
	if len(hash) == 0 {
		return nil, errors.New("NoiseTransport: GetSession: RouterInfo has no IdentityHash")
	}
	if t, ok := noopt.peerConnections[hash]; ok {
		return t, nil
	}
	if noopt.peerConnections[hash], err = NewNoiseTransportSession(routerInfo); err != nil {
		return noopt.peerConnections[hash], err
	}
	return nil, fmt.Errorf("Unable to obtain transport session with %s", routerInfo.IdentHash())
}

// Compatable return true if a routerInfo is compatable with this transport
func (noopt *NoiseTransport) Compatable(routerInfo router_info.RouterInfo) bool {
	_, ok := noopt.peerConnections[routerInfo.IdentHash()]
	return ok
}

// close the transport cleanly
// blocks until done
// returns an error if one happens
func (noopt *NoiseTransport) Close() error {
	return nil
}

// NewNoiseTransport create a NoiseTransport using a supplied net.Listener
func NewNoiseTransport(netSocket net.Listener) *NoiseTransport {
	return &NoiseTransport{
		peerConnections: make(map[data.Hash]transport.TransportSession),
		netSocket:       netSocket,
	}
}

// NewNoiseTransportSocket creates a Noise transport socket with a random
// host and port.
func NewNoiseTransportSocket() (*NoiseTransport, error) {
	netSocket, err := net.Listen("tcp", "")
	if err != nil {
		return nil, err
	}
	return NewNoiseTransport(netSocket), nil
}
