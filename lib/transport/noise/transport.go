package noise

/**
 * NoiseTransport is an unused transport which is used only for testing the
 * transport interfaces. I2P adds obfuscation to NOISE with the NTCP2 protocol
 * which is one of the transports which we use in practice.
**/

import (
	"errors"
	"net"
	"sync"

	"github.com/flynn/noise"
	"github.com/go-i2p/go-i2p/lib/common/data"
	"github.com/go-i2p/go-i2p/lib/common/router_identity"
	"github.com/go-i2p/go-i2p/lib/common/router_info"
	"github.com/go-i2p/go-i2p/lib/transport"
)

type NoiseTransport struct {
	*noise.CipherState
	router_identity.RouterIdentity
	sync.Mutex
	Listener        net.Listener
	peerConnections map[data.Hash]transport.TransportSession
}

var exampleNoiseTransport transport.Transport = &NoiseTransport{}

// ExampleNoiseListener is not a real Noise Listener, do not use it.
// It is exported so that it can be confirmed that the transport
// implements net.Listener
var ExampleNoiseListener net.Listener = exampleNoiseTransport

func (noopt *NoiseTransport) Accept() (net.Conn, error) {
	return noopt.Listener.Accept()
}

func (noopt *NoiseTransport) Addr() net.Addr {
	return noopt.Listener.Addr()
}

func (noopt *NoiseTransport) Name() string {
	return "noise"
}

// Set the router identity for this transport.
// will bind if the underlying socket is not already
// if the underlying socket is already bound update the RouterIdentity
// returns any errors that happen if they do
func (noopt *NoiseTransport) SetIdentity(ident router_identity.RouterIdentity) error {
	noopt.RouterIdentity = ident
	return nil
}

// Obtain a transport session with a router given its RouterInfo.
// If a session with this router is NOT already made attempt to create one and block until made or until an error happens
// returns an established TransportSession and nil on success
// returns nil and an error on error
func (noopt *NoiseTransport) GetSession(routerInfo router_info.RouterInfo) (transport.TransportSession, error) {
	hash := routerInfo.IdentHash()
	if len(hash) == 0 {
		return nil, errors.New("NoiseTransport: GetSession: RouterInfo has no IdentityHash")
	}
	if t, ok := noopt.peerConnections[hash]; ok == true {
		return t, nil
	}
	conn, err := noopt.Accept()
	if err == nil {
		if noopt.peerConnections[hash], err = NewNoiseTransportSession(routerInfo, conn); err != nil {
			return noopt.peerConnections[hash], err
		}
	}
	return nil, err
}

// return true if a routerInfo is compatable with this transport
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

func NewNoiseTransport(netSocket net.Listener) *NoiseTransport {
	return &NoiseTransport{
		peerConnections: make(map[data.Hash]transport.TransportSession),
		Listener:        netSocket,
	}
}
