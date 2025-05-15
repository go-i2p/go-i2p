package noise

/**
 * NoiseTransport is an unused transport which is used only for testing the
 * transport interfaces. I2P adds obfuscation to NOISE with the NTCP2 protocol
 * which is one of the transports which we use in practice.
**/

import (
	"net"
	"sync"

	"github.com/flynn/noise"
	"github.com/samber/oops"
	"github.com/sirupsen/logrus"

	"github.com/go-i2p/go-i2p/lib/common/data"
	"github.com/go-i2p/go-i2p/lib/common/router_info"
	"github.com/go-i2p/go-i2p/lib/transport"
)

const NOISE_PROTOCOL_NAME = "NOISE"

type NoiseTransport struct {
	sync.Mutex
	router_info.RouterInfo
	transportStyle string
	Listener       net.Listener
	// peerConnections map[data.Hash]transport.TransportSession
	peerConnections map[data.Hash]*NoiseSession
}

func (noopt *NoiseTransport) Compatible(routerInfo router_info.RouterInfo) bool {
	// Check if we have an existing session with this router
	_, ok := noopt.peerConnections[routerInfo.IdentHash()]
	if ok {
		return true
	}

	// Check router addresses for Noise protocol support
	for _, addr := range routerInfo.RouterAddresses() {
		transportStyle, err := addr.TransportStyle().Data()
		if err != nil {
			continue
		}

		// Check for Noise protocol support
		if transportStyle == NOISE_PROTOCOL_NAME {
			// A router is compatible if it has a static key
			if addr.CheckOption("s") {
				return true
			}
		}
	}
	return false
}

var exampleNoiseTransport transport.Transport = &NoiseTransport{}

// ExampleNoiseListener is not a real Noise Listener, do not use it.
// It is exported so that it can be confirmed that the transport
// implements net.Listener
var ExampleNoiseListener net.Listener = exampleNoiseTransport

// Accept a connection on a listening socket.
func (noopt *NoiseTransport) Accept() (net.Conn, error) {
	log.Debug("NoiseTransport: Accepting new connection")
	// return noopt.Listener.Accept()
	conn, err := noopt.Listener.Accept()
	if err != nil {
		log.WithError(err).Error("NoiseTransport: Failed to accept connection")
	} else {
		log.WithField("remote_addr", conn.RemoteAddr().String()).Debug("NoiseTransport: Accepted new connection")
	}
	return conn, err
}

// Addr of the transport, for now this is returning the IP:Port the transport is listening on,
// but this might actually be the router identity
func (noopt *NoiseTransport) Addr() net.Addr {
	// return noopt.Listener.Addr()
	addr := noopt.Listener.Addr()
	log.WithField("addr", addr.String()).Debug("NoiseTransport: Returning address")
	return addr
}

// Name of the transport TYPE, in this case `noise`
func (noopt *NoiseTransport) Name() string {
	return "noise"
}

// SetIdentity will set the router identity for this transport.
// will bind if the underlying socket is not already
// if the underlying socket is already bound update the RouterIdentity
// returns any errors that happen if they do
func (noopt *NoiseTransport) SetIdentity(ident router_info.RouterInfo) (err error) {
	log.WithField("identity", ident).Debug("NoiseTransport: Setting identity")
	noopt.RouterInfo = ident
	if noopt.Listener == nil {
		log.WithFields(logrus.Fields{
			"at":     "(NoiseTransport) SetIdentity",
			"reason": "network socket is null",
		}).Error("network socket is null")
		err = oops.Errorf("network socket is null")
		return
	}
	log.Debug("NoiseTransport: Identity set successfully")
	return nil
}

// Obtain a transport session with a router given its RouterInfo.
// If a session with this router is NOT already made attempt to create one and block until made or until an error happens
// returns an established TransportSession and nil on success
// returns nil and an error on error
func (noopt *NoiseTransport) GetSession(routerInfo router_info.RouterInfo) (transport.TransportSession, error) {
	hash := routerInfo.IdentHash()
	log.WithField("hash", hash).Debug("NoiseTransport: Getting session")
	if len(hash) == 0 {
		log.Error("NoiseTransport: RouterInfo has no IdentityHash")
		return nil, oops.Errorf("NoiseTransport: GetSession: RouterInfo has no IdentityHash")
	}
	if t, ok := noopt.peerConnections[hash]; ok {
		log.Debug("NoiseTransport: Existing session found")
		return t, nil
	}
	log.Debug("NoiseTransport: Creating new session")
	var err error
	if noopt.peerConnections[hash], err = NewNoiseSession(routerInfo); err != nil {
		log.WithError(err).Error("NoiseTransport: Failed to create new session")
		return noopt.peerConnections[hash], err
	}
	log.Debug("NoiseTransport: New session created successfully")
	return nil, err
}

func (c *NoiseTransport) getSession(routerInfo router_info.RouterInfo) (transport.TransportSession, error) {
	log.WithField("router_info", routerInfo.String()).Debug("NoiseTransport: Getting session (internal)")
	session, err := c.GetSession(routerInfo)
	if err != nil {
		log.WithError(err).Error("NoiseTransport: Failed to get session")
		return nil, err
	}
	for {
		if session.(*NoiseSession).HandshakeComplete() {
			log.Debug("NoiseTransport: Handshake complete")
			return session, nil
		}
		if session.(*NoiseSession).Cond == nil {
			log.Debug("NoiseTransport: No condition variable, breaking")
			break
		}
		log.Debug("NoiseTransport: Waiting for handshake to complete")
		session.(*NoiseSession).Cond.Wait()
	}
	log.Debug("NoiseTransport: Returning session")
	return session, nil
}

// close the transport cleanly
// blocks until done
// returns an error if one happens
func (noopt *NoiseTransport) Close() error {
	log.Debug("NoiseTransport: Closing transport")
	return nil
}

// NewNoiseTransport create a NoiseTransport using a supplied net.Listener
func NewNoiseTransport(netSocket net.Listener) *NoiseTransport {
	log.WithField("listener_addr", netSocket.Addr().String()).Debug("Creating new NoiseTransport")
	return &NoiseTransport{
		peerConnections: make(map[data.Hash]*NoiseSession),
		Listener:        netSocket,
		transportStyle:  NOISE_PROTOCOL_NAME,
	}
}

// NewNoiseTransportSocket creates a Noise transport socket with a random
// host and port.
func NewNoiseTransportSocket() (*NoiseTransport, error) {
	log.Debug("Creating new NoiseTransportSocket")
	netSocket, err := net.Listen("tcp", "")
	if err != nil {
		log.WithError(err).Error("Failed to create listener for NoiseTransportSocket")
		return nil, err
	}
	// return NewNoiseTransport(netSocket), nil
	_transport := NewNoiseTransport(netSocket)
	log.WithField("addr", netSocket.Addr().String()).Debug("Created new NoiseTransportSocket")
	return _transport, nil
}

// LocalStaticKey is equal to the NTCP2 static public key, found in our router info
func (s *NoiseTransport) localStaticKey() ([32]byte, error) {
	// s.RouterIdentity
	for _, addr := range s.RouterInfo.RouterAddresses() {
		transportStyle, err := addr.TransportStyle().Data()
		if err != nil {
			continue
		}
		if transportStyle == s.transportStyle {
			return addr.StaticKey()
		}
	}
	return [32]byte{}, oops.Errorf("Remote static key error")
}

func (s *NoiseTransport) localStaticIV() ([16]byte, error) {
	for _, addr := range s.RouterInfo.RouterAddresses() {
		transportStyle, err := addr.TransportStyle().Data()
		if err != nil {
			continue
		}
		if transportStyle == s.transportStyle {
			return addr.InitializationVector()
		}
	}
	return [16]byte{}, oops.Errorf("Remote static IV error")
}

func (h *NoiseTransport) HandshakeKey() *noise.DHKey {
	return nil
}
