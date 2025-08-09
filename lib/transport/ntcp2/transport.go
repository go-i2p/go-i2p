package ntcp2

import (
	"context"
	"encoding/base64"
	"net"
	"sync"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/transport"
	"github.com/go-i2p/go-noise/ntcp2"
	"github.com/sirupsen/logrus"
)

type NTCP2Transport struct {
	// Network listener (uses net.Listener interface per guidelines)
	listener net.Listener // Will be *ntcp2.NTCP2Listener internally

	// Configuration
	config   *Config
	identity router_info.RouterInfo

	// Session management
	sessions sync.Map // map[string]*NTCP2Session (keyed by router hash)

	// Lifecycle management
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Logging
	logger *logrus.Entry
}

func NewNTCP2Transport(identity router_info.RouterInfo, config *Config) (*NTCP2Transport, error) {
	ctx, cancel := context.WithCancel(context.Background())
	logger := logrus.WithField("component", "ntcp2")
	identityBytes := identity.IdentHash().Bytes()
	// Create a new NTCP2 configuration
	ntcp2Config, err := ntcp2.NewNTCP2Config(identityBytes[:], false)
	if err != nil {
		cancel()
		return nil, err
	}
	config.NTCP2Config = ntcp2Config

	transport := &NTCP2Transport{
		config:   config,
		identity: identity,
		ctx:      ctx,
		cancel:   cancel,
		logger:   logger,
		wg:       sync.WaitGroup{},
		sessions: sync.Map{},
	}

	// Initialize the network listener
	tcpListener, err := net.Listen("tcp", config.ListenerAddress)
	if err != nil {
		return nil, err
	}

	listener, err := ntcp2.NewNTCP2Listener(tcpListener, ntcp2Config)
	if err != nil {
		return nil, err
	}
	transport.listener = listener

	return transport, nil
}

// Accept accepts an incoming session.
func (t *NTCP2Transport) Accept() (net.Conn, error) {
	if t.listener == nil {
		return nil, ErrSessionClosed
	}
	return t.listener.Accept()
}

// Addr returns the network address the transport is bound to.
func (t *NTCP2Transport) Addr() net.Addr {
	if t.listener == nil {
		return nil
	}
	return t.listener.Addr()
}

// SetIdentity sets the router identity for this transport.
func (t *NTCP2Transport) SetIdentity(ident router_info.RouterInfo) error {
	t.identity = ident

	// Update the NTCP2 configuration with new identity
	identityBytes := ident.IdentHash().Bytes()
	ntcp2Config, err := ntcp2.NewNTCP2Config(identityBytes[:], false)
	if err != nil {
		return WrapNTCP2Error(err, "updating identity")
	}
	t.config.NTCP2Config = ntcp2Config

	// If listener is already created, we need to recreate it with new identity
	if t.listener != nil {
		if err := t.listener.Close(); err != nil {
			t.logger.WithError(err).Warn("Error closing existing listener during identity update")
		}

		tcpListener, err := net.Listen("tcp", t.config.ListenerAddress)
		if err != nil {
			return WrapNTCP2Error(err, "rebinding listener")
		}

		listener, err := ntcp2.NewNTCP2Listener(tcpListener, ntcp2Config)
		if err != nil {
			return WrapNTCP2Error(err, "creating new listener")
		}
		t.listener = listener
	}

	return nil
}

// GetSession obtains a transport session with a router given its RouterInfo.
func (t *NTCP2Transport) GetSession(routerInfo router_info.RouterInfo) (transport.TransportSession, error) {
	// Check if router supports NTCP2
	if !t.Compatible(routerInfo) {
		return nil, ErrNTCP2NotSupported
	}

	// Use router hash as session key
	routerHashBytes := routerInfo.IdentHash().Bytes()
	routerHash := base64.StdEncoding.EncodeToString(routerHashBytes[:])

	// Check if session already exists
	if existingSession, ok := t.sessions.Load(routerHash); ok {
		if session, ok := existingSession.(*NTCP2Session); ok {
			return session, nil
		}
	}

	// TODO: Implement outbound connection creation
	// For now, return an error indicating outbound connections are not yet implemented
	return nil, WrapNTCP2Error(ErrNTCP2NotSupported, "outbound connections not yet implemented")
} // Compatible returns true if a routerInfo is compatible with this transport.
func (t *NTCP2Transport) Compatible(routerInfo router_info.RouterInfo) bool {
	return SupportsNTCP2(&routerInfo)
}

// Close closes the transport cleanly.
func (t *NTCP2Transport) Close() error {
	// Cancel context to stop all operations
	t.cancel()

	// Close listener
	var listenerErr error
	if t.listener != nil {
		listenerErr = t.listener.Close()
	}

	// Close all sessions
	t.sessions.Range(func(key, value interface{}) bool {
		if session, ok := value.(*NTCP2Session); ok {
			if err := session.Close(); err != nil {
				t.logger.WithError(err).WithField("session", key).Warn("Error closing session")
			}
		}
		t.sessions.Delete(key)
		return true
	})

	// Wait for background operations to complete
	t.wg.Wait()

	if listenerErr != nil {
		return WrapNTCP2Error(listenerErr, "closing listener")
	}

	return nil
}

// Name returns the name of this transport.
func (t *NTCP2Transport) Name() string {
	return "NTCP2"
}
