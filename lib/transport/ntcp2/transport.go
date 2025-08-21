package ntcp2

import (
	"context"
	"net"
	"sync"

	"github.com/go-i2p/common/data"
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
	t.logger.WithField("router_hash", routerInfo.IdentHash()).Debug("Getting NTCP2 session")

	// Check if we already have a session with this router
	routerHash := routerInfo.IdentHash()
	if session, exists := t.sessions.Load(routerHash); exists {
		if ntcp2Session, ok := session.(*NTCP2Session); ok {
			t.logger.Debug("Found existing NTCP2 session")
			return ntcp2Session, nil
		}
	}

	// Create outbound connection
	t.logger.Debug("Creating new outbound NTCP2 connection")

	// Extract NTCP2 address from RouterInfo
	tcpAddr, err := ExtractNTCP2Addr(routerInfo)
	if err != nil {
		return nil, WrapNTCP2Error(err, "extracting NTCP2 address")
	}

	// Create NTCP2 config for outbound connection
	identityBytes := t.identity.IdentHash().Bytes()
	config, err := ntcp2.NewNTCP2Config(identityBytes[:], true)
	if err != nil {
		return nil, WrapNTCP2Error(err, "creating NTCP2 config")
	}

	// Set remote router hash
	remoteHashBytes := routerInfo.IdentHash().Bytes()
	config = config.WithRemoteRouterHash(remoteHashBytes[:])

	// Dial the outbound connection using go-noise
	conn, err := ntcp2.DialNTCP2WithHandshake("tcp", tcpAddr.String(), config)
	if err != nil {
		return nil, WrapNTCP2Error(err, "dialing NTCP2 connection")
	}

	// Create session wrapper
	session := NewNTCP2Session(conn, t.ctx, t.logger)

	// Set up cleanup callback so session can remove itself from map when it closes
	session.SetCleanupCallback(func() {
		t.removeSession(routerHash)
	})

	// Store the session
	t.sessions.Store(routerHash, session)

	t.logger.Debug("Successfully created outbound NTCP2 session")
	return session, nil
} // Compatible returns true if a routerInfo is compatible with this transport.
func (t *NTCP2Transport) Compatible(routerInfo router_info.RouterInfo) bool {
	return SupportsNTCP2(&routerInfo)
}

// removeSession removes a session from the session map (called by session cleanup callback)
func (t *NTCP2Transport) removeSession(routerHash data.Hash) {
	t.sessions.Delete(routerHash)
	t.logger.WithField("router_hash", routerHash).Debug("Removed session from transport session map")
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
