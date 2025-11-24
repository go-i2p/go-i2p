package ntcp2

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/go-i2p/lib/transport"
	"github.com/go-i2p/go-noise/ntcp2"
	"github.com/go-i2p/logger"
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
	logger *logger.Entry
}

func NewNTCP2Transport(identity router_info.RouterInfo, config *Config) (*NTCP2Transport, error) {
	ctx, cancel := context.WithCancel(context.Background())
	logger := logger.WithField("component", "ntcp2")

	identHashBytes := identity.IdentHash().Bytes()
	logger.WithFields(map[string]interface{}{
		"router_hash":      fmt.Sprintf("%x", identHashBytes[:8]),
		"listener_address": config.ListenerAddress,
	}).Info("Initializing NTCP2 transport")

	ntcp2Config, err := createNTCP2Config(identity, cancel)
	if err != nil {
		logger.WithError(err).Error("Failed to create NTCP2 config")
		return nil, err
	}

	if err := initializeCryptoKeys(ntcp2Config, cancel); err != nil {
		logger.WithError(err).Error("Failed to initialize crypto keys")
		return nil, err
	}

	logger.Debug("Crypto keys initialized successfully")
	config.NTCP2Config = ntcp2Config

	transport := buildTransportInstance(config, identity, ctx, cancel, logger)

	if err := setupNetworkListener(transport, config, ntcp2Config); err != nil {
		logger.WithError(err).Error("Failed to setup network listener")
		return nil, err
	}

	logger.WithField("address", transport.Addr().String()).Info("NTCP2 transport initialized successfully")
	return transport, nil
}

// createNTCP2Config creates and initializes the NTCP2 configuration from router identity.
func createNTCP2Config(identity router_info.RouterInfo, cancel context.CancelFunc) (*ntcp2.NTCP2Config, error) {
	identityBytes := identity.IdentHash().Bytes()
	ntcp2Config, err := ntcp2.NewNTCP2Config(identityBytes[:], false)
	if err != nil {
		cancel()
		return nil, err
	}
	return ntcp2Config, nil
}

// initializeCryptoKeys generates static key and obfuscation IV if not already set.
// TODO: These should be loaded from persistent storage or derived from router identity.
func initializeCryptoKeys(ntcp2Config *ntcp2.NTCP2Config, cancel context.CancelFunc) error {
	if err := generateStaticKeyIfNeeded(ntcp2Config, cancel); err != nil {
		return err
	}
	return generateObfuscationIVIfNeeded(ntcp2Config, cancel)
}

// generateStaticKeyIfNeeded creates a random 32-byte static key if not present.
func generateStaticKeyIfNeeded(ntcp2Config *ntcp2.NTCP2Config, cancel context.CancelFunc) error {
	if len(ntcp2Config.StaticKey) == 0 {
		ntcp2Config.StaticKey = make([]byte, 32)
		if _, err := rand.Read(ntcp2Config.StaticKey); err != nil {
			cancel()
			return WrapNTCP2Error(err, "generating static key")
		}
	}
	return nil
}

// generateObfuscationIVIfNeeded creates a random 16-byte obfuscation IV if not present.
func generateObfuscationIVIfNeeded(ntcp2Config *ntcp2.NTCP2Config, cancel context.CancelFunc) error {
	if len(ntcp2Config.ObfuscationIV) == 0 {
		ntcp2Config.ObfuscationIV = make([]byte, 16)
		if _, err := rand.Read(ntcp2Config.ObfuscationIV); err != nil {
			cancel()
			return WrapNTCP2Error(err, "generating obfuscation IV")
		}
	}
	return nil
}

// buildTransportInstance constructs the NTCP2Transport struct with initialized fields.
func buildTransportInstance(config *Config, identity router_info.RouterInfo, ctx context.Context, cancel context.CancelFunc, logger *logger.Entry) *NTCP2Transport {
	return &NTCP2Transport{
		config:   config,
		identity: identity,
		ctx:      ctx,
		cancel:   cancel,
		logger:   logger,
		wg:       sync.WaitGroup{},
		sessions: sync.Map{},
	}
}

// setupNetworkListener creates and attaches the TCP and NTCP2 listeners to the transport.
func setupNetworkListener(transport *NTCP2Transport, config *Config, ntcp2Config *ntcp2.NTCP2Config) error {
	tcpListener, err := net.Listen("tcp", config.ListenerAddress)
	if err != nil {
		return err
	}

	listener, err := ntcp2.NewNTCP2Listener(tcpListener, ntcp2Config)
	if err != nil {
		return err
	}

	transport.listener = listener
	return nil
}

// Accept accepts an incoming session.
func (t *NTCP2Transport) Accept() (net.Conn, error) {
	if t.listener == nil {
		t.logger.Error("Accept called but listener is nil")
		return nil, ErrSessionClosed
	}
	t.logger.Debug("Accepting incoming NTCP2 connection")
	conn, err := t.listener.Accept()
	if err != nil {
		t.logger.WithError(err).Warn("Failed to accept incoming connection")
		return nil, err
	}
	t.logger.WithField("remote_addr", conn.RemoteAddr().String()).Info("Accepted incoming NTCP2 connection")
	return conn, nil
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
	identHashBytes := ident.IdentHash().Bytes()
	t.logger.WithField("router_hash", fmt.Sprintf("%x", identHashBytes[:8])).Info("Updating NTCP2 transport identity")
	t.identity = ident

	// Update the NTCP2 configuration with new identity
	identityBytes := ident.IdentHash().Bytes()
	ntcp2Config, err := ntcp2.NewNTCP2Config(identityBytes[:], false)
	if err != nil {
		t.logger.WithError(err).Error("Failed to create new NTCP2 config for identity update")
		return WrapNTCP2Error(err, "updating identity")
	}
	t.config.NTCP2Config = ntcp2Config

	// If listener is already created, we need to recreate it with new identity
	if t.listener != nil {
		t.logger.Info("Recreating listener with new identity")
		if err := t.listener.Close(); err != nil {
			t.logger.WithError(err).Warn("Error closing existing listener during identity update")
		}

		tcpListener, err := net.Listen("tcp", t.config.ListenerAddress)
		if err != nil {
			t.logger.WithError(err).Error("Failed to rebind listener")
			return WrapNTCP2Error(err, "rebinding listener")
		}

		listener, err := ntcp2.NewNTCP2Listener(tcpListener, ntcp2Config)
		if err != nil {
			t.logger.WithError(err).Error("Failed to create new NTCP2 listener")
			return WrapNTCP2Error(err, "creating new listener")
		}
		t.listener = listener
		t.logger.WithField("address", t.listener.Addr().String()).Info("Listener recreated successfully")
	}

	t.logger.Info("Identity updated successfully")
	return nil
}

// GetSession obtains a transport session with a router given its RouterInfo.
func (t *NTCP2Transport) GetSession(routerInfo router_info.RouterInfo) (transport.TransportSession, error) {
	routerHash := routerInfo.IdentHash()
	routerHashBytes := routerHash.Bytes()
	t.logger.WithFields(map[string]interface{}{
		"router_hash": fmt.Sprintf("%x", routerHashBytes[:8]),
		"operation":   "get_session",
	}).Debug("Getting NTCP2 session")

	if session, found := t.findExistingSession(routerHash); found {
		return session, nil
	}

	return t.createOutboundSession(routerInfo, routerHash)
}

func (t *NTCP2Transport) findExistingSession(routerHash data.Hash) (transport.TransportSession, bool) {
	if session, exists := t.sessions.Load(routerHash); exists {
		if ntcp2Session, ok := session.(*NTCP2Session); ok {
			routerHashBytes := routerHash.Bytes()
			t.logger.WithFields(map[string]interface{}{
				"router_hash":     fmt.Sprintf("%x", routerHashBytes[:8]),
				"send_queue_size": ntcp2Session.SendQueueSize(),
			}).Info("Reusing existing NTCP2 session")
			return ntcp2Session, true
		}
	}
	routerHashBytes := routerHash.Bytes()
	t.logger.WithField("router_hash", fmt.Sprintf("%x", routerHashBytes[:8])).Debug("No existing session found")
	return nil, false
}

func (t *NTCP2Transport) createOutboundSession(routerInfo router_info.RouterInfo, routerHash data.Hash) (transport.TransportSession, error) {
	routerHashBytes := routerHash.Bytes()
	t.logger.WithField("router_hash", fmt.Sprintf("%x", routerHashBytes[:8])).Info("Creating new outbound NTCP2 session")

	conn, err := t.dialNTCP2Connection(routerInfo)
	if err != nil {
		t.logger.WithError(err).WithField("router_hash", fmt.Sprintf("%x", routerHashBytes[:8])).Error("Failed to dial NTCP2 connection")
		return nil, err
	}

	session := t.setupSession(conn, routerHash)
	t.logger.WithFields(map[string]interface{}{
		"router_hash": fmt.Sprintf("%x", routerHashBytes[:8]),
		"remote_addr": conn.RemoteAddr().String(),
	}).Info("Successfully created outbound NTCP2 session")
	return session, nil
}

func (t *NTCP2Transport) dialNTCP2Connection(routerInfo router_info.RouterInfo) (*ntcp2.NTCP2Conn, error) {
	tcpAddr, err := ExtractNTCP2Addr(routerInfo)
	if err != nil {
		t.logger.WithError(err).Error("Failed to extract NTCP2 address from RouterInfo")
		return nil, WrapNTCP2Error(err, "extracting NTCP2 address")
	}

	t.logger.WithField("remote_addr", tcpAddr.String()).Debug("Extracted NTCP2 address")

	config, err := t.createNTCP2Config(routerInfo)
	if err != nil {
		t.logger.WithError(err).Error("Failed to create NTCP2 config for outbound connection")
		return nil, err
	}

	t.logger.WithField("remote_addr", tcpAddr.String()).Info("Dialing NTCP2 connection")
	conn, err := ntcp2.DialNTCP2WithHandshake("tcp", tcpAddr.String(), config)
	if err != nil {
		t.logger.WithError(err).WithField("remote_addr", tcpAddr.String()).Error("Failed to dial NTCP2 connection")
		return nil, WrapNTCP2Error(err, "dialing NTCP2 connection")
	}

	t.logger.WithField("remote_addr", tcpAddr.String()).Info("NTCP2 connection established")
	return conn, nil
}

func (t *NTCP2Transport) createNTCP2Config(routerInfo router_info.RouterInfo) (*ntcp2.NTCP2Config, error) {
	identityBytes := t.identity.IdentHash().Bytes()
	config, err := ntcp2.NewNTCP2Config(identityBytes[:], true)
	if err != nil {
		return nil, WrapNTCP2Error(err, "creating NTCP2 config")
	}

	remoteHashBytes := routerInfo.IdentHash().Bytes()
	return config.WithRemoteRouterHash(remoteHashBytes[:]), nil
}

func (t *NTCP2Transport) setupSession(conn *ntcp2.NTCP2Conn, routerHash data.Hash) *NTCP2Session {
	session := NewNTCP2Session(conn, t.ctx, t.logger)

	session.SetCleanupCallback(func() {
		t.removeSession(routerHash)
	})

	t.sessions.Store(routerHash, session)
	return session
}

// Compatible returns true if a routerInfo is compatible with this transport.
func (t *NTCP2Transport) Compatible(routerInfo router_info.RouterInfo) bool {
	supported := SupportsNTCP2(&routerInfo)
	routerHashBytes := routerInfo.IdentHash().Bytes()
	t.logger.WithFields(map[string]interface{}{
		"router_hash": fmt.Sprintf("%x", routerHashBytes[:8]),
		"supported":   supported,
	}).Debug("Checking NTCP2 compatibility")
	return supported
}

// removeSession removes a session from the session map (called by session cleanup callback)
func (t *NTCP2Transport) removeSession(routerHash data.Hash) {
	routerHashBytes := routerHash.Bytes()
	t.sessions.Delete(routerHash)
	t.logger.WithField("router_hash", fmt.Sprintf("%x", routerHashBytes[:8])).Info("Removed session from transport session map")
}

// Close closes the transport cleanly.
func (t *NTCP2Transport) Close() error {
	t.logger.Info("Closing NTCP2 transport")

	t.cancelTransportContext()
	listenerErr := t.closeNetworkListener()
	t.closeAllActiveSessions()
	t.waitForBackgroundOperations()

	return t.handleCloseCompletion(listenerErr)
}

// cancelTransportContext stops all transport operations by canceling the context.
func (t *NTCP2Transport) cancelTransportContext() {
	t.logger.Debug("Canceling transport context")
	t.cancel()
}

// closeNetworkListener closes the network listener if present.
// Returns any error encountered during closure.
func (t *NTCP2Transport) closeNetworkListener() error {
	if t.listener == nil {
		return nil
	}

	t.logger.Debug("Closing network listener")
	err := t.listener.Close()
	if err != nil {
		t.logger.WithError(err).Warn("Error closing listener")
	}
	return err
}

// closeAllActiveSessions iterates through all sessions and closes them.
// Logs the total number of sessions closed.
func (t *NTCP2Transport) closeAllActiveSessions() {
	t.logger.Debug("Closing all active sessions")
	sessionCount := 0

	t.sessions.Range(func(key, value interface{}) bool {
		sessionCount++
		t.closeIndividualSession(key, value)
		t.sessions.Delete(key)
		return true
	})

	t.logger.WithField("session_count", sessionCount).Info("Closed all sessions")
}

// closeIndividualSession closes a single session and logs any errors.
func (t *NTCP2Transport) closeIndividualSession(key, value interface{}) {
	session, ok := value.(*NTCP2Session)
	if !ok {
		return
	}

	routerHash, ok := key.(data.Hash)
	if !ok {
		return
	}

	if err := session.Close(); err != nil {
		routerHashBytes := routerHash.Bytes()
		t.logger.WithError(err).WithField("router_hash", fmt.Sprintf("%x", routerHashBytes[:8])).Warn("Error closing session")
	}
}

// waitForBackgroundOperations blocks until all background goroutines complete.
func (t *NTCP2Transport) waitForBackgroundOperations() {
	t.logger.Debug("Waiting for background operations to complete")
	t.wg.Wait()
}

// handleCloseCompletion processes the final close status and returns appropriate error.
func (t *NTCP2Transport) handleCloseCompletion(listenerErr error) error {
	if listenerErr != nil {
		t.logger.WithError(listenerErr).Error("Transport closed with listener error")
		return WrapNTCP2Error(listenerErr, "closing listener")
	}

	t.logger.Info("NTCP2 transport closed successfully")
	return nil
}

// Name returns the name of this transport.
func (t *NTCP2Transport) Name() string {
	return "NTCP2"
}
