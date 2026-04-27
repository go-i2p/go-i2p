package ntcp2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/go-i2p/lib/transport"
	"github.com/go-i2p/go-noise/ntcp2"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"

	nattraversal "github.com/go-i2p/go-nat-listener"
)

// NTCP2Transport implements the I2P NTCP2 transport protocol, managing listener setup, session lifecycle, and peer connections.
type NTCP2Transport struct {
	// Network listener (uses net.Listener interface per guidelines)
	listener net.Listener // Will be *ntcp2.NTCP2Listener internally

	// Configuration
	config   *Config
	identity router_info.RouterInfo

	// Keystore for crypto key initialization (needed by SetIdentity)
	keystore KeystoreProvider

	// Handler for spec-compliance callbacks (probing resistance, replay cache,
	// timestamp validation, encrypted termination).
	handler *DefaultHandler

	// peerConnNotifier receives connection outcome feedback (optional).
	// Set via SetPeerConnNotifier after construction. Uses atomic.Value for safe concurrent access.
	peerConnNotifier atomic.Value // stores transport.PeerConnNotifier

	// routerInfoRefresher requests stale RI eviction on handshake EOF (optional).
	// Set via SetRouterInfoRefresher after construction.
	routerInfoRefresher transport.RouterInfoRefresher

	// Session management
	sessions     sync.Map // map[string]*NTCP2Session (keyed by router hash)
	sessionCount int32    // atomic O(1) session counter

	// Protects identity, config.NTCP2Config, and listener from concurrent
	// access by SetIdentity vs GetSession/Accept/Compatible.
	identityMu sync.RWMutex

	// Lifecycle management
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Logging
	logger *logger.Entry

	// closeOnce ensures Close() is idempotent.
	closeOnce sync.Once
	closeErr  error
}

// KeystoreProvider is the interface that supplies the X25519 encryption private key required for NTCP2 handshake negotiation.
type KeystoreProvider interface {
	GetEncryptionPrivateKey() types.PrivateEncryptionKey
}

// NewNTCP2Transport creates and initializes a new NTCP2Transport with the given router identity, configuration, and keystore provider.
func NewNTCP2Transport(identity router_info.RouterInfo, config *Config, keystore KeystoreProvider) (*NTCP2Transport, error) {
	ctx, cancel := context.WithCancel(context.Background())
	logger := logger.WithField("component", "ntcp2")

	identHash, err := identity.IdentHash()
	if err != nil {
		cancel()
		return nil, oops.Wrapf(err, "failed to get router identity hash")
	}
	identHashBytes := identHash.Bytes()
	logger.WithFields(map[string]interface{}{
		"router_hash":      fmt.Sprintf("%x", identHashBytes[:8]),
		"listener_address": config.ListenerAddress,
	}).Info("Initializing NTCP2 transport")

	ntcp2Config, err := createNTCP2Config(identity, cancel)
	if err != nil {
		logger.WithError(err).Error("Failed to create NTCP2 config")
		return nil, err
	}

	if err := initializeCryptoKeys(ntcp2Config, identity, keystore, config.WorkingDir, cancel); err != nil {
		logger.WithError(err).Error("Failed to initialize crypto keys")
		return nil, err
	}

	logger.Debug("Crypto keys initialized successfully")
	config.NTCP2Config = ntcp2Config

	transport := buildTransportInstance(config, identity, keystore, ctx, cancel, logger)

	if err := setupNetworkListener(transport, config, ntcp2Config); err != nil {
		cancel()
		logger.WithError(err).Error("Failed to setup network listener")
		return nil, err
	}

	logger.WithField("address", transport.Addr().String()).Info("NTCP2 transport initialized successfully")
	return transport, nil
}

// createNTCP2Config creates and initializes the NTCP2 configuration from router identity.
func createNTCP2Config(identity router_info.RouterInfo, cancel context.CancelFunc) (*ntcp2.NTCP2Config, error) {
	identHash, err := identity.IdentHash()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to get router identity hash")
	}
	ntcp2Config, err := ntcp2.NewNTCP2Config(identHash, false)
	if err != nil {
		cancel()
		return nil, err
	}
	return ntcp2Config, nil
}

// initializeCryptoKeys loads or derives NTCP2 cryptographic keys from persistent storage.
// The static key is derived from the router's X25519 encryption key (already persistent).
// The obfuscation IV is loaded from persistent storage or generated if not found.
func initializeCryptoKeys(ntcp2Config *ntcp2.NTCP2Config, identity router_info.RouterInfo, keystore KeystoreProvider, workingDir string, cancel context.CancelFunc) error {
	if err := loadStaticKeyFromRouter(ntcp2Config, identity, keystore, cancel); err != nil {
		return err
	}
	return loadOrGenerateObfuscationIV(ntcp2Config, workingDir, cancel)
}

// loadStaticKeyFromRouter derives the NTCP2 static key from the router's encryption key.
// This ensures the static key is persistent (stored in RouterInfoKeystore) and consistent
// across router restarts, which is critical for peer recognition.
func loadStaticKeyFromRouter(ntcp2Config *ntcp2.NTCP2Config, identity router_info.RouterInfo, keystore KeystoreProvider, cancel context.CancelFunc) error {
	if len(ntcp2Config.StaticKey) != 0 {
		return nil // Already set
	}

	// Extract X25519 encryption private key from RouterInfoKeystore
	encryptionPrivKey := keystore.GetEncryptionPrivateKey()
	if encryptionPrivKey == nil {
		if cancel != nil {
			cancel()
		}
		return WrapNTCP2Error(oops.Errorf("encryption private key is nil"), "retrieving encryption key from keystore")
	}

	// Use the encryption private key as the NTCP2 static key
	ntcp2Config.StaticKey = encryptionPrivKey.Bytes()
	if len(ntcp2Config.StaticKey) != 32 {
		if cancel != nil {
			cancel()
		}
		return WrapNTCP2Error(oops.Errorf("invalid static key size: expected 32 bytes, got %d", len(ntcp2Config.StaticKey)), "loading static key")
	}
	return nil
}

// loadOrGenerateObfuscationIV loads the obfuscation IV from persistent storage.
// If not found, generates a new random IV and stores it for future use.
func loadOrGenerateObfuscationIV(ntcp2Config *ntcp2.NTCP2Config, workingDir string, cancel context.CancelFunc) error {
	if len(ntcp2Config.ObfuscationIV) != 0 {
		return nil // Already set
	}

	persistentCfg := NewPersistentConfig(workingDir)
	iv, err := persistentCfg.LoadOrGenerateObfuscationIV()
	if err != nil {
		if cancel != nil {
			cancel()
		}
		return WrapNTCP2Error(err, "loading obfuscation IV")
	}

	ntcp2Config.ObfuscationIV = iv
	return nil
}

// buildTransportInstance constructs the NTCP2Transport struct with initialized fields.
func buildTransportInstance(config *Config, identity router_info.RouterInfo, keystore KeystoreProvider, ctx context.Context, cancel context.CancelFunc, logger *logger.Entry) *NTCP2Transport {
	return &NTCP2Transport{
		config:   config,
		identity: identity,
		keystore: keystore,
		handler:  NewDefaultHandler(),
		ctx:      ctx,
		cancel:   cancel,
		logger:   logger,
		wg:       sync.WaitGroup{},
		sessions: sync.Map{},
	}
}

// setupNetworkListener creates and attaches the TCP and NTCP2 listeners to the transport.
// bindOSAssignedPort discovers a free port via a temporary OS-assigned binding, then
// re-binds through NAT traversal (UPnP/NAT-PMP with fallback) on that port so that
// the resulting listener carries a real external address rather than the unspecified "::" host.
func bindOSAssignedPort(config *Config) (net.Listener, error) {
	// Step 1: ask the OS for any available port.
	temp, err := net.Listen("tcp", config.ListenerAddress)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to probe available port")
	}
	assignedPort := temp.Addr().(*net.TCPAddr).Port
	if closeErr := temp.Close(); closeErr != nil {
		log.WithError(closeErr).Warn("failed to close probe listener")
	}

	// Step 2: re-bind on the discovered port with NAT traversal so the listener
	// address carries the external IP instead of the unspecified "::" host.
	log.WithField("port", assignedPort).Info("probed OS-assigned port; attempting NAT traversal")
	return bindWithNATTraversal(config, assignedPort)
}

// bindWithNATTraversal creates a TCP listener on the specified port, attempting
// NAT traversal (UPnP/NAT-PMP) with a 10-second timeout context.
func bindWithNATTraversal(config *Config, port int) (net.Listener, error) {
	natCtx, natCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer natCancel()
	l, err := nattraversal.ListenWithFallbackContext(natCtx, port)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create TCP listener")
	}
	if boundAddr := l.Addr().String(); boundAddr != config.ListenerAddress {
		config.ListenerAddress = boundAddr
	}
	return l, nil
}

// attachNTCP2Listener wraps tcpListener in an NTCP2 listener and stores it on
// the transport. Closes tcpListener on NTCP2 setup failure.
func attachNTCP2Listener(transport *NTCP2Transport, tcpListener net.Listener, ntcp2Config *ntcp2.NTCP2Config) error {
	listener, err := ntcp2.NewNTCP2Listener(tcpListener, ntcp2Config)
	if err != nil {
		if closeErr := tcpListener.Close(); closeErr != nil {
			log.WithError(closeErr).Warn("Failed to close TCP listener after NTCP2 listener creation failure")
		}
		return err
	}
	transport.listener = listener
	return nil
}

func setupNetworkListener(transport *NTCP2Transport, config *Config, ntcp2Config *ntcp2.NTCP2Config) error {
	_, portStr, err := net.SplitHostPort(config.ListenerAddress)
	if err != nil {
		return oops.Wrapf(err, "failed to parse listener address")
	}
	iport, err := strconv.Atoi(portStr)
	if err != nil {
		return oops.Wrapf(err, "failed to convert port to integer")
	}

	var tcpListener net.Listener
	if iport == 0 {
		tcpListener, err = bindOSAssignedPort(config)
	} else {
		tcpListener, err = bindWithNATTraversal(config, iport)
	}
	if err != nil {
		return err
	}
	return attachNTCP2Listener(transport, tcpListener, ntcp2Config)
}

// Accept accepts an incoming session.
// The accepted connection is tracked in the transport's session map so that
// GetSessionCount() and checkSessionLimit() accurately reflect both inbound
// and outbound sessions. A cleanup callback is registered to remove the
// tracking entry when the connection is closed.
//
// Unlike using AcceptWithHandshake directly, this method performs the Noise XK
// handshake manually so that handshake-phase AEAD failures trigger probing
// resistance (random delay + junk read) before closing the connection. This
// prevents active probers from distinguishing an NTCP2 listener from a random
// TCP service by timing how quickly the connection closes.
//
// Spec reference: https://geti2p.net/spec/ntcp2#probing-resistance
func (t *NTCP2Transport) Accept() (net.Conn, error) {
	if t.listener == nil {
		t.logger.Error("Accept called but listener is nil")
		return nil, ErrSessionClosed
	}

	if err := t.checkSessionLimit(); err != nil {
		t.logger.WithFields(map[string]interface{}{
			"session_count": t.GetSessionCount(),
			"max_sessions":  t.config.GetMaxSessions(),
		}).Warn("Rejecting inbound connection: session limit reached")
		return nil, err
	}

	t.logger.Debug("Accepting incoming NTCP2 connection")

	conn, err := t.listener.Accept()
	if err != nil {
		t.unreserveSessionSlot()
		t.logger.WithError(err).Warn("Failed to accept incoming connection")
		return nil, err
	}

	if err := t.performInboundHandshake(conn); err != nil {
		return nil, err
	}

	return t.trackInboundConnection(conn), nil
}

// performInboundHandshake performs the Noise XK handshake on an accepted connection.
// On failure, applies probing resistance and releases the reserved session slot.
// On success, propagates the peer's static key to derive the remote router hash.
func (t *NTCP2Transport) performInboundHandshake(conn net.Conn) error {
	ntcp2Conn, ok := conn.(*ntcp2.NTCP2Conn)
	if !ok {
		t.logger.Warn("Accepted connection is not *ntcp2.NTCP2Conn, skipping manual handshake")
		return nil
	}
	if err := ntcp2Conn.UnderlyingConn().Handshake(t.ctx); err != nil {
		raw := extractRawConn(ntcp2Conn.UnderlyingConn())
		t.logger.WithError(err).Debug("Inbound handshake failed, applying probing resistance")
		applyProbingResistance(raw)
		_ = ntcp2Conn.Close()
		t.unreserveSessionSlot()
		return WrapNTCP2Error(err, "inbound handshake (probing resistance applied)")
	}
	// Propagate the peer's static key from the completed handshake into the
	// remote NTCP2Addr so that extractPeerHash returns the real router hash
	// instead of the fallback address-derived hash.
	ntcp2Conn.PropagatePeerStaticKey()

	// Log what the remote peer sent as their RouterInfo (Alice's msg3 payload).
	// This allows post-hoc diagnosis of E2-pattern EOFs: if Alice closes immediately
	// after msg3, logging here confirms the handshake itself succeeded and the issue
	// is in the data phase (peer policy / caps mismatch / no-data timeout).
	t.identityMu.RLock()
	localRI := t.identity
	t.identityMu.RUnlock()
	localCaps := localRI.RouterCapabilities()
	localAddrCount := localRI.RouterAddressCount()
	t.logger.WithFields(map[string]interface{}{
		"remote_addr":      conn.RemoteAddr().String(),
		"local_caps":       localCaps,
		"local_addr_count": localAddrCount,
	}).Info("Inbound Noise XK handshake completed successfully (responder role)")
	return nil
}

// trackInboundConnection registers the accepted connection for session counting
// and wraps it to ensure cleanup on close.
func (t *NTCP2Transport) trackInboundConnection(conn net.Conn) net.Conn {
	peerHash := t.extractPeerHash(conn)
	if _, loaded := t.sessions.LoadOrStore(peerHash, conn); loaded {
		t.unreserveSessionSlot()
	}

	wrappedConn := &trackedConn{
		Conn: conn,
		onClose: func() {
			t.removeSession(peerHash)
		},
	}

	t.logger.WithFields(map[string]interface{}{
		"remote_addr":   conn.RemoteAddr().String(),
		"peer_hash":     fmt.Sprintf("%x", peerHash[:8]),
		"session_count": t.GetSessionCount(),
	}).Info("Accepted and tracked incoming NTCP2 connection")
	return wrappedConn
}

// extractPeerHash extracts the peer's router hash from an accepted connection.
// Returns a hash derived from the NTCP2Addr if available, or a hash derived
// from the remote address as a fallback key for session map tracking.
func (t *NTCP2Transport) extractPeerHash(conn net.Conn) data.Hash {
	var peerHash data.Hash

	if ntcpAddr, ok := conn.RemoteAddr().(*ntcp2.NTCP2Addr); ok {
		hashBytes := ntcpAddr.RouterHash()
		peerHash = hashBytes
		// If the hash is non-zero, use it directly
		var zeroHash data.Hash
		if peerHash != zeroHash {
			return peerHash
		}
	}

	// Fallback: generate a unique key from the remote address.
	// After PropagatePeerStaticKey() in performInboundHandshake, NTCP2
	// connections should have a real router hash. This fallback handles
	// non-NTCP2 connections or edge cases where the hash is unavailable.
	// Strip the ephemeral port so reconnections from the same host produce
	// the same hash, avoiding duplicate session tracking entries.
	addrStr := conn.RemoteAddr().String()
	if host, _, err := net.SplitHostPort(addrStr); err == nil {
		addrStr = host
	}
	addrBytes := []byte(addrStr)
	copy(peerHash[:], addrBytes)
	// Set a marker byte to distinguish address-derived hashes
	if len(addrBytes) < 32 {
		peerHash[31] = 0xFF // marker for address-derived hash
	}

	return peerHash
}

// trackedConn wraps a net.Conn to execute a cleanup function when closed.
// This ensures inbound connections are removed from the session tracking map
// when the connection is closed, preventing session counter drift.
type trackedConn struct {
	net.Conn
	onClose   func()
	closeOnce sync.Once
}

// Close closes the underlying connection and runs the cleanup callback exactly once.
// The cleanup callback always runs regardless of whether the underlying connection
// closes successfully, because a failed close still renders the connection unusable
// and we must not leak session map entries. Without this, failed closes (e.g., "use
// of closed network connection") would permanently leak entries in the session tracking
// map, eventually preventing new connections.
func (tc *trackedConn) Close() error {
	err := tc.Conn.Close()
	tc.closeOnce.Do(tc.onClose)
	return err
}

// Addr returns the network address the transport is bound to.
func (t *NTCP2Transport) Addr() net.Addr {
	t.identityMu.RLock()
	l := t.listener
	t.identityMu.RUnlock()
	if l == nil {
		return nil
	}
	return l.Addr()
}

// UpdateLocalRouterInfo replaces the stored local RouterInfo with a re-signed
// version that includes the transport's address. Safe to call during transport
// initialization (before the router starts accepting connections). Unlike
// SetIdentity, this does NOT recreate the listener.
func (t *NTCP2Transport) UpdateLocalRouterInfo(ri router_info.RouterInfo) {
	t.identityMu.Lock()
	t.identity = ri
	t.identityMu.Unlock()
}

// SetPeerConnNotifier wires a connection-outcome notifier into the transport.
// Call this after construction to enable PeerTracker feedback. Safe to call
// concurrently; the field is only read under t.identityMu or from the
// goroutine that dials (no hot-path lock needed because the pointer is set
// once before any sessions are created).
func (t *NTCP2Transport) SetPeerConnNotifier(n transport.PeerConnNotifier) {
	t.peerConnNotifier.Store(n)
}

// getPeerConnNotifier returns the current PeerConnNotifier, or nil if none is set.
func (t *NTCP2Transport) getPeerConnNotifier() transport.PeerConnNotifier {
	if v := t.peerConnNotifier.Load(); v != nil {
		return v.(transport.PeerConnNotifier)
	}
	return nil
}

// SetRouterInfoRefresher wires a RouterInfo cache-eviction notifier so that
// stale entries are removed from NetDB after a handshake EOF failure.
func (t *NTCP2Transport) SetRouterInfoRefresher(r transport.RouterInfoRefresher) {
	t.routerInfoRefresher = r
}

// SetIdentity sets the router identity for this transport.
// Protected by identityMu to prevent races with GetSession/Accept/Compatible.
func (t *NTCP2Transport) SetIdentity(ident router_info.RouterInfo) error {
	if err := t.logIdentityUpdate(ident); err != nil {
		return err
	}

	ntcp2Config, err := t.createNTCP2ConfigFromIdentity(ident)
	if err != nil {
		return err
	}

	if err := initializeCryptoKeys(ntcp2Config, ident, t.keystore, t.config.WorkingDir, nil); err != nil {
		return oops.Wrapf(err, "failed to reinitialize crypto keys after identity update")
	}

	t.identityMu.Lock()
	t.identity = ident
	t.config.NTCP2Config = ntcp2Config
	t.identityMu.Unlock()

	if err := t.recreateListenerIfNeeded(ntcp2Config); err != nil {
		return err
	}

	t.logger.Info("Identity updated successfully")
	return nil
}

// logIdentityUpdate logs the identity update operation and validates the identity hash.
func (t *NTCP2Transport) logIdentityUpdate(ident router_info.RouterInfo) error {
	identHash, err := ident.IdentHash()
	if err != nil {
		return oops.Wrapf(err, "failed to get router identity hash")
	}
	identHashBytes := identHash.Bytes()
	t.logger.WithField("router_hash", fmt.Sprintf("%x", identHashBytes[:8])).Info("Updating NTCP2 transport identity")
	return nil
}

// createNTCP2ConfigFromIdentity creates a new NTCP2 configuration from the provided router identity.
func (t *NTCP2Transport) createNTCP2ConfigFromIdentity(ident router_info.RouterInfo) (*ntcp2.NTCP2Config, error) {
	identityHash, err := ident.IdentHash()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to get router identity hash")
	}
	ntcp2Config, err := ntcp2.NewNTCP2Config(identityHash, false)
	if err != nil {
		t.logger.WithError(err).Error("Failed to create new NTCP2 config for identity update")
		return nil, WrapNTCP2Error(err, "updating identity")
	}
	return ntcp2Config, nil
}

// recreateListenerIfNeeded recreates the network listener with new identity if one exists.
// Holds identityMu to protect concurrent access to t.listener.
func (t *NTCP2Transport) recreateListenerIfNeeded(ntcp2Config *ntcp2.NTCP2Config) error {
	t.identityMu.Lock()
	if t.listener == nil {
		t.identityMu.Unlock()
		return nil
	}

	t.logger.Info("Recreating listener with new identity")
	t.closeExistingListenerLocked()
	t.identityMu.Unlock()

	listener, err := t.createNewListenerWithConfig(ntcp2Config)
	if err != nil {
		return err
	}

	t.identityMu.Lock()
	t.listener = listener
	t.logger.WithField("address", t.listener.Addr().String()).Info("Listener recreated successfully")
	t.identityMu.Unlock()
	return nil
}

// closeExistingListenerLocked closes the current listener and logs any errors.
// Must be called with identityMu held.
func (t *NTCP2Transport) closeExistingListenerLocked() {
	if err := t.listener.Close(); err != nil {
		t.logger.WithError(err).Warn("Error closing existing listener during identity update")
	}
}

// createNewListenerWithConfig creates a new TCP and NTCP2 listener with the provided configuration.
func (t *NTCP2Transport) createNewListenerWithConfig(ntcp2Config *ntcp2.NTCP2Config) (net.Listener, error) {
	tcpListener, err := net.Listen("tcp", t.config.ListenerAddress)
	if err != nil {
		t.logger.WithError(err).Error("Failed to rebind listener")
		return nil, WrapNTCP2Error(err, "rebinding listener")
	}

	listener, err := ntcp2.NewNTCP2Listener(tcpListener, ntcp2Config)
	if err != nil {
		// Close the TCP listener to prevent file descriptor leak.
		if closeErr := tcpListener.Close(); closeErr != nil {
			t.logger.WithError(closeErr).Warn("Failed to close TCP listener after NTCP2 listener creation failure")
		}
		t.logger.WithError(err).Error("Failed to create new NTCP2 listener")
		return nil, WrapNTCP2Error(err, "creating new listener")
	}

	return listener, nil
}

// GetSession obtains a transport session with a router given its RouterInfo.
func (t *NTCP2Transport) GetSession(routerInfo router_info.RouterInfo) (transport.TransportSession, error) {
	routerHash, err := routerInfo.IdentHash()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to get router hash")
	}
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
	session, exists := t.sessions.Load(routerHash)
	if !exists {
		t.logNoSessionFound(routerHash)
		return nil, false
	}

	if ntcp2Session, ok := session.(*NTCP2Session); ok {
		return t.validateExistingSession(ntcp2Session, routerHash)
	}

	if conn, ok := session.(net.Conn); ok {
		return t.promoteInboundConnection(conn, session, routerHash)
	}

	t.logNoSessionFound(routerHash)
	return nil, false
}

// validateExistingSession checks whether an existing NTCP2 session is still
// alive. If stale, it evicts the session and returns false.
func (t *NTCP2Transport) validateExistingSession(s *NTCP2Session, routerHash data.Hash) (transport.TransportSession, bool) {
	if s.ctx.Err() != nil {
		routerHashBytes := routerHash.Bytes()
		t.logger.WithFields(map[string]interface{}{
			"router_hash": fmt.Sprintf("%x", routerHashBytes[:8]),
			"reason":      s.ctx.Err().Error(),
		}).Info("Evicting stale NTCP2 session")
		if _, loaded := t.sessions.LoadAndDelete(routerHash); loaded {
			atomic.AddInt32(&t.sessionCount, -1)
		}
		return nil, false
	}
	routerHashBytes := routerHash.Bytes()
	t.logger.WithFields(map[string]interface{}{
		"router_hash":     fmt.Sprintf("%x", routerHashBytes[:8]),
		"send_queue_size": s.SendQueueSize(),
	}).Info("Reusing existing NTCP2 session")
	return s, true
}

// promoteInboundConnection promotes a raw inbound net.Conn to a full
// NTCP2Session using CompareAndSwap to prevent double-promotion races.
// Uses NewNTCP2SessionDeferred to avoid starting workers before CAS succeeds,
// matching the pattern in resolveExistingSession.
func (t *NTCP2Transport) promoteInboundConnection(conn net.Conn, original interface{}, routerHash data.Hash) (transport.TransportSession, bool) {
	promoted := NewNTCP2SessionDeferred(conn, t.ctx, t.logger)
	if t.sessions.CompareAndSwap(routerHash, original, promoted) {
		// Set cleanup callback AFTER the CAS succeeds, so only the winning
		// session's cleanup can affect the session map. If set before CAS,
		// the losing session's Close() would invoke removeSession() and
		// delete the winner's entry.
		promoted.SetCleanupCallback(func() {
			t.removeSession(routerHash)
		})
		promoted.StartWorkers()
		routerHashBytes := routerHash.Bytes()
		t.logger.WithFields(map[string]interface{}{
			"router_hash": fmt.Sprintf("%x", routerHashBytes[:8]),
		}).Info("Promoted inbound net.Conn to NTCP2Session")
		return promoted, true
	}
	// Another goroutine won the promotion race — close our duplicate
	// No cleanup callback is set, so Close() won't affect the session map
	_ = promoted.Close()
	if winner, exists := t.sessions.Load(routerHash); exists {
		if winnerSession, ok := winner.(*NTCP2Session); ok {
			return winnerSession, true
		}
	}
	return nil, false
}

// logNoSessionFound logs that no existing session was found for the given hash.
func (t *NTCP2Transport) logNoSessionFound(routerHash data.Hash) {
	routerHashBytes := routerHash.Bytes()
	t.logger.WithField("router_hash", fmt.Sprintf("%x", routerHashBytes[:8])).Debug("No existing session found")
}

func (t *NTCP2Transport) createOutboundSession(routerInfo router_info.RouterInfo, routerHash data.Hash) (transport.TransportSession, error) {
	routerHashBytes := routerHash.Bytes()

	// Enforce connection pool limit before dialing (reserves a session slot atomically)
	if err := t.checkSessionLimit(); err != nil {
		t.logger.WithFields(map[string]interface{}{
			"router_hash":   fmt.Sprintf("%x", routerHashBytes[:8]),
			"session_count": t.GetSessionCount(),
			"max_sessions":  t.config.GetMaxSessions(),
		}).Warn("Connection pool full, rejecting outbound session")
		return nil, err
	}

	t.logger.WithField("router_hash", fmt.Sprintf("%x", routerHashBytes[:8])).Info("Creating new outbound NTCP2 session")

	if n := t.getPeerConnNotifier(); n != nil {
		n.RecordAttempt(routerHash)
	}
	dialStart := time.Now()
	conn, err := t.dialNTCP2Connection(routerInfo)
	if err != nil {
		t.handleDialFailure(routerHash, routerHashBytes, err)
		return nil, err
	}

	return t.finalizeOutboundSession(conn, routerHash, routerHashBytes, dialStart)
}

// handleDialFailure releases the reserved session slot and records dial failure metrics.
func (t *NTCP2Transport) handleDialFailure(routerHash data.Hash, routerHashBytes [32]byte, err error) {
	t.unreserveSessionSlot()
	t.logger.WithError(err).WithField("router_hash", fmt.Sprintf("%x", routerHashBytes[:8])).Debug("Failed to dial NTCP2 connection")
	if n := t.getPeerConnNotifier(); n != nil {
		if errors.Is(err, ErrInvalidRouterInfo) {
			n.RecordPermanentFailure(routerHash, "no_reachable_ntcp2_address")
		} else {
			n.RecordFailure(routerHash, err.Error())
		}
	}
	// On EOF the peer likely rotated its static key; evict the cached RI.
	if errors.Is(err, io.EOF) {
		if r := t.routerInfoRefresher; r != nil {
			go r.RequestRouterInfoRefresh(routerHash)
		}
	}
}

// finalizeOutboundSession sets up the session object and records success metrics.
func (t *NTCP2Transport) finalizeOutboundSession(conn *ntcp2.NTCP2Conn, routerHash data.Hash, routerHashBytes [32]byte, dialStart time.Time) (transport.TransportSession, error) {
	session := t.setupSession(conn, routerHash)
	if session == nil {
		return nil, oops.Errorf("failed to set up session for %x: corrupt session map entry, connection closed", routerHashBytes[:8])
	}
	if n := t.getPeerConnNotifier(); n != nil {
		n.RecordSuccess(routerHash, time.Since(dialStart).Milliseconds())
	}
	t.logger.WithFields(map[string]interface{}{
		"router_hash": fmt.Sprintf("%x", routerHashBytes[:8]),
		"remote_addr": conn.RemoteAddr().String(),
	}).Info("Successfully created outbound NTCP2 session")
	return session, nil
}

func (t *NTCP2Transport) dialNTCP2Connection(routerInfo router_info.RouterInfo) (*ntcp2.NTCP2Conn, error) {
	ntcp2Addr, tcpAddrString, err := t.extractNTCP2AddressInfo(routerInfo)
	if err != nil {
		return nil, err
	}

	config, err := t.createNTCP2Config(routerInfo)
	if err != nil {
		t.logger.WithError(err).Error("Failed to create NTCP2 config for outbound connection")
		return nil, err
	}

	peerHashBytes := t.getPeerHashBytes(routerInfo)
	t.logTCPConnectionAttempt(tcpAddrString, peerHashBytes)

	tcpDialStart := time.Now()
	// Note: Previously there was a separate testTCPConnection() call here that would
	// dial, immediately close, then dial again in performNTCP2Handshake. This doubled
	// connection attempts, wasted file descriptors, and added latency. The actual
	// NTCP2 handshake will fail with appropriate diagnostics if TCP is unreachable.

	return t.performNTCP2Handshake(ntcp2Addr, tcpAddrString, peerHashBytes, config, tcpDialStart)
}

// extractNTCP2AddressInfo extracts the NTCP2 address and TCP address string from router info.
func (t *NTCP2Transport) extractNTCP2AddressInfo(routerInfo router_info.RouterInfo) (net.Addr, string, error) {
	ntcp2Addr, err := ExtractNTCP2Addr(routerInfo)
	if err != nil {
		t.logger.WithError(err).Debug("Failed to extract NTCP2 address from RouterInfo")
		return nil, "", WrapNTCP2Error(err, "extracting NTCP2 address")
	}

	// Extract the underlying TCP address for raw connection test
	// ntcp2Addr.String() returns "ntcp2://hash/initiator/ip:port" format
	// We need just the "ip:port" part for net.DialTimeout
	var tcpAddrString string
	if ntcpAddr, ok := ntcp2Addr.(*ntcp2.NTCP2Addr); ok {
		// NTCP2Addr has an UnderlyingAddr() method that returns the wrapped net.Addr
		underlyingAddr := ntcpAddr.UnderlyingAddr()
		tcpAddrString = underlyingAddr.String()
	} else {
		// Fallback to string representation (shouldn't happen)
		tcpAddrString = ntcp2Addr.String()
	}

	t.logger.WithField("remote_addr", ntcp2Addr.String()).Debug("Extracted NTCP2 address")
	return ntcp2Addr, tcpAddrString, nil
}

// getPeerHashBytes extracts the peer hash bytes from router info.
func (t *NTCP2Transport) getPeerHashBytes(routerInfo router_info.RouterInfo) []byte {
	peerHash, _ := routerInfo.IdentHash()
	hashBytes := peerHash.Bytes()
	return hashBytes[:]
}

// logTCPConnectionAttempt logs the start of a TCP connection attempt.
func (t *NTCP2Transport) logTCPConnectionAttempt(tcpAddrString string, peerHashBytes []byte) {
	t.logger.WithFields(map[string]interface{}{
		"remote_addr": tcpAddrString,
		"peer_hash":   fmt.Sprintf("%x", peerHashBytes[:8]),
	}).Debug("Attempting raw TCP connection before noise handshake")
	t.logger.Infof("Attempting TCP connection to peer at %s (hash: %x...)", tcpAddrString, peerHashBytes[:8])
}

// performNTCP2Handshake performs the NTCP2 handshake after successful TCP connection.
// The handshake is split into two phases: TCP dial + Noise wrapping (no handshake),
// followed by a manual Handshake() call. This allows us to apply probing resistance
// (random delay + junk read) on handshake failure, so that both sides are
// indistinguishable from a random TCP service to an active prober.
//
// The TCP dial uses a 10 s context deadline (reduced from 30 s; P0.2) which is
// sufficient for reachable peers and avoids holding goroutines for 30 s against
// hosts that silently drop SYN packets.
//
// Spec reference: https://geti2p.net/spec/ntcp2#probing-resistance
func (t *NTCP2Transport) performNTCP2Handshake(ntcp2Addr net.Addr, tcpAddrString string, peerHashBytes []byte, config *ntcp2.NTCP2Config, tcpDialStart time.Time) (*ntcp2.NTCP2Conn, error) {
	t.logger.WithField("remote_addr", ntcp2Addr.String()).Info("Dialing NTCP2 connection")

	// Phase 1a: TCP dial with a 10 s deadline (P0.2: reduced from 30 s to avoid
	// blocking goroutines for 30 s against hosts that silently drop SYN packets).
	dialCtx, dialCancel := context.WithTimeout(t.ctx, 10*time.Second)
	defer dialCancel()
	tcpDialer := &net.Dialer{}
	tcpConn, err := tcpDialer.DialContext(dialCtx, "tcp", tcpAddrString)
	if err != nil {
		handshakeDuration := time.Since(tcpDialStart)
		t.logHandshakeFailure(tcpAddrString, peerHashBytes, err, handshakeDuration)
		return nil, WrapNTCP2Error(err, "dialing NTCP2 connection (TCP)")
	}

	// Phase 1b: Wrap the established TCP connection in NTCP2Conn (no handshake yet).
	conn, err := ntcp2.WrapNTCP2Conn(tcpConn, config)
	if err != nil {
		tcpConn.Close()
		handshakeDuration := time.Since(tcpDialStart)
		t.logHandshakeFailure(tcpAddrString, peerHashBytes, err, handshakeDuration)
		return nil, WrapNTCP2Error(err, "wrapping NTCP2 connection")
	}

	// Phase 2: Perform the NTCP2 wire-format handshake (no framing, 16-byte options block).
	handshakeStart := time.Now()
	ctx := t.ctx
	if err := conn.Handshake(ctx); err != nil {
		handshakeDuration := time.Since(handshakeStart)
		t.logHandshakeFailure(tcpAddrString, peerHashBytes, err, handshakeDuration)

		// Apply probing resistance: random delay + junk read before closing.
		// Both initiator and responder must behave identically on failure.
		raw := extractRawConn(conn.UnderlyingConn())
		t.logger.WithError(err).Debug("Outbound handshake failed, applying probing resistance")
		applyProbingResistance(raw)
		_ = conn.Close()
		return nil, WrapNTCP2Error(err, "NTCP2 handshake (probing resistance applied)")
	}

	t.logger.WithFields(map[string]interface{}{
		"remote_addr":       tcpAddrString,
		"peer_hash":         fmt.Sprintf("%x", peerHashBytes[:8]),
		"total_duration_ms": time.Since(tcpDialStart).Milliseconds(),
	}).Info("NTCP2 connection established")
	return conn, nil
}

// logHandshakeFailure logs detailed diagnostics for an NTCP2 handshake failure.
// This includes TCP-level failures since we now do a single connection attempt.
func (t *NTCP2Transport) logHandshakeFailure(tcpAddrString string, peerHashBytes []byte, err error, handshakeDuration time.Duration) {
	// Determine if this was a TCP-level failure or handshake-level failure
	errorType := classifyDialError(err)
	isTCPFailure := errorType == "timeout" || errorType == "connection_refused" ||
		errorType == "host_unreachable" || errorType == "no_route" || errorType == "network_unreachable"

	// IPv6 connectivity diagnostics
	isIPv6 := strings.Contains(tcpAddrString, "[")

	phase := "noise_handshake"
	impact := "cannot establish secure channel"
	if isTCPFailure {
		phase = "tcp_dial"
		impact = "network unreachable - check firewall/routing"
	}

	fields := map[string]interface{}{
		"remote_addr":    tcpAddrString,
		"peer_hash":      fmt.Sprintf("%x", peerHashBytes[:8]),
		"peer_hash_full": fmt.Sprintf("%x", peerHashBytes),
		"error_type":     errorType,
		"error_message":  err.Error(),
		"duration_ms":    handshakeDuration.Milliseconds(),
		"syscall_error":  getSyscallError(err),
		"is_ipv6":        isIPv6,
		"phase":          phase,
		"impact":         impact,
	}

	// IPv6 peers on an IPv4-only host will always fail with ENETUNREACH.
	// This is a known, persistent, expected condition — log at Debug to
	// avoid inflating the error rate with non-actionable noise.
	if isIPv6 && errorType == "network_unreachable" {
		t.logger.WithFields(fields).Debug("Skipping IPv6 peer — no IPv6 connectivity on this host")
		return
	}

	// Handshake rejections (EOF / connection reset during noise handshake) are
	// expected when a new router joins the network — remote peers may not
	// recognise our identity and close immediately. Log at Warn, not Error.
	isExpectedRejection := errorType == "handshake_rejected_eof" || errorType == "connection_reset"
	if isExpectedRejection {
		t.logger.WithFields(fields).Warn("NTCP2 handshake rejected by peer")
	} else {
		t.logger.WithFields(fields).Warn("Failed to dial NTCP2 connection")
	}

	if isTCPFailure {
		t.logger.WithFields(fields).Debug("TCP connection failed (details in structured fields above)")
	}
}

// classifyDialError categorizes network dial errors for structured logging
func classifyDialError(err error) string {
	if err == nil {
		return "none"
	}

	errStr := err.Error()
	switch {
	case strings.Contains(errStr, "timeout"):
		return "timeout"
	case strings.Contains(errStr, "refused"):
		return "connection_refused"
	case strings.Contains(errStr, "network is unreachable"):
		return "network_unreachable"
	case strings.Contains(errStr, "no route"):
		return "no_route"
	case strings.Contains(errStr, "unreachable"):
		// Catch-all for other unreachable errors (e.g., "host unreachable",
		// "no route to host"). Must come after the more specific "network is
		// unreachable" check above.
		return "host_unreachable"
	case strings.Contains(errStr, "EOF"):
		return "handshake_rejected_eof"
	case strings.Contains(errStr, "connection reset"):
		return "connection_reset"
	case strings.Contains(errStr, "handshake"):
		return "handshake_failed"
	case strings.Contains(errStr, "context canceled"):
		return "canceled"
	default:
		return "unknown"
	}
}

// getSyscallError extracts syscall error details from network errors
func getSyscallError(err error) string {
	if err == nil {
		return "none"
	}

	// Unwrap to find syscall.Errno
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Err != nil {
			var syscallErr syscall.Errno
			if errors.As(opErr.Err, &syscallErr) {
				return fmt.Sprintf("syscall.Errno(%d): %s", syscallErr, syscallErr.Error())
			}
			return fmt.Sprintf("op_error: %s", opErr.Err.Error())
		}
	}

	return "not_syscall_error"
}

func (t *NTCP2Transport) createNTCP2Config(routerInfo router_info.RouterInfo) (*ntcp2.NTCP2Config, error) {
	remoteHash, err := routerInfo.IdentHash()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to get remote router hash")
	}

	t.identityMu.RLock()
	ourStaticKey := t.config.NTCP2Config.StaticKey
	t.identityMu.RUnlock()

	config, err := ntcp2.NewNTCP2Config(remoteHash, true)
	if err != nil {
		return nil, WrapNTCP2Error(err, "creating NTCP2 config")
	}

	config.WithStaticKey(ourStaticKey)
	config = config.WithRemoteRouterHash(remoteHash)

	if err := ConfigureDialConfig(config, routerInfo); err != nil {
		t.logger.WithError(err).Error("Cannot extract peer static key for NTCP2 XK handshake - peer RouterInfo is missing required 's=' option")
		return nil, WrapNTCP2Error(err, "extracting peer NTCP2 static key")
	}

	if err := t.attachLocalRouterInfo(config); err != nil {
		return nil, err
	}

	return config, nil
}

// attachLocalRouterInfo serializes our RouterInfo and attaches it to the config for msg3.
func (t *NTCP2Transport) attachLocalRouterInfo(config *ntcp2.NTCP2Config) error {
	t.identityMu.RLock()
	localRI := t.identity
	t.identityMu.RUnlock()
	riBytes, err := localRI.Bytes()
	if err != nil {
		return oops.Wrapf(err, "cannot serialize local RouterInfo for NTCP2 msg3")
	}
	addrCount := localRI.RouterAddressCount()
	sigValid, sigErr := localRI.VerifySignature()
	t.logger.WithFields(map[string]interface{}{
		"ri_bytes_len":    len(riBytes),
		"ri_addr_count":   addrCount,
		"sig_valid":       sigValid,
		"sig_verify_err":  fmt.Sprintf("%v", sigErr),
		"ri_bytes_prefix": fmt.Sprintf("%x", riBytes[:min(16, len(riBytes))]),
		"ri_bytes_suffix": fmt.Sprintf("%x", riBytes[max(0, len(riBytes)-16):]),
	}).Info("LocalRouterInfo for msg3 outbound")
	config.WithLocalRouterInfo(riBytes)
	return nil
}

func (t *NTCP2Transport) setupSession(conn *ntcp2.NTCP2Conn, routerHash data.Hash) *NTCP2Session {
	// Create session WITHOUT starting workers to avoid spawning goroutines
	// that may be immediately discarded if an existing session wins the race.
	session := NewNTCP2SessionDeferred(conn, t.ctx, t.logger)

	existing, loaded := t.sessions.LoadOrStore(routerHash, session)
	if loaded {
		// A session already exists for this peer. Close the newly created
		// session (no workers running, just closes conn and channels) and
		// return the existing one. Release the reserved session slot.
		_ = session.Close()
		t.unreserveSessionSlot()
		resolved := t.resolveExistingSession(existing, routerHash)
		if resolved == nil {
			// resolveExistingSession encountered an unexpected map entry type.
			// Delete the corrupt entry. We cannot reuse 'conn' because
			// session.Close() already closed it — return nil to signal failure.
			t.sessions.Delete(routerHash)
			routerHashBytes := routerHash.Bytes()
			t.logger.WithFields(map[string]interface{}{
				"router_hash": fmt.Sprintf("%x", routerHashBytes[:8]),
			}).Error("setupSession: corrupt session map entry deleted, connection already closed — caller must re-dial")
			return nil
		}
		return resolved
	}

	// We won the store — start workers and wire up the cleanup callback.
	// The session slot was already reserved by checkSessionLimit.
	session.StartWorkers()
	session.SetCleanupCallback(func() {
		t.removeSession(routerHash)
	})
	return session
}

// resolveExistingSession safely extracts or promotes an existing session map
// entry to *NTCP2Session. Accept() stores raw net.Conn values while
// setupSession stores *NTCP2Session values; this method handles both types
// to prevent a type assertion panic when the two race.
func (t *NTCP2Transport) resolveExistingSession(existing interface{}, routerHash data.Hash) *NTCP2Session {
	// Fast path: already an NTCP2Session.
	if ntcp2Session, ok := existing.(*NTCP2Session); ok {
		return ntcp2Session
	}

	// Slow path: Accept() stored a raw net.Conn. Promote it to a full
	// NTCP2Session so the caller gets a usable session object.
	if rawConn, ok := existing.(net.Conn); ok {
		// Use deferred session creation to avoid starting workers before
		// we've confirmed this goroutine wins the CAS race. Workers on
		// a losing session would share the same conn, causing errors.
		promoted := NewNTCP2SessionDeferred(rawConn, t.ctx, t.logger)
		// NOTE: Do NOT set the cleanup callback before CAS. If this
		// goroutine loses the race, calling promoted.Close() would
		// trigger removeSession and delete the *winner's* map entry.
		if t.sessions.CompareAndSwap(routerHash, existing, promoted) {
			promoted.SetCleanupCallback(func() {
				t.removeSession(routerHash)
			})
			promoted.StartWorkers()
			routerHashBytes := routerHash.Bytes()
			t.logger.WithFields(map[string]interface{}{
				"router_hash": fmt.Sprintf("%x", routerHashBytes[:8]),
			}).Info("Promoted inbound net.Conn to NTCP2Session in setupSession")
			return promoted
		}
		// Another goroutine won the promotion race — discard ours and
		// return whatever is in the map now. No cleanup callback was
		// set and no workers were started, so Close() is lightweight.
		_ = promoted.Close()
		if winner, exists := t.sessions.Load(routerHash); exists {
			if winnerSession, ok := winner.(*NTCP2Session); ok {
				return winnerSession
			}
		}
	}

	// Should not reach here in practice. Log an error and return a
	// descriptive error via a nil session — callers must check for nil.
	t.logger.Error("resolveExistingSession: unexpected session map entry type — returning nil")
	return nil
}

// checkSessionLimit returns ErrConnectionPoolFull if the maximum number of
// concurrent sessions has been reached. Uses atomic compare-and-swap to
// reserve a session slot, preventing TOCTOU races under concurrent access.
// If the caller does not actually use the slot, they must call unreserveSessionSlot.
func (t *NTCP2Transport) checkSessionLimit() error {
	maxSessions := t.config.GetMaxSessions()
	for {
		current := atomic.LoadInt32(&t.sessionCount)
		if int(current) >= maxSessions {
			t.logger.WithFields(map[string]interface{}{
				"current_sessions": int(current),
				"max_sessions":     maxSessions,
			}).Warn("Session limit reached")
			return ErrConnectionPoolFull
		}
		// Atomically reserve a slot
		if atomic.CompareAndSwapInt32(&t.sessionCount, current, current+1) {
			return nil
		}
		// CAS failed — another goroutine changed the count, retry
	}
}

// unreserveSessionSlot releases a session slot reserved by checkSessionLimit
// when the session was not actually established (e.g., handshake failure).
// Uses CAS loop to prevent the counter from going negative.
func (t *NTCP2Transport) unreserveSessionSlot() {
	for {
		current := atomic.LoadInt32(&t.sessionCount)
		if current <= 0 {
			t.logger.Warn("unreserveSessionSlot called but session count is already zero")
			return
		}
		if atomic.CompareAndSwapInt32(&t.sessionCount, current, current-1) {
			return
		}
	}
}

// Compatible returns true if a routerInfo is compatible with this transport.
// It checks that the RouterInfo has at least one directly dialable NTCP2 address
// (i.e., one with a valid host and port), not just any NTCP2 address listing.
func (t *NTCP2Transport) Compatible(routerInfo router_info.RouterInfo) bool {
	dialable := HasDialableNTCP2Address(&routerInfo)
	routerHash, err := routerInfo.IdentHash()
	if err != nil {
		t.logger.WithError(err).Warn("Failed to get router hash for compatibility check")
		return dialable
	}
	routerHashBytes := routerHash.Bytes()
	t.logger.WithFields(map[string]interface{}{
		"router_hash": fmt.Sprintf("%x", routerHashBytes[:8]),
		"dialable":    dialable,
	}).Debug("Checking NTCP2 compatibility")
	return dialable
}

// removeSession removes a session from the session map (called by session cleanup callback)
func (t *NTCP2Transport) removeSession(routerHash data.Hash) {
	routerHashBytes := routerHash.Bytes()
	if _, loaded := t.sessions.LoadAndDelete(routerHash); loaded {
		atomic.AddInt32(&t.sessionCount, -1)
	}
	t.logger.WithField("router_hash", fmt.Sprintf("%x", routerHashBytes[:8])).Info("Removed session from transport session map")
}

// GetSessionCount returns the number of active sessions managed by this transport.
// Uses an atomic counter for O(1) performance instead of iterating the session map.
func (t *NTCP2Transport) GetSessionCount() int {
	return int(atomic.LoadInt32(&t.sessionCount))
}

// GetTotalBandwidth returns the total bytes sent and received across all active sessions.
// This aggregates bandwidth statistics from all sessions managed by this transport.
func (t *NTCP2Transport) GetTotalBandwidth() (totalBytesSent, totalBytesReceived uint64) {
	t.sessions.Range(func(key, value interface{}) bool {
		if session, ok := value.(*NTCP2Session); ok {
			sent, received := session.GetBandwidthStats()
			totalBytesSent += sent
			totalBytesReceived += received
		}
		return true // Continue iteration
	})
	t.logger.WithFields(map[string]interface{}{
		"total_bytes_sent":     totalBytesSent,
		"total_bytes_received": totalBytesReceived,
	}).Debug("Aggregated bandwidth across all sessions")
	return totalBytesSent, totalBytesReceived
}

// Close closes the transport cleanly.
func (t *NTCP2Transport) Close() error {
	t.closeOnce.Do(func() {
		t.logger.Info("Closing NTCP2 transport")

		t.cancelTransportContext()
		listenerErr := t.closeNetworkListener()
		t.closeAllActiveSessions()
		t.waitForBackgroundOperations()

		t.closeErr = t.handleCloseCompletion(listenerErr)
	})
	return t.closeErr
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
		if _, loaded := t.sessions.LoadAndDelete(key); loaded {
			atomic.AddInt32(&t.sessionCount, -1)
		}
		return true
	})

	t.logger.WithField("session_count", sessionCount).Info("Closed all sessions")
}

// closeIndividualSession closes a single session and logs any errors.
// Handles both *NTCP2Session values (from setupSession) and raw net.Conn
// values (from Accept, not yet promoted) to prevent connection leaks on shutdown.
func (t *NTCP2Transport) closeIndividualSession(key, value interface{}) {
	routerHash, hashOk := key.(data.Hash)

	switch v := value.(type) {
	case *NTCP2Session:
		if err := v.Close(); err != nil && hashOk {
			routerHashBytes := routerHash.Bytes()
			t.logger.WithError(err).WithField("router_hash", fmt.Sprintf("%x", routerHashBytes[:8])).Warn("Error closing session")
		}
	case net.Conn:
		// Raw net.Conn stored by Accept() but never promoted to *NTCP2Session.
		if err := v.Close(); err != nil && hashOk {
			routerHashBytes := routerHash.Bytes()
			t.logger.WithError(err).WithField("router_hash", fmt.Sprintf("%x", routerHashBytes[:8])).Warn("Error closing raw inbound connection")
		}
	default:
		t.logger.Warn("Unexpected session map entry type during shutdown")
	}
}

// waitForBackgroundOperations blocks until all background goroutines complete.
func (t *NTCP2Transport) waitForBackgroundOperations() {
	t.logger.Debug("Waiting for background operations to complete")
	t.wg.Wait()
}

// handleCloseCompletion processes the final close status and returns appropriate error.
func (t *NTCP2Transport) handleCloseCompletion(listenerErr error) error {
	// Close the handler to stop replay cache cleanup goroutine.
	if t.handler != nil {
		t.handler.Close()
	}

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
