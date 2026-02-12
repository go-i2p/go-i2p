package ntcp2

import (
	"context"
	"errors"
	"fmt"
	"net"
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
)

type NTCP2Transport struct {
	// Network listener (uses net.Listener interface per guidelines)
	listener net.Listener // Will be *ntcp2.NTCP2Listener internally

	// Configuration
	config   *Config
	identity router_info.RouterInfo

	// Keystore for crypto key initialization (needed by SetIdentity)
	keystore KeystoreProvider

	// Session management
	sessions     sync.Map // map[string]*NTCP2Session (keyed by router hash)
	sessionCount int32    // atomic O(1) session counter

	// Lifecycle management
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Logging
	logger *logger.Entry
}

type KeystoreProvider interface {
	GetEncryptionPrivateKey() types.PrivateEncryptionKey
}

func NewNTCP2Transport(identity router_info.RouterInfo, config *Config, keystore KeystoreProvider) (*NTCP2Transport, error) {
	ctx, cancel := context.WithCancel(context.Background())
	logger := logger.WithField("component", "ntcp2")

	identHash, err := identity.IdentHash()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to get router identity hash: %w", err)
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
		return nil, fmt.Errorf("failed to get router identity hash: %w", err)
	}
	identityBytes := identHash.Bytes()
	ntcp2Config, err := ntcp2.NewNTCP2Config(identityBytes[:], false)
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
		return WrapNTCP2Error(fmt.Errorf("encryption private key is nil"), "retrieving encryption key from keystore")
	}

	// Use the encryption private key as the NTCP2 static key
	ntcp2Config.StaticKey = encryptionPrivKey.Bytes()
	if len(ntcp2Config.StaticKey) != 32 {
		if cancel != nil {
			cancel()
		}
		return WrapNTCP2Error(fmt.Errorf("invalid static key size: expected 32 bytes, got %d", len(ntcp2Config.StaticKey)), "loading static key")
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
		ctx:      ctx,
		cancel:   cancel,
		logger:   logger,
		wg:       sync.WaitGroup{},
		sessions: sync.Map{},
	}
}

// setupNetworkListener creates and attaches the TCP and NTCP2 listeners to the transport.
func setupNetworkListener(transport *NTCP2Transport, config *Config, ntcp2Config *ntcp2.NTCP2Config) error {
	// Here's where we do NAT traversal if needed (not implemented yet)
	// uses github.com/go-i2p/go-nat-listener

	tcpListener, err := net.Listen("tcp", config.ListenerAddress)
	if err != nil {
		return fmt.Errorf("failed to create TCP listener: %w", err)
	}
	/*
		This works now, but it's disabled until we can test it properly.
			_, port, err := net.SplitHostPort(config.ListenerAddress)
			if err != nil {
				return fmt.Errorf("invalid listener address: %w", err)
			}
			iport, err := strconv.Atoi(port)
			if err != nil {
				return fmt.Errorf("invalid listener port: %w", err)
			}
			tcpListener, err := nattraversal.ListenWithFallback(iport)
			if err != nil {
				log.Fatal("Failed to create listener:", err)
			}
	*/

	listener, err := ntcp2.NewNTCP2Listener(tcpListener, ntcp2Config)
	if err != nil {
		return err
	}

	transport.listener = listener
	return nil
}

// Accept accepts an incoming session.
// The accepted connection is tracked in the transport's session map so that
// GetSessionCount() and checkSessionLimit() accurately reflect both inbound
// and outbound sessions. A cleanup callback is registered to remove the
// tracking entry when the connection is closed.
func (t *NTCP2Transport) Accept() (net.Conn, error) {
	if t.listener == nil {
		t.logger.Error("Accept called but listener is nil")
		return nil, ErrSessionClosed
	}

	// Enforce session limit before accepting (reserves a session slot atomically)
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
		t.unreserveSessionSlot() // Release the reserved slot on accept failure
		t.logger.WithError(err).Warn("Failed to accept incoming connection")
		return nil, err
	}

	// Track the inbound connection for accurate session counting.
	// We store the raw conn as a placeholder in the session map keyed by a hash
	// derived from the connection's remote address. This ensures GetSessionCount()
	// includes inbound connections and checkSessionLimit() prevents exceeding MaxSessions.
	// We do NOT create an NTCP2Session here because the router layer creates its own
	// session from the returned conn (in createSessionFromConn), and having two
	// sessions with send/receive workers on the same conn would corrupt the stream.
	peerHash := t.extractPeerHash(conn)
	if _, loaded := t.sessions.LoadOrStore(peerHash, conn); loaded {
		// Session already existed for this peer — release the reserved slot
		t.unreserveSessionSlot()
	}

	// Wrap the connection so that closing it also removes it from the session map,
	// preventing session counter drift.
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
	return wrappedConn, nil
}

// extractPeerHash extracts the peer's router hash from an accepted connection.
// Returns a hash derived from the NTCP2Addr if available, or a hash derived
// from the remote address as a fallback key for session map tracking.
func (t *NTCP2Transport) extractPeerHash(conn net.Conn) data.Hash {
	var peerHash data.Hash

	if ntcpAddr, ok := conn.RemoteAddr().(*ntcp2.NTCP2Addr); ok {
		hashBytes := ntcpAddr.RouterHash()
		if len(hashBytes) == 32 {
			copy(peerHash[:], hashBytes)
			// If the hash is non-zero, use it directly
			var zeroHash data.Hash
			if peerHash != zeroHash {
				return peerHash
			}
		}
	}

	// Fallback: generate a unique key from the remote address.
	// This handles the case where the noise handshake doesn't yet populate
	// the router hash (currently returns zeros for inbound connections).
	addrStr := conn.RemoteAddr().String()
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
func (tc *trackedConn) Close() error {
	err := tc.Conn.Close()
	tc.closeOnce.Do(tc.onClose)
	return err
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
	if err := t.logIdentityUpdate(ident); err != nil {
		return err
	}
	t.identity = ident

	ntcp2Config, err := t.createNTCP2ConfigFromIdentity(ident)
	if err != nil {
		return err
	}

	if err := initializeCryptoKeys(ntcp2Config, ident, t.keystore, t.config.WorkingDir, nil); err != nil {
		return fmt.Errorf("failed to reinitialize crypto keys after identity update: %w", err)
	}

	t.config.NTCP2Config = ntcp2Config

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
		return fmt.Errorf("failed to get router identity hash: %w", err)
	}
	identHashBytes := identHash.Bytes()
	t.logger.WithField("router_hash", fmt.Sprintf("%x", identHashBytes[:8])).Info("Updating NTCP2 transport identity")
	return nil
}

// createNTCP2ConfigFromIdentity creates a new NTCP2 configuration from the provided router identity.
func (t *NTCP2Transport) createNTCP2ConfigFromIdentity(ident router_info.RouterInfo) (*ntcp2.NTCP2Config, error) {
	identityHash, err := ident.IdentHash()
	if err != nil {
		return nil, fmt.Errorf("failed to get router identity hash: %w", err)
	}
	identityBytes := identityHash.Bytes()
	ntcp2Config, err := ntcp2.NewNTCP2Config(identityBytes[:], false)
	if err != nil {
		t.logger.WithError(err).Error("Failed to create new NTCP2 config for identity update")
		return nil, WrapNTCP2Error(err, "updating identity")
	}
	return ntcp2Config, nil
}

// recreateListenerIfNeeded recreates the network listener with new identity if one exists.
func (t *NTCP2Transport) recreateListenerIfNeeded(ntcp2Config *ntcp2.NTCP2Config) error {
	if t.listener == nil {
		return nil
	}

	t.logger.Info("Recreating listener with new identity")
	t.closeExistingListener()

	listener, err := t.createNewListenerWithConfig(ntcp2Config)
	if err != nil {
		return err
	}

	t.listener = listener
	t.logger.WithField("address", t.listener.Addr().String()).Info("Listener recreated successfully")
	return nil
}

// closeExistingListener closes the current listener and logs any errors.
func (t *NTCP2Transport) closeExistingListener() {
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
		t.logger.WithError(err).Error("Failed to create new NTCP2 listener")
		return nil, WrapNTCP2Error(err, "creating new listener")
	}

	return listener, nil
}

// GetSession obtains a transport session with a router given its RouterInfo.
func (t *NTCP2Transport) GetSession(routerInfo router_info.RouterInfo) (transport.TransportSession, error) {
	routerHash, err := routerInfo.IdentHash()
	if err != nil {
		return nil, fmt.Errorf("failed to get router hash: %w", err)
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
	if session, exists := t.sessions.Load(routerHash); exists {
		if ntcp2Session, ok := session.(*NTCP2Session); ok {
			// Check if the session is still alive (context not cancelled, connection not closed)
			if ntcp2Session.ctx.Err() != nil {
				routerHashBytes := routerHash.Bytes()
				t.logger.WithFields(map[string]interface{}{
					"router_hash": fmt.Sprintf("%x", routerHashBytes[:8]),
					"reason":      ntcp2Session.ctx.Err().Error(),
				}).Info("Evicting stale NTCP2 session")
				if _, loaded := t.sessions.LoadAndDelete(routerHash); loaded {
					atomic.AddInt32(&t.sessionCount, -1)
				}
				return nil, false
			}
			routerHashBytes := routerHash.Bytes()
			t.logger.WithFields(map[string]interface{}{
				"router_hash":     fmt.Sprintf("%x", routerHashBytes[:8]),
				"send_queue_size": ntcp2Session.SendQueueSize(),
			}).Info("Reusing existing NTCP2 session")
			return ntcp2Session, true
		}
		// Inbound connections are stored as net.Conn by Accept().
		// Promote the raw conn to a full NTCP2Session so that GetSession
		// can return it and we avoid creating a redundant outbound connection.
		if conn, ok := session.(net.Conn); ok {
			promoted := NewNTCP2Session(conn, t.ctx, t.logger)
			promoted.SetCleanupCallback(func() {
				t.removeSession(routerHash)
			})
			t.sessions.Store(routerHash, promoted)
			routerHashBytes := routerHash.Bytes()
			t.logger.WithFields(map[string]interface{}{
				"router_hash": fmt.Sprintf("%x", routerHashBytes[:8]),
			}).Info("Promoted inbound net.Conn to NTCP2Session")
			return promoted, true
		}
	}
	routerHashBytes := routerHash.Bytes()
	t.logger.WithField("router_hash", fmt.Sprintf("%x", routerHashBytes[:8])).Debug("No existing session found")
	return nil, false
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

	conn, err := t.dialNTCP2Connection(routerInfo)
	if err != nil {
		t.unreserveSessionSlot() // Release the reserved slot on dial failure
		t.logger.WithError(err).WithField("router_hash", fmt.Sprintf("%x", routerHashBytes[:8])).Debug("Failed to dial NTCP2 connection")
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

// testTCPConnection tests raw TCP connectivity before attempting NTCP2 handshake.
func (t *NTCP2Transport) testTCPConnection(tcpAddrString string, peerHashBytes []byte, tcpDialStart time.Time) error {
	tcpConn, tcpErr := net.DialTimeout("tcp", tcpAddrString, 30*time.Second)
	tcpDialDuration := time.Since(tcpDialStart)

	if tcpErr != nil {
		t.logTCPConnectionFailure(tcpAddrString, peerHashBytes, tcpErr, tcpDialDuration)
		return fmt.Errorf("TCP dial failed to %s: %w", tcpAddrString, tcpErr)
	}
	tcpConn.Close() // Close test connection

	t.logger.WithFields(map[string]interface{}{
		"remote_addr": tcpAddrString,
		"peer_hash":   fmt.Sprintf("%x", peerHashBytes[:8]),
		"duration_ms": tcpDialDuration.Milliseconds(),
	}).Info("TCP connection successful, attempting noise handshake")

	return nil
}

// logTCPConnectionFailure logs detailed diagnostics for a TCP connection failure.
func (t *NTCP2Transport) logTCPConnectionFailure(tcpAddrString string, peerHashBytes []byte, tcpErr error, tcpDialDuration time.Duration) {
	// BUG FIX #6: IPv6 connectivity diagnostics
	// TCP connection failed - log detailed diagnostics including protocol version
	isIPv6 := strings.Contains(tcpAddrString, "[")
	t.logger.WithFields(map[string]interface{}{
		"remote_addr":    tcpAddrString,
		"peer_hash":      fmt.Sprintf("%x", peerHashBytes[:8]),
		"peer_hash_full": fmt.Sprintf("%x", peerHashBytes),
		"error":          tcpErr.Error(),
		"error_type":     classifyDialError(tcpErr),
		"duration_ms":    tcpDialDuration.Milliseconds(),
		"syscall_error":  getSyscallError(tcpErr),
		"is_ipv6":        isIPv6,
		"phase":          "tcp_dial",
		"impact":         "network unreachable - check firewall/routing",
	}).Error("TCP connection failed before noise handshake")
	t.logger.Errorf("TCP connection FAILED to %s after %dms: %v (type: %s)",
		tcpAddrString, tcpDialDuration.Milliseconds(), tcpErr, classifyDialError(tcpErr))
}

// performNTCP2Handshake performs the NTCP2 handshake after successful TCP connection.
func (t *NTCP2Transport) performNTCP2Handshake(ntcp2Addr net.Addr, tcpAddrString string, peerHashBytes []byte, config *ntcp2.NTCP2Config, tcpDialStart time.Time) (*ntcp2.NTCP2Conn, error) {
	t.logger.WithField("remote_addr", ntcp2Addr.String()).Info("Dialing NTCP2 connection")
	handshakeStart := time.Now()
	conn, err := ntcp2.DialNTCP2WithHandshake("tcp", tcpAddrString, config)
	handshakeDuration := time.Since(handshakeStart)

	if err != nil {
		t.logHandshakeFailure(tcpAddrString, peerHashBytes, err, handshakeDuration)
		return nil, WrapNTCP2Error(err, "dialing NTCP2 connection")
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

	t.logger.WithFields(map[string]interface{}{
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
	}).Error("Failed to dial NTCP2 connection")

	if isTCPFailure {
		t.logger.Errorf("TCP connection FAILED to %s after %dms: %v (type: %s)",
			tcpAddrString, handshakeDuration.Milliseconds(), err, errorType)
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
	case strings.Contains(errStr, "unreachable"):
		return "host_unreachable"
	case strings.Contains(errStr, "no route"):
		return "no_route"
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
	identHash, err := t.identity.IdentHash()
	if err != nil {
		return nil, fmt.Errorf("failed to get our identity hash: %w", err)
	}
	identityBytes := identHash.Bytes()
	config, err := ntcp2.NewNTCP2Config(identityBytes[:], true)
	if err != nil {
		return nil, WrapNTCP2Error(err, "creating NTCP2 config")
	}

	remoteHash, err := routerInfo.IdentHash()
	if err != nil {
		return nil, fmt.Errorf("failed to get remote router hash: %w", err)
	}
	remoteHashBytes := remoteHash.Bytes()
	return config.WithRemoteRouterHash(remoteHashBytes[:]), nil
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
		session.Close()
		t.unreserveSessionSlot()
		return existing.(*NTCP2Session)
	}

	// We won the store — start workers and wire up the cleanup callback.
	// The session slot was already reserved by checkSessionLimit.
	session.StartWorkers()
	session.SetCleanupCallback(func() {
		t.removeSession(routerHash)
	})
	return session
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
func (t *NTCP2Transport) Compatible(routerInfo router_info.RouterInfo) bool {
	supported := SupportsNTCP2(&routerInfo)
	routerHash, err := routerInfo.IdentHash()
	if err != nil {
		t.logger.WithError(err).Warn("Failed to get router hash for compatibility check")
		// Still return compatibility result based on NTCP2 support
		return supported
	}
	routerHashBytes := routerHash.Bytes()
	t.logger.WithFields(map[string]interface{}{
		"router_hash": fmt.Sprintf("%x", routerHashBytes[:8]),
		"supported":   supported,
	}).Debug("Checking NTCP2 compatibility")
	return supported
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
		if _, loaded := t.sessions.LoadAndDelete(key); loaded {
			atomic.AddInt32(&t.sessionCount, -1)
		}
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
