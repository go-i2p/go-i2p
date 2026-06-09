package ntcp2

import (
	"context"
	"crypto/sha256"
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
	"github.com/go-i2p/go-i2p/lib/nat"
	"github.com/go-i2p/go-i2p/lib/transport"
	"github.com/go-i2p/go-noise/ntcp2"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// acceptedConn is a marker type wrapping a raw connection that has been
// delivered via Accept(). It prevents the connection from being promoted
// to a session (which would create dual ownership), since the Accept()
// consumer now owns the socket lifecycle.
type acceptedConn struct {
	net.Conn
}

// Session Map Ownership Invariant (X-3 fix):
// Each peerHash in the sessions map has EXACTLY ONE owner at any given time:
//   - rawConn (net.Conn): owned by trackInboundConnection, transferable to Accept or promotion
//   - acceptedConn: owned by the Accept() consumer; MUST NOT be promoted (dual-ownership)
//   - *NTCP2Session: owned by the session lifecycle; cleanup via removeSession
//
// State transitions use CompareAndSwap to prevent race conditions:
//   - rawConn → acceptedConn: CAS in inboundHandshakeWorker (after successful queue send)
//   - rawConn → *NTCP2Session: CAS in promoteInboundConnection (via GetSession)
//
// If inbound Accept CAS fails, a concurrent GetSession has already promoted the connection;
// do not deliver to Accept (ownership already transferred to the session).
// If promotion CAS fails, another goroutine won the race; close the duplicate session.
//
// NTCP2Transport implements the I2P NTCP2 transport protocol, managing listener setup, session lifecycle, and peer connections.
type NTCP2Transport struct {
	// Network listener (uses net.Listener interface per guidelines)
	listener net.Listener // Will be *ntcp2.Listener internally

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

	// routerInfoStorer persists peer RouterInfos learned during inbound NTCP2 handshakes
	// into the local NetDB. Set via SetRouterInfoStorer after construction.
	routerInfoStorer atomic.Value // stores transport.RouterInfoStorer

	// pendingConns receives fully-handshaked inbound connections ready for Accept().
	// Initialized lazily by startInboundAcceptRunner on the first Accept() call.
	pendingConns chan net.Conn

	// acceptRunOnce ensures the background inbound accept runner is started exactly once.
	acceptRunOnce sync.Once

	// Session management
	// sessions map[string]<value> where value can be:
	//  - net.Conn (raw inbound connection after trackInboundConnection, before Accept or promotion)
	//  - acceptedConn (wrapper marking ownership transferred to Accept() consumer - MUST NOT promote)
	//  - *NTCP2Session (fully established session)
	// State transitions (all use CompareAndSwap to prevent races):
	//  - net.Conn → acceptedConn (inboundHandshakeWorker after successful pendingConns send)
	//  - net.Conn → *NTCP2Session (promotion via GetSession or setupSession)
	// See "Session Map Ownership Invariant" comment above for details.
	sessions       sync.Map // map[string]*NTCP2Session (keyed by router hash)
	sessionCount   int32    // atomic O(1) session counter
	isShuttingDown int32    // atomic flag set during Close() for visibility (A-4: no longer used for accounting gating)

	// Metrics for critical bugs (X-1)
	acceptedConnPromotionAttempts int32 // atomic counter for bug detection: how many times promoteInboundConnection refused an acceptedConn

	// E-3 fix: Track RouterInfo store failures for observability and alerting.
	// Incremented when storeRouterInfoInNetDB fails (NetDB unavailable, parse errors, storage I/O failures).
	// High count indicates NetDB problems that break OBEP reply routing.
	routerInfoStoreFailures int32 // atomic counter

	// A-3 fix: Transport lifecycle and accounting metrics
	metrics transportMetrics

	// TEST ONLY: bypass *ntcp2.Conn type check in performInboundHandshake.
	// MUST NOT be set in production - allows un-handshaked connections (security risk).
	testBypassHandshakeTypeCheck bool

	// Protects identity, config.Config, and listener from concurrent
	// access by SetIdentity vs GetSession/Accept/Compatible.
	identityMu sync.RWMutex

	// Lifecycle management
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Port mapping lifecycle manager for UPnP/NAT-PMP (Phase 4 integration)
	portMapperManager *nat.PortMapperManager

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
	config.Config = ntcp2Config

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
func createNTCP2Config(identity router_info.RouterInfo, cancel context.CancelFunc) (*ntcp2.Config, error) {
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
func initializeCryptoKeys(ntcp2Config *ntcp2.Config, identity router_info.RouterInfo, keystore KeystoreProvider, workingDir string, cancel context.CancelFunc) error {
	if err := loadStaticKeyFromRouter(ntcp2Config, identity, keystore, cancel); err != nil {
		return err
	}
	return loadOrGenerateObfuscationIV(ntcp2Config, workingDir, cancel)
}

// loadStaticKeyFromRouter derives the NTCP2 static key from the router's encryption key.
// This ensures the static key is persistent (stored in RouterInfoKeystore) and consistent
// across router restarts, which is critical for peer recognition.
func loadStaticKeyFromRouter(ntcp2Config *ntcp2.Config, identity router_info.RouterInfo, keystore KeystoreProvider, cancel context.CancelFunc) error {
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
func loadOrGenerateObfuscationIV(ntcp2Config *ntcp2.Config, workingDir string, cancel context.CancelFunc) error {
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
//
// Note: On iOS, app sandbox restrictions prevent net.Listen on arbitrary ports
// without the com.apple.developer.networking.multipath entitlement or a
// NEPacketTunnelProvider extension. Attempting to listen will fail with EACCES.
// bindOSAssignedPort probes for an available OS-assigned port, closes the probe
// socket, and rebinds that port. To handle the TOCTOU race where another process
// may claim the port between probe and rebind, this function retries up to
// maxPortProbeRetries times. Each retry probes a new port and attempts rebind.
// P-1 partial mitigation: Increased retries to 5, added jitter, clear error message.
// P-2 fix: Returns bound address instead of mutating config.ListenerAddress.
func bindOSAssignedPort(config *Config) (net.Listener, string, error) {
	cfg := nat.DefaultBindConfig("tcp", config.ListenerAddress)
	result, err := nat.ProbeAndBindWithNATTraversal(cfg)
	if err != nil {
		return nil, "", err
	}
	return result.Listener, result.BoundAddress, nil
}

// isLoopbackAddress returns true if host is empty, a loopback IP, or resolves
// entirely to loopback addresses. P-1 fix: catches "localhost" and other hostnames.
// bindWithNATTraversal creates a TCP listener on the specified port, attempting
// NAT traversal (UPnP/NAT-PMP) with a 3-second timeout context.
// Returns the listener and the bound address. Callers are responsible for updating
// config.ListenerAddress under appropriate locking.
// Loopback addresses (127.x.x.x, ::1) bypass NAT traversal entirely because
// they are unreachable from the internet. For all other addresses a 3-second
// timeout keeps startup fast in environments without UPnP/NAT-PMP; the
// fallback to a plain TCP listener is transparent to callers.
func bindWithNATTraversal(config *Config, port int) (net.Listener, string, error) {
	cfg := nat.DefaultBindConfig("tcp", config.ListenerAddress)
	cfg.RequestedPort = port
	result, err := nat.BindWithNATTraversal(cfg)
	if err != nil {
		return nil, "", err
	}
	return result.Listener, result.BoundAddress, nil
}

// attachNTCP2Listener wraps tcpListener in an NTCP2 listener and stores it on
// the transport. Closes tcpListener on NTCP2 setup failure.
func attachNTCP2Listener(transport *NTCP2Transport, tcpListener net.Listener, ntcp2Config *ntcp2.Config) error {
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

func setupNetworkListener(transport *NTCP2Transport, config *Config, ntcp2Config *ntcp2.Config) error {
	_, portStr, err := net.SplitHostPort(config.ListenerAddress)
	if err != nil {
		return oops.Wrapf(err, "failed to parse listener address")
	}
	iport, err := strconv.Atoi(portStr)
	if err != nil {
		return oops.Wrapf(err, "failed to convert port to integer")
	}

	var tcpListener net.Listener
	var boundAddr string
	if iport == 0 {
		tcpListener, boundAddr, err = bindOSAssignedPort(config)
	} else {
		tcpListener, boundAddr, err = bindWithNATTraversal(config, iport)
	}
	if err != nil {
		return err
	}
	config.ListenerAddress = boundAddr

	// Phase 4: Initialize port mapper for TCP port mapping on non-loopback addresses
	host, portStr, _ := net.SplitHostPort(boundAddr)
	if !nat.IsLoopbackAddress(host) {
		port, _ := strconv.Atoi(portStr)
		cfg := &nat.PortMapperConfig{
			Network:      "tcp",
			InternalPort: port,
			Context:      transport.ctx,
		}
		transport.portMapperManager = nat.NewPortMapperManager(cfg)
		transport.logger.WithField("internal_port", port).Debug("Started TCP port mapper")
	}

	return attachNTCP2Listener(transport, tcpListener, ntcp2Config)
}

// Accept accepts an incoming session.
// The accepted connection is tracked in the transport's session map so that
// GetSessionCount() and checkSessionLimit() accurately reflect both inbound
// and outbound sessions. A cleanup callback is registered to remove the
// tracking entry when the connection is closed.
//
// Handshakes run in per-connection goroutines so that one slow or malicious
// peer cannot block the accept loop. The background runner is started lazily
// on the first call to Accept().
//
// Spec reference: https://geti2p.net/spec/ntcp2#probing-resistance
func (t *NTCP2Transport) Accept() (net.Conn, error) {
	t.identityMu.RLock()
	if t.listener == nil {
		t.identityMu.RUnlock()
		t.logger.Error("Accept called but listener is nil")
		return nil, ErrSessionClosed
	}
	t.identityMu.RUnlock()

	t.startInboundAcceptRunner()

	select {
	case conn, ok := <-t.pendingConns:
		if !ok {
			return nil, ErrSessionClosed
		}
		return conn, nil
	case <-t.ctx.Done():
		return nil, ErrSessionClosed
	}
}

// startInboundAcceptRunner starts the background accept loop exactly once.
// It initialises pendingConns and spawns the goroutine that continuously
// calls listener.Accept() and hands off raw connections to per-connection
// handshake workers. A second goroutine closes the listener when the
// transport context is cancelled so that a blocking listener.Accept() call
// is unblocked promptly on shutdown.
func (t *NTCP2Transport) startInboundAcceptRunner() {
	t.acceptRunOnce.Do(func() {
		t.pendingConns = make(chan net.Conn, 64)
		t.wg.Add(1)
		go t.runInboundAcceptLoop()
		// Ensure listener.Accept() unblocks when the transport is cancelled.
		// Track this goroutine in wg to ensure proper shutdown ordering.
		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
			<-t.ctx.Done()
			t.identityMu.RLock()
			listener := t.listener
			t.identityMu.RUnlock()
			if listener != nil {
				listener.Close()
			}
		}()
	})
}

// runInboundAcceptLoop is the background goroutine that accepts raw TCP
// connections from the listener and dispatches per-connection handshake
// goroutines. It terminates when the listener is closed or the transport
// context is cancelled.
func (t *NTCP2Transport) runInboundAcceptLoop() {
	defer t.wg.Done()
	for {
		if !t.acceptNextConnection() {
			return
		}
	}
}

// acceptNextConnection accepts and processes one incoming connection.
// Returns false if the accept loop should terminate.
func (t *NTCP2Transport) acceptNextConnection() bool {
	// CRITICAL-1.1 NOTE: We read the listener pointer under RLock but do NOT hold
	// the lock across Accept() — that would cause deadlock (Accept blocks indefinitely,
	// preventing SetIdentity from acquiring write lock). Instead, we accept potential
	// "use of closed network connection" errors if SetIdentity swaps the listener
	// between our read and Accept() call. Such errors are caught by the error handler
	// below and cause a retry with the new listener. This is safe: the connection
	// from a swapped-out listener is never processed with mismatched crypto config.
	t.identityMu.RLock()
	listener := t.listener
	t.identityMu.RUnlock()

	// Distinguish "listener nil during swap" from "listener nil during shutdown".
	// If the transport is still running but listener is nil, wait and retry
	// (SetIdentity is likely swapping the listener). Only terminate on shutdown.
	if listener == nil {
		select {
		case <-t.ctx.Done():
			// Shutdown signaled; exit loop.
			t.logger.Debug("Listener is nil and transport shutting down; terminating accept loop")
			return false
		case <-time.After(50 * time.Millisecond):
			// Listener temporarily nil (likely during SetIdentity swap); retry.
			t.logger.Debug("Listener is nil but transport running; waiting for listener swap to complete")
			return true
		}
	}

	// CRITICAL-1.1: Accept() is called without holding any lock. If SetIdentity
	// swaps the listener concurrently, Accept() may return "use of closed network
	// connection" error (handled below) or may succeed on the old listener (the
	// connection is then closed and session count remains balanced). We do NOT
	// hold RLock across Accept() because that would deadlock with SetIdentity's
	// Lock() acquisition.
	rawConn, err := listener.Accept()

	if t.shouldShutdown(rawConn) {
		return false
	}

	if err != nil {
		// MEDIUM 5.1: Distinguish transient from permanent accept errors.
		// Only exit the loop on permanent errors (shutdown signaled or listener gone).
		// For transient errors (EMFILE, etc.), log and continue accepting.
		// CRITICAL-1.1: "use of closed network connection" from a SetIdentity listener
		// swap is treated as transient — we retry and pick up the new listener.
		select {
		case <-t.ctx.Done():
			// Shutdown signaled; exit loop and log at debug level
			t.logger.WithError(err).Debug("Accept error during shutdown; closing accept loop")
			return false
		default:
			// Transient error: log as info, sleep briefly to avoid tight loop, and continue
			t.logger.WithError(err).Info("Transient accept error; will retry")
			time.Sleep(10 * time.Millisecond)
			return true
		}
	}

	if !t.canAcceptNewSession(rawConn) {
		return true // continue accepting
	}

	go t.inboundHandshakeWorker(rawConn)
	return true
}

// shouldShutdown checks if the transport is shutting down and closes the connection if provided.
func (t *NTCP2Transport) shouldShutdown(rawConn net.Conn) bool {
	select {
	case <-t.ctx.Done():
		if rawConn != nil {
			rawConn.Close()
		}
		return true
	default:
		return false
	}
}

// canAcceptNewSession checks if we can accept a new session without exceeding limits.
func (t *NTCP2Transport) canAcceptNewSession(rawConn net.Conn) bool {
	if err := t.checkSessionLimit(); err != nil {
		t.logger.WithFields(map[string]interface{}{
			"session_count": t.GetSessionCount(),
			"max_sessions":  t.config.GetMaxSessions(),
		}).Warn("Session limit reached — dropping inbound TCP connection")
		rawConn.Close()
		return false
	}
	return true
}

// inboundHandshakeWorker performs the full NTCP2 inbound handshake for a
// single raw TCP connection. On success the tracked connection is sent on
// pendingConns for consumption by Accept(). On failure the connection and
// the reserved session slot are cleaned up. Times out if the queue is full
// to prevent indefinite blocking and slot reservation exhaustion.
func (t *NTCP2Transport) inboundHandshakeWorker(conn net.Conn) {
	if err := t.performInboundHandshake(conn); err != nil {
		// performInboundHandshake already closes conn and unreserves the slot.
		return
	}

	tracked, isFresh := t.trackInboundConnection(conn)
	if !isFresh {
		// Duplicate detected: already closed and unreserved, nothing more to do.
		return
	}

	// Use a timeout to send to the pending queue to avoid indefinitely blocking
	// and holding a reserved slot when the queue is full or Accept() is slow.
	// If the send times out, close the connection and unreserve.
	const queueTimeout = 5 * time.Second
	sendCtx, cancel := context.WithTimeout(context.Background(), queueTimeout)
	defer cancel()

	select {
	case t.pendingConns <- tracked:
		// Successfully enqueued for Accept() to consume.
		// Mark the connection as accepted to prevent dual-ownership via promotion (R-3).
		// Use CompareAndSwap instead of Store to avoid clobbering a concurrent promotion (X-3).
		peerHash := t.extractPeerHash(tracked)
		// The original value should be the underlying raw conn (before wrapping in trackedConn).
		// If CAS fails, a concurrent GetSession already promoted this to a session, so we
		// don't deliver it to Accept (ownership already transferred).
		originalConn := tracked.(*trackedConn).Conn
		if !t.sessions.CompareAndSwap(peerHash, originalConn, acceptedConn{Conn: tracked}) {
			// Promotion race: concurrent GetSession already promoted this to a session.
			// The promoted session now owns the underlying conn and the reserved slot.
			// Do NOT call tracked.Close() here - it would:
			//   1. Close the conn now owned by the promoted session (interferes with it)
			//   2. Fire onClose callback which removes the promoted session from map
			// The trackedConn wrapper is safely GC'd. (trackedConn cleanup race fix)
			t.logger.WithFields(map[string]interface{}{
				"remote_addr": conn.RemoteAddr().String(),
				"peer_hash":   fmt.Sprintf("%x", peerHash[:8]),
			}).Debug("Inbound connection promoted concurrently; not delivering to Accept")
			return
		}
	case <-sendCtx.Done():
		// Queue send timed out: close the connection.
		// The tracked conn's onClose callback will call removeSession which
		// decrements the session count, so we don't call unreserveSessionSlot here.
		t.logger.WithFields(map[string]interface{}{
			"remote_addr":   conn.RemoteAddr().String(),
			"queue_timeout": queueTimeout,
			"session_count": t.GetSessionCount(),
			"pending_conns": len(t.pendingConns),
		}).Warn("Inbound connection dropped: pending queue send timeout (accept consumer too slow?)")
		tracked.Close()
	case <-t.ctx.Done():
		// Transport shutting down: close the connection.
		// The tracked conn's onClose callback handles session cleanup.
		tracked.Close()
	}
}

// performInboundHandshake performs the Noise XK handshake on an accepted connection.
// On failure, applies probing resistance and releases the reserved session slot.
// On success, propagates the peer's static key, extracts and stores the peer's
// RouterInfo from message 3, and wires the AEAD-error termination callback.
func (t *NTCP2Transport) performInboundHandshake(conn net.Conn) error {
	ntcp2Conn, ok := conn.(*ntcp2.Conn)
	if !ok {
		if t.testBypassHandshakeTypeCheck {
			// TEST ONLY: Skip handshake for mock connections.
			// This allows tests to verify session tracking/accept loop logic
			// without full Noise protocol setup. NEVER enable in production.
			t.logger.WithField("conn_type", fmt.Sprintf("%T", conn)).
				Debug("testBypassHandshakeTypeCheck enabled; skipping handshake for non-*ntcp2.Conn")
			return nil
		}
		t.logger.WithField("conn_type", fmt.Sprintf("%T", conn)).
			Error("Accepted connection is not *ntcp2.Conn; rejecting")
		_ = conn.Close()
		t.unreserveSessionSlot()
		return oops.Errorf("accepted connection is not *ntcp2.Conn (got %T)", conn)
	}

	if err := t.executeHandshake(ntcp2Conn); err != nil {
		return err
	}

	t.setupAEADErrorCallback(ntcp2Conn)

	if err := t.extractAndStorePeerRouterInfo(ntcp2Conn, conn); err != nil {
		return err
	}

	t.logHandshakeSuccess(conn)
	return nil
}

// executeHandshake performs the Noise XK handshake with probing resistance on failure.
func (t *NTCP2Transport) executeHandshake(ntcp2Conn *ntcp2.Conn) error {
	if err := ntcp2Conn.UnderlyingConn().Handshake(t.ctx); err != nil {
		raw := extractRawConn(ntcp2Conn.UnderlyingConn())
		t.logger.WithError(err).Debug("Inbound handshake failed, applying probing resistance")
		applyProbingResistance(raw)
		_ = ntcp2Conn.Close()
		t.unreserveSessionSlot()
		return WrapNTCP2Error(err, "inbound handshake (probing resistance applied)")
	}
	ntcp2Conn.PropagatePeerStaticKey()
	return nil
}

// setupAEADErrorCallback wires the AEAD error callback to send termination before RST.
func (t *NTCP2Transport) setupAEADErrorCallback(ntcp2Conn *ntcp2.Conn) {
	ntcp2Conn.OnAEADError = func(rawConn net.Conn) {
		term := BuildTerminationBlock(TerminationAEADFailure)
		t.writeTerminationBlockBestEffort(rawConn, term)
	}
}

// extractAndStorePeerRouterInfo extracts the peer's RouterInfo from msg3 and stores it.
func (t *NTCP2Transport) extractAndStorePeerRouterInfo(ntcp2Conn *ntcp2.Conn, conn net.Conn) error {
	riBytes := ntcp2Conn.PeerRouterInfoBytes()
	if len(riBytes) == 0 {
		t.logger.WithField("remote_addr", conn.RemoteAddr().String()).
			Warn("Inbound NTCP2: no RouterInfo block in msg3 — protocol violation; closing")
		_ = ntcp2Conn.Close()
		t.unreserveSessionSlot()
		return oops.Errorf("inbound NTCP2: missing RouterInfo block in msg3")
	}

	peerRI, _, parseErr := router_info.ReadRouterInfo(riBytes)
	if parseErr != nil {
		// MEDIUM 5.2: RouterInfo parse failure should be a hard session-establishment error,
		// not a warning that allows degraded routing. Abort handshake on parse failure.
		t.logger.WithError(parseErr).WithField("remote_addr", conn.RemoteAddr().String()).
			Warn("Inbound NTCP2: failed to parse peer RouterInfo from msg3; aborting handshake")
		_ = ntcp2Conn.Close()
		t.unreserveSessionSlot()
		return oops.Errorf("RouterInfo parse failed: %w", parseErr)
	}

	t.updateRemoteAddressWithIdentHash(ntcp2Conn, peerRI)
	if err := t.storeRouterInfoInNetDB(peerRI, conn); err != nil {
		// E-3 fix: Increment observable metric on store failure for monitoring.
		atomic.AddInt32(&t.routerInfoStoreFailures, 1)
		// E-5: Storage failures are now observable; log at Warn (not Error, because the
		// handshake succeeded and the session can still be used for message routing).
		// E-3: Enhanced log with guidance for operators.
		t.logger.WithError(err).WithFields(map[string]interface{}{
			"remote_addr":          conn.RemoteAddr().String(),
			"total_store_failures": atomic.LoadInt32(&t.routerInfoStoreFailures),
			"impact":               "OBEP reply routing may fail for this peer",
		}).Warn("Inbound NTCP2: handshake succeeded but failed to persist peer RouterInfo in NetDB")
	}
	return nil
}

// updateRemoteAddressWithIdentHash updates the remote address with the real router hash.
func (t *NTCP2Transport) updateRemoteAddressWithIdentHash(ntcp2Conn *ntcp2.Conn, peerRI router_info.RouterInfo) {
	identHash, hashErr := peerRI.IdentHash()
	if hashErr != nil {
		return
	}
	remoteAddr, addrOk := ntcp2Conn.RemoteAddr().(*ntcp2.Addr)
	if addrOk {
		remoteAddr.SetRouterHash(identHash)
	}
}

// storeRouterInfoInNetDB stores the peer's RouterInfo in the local NetDB.
// E-5 remediation: Returns an error if storage fails, allowing the caller to log and
// surface metrics for storage failures. Type-asserts to RouterInfoStorerWithErrors
// if available; otherwise falls back to the void StoreRouterInfo method and returns nil.
func (t *NTCP2Transport) storeRouterInfoInNetDB(peerRI router_info.RouterInfo, conn net.Conn) error {
	storer := t.getRouterInfoStorer()
	if storer == nil {
		return nil
	}

	// E-5: Prefer error-returning storage for observability
	if storerWithErrors, ok := storer.(transport.RouterInfoStorerWithErrors); ok {
		if err := storerWithErrors.StoreRouterInfoWithError(peerRI); err != nil {
			return err
		}
		t.logger.WithField("remote_addr", conn.RemoteAddr().String()).
			Debug("Inbound NTCP2: stored peer RouterInfo in NetDB")
		return nil
	}

	// Fallback: void StoreRouterInfo (no error observability)
	storer.StoreRouterInfo(peerRI)
	t.logger.WithField("remote_addr", conn.RemoteAddr().String()).
		Debug("Inbound NTCP2: stored peer RouterInfo in NetDB (no error reporting)")
	return nil
}

// logHandshakeSuccess logs successful handshake completion with local capabilities.
func (t *NTCP2Transport) logHandshakeSuccess(conn net.Conn) {
	t.identityMu.RLock()
	localRI := t.identity
	t.identityMu.RUnlock()

	t.logger.WithFields(map[string]interface{}{
		"remote_addr":      conn.RemoteAddr().String(),
		"local_caps":       localRI.RouterCapabilities(),
		"local_addr_count": localRI.RouterAddressCount(),
	}).Info("Inbound Noise XK handshake completed successfully (responder role)")
}

func (t *NTCP2Transport) writeTerminationBlockBestEffort(rawConn net.Conn, term []byte) {
	n, err := rawConn.Write(term)
	if err != nil || n != len(term) {
		remoteAddr := "<unknown>"
		if ra := rawConn.RemoteAddr(); ra != nil {
			remoteAddr = ra.String()
		}
		if t.logger != nil {
			t.logger.WithFields(map[string]interface{}{
				"written_bytes":  n,
				"expected_bytes": len(term),
				"remote_addr":    remoteAddr,
			}).WithError(err).Warn("Failed to write AEAD termination block")
		}
	}
}

// trackInboundConnection registers the accepted connection for session counting
// and wraps it to ensure cleanup on close. Returns (wrappedConn, isFresh) where
// isFresh=true if this was a new insertion, or isFresh=false if a duplicate was detected.
// On duplicate detection, the duplicate is closed and the reserved slot is unreserved.
func (t *NTCP2Transport) trackInboundConnection(conn net.Conn) (net.Conn, bool) {
	peerHash := t.extractPeerHash(conn)
	if _, loaded := t.sessions.LoadOrStore(peerHash, conn); loaded {
		// Duplicate detected: unreserve the slot and close this connection.
		t.unreserveSessionSlot()
		conn.Close()
		t.logger.WithFields(map[string]interface{}{
			"remote_addr": conn.RemoteAddr().String(),
			"peer_hash":   fmt.Sprintf("%x", peerHash[:8]),
		}).Debug("Duplicate inbound connection detected and closed; reservation unreserved")
		return conn, false // Mark as duplicate
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
	return wrappedConn, true // Mark as fresh
}

// extractPeerHash extracts the peer's router hash from an accepted connection.
// Returns a hash derived from the NTCP2Addr if available, or a hash derived
// from the remote address as a fallback key for session map tracking.
func (t *NTCP2Transport) extractPeerHash(conn net.Conn) data.Hash {
	var peerHash data.Hash

	if ntcpAddr, ok := conn.RemoteAddr().(*ntcp2.Addr); ok {
		hashBytes := ntcpAddr.RouterHash()
		peerHash = hashBytes
		// If the hash is non-zero, use it directly
		var zeroHash data.Hash
		if peerHash != zeroHash {
			return peerHash
		}
	}

	// SA-3 fix: Fallback for connections without a router hash.
	// Hash the full address with SHA-256 to avoid truncation collisions when
	// address strings exceed 32 bytes (long IPv6 addresses with zones).
	// Set a consistent marker byte to separate address-derived keys from real
	// router hashes, preventing collisions if a router hash happens to match
	// an address-derived key.
	//
	// Strip the ephemeral port so reconnections from the same host produce
	// the same hash, avoiding duplicate session tracking entries.
	addrStr := conn.RemoteAddr().String()
	if host, _, err := net.SplitHostPort(addrStr); err == nil {
		addrStr = host
	}
	hash := sha256.Sum256([]byte(addrStr))
	copy(peerHash[:], hash[:])
	// Set marker byte to distinguish address-derived hashes from real router hashes
	peerHash[0] = 0xFF

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
	staticKey := t.config.Config.StaticKey
	t.identityMu.Unlock()

	if err := verifyLocalRouterInfoMatchesStaticKey(ri, staticKey); err != nil {
		t.logger.WithError(err).Error(
			"UpdateLocalRouterInfo: new RouterInfo's NTCP2 `s=` does not match " +
				"live static key — all subsequent outbound NTCP2 handshakes will " +
				"succeed cryptographically but be closed by remote peers (i2pd " +
				"GetNTCP2AddressWithStaticKey check). Investigate the call site that " +
				"supplied this RouterInfo.",
		)
	}
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

// SetRouterInfoStorer wires a NetDB store so that RouterInfos received from
// inbound peers during the NTCP2 handshake are persisted locally. This is
// required for tunnel-build reply routing to work: the OBEP looks up the
// originator's RouterInfo in the NetDB when delivering a ShortTunnelBuildReply.
func (t *NTCP2Transport) SetRouterInfoStorer(s transport.RouterInfoStorer) {
	t.routerInfoStorer.Store(s)
}

// getRouterInfoStorer returns the current RouterInfoStorer, or nil if none is set.
func (t *NTCP2Transport) getRouterInfoStorer() transport.RouterInfoStorer {
	if v := t.routerInfoStorer.Load(); v != nil {
		return v.(transport.RouterInfoStorer)
	}
	return nil
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

	// BUG FIX HIGH 3.2: Recreate listener BEFORE updating identity/config to avoid
	// half-transitioned state if listener rebind fails. Test listener rebind success
	// while holding identity steady, then apply both changes atomically.
	if err := t.recreateListenerIfNeeded(ntcp2Config); err != nil {
		return err
	}

	// Only update identity/config after listener rebind succeeds.
	t.identityMu.Lock()
	t.identity = ident
	t.config.Config = ntcp2Config
	t.identityMu.Unlock()

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
func (t *NTCP2Transport) createNTCP2ConfigFromIdentity(ident router_info.RouterInfo) (*ntcp2.Config, error) {
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
// Holds identityMu to protect concurrent access to t.listener throughout the entire operation.
func (t *NTCP2Transport) recreateListenerIfNeeded(ntcp2Config *ntcp2.Config) error {
	t.identityMu.Lock()
	if t.listener == nil {
		t.identityMu.Unlock()
		return nil
	}

	// S-2 fix: Snapshot old listener but keep it active during new listener creation.
	// Only swap and close old listener after new one succeeds. Prevents infinite
	// retry loop in acceptNextConnection if new listener creation fails.
	currentAddr := t.config.ListenerAddress
	oldListener := t.listener
	t.identityMu.Unlock()

	t.logger.Info("Recreating listener with new identity")

	// Create new listener outside the lock using the snapshotted address
	newListener, newAddr, err := t.createNewListenerWithConfig(ntcp2Config, currentAddr)
	if err != nil {
		// S-2 fix: On failure, old listener remains active (not set to nil).
		// Accept loop continues serving on old listener instead of retrying forever on nil.
		t.logger.WithError(err).Error("Failed to create new listener during identity update; keeping old listener active")
		return err
	}

	// S-2 fix: Install new listener and close old listener ONLY after new one succeeds.
	// This atomic swap ensures t.listener is never nil on error path.
	t.identityMu.Lock()
	t.listener = newListener
	t.config.ListenerAddress = newAddr
	t.identityMu.Unlock()

	// Close the old listener outside the lock after successful swap
	if err := oldListener.Close(); err != nil {
		t.logger.WithError(err).Warn("Error closing old listener after successful recreation")
	}

	t.logger.WithField("address", newAddr).Info("Listener recreated successfully")
	return nil
}

// createNewListenerWithConfig creates a new TCP and NTCP2 listener with the provided configuration.
// Takes the listener address as a parameter to avoid reading shared state outside the identity lock.
// Returns the new listener and the new bound address (which may differ after NAT traversal).
func (t *NTCP2Transport) createNewListenerWithConfig(ntcp2Config *ntcp2.Config, listenerAddress string) (net.Listener, string, error) {
	// Extract port from the current listener address to maintain the same listening port.
	_, portStr, err := net.SplitHostPort(listenerAddress)
	if err != nil {
		t.logger.WithError(err).Error("Failed to extract port from listener address for recreation")
		return nil, "", WrapNTCP2Error(err, "parsing listener port")
	}
	iport, err := strconv.Atoi(portStr)
	if err != nil {
		t.logger.WithError(err).Error("Failed to convert port to integer")
		return nil, "", WrapNTCP2Error(err, "parsing listener port")
	}

	// Use NAT traversal to rebind with the same port, preserving external address mapping.
	// This ensures the recreated listener maintains NAT-mapped address semantics.
	// R-2 fix: bindWithNATTraversal now returns the bound address; we capture and return it
	// for the caller to update config under lock.
	tcpListener, boundAddr, err := bindWithNATTraversal(t.config, iport)
	if err != nil {
		t.logger.WithError(err).Error("Failed to rebind listener with NAT traversal")
		return nil, "", WrapNTCP2Error(err, "rebinding listener")
	}

	listener, err := ntcp2.NewNTCP2Listener(tcpListener, ntcp2Config)
	if err != nil {
		// Close the TCP listener to prevent file descriptor leak.
		if closeErr := tcpListener.Close(); closeErr != nil {
			t.logger.WithError(closeErr).Warn("Failed to close TCP listener after NTCP2 listener creation failure")
		}
		t.logger.WithError(err).Error("Failed to create new NTCP2 listener")
		return nil, "", WrapNTCP2Error(err, "creating new listener")
	}

	// Return the actual bound address from bindWithNATTraversal (not from listener.Addr(),
	// which may differ if NAT mapping occurred).
	return listener, boundAddr, nil
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

// sessionMapEntryKind describes the type of entry found in the sessions map.
type sessionMapEntryKind int

const (
	// entryIsSession indicates the entry is already a *NTCP2Session.
	entryIsSession sessionMapEntryKind = iota
	// entryIsRawConn indicates the entry is a raw net.Conn that needs promotion.
	entryIsRawConn
	// entryIsAcceptedConn indicates the entry is an acceptedConn owned by Accept().
	entryIsAcceptedConn
	// entryIsUnexpected indicates the entry has an unrecognized type.
	entryIsUnexpected
)

// sessionMapEntryResolution describes the result of resolving a session map entry.
// This factored helper ensures all lookup paths apply the same guards (X-1 fix).
type sessionMapEntryResolution struct {
	kind    sessionMapEntryKind
	session *NTCP2Session // non-nil when kind == entryIsSession
	rawConn net.Conn      // non-nil when kind == entryIsRawConn
}

// resolveSessionMapEntry examines a session map entry and returns a resolution
// indicating whether it's already a session, needs promotion, should be skipped
// (acceptedConn), or is an unexpected type. This helper centralizes the type
// guards that prevent dual socket ownership (X-1) and accounting corruption (A-1).
func (t *NTCP2Transport) resolveSessionMapEntry(existing interface{}) sessionMapEntryResolution {
	// Fast path: already a full session.
	if ntcp2Session, ok := existing.(*NTCP2Session); ok {
		return sessionMapEntryResolution{
			kind:    entryIsSession,
			session: ntcp2Session,
		}
	}

	// Skip connections already delivered to Accept() (X-1 fix).
	// The Accept() consumer owns the socket; promotion would create dual ownership.
	if _, ok := existing.(acceptedConn); ok {
		return sessionMapEntryResolution{kind: entryIsAcceptedConn}
	}

	// Raw connection needs promotion.
	if rawConn, ok := existing.(net.Conn); ok {
		return sessionMapEntryResolution{
			kind:    entryIsRawConn,
			rawConn: rawConn,
		}
	}

	// Unexpected type — should never happen in correct code.
	return sessionMapEntryResolution{kind: entryIsUnexpected}
}

func (t *NTCP2Transport) findExistingSession(routerHash data.Hash) (transport.TransportSession, bool) {
	existing, exists := t.sessions.Load(routerHash)
	if !exists {
		t.logNoSessionFound(routerHash)
		return nil, false
	}

	// Use centralized resolver to ensure consistent type guards across all lookup paths (X-1 fix).
	resolution := t.resolveSessionMapEntry(existing)

	switch resolution.kind {
	case entryIsSession:
		return t.validateExistingSession(resolution.session, routerHash)

	case entryIsRawConn:
		return t.promoteInboundConnection(resolution.rawConn, existing, routerHash)

	case entryIsAcceptedConn:
		// Skip — socket is owned by Accept() consumer.
		t.logNoSessionFound(routerHash)
		return nil, false

	case entryIsUnexpected:
		// Log unexpected type and return not-found.
		t.logger.WithField("entry_type", fmt.Sprintf("%T", existing)).
			Error("findExistingSession: unexpected session map entry type")
		t.logNoSessionFound(routerHash)
		return nil, false

	default:
		// Unreachable — all enum values handled.
		t.logNoSessionFound(routerHash)
		return nil, false
	}
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
	// Defensive check: refuse to promote an acceptedConn (X-1 fix).
	// This should never happen if findExistingSession is correct, but
	// defense-in-depth prevents dual socket ownership.
	if _, ok := original.(acceptedConn); ok {
		atomic.AddInt32(&t.acceptedConnPromotionAttempts, 1)
		routerHashBytes := routerHash.Bytes()
		t.logger.WithFields(map[string]interface{}{
			"router_hash": fmt.Sprintf("%x", routerHashBytes[:8]),
		}).Error("Refusing to promote acceptedConn (already delivered to Accept)")
		return nil, false
	}

	promoted := NewNTCP2SessionDeferred(conn, t.ctx, t.logger)

	// CRITICAL-3.1 FIX: Start workers AFTER CAS succeeds, not before.
	// Starting workers before CAS means losers have running workers that may
	// interfere with the winner's connection (frame corruption, data races).
	// The old comment claimed this "ensures no other goroutine sees a session
	// without running workers," but that's a non-issue: only the winner is
	// visible in the map, and we start its workers immediately after CAS.

	if t.sessions.CompareAndSwap(routerHash, original, promoted) {
		// Pre-flight check: verify session is in map before starting workers (CRITICAL-3.1)
		routerHashBytes := routerHash.Bytes()
		if mapValue, exists := t.sessions.Load(routerHash); !exists {
			t.logger.WithField("router_hash", fmt.Sprintf("%x", routerHashBytes[:8])).
				Error("CRITICAL-3.1 violation: CAS succeeded but session missing from map before StartWorkers")
		} else if mapSession, ok := mapValue.(*NTCP2Session); !ok || mapSession != promoted {
			t.logger.WithField("router_hash", fmt.Sprintf("%x", routerHashBytes[:8])).
				Error("CRITICAL-3.1 violation: CAS succeeded but wrong session in map before StartWorkers")
		}

		// Start workers NOW that we've won the promotion race
		promoted.StartWorkers()

		// Set cleanup callback AFTER the CAS succeeds, so only the winning
		// session's cleanup can affect the session map. If set before CAS,
		// the losing session's Close() would invoke removeSession() and
		// delete the winner's entry.
		promoted.SetCleanupCallback(func() {
			t.removeSession(routerHash)
		})
		t.logger.WithFields(map[string]interface{}{
			"router_hash": fmt.Sprintf("%x", routerHashBytes[:8]),
		}).Info("Promoted inbound net.Conn to NTCP2Session")
		return promoted, true
	}
	// Another goroutine won the promotion race — close our duplicate.
	// Workers will exit cleanly due to context.Done().
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
func (t *NTCP2Transport) finalizeOutboundSession(conn *ntcp2.Conn, routerHash data.Hash, routerHashBytes [32]byte, dialStart time.Time) (transport.TransportSession, error) {
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

func (t *NTCP2Transport) dialNTCP2Connection(routerInfo router_info.RouterInfo) (*ntcp2.Conn, error) {
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
	if ntcpAddr, ok := ntcp2Addr.(*ntcp2.Addr); ok {
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
func (t *NTCP2Transport) performNTCP2Handshake(ntcp2Addr net.Addr, tcpAddrString string, peerHashBytes []byte, config *ntcp2.Config, tcpDialStart time.Time) (*ntcp2.Conn, error) {
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

func (t *NTCP2Transport) createNTCP2Config(routerInfo router_info.RouterInfo) (*ntcp2.Config, error) {
	remoteHash, err := routerInfo.IdentHash()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to get remote router hash")
	}

	t.identityMu.RLock()
	ourStaticKey := t.config.Config.StaticKey
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
func (t *NTCP2Transport) attachLocalRouterInfo(config *ntcp2.Config) error {
	t.identityMu.RLock()
	localRI := t.identity
	ourStaticKey := t.config.Config.StaticKey
	t.identityMu.RUnlock()

	// Per-dial sanity check: mirror i2pd's GetNTCP2AddressWithStaticKey.
	// i2pd silently terminates with zero data-phase bytes if the static key
	// we sent in msg1 is not published in any NTCP2 address of the RouterInfo
	// we send in msg3. This produces "frame #0 EOF" after a successful Noise
	// handshake. Detect and surface the mismatch here, before opening TCP.
	if err := verifyLocalRouterInfoMatchesStaticKey(localRI, ourStaticKey); err != nil {
		return oops.Wrapf(err,
			"outbound NTCP2: local RouterInfo does not advertise the static key "+
				"we will send in the Noise handshake; remote peers will silently "+
				"drop the connection after msg3")
	}

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
		"ri_bytes_full":   fmt.Sprintf("%x", riBytes),
	}).Info("LocalRouterInfo for msg3 outbound")
	config.WithLocalRouterInfo(riBytes)
	return nil
}

func (t *NTCP2Transport) setupSession(conn *ntcp2.Conn, routerHash data.Hash) *NTCP2Session {
	// Create session WITHOUT starting workers to avoid spawning goroutines
	// that may be immediately discarded if an existing session wins the race.
	session := NewNTCP2SessionDeferred(conn, t.ctx, t.logger)

	// CRITICAL-3.1 FIX: Start workers AFTER LoadOrStore succeeds, not before.
	// Starting workers before LoadOrStore means losers have running workers that
	// may interfere with the winner's connection (frame corruption, data races).
	// The old comment claimed this "ensures no other goroutine sees a session
	// without running workers," but that's a non-issue: only the winner is
	// visible in the map, and we start its workers immediately after LoadOrStore.

	existing, loaded := t.sessions.LoadOrStore(routerHash, session)
	if loaded {
		// A session already exists for this peer. Close the newly created
		// session (workers haven't started yet, so clean shutdown is simple)
		// and return the existing one. Release the reserved session slot.
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

	// We won the store — start workers NOW
	// Pre-flight check: verify session is in map before starting workers (CRITICAL-3.1)
	routerHashBytes := routerHash.Bytes()
	if mapValue, exists := t.sessions.Load(routerHash); !exists {
		t.logger.WithField("router_hash", fmt.Sprintf("%x", routerHashBytes[:8])).
			Error("CRITICAL-3.1 violation: LoadOrStore succeeded but session missing from map before StartWorkers")
	} else if mapSession, ok := mapValue.(*NTCP2Session); !ok || mapSession != session {
		t.logger.WithField("router_hash", fmt.Sprintf("%x", routerHashBytes[:8])).
			Error("CRITICAL-3.1 violation: LoadOrStore succeeded but wrong session in map before StartWorkers")
	}

	session.StartWorkers()

	// Wire up the cleanup callback.
	// The session slot was already reserved by checkSessionLimit.
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
	// Use centralized resolver to ensure consistent type guards across all lookup paths (X-1 fix).
	resolution := t.resolveSessionMapEntry(existing)

	switch resolution.kind {
	case entryIsSession:
		return resolution.session

	case entryIsRawConn:
		return t.promoteRawConnToSession(resolution.rawConn, routerHash, existing)

	case entryIsAcceptedConn:
		// Skip — socket is owned by Accept() consumer.
		return nil

	case entryIsUnexpected:
		// Should not reach here in practice. Log an error and return nil.
		// CRITICAL-5.1: Log full value (not just type) for debugging corrupt map entries
		t.logger.WithField("entry_value", fmt.Sprintf("%#v", existing)).
			Error("resolveExistingSession: unexpected session map entry type — returning nil")
		return nil

	default:
		// Unreachable — all enum values handled.
		return nil
	}
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

// promoteRawConnToSession promotes a raw net.Conn to NTCP2Session with CAS protection.
func (t *NTCP2Transport) promoteRawConnToSession(rawConn net.Conn, routerHash data.Hash, existing interface{}) *NTCP2Session {
	// Use deferred session creation to avoid starting workers before
	// we've confirmed this goroutine wins the CAS race. Workers on
	// a losing session would share the same conn, causing errors.
	promoted := NewNTCP2SessionDeferred(rawConn, t.ctx, t.logger)

	// CRITICAL-3.1 FIX: Start workers AFTER CAS succeeds, not before.
	// Starting workers before CAS means losers have running workers that may
	// interfere with the winner's connection (frame corruption, data races).
	// The old comment claimed this "ensures no other goroutine sees a session
	// without running workers," but that's a non-issue: only the winner is
	// visible in the map, and we start its workers immediately after CAS.

	// NOTE: Do NOT set the cleanup callback before CAS. If this
	// goroutine loses the race, calling promoted.Close() would
	// trigger removeSession and delete the *winner's* map entry.
	if t.sessions.CompareAndSwap(routerHash, existing, promoted) {
		// Pre-flight check: verify session is in map before starting workers (CRITICAL-3.1)
		routerHashBytes := routerHash.Bytes()
		if mapValue, exists := t.sessions.Load(routerHash); !exists {
			t.logger.WithField("router_hash", fmt.Sprintf("%x", routerHashBytes[:8])).
				Error("CRITICAL-3.1 violation: CAS succeeded but session missing from map before StartWorkers")
		} else if mapSession, ok := mapValue.(*NTCP2Session); !ok || mapSession != promoted {
			t.logger.WithField("router_hash", fmt.Sprintf("%x", routerHashBytes[:8])).
				Error("CRITICAL-3.1 violation: CAS succeeded but wrong session in map before StartWorkers")
		}

		// Start workers NOW that we've won the promotion race
		promoted.StartWorkers()

		promoted.SetCleanupCallback(func() {
			t.removeSession(routerHash)
		})
		t.logger.WithFields(map[string]interface{}{
			"router_hash": fmt.Sprintf("%x", routerHashBytes[:8]),
		}).Info("Promoted inbound net.Conn to NTCP2Session in setupSession")
		return promoted
	}
	// Another goroutine won the promotion race — discard ours.
	// Detach the shared conn before closing so the loser doesn't close
	// the winner's socket. Workers will exit cleanly when Close() cancels
	// the session context (SM-2 fix).
	promoted.DetachConn()
	_ = promoted.Close()
	if winner, exists := t.sessions.Load(routerHash); exists {
		if winnerSession, ok := winner.(*NTCP2Session); ok {
			return winnerSession
		}
	}
	return nil
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
	// A-4 fix: No longer gate on isShuttingDown. Let cleanup callbacks
	// always decrement properly, even during shutdown. Close() reconciliation
	// will only decrement truly-stale sessions (those that weren't cleaned up).
	// This makes shutdown accounting deterministic.
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

// GetRouterInfoStoreFailures returns the total count of RouterInfo storage failures
// since transport startup. Incremented each time storeRouterInfoInNetDB fails.
// E-3 fix: Exposes NetDB health for monitoring and alerting. High count indicates
// NetDB unavailability or I/O errors that break OBEP reply routing.
func (t *NTCP2Transport) GetRouterInfoStoreFailures() int {
	return int(atomic.LoadInt32(&t.routerInfoStoreFailures))
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
	// Phase 4: Stop port mapper before closing listener
	if t.portMapperManager != nil {
		if err := t.portMapperManager.Stop(); err != nil {
			t.logger.WithError(err).Warn("Failed to stop port mapper during close")
		}
	}

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
// Logs the total number of sessions closed. A-4 fix: cleanup callbacks now
// run properly during shutdown, so sessions should be removed by their callbacks
// rather than by this explicit cleanup (reconciliation should find zero stale).
func (t *NTCP2Transport) closeAllActiveSessions() {
	// Set shutdown flag for visibility
	atomic.StoreInt32(&t.isShuttingDown, 1)

	t.logger.Debug("Closing all active sessions")
	sessionCount := 0

	t.sessions.Range(func(key, value interface{}) bool {
		sessionCount++
		t.closeIndividualSession(key, value)
		// CRITICAL-8.1 FIX: Do NOT LoadAndDelete here. The cleanup callback
		// will delete the entry and decrement sessionCount. If we LoadAndDelete
		// here, we decrement immediately, and when the cleanup callback runs
		// (possibly delayed by GC/scheduler), it decrements again, causing
		// sessionCount to go negative. The reconciliation loop below will catch
		// any truly stale sessions (those without cleanup callbacks).
		return true
	})

	// A-4 fix: Reconcile by decrementing truly-stale sessions (those whose
	// cleanup callbacks didn't fire). With removeSession no longer gated,
	// this should find zero stale sessions in the normal case.
	var staleCount int
	t.sessions.Range(func(key, value interface{}) bool {
		if _, loaded := t.sessions.LoadAndDelete(key); loaded {
			staleCount++
			atomic.AddInt32(&t.sessionCount, -1)
		}
		return true
	})
	if staleCount > 0 {
		t.logger.WithField("stale_sessions", staleCount).Warn("Found stale sessions after close")
		// A-3 fix: Track how often reconciliation finds drift for monitoring.
		// This should always be zero when accounting is correct (X-2/X-3 fixes).
		t.metrics.staleSessionsReconciled.Add(1)
	}
	// A-4 fix: Verify sessionCount is now 0 (all sessions properly decremented).
	// Non-zero indicates accounting bug (sessions without cleanup callbacks).
	finalCount := atomic.LoadInt32(&t.sessionCount)
	if finalCount != 0 {
		t.logger.WithField("final_count", finalCount).Error("sessionCount non-zero after reconciliation")
		// Force-reset as safety net, but this indicates a bug
		atomic.StoreInt32(&t.sessionCount, 0)
	}
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
	case acceptedConn:
		// Connection delivered to Accept() consumer (R-3 fix).
		if err := v.Close(); err != nil && hashOk {
			routerHashBytes := routerHash.Bytes()
			t.logger.WithError(err).WithField("router_hash", fmt.Sprintf("%x", routerHashBytes[:8])).Warn("Error closing accepted connection")
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

// AcceptedConnPromotionAttempts returns the number of times promoteInboundConnection
// refused to promote an acceptedConn (X-1 bug detection metric).
// This counter should remain at 0 in a correct implementation. A non-zero value
// indicates findExistingSession bypassed the acceptedConn guard and attempted
// dual socket ownership.
func (t *NTCP2Transport) AcceptedConnPromotionAttempts() int32 {
	return atomic.LoadInt32(&t.acceptedConnPromotionAttempts)
}

// Name returns the name of this transport.
func (t *NTCP2Transport) Name() string {
	return "NTCP2"
}
