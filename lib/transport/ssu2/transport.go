package ssu2

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
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
	nattraversal "github.com/go-i2p/go-nat-listener"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
	"golang.org/x/time/rate"
)

// abandonedRelayTag tracks a relay tag that was allocated but not successfully
// registered, for monitoring and future cleanup.
type abandonedRelayTag struct {
	tag         uint32
	addr        *net.UDPAddr
	allocatedAt time.Time
	reason      string // why registration failed
}

// acceptedConn is a marker type wrapping a raw connection that has been
// delivered via Accept(). It prevents the connection from being promoted
// to a session (which would create dual ownership), since the Accept()
// consumer now owns the socket lifecycle.
type acceptedConn struct {
	net.Conn
}

// Session Map Ownership Invariant (X-3 fix):
// Each peerHash (RouterHash) in the sessions map has EXACTLY ONE owner at any given time:
//   - net.Conn (raw or *ssu2noise.SSU2Conn): owned by trackInboundConnection, transferable to Accept or promotion
//   - acceptedConn: owned by the Accept() consumer; MUST NOT be promoted (dual-ownership)
//   - *SSU2Session: owned by the session lifecycle; cleanup via removeSession
//
// State transitions use CompareAndSwap to prevent race conditions:
//   - rawConn → acceptedConn: CAS in inboundHandshakeWorker (after successful queue send)
//   - rawConn → *SSU2Session: CAS in promoteInboundConnection (via GetSession) or registerOrReuseSession
//
// If inbound Accept CAS fails, a concurrent GetSession/dial has already promoted the connection;
// do not deliver to Accept (ownership already transferred to the session).
// If promotion CAS fails, another goroutine won the race; close the duplicate session.
//
// SSU2Transport implements transport.Transport for SSU2 connections.
type SSU2Transport struct {
	listener *ssu2noise.SSU2Listener
	config   *Config
	identity router_info.RouterInfo
	keystore KeystoreProvider
	handler  *DefaultHandler

	// Session management
	// sessions map[RouterHash]<value> where value can be:
	//  - net.Conn (raw inbound connection after trackInboundConnection, before Accept or promotion)
	//  - acceptedConn (wrapper marking ownership transferred to Accept() consumer - MUST NOT promote)
	//  - *SSU2Session (fully established session)
	// State transitions (all use CompareAndSwap to prevent races):
	//  - net.Conn → acceptedConn (inboundHandshakeWorker after successful pendingConns send)
	//  - net.Conn → *SSU2Session (promotion via GetSession/registerOrReuseSession)
	// See "Session Map Ownership Invariant" comment above for details.
	sessions       sync.Map
	sessionCount   int32
	isShuttingDown int32 // atomic flag set during Close() to prevent cleanup callbacks from double-decrementing

	identityMu sync.RWMutex

	// NAT traversal managers (initialised after listener starts).
	peerTestManager    *ssu2noise.PeerTestManager
	relayManager       *ssu2noise.RelayManager
	introducerRegistry *ssu2noise.IntroducerRegistry
	holePunchCoord     *ssu2noise.HolePunchCoordinator

	// pendingRelayResponses holds channels waiting for a RelayResponse keyed by nonce.
	// Used by dialViaIntroducer to synchronise with the protocol callback.
	// Values are *pendingRelayResponse; a consumed flag prevents a late delivery
	// from being written to a channel whose reader has already given up.
	pendingRelayResponses sync.Map // map[uint32]*pendingRelayResponse

	// NAT state cache with TTL.
	natStateCache *natState

	// Port mapper lifecycle management (MEDIUM 2.5): when port mapping succeeds,
	// we store the mapper and external port so we can properly clean up the
	// mapping during transport Close(). Protected by portMapperMu.
	portMapperMu       sync.Mutex
	activePortMapper   nattraversal.PortMapper
	activeExternalPort int

	// Key management.
	persistentConfig   *PersistentConfig
	keyRotationManager *ssu2noise.KeyRotationManager

	// peerConnNotifier receives connection outcome feedback (optional).
	// Set via SetPeerConnNotifier after construction. Uses atomic.Value for safe concurrent access.
	peerConnNotifier atomic.Value // stores transport.PeerConnNotifier

	// abandonedRelayTags tracks relay tags allocated but not successfully registered.
	// Used for monitoring and future cleanup when a release API becomes available.
	abandonedRelayTagsMu sync.Mutex
	abandonedRelayTags   []abandonedRelayTag

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// NAT manager lifecycle: per-generation context for NAT goroutines and managers.
	// L-1: Cancelled and replaced on each SetIdentity to stop old NAT goroutines
	// before starting new ones.
	natCtxMu  sync.Mutex
	natCtx    context.Context
	natCancel context.CancelFunc

	logger *logger.Entry

	// peerTestGlobalLimiter caps total PeerTestRelay emissions per second
	// across all sessions to limit amplification.
	peerTestGlobalLimiter *rate.Limiter

	// startupPeerTestCount tracks how many auto peer-tests have been sent at
	// startup (capped at 3 per D3 spec).
	startupPeerTestCount int32

	// peerTestRepublish is an optional callback invoked when PeerTest
	// observations confirm a new external address. Set after construction.
	peerTestRepublish atomic.Value // stores func()

	// T-1 fix: Single-flight guard prevents concurrent NAT detection runs.
	// Multiple interleaved StartNATDetection calls would overwrite retry state;
	// this flag ensures only one detection sequence runs at a time.
	natDetectionRunning atomic.Bool

	// E-2 fix: Track NAT manager initialization health. Set to true when initNATManagers
	// succeeds, false when it fails. Allows health checks and metrics to expose NAT-degraded mode.
	// When false, NAT traversal features (hole-punching, peer tests, relay) are unavailable.
	natManagersHealthy atomic.Bool

	// Peer test retry state (T-1 fix): tracks consecutive failures and timing
	// for exponential backoff retry of NAT detection. Protected by peerTestRetryMu.
	peerTestRetryMu     sync.Mutex
	peerTestRetryCount  int
	peerTestLastAttempt time.Time
	peerTestCandidates  []router_info.RouterInfo
	peerTestRepublishFn func()
	peerTestRetryTimer  *time.Timer

	// closeOnce ensures Close() is idempotent.
	closeOnce sync.Once
	closeErr  error

	// reachMetrics tracks reachability-related events for monitoring.
	reachMetrics reachabilityMetrics

	// E-4 fix: warnOnce for RouterStoreFunc misconfiguration warning.
	// Ensures warn is emitted only once per transport lifetime when RouterInfo
	// blocks arrive but RouterStoreFunc is nil in non-test builds.
	routerStoreWarnOnce sync.Once
}

// KeystoreProvider provides access to the router's cryptographic keys.
type KeystoreProvider interface {
	GetEncryptionPrivateKey() types.PrivateEncryptionKey
	GetSigningPrivateKey() types.PrivateKey
}

// NewSSU2Transport creates a new SSU2 transport instance.
func NewSSU2Transport(identity router_info.RouterInfo, config *Config, keystore KeystoreProvider) (*SSU2Transport, error) {
	ctx, cancel := context.WithCancel(context.Background())
	l := logger.WithField("component", "ssu2")

	if err := prepareIdentityAndLog(identity, config.ListenerAddress, l); err != nil {
		cancel()
		return nil, err
	}

	ssu2Config, err := setupSSU2Config(identity, keystore, cancel)
	if err != nil {
		return nil, err
	}
	config.SSU2Config = ssu2Config

	t := createSSU2TransportStruct(config, identity, keystore, ctx, cancel, l)

	if err := setupUDPListener(t, config, ssu2Config); err != nil {
		t.handler.Close()
		cancel()
		return nil, err
	}

	if err := conditionallyInitKeyManagement(t, config, ssu2Config, cancel); err != nil {
		t.handler.Close()
		cancel()
		return nil, err
	}

	l.WithField("address", t.Addr().String()).Info("SSU2 transport initialized")
	return t, nil
}

// prepareIdentityAndLog extracts the identity hash and logs initialization.
func prepareIdentityAndLog(identity router_info.RouterInfo, listenerAddress string, l *logger.Entry) error {
	identHash, err := identity.IdentHash()
	if err != nil {
		return oops.Wrapf(err, "failed to get router identity hash")
	}
	identHashBytes := identHash.Bytes()
	l.WithFields(map[string]interface{}{
		"router_hash":      fmt.Sprintf("%x", identHashBytes[:8]),
		"listener_address": listenerAddress,
	}).Info("Initializing SSU2 transport")
	return nil
}

// setupSSU2Config creates the SSU2Config and initializes crypto keys.
func setupSSU2Config(identity router_info.RouterInfo, keystore KeystoreProvider, cancel context.CancelFunc) (*ssu2noise.SSU2Config, error) {
	ssu2Config, err := createSSU2Config(identity)
	if err != nil {
		cancel()
		return nil, err
	}

	if err := initializeCryptoKeys(ssu2Config, keystore); err != nil {
		cancel()
		return nil, err
	}

	return ssu2Config, nil
}

// createSSU2TransportStruct creates the SSU2Transport struct with default values.
func createSSU2TransportStruct(config *Config, identity router_info.RouterInfo, keystore KeystoreProvider, ctx context.Context, cancel context.CancelFunc, l *logger.Entry) *SSU2Transport {
	return &SSU2Transport{
		config:                config,
		identity:              identity,
		keystore:              keystore,
		handler:               NewDefaultHandler(),
		natStateCache:         &natState{},
		peerTestGlobalLimiter: rate.NewLimiter(100, 200),
		ctx:                   ctx,
		cancel:                cancel,
		logger:                l,
	}
}

// conditionallyInitKeyManagement initializes key management if WorkingDir is present.
func conditionallyInitKeyManagement(t *SSU2Transport, config *Config, ssu2Config *ssu2noise.SSU2Config, cancel context.CancelFunc) error {
	if config.WorkingDir == "" {
		return nil
	}
	if err := initKeyManagement(t, ssu2Config); err != nil {
		cancel()
		return err
	}
	return nil
}

// createSSU2Config creates an SSU2Config from the router identity.
func createSSU2Config(identity router_info.RouterInfo) (*ssu2noise.SSU2Config, error) {
	identHash, err := identity.IdentHash()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to get router identity hash")
	}
	cfg, err := ssu2noise.NewSSU2Config(identHash, false)
	if err != nil {
		return nil, WrapSSU2Error(err, "creating SSU2 config")
	}
	cfg = cfg.WithRouterInfoValidator(ssu2noise.DefaultRouterInfoValidator)
	return cfg, nil
}

// initializeCryptoKeys loads the X25519 static key from the keystore.
func initializeCryptoKeys(cfg *ssu2noise.SSU2Config, keystore KeystoreProvider) error {
	if len(cfg.StaticKey) != 0 {
		return nil
	}
	encryptionPrivKey := keystore.GetEncryptionPrivateKey()
	if encryptionPrivKey == nil {
		return WrapSSU2Error(oops.Errorf("encryption private key is nil"), "retrieving encryption key")
	}
	cfg.StaticKey = encryptionPrivKey.Bytes()
	if len(cfg.StaticKey) != 32 {
		return WrapSSU2Error(
			oops.Errorf("invalid static key size: expected 32 bytes, got %d", len(cfg.StaticKey)),
			"loading static key",
		)
	}
	return nil
}

// setupUDPListener creates the UDP listener and wraps it with SSU2.
// When a specific port is requested (non-zero), NAT traversal (UPnP/NAT-PMP) is
// attempted so the router publishes its external IP:port in the RouterInfo.
// Port 0 (OS-assigned) skips NAT traversal because there is no stable port to map.
func setupUDPListener(t *SSU2Transport, config *Config, ssu2Config *ssu2noise.SSU2Config) error {
	_, portStr, err := net.SplitHostPort(config.ListenerAddress)
	if err != nil {
		return oops.Wrapf(err, "failed to parse listener address")
	}
	iport, err := strconv.Atoi(portStr)
	if err != nil {
		return oops.Wrapf(err, "failed to convert port to integer")
	}

	udpConn, boundAddr, err := createUDPConn(config, iport)
	if err != nil {
		return err
	}
	config.ListenerAddress = boundAddr

	return startSSU2Listener(t, udpConn, ssu2Config)
}

// createUDPConn creates a UDP packet connection, using OS-assigned port or NAT traversal.
// Returns the connection and the bound address. Caller must update config.ListenerAddress.
func createUDPConn(config *Config, iport int) (net.PacketConn, string, error) {
	if iport == 0 {
		conn, boundAddr, err := listenWithOSPort(config)
		if err != nil {
			return nil, "", err
		}
		return conn, boundAddr, nil
	}
	return listenWithNATTraversal(config, iport)
}

// listenWithOSPort discovers a free UDP port via a temporary OS-assigned binding,
// then re-binds through NAT traversal (UPnP/NAT-PMP with fallback) on that port
// so the resulting connection carries a real external address.
// To handle the TOCTOU race where another process may claim the port between
// probe and rebind, this function retries up to maxPortProbeRetries times.
// Each retry probes a new port and attempts rebind.
// P-1 partial mitigation: Increased retries to 5, added jitter, clear error message.
// P-2 fix: Returns bound address instead of relying on caller extraction.
//
// Note: On iOS, app sandbox restrictions prevent net.ListenPacket and net.ListenUDP
// on arbitrary ports without the com.apple.developer.networking.multipath entitlement
// or a NEPacketTunnelProvider extension. Attempting to listen will fail with EACCES.
// Pure go-i2p in-app deployment is not supported on iOS App Store builds.
func listenWithOSPort(config *Config) (net.PacketConn, string, error) {
	const maxPortProbeRetries = 5 // P-1: increased from 3 to 5
	var lastErr error

	for attempt := 0; attempt < maxPortProbeRetries; attempt++ {
		// Step 1: ask the OS for any available UDP port, with SO_REUSEADDR to allow
		// rebinding immediately after. This reduces the TOCTOU window where another
		// process could claim the port between close and rebind.
		listenCfg := net.ListenConfig{
			Control: func(network, address string, c syscall.RawConn) error {
				var sockoptErr error
				err := c.Control(func(fd uintptr) {
					if sockoptErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); sockoptErr != nil {
						log.WithError(sockoptErr).Warn("Failed to set SO_REUSEADDR on probe UDP listener")
					}
				})
				if err != nil {
					return err
				}
				return sockoptErr
			},
		}

		udpAddr, err := net.ResolveUDPAddr("udp", config.ListenerAddress)
		if err != nil {
			return nil, "", oops.Wrapf(err, "failed to resolve UDP address")
		}
		temp, err := listenCfg.ListenPacket(context.Background(), "udp", udpAddr.String())
		if err != nil {
			return nil, "", oops.Wrapf(err, "failed to probe UDP port")
		}
		assignedPort := temp.LocalAddr().(*net.UDPAddr).Port
		if closeErr := temp.Close(); closeErr != nil {
			log.WithError(closeErr).Warn("failed to close probe UDP listener")
		}

		// Step 2: re-bind on the discovered port with NAT traversal so the connection
		// address carries the external IP instead of the unspecified "::" host.
		// SO_REUSEADDR on the final listener allows immediate rebind even if the
		// port is in TIME_WAIT state from the probe listener close.
		if attempt == 0 {
			log.WithField("port", assignedPort).Info("probed OS-assigned UDP port; attempting NAT traversal")
		}
		conn, boundAddr, err := listenWithNATTraversal(config, assignedPort)
		if err == nil {
			return conn, boundAddr, nil
		}

		// If rebind failed, check if it was due to "address already in use" (TOCTOU race).
		// If so, retry. Otherwise, return the error immediately.
		lastErr = err
		if !strings.Contains(err.Error(), "address already in use") && !strings.Contains(err.Error(), "Address already in use") {
			return nil, "", err
		}
		if attempt < maxPortProbeRetries-1 {
			log.WithFields(map[string]interface{}{
				"port":    assignedPort,
				"attempt": attempt + 1,
				"error":   err,
			}).Warn("TOCTOU race: probed UDP port claimed by another process; retrying")
			// P-1: Wait with jitter between retries to reduce contention.
			// Base 50ms + ±25% jitter = [37.5ms, 62.5ms]
			baseDelay := 50 * time.Millisecond
			jitterBytes := make([]byte, 2)
			if _, randErr := rand.Read(jitterBytes); randErr == nil {
				// Convert 2 random bytes to float64 in [0, 1)
				randVal := float64(uint16(jitterBytes[0])<<8|uint16(jitterBytes[1])) / 65536.0
				jitterFactor := 0.75 + (randVal * 0.5) // [0.75, 1.25]
				baseDelay = time.Duration(float64(baseDelay) * jitterFactor)
			} else {
				log.WithError(randErr).Warn("Failed to generate jitter; using base delay")
			}
			time.Sleep(baseDelay)
		}
	}

	// P-1: Clear error message when all retries exhausted
	return nil, "", oops.Wrapf(lastErr, "failed to bind OS-assigned UDP port after %d attempts (TOCTOU race: another process keeps claiming probed ports)", maxPortProbeRetries)
}

// isLoopbackAddress returns true if host is empty, a loopback IP, or resolves
// entirely to loopback addresses. P-1 fix: catches "localhost" and other hostnames.
func isLoopbackAddress(host string) bool {
	if host == "" {
		// Empty host means wildcard binding (not loopback)
		return false
	}
	// Try parsing as IP first (fast path)
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	// Not a literal IP — resolve the hostname
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		// Resolution failed or empty — assume non-loopback (fail open for reachability)
		return false
	}
	// Return true only if *all* resolved IPs are loopback
	for _, ip := range ips {
		if !ip.IsLoopback() {
			return false
		}
	}
	return true
}

// listenWithNATTraversal creates a UDP listener with NAT port mapping.
// Returns the packet connection and the bound address. Callers are responsible
// for updating config.ListenerAddress under appropriate locking.
// Loopback addresses (127.x.x.x, ::1) bypass NAT traversal entirely because
// they are unreachable from the internet. For all other addresses a 3-second
// timeout keeps startup fast in environments without UPnP/NAT-PMP; the
// fallback to a plain UDP listener is transparent to callers.
func listenWithNATTraversal(config *Config, iport int) (net.PacketConn, string, error) {
	host, _, _ := net.SplitHostPort(config.ListenerAddress)
	// Only attempt NAT traversal for non-loopback addresses.
	// Loopback addresses (127.x.x.x, ::1) bypass NAT traversal entirely because
	// they are unreachable from the internet. Empty host ("") indicates wildcard
	// binding and requires NAT traversal to make the listener reachable.
	//
	// P-1 fix: Resolve hostnames (e.g., "localhost") before loopback check.
	// net.ParseIP("localhost") returns nil, so the original check would treat
	// localhost as a public address and waste 3s attempting UPnP/NAT-PMP.
	isLoopback := isLoopbackAddress(host)

	if isLoopback {
		// Use SO_REUSEADDR to allow rebinding immediately after probing port 0.
		listenCfg := net.ListenConfig{
			Control: func(network, address string, c syscall.RawConn) error {
				var sockoptErr error
				err := c.Control(func(fd uintptr) {
					// SO_REUSEADDR allows rebinding to a port in TIME_WAIT state,
					// reducing the TOCTOU race window in listenWithOSPort().
					if sockoptErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); sockoptErr != nil {
						log.WithError(sockoptErr).Warn("Failed to set SO_REUSEADDR on listening socket")
					}
				})
				if err != nil {
					return err
				}
				return sockoptErr
			},
		}
		conn, err := listenCfg.ListenPacket(context.Background(), "udp", fmt.Sprintf("%s:%d", host, iport))
		if err != nil {
			return nil, "", oops.Wrapf(err, "failed to create UDP listener")
		}
		return conn, conn.LocalAddr().String(), nil
	}
	natCtx, natCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer natCancel()
	natPL, err := nattraversal.ListenPacketWithFallbackContext(natCtx, iport)
	if err != nil {
		return nil, "", oops.Wrapf(err, "failed to create UDP listener")
	}
	return natPL.PacketConn(), natPL.Addr().String(), nil
}

// startSSU2Listener creates and starts the SSU2 protocol listener over a UDP connection.
func startSSU2Listener(t *SSU2Transport, udpConn net.PacketConn, ssu2Config *ssu2noise.SSU2Config) error {
	listener, err := ssu2noise.NewSSU2Listener(udpConn, ssu2Config)
	if err != nil {
		_ = udpConn.Close()
		return WrapSSU2Error(err, "creating SSU2 listener")
	}

	if err := listener.Start(); err != nil {
		_ = listener.Close()
		return WrapSSU2Error(err, "starting SSU2 listener")
	}

	t.listener = listener
	if err := initNATManagers(t); err != nil {
		// E-2 fix: Set health status to false when NAT init fails.
		t.natManagersHealthy.Store(false)
		t.logger.WithError(err).Warn("NAT manager initialization failed; NAT features degraded (hole-punching, peer tests, relay unavailable)")
		// Don't fail transport startup, but log the failure and mark degraded mode
	} else {
		// E-2 fix: Set health status to true on successful NAT init.
		t.natManagersHealthy.Store(true)
	}
	return nil
}

// Accept accepts an incoming SSU2 connection.
func (t *SSU2Transport) Accept() (net.Conn, error) {
	// BUG FIX MEDIUM 1.7: Protect listener access with identityMu to prevent races
	// with SetIdentity() and Close(). Matches pattern in Addr() and NTCP2.Accept().
	t.identityMu.RLock()
	listener := t.listener
	t.identityMu.RUnlock()
	if listener == nil {
		return nil, ErrSessionClosed
	}

	// L-3 fix part 1: Fast-path reject if pool already full (non-reserving check)
	// This provides immediate rejection for tests/callers checking capacity
	// without blocking on Accept() when we know we can't serve the connection.
	if t.isSessionLimitReached() {
		return nil, ErrConnectionPoolFull
	}

	// L-3 fix part 2: Accept connection BEFORE reserving slot (don't hold reservation while blocking)
	conn, err := listener.Accept()
	if err != nil {
		return nil, err
	}

	// L-3 fix part 3: Now reserve slot after we have actual connection
	// Handles race where pool filled while blocking on Accept()
	if err := t.checkSessionLimit(); err != nil {
		// Close the accepted connection since we can't serve it
		// No unreserve needed: checkSessionLimit failed before reserving slot
		conn.Close()
		return nil, err
	}

	tracked, isFresh := t.trackInboundConnection(conn)
	if !isFresh {
		// Duplicate detected: trackInboundConnection closed and unreserved it.
		// Return a clean error to the caller.
		return nil, ErrDuplicateSession
	}

	// Mark the connection as accepted to prevent dual-ownership via promotion (R-3).
	// Use CompareAndSwap instead of Store to avoid clobbering a concurrent promotion (X-3).
	peerHash := t.extractPeerHash(tracked)
	// The original value should be the underlying raw conn (before wrapping in trackedConn).
	// If CAS fails, a concurrent GetSession already promoted this to a session, so we
	// don't deliver it to Accept (ownership already transferred).
	originalConn := tracked.(*trackedConn).Conn
	if !t.sessions.CompareAndSwap(peerHash, originalConn, acceptedConn{Conn: tracked}) {
		// Promotion race: concurrent GetSession won. Close the tracked wrapper
		// and unreserve the slot since we're not delivering to Accept.
		t.logger.WithFields(map[string]interface{}{
			"remote_addr": conn.RemoteAddr().String(),
			"peer_hash":   fmt.Sprintf("%x", peerHash[:8]),
		}).Debug("Inbound SSU2 connection promoted concurrently; not delivering to Accept")
		tracked.Close()
		return nil, ErrDuplicateSession
	}

	return tracked, nil
}

// trackInboundConnection registers the accepted connection for session counting
// and wraps it to ensure cleanup on close. Returns (wrappedConn, isFresh) where
// isFresh=true if this was a new insertion, or isFresh=false if a duplicate was detected.
// On duplicate detection, the duplicate is closed and the reserved slot is unreserved.
func (t *SSU2Transport) trackInboundConnection(conn net.Conn) (net.Conn, bool) {
	peerHash := t.extractPeerHash(conn)
	if _, loaded := t.sessions.LoadOrStore(peerHash, conn); loaded {
		// Duplicate detected: unreserve the slot and close this connection.
		t.unreserveSessionSlot()
		conn.Close()
		t.logger.WithFields(map[string]interface{}{
			"remote_addr": conn.RemoteAddr().String(),
			"peer_hash":   fmt.Sprintf("%x", peerHash[:8]),
		}).Debug("Duplicate inbound SSU2 connection detected and closed; reservation unreserved")
		return conn, false // Mark as duplicate
	}
	// Auto-initiate a PeerTest against the first 3 peers that connect (D3).
	if ssu2Conn, ok := conn.(*ssu2noise.SSU2Conn); ok {
		t.maybeAutoInitiatePeerTest(ssu2Conn.RemoteAddr())
	}
	return &trackedConn{
		Conn: conn,
		onClose: func() {
			t.removeSession(peerHash)
		},
	}, true // Mark as fresh
}

func (t *SSU2Transport) extractPeerHash(conn net.Conn) data.Hash {
	var peerHash data.Hash
	if ssu2Addr, ok := conn.RemoteAddr().(*ssu2noise.SSU2Addr); ok {
		hashBytes := ssu2Addr.RouterHash()
		peerHash = hashBytes
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
	peerHash[0] = 0xFE // distinct from NTCP2 (0xFF) for debugging

	return peerHash
}

// trackedConn wraps a net.Conn to execute a cleanup function when closed.
type trackedConn struct {
	net.Conn
	onClose   func()
	closeOnce sync.Once
}

// Close closes the underlying connection and runs the close callback once.
func (tc *trackedConn) Close() error {
	err := tc.Conn.Close()
	tc.closeOnce.Do(tc.onClose)
	return err
}

// Addr returns the network address the transport is bound to.
func (t *SSU2Transport) Addr() net.Addr {
	t.identityMu.RLock()
	l := t.listener
	t.identityMu.RUnlock()
	if l == nil {
		return nil
	}
	return l.Addr()
}

// SetPeerConnNotifier wires a connection-outcome notifier into the transport.
// Call this after construction to enable PeerTracker feedback.
func (t *SSU2Transport) SetPeerConnNotifier(n transport.PeerConnNotifier) {
	t.peerConnNotifier.Store(n)
}

// AttachTransportCallbacks wires transport-level NAT/relay callbacks into the
// provided session so inbound sessions created outside transport internals can
// use the same callback path as transport-managed sessions.
func (t *SSU2Transport) AttachTransportCallbacks(session *SSU2Session) {
	if t == nil || session == nil {
		return
	}
	session.SetTransportCallbacks(t.buildTransportCallbacks(session))
}

// getPeerConnNotifier returns the current PeerConnNotifier, or nil if none is set.
func (t *SSU2Transport) getPeerConnNotifier() transport.PeerConnNotifier {
	if v := t.peerConnNotifier.Load(); v != nil {
		return v.(transport.PeerConnNotifier)
	}
	return nil
}

// recordPeerAttempt notifies the PeerTracker of a dial attempt if wired.
func (t *SSU2Transport) recordPeerAttempt(hash data.Hash) {
	if n := t.getPeerConnNotifier(); n != nil {
		n.RecordAttempt(hash)
	}
}

// recordPeerFailure notifies the PeerTracker of a dial failure. If the error
// is ErrInvalidRouterInfo, the peer is marked as permanently unreachable.
func (t *SSU2Transport) recordPeerFailure(hash data.Hash, err error) {
	if n := t.getPeerConnNotifier(); n != nil {
		if errors.Is(err, ErrInvalidRouterInfo) {
			n.RecordPermanentFailure(hash, "no_reachable_ssu2_address")
		} else {
			n.RecordFailure(hash, err.Error())
		}
	}
}

// recordPeerSuccess notifies the PeerTracker of a successful connection.
func (t *SSU2Transport) recordPeerSuccess(hash data.Hash, latencyMs int64) {
	if n := t.getPeerConnNotifier(); n != nil {
		n.RecordSuccess(hash, latencyMs)
	}
}

// SetIdentity sets the router identity for this transport.
func (t *SSU2Transport) SetIdentity(ident router_info.RouterInfo) error {
	identHash, err := ident.IdentHash()
	if err != nil {
		return oops.Wrapf(err, "failed to get router identity hash")
	}
	identHashBytes := identHash.Bytes()
	t.logger.WithField("router_hash", fmt.Sprintf("%x", identHashBytes[:8])).Info("Updating SSU2 transport identity")

	ssu2Config, err := createSSU2Config(ident)
	if err != nil {
		return WrapSSU2Error(err, "updating identity")
	}

	if err := initializeCryptoKeys(ssu2Config, t.keystore); err != nil {
		return oops.Wrapf(err, "failed to reinitialize crypto keys")
	}

	// BUG FIX HIGH 3.3: SSU2 listener must be recreated when identity changes,
	// similar to NTCP2. The listener encapsulates the old identity's crypto keys.
	// Without rebinding, the listener presents the old static key to peers while
	// the transport claims a new identity, violating protocol coherence.
	// Close old listener and create new one with updated config.

	// BUG FIX HIGH SM-1 / L-1: Stop NAT managers and goroutines before swapping the listener.
	// NAT managers hold references to the old listener and must be re-initialized.
	// L-1 fix item 3: Call stopNATManagers() before initNATManagers().
	stopNATManagers(t)

	// S-2 + S-3 fix: Snapshot old state (listener, address, identity, config) for rollback.
	// Keep old listener active during new listener creation for atomic swap.
	t.identityMu.RLock()
	currentAddr := t.config.ListenerAddress
	oldListener := t.listener
	oldIdentity := t.identity
	oldSSU2Config := t.config.SSU2Config
	t.identityMu.RUnlock()

	// Create new listener with the new identity/config if one existed before.
	if oldListener != nil {
		// Extract port from the snapshotted listener address to maintain the same listening port.
		_, portStr, err := net.SplitHostPort(currentAddr)
		if err != nil {
			t.logger.WithError(err).Error("Failed to extract port from SSU2 listener address")
			return err
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			t.logger.WithError(err).Error("Failed to parse port from SSU2 listener address")
			return err
		}

		// S-2 fix: Create new UDP connection and listener outside the lock.
		// On any failure, return error immediately without touching t.listener.
		// This keeps old listener active so Accept() continues working.
		udpConn, newAddr, err := listenWithNATTraversal(t.config, port)
		if err != nil {
			t.logger.WithError(err).Error("Failed to rebind UDP address during identity update")
			return err
		}

		listener, err := ssu2noise.NewSSU2Listener(udpConn, ssu2Config)
		if err != nil {
			_ = udpConn.Close()
			t.logger.WithError(err).Error("Failed to create new SSU2 listener during identity update")
			return WrapSSU2Error(err, "recreating SSU2 listener")
		}

		if err := listener.Start(); err != nil {
			_ = listener.Close()
			t.logger.WithError(err).Error("Failed to start new SSU2 listener during identity update")
			return WrapSSU2Error(err, "starting recreated SSU2 listener")
		}

		// S-2 + S-3 fix: Install new listener AND update identity/config under lock.
		// From this point, Accept() uses new listener and NAT init sees new identity.
		// If NAT/key init fails below, rollback restores ALL old state atomically.
		t.identityMu.Lock()
		t.listener = listener
		t.config.ListenerAddress = newAddr
		t.identity = ident
		t.config.SSU2Config = ssu2Config
		t.identityMu.Unlock()

		// BUG FIX HIGH SM-1: Re-initialize NAT managers with the new listener.
		// NAT managers must be bound to the new listener, not the old one.
		// S-3 fix: NAT managers now see new identity (t.identity updated above).
		// S-2 fix: On failure, close new listener and restore ALL old state.
		// E-2 fix: Track NAT manager health status.
		if err := initNATManagers(t); err != nil {
			t.natManagersHealthy.Store(false) // E-2 fix: Mark NAT degraded
			t.logger.WithError(err).Error("Failed to reinitialize NAT managers after identity update")
			// Rollback ALL state: listener, address, identity, config
			t.identityMu.Lock()
			_ = t.listener.Close() // Close failed new listener
			t.listener = oldListener
			t.config.ListenerAddress = currentAddr
			t.identity = oldIdentity
			t.config.SSU2Config = oldSSU2Config
			t.identityMu.Unlock()
			return err
		}
		t.natManagersHealthy.Store(true) // E-2 fix: Mark NAT healthy on success

		// L-1 item 4: Re-initialize keyRotationManager with the new identity's keys.
		// S-2 fix: On failure, close new listener and restore ALL old state.
		if err := initKeyManagement(t, ssu2Config); err != nil {
			t.logger.WithError(err).Error("Failed to reinitialize key rotation manager after identity update")
			// Rollback ALL state: listener, address, identity, config
			t.identityMu.Lock()
			_ = t.listener.Close() // Close failed new listener
			t.listener = oldListener
			t.config.ListenerAddress = currentAddr
			t.identity = oldIdentity
			t.config.SSU2Config = oldSSU2Config
			t.identityMu.Unlock()
			return err
		}

		// S-2 fix: Only close old listener after all initialization succeeds.
		// This ensures atomic swap: old listener stays active until new one fully ready.
		if err := oldListener.Close(); err != nil {
			t.logger.WithError(err).Warn("Error closing old SSU2 listener after successful recreation")
		}
	}

	// S-3 fix: Identity/config already updated above (before NAT init) so NAT managers
	// see new identity during initialization. No further updates needed here.
	t.logger.Info("SSU2 transport identity updated successfully with listener rebind")
	return nil
}

// GetSession obtains a transport session with a router given its RouterInfo.
// It tries direct dial first; if the peer only advertises introducer addresses
// and a RouterLookupFunc is configured, it falls back to the relay path.
func (t *SSU2Transport) GetSession(routerInfo router_info.RouterInfo) (transport.TransportSession, error) {
	routerHash, err := routerInfo.IdentHash()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to get router hash")
	}

	if session, found := t.findExistingSession(routerHash); found {
		return session, nil
	}

	if HasDialableSSU2Address(&routerInfo) {
		return t.createOutboundSession(routerInfo, routerHash)
	}

	if t.config.RouterLookupFunc != nil && HasIntroducerOnlySSU2Address(&routerInfo) {
		return t.dialViaIntroducer(routerInfo, routerHash)
	}

	return nil, oops.Errorf("no reachable SSU2 address for router %x", routerHash[:4])
}

func (t *SSU2Transport) findExistingSession(routerHash data.Hash) (transport.TransportSession, bool) {
	existing, exists := t.sessions.Load(routerHash)
	if !exists {
		return nil, false
	}

	return t.resolveSessionFromMap(existing, routerHash)
}

// resolveSessionFromMap resolves session from map entry (either live session or connection to promote).
func (t *SSU2Transport) resolveSessionFromMap(existing interface{}, routerHash data.Hash) (transport.TransportSession, bool) {
	if session, ok := existing.(*SSU2Session); ok {
		if session.ctx.Err() != nil {
			if _, loaded := t.sessions.LoadAndDelete(routerHash); loaded {
				atomic.AddInt32(&t.sessionCount, -1)
			}
			return nil, false
		}
		return session, true
	}

	// Skip connections already delivered to Accept() (X-2 fix).
	// The Accept() consumer owns the socket; promotion would create dual ownership.
	if _, ok := existing.(acceptedConn); ok {
		return nil, false
	}

	if conn, ok := existing.(net.Conn); ok {
		return t.promoteInboundConnection(conn, existing, routerHash)
	}
	return nil, false
}

func (t *SSU2Transport) promoteInboundConnection(conn net.Conn, original interface{}, routerHash data.Hash) (transport.TransportSession, bool) {
	// Defensive check: refuse to promote an acceptedConn (X-2 fix).
	// This should never happen if resolveSessionFromMap is correct, but
	// defense-in-depth prevents dual socket ownership.
	if _, ok := original.(acceptedConn); ok {
		routerHashBytes := routerHash.Bytes()
		t.logger.WithFields(map[string]interface{}{
			"router_hash": fmt.Sprintf("%x", routerHashBytes[:8]),
		}).Error("Refusing to promote acceptedConn (already delivered to Accept)")
		return nil, false
	}

	ssu2Conn, ok := conn.(*ssu2noise.SSU2Conn)
	if !ok {
		return nil, false
	}
	promoted := NewSSU2SessionDeferred(ssu2Conn, t.ctx, t.logger)
	promoted.maxRetransmit = t.config.GetMaxRetransmissions()
	promoted.SetTransportCallbacks(t.buildTransportCallbacks(promoted))

	// Start workers BEFORE making session visible in map (MEDIUM 3.4).
	// This ensures no other goroutine sees a session without running workers.
	promoted.StartWorkers()

	if t.sessions.CompareAndSwap(routerHash, original, promoted) {
		// Workers are already running; set cleanup callback for when this session closes.
		promoted.SetCleanupCallback(func() {
			t.removeSession(routerHash)
		})
		return promoted, true
	}

	// CompareAndSwap failed; close the session (workers will exit cleanly).
	// Detach the shared conn first so the loser doesn't close the winner's
	// socket. Workers will exit when Close() cancels the session context (SM-2 fix).
	promoted.DetachConn()
	_ = promoted.Close()
	if winner, exists := t.sessions.Load(routerHash); exists {
		if winnerSession, ok := winner.(*SSU2Session); ok {
			return winnerSession, true
		}
	}
	return nil, false
}

func (t *SSU2Transport) createOutboundSession(routerInfo router_info.RouterInfo, routerHash data.Hash) (transport.TransportSession, error) {
	if err := t.checkSessionLimit(); err != nil {
		return nil, err
	}

	// Use deferred cleanup - only unreserve if slotUsed is false
	slotUsed := false
	defer func() {
		if !slotUsed {
			t.unreserveSessionSlot()
		}
	}()

	dialConfig, remoteUDPAddr, err := t.prepareDialConfig(routerInfo)
	if err != nil {
		t.recordPeerAttempt(routerHash)
		t.recordPeerFailure(routerHash, err)
		return nil, err
	}

	t.recordPeerAttempt(routerHash)
	dialStart := time.Now()
	conn, err := ssu2noise.DialSSU2WithHandshakeContext(t.ctx, nil, remoteUDPAddr, dialConfig)
	if err != nil {
		t.recordPeerFailure(routerHash, err)
		t.logger.WithFields(map[string]interface{}{
			"router_hash": fmt.Sprintf("%x", routerHash[:8]),
			"error":       err.Error(),
		}).Warn("SSU2 outbound dial failed")
		return nil, WrapSSU2Error(err, "dialing SSU2 connection")
	}

	session, newSlotUsed, err := t.registerOrReuseSession(conn, routerHash)
	if err != nil {
		return nil, err
	}

	t.recordPeerSuccess(routerHash, time.Since(dialStart).Milliseconds())
	slotUsed = newSlotUsed
	return session, nil
}

// prepareDialConfig creates the dial configuration for an outbound SSU2 session.
func (t *SSU2Transport) prepareDialConfig(routerInfo router_info.RouterInfo) (*ssu2noise.SSU2Config, *net.UDPAddr, error) {
	remoteUDPAddr, err := resolveRemoteAddr(routerInfo)
	if err != nil {
		return nil, nil, err
	}

	dialConfig, err := t.createBaseDialConfig()
	if err != nil {
		return nil, nil, err
	}

	if err := t.applyRemotePeerConfig(dialConfig, routerInfo); err != nil {
		return nil, nil, err
	}

	return dialConfig, remoteUDPAddr, nil
}

// resolveRemoteAddr extracts and resolves the remote peer's SSU2 UDP address.
func resolveRemoteAddr(routerInfo router_info.RouterInfo) (*net.UDPAddr, error) {
	ssu2Addr, err := ExtractSSU2Addr(routerInfo)
	if err != nil {
		return nil, WrapSSU2Error(err, "extracting SSU2 address")
	}
	remoteUDPAddr, err := net.ResolveUDPAddr("udp", ssu2Addr.String())
	if err != nil {
		return nil, WrapSSU2Error(err, "resolving remote UDP address")
	}
	return remoteUDPAddr, nil
}

// createBaseDialConfig creates an SSU2 dial config with our identity and crypto keys.
func (t *SSU2Transport) createBaseDialConfig() (*ssu2noise.SSU2Config, error) {
	t.identityMu.RLock()
	identHash, err := t.identity.IdentHash()
	t.identityMu.RUnlock()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to get our identity hash")
	}

	dialConfig, err := ssu2noise.NewSSU2Config(identHash, true)
	if err != nil {
		return nil, WrapSSU2Error(err, "creating dial config")
	}

	if err := initializeCryptoKeys(dialConfig, t.keystore); err != nil {
		return nil, err
	}

	if ik := t.GetIntroKey(); len(ik) == 32 {
		dialConfig.IntroKey = ik
	}
	return dialConfig, nil
}

// applyRemotePeerConfig sets the remote router hash, static key, and intro key on the dial config.
func (t *SSU2Transport) applyRemotePeerConfig(dialConfig *ssu2noise.SSU2Config, routerInfo router_info.RouterInfo) error {
	remoteHash, err := routerInfo.IdentHash()
	if err != nil {
		return oops.Wrapf(err, "failed to get remote router hash")
	}
	dialConfig.WithRemoteRouterHash(remoteHash)

	remoteStaticKey, err := extractRemoteStaticKey(routerInfo)
	if err != nil {
		return WrapSSU2Error(err, "extracting remote static key")
	}
	dialConfig.WithRemoteStaticKey(remoteStaticKey)

	remoteIK, err := ExtractSSU2IntroKey(routerInfo)
	if err != nil {
		return WrapSSU2Error(err, "extracting remote SSU2 intro key")
	}
	dialConfig.RemoteIntroKey = remoteIK

	return nil
}

// extractRemoteStaticKey extracts the X25519 static public key from a remote
// router's SSU2 address. This key is required for the Noise XK handshake.
func extractRemoteStaticKey(routerInfo router_info.RouterInfo) ([]byte, error) {
	for _, addr := range routerInfo.RouterAddresses() {
		if !isSSU2Transport(addr) {
			continue
		}
		sk, err := addr.StaticKey()
		if err != nil {
			continue
		}
		return sk[:], nil
	}
	return nil, oops.Errorf("no SSU2 address with static key found in RouterInfo")
}

// registerOrReuseSession creates a new session or returns an existing one for the router hash.
// Returns the session, a boolean indicating if a new slot is used, and any error.
func (t *SSU2Transport) registerOrReuseSession(conn *ssu2noise.SSU2Conn, routerHash data.Hash) (*SSU2Session, bool, error) {
	session := NewSSU2SessionDeferred(conn, t.ctx, t.logger)
	session.maxRetransmit = t.config.GetMaxRetransmissions()
	session.SetTransportCallbacks(t.buildTransportCallbacks(session))

	// Start workers BEFORE putting session in map (MEDIUM 3.4).
	// This ensures no other goroutine sees a session without running workers.
	session.StartWorkers()

	existing, loaded := t.sessions.LoadOrStore(routerHash, session)
	if loaded {
		// Session already exists; close our new session (workers will exit cleanly).
		_ = session.Close()
		if existingSession, ok := existing.(*SSU2Session); ok {
			return existingSession, false, nil // Reusing existing, slot not used
		}
		// Skip connections already delivered to Accept() (X-2 fix).
		// The Accept() consumer owns the socket; treat as concurrent connection attempt.
		if _, ok := existing.(acceptedConn); ok {
			// Close the newly dialed session since we can't reuse the accepted conn.
			return nil, false, oops.Errorf("peer has accepted connection (owned by Accept consumer)")
		}
		// Found a raw net.Conn (from Accept) — promote it to SSU2Session.
		if rawConn, ok := existing.(net.Conn); ok {
			promoted := t.promoteRawConnToSession(rawConn, routerHash, existing)
			if promoted != nil {
				return promoted, false, nil // Promoted, slot not used (already reserved by Accept)
			}
		}
		// Unexpected map entry type — delete the corrupt entry and return error.
		// This prevents future connection attempts from reusing a corrupted state.
		// The connection already closed, so we cannot recover it.
		t.sessions.Delete(routerHash)
		// IMPORTANT: Decrement the counter since we're deleting a tracked entry (X-2 fix).
		atomic.AddInt32(&t.sessionCount, -1)
		routerHashBytes := routerHash.Bytes()
		t.logger.WithFields(map[string]interface{}{
			"router_hash": fmt.Sprintf("%x", routerHashBytes[:8]),
		}).Error("registerOrReuseSession: corrupt session map entry deleted")
		return nil, false, oops.Errorf("unexpected session map entry type")
	}

	// Workers are already running; set cleanup callback for when this session closes.
	session.SetCleanupCallback(func() {
		t.removeSession(routerHash)
	})
	return session, true, nil // New session, slot is used
}

// promoteRawConnToSession promotes a raw net.Conn (from Accept) to SSU2Session
// with CAS protection. Mirrors NTCP2 promotion logic to handle simultaneous
// inbound/outbound connections to the same peer.
func (t *SSU2Transport) promoteRawConnToSession(rawConn net.Conn, routerHash data.Hash, existing interface{}) *SSU2Session {
	// Type-assert to *ssu2noise.SSU2Conn.
	ssu2Conn, ok := rawConn.(*ssu2noise.SSU2Conn)
	if !ok {
		// Not an SSU2Conn — cannot promote.
		t.logger.WithFields(map[string]interface{}{
			"router_hash": fmt.Sprintf("%x", routerHash[:8]),
			"conn_type":   fmt.Sprintf("%T", rawConn),
		}).Error("promoteRawConnToSession: cannot promote non-SSU2Conn")
		return nil
	}

	// Create a new SSU2Session from the raw conn.
	promoted := NewSSU2SessionDeferred(ssu2Conn, t.ctx, t.logger)
	promoted.maxRetransmit = t.config.GetMaxRetransmissions()
	promoted.SetTransportCallbacks(t.buildTransportCallbacks(promoted))

	// Start workers BEFORE CompareAndSwap to ensure no other goroutine
	// sees a session without running workers.
	promoted.StartWorkers()

	// NOTE: Do NOT set the cleanup callback before CAS. If this
	// goroutine loses the race, calling promoted.Close() would
	// trigger removeSession and delete the *winner's* map entry.
	if t.sessions.CompareAndSwap(routerHash, existing, promoted) {
		promoted.SetCleanupCallback(func() {
			t.removeSession(routerHash)
		})
		routerHashBytes := routerHash.Bytes()
		t.logger.WithFields(map[string]interface{}{
			"router_hash": fmt.Sprintf("%x", routerHashBytes[:8]),
		}).Info("Promoted inbound net.Conn to SSU2Session in registerOrReuseSession")
		return promoted
	}

	// Another goroutine won the promotion race — discard ours.
	// Workers will exit cleanly due to context.Done().
	_ = promoted.Close()
	if winner, exists := t.sessions.Load(routerHash); exists {
		if winnerSession, ok := winner.(*SSU2Session); ok {
			return winnerSession
		}
	}
	return nil
}

// Compatible returns true if we can reach this router over SSU2 — either by
// dialling it directly or by going through one of its introducers (when a
// RouterLookupFunc is configured).
func (t *SSU2Transport) Compatible(routerInfo router_info.RouterInfo) bool {
	if HasDialableSSU2Address(&routerInfo) {
		return true
	}
	if t.config.RouterLookupFunc != nil && HasIntroducerOnlySSU2Address(&routerInfo) {
		return true
	}
	return false
}

// NATManagersHealthy returns true if NAT managers (hole-punching, peer tests, relay)
// initialized successfully. When false, the transport is in NAT-degraded mode: basic
// connections work, but NAT traversal features are unavailable.
// E-2 fix: Explicit health status visibility for monitoring and metrics.
func (t *SSU2Transport) NATManagersHealthy() bool {
	return t.natManagersHealthy.Load()
}

// Close closes the transport cleanly.
func (t *SSU2Transport) Close() error {
	t.closeOnce.Do(func() {
		t.logger.Info("Closing SSU2 transport")
		// SA-2 fix: Set shutdown flag to prevent cleanup callbacks from decrementing during shutdown
		atomic.StoreInt32(&t.isShuttingDown, 1)
		t.cancel()

		if t.relayManager != nil {
			t.relayManager.Stop()
		}

		if t.keyRotationManager != nil {
			t.keyRotationManager.Stop()
		}

		// Clean up peer test retry timer (T-1 fix)
		t.peerTestRetryMu.Lock()
		if t.peerTestRetryTimer != nil {
			t.peerTestRetryTimer.Stop()
			t.peerTestRetryTimer = nil
		}
		t.peerTestRetryMu.Unlock()

		var listenerErr error
		// BUG FIX MEDIUM 1.7: Protect listener access with identityMu lock to prevent
		// races with SetIdentity() and Accept().
		t.identityMu.RLock()
		listener := t.listener
		t.identityMu.RUnlock()
		if listener != nil {
			listenerErr = listener.Close()
		}

		t.sessions.Range(func(key, value interface{}) bool {
			if session, ok := value.(*SSU2Session); ok {
				_ = session.Close()
			} else if accepted, ok := value.(acceptedConn); ok {
				_ = accepted.Close()
			} else if conn, ok := value.(net.Conn); ok {
				_ = conn.Close()
			}
			return true
		})

		t.wg.Wait()
		t.handler.Close()

		// Reconcile sessionCount after shutdown to ensure it reflects actual session state.
		// Clear any stale sessions from the map and reset count to 0 to ensure
		// transport can be cleanly restarted if needed. This corrects for any
		// cleanup callbacks that didn't fire or incomplete close paths.
		var staleCount int
		t.sessions.Range(func(key, value interface{}) bool {
			staleCount++
			_, _ = t.sessions.LoadAndDelete(key)
			return true
		})
		if staleCount > 0 {
			t.logger.WithField("stale_sessions", staleCount).Warn("Cleanup after Close found stale sessions")
			// A-3 fix: Track how often reconciliation finds drift for monitoring.
			// This should always be zero when accounting is correct (X-2/X-3 fixes).
			t.reachMetrics.staleSessionsReconciled.Add(1)
		}
		atomic.StoreInt32(&t.sessionCount, 0)

		// Clean up port mapper if one was successfully created (MEDIUM 2.5)
		t.portMapperMu.Lock()
		if t.activePortMapper != nil && t.activeExternalPort > 0 {
			if err := t.activePortMapper.UnmapPort("udp", t.activeExternalPort); err != nil {
				t.logger.WithFields(map[string]interface{}{
					"external_port": t.activeExternalPort,
					"error":         err,
				}).Warn("Failed to unmap port during transport Close (non-fatal)")
			} else {
				t.logger.WithField("external_port", t.activeExternalPort).Debug("Port mapping cleaned up on transport close")
			}
			t.activePortMapper = nil
			t.activeExternalPort = 0
		}
		t.portMapperMu.Unlock()

		t.logger.Info("SSU2 transport closed")
		t.closeErr = listenerErr
	})
	return t.closeErr
}

// Name returns the name of this transport.
func (t *SSU2Transport) Name() string {
	return "SSU2"
}

// GetSessionCount returns the number of active sessions.
func (t *SSU2Transport) GetSessionCount() int {
	return int(atomic.LoadInt32(&t.sessionCount))
}

// GetTotalBandwidth returns the total bytes sent and received across all active sessions.
func (t *SSU2Transport) GetTotalBandwidth() (totalBytesSent, totalBytesReceived uint64) {
	t.sessions.Range(func(_, value interface{}) bool {
		if session, ok := value.(*SSU2Session); ok {
			sent, received := session.GetBandwidthStats()
			totalBytesSent += sent
			totalBytesReceived += received
		}
		return true
	})
	return totalBytesSent, totalBytesReceived
}

// isSessionLimitReached returns true if the session pool is at or above capacity.
// This is a non-reserving check used for fail-fast rejection in Accept().
// Use checkSessionLimit() when you need to atomically reserve a slot.
func (t *SSU2Transport) isSessionLimitReached() bool {
	current := atomic.LoadInt32(&t.sessionCount)
	maxSessions := t.config.GetMaxSessions()
	return int(current) >= maxSessions
}

func (t *SSU2Transport) checkSessionLimit() error {
	maxSessions := t.config.GetMaxSessions()
	for {
		current := atomic.LoadInt32(&t.sessionCount)
		if int(current) >= maxSessions {
			return ErrConnectionPoolFull
		}
		if atomic.CompareAndSwapInt32(&t.sessionCount, current, current+1) {
			return nil
		}
	}
}

func (t *SSU2Transport) unreserveSessionSlot() {
	for {
		current := atomic.LoadInt32(&t.sessionCount)
		if current <= 0 {
			return
		}
		if atomic.CompareAndSwapInt32(&t.sessionCount, current, current-1) {
			return
		}
	}
}

// removeSession removes a session from the session map (called by session cleanup callback).
// SA-2 fix: During shutdown, cleanup callbacks skip removeSession to avoid double-decrement.
func (t *SSU2Transport) removeSession(routerHash data.Hash) {
	shutdownFlag := atomic.LoadInt32(&t.isShuttingDown)
	if shutdownFlag != 0 {
		// Close() will handle cleanup; skip to prevent double-decrement
		return
	}
	if _, loaded := t.sessions.LoadAndDelete(routerHash); loaded {
		atomic.AddInt32(&t.sessionCount, -1)
	}
}

// findSessionByAddr iterates all active sessions and returns the first
// SSU2Session whose remote address matches addr. Returns nil if none found.
func (t *SSU2Transport) findSessionByAddr(addr *net.UDPAddr) *SSU2Session {
	if addr == nil {
		return nil
	}
	addrString := addr.String()
	var found *SSU2Session
	t.sessions.Range(func(_, value interface{}) bool {
		s, ok := value.(*SSU2Session)
		if !ok {
			return true
		}
		// Use locked accessor to avoid race with DetachConn (R-1 fix).
		remoteAddr := s.RemoteAddr()
		if remoteAddr != nil && remoteAddr.String() == addrString {
			found = s
			return false
		}
		return true
	})
	return found
}

// findSessionByHash looks up a session by the peer's identity hash.
// Returns nil if no session exists for the given hash.
// Handles both raw connections (promoting them if needed) and full sessions (MEDIUM 3.5).
func (t *SSU2Transport) findSessionByHash(hash data.Hash) *SSU2Session {
	val, ok := t.sessions.Load(hash)
	if !ok {
		return nil
	}

	// Already a full session
	if s, ok := val.(*SSU2Session); ok {
		return s
	}

	// Skip connections already delivered to Accept() (R-3 fix).
	// The Accept() consumer owns the socket; promotion would create dual ownership.
	if _, ok := val.(acceptedConn); ok {
		return nil
	}

	// Raw connection that needs promotion
	if conn, ok := val.(net.Conn); ok {
		if promoted, success := t.promoteInboundConnection(conn, val, hash); success {
			if session, ok := promoted.(*SSU2Session); ok {
				return session
			}
		}
		return nil
	}

	return nil
}

// RemoteUDPAddr returns the remote UDP address of the session's underlying
// SSU2 connection.
func (s *SSU2Session) RemoteUDPAddr() *net.UDPAddr {
	conn := s.Conn()
	if conn == nil {
		return nil
	}
	return conn.GetRemoteAddr()
}
