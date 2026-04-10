package ssu2

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/go-i2p/lib/transport"
	nattraversal "github.com/go-i2p/go-nat-listener"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// SSU2Transport implements transport.Transport for SSU2 connections.
type SSU2Transport struct {
	listener *ssu2noise.SSU2Listener
	config   *Config
	identity router_info.RouterInfo
	keystore KeystoreProvider
	handler  *DefaultHandler

	sessions     sync.Map
	sessionCount int32

	identityMu sync.RWMutex

	// NAT traversal managers (initialised after listener starts).
	peerTestManager    *ssu2noise.PeerTestManager
	relayManager       *ssu2noise.RelayManager
	introducerRegistry *ssu2noise.IntroducerRegistry
	holePunchCoord     *ssu2noise.HolePunchCoordinator

	// pendingRelayResponses holds channels waiting for a RelayResponse keyed by nonce.
	// Used by dialViaIntroducer to synchronise with the protocol callback.
	pendingRelayResponses sync.Map // map[uint32]chan *ssu2noise.RelayResponseBlock

	// NAT state cache with TTL.
	natStateCache *natState

	// Key management.
	persistentConfig   *PersistentConfig
	keyRotationManager *ssu2noise.KeyRotationManager

	// peerConnNotifier receives connection outcome feedback (optional).
	// Set via SetPeerConnNotifier after construction.
	peerConnNotifier transport.PeerConnNotifier

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	logger *logger.Entry
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

	identHash, err := identity.IdentHash()
	if err != nil {
		cancel()
		return nil, oops.Wrapf(err, "failed to get router identity hash")
	}
	identHashBytes := identHash.Bytes()
	l.WithFields(map[string]interface{}{
		"router_hash":      fmt.Sprintf("%x", identHashBytes[:8]),
		"listener_address": config.ListenerAddress,
	}).Info("Initializing SSU2 transport")

	ssu2Config, err := createSSU2Config(identity)
	if err != nil {
		cancel()
		return nil, err
	}

	if err := initializeCryptoKeys(ssu2Config, keystore); err != nil {
		cancel()
		return nil, err
	}

	config.SSU2Config = ssu2Config

	t := &SSU2Transport{
		config:        config,
		identity:      identity,
		keystore:      keystore,
		handler:       NewDefaultHandler(),
		natStateCache: &natState{},
		ctx:           ctx,
		cancel:        cancel,
		logger:        l,
	}

	if err := setupUDPListener(t, config, ssu2Config); err != nil {
		cancel()
		return nil, err
	}

	if config.WorkingDir != "" {
		if err := initKeyManagement(t, ssu2Config); err != nil {
			cancel()
			return nil, err
		}
	}

	l.WithField("address", t.Addr().String()).Info("SSU2 transport initialized")
	return t, nil
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

	var udpConn net.PacketConn

	if iport == 0 {
		// Port 0 means "let the OS choose". NAT traversal requires a specific
		// port to map, so skip it and create the connection directly.
		udpAddr, resolveErr := net.ResolveUDPAddr("udp", config.ListenerAddress)
		if resolveErr != nil {
			return oops.Wrapf(resolveErr, "failed to resolve UDP address")
		}
		rawConn, listenErr := net.ListenUDP("udp", udpAddr)
		if listenErr != nil {
			return oops.Wrapf(listenErr, "failed to create UDP listener")
		}
		config.ListenerAddress = rawConn.LocalAddr().String()
		log.WithField("address", config.ListenerAddress).Info("UDP listener started (no NAT traversal for OS-assigned port)")
		udpConn = rawConn
	} else {
		// A specific port was requested — attempt NAT traversal with fallback.
		natCtx, natCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer natCancel()
		natPL, natErr := nattraversal.ListenPacketWithFallbackContext(natCtx, iport)
		if natErr != nil {
			return oops.Wrapf(natErr, "failed to create UDP listener")
		}
		// Keep config in sync with the actual bound address.
		if boundAddr := natPL.Addr().String(); boundAddr != config.ListenerAddress {
			config.ListenerAddress = boundAddr
		}
		udpConn = natPL.PacketConn()
	}

	listener, err := ssu2noise.NewSSU2Listener(udpConn, ssu2Config)
	if err != nil {
		udpConn.Close()
		return WrapSSU2Error(err, "creating SSU2 listener")
	}

	if err := listener.Start(); err != nil {
		udpConn.Close()
		return WrapSSU2Error(err, "starting SSU2 listener")
	}

	t.listener = listener
	initNATManagers(t)
	return nil
}

// Accept accepts an incoming SSU2 connection.
func (t *SSU2Transport) Accept() (net.Conn, error) {
	if t.listener == nil {
		return nil, ErrSessionClosed
	}

	if err := t.checkSessionLimit(); err != nil {
		return nil, err
	}

	conn, err := t.listener.Accept()
	if err != nil {
		t.unreserveSessionSlot()
		return nil, err
	}

	return t.trackInboundConnection(conn), nil
}

func (t *SSU2Transport) trackInboundConnection(conn net.Conn) net.Conn {
	peerHash := t.extractPeerHash(conn)
	if _, loaded := t.sessions.LoadOrStore(peerHash, conn); loaded {
		t.unreserveSessionSlot()
	}
	return &trackedConn{
		Conn: conn,
		onClose: func() {
			t.removeSession(peerHash)
		},
	}
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
	addrStr := conn.RemoteAddr().String()
	if host, _, err := net.SplitHostPort(addrStr); err == nil {
		addrStr = host
	}
	copy(peerHash[:], []byte(addrStr))
	if len([]byte(addrStr)) < 32 {
		peerHash[31] = 0xFE // marker for address-derived SSU2 hash
	}
	return peerHash
}

// trackedConn wraps a net.Conn to execute a cleanup function when closed.
type trackedConn struct {
	net.Conn
	onClose   func()
	closeOnce sync.Once
}

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
	t.peerConnNotifier = n
}

// recordPeerAttempt notifies the PeerTracker of a dial attempt if wired.
func (t *SSU2Transport) recordPeerAttempt(hash data.Hash) {
	if n := t.peerConnNotifier; n != nil {
		n.RecordAttempt(hash)
	}
}

// recordPeerFailure notifies the PeerTracker of a dial failure. If the error
// is ErrInvalidRouterInfo, the peer is marked as permanently unreachable.
func (t *SSU2Transport) recordPeerFailure(hash data.Hash, err error) {
	if n := t.peerConnNotifier; n != nil {
		if errors.Is(err, ErrInvalidRouterInfo) {
			n.RecordPermanentFailure(hash, "no_reachable_ssu2_address")
		} else {
			n.RecordFailure(hash, err.Error())
		}
	}
}

// recordPeerSuccess notifies the PeerTracker of a successful connection.
func (t *SSU2Transport) recordPeerSuccess(hash data.Hash, latencyMs int64) {
	if n := t.peerConnNotifier; n != nil {
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

	t.identityMu.Lock()
	t.identity = ident
	t.config.SSU2Config = ssu2Config
	t.identityMu.Unlock()

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
	if session, ok := existing.(*SSU2Session); ok {
		if session.ctx.Err() != nil {
			if _, loaded := t.sessions.LoadAndDelete(routerHash); loaded {
				atomic.AddInt32(&t.sessionCount, -1)
			}
			return nil, false
		}
		return session, true
	}
	if conn, ok := existing.(net.Conn); ok {
		return t.promoteInboundConnection(conn, existing, routerHash)
	}
	return nil, false
}

func (t *SSU2Transport) promoteInboundConnection(conn net.Conn, original interface{}, routerHash data.Hash) (transport.TransportSession, bool) {
	ssu2Conn, ok := conn.(*ssu2noise.SSU2Conn)
	if !ok {
		return nil, false
	}
	promoted := NewSSU2Session(ssu2Conn, t.ctx, t.logger)
	promoted.maxRetransmit = t.config.GetMaxRetransmissions()
	promoted.SetTransportCallbacks(t.buildTransportCallbacks())
	if t.sessions.CompareAndSwap(routerHash, original, promoted) {
		promoted.SetCleanupCallback(func() {
			t.removeSession(routerHash)
		})
		return promoted, true
	}
	promoted.Close()
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
	ssu2Addr, err := ExtractSSU2Addr(routerInfo)
	if err != nil {
		return nil, nil, WrapSSU2Error(err, "extracting SSU2 address")
	}

	remoteUDPAddr, err := net.ResolveUDPAddr("udp", ssu2Addr.String())
	if err != nil {
		return nil, nil, WrapSSU2Error(err, "resolving remote UDP address")
	}

	t.identityMu.RLock()
	identHash, err := t.identity.IdentHash()
	t.identityMu.RUnlock()
	if err != nil {
		return nil, nil, oops.Wrapf(err, "failed to get our identity hash")
	}

	dialConfig, err := ssu2noise.NewSSU2Config(identHash, true)
	if err != nil {
		return nil, nil, WrapSSU2Error(err, "creating dial config")
	}

	if err := initializeCryptoKeys(dialConfig, t.keystore); err != nil {
		return nil, nil, err
	}

	remoteHash, err := routerInfo.IdentHash()
	if err != nil {
		return nil, nil, oops.Wrapf(err, "failed to get remote router hash")
	}
	dialConfig = dialConfig.WithRemoteRouterHash(remoteHash)

	remoteStaticKey, err := extractRemoteStaticKey(routerInfo)
	if err != nil {
		return nil, nil, WrapSSU2Error(err, "extracting remote static key")
	}
	dialConfig = dialConfig.WithRemoteStaticKey(remoteStaticKey)

	// Set our local intro key so that header protection is enabled for the
	// outbound session (initHeaderProtection requires IntroKey to be set).
	if ik := t.GetIntroKey(); len(ik) == 32 {
		dialConfig.IntroKey = ik
	}

	// Set the remote router's intro key so that the first-packet ChaCha
	// obfuscation uses Bob's published intro key rather than the fallback
	// router hash, which would cause Bob to discard our SessionRequest.
	remoteIK, err := ExtractSSU2IntroKey(routerInfo)
	if err != nil {
		return nil, nil, WrapSSU2Error(err, "extracting remote SSU2 intro key")
	}
	dialConfig.RemoteIntroKey = remoteIK

	return dialConfig, remoteUDPAddr, nil
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
	session.SetTransportCallbacks(t.buildTransportCallbacks())

	existing, loaded := t.sessions.LoadOrStore(routerHash, session)
	if loaded {
		session.Close()
		if existingSession, ok := existing.(*SSU2Session); ok {
			return existingSession, false, nil // Reusing existing, slot not used
		}
		return nil, false, oops.Errorf("unexpected session map entry type")
	}

	session.StartWorkers()
	session.SetCleanupCallback(func() {
		t.removeSession(routerHash)
	})
	return session, true, nil // New session, slot is used
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

// Close closes the transport cleanly.
func (t *SSU2Transport) Close() error {
	t.logger.Info("Closing SSU2 transport")
	t.cancel()

	if t.relayManager != nil {
		t.relayManager.Stop()
	}

	if t.keyRotationManager != nil {
		t.keyRotationManager.Stop()
	}

	var listenerErr error
	if t.listener != nil {
		listenerErr = t.listener.Close()
	}

	t.sessions.Range(func(key, value interface{}) bool {
		if session, ok := value.(*SSU2Session); ok {
			session.Close()
		} else if conn, ok := value.(net.Conn); ok {
			conn.Close()
		}
		return true
	})

	t.wg.Wait()
	t.handler.Close()

	t.logger.Info("SSU2 transport closed")
	return listenerErr
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

func (t *SSU2Transport) removeSession(routerHash data.Hash) {
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
	var found *SSU2Session
	t.sessions.Range(func(_, value interface{}) bool {
		s, ok := value.(*SSU2Session)
		if !ok || s.conn == nil {
			return true
		}
		if s.conn.RemoteAddr().String() == addr.String() {
			found = s
			return false
		}
		return true
	})
	return found
}

// findSessionByHash looks up a session by the peer's identity hash.
// Returns nil if no session exists for the given hash.
func (t *SSU2Transport) findSessionByHash(hash data.Hash) *SSU2Session {
	val, ok := t.sessions.Load(hash)
	if !ok {
		return nil
	}
	s, _ := val.(*SSU2Session)
	return s
}

// RemoteUDPAddr returns the remote UDP address of the session's underlying
// SSU2 connection.
func (s *SSU2Session) RemoteUDPAddr() *net.UDPAddr {
	if s.conn == nil {
		return nil
	}
	return s.conn.GetRemoteAddr()
}
