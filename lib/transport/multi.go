package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"

	"github.com/go-i2p/go-i2p/lib/util/logutil"
)

// DefaultMaxConnections is the default maximum number of concurrent connections
// across all muxed transports. This prevents resource exhaustion under heavy load.
const DefaultMaxConnections = 1024

// peerCooldown is how long to suppress connection attempts to a peer after all
// transports failed. This avoids flooding the network with doomed dials.
const peerCooldown = 60 * time.Second

// Compile-time check that TransportMuxer implements Transport interface
var _ Transport = (*TransportMuxer)(nil)

// TransportMuxer muxes multiple transports into one Transport.
// It implements transport.Transport.
type TransportMuxer struct {
	// the underlying transports we are using in order of most prominant to least
	trans []Transport

	// MaxConnections is the maximum number of concurrent sessions allowed
	// across all transports in this muxer. 0 means use DefaultMaxConnections.
	MaxConnections int

	// activeSessionCount tracks the number of currently active sessions
	activeSessionCount int32 // atomic

	// failedPeers records the last failure time for peers whose transports all
	// failed. GetSession skips peers still inside the cooldown window to avoid
	// repeatedly dialling unreachable routers (RCA-3 / AUDIT.md).
	failedPeers    map[[32]byte]time.Time
	peerCooldownMu sync.Mutex

	// acceptChan is a persistent channel fed by long-lived accept goroutines.
	// Lazily initialised by ensureAcceptLoop. Connections arriving here are
	// not yet counted against the connection limit — the caller of Accept /
	// AcceptWithTimeout must still call checkConnectionLimit.
	acceptChan chan acceptResult

	// acceptOnce guards one-time startup of the persistent accept loop.
	acceptOnce sync.Once

	// acceptDone is closed when Close() is called to signal accept goroutines to exit.
	acceptDone chan struct{}

	// acceptWg tracks the persistent accept goroutines so Close() can wait
	// for them to actually exit rather than hoping they will.
	acceptWg sync.WaitGroup

	// closeOnce ensures Close() is idempotent.
	closeOnce sync.Once
	closeErr  error
}

// Mux combines a set of transports together.
func Mux(t ...Transport) (tmux *TransportMuxer) {
	tmux = &TransportMuxer{
		acceptDone:  make(chan struct{}),
		failedPeers: make(map[[32]byte]time.Time),
	}
	tmux.trans = append(tmux.trans, t...)
	tmux.acceptWg.Add(1)
	go tmux.failedPeersCleanupLoop()
	return tmux
}

// MuxWithLimit creates a TransportMuxer with a specified maximum connection limit.
func MuxWithLimit(maxConnections int, t ...Transport) (tmux *TransportMuxer) {
	tmux = Mux(t...)
	tmux.MaxConnections = maxConnections
	return tmux
}

func (tmux *TransportMuxer) logMuxerMethod(methodName string, fields logger.Fields, level, message string) {
	entry := logAt("(TransportMuxer) " + methodName).WithFields(fields)
	switch level {
	case "error":
		entry.Error(message)
	case "warn":
		entry.Warn(message)
	default:
		entry.Debug(message)
	}
}

// ReleaseSession decrements the active session counter.
// This should be called when a session is closed to free up capacity.
// If the counter would go below zero (indicating a bookkeeping bug with more
// releases than reservations), it is clamped at zero and logged as a warning.
func (tmux *TransportMuxer) ReleaseSession() {
	newCount := atomic.AddInt32(&tmux.activeSessionCount, -1)
	if newCount < 0 {
		// Underflow: more releases than reservations; indicates a bug in session tracking.
		// Clamp to zero and log a warning.
		atomic.StoreInt32(&tmux.activeSessionCount, 0)
		logAt("(TransportMuxer) ReleaseSession").WithFields(logger.Fields{}).Warn("session counter underflow; releases exceed reservations (clamped to 0)")
	}
}

// SetIdentity sets the identity for every transport.
func (tmux *TransportMuxer) SetIdentity(ident router_info.RouterInfo) (err error) {
	identHash, _ := ident.IdentHash()
	tmux.logMuxerMethod("SetIdentity", logger.Fields{
		"reason":          "configure_all_transports",
		"identity_hash":   logutil.HashPrefix(identHash),
		"transport_count": len(tmux.trans),
	}, "debug", "setting identity for all transports")
	for i, t := range tmux.trans {
		err = t.SetIdentity(ident)
		if err != nil {
			tmux.logMuxerMethod("SetIdentity", logger.Fields{
				"reason":          "transport_rejected_identity",
				"transport_index": i,
				"error":           err.Error(),
			}, "error", "failed to set identity for transport")
			// an error happened let's return and complain
			return err
		}
		tmux.logMuxerMethod("SetIdentity", logger.Fields{
			"reason":          "transport_configured",
			"transport_index": i,
		}, "debug", "identity set for transport")
	}
	tmux.logMuxerMethod("SetIdentity", logger.Fields{
		"reason": "all_transports_configured",
	}, "debug", "identity set for all transports")
	return err
}

// Close closes every transport that this transport muxer has.
func (tmux *TransportMuxer) Close() (err error) {
	tmux.closeOnce.Do(func() {
		tmux.logMuxerMethod("Close", logger.Fields{
			"reason":          "shutdown_requested",
			"transport_count": len(tmux.trans),
		}, "debug", "closing all transports")

		tmux.signalAcceptDone()

		errs := tmux.closeAllTransports()

		tmux.waitForAcceptGoroutines()

		tmux.logMuxerMethod("Close", logger.Fields{
			"reason": "all_transports_closed",
		}, "debug", "all transports closed")
		tmux.closeErr = errors.Join(errs...)
	})
	return tmux.closeErr
}

// signalAcceptDone closes the acceptDone channel to stop persistent accept loops.
// Safe to call if the channel is already closed.
func (tmux *TransportMuxer) signalAcceptDone() {
	select {
	case <-tmux.acceptDone:
		// already closed
	default:
		close(tmux.acceptDone)
	}
}

// closeAllTransports iterates through all registered transports and closes each one,
// collecting any errors encountered.
func (tmux *TransportMuxer) closeAllTransports() []error {
	var errs []error
	for i, t := range tmux.trans {
		if closeErr := t.Close(); closeErr != nil {
			errs = append(errs, closeErr)
			tmux.logMuxerMethod("Close", logger.Fields{
				"reason":          "transport_close_failed",
				"transport_index": i,
				"error":           closeErr.Error(),
			}, "warn", "error closing transport")
		} else {
			tmux.logMuxerMethod("Close", logger.Fields{
				"reason":          "transport_closed",
				"transport_index": i,
			}, "debug", "transport closed successfully")
		}
	}
	return errs
}

// waitForAcceptGoroutines waits up to 3 seconds for accept goroutines to exit
// after transports have been closed.
func (tmux *TransportMuxer) waitForAcceptGoroutines() {
	acceptExited := make(chan struct{})
	go func() {
		tmux.acceptWg.Wait()
		close(acceptExited)
	}()
	select {
	case <-acceptExited:
		tmux.logMuxerMethod("Close", logger.Fields{
			"reason": "accept_goroutines_exited",
		}, "debug", "all accept goroutines exited cleanly")
	case <-time.After(3 * time.Second):
		tmux.logMuxerMethod("Close", logger.Fields{
			"reason": "accept_goroutines_timeout",
		}, "warn", "timed out waiting for accept goroutines to exit")
	}
}

// Name returns the name of this transport combined with the names of all the ones that we mux.
func (tmux *TransportMuxer) Name() string {
	if len(tmux.trans) == 0 {
		return "Muxed Transport: (none)"
	}

	var sb strings.Builder
	sb.WriteString("Muxed Transport: ")
	first := true
	for _, t := range tmux.trans {
		if t == nil {
			continue
		}
		if !first {
			sb.WriteString(", ")
		}
		first = false
		sb.WriteString(t.Name())
	}
	return sb.String()
}

// tryGetSessionFromTransport attempts to get a session from a compatible transport.
// Returns the session and nil if successful, or nil and an error if it fails.
func (tmux *TransportMuxer) tryGetSessionFromTransport(t Transport, routerInfo router_info.RouterInfo, index int) (TransportSession, error) {
	peerHash, _ := routerInfo.IdentHash()
	logAt("(TransportMuxer) GetSession").WithFields(logger.Fields{
		"reason":          "compatible_transport_found",
		"transport_index": index,
	}).Debug("found compatible transport, attempting session")

	s, err := t.GetSession(routerInfo)
	if err != nil {
		logAt("(TransportMuxer) GetSession").WithFields(logger.Fields{
			"phase":           "session_establishment",
			"reason":          "session_creation_failed",
			"transport_name":  t.Name(),
			"transport_index": index,
			"peer_hash":       fmt.Sprintf("%x", peerHash[:]),
			"error":           err.Error(),
			"impact":          "cannot communicate with this peer via this transport",
			"addresses":       len(routerInfo.RouterAddresses()),
		}).Warn("transport session failed, trying next transport")
		return nil, err
	}

	logAt("(TransportMuxer) GetSession").WithFields(logger.Fields{
		"reason":          "session_established",
		"transport_index": index,
	}).Debug("successfully got session from transport")
	return s, nil
}

// collectAddressTypes returns the transport style strings from all RouterAddresses.
func collectAddressTypes(routerInfo router_info.RouterInfo) []string {
	addressTypes := make([]string, 0, len(routerInfo.RouterAddresses()))
	for _, addr := range routerInfo.RouterAddresses() {
		style := addr.TransportStyle()
		if styleBytes, err := style.Data(); err == nil {
			addressTypes = append(addressTypes, string(styleBytes))
		}
	}
	return addressTypes
}

// logNoTransportError logs diagnostics when none of our registered transports
// know how to reach the peer's advertised address types at all.
func (tmux *TransportMuxer) logNoTransportError(routerInfo router_info.RouterInfo) {
	peerHash, _ := routerInfo.IdentHash()
	addressTypes := collectAddressTypes(routerInfo)

	logAt("(TransportMuxer) GetSession").WithFields(logger.Fields{
		"phase":          "session_establishment",
		"reason":         "no_compatible_transport",
		"peer_hash":      fmt.Sprintf("%x", peerHash[:]),
		"num_transports": len(tmux.trans),
		"addresses":      len(routerInfo.RouterAddresses()),
		"address_types":  addressTypes,
		"impact":         "peer completely unreachable",
		"diagnosis":      "none of our registered transports support this peer's address types",
	}).Error("failed to get session - no compatible transport for peer's address types")
}

// logAllTransportsFailed logs diagnostics when compatible transports were found
// but every attempt to establish a session failed.
func (tmux *TransportMuxer) logAllTransportsFailed(routerInfo router_info.RouterInfo) {
	peerHash, _ := routerInfo.IdentHash()
	addressTypes := collectAddressTypes(routerInfo)

	tmux.recordPeerFailure(peerHash)

	logAt("(TransportMuxer) GetSession").WithFields(logger.Fields{
		"phase":          "session_establishment",
		"reason":         "all_transports_failed",
		"peer_hash":      fmt.Sprintf("%x", peerHash[:]),
		"num_transports": len(tmux.trans),
		"addresses":      len(routerInfo.RouterAddresses()),
		"address_types":  addressTypes,
		"cooldown":       peerCooldown.String(),
		"impact":         "peer unreachable via all compatible transports",
		"diagnosis":      "all compatible transport handshakes or dials failed; check individual transport warnings above",
	}).Warn("failed to get session - all compatible transports failed")
}

// isPeerCoolingDown returns true if we recently failed to reach this peer and
// should skip retrying until the cooldown expires.
func (tmux *TransportMuxer) isPeerCoolingDown(peerHash [32]byte) bool {
	tmux.peerCooldownMu.Lock()
	defer tmux.peerCooldownMu.Unlock()

	if failTime, ok := tmux.failedPeers[peerHash]; ok {
		if time.Since(failTime) < peerCooldown {
			return true
		}
		delete(tmux.failedPeers, peerHash)
	}
	return false
}

// recordPeerFailure marks a peer as recently failed so future GetSession calls
// are suppressed for the cooldown window.
func (tmux *TransportMuxer) recordPeerFailure(peerHash [32]byte) {
	tmux.peerCooldownMu.Lock()
	defer tmux.peerCooldownMu.Unlock()

	tmux.failedPeers[peerHash] = time.Now()
}

// cleanupExpiredPeers removes failedPeers entries whose cooldown has expired.
// This prevents unbounded map growth for peers that fail once and are never
// re-contacted.
func (tmux *TransportMuxer) cleanupExpiredPeers() {
	tmux.peerCooldownMu.Lock()
	defer tmux.peerCooldownMu.Unlock()
	for hash, failTime := range tmux.failedPeers {
		if time.Since(failTime) >= peerCooldown {
			delete(tmux.failedPeers, hash)
		}
	}
}

// failedPeersCleanupLoop periodically sweeps expired entries from the
// failedPeers map to prevent unbounded growth over the router's lifetime.
func (tmux *TransportMuxer) failedPeersCleanupLoop() {
	defer tmux.acceptWg.Done()
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			tmux.cleanupExpiredPeers()
		case <-tmux.acceptDone:
			return
		}
	}
}

// get a transport session given a router info
// return session and nil if successful
// findCompatibleSession tries each registered transport in order and returns
// the first successfully established session. Returns the session, whether any
// compatible transport was found, whether a slot was consumed, and any error.
func (tmux *TransportMuxer) findCompatibleSession(routerInfo router_info.RouterInfo) (TransportSession, bool, bool, error) {
	for i, t := range tmux.trans {
		if !t.Compatible(routerInfo) {
			continue
		}
		s, err := tmux.tryGetSessionFromTransport(t, routerInfo, i)
		if err != nil {
			continue
		}
		return s, true, true, nil
	}
	// Walk again to report whether any compatible transport existed.
	for _, t := range tmux.trans {
		if t.Compatible(routerInfo) {
			return nil, true, false, nil
		}
	}
	return nil, false, false, nil
}

func (tmux *TransportMuxer) beginSessionAttempt(routerInfo router_info.RouterInfo) error {
	peerHash, _ := routerInfo.IdentHash()

	// Skip peers that recently failed all transports (cooldown window).
	if tmux.isPeerCoolingDown(peerHash) {
		tmux.logMuxerMethod("GetSession", logger.Fields{
			"reason":    "peer_cooldown",
			"peer_hash": logutil.HashPrefix(peerHash),
			"cooldown":  peerCooldown.String(),
		}, "debug", "skipping peer still in cooldown")
		return ErrNoTransportAvailable
	}

	tmux.logMuxerMethod("GetSession", logger.Fields{
		"reason":         "attempting_peer_connection",
		"peer_hash":      logutil.HashPrefix(peerHash),
		"num_transports": len(tmux.trans),
	}, "debug", "attempting to get session")

	return tmux.checkConnectionLimit()
}

func (tmux *TransportMuxer) handleSessionFailure(routerInfo router_info.RouterInfo, compatibleFound bool) error {
	if compatibleFound {
		tmux.logAllTransportsFailed(routerInfo)
	} else {
		tmux.logNoTransportError(routerInfo)
	}
	return ErrNoTransportAvailable
}

// GetSession returns nil and ErrNoTransportAvailable if we failed to get a session,
// or nil and ErrConnectionPoolFull if the connection limit has been reached.
func (tmux *TransportMuxer) GetSession(routerInfo router_info.RouterInfo) (s TransportSession, err error) {
	if err := tmux.beginSessionAttempt(routerInfo); err != nil {
		return nil, err
	}

	// Ensure the reserved slot is released if we don't return a session.
	// This prevents permanent counter drift if a transport panics or all
	// transports fail to produce a session.
	slotUsed := false
	defer func() {
		if !slotUsed {
			atomic.AddInt32(&tmux.activeSessionCount, -1)
		}
	}()

	session, compatibleFound, slotConsumed, _ := tmux.findCompatibleSession(routerInfo)
	if slotConsumed {
		slotUsed = true
		return &trackedSession{TransportSession: session, mux: tmux}, nil
	}

	// No session established — slot will be released by defer.
	return nil, tmux.handleSessionFailure(routerInfo, compatibleFound)
}

// Compatible returns true if there is a transport that we mux that is compatible with this router info.
func (tmux *TransportMuxer) Compatible(routerInfo router_info.RouterInfo) bool {
	for _, t := range tmux.trans {
		if t.Compatible(routerInfo) {
			return true
		}
	}
	return false
}

// Accept accepts an incoming connection from any available transport.
// This implements the Transport interface requirement.
// It listens on ALL transports via a persistent accept loop and returns the first connection.
// Returns the connection and nil on success.
// Returns nil and ErrNoTransportAvailable if no transports are configured.
// Returns nil and ErrConnectionPoolFull if the connection limit has been reached.
func (tmux *TransportMuxer) Accept() (net.Conn, error) {
	tmux.logMuxerMethod("Accept", logger.Fields{
		"reason":          "awaiting_connection",
		"transport_count": len(tmux.trans),
	}, "debug", "accepting connection from all transports")

	if err := tmux.validateTransports(); err != nil {
		return nil, err
	}

	if err := tmux.checkConnectionLimit(); err != nil {
		return nil, err
	}

	tmux.ensureAcceptLoop()

	return tmux.waitForAcceptedConnection()
}

// waitForAcceptedConnection blocks until a connection is available from the accept loop
// or the muxer shuts down. Returns the accepted connection wrapped in a trackedConn.
func (tmux *TransportMuxer) waitForAcceptedConnection() (net.Conn, error) {
	select {
	case res, ok := <-tmux.acceptChan:
		return tmux.handleAcceptResultCommon(res, ok, "Accept")
	case <-tmux.acceptDone:
		atomic.AddInt32(&tmux.activeSessionCount, -1)
		return nil, oops.Errorf("transport muxer closed")
	}
}

// Addr returns the address of the first transport's listener.
// This implements the Transport interface requirement.
// Returns nil if no transports are configured.
func (tmux *TransportMuxer) Addr() net.Addr {
	if len(tmux.trans) == 0 {
		return nil
	}
	return tmux.trans[0].Addr()
}

// AcceptWithTimeout accepts an incoming connection with a timeout.
// This method listens on ALL transports via a persistent accept loop with a timeout,
// enabling graceful shutdown of session monitoring loops.
// Returns the connection and nil on success.
// Returns nil and context.DeadlineExceeded if the timeout expires.
// Returns nil and any other error from the underlying transport Accept().
func (tmux *TransportMuxer) AcceptWithTimeout(timeout time.Duration) (net.Conn, error) {
	tmux.logMuxerMethod("AcceptWithTimeout", logger.Fields{
		"reason":          "awaiting_connection",
		"timeout_ms":      timeout.Milliseconds(),
		"transport_count": len(tmux.trans),
	}, "debug", "accepting connection with timeout from all transports")

	if err := tmux.validateTransports(); err != nil {
		return nil, err
	}

	if err := tmux.checkConnectionLimit(); err != nil {
		return nil, err
	}

	tmux.ensureAcceptLoop()

	return tmux.waitForConnection(timeout)
}

// waitForConnection blocks until a connection is accepted, the timeout expires,
// or the muxer is closed.
func (tmux *TransportMuxer) waitForConnection(timeout time.Duration) (net.Conn, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case res, ok := <-tmux.acceptChan:
		return tmux.handleAcceptResultCommon(res, ok, "AcceptWithTimeout")
	case <-timer.C:
		atomic.AddInt32(&tmux.activeSessionCount, -1)
		tmux.logMuxerMethod("AcceptWithTimeout", logger.Fields{
			"reason": "timeout_exceeded",
		}, "debug", "accept timed out")
		return nil, context.DeadlineExceeded
	case <-tmux.acceptDone:
		atomic.AddInt32(&tmux.activeSessionCount, -1)
		return nil, oops.Errorf("transport muxer closed")
	}
}

// handleAcceptResultCommon processes a result from the accept channel.
func (tmux *TransportMuxer) handleAcceptResultCommon(res acceptResult, ok bool, methodName string) (net.Conn, error) {
	if !ok {
		atomic.AddInt32(&tmux.activeSessionCount, -1)
		return nil, oops.Errorf("transport muxer closed")
	}
	if res.err != nil {
		atomic.AddInt32(&tmux.activeSessionCount, -1)
		return nil, res.err
	}
	tmux.logMuxerMethod(methodName, logger.Fields{
		"reason":          "connection_accepted",
		"transport_index": res.transportIndex,
		"active_sessions": atomic.LoadInt32(&tmux.activeSessionCount),
	}, "debug", "accept succeeded")
	return NewTrackedConn(res.conn, tmux.ReleaseSession), nil
}

// validateTransports checks that at least one transport is configured.
// Returns ErrNoTransportAvailable if no transports are registered.
func (tmux *TransportMuxer) validateTransports() error {
	if len(tmux.trans) == 0 {
		return ErrNoTransportAvailable
	}
	return nil
}

// ensureAcceptLoop starts the persistent accept goroutines exactly once.
// Each transport gets one long-lived goroutine that continuously calls Accept()
// and feeds results into the shared acceptChan. Goroutines exit when their
// transport.Accept() returns an error after Close() has been called, or
// when acceptDone is closed.
func (tmux *TransportMuxer) ensureAcceptLoop() {
	tmux.acceptOnce.Do(func() {
		// Buffer large enough so goroutines can always send without blocking
		tmux.acceptChan = make(chan acceptResult, len(tmux.trans)*4)
		for i, t := range tmux.trans {
			tmux.acceptWg.Add(1)
			go tmux.runAcceptWorker(t, i)
		}
	})
}

// runAcceptWorker runs a persistent accept loop for a single transport.
// It continuously calls Accept() on the transport and forwards results
// to the shared acceptChan. The worker exits when acceptDone is closed.
func (tmux *TransportMuxer) runAcceptWorker(t Transport, index int) {
	defer tmux.acceptWg.Done()
	for {
		conn, err := t.Accept()
		if tmux.isShuttingDown(conn) {
			return
		}
		if !tmux.processAcceptResult(conn, err, index) {
			return
		}
	}
}

// processAcceptResult processes accept result and returns false if worker should stop.
func (tmux *TransportMuxer) processAcceptResult(conn net.Conn, err error, index int) bool {
	if err != nil {
		tmux.logMuxerMethod("acceptLoop", logger.Fields{
			"transport_index": index,
			"error":           err.Error(),
		}, "debug", "accept error from transport")
		if tmux.shouldStopAfterError() {
			return false
		}
		// Temporary error — brief back-off then retry
		time.Sleep(50 * time.Millisecond)
		return true
	}
	return tmux.deliverAcceptResult(conn, index)
}

// isShuttingDown checks whether the muxer is shutting down and closes
// any just-accepted connection if so.
func (tmux *TransportMuxer) isShuttingDown(conn net.Conn) bool {
	select {
	case <-tmux.acceptDone:
		if conn != nil {
			conn.Close()
		}
		return true
	default:
		return false
	}
}

// shouldStopAfterError checks whether the muxer is shutting down after
// an accept error. Returns true if the accept loop should exit.
func (tmux *TransportMuxer) shouldStopAfterError() bool {
	select {
	case <-tmux.acceptDone:
		return true
	default:
		return false
	}
}

// deliverAcceptResult sends a successfully accepted connection to the
// shared acceptChan. Returns false if the muxer is shutting down.
func (tmux *TransportMuxer) deliverAcceptResult(conn net.Conn, index int) bool {
	select {
	case tmux.acceptChan <- acceptResult{conn: conn, err: nil, transportIndex: index}:
		return true
	case <-tmux.acceptDone:
		conn.Close()
		return false
	}
}

type acceptResult struct {
	conn           net.Conn
	err            error
	transportIndex int
}

// getMaxConnections returns the effective maximum connection limit.
// Returns DefaultMaxConnections if MaxConnections is not set (0 or negative).
func (tmux *TransportMuxer) getMaxConnections() int {
	if tmux.MaxConnections <= 0 {
		return DefaultMaxConnections
	}
	return tmux.MaxConnections
}

// ActiveSessionCount returns the current number of active sessions tracked by the muxer.
func (tmux *TransportMuxer) ActiveSessionCount() int {
	return int(atomic.LoadInt32(&tmux.activeSessionCount))
}

// checkConnectionLimit atomically reserves a connection slot. Returns
// ErrConnectionPoolFull if the maximum number of concurrent connections
// has been reached, or nil on success. The caller MUST call
// releaseConnectionSlot if the session creation ultimately fails.
func (tmux *TransportMuxer) checkConnectionLimit() error {
	max := int32(tmux.getMaxConnections())
	current, ok := atomicCompareAndSwapRetry(&tmux.activeSessionCount, func(value int32) bool {
		return value < max
	}, 1)
	if !ok {
		tmux.logMuxerMethod("checkConnectionLimit", logger.Fields{
			"reason":          "connection_pool_full",
			"active_sessions": int(current),
			"max_connections": int(max),
		}, "warn", "connection pool limit reached")
		return ErrConnectionPoolFull
	}
	return nil
}

// GetTransports returns a copy of the slice of transports in this muxer.
// This allows external code to iterate over transports without exposing internal state.
func (tmux *TransportMuxer) GetTransports() []Transport {
	// Return a copy to prevent external modifications
	transports := make([]Transport, len(tmux.trans))
	copy(transports, tmux.trans)
	return transports
}

// trackedSession wraps a TransportSession to auto-decrement the active
// session counter when Close() is called. This prevents counter drift
// that occurs when callers forget to call ReleaseSession().
type trackedSession struct {
	TransportSession
	mux      *TransportMuxer
	released int32 // atomic; 1 = already released
}

// Unwrap returns the underlying TransportSession without the tracking wrapper.
// This allows callers (e.g. registerNewSession) to type-assert the concrete
// session type (NTCP2Session, SSU2Session) for protocol-specific handling.
func (ts *trackedSession) Unwrap() TransportSession {
	return ts.TransportSession
}

// Close closes the underlying session and decrements the active session
// counter exactly once, even if Close is called multiple times.
func (ts *trackedSession) Close() error {
	if atomic.CompareAndSwapInt32(&ts.released, 0, 1) {
		ts.mux.ReleaseSession()
	}
	return ts.TransportSession.Close()
}
