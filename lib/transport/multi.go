package transport

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/logger"
)

// DefaultMaxConnections is the default maximum number of concurrent connections
// across all muxed transports. This prevents resource exhaustion under heavy load.
const DefaultMaxConnections = 1024

// Compile-time check that TransportMuxer implements Transport interface
var _ Transport = (*TransportMuxer)(nil)

// muxes multiple transports into 1 Transport
// implements transport.Transport
type TransportMuxer struct {
	// the underlying transports we are using in order of most prominant to least
	trans []Transport

	// MaxConnections is the maximum number of concurrent sessions allowed
	// across all transports in this muxer. 0 means use DefaultMaxConnections.
	MaxConnections int

	// activeSessionCount tracks the number of currently active sessions
	activeSessionCount int32 // atomic
}

// mux a bunch of transports together
func Mux(t ...Transport) (tmux *TransportMuxer) {
	log.WithFields(logger.Fields{
		"at":              "Mux",
		"reason":          "initialization",
		"transport_count": len(t),
	}).Debug("creating new TransportMuxer")
	tmux = new(TransportMuxer)
	tmux.trans = append(tmux.trans, t...)
	log.WithFields(logger.Fields{
		"at":     "Mux",
		"reason": "created_successfully",
	}).Debug("TransportMuxer created")
	return tmux
}

// MuxWithLimit creates a TransportMuxer with a specified maximum connection limit.
func MuxWithLimit(maxConnections int, t ...Transport) (tmux *TransportMuxer) {
	tmux = Mux(t...)
	tmux.MaxConnections = maxConnections
	log.WithFields(logger.Fields{
		"at":              "MuxWithLimit",
		"max_connections": maxConnections,
	}).Debug("TransportMuxer created with connection limit")
	return tmux
}

// ReleaseSession decrements the active session counter.
// This should be called when a session is closed to free up capacity.
func (tmux *TransportMuxer) ReleaseSession() {
	newCount := atomic.AddInt32(&tmux.activeSessionCount, -1)
	if newCount < 0 {
		atomic.StoreInt32(&tmux.activeSessionCount, 0)
	}
	log.WithFields(logger.Fields{
		"at":              "(TransportMuxer) ReleaseSession",
		"active_sessions": atomic.LoadInt32(&tmux.activeSessionCount),
	}).Debug("session released")
}

// set the identity for every transport
func (tmux *TransportMuxer) SetIdentity(ident router_info.RouterInfo) (err error) {
	identHash, _ := ident.IdentHash()
	log.WithFields(logger.Fields{
		"at":              "(TransportMuxer) SetIdentity",
		"reason":          "configure_all_transports",
		"identity_hash":   fmt.Sprintf("%x...", identHash[:8]),
		"transport_count": len(tmux.trans),
	}).Debug("setting identity for all transports")
	for i, t := range tmux.trans {
		err = t.SetIdentity(ident)
		if err != nil {
			log.WithFields(logger.Fields{
				"at":              "(TransportMuxer) SetIdentity",
				"reason":          "transport_rejected_identity",
				"transport_index": i,
				"error":           err.Error(),
			}).Error("failed to set identity for transport")
			// an error happened let's return and complain
			return err
		}
		log.WithFields(logger.Fields{
			"at":              "(TransportMuxer) SetIdentity",
			"reason":          "transport_configured",
			"transport_index": i,
		}).Debug("identity set for transport")
	}
	log.WithFields(logger.Fields{
		"at":     "(TransportMuxer) SetIdentity",
		"reason": "all_transports_configured",
	}).Debug("identity set for all transports")
	return err
}

// close every transport that this transport muxer has
func (tmux *TransportMuxer) Close() (err error) {
	log.WithFields(logger.Fields{
		"at":              "(TransportMuxer) Close",
		"reason":          "shutdown_requested",
		"transport_count": len(tmux.trans),
	}).Debug("closing all transports")
	for i, t := range tmux.trans {
		err = t.Close()
		if err != nil {
			// Log error but continue closing remaining transports
			log.WithFields(logger.Fields{
				"at":              "(TransportMuxer) Close",
				"reason":          "transport_close_failed",
				"transport_index": i,
				"error":           err.Error(),
			}).Warn("error closing transport")
		} else {
			log.WithFields(logger.Fields{
				"at":              "(TransportMuxer) Close",
				"reason":          "transport_closed",
				"transport_index": i,
			}).Debug("transport closed successfully")
		}
	}
	log.WithFields(logger.Fields{
		"at":     "(TransportMuxer) Close",
		"reason": "all_transports_closed",
	}).Debug("all transports closed")
	return err
}

// the name of this transport with the names of all the ones that we mux
func (tmux *TransportMuxer) Name() string {
	log.WithFields(logger.Fields{
		"at":     "(TransportMuxer) Name",
		"reason": "generating_composite_name",
	}).Debug("generating muxed transport name")
	name := "Muxed Transport: "
	for _, t := range tmux.trans {
		name += t.Name() + ", "
	}
	// Trim trailing ", " if present
	if len(name) >= 2 && name[len(name)-2:] == ", " {
		name = name[:len(name)-2]
	}
	log.WithFields(logger.Fields{
		"at":     "(TransportMuxer) Name",
		"reason": "name_generated",
		"name":   name,
	}).Debug("muxed transport name generated")
	return name
}

// tryGetSessionFromTransport attempts to get a session from a compatible transport.
// Returns the session and nil if successful, or nil and an error if it fails.
func (tmux *TransportMuxer) tryGetSessionFromTransport(t Transport, routerInfo router_info.RouterInfo, index int) (TransportSession, error) {
	peerHash, _ := routerInfo.IdentHash()
	log.WithFields(logger.Fields{
		"at":              "(TransportMuxer) GetSession",
		"reason":          "compatible_transport_found",
		"transport_index": index,
	}).Debug("found compatible transport, attempting session")

	s, err := t.GetSession(routerInfo)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":              "(TransportMuxer) GetSession",
			"phase":           "session_establishment",
			"reason":          "session_creation_failed",
			"transport_index": index,
			"peer_hash":       fmt.Sprintf("%x", peerHash[:]),
			"error":           err.Error(),
			"impact":          "cannot communicate with this peer",
			"addresses":       len(routerInfo.RouterAddresses()),
		}).Warn("failed to get session from compatible transport, trying next")
		return nil, err
	}

	log.WithFields(logger.Fields{
		"at":              "(TransportMuxer) GetSession",
		"reason":          "session_established",
		"transport_index": index,
	}).Debug("successfully got session from transport")
	return s, nil
}

// logNoTransportError logs detailed diagnostics when no compatible transport is found.
func (tmux *TransportMuxer) logNoTransportError(routerInfo router_info.RouterInfo) {
	peerHash, _ := routerInfo.IdentHash()
	addressTypes := make([]string, 0, len(routerInfo.RouterAddresses()))
	for _, addr := range routerInfo.RouterAddresses() {
		style := addr.TransportStyle()
		if styleBytes, err := style.Data(); err == nil {
			addressTypes = append(addressTypes, string(styleBytes))
		}
	}

	log.WithFields(logger.Fields{
		"at":             "(TransportMuxer) GetSession",
		"phase":          "session_establishment",
		"reason":         "no_compatible_transport",
		"peer_hash":      fmt.Sprintf("%x", peerHash[:]),
		"num_transports": len(tmux.trans),
		"addresses":      len(routerInfo.RouterAddresses()),
		"address_types":  addressTypes,
		"impact":         "peer completely unreachable",
		"diagnosis":      "peer may only support introducer-based connections or SSU2",
		"recommendation": "implement introducer support or SSU2 transport",
	}).Error("failed to get session - no compatible transports found")
}

// get a transport session given a router info
// return session and nil if successful
// return nil and ErrNoTransportAvailable if we failed to get a session
// return nil and ErrConnectionPoolFull if the connection limit has been reached
func (tmux *TransportMuxer) GetSession(routerInfo router_info.RouterInfo) (s TransportSession, err error) {
	peerHash, _ := routerInfo.IdentHash()
	log.WithFields(logger.Fields{
		"at":             "(TransportMuxer) GetSession",
		"reason":         "attempting_peer_connection",
		"peer_hash":      fmt.Sprintf("%x...", peerHash[:8]),
		"num_transports": len(tmux.trans),
	}).Debug("attempting to get session")

	// Enforce connection pool limit
	if err := tmux.checkConnectionLimit(); err != nil {
		return nil, err
	}

	for i, t := range tmux.trans {
		if t.Compatible(routerInfo) {
			s, err = tmux.tryGetSessionFromTransport(t, routerInfo, i)
			if err != nil {
				continue
			}
			atomic.AddInt32(&tmux.activeSessionCount, 1)
			return s, err
		}
	}

	tmux.logNoTransportError(routerInfo)
	err = ErrNoTransportAvailable
	return s, err
}

// is there a transport that we mux that is compatible with this router info?
func (tmux *TransportMuxer) Compatible(routerInfo router_info.RouterInfo) bool {
	peerHash, _ := routerInfo.IdentHash()
	log.WithFields(logger.Fields{
		"at":        "(TransportMuxer) Compatible",
		"reason":    "checking_compatibility",
		"peer_hash": fmt.Sprintf("%x...", peerHash[:8]),
	}).Debug("checking transport compatibility")
	for i, t := range tmux.trans {
		if t.Compatible(routerInfo) {
			log.WithFields(logger.Fields{
				"at":              "(TransportMuxer) Compatible",
				"reason":          "compatible_transport_found",
				"transport_index": i,
			}).Debug("found compatible transport")
			return true
		}
	}
	log.WithFields(logger.Fields{
		"at":     "(TransportMuxer) Compatible",
		"reason": "no_compatible_transport",
	}).Debug("no compatible transport found")
	return false
}

// Accept accepts an incoming connection from any available transport.
// This implements the Transport interface requirement.
// It listens on ALL transports concurrently and returns the first connection.
// Returns the connection and nil on success.
// Returns nil and ErrNoTransportAvailable if no transports are configured.
// Returns nil and ErrConnectionPoolFull if the connection limit has been reached.
func (tmux *TransportMuxer) Accept() (net.Conn, error) {
	log.WithFields(logger.Fields{
		"at":              "(TransportMuxer) Accept",
		"reason":          "awaiting_connection",
		"transport_count": len(tmux.trans),
	}).Debug("accepting connection from all transports")

	if err := tmux.validateTransports(); err != nil {
		return nil, err
	}

	if err := tmux.checkConnectionLimit(); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resultChan := tmux.startAcceptGoroutines(ctx, "(TransportMuxer) Accept")
	return tmux.collectAcceptResult(resultChan, cancel, "(TransportMuxer) Accept", nil)
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
// This method listens on ALL transports concurrently with a timeout context,
// enabling graceful shutdown of session monitoring loops.
// When the timeout fires, any connections accepted after cancellation are properly closed.
// Returns the connection and nil on success.
// Returns nil and context.DeadlineExceeded if the timeout expires.
// Returns nil and any other error from the underlying transport Accept().
func (tmux *TransportMuxer) AcceptWithTimeout(timeout time.Duration) (net.Conn, error) {
	log.WithFields(logger.Fields{
		"at":              "(TransportMuxer) AcceptWithTimeout",
		"reason":          "awaiting_connection",
		"timeout_ms":      timeout.Milliseconds(),
		"transport_count": len(tmux.trans),
	}).Debug("accepting connection with timeout from all transports")

	if err := tmux.validateTransports(); err != nil {
		return nil, err
	}

	if err := tmux.checkConnectionLimit(); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	resultChan := tmux.startAcceptGoroutines(ctx, "(TransportMuxer) AcceptWithTimeout")
	return tmux.collectAcceptResult(resultChan, cancel, "(TransportMuxer) AcceptWithTimeout", ctx)
}

// validateTransports checks that at least one transport is configured.
// Returns ErrNoTransportAvailable if no transports are registered.
func (tmux *TransportMuxer) validateTransports() error {
	if len(tmux.trans) == 0 {
		return ErrNoTransportAvailable
	}
	return nil
}

// startAcceptGoroutines launches concurrent accept operations on all transports.
// Each goroutine sends its result to the returned channel. If the context is
// cancelled before the result is sent, any accepted connection is closed to
// prevent resource leaks.
func (tmux *TransportMuxer) startAcceptGoroutines(ctx context.Context, caller string) chan acceptResult {
	resultChan := make(chan acceptResult, len(tmux.trans))
	for i, t := range tmux.trans {
		go func(transport Transport, index int) {
			conn, err := transport.Accept()
			select {
			case <-ctx.Done():
				if conn != nil {
					conn.Close()
					log.WithFields(logger.Fields{
						"at":              caller,
						"reason":          "connection_closed_after_cancel",
						"transport_index": index,
					}).Debug("closed connection from cancelled accept")
				}
			default:
				resultChan <- acceptResult{conn: conn, err: err, transportIndex: index}
			}
		}(t, i)
	}
	return resultChan
}

// handleAcceptSuccess increments the session counter and logs the accepted connection.
func (tmux *TransportMuxer) handleAcceptSuccess(res acceptResult, cancel context.CancelFunc, caller string) net.Conn {
	cancel()
	atomic.AddInt32(&tmux.activeSessionCount, 1)
	log.WithFields(logger.Fields{
		"at":              caller,
		"reason":          "connection_accepted",
		"transport_index": res.transportIndex,
		"active_sessions": atomic.LoadInt32(&tmux.activeSessionCount),
	}).Debug("accept succeeded")
	return res.conn
}

// collectAcceptResult waits for the first successful accept or exhaustion of all
// transports. When ctx is non-nil, the context's deadline is also monitored so
// that a timeout can be reported via ctx.Err().
func (tmux *TransportMuxer) collectAcceptResult(resultChan chan acceptResult, cancel context.CancelFunc, caller string, ctx context.Context) (net.Conn, error) {
	if ctx != nil {
		return tmux.collectWithTimeout(resultChan, cancel, caller, ctx)
	}
	return tmux.collectWithoutTimeout(resultChan, cancel, caller)
}

// collectWithTimeout waits for accept results while also monitoring a context deadline.
// Returns context.DeadlineExceeded if the timeout fires before a connection is accepted.
func (tmux *TransportMuxer) collectWithTimeout(resultChan chan acceptResult, cancel context.CancelFunc, caller string, ctx context.Context) (net.Conn, error) {
	var lastErr error
	failCount := 0
	for failCount < len(tmux.trans) {
		select {
		case res := <-resultChan:
			if conn := tmux.processAcceptResult(res, &lastErr, &failCount, cancel, caller); conn != nil {
				return conn, nil
			}
		case <-ctx.Done():
			log.WithFields(logger.Fields{
				"at":     caller,
				"reason": "timeout_exceeded",
			}).Debug("accept timed out")
			return nil, ctx.Err()
		}
	}
	return nil, tmux.logAllFailed(lastErr, caller)
}

// collectWithoutTimeout waits for accept results from all transports without a deadline.
func (tmux *TransportMuxer) collectWithoutTimeout(resultChan chan acceptResult, cancel context.CancelFunc, caller string) (net.Conn, error) {
	var lastErr error
	failCount := 0
	for failCount < len(tmux.trans) {
		res := <-resultChan
		if conn := tmux.processAcceptResult(res, &lastErr, &failCount, cancel, caller); conn != nil {
			return conn, nil
		}
	}
	return nil, tmux.logAllFailed(lastErr, caller)
}

// logAllFailed logs that all transport accept operations have failed and returns the last error.
func (tmux *TransportMuxer) logAllFailed(lastErr error, caller string) error {
	log.WithFields(logger.Fields{
		"at":     caller,
		"reason": "all_accepts_failed",
	}).Debug("all transport accepts failed")
	return lastErr
}

// processAcceptResult handles a single accept result from the result channel.
// Returns the connection if successful, or nil if the transport failed.
func (tmux *TransportMuxer) processAcceptResult(res acceptResult, lastErr *error, failCount *int, cancel context.CancelFunc, caller string) net.Conn {
	if res.err == nil && res.conn != nil {
		return tmux.handleAcceptSuccess(res, cancel, caller)
	}
	*lastErr = res.err
	*failCount++
	log.WithFields(logger.Fields{
		"at":              caller,
		"reason":          "transport_accept_failed",
		"transport_index": res.transportIndex,
	}).Debug("accept failed from transport")
	return nil
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

// checkConnectionLimit returns ErrConnectionPoolFull if the maximum number of
// concurrent connections has been reached.
func (tmux *TransportMuxer) checkConnectionLimit() error {
	max := tmux.getMaxConnections()
	current := int(atomic.LoadInt32(&tmux.activeSessionCount))
	if current >= max {
		log.WithFields(logger.Fields{
			"at":              "(TransportMuxer) checkConnectionLimit",
			"reason":          "connection_pool_full",
			"active_sessions": current,
			"max_connections": max,
		}).Warn("connection pool limit reached")
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
