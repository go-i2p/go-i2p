package router

import (
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/transport"
	ntcp "github.com/go-i2p/go-i2p/lib/transport/ntcp2"
	ssu2 "github.com/go-i2p/go-i2p/lib/transport/ssu2"
	"github.com/go-i2p/go-i2p/lib/util/logutil"
	"github.com/samber/oops"

	"github.com/go-i2p/logger"
)

// ensureNetDBReady validates NetDB state and performs reseed if needed.
// Returns an error if the router's StdNetDB is nil (e.g. during shutdown).

// removeSession removes a session when it closes.
// This method is typically called from a session's cleanup callback
// to ensure the router doesn't attempt to send messages to closed sessions.
// Thread-safe for concurrent access.
func (r *Router) removeSession(peerHash common.Hash) {
	r.sessionMutex.Lock()
	defer r.sessionMutex.Unlock()

	delete(r.activeSessions, peerHash)
	log.WithField("peer_hash", logutil.HashPrefix(peerHash)).Debug("Removed session")
}

// getSessionByHash retrieves a session for a specific peer.
// Returns an error if no active session exists for the given peer hash.
// Thread-safe for concurrent read access using RWMutex.
func (r *Router) getSessionByHash(peerHash common.Hash) (transport.TransportSession, error) {
	r.sessionMutex.RLock()
	defer r.sessionMutex.RUnlock()

	if session, ok := r.activeSessions[peerHash]; ok {
		return session, nil
	}
	return nil, oops.Errorf("no session found for peer %x", peerHash[:8])
}

// GetSessionByHash implements SessionProvider interface for DatabaseManager.
// This enables the I2NP message processing layer to send responses back through
// the router's active transport sessions.
// NTCP2Session already implements the i2np.TransportSession interface.
// If no active session exists, it attempts to establish an outbound connection.
func (r *Router) GetSessionByHash(hash common.Hash) (i2np.I2NPTransportSession, error) {
	// Check if router is still running before proceeding
	r.runMux.RLock()
	running := r.running
	r.runMux.RUnlock()

	if !running {
		return nil, oops.Errorf("router is not running")
	}

	// First check for existing session
	session, err := r.getSessionByHash(hash)
	if err == nil {
		// NTCP2Session implements i2np.TransportSession (QueueSendI2NP, SendQueueSize)
		return session, nil
	}

	// No existing session - try to establish outbound connection
	log.WithField("peer_hash", logutil.HashPrefix(hash)).Debug("No active session, attempting outbound connection")

	routerInfo, err := r.retrieveRouterInfoWithTimeout(hash)
	if err != nil {
		return nil, err
	}

	transportSession, err := r.establishOutboundSession(hash, routerInfo)
	if err != nil {
		return nil, err
	}

	r.registerNewSession(hash, transportSession)
	return transportSession, nil
}

// retrieveRouterInfoWithTimeout looks up RouterInfo from NetDB with a timeout.
func (r *Router) retrieveRouterInfoWithTimeout(hash common.Hash) (*router_info.RouterInfo, error) {
	routerInfoChan, err := r.getRouterInfoChannel(hash)
	if err != nil {
		return nil, err
	}
	return r.waitForRouterInfo(routerInfoChan, hash)
}

// getRouterInfoChannel initiates a RouterInfo lookup and returns the result channel.
func (r *Router) getRouterInfoChannel(hash common.Hash) (<-chan router_info.RouterInfo, error) {
	if r.netdb == nil {
		return nil, oops.Errorf("router NetDB not available")
	}
	routerInfoChan := r.netdb.GetRouterInfo(hash)
	if routerInfoChan == nil {
		return nil, oops.Errorf("no RouterInfo found for peer %x", hash[:8])
	}
	return routerInfoChan, nil
}

// waitForRouterInfo waits for a RouterInfo to arrive on the channel with timeout.
func (r *Router) waitForRouterInfo(ch <-chan router_info.RouterInfo, hash common.Hash) (*router_info.RouterInfo, error) {
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()

	select {
	case routerInfo, ok := <-ch:
		if !ok {
			return nil, oops.Errorf("failed to receive RouterInfo for peer %x", hash[:8])
		}
		return &routerInfo, nil
	case <-timer.C:
		r.logRouterInfoTimeout(hash)
		return nil, oops.Errorf("timeout waiting for RouterInfo for peer %x", hash[:8])
	}
}

// establishOutboundSession creates a new transport session to a peer.
func (r *Router) establishOutboundSession(hash common.Hash, routerInfo *router_info.RouterInfo) (i2np.I2NPTransportSession, error) {
	if err := r.validateTransportMuxer(hash); err != nil {
		return nil, err
	}

	transportSession, err := r.transports.GetSession(*routerInfo)
	if err != nil {
		r.logSessionEstablishmentFailure(hash, routerInfo, err)
		return nil, oops.Wrapf(err, "failed to establish outbound session")
	}

	return transportSession, nil
}

// validateTransportMuxer checks if the transport muxer is initialized.
func (r *Router) validateTransportMuxer(hash common.Hash) error {
	if r.transports == nil {
		log.WithFields(logger.Fields{
			"at":        "Router.GetSessionByHash",
			"phase":     "session_establishment",
			"operation": "outbound_connection",
			"peer_hash": logutil.HashPrefix(hash),
			"reason":    "transport_not_initialized",
		}).Error("TransportMuxer not initialized")
		return oops.Errorf("transport not initialized for peer %x", hash[:8])
	}
	return nil
}

// registerNewSession stores a newly established session and starts a reader
// goroutine so that inbound I2NP messages on outbound sessions are processed.
// Without the reader goroutine, messages (e.g. tunnel build replies) pile up in
// the session's recvChan and are never consumed, which was the root cause of
// zero operational tunnels (RCA-1 / AUDIT.md).
func (r *Router) registerNewSession(hash common.Hash, transportSession i2np.I2NPTransportSession) {
	// Unwrap the trackedSession wrapper from TransportMuxer so the type switch
	// can match the concrete session type (NTCP2Session, SSU2Session).
	// Without this, the *trackedSession wrapper causes every case to miss,
	// falling through to the default branch and preventing reader goroutines
	// from starting on outbound sessions (see AUDIT-2026-04-09.md RCA-1).
	type unwrapper interface {
		Unwrap() transport.TransportSession
	}
	if uw, ok := transportSession.(unwrapper); ok {
		if inner, ok := uw.Unwrap().(i2np.I2NPTransportSession); ok {
			transportSession = inner
		}
	}

	switch s := transportSession.(type) {
	case *ntcp.NTCP2Session:
		s.SetCleanupCallback(func() { r.removeSession(hash) })
		r.addSession(hash, s)
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.processSessionMessages(s, staticAuthenticatedPeer{hash: hash, handshakeComplete: true})
		}()
		log.WithField("peer_hash", logutil.HashPrefix(hash)).Info("Established and registered new outbound NTCP2 session")
	case *ssu2.SSU2Session:
		s.SetCleanupCallback(func() { r.removeSession(hash) })
		r.addSession(hash, s)
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.processSessionMessages(s, staticAuthenticatedPeer{hash: hash, handshakeComplete: true})
		}()
		log.WithField("peer_hash", logutil.HashPrefix(hash)).Info("Established and registered new outbound SSU2 session")
	default:
		log.WithField("peer_hash", logutil.HashPrefix(hash)).Warn("Unknown transport session type, cannot start reader goroutine")
	}
}

// logSessionEstablishmentFailure logs detailed context about session establishment failures.
// Downgraded from Error to Warn because the error is already returned to
// the caller; logging it again at Error inflated the apparent error count (E4/E5
// in the AUDIT report were the same event logged twice).
func (r *Router) logSessionEstablishmentFailure(hash common.Hash, routerInfo *router_info.RouterInfo, err error) {
	log.WithFields(logger.Fields{
		"at":            "Router.GetSessionByHash",
		"phase":         "session_establishment",
		"operation":     "outbound_connection",
		"peer_hash":     logutil.HashPrefix(hash),
		"error":         err.Error(),
		"address_count": len(routerInfo.RouterAddresses()),
		"has_ntcp2":     hasNTCP2Address(*routerInfo),
	}).Warn("failed to get session")
}

// logRouterInfoTimeout logs timeout events when waiting for RouterInfo from NetDB.
func (r *Router) logRouterInfoTimeout(hash common.Hash) {
	log.WithFields(logger.Fields{
		"at":        "Router.GetSessionByHash",
		"phase":     "session_establishment",
		"operation": "netdb_lookup",
		"peer_hash": logutil.HashPrefix(hash),
		"timeout":   "30s",
	}).Error("Timeout waiting for RouterInfo from NetDB")
}
