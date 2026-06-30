package router

import (
	"net"

	"github.com/go-i2p/go-i2p/lib/transport"
	ntcp "github.com/go-i2p/go-i2p/lib/transport/ntcp2"
	ssu2 "github.com/go-i2p/go-i2p/lib/transport/ssu2"
)

// findTransport returns the first transport of the specified type, or nil if not found.
// This consolidates the common pattern: get muxer, nil check, iterate transports, type-assert.
func (r *Router) findTransport(typeCheck func(transport.Transport) bool) transport.Transport {
	muxer := r.transports
	if muxer == nil {
		return nil
	}
	for _, t := range muxer.GetTransports() {
		if typeCheck(t) {
			return t
		}
	}
	return nil
}

// GetActiveSessionCount returns the number of active transport sessions.
// Thread-safe access to the activeSessions map.
func (r *Router) GetActiveSessionCount() int {
	r.sessionMutex.RLock()
	defer r.sessionMutex.RUnlock()
	return len(r.activeSessions)
}

// GetNTCP2SessionCount returns the number of active NTCP2 (TCP) sessions.
// Returns 0 if the NTCP2 transport is not available.
func (r *Router) GetNTCP2SessionCount() int {
	t := r.findTransport(func(t transport.Transport) bool {
		_, ok := t.(*ntcp.NTCP2Transport)
		return ok
	})
	if nt, ok := t.(*ntcp.NTCP2Transport); ok {
		return int(nt.GetSessionCount())
	}
	return 0
}

// GetSSU2SessionCount returns the number of active SSU2 (UDP) sessions.
// Returns 0 if the SSU2 transport is not available.
func (r *Router) GetSSU2SessionCount() int {
	t := r.findTransport(func(t transport.Transport) bool {
		_, ok := t.(*ssu2.SSU2Transport)
		return ok
	})
	if st, ok := t.(*ssu2.SSU2Transport); ok {
		return int(st.GetSessionCount())
	}
	return 0
}

// GetTransportAddr returns the listening address of the first available transport.
// This is used by I2PControl to expose NTCP2 port and address information.
// Returns nil if no transports are available.
func (r *Router) GetTransportAddr() net.Addr {
	// Capture locally to avoid TOCTOU race with concurrent shutdown.
	muxer := r.transports
	if muxer == nil {
		return nil
	}

	transports := muxer.GetTransports()
	if len(transports) == 0 {
		return nil
	}

	// Return the address of the first transport (typically NTCP2)
	return transports[0].Addr()
}

// GetSSU2Addr returns the listening UDP address of the SSU2 transport.
// Returns nil if SSU2 is not available or not yet bound.
func (r *Router) GetSSU2Addr() net.Addr {
	t := r.findTransport(func(t transport.Transport) bool {
		_, ok := t.(*ssu2.SSU2Transport)
		return ok
	})
	if t != nil {
		return t.Addr()
	}
	return nil
}

// GetNetworkStatus returns the I2PControl network status code.
// Status codes:
//
//	0  = OK                  (running, directly reachable with a confirmed external address)
//	1  = TESTING             (not yet connected to any peers)
//	2  = FIREWALLED          (inbound blocked: no confirmed external address, or
//	                          reachable only via introducers behind a restricted /
//	                          port-restricted NAT — "reachable but inbound blocked")
//	3  = HIDDEN              (router is in hidden mode by configuration)
//	8  = ERROR_I2CP          (router not running)
//	11 = ERROR_SYMMETRIC_NAT (reachable only via introducers behind a symmetric NAT)
func (r *Router) GetNetworkStatus() int {
	if !r.IsRunning() {
		return 8 // ERROR_I2CP
	}
	// Hidden mode is a configuration posture that must be reported regardless
	// of transient peer-count or reseeding state; check it first.
	if r.cfg != nil && r.cfg.Hidden {
		return 3 // HIDDEN
	}
	if r.IsReseeding() || r.GetActiveSessionCount() == 0 {
		return 1 // TESTING — no active peers yet
	}
	// Firewalled: has peers but no confirmed external address.
	if r.collectBestExternalAddr() == "" {
		return 2 // FIREWALLED
	}
	// We have a confirmed external address. If NAT detection concluded that
	// unsolicited inbound connections are blocked, report the specific
	// firewalled variant (FIREWALLED, or ERROR_SYMMETRIC_NAT for symmetric NAT)
	// rather than OK. Without this guard a firewalled router with a
	// PeerTest-confirmed external address misreports as fully reachable.
	//
	// Precedence rule: a directly-reachable public-IPv4 host wins over any
	// (possibly stale or in-progress) relay-requiring NAT classification in the
	// SSU2 cache. Such a host is reachable by unsolicited direct inbound by
	// definition, so report OK and never a firewalled variant. This makes the
	// verdict deterministic regardless of PeerTest timing.
	if r.directPublicExternalAddr() != "" {
		return 0 // OK — directly reachable via public IPv4
	}
	if code := r.inboundBlockedStatusCode(); code != 0 {
		return code
	}
	return 0 // OK
}

// inboundBlockedStatusCode returns the I2PControl status code that describes how
// NAT detection found inbound connectivity to be blocked (2 = FIREWALLED,
// 11 = ERROR_SYMMETRIC_NAT), or 0 when SSU2 is unavailable or NAT detection has
// not (yet) found a relay-requiring NAT. Returning 0 in the unavailable /
// not-yet-tested / directly-reachable cases ensures such routers are never
// misreported as inbound-blocked.
func (r *Router) inboundBlockedStatusCode() int {
	ssu2Transport := r.getSSU2Transport()
	if ssu2Transport == nil {
		return 0
	}
	return ssu2Transport.InboundBlockedStatusCode()
}
