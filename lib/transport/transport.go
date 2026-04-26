package transport

import (
	"net"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"

	"github.com/go-i2p/go-i2p/lib/i2np"
)

// PeerConnNotifier receives transport-layer connection feedback so that
// higher-level routing components (e.g. PeerTracker) can update peer
// reputation without coupling the transport packages to netdb.
type PeerConnNotifier interface {
	// RecordAttempt is called just before a dial attempt begins.
	RecordAttempt(hash common.Hash)
	// RecordSuccess is called when a handshake completes successfully.
	// responseTimeMs is the round-trip to fully-established session in ms.
	RecordSuccess(hash common.Hash, responseTimeMs int64)
	// RecordFailure is called when a dial or handshake fails.
	RecordFailure(hash common.Hash, reason string)
	// RecordPermanentFailure is called when a peer is structurally unreachable
	// (e.g. IPv6-only peer with no local IPv6 connectivity, or a malformed
	// RouterInfo with no valid address).  It immediately advances the peer's
	// consecutive-failure counter to the staleness threshold so that
	// IsLikelyStale() returns true on the very next hop-selection pass,
	// preventing repeated wasted dial attempts.
	RecordPermanentFailure(hash common.Hash, reason string)
}

// RouterInfoRefresher allows transport layers to request a stale RouterInfo
// be evicted from the local NetDB cache. Implementations should enforce a
// per-peer cooldown to prevent thundering-herd on popular peers.
type RouterInfoRefresher interface {
	// RequestRouterInfoRefresh marks a peer's RouterInfo as stale and removes
	// it from the in-memory cache. The implementation must honour a per-peer
	// cooldown (e.g. one eviction per 5 minutes).
	RequestRouterInfoRefresh(hash common.Hash)
}

// TransportSession is a session between 2 routers for transmitting i2np messages securely.
type TransportSession interface {
	// queue an i2np message to be sent over the session
	// returns an error if the session is closed or the send queue is full
	QueueSendI2NP(msg i2np.I2NPMessage) error
	// return how many i2np messages are not completely sent yet
	SendQueueSize() int
	// blocking read the next fully recv'd i2np message from this session
	ReadNextI2NP() (i2np.I2NPMessage, error)
	// close the session cleanly
	// returns any errors that happen while closing the session
	Close() error
	// create a handshake message for the session
	// CreateHandshakeMessage() (i2np.I2NPMessage, error)
}

// Transport defines the interface for an I2P transport layer capable of accepting connections,
// managing sessions, and binding to a router identity.
type Transport interface {
	// Accept accepts an incoming session.
	Accept() (net.Conn, error)

	// Addr returns an
	Addr() net.Addr

	// Set the router identity for this transport.
	// will bind if the underlying socket is not already
	// if the underlying socket is already bound update the RouterIdentity
	// returns any errors that happen if they do
	SetIdentity(ident router_info.RouterInfo) error

	// Obtain a transport session with a router given its RouterInfo.
	// If a session with this router is NOT already made attempt to create one and block until made or until an error happens
	// returns an established TransportSession and nil on success
	// returns nil and an error on error
	GetSession(routerInfo router_info.RouterInfo) (TransportSession, error)

	// return true if a routerInfo is compatible with this transport
	Compatible(routerInfo router_info.RouterInfo) bool

	// close the transport cleanly
	// blocks until done
	// returns an error if one happens
	Close() error

	// get the name of this tranport as a string
	Name() string
}
