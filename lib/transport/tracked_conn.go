package transport

import (
	"net"
	"sync"
)

// TrackedConn wraps a net.Conn to execute a cleanup function when the connection
// is closed. It ensures the cleanup is called exactly once, even with concurrent Close() calls.
// This is used by multiple transport implementations to track session lifecycle.
type TrackedConn struct {
	net.Conn
	onClose   func()
	closeOnce sync.Once
}

// Close closes the underlying connection and runs the close callback exactly once.
func (tc *TrackedConn) Close() error {
	err := tc.Conn.Close()
	if tc.onClose != nil {
		tc.closeOnce.Do(tc.onClose)
	}
	return err
}

// NewTrackedConn creates a new TrackedConn that wraps the given net.Conn and
// calls onClose (if not nil) exactly once when the connection is closed.
func NewTrackedConn(conn net.Conn, onClose func()) *TrackedConn {
	return &TrackedConn{
		Conn:    conn,
		onClose: onClose,
	}
}

// UnwrapTrackedConn returns the connection inside any number of TrackedConn
// layers, or conn itself when it is not wrapped.
//
// A connection picked up from a TransportMuxer has been wrapped at least twice:
// once by the transport that accepted it and once by the muxer for its own
// session accounting. Callers that need the concrete protocol connection — the
// router type-asserting an accepted connection to *ssu2.SSU2Conn, for example —
// must unwrap first, or the assertion fails on the outermost wrapper and the
// connection is dropped even though it is perfectly usable.
//
// The loop is bounded by the number of wrappers actually present; a wrapper
// whose inner Conn is not itself a TrackedConn ends the walk.
func UnwrapTrackedConn(conn net.Conn) net.Conn {
	for {
		tracked, ok := conn.(*TrackedConn)
		if !ok || tracked.Conn == nil {
			return conn
		}
		conn = tracked.Conn
	}
}
