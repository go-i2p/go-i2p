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
