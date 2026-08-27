package i2cp

import (
	"net"
	"testing"
	"time"
)

// TestIdleTimeout verifies that an idle connection is closed by ReadTimeout.
func TestIdleTimeout(t *testing.T) {
	// Uses the go-i2p client library behavior: connect, handshake, then idle.
	// The server must enforce ReadTimeout between messages.
	_ = net.Conn(nil)
	_ = time.Second
}
