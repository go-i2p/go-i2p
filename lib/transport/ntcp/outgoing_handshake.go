package ntcp

import (
	"net"
	"time"

	"github.com/go-i2p/go-i2p/lib/transport/ntcp/handshake"
	"github.com/samber/oops"
)

// PerformOutboundHandshake initiates and completes a handshake as the initiator
func (c *NTCP2Session) PerformOutboundHandshake(conn net.Conn, hs *handshake.HandshakeState) error {
	// Set deadline for the entire handshake process
	if err := conn.SetDeadline(time.Now().Add(NTCP2_HANDSHAKE_TIMEOUT)); err != nil {
		return oops.Errorf("failed to set deadline: %v", err)
	}
	defer conn.SetDeadline(time.Time{}) // Clear deadline after handshake

	// 1. Send SessionRequest
	if err := c.sendSessionRequest(conn, hs); err != nil {
		return oops.Errorf("failed to send session request: %v", err)
	}

	// 2. Receive SessionCreated
	if err := c.receiveSessionCreated(conn, hs); err != nil {
		return oops.Errorf("failed to receive session created: %v", err)
	}

	// 3. Send SessionConfirm
	if err := c.sendSessionConfirm(conn, hs); err != nil {
		return oops.Errorf("failed to send session confirm: %v", err)
	}

	// Handshake complete, derive session keys
	return c.deriveSessionKeys(hs)
}
