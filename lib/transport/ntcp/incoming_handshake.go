package ntcp

import (
	"net"
	"time"

	"github.com/go-i2p/go-i2p/lib/crypto/curve25519"
	"github.com/go-i2p/go-i2p/lib/crypto/types"
	"github.com/go-i2p/go-i2p/lib/transport/ntcp/handshake"
	"github.com/samber/oops"
)

// PerformInboundHandshake handles a handshake initiated by a remote peer
func (c *NTCP2Session) PerformInboundHandshake(conn net.Conn, localKey types.PrivateKey) (*handshake.HandshakeState, error) {
	// Set deadline for the entire handshake process
	if err := conn.SetDeadline(time.Now().Add(NTCP2_HANDSHAKE_TIMEOUT)); err != nil {
		return nil, oops.Errorf("failed to set deadline: %v", err)
	}
	defer conn.SetDeadline(time.Time{}) // Clear deadline after handshake

	// Create handshake state for responder
	hs := &handshake.HandshakeState{
		IsInitiator:    false,
		LocalStaticKey: localKey,
		Timestamp:      uint32(time.Now().Unix()),
	}

	// Generate ephemeral keypair
	var err error
	_, hs.LocalEphemeral, err = curve25519.GenerateKeyPair()
	if err != nil {
		return nil, oops.Errorf("failed to generate ephemeral key: %v", err)
	}

	// 1. Receive SessionRequest
	if err := c.receiveSessionRequest(conn, hs); err != nil {
		return nil, oops.Errorf("failed to receive session request: %v", err)
	}

	// 2. Send SessionCreated
	if err := c.sendSessionCreated(conn, hs); err != nil {
		return nil, oops.Errorf("failed to send session created: %v", err)
	}

	// 3. Receive SessionConfirm
	if err := c.receiveSessionConfirm(conn, hs); err != nil {
		return nil, oops.Errorf("failed to receive session confirm: %v", err)
	}

	// Handshake complete, derive session keys
	if err := c.deriveSessionKeys(hs); err != nil {
		return nil, err
	}

	return hs, nil
}
