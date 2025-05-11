package ntcp

import (
	"fmt"
	"net"

	"github.com/go-i2p/go-i2p/lib/crypto/types"
	"github.com/go-i2p/go-i2p/lib/transport/ntcp/handshake"
)

// PerformInboundHandshake handles a handshake initiated by a remote peer
func (c *NTCP2Session) PerformInboundHandshake(conn net.Conn, localKey types.PrivateKey) (*handshake.HandshakeState, error) {
	return nil, fmt.Errorf("not implemented")
}
