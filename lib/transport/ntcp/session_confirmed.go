package ntcp

import (
	"github.com/flynn/noise"
	"github.com/go-i2p/go-i2p/lib/common/router_info"
	"github.com/go-i2p/go-i2p/lib/transport/messages"
)

// CreateSessionConfirmed builds the SessionConfirmed message (Message 3 in NTCP2 handshake)
// This is sent by Alice to Bob after receiving SessionCreated
func (c *NTCP2Session) CreateSessionConfirmed(
	handshakeState *noise.HandshakeState,
	localRouterInfo *router_info.RouterInfo,
) (*messages.SessionConfirmed, error) {
	panic("unimplemented")
}
