package ntcp

import (
	"github.com/flynn/noise"
	"github.com/go-i2p/go-i2p/lib/common/router_info"
	"github.com/go-i2p/go-i2p/lib/transport/messages"
)

// CreateSessionCreated builds the SessionCreated message (Message 3 in NTCP2 handshake)
// This is sent by Alice to Bob after receiving SessionCreated
func (c *NTCP2Session) CreateSessionCreated(
	handshakeState *noise.HandshakeState,
	localRouterInfo *router_info.RouterInfo,
) (*messages.SessionCreated, error) {
	panic("unimplemented")
}
