package ntcp

/**
 * https://geti2p.net/spec/ntcp2
**/

import (
	"net"

	"github.com/go-i2p/go-i2p/lib/common/router_identity"
	"github.com/go-i2p/go-i2p/lib/common/router_info"
	"github.com/go-i2p/go-i2p/lib/transport"
	"github.com/go-i2p/go-i2p/lib/transport/noise"
)

const (
	NTCP_PROTOCOL_VERSION = 2
	NTCP_PROTOCOL_NAME    = "NTCP2"
	NTCP_MESSAGE_MAX_SIZE = 65537
)

var exampleNTCPTransport transport.Transport = &Transport{}

// Transport is an ntcp2 transport implementing transport.Transport interface
type Transport struct {
	*noise.NoiseTransport
}

// Accept implements transport.Transport.
func (t *Transport) Accept() (net.Conn, error) {
	panic("unimplemented")
}

// Addr implements transport.Transport.
func (t *Transport) Addr() net.Addr {
	panic("unimplemented")
}

// Close implements transport.Transport.
func (t *Transport) Close() error {
	panic("unimplemented")
}

// Compatible implements transport.Transport.
func (t *Transport) Compatible(routerInfo router_info.RouterInfo) bool {
	panic("unimplemented")
}

// GetSession implements transport.Transport.
func (t *Transport) GetSession(routerInfo router_info.RouterInfo) (transport.TransportSession, error) {
	panic("unimplemented")
}

// Name implements transport.Transport.
func (t *Transport) Name() string {
	panic("unimplemented")
}

// SetIdentity implements transport.Transport.
func (t *Transport) SetIdentity(ident router_identity.RouterIdentity) error {
	panic("unimplemented")
}

// NewTransport creates a new ntcp2 transport
