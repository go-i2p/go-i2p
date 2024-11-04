package ntcp

/**
 * https://geti2p.net/spec/ntcp2
**/

import "github.com/go-i2p/go-i2p/lib/transport/noise"

const (
	NTCP_PROTOCOL_VERSION = 2
	NTCP_PROTOCOL_NAME    = "NTCP2"
	NTCP_MESSAGE_MAX_SIZE = 65537
)

// Transport is an ntcp2 transport implementing transport.Transport interface
type Transport struct{
	*noise.NoiseTransport
}

// NewTransport creates a new ntcp2 transport