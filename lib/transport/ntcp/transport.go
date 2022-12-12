package ntcp

import "github.com/go-i2p/go-i2p/lib/transport/noise"

/**
 * https://geti2p.net/spec/ntcp2
**/

const (
	NTCP_PROTOCOL_VERSION = 2
	NTCP_PROTOCOL_NAME    = "NTCP2"
	NTCP_MESSAGE_MAX_SIZE = 65537
)

// NTCPTransport is an ntcp transport implementing transport.Transport interface
type NTCPTransport noise.NoiseTransport
