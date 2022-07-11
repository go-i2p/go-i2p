package ntcp

/**
 * https://geti2p.net/spec/ntcp2
**/

const (
	NTCP_PROTOCOL_VERSION = 2
	NTCP_PROTOCOL_NAME    = "NTCP2"
	NTCP_MESSAGE_MAX_SIZE = 65537
)

// Transport is an ntcp transport implementing transport.Transport interface
type Transport struct {
}
