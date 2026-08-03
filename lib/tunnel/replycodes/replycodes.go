package replycodes

// Tunnel build reply codes as defined in the I2P specification.
// These codes indicate the result of a tunnel build request at each hop.
const (
	// TunnelBuildReplySuccess indicates the hop accepted the tunnel build request.
	TunnelBuildReplySuccess = 0x00

	// TunnelBuildReplyReject indicates the hop rejected the tunnel build request.
	TunnelBuildReplyReject = 0x01

	// TunnelBuildReplyOverload indicates the router is overloaded.
	TunnelBuildReplyOverload = 0x02

	// TunnelBuildReplyBandwidth indicates insufficient bandwidth.
	TunnelBuildReplyBandwidth = 0x03

	// TunnelBuildReplyInvalid indicates invalid request data.
	TunnelBuildReplyInvalid = 0x04

	// TunnelBuildReplyExpired indicates the request has expired.
	TunnelBuildReplyExpired = 0x05
)
