package replycodes

// Tunnel build reply codes as defined in the I2P specification.
// In practice, only 0x00 (Success) and 0x03 (Bandwidth Rejection) are sent.
// The other codes are deprecated but we still process them if received from other routers.
const (
	// TunnelBuildReplySuccess indicates the hop accepted the tunnel build request.
	// This is the only success code and is actively used.
	TunnelBuildReplySuccess = 0x00

	// TunnelBuildReplyProbabilisticRejectionLegacy is deprecated (0x01).
	// Not sent, but processed if received from other routers.
	// Indicates a probabilistic build rejection.
	TunnelBuildReplyProbabilisticRejectionLegacy = 0x01

	// TunnelBuildReplyOverload is deprecated (0x02). Not sent, but processed if received.
	TunnelBuildReplyOverload = 0x02

	// TunnelBuildReplyBandwidth indicates a bandwidth rejection (0x03).
	// This is the standard rejection code actively used in place of the deprecated codes.
	// It indicates the hop rejected the build due to insufficient bandwidth/capacity.
	TunnelBuildReplyBandwidth = 0x03

	// TunnelBuildReplyInvalid is deprecated (0x04). Not sent, but processed if received.
	TunnelBuildReplyInvalid = 0x04

	// TunnelBuildReplyCritical indicates a critical tunnel rejection (0x05).
	// This is NOT "expired" - it's a critical rejection. Not sent, but processed if received.
	TunnelBuildReplyCritical = 0x05
)
