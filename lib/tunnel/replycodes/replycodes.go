package replycodes

// Tunnel build reply codes as defined in the I2P specification
// (tunnel-creation.rst, BuildResponseRecord reply byte).
//
// The wire values are 0 (accepted), 10 (probabilistic reject), 20 (transient
// overload), 30 (bandwidth), and 50 (critical). These match Java I2P's
// TunnelHistory constants (TUNNEL_REJECT_PROBABALISTIC_REJECT=10,
// TUNNEL_REJECT_TRANSIENT_OVERLOAD=20, TUNNEL_REJECT_BANDWIDTH=30,
// TUNNEL_REJECT_CRIT=50) and i2pd's retCode usage (30).
//
// In practice, only 0 (Success) and 30 (Bandwidth) are sent by current
// routers. The other codes are processed if received for interop.
const (
	// TunnelBuildReplySuccess indicates the hop accepted the tunnel build request.
	// This is the only success code.
	TunnelBuildReplySuccess = 0

	// TunnelBuildReplyProbabilisticReject indicates a probabilistic rejection
	// due to a flood of build requests (wire code 10). Rarely sent.
	TunnelBuildReplyProbabilisticReject = 10

	// TunnelBuildReplyTransientOverload indicates temporary CPU/job/tunnel
	// overload (wire code 20). Rarely sent.
	TunnelBuildReplyTransientOverload = 20

	// TunnelBuildReplyBandwidth indicates a bandwidth-limit rejection
	// (wire code 30). This is the standard rejection code used for most
	// rejections, even when the real reason is not bandwidth.
	TunnelBuildReplyBandwidth = 30

	// TunnelBuildReplyCritical indicates a critical rejection such as router
	// shutdown (wire code 50). Not currently sent by Java I2P.
	TunnelBuildReplyCritical = 50

	// TunnelBuildReplyPendingDecryption is an internal sentinel (0xFF) marking a
	// reply record whose Reply field has not yet been populated because the
	// record is still encrypted and awaiting deferred decryption. It is never
	// transmitted on the wire and never appears in a decrypted cleartext record
	// (spec codes are 0-50). Consumers must not treat it as a rejection.
	TunnelBuildReplyPendingDecryption = 0xFF
)
