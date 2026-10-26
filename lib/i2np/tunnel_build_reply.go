package i2np

import (
	"github.com/go-i2p/go-i2p/lib/tunnel/replycodes"
)

/*
I2P I2NP Tunnel Build Reply codes
https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/i2np.rst

Reply codes shared by all tunnel build reply message types.
The type 26 reply is OutboundTunnelBuildReply (i2np.rst:696, :1721), the
specification name for this package's OutboundTunnelBuildReply type.
*/

// TunnelBuildReply constants for processing responses
// These are aliases of the canonical constants in lib/tunnel/replycodes
const (
	TunnelBuildReplySuccess             = replycodes.TunnelBuildReplySuccess             // Tunnel hop accepted the request (0)
	TunnelBuildReplyProbabilisticReject = replycodes.TunnelBuildReplyProbabilisticReject // Probabilistic rejection (10)
	TunnelBuildReplyTransientOverload   = replycodes.TunnelBuildReplyTransientOverload   // Transient overload (20)
	TunnelBuildReplyBandwidth           = replycodes.TunnelBuildReplyBandwidth           // Bandwidth rejection (30) - standard reject code
	TunnelBuildReplyCritical            = replycodes.TunnelBuildReplyCritical            // Critical rejection (50)

	// TunnelBuildReplyPendingDecryption is an internal sentinel (0xFF) for reply
	// records awaiting deferred decryption. Never transmitted on the wire.
	TunnelBuildReplyPendingDecryption = replycodes.TunnelBuildReplyPendingDecryption
)
