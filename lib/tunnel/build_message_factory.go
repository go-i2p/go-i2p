package tunnel

import (
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/session_key"
)

// BuildMessageFactory creates tunnel build messages without depending on lib/i2np concrete types.
// This interface breaks the circular dependency between lib/tunnel and lib/i2np by allowing
// the orchestrator to create messages through abstraction.
//
// The concrete implementation lives in lib/i2np, where the actual message types are defined.
type BuildMessageFactory interface {
	// CreateShortTunnelBuildMessage creates a Short Tunnel Build Message (STBM) from the given
	// build result, message ID, and cryptographic material for reply processing.
	//
	// The STBM uses Noise protocol for enhanced security and includes garlic-encrypted replies.
	CreateShortTunnelBuildMessage(
		result *BuildTunnelResult,
		messageID int,
		replyKeys []session_key.SessionKey,
		replyIVs [][16]byte,
		noiseHashes [][32]byte,
	) (BuildMessage, error)

	// CreateVariableTunnelBuildMessage creates a Variable Tunnel Build (VTB) message from the
	// given build result, message ID, and cryptographic material for reply processing.
	//
	// VTB is the legacy tunnel build format, supported for backwards compatibility.
	CreateVariableTunnelBuildMessage(
		result *BuildTunnelResult,
		messageID int,
		replyKeys []session_key.SessionKey,
		replyIVs [][16]byte,
	) (BuildMessage, error)
}

// BuildMessage represents an I2NP tunnel build message (STBM or VTB).
// This interface abstracts the actual i2np.Message type to avoid circular dependencies.
type BuildMessage interface {
	// GetBytes returns the serialized message bytes.
	GetBytes() []byte

	// GetID returns the I2NP message ID.
	GetID() int

	// GetType returns the I2NP message type code.
	GetType() uint8
}

// MessageSender abstracts I2NP session access for sending tunnel build messages.
// This interface allows the orchestrator to send messages without depending on i2np types.
type MessageSender interface {
	// GetSessionForHash returns a transport session for the given peer hash.
	GetSessionForHash(hash common.Hash) (TransportSession, error)
}

// TransportSession represents a transport session for sending messages to a peer.
type TransportSession interface {
	// SendMessage sends an I2NP message through this transport session.
	SendMessage(msg BuildMessage) error

	// GetPeerHash returns the hash of the peer this session is connected to.
	GetPeerHash() common.Hash
}

// GarlicKeyRegistrar receives one-time garlic decryption keys derived from STBM Noise
// transcript hashes so that incoming ShortTunnelBuildReply garlic messages can be decrypted.
type GarlicKeyRegistrar interface {
	// RegisterOneTimeKey registers a one-time garlic decryption key.
	// The hash is derived from the Noise protocol transcript.
	RegisterOneTimeKey(hash [32]byte) error
}

// ReplyHandler processes tunnel build replies and extracts hop-specific status.
// This interface abstracts the i2np.TunnelReplyHandler to avoid circular dependencies.
type ReplyHandler interface {
	// GetHopCount returns the number of hops in this tunnel build.
	GetHopCount() int

	// GetReplyKey returns the reply decryption key for the given hop index.
	GetReplyKey(hop int) (session_key.SessionKey, error)

	// GetReplyIV returns the reply decryption IV for the given hop index.
	GetReplyIV(hop int) ([16]byte, error)

	// GetNoiseHash returns the Noise transcript hash for the given hop (STBM only).
	GetNoiseHash(hop int) ([32]byte, error)

	// OnSuccess is called when a hop accepts the build request.
	OnSuccess(hop int)

	// OnReject is called when a hop rejects the build request.
	OnReject(hop int, reason string)
}
