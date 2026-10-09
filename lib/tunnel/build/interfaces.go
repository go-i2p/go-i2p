// Package build contains coordinator interfaces for tunnel building and management.
// This is a dependency-minimal package that imports only lib/tunnel/buildrecord
// and external packages, allowing both lib/tunnel and lib/i2np to depend on it
// without creating circular imports.
package build

import (
	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/go-i2p/lib/tunnel/buildrecord"
)

// TunnelBuilder represents types that can build tunnels.
// Implementations provide the build request records needed to establish a tunnel.
type TunnelBuilder interface {
	GetBuildRecords() []buildrecord.BuildRequestRecord
	GetRecordCount() int
}

// TunnelReplyHandler represents types that handle tunnel build replies.
// Implementations process the response records returned by hops during tunnel establishment.
type TunnelReplyHandler interface {
	GetReplyRecords() []buildrecord.BuildResponseRecord
	// GetRawReplyRecords returns the raw encrypted record bytes before parsing.
	// This is needed for decryption: re-serializing parsed records corrupts
	// the original ciphertext. Returns nil if raw records were not preserved.
	GetRawReplyRecords() [][]byte
	ProcessReply() error
}

// TunnelBuildReplyProcessor defines the interface for processing tunnel build reply messages.
// When a tunnel build reply (types 22, 24, 26) arrives, the processor correlates it with
// the original build request and updates tunnel state accordingly.
type TunnelBuildReplyProcessor interface {
	// ProcessTunnelBuildReply handles a parsed tunnel build reply.
	// handler provides the reply records, messageID correlates with the original request.
	ProcessTunnelBuildReply(handler TunnelReplyHandler, messageID int) error
}

// GarlicKeyRegistrar allows callers to register one-time symmetric garlic keys
// derived from STBM Noise transcript hashes. Implemented by *GarlicSessionManager.
type GarlicKeyRegistrar interface {
	// RegisterOneTimeGarlicKey stores a single-use garlic key for a pending
	// ShortTunnelBuildReply. tag is garlicKeyMaterial[24:32], key is [0:32].
	RegisterOneTimeGarlicKey(tag [8]byte, key [32]byte)
}

// BuildMessageFactory creates serialized I2NP tunnel build messages.
// This interface decouples tunnel coordination from I2NP message types,
// allowing lib/tunnel/build to construct messages without importing lib/i2np.
//
// Only the modern Short Tunnel Build (STBM, type 25) send format is supported.
// The legacy fixed TunnelBuild (type 21) and VariableTunnelBuild (type 23)
// send paths have been removed; their receive-side parsing remains for interop.
type BuildMessageFactory interface {
	// CreateShortTunnelBuildMessage creates a serialized Short Tunnel Build message (type 25).
	// encryptedRecords contains 218-byte encrypted STBM records, messageID is the I2NP message ID.
	// Returns the serialized message bytes ready for transmission and any marshaling error.
	CreateShortTunnelBuildMessage(encryptedRecords [][]byte, messageID int) ([]byte, error)
}

// TunnelReplyProcessor processes tunnel build replies and manages reply decryption.
// This interface decouples reply handling from the TunnelManager implementation.
type TunnelReplyProcessor interface {
	// RegisterPendingBuild registers a pending tunnel build for reply correlation.
	RegisterPendingBuild(
		tunnelID buildrecord.TunnelID,
		replyKeys []session_key.SessionKey,
		replyIVs [][16]byte,
		isInbound bool,
		hopCount int,
	) error

	// SetPendingBuildNoiseHashes stores Noise transcript hashes for STBM reply AEAD decryption.
	SetPendingBuildNoiseHashes(tunnelID buildrecord.TunnelID, noiseHashes [][32]byte) error

	// ProcessBuildReply processes an incoming tunnel build reply message.
	ProcessBuildReply(handler TunnelReplyHandler, tunnelID buildrecord.TunnelID) error
}
