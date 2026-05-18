// Package build contains coordinator interfaces for tunnel building and management.
// This is a dependency-minimal package that imports only lib/tunnel/buildrecord
// and external packages, allowing both lib/tunnel and lib/i2np to depend on it
// without creating circular imports.
package build

import (
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
type BuildMessageFactory interface {
	// CreateShortTunnelBuildMessage creates a serialized Short Tunnel Build message (type 25).
	// encryptedRecords contains 218-byte encrypted STBM records, messageID is the I2NP message ID.
	// Returns the serialized message bytes ready for transmission.
	CreateShortTunnelBuildMessage(encryptedRecords [][]byte, messageID int) []byte

	// CreateVariableTunnelBuildMessage creates a serialized Variable Tunnel Build message (type 23).
	// encryptedRecords contains 528-byte encrypted VTB records, messageID is the I2NP message ID.
	// Returns the serialized message bytes ready for transmission.
	CreateVariableTunnelBuildMessage(encryptedRecords [][]byte, messageID int) []byte

	// CreateTunnelBuildMessage creates a serialized Tunnel Build message (type 21).
	// encryptedRecords must contain exactly 8 records of 528 bytes each, messageID is the I2NP message ID.
	// Returns the serialized message bytes ready for transmission.
	CreateTunnelBuildMessage(encryptedRecords [][]byte, messageID int) []byte
}
