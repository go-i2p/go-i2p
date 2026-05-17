package build

import (
	common "github.com/go-i2p/common/data"
)

// BuildSession represents a transport session capable of sending raw bytes
// for tunnel build messages. This interface decouples tunnel building from
// I2NP message types, allowing lib/tunnel/build to avoid importing lib/i2np.
type BuildSession interface {
	// Send transmits raw bytes (a serialized I2NP message) to the peer.
	Send(data []byte) error
}

// BuildSessionProvider defines the interface for obtaining transport sessions
// by peer hash. The tunnel builder uses this to send build requests without
// depending on I2NP-specific transport session types.
type BuildSessionProvider interface {
	// GetSessionByHash returns a BuildSession for the given peer hash,
	// or an error if no session exists.
	GetSessionByHash(hash common.Hash) (BuildSession, error)
}
