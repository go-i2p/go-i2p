package handshake

import "github.com/flynn/noise"

// HandshakeState manages the Noise handshake state
type HandshakeState interface {
	// GenerateEphemeral creates ephemeral keypair
	GenerateEphemeral() (*noise.DHKey, error)

	// WriteMessage creates Noise message
	WriteMessage([]byte) ([]byte, *noise.CipherState, *noise.CipherState, error)

	// HandshakeComplete returns true if handshake is complete
	HandshakeComplete() bool

	// CompleteHandshake completes the handshake
	CompleteHandshake() error

	SetEphemeralTransformer(transformer KeyTransformer)
	GetHandshakeHash() []byte
	SetPrologue(prologue []byte) error
	MixHash(data []byte) error
	MixKey(input []byte) ([]byte, error)
}
