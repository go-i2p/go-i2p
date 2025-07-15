package handshake

import (
	"crypto/rand"
	"io"

	"github.com/flynn/noise"
	"github.com/go-i2p/go-i2p/lib/transport/handshake"
)

// HandshakeBuilder constructs customized HandshakeState instances
type HandshakeBuilder struct {
	isInitiator    bool
	pattern        noise.HandshakePattern
	staticKey      noise.DHKey
	peerStaticKey  []byte
	prologue       []byte
	randomSource   io.Reader
	keyTransformer handshake.KeyTransformer
}

// NewHandshakeBuilder creates a new HandshakeBuilder with default values
func NewHandshakeBuilder() *HandshakeBuilder {
	return &HandshakeBuilder{
		pattern:        noise.HandshakeXK,
		randomSource:   rand.Reader,
		keyTransformer: &handshake.NoOpTransformer{},
	}
}

// AsInitiator sets this handshake as the initiator
func (b *HandshakeBuilder) AsInitiator(isInitiator bool) *HandshakeBuilder {
	b.isInitiator = isInitiator
	return b
}

// WithPattern sets the handshake pattern
func (b *HandshakeBuilder) WithPattern(pattern noise.HandshakePattern) *HandshakeBuilder {
	b.pattern = pattern
	return b
}

// WithStaticKey sets the local static key
func (b *HandshakeBuilder) WithStaticKey(key noise.DHKey) *HandshakeBuilder {
	b.staticKey = key
	return b
}

// WithPeerStaticKey sets the peer's static key
func (b *HandshakeBuilder) WithPeerStaticKey(key []byte) *HandshakeBuilder {
	b.peerStaticKey = key
	return b
}

// WithPrologue sets the prologue data
func (b *HandshakeBuilder) WithPrologue(prologue []byte) *HandshakeBuilder {
	b.prologue = prologue
	return b
}

// WithKeyTransformer sets a custom key transformer
func (b *HandshakeBuilder) WithKeyTransformer(transformer handshake.KeyTransformer) *HandshakeBuilder {
	b.keyTransformer = transformer
	return b
}

// Build creates a configured HandshakeState
func (b *HandshakeBuilder) Build() (handshake.HandshakeState, error) {
	// Configure and build the noise handshake state
	config := noise.Config{
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:       b.pattern,
		Initiator:     b.isInitiator,
		StaticKeypair: b.staticKey,
		PeerStatic:    b.peerStaticKey,
		Prologue:      b.prologue,
		Random:        b.randomSource,
	}

	noiseState, err := noise.NewHandshakeState(config)
	if err != nil {
		return nil, err
	}

	// Create and return our enhanced handshake state
	state := &NoiseHandshakeState{
		HandshakeState: noiseState,
		KeyTransformer: b.keyTransformer,
	}

	return state, nil
}
