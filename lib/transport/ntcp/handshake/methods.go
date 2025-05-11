package handshake

import (
	"github.com/flynn/noise"
	"github.com/go-i2p/go-i2p/lib/crypto/curve25519"
	"github.com/samber/oops"
)

// CompleteHandshake implements handshake.HandshakeState.
func (h *HandshakeState) CompleteHandshake() error {
	// Verify we have all necessary components for a complete handshake
	if len(h.SharedSecret) == 0 {
		return oops.Errorf("handshake incomplete: missing shared secret")
	}

	if len(h.ChachaKey) == 0 {
		return oops.Errorf("handshake incomplete: missing session key")
	}

	if len(h.HandshakeHash) == 0 {
		return oops.Errorf("handshake incomplete: missing handshake hash")
	}
	return nil
}

// GenerateEphemeral implements handshake.HandshakeState.
func (h *HandshakeState) GenerateEphemeral() (*noise.DHKey, error) {
	// Already generated in NewHandshakeState, but we format it for noise protocol
	if h.LocalEphemeral == nil {
		var err error
		_, h.LocalEphemeral, err = curve25519.GenerateKeyPair()
		if err != nil {
			return nil, oops.Errorf("failed to generate ephemeral key: %w", err)
		}
	}

	// Convert our key types to Noise framework key type
	public, err := h.LocalEphemeral.Public()
	if err != nil {
		return nil, oops.Errorf("failed to get public key: %w", err)
	}
	// Convert to Noise DHKey format
	dhKey := &noise.DHKey{
		Private: h.LocalEphemeral.Bytes(),
		Public:  public.Bytes(),
	}

	return dhKey, nil
}

// HandshakeComplete implements handshake.HandshakeState.
func (h *HandshakeState) HandshakeComplete() bool {
	// The handshake is complete when we have:
	// 1. A shared secret
	// 2. A ChaCha20 key for the session
	// 3. A handshake hash
	return h.SharedSecret != nil &&
		h.ChachaKey != nil &&
		h.HandshakeHash != nil &&
		len(h.SharedSecret) > 0 &&
		len(h.ChachaKey) > 0 &&
		len(h.HandshakeHash) > 0
}

// WriteMessage implements handshake.HandshakeState.
func (h *HandshakeState) WriteMessage(payload []byte) ([]byte, *noise.CipherState, *noise.CipherState, error) {
	return []byte{}, nil, nil, oops.Errorf("not implemented")
}
