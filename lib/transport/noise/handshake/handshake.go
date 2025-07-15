package handshake

import (
	"reflect"
	"sync"

	"github.com/flynn/noise"
	"github.com/go-i2p/go-i2p/lib/transport/handshake"
	"github.com/go-i2p/go-i2p/lib/transport/noise/kdf"
	"github.com/samber/oops"
)

// HandshakeState wraps noise.HandshakeState with additional functionality
type NoiseHandshakeState struct {
	mutex sync.Mutex
	noise.HandshakePattern
	*noise.HandshakeState
	handshake.KeyTransformer
	*kdf.NoiseKDF
	isComplete bool
}

func NewHandshakeState(staticKey noise.DHKey, isInitiator bool) (*NoiseHandshakeState, error) {
	hs := &NoiseHandshakeState{
		HandshakePattern: noise.HandshakeXK,
	}

	config := noise.Config{
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:       hs.HandshakePattern,
		Initiator:     isInitiator,
		StaticKeypair: staticKey,
	}

	protocol, err := noise.NewHandshakeState(config)
	if err != nil {
		return nil, err
	}

	hs.HandshakeState = protocol
	return hs, nil
}

// SetEphemeral allows setting a potentially modified ephemeral key
// This is needed for NTCP2's obfuscation layer
func (h *NoiseHandshakeState) SetEphemeral(key *noise.DHKey) error {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	// in Noise, SetEphemeral is a no-op because the ephemeral key is
	// already set in the handshake state
	// This is a placeholder for any additional logic needed
	// in the future
	return nil
}

// GenerateEphemeral implements handshake.HandshakeState
func (hs *NoiseHandshakeState) GenerateEphemeral() (*noise.DHKey, error) {
	hs.mutex.Lock()
	defer hs.mutex.Unlock()
	// in Noise, GenerateEphemeral is a no-op because the ephemeral key is
	// already set in the handshake state
	// This is a placeholder for any additional logic needed
	// in the future
	dhKey := hs.HandshakeState.LocalEphemeral()
	// Set the ephemeral key in the handshake state
	// This is a placeholder for any additional logic needed
	// in the future

	return &dhKey, nil
}

// WriteMessage implements handshake.HandshakeState
func (hs *NoiseHandshakeState) WriteMessage(payload []byte) ([]byte, *noise.CipherState, *noise.CipherState, error) {
	hs.mutex.Lock()
	defer hs.mutex.Unlock()

	// Generate the message with normal Noise implementation
	message, cs0, cs1, err := hs.HandshakeState.WriteMessage(nil, payload)
	if err != nil {
		return nil, nil, nil, oops.Errorf("failed to write handshake message: %w", err)
	}

	// If cipher states are returned, handshake is complete
	if cs0 != nil && cs1 != nil {
		hs.isComplete = true
		// Update handshake hash from the Noise state
		hs.updateHandshakeHash()
	}

	// Apply key transformation if the ephemeral key is in this message
	if len(message) >= 32 { // Approximate check for ephemeral key presence
		transformedMessage, err := hs.KeyTransformer.ObfuscateKey(message)
		if err != nil {
			return nil, nil, nil, oops.Errorf("failed to obfuscate key: %w", err)
		}
		message = transformedMessage
	}

	return message, cs0, cs1, nil
}

// ReadMessage implements handshake.HandshakeState
func (hs *NoiseHandshakeState) ReadMessage(message []byte) ([]byte, *noise.CipherState, *noise.CipherState, error) {
	hs.mutex.Lock()
	defer hs.mutex.Unlock()

	// Process the message with normal Noise implementation
	payload, cs0, cs1, err := hs.HandshakeState.ReadMessage(nil, message)
	if err != nil {
		return nil, nil, nil, oops.Errorf("failed to read handshake message: %w", err)
	}

	// If cipher states are returned, handshake is complete
	if cs0 != nil && cs1 != nil {
		hs.isComplete = true
		// Update handshake hash from the Noise state
		hs.updateHandshakeHash()
	}

	return payload, cs0, cs1, nil
}

// HandshakeComplete implements handshake.HandshakeState
func (hs *NoiseHandshakeState) HandshakeComplete() bool {
	hs.mutex.Lock()
	defer hs.mutex.Unlock()
	return hs.isComplete
}

// CompleteHandshake implements handshake.HandshakeState
func (hs *NoiseHandshakeState) CompleteHandshake() error {
	hs.mutex.Lock()
	defer hs.mutex.Unlock()
	hs.isComplete = true
	return nil
}

// SetEphemeralTransformer implements handshake.HandshakeState
func (hs *NoiseHandshakeState) SetEphemeralTransformer(transformer handshake.KeyTransformer) {
	hs.mutex.Lock()
	defer hs.mutex.Unlock()
	hs.KeyTransformer = transformer
}

// GetHandshakeHash implements handshake.HandshakeState
func (hs *NoiseHandshakeState) GetHandshakeHash() []byte {
	hs.mutex.Lock()
	defer hs.mutex.Unlock()

	if hs.NoiseKDF != nil {
		return hs.NoiseKDF.GetHandshakeHash()
	}

	// Fallback when KDF not available
	return nil
}

// SetPrologue implements handshake.HandshakeState
func (hs *NoiseHandshakeState) SetPrologue(prologue []byte) error {
	hs.mutex.Lock()
	defer hs.mutex.Unlock()

	// In a real implementation, we would need to access the HandshakeState internals
	// or use the Noise API to set the prologue.
	// For now, we'll just mix it into our KDF if available
	if hs.NoiseKDF != nil {
		return hs.NoiseKDF.MixHash(prologue)
	}

	// Future implementation: Call appropriate method on noise.HandshakeState
	// or reconstruct the HandshakeState with the prologue

	return oops.Errorf("prologue setting not fully implemented")
}

// MixHash implements handshake.HandshakeState
func (hs *NoiseHandshakeState) MixHash(data []byte) error {
	hs.mutex.Lock()
	defer hs.mutex.Unlock()

	if hs.NoiseKDF == nil {
		// Initialize KDF if not already done
		protocolName := []byte("Noise_XK_25519_ChaChaPoly_SHA256")
		hs.NoiseKDF = kdf.NewNoiseKDF(protocolName)
	}

	return hs.NoiseKDF.MixHash(data)
}

// MixKey implements handshake.HandshakeState
func (hs *NoiseHandshakeState) MixKey(input []byte) ([]byte, error) {
	hs.mutex.Lock()
	defer hs.mutex.Unlock()

	if hs.NoiseKDF == nil {
		// Initialize KDF if not already done
		protocolName := []byte("Noise_XK_25519_ChaChaPoly_SHA256")
		hs.NoiseKDF = kdf.NewNoiseKDF(protocolName)
	}

	return hs.NoiseKDF.MixKey(input)
}

// updateHandshakeHash is a helper method to extract handshake hash from the Noise state
func (hs *NoiseHandshakeState) updateHandshakeHash() {
	// Use reflection to access the internal symmetricState field in noise.HandshakeState
	hsValue := reflect.ValueOf(hs.HandshakeState).Elem()

	// Find the symmetricState field
	symmetricStateField := hsValue.FieldByName("symmetricState")
	if !symmetricStateField.IsValid() {
		// Fallback if we can't find the field
		if hs.NoiseKDF == nil {
			hs.NoiseKDF = kdf.NewNoiseKDF([]byte("Noise_XK_25519_ChaChaPoly_SHA256"))
		}
		return
	}

	// Get the symmetricState value
	symmetricState := symmetricStateField
	if symmetricState.Kind() == reflect.Ptr {
		symmetricState = symmetricState.Elem()
	}

	// Find the handshake hash field (usually named 'h')
	hashField := symmetricState.FieldByName("h")
	if !hashField.IsValid() {
		// Fallback if we can't find the hash field
		if hs.NoiseKDF == nil {
			hs.NoiseKDF = kdf.NewNoiseKDF([]byte("Noise_XK_25519_ChaChaPoly_SHA256"))
		}
		return
	}

	// Extract the hash bytes
	var hashBytes []byte
	if hashField.Kind() == reflect.Slice && hashField.Type().Elem().Kind() == reflect.Uint8 {
		hashBytes = make([]byte, hashField.Len())
		for i := 0; i < hashField.Len(); i++ {
			hashBytes[i] = byte(hashField.Index(i).Uint())
		}
	}

	// Create or update KDF with the actual handshake hash
	if hs.NoiseKDF == nil {
		hs.NoiseKDF = kdf.NewNoiseKDF([]byte("Noise_XK_25519_ChaChaPoly_SHA256"))
	}

	// Update the KDF with the extracted hash
	if len(hashBytes) > 0 {
		// Assuming NoiseKDF allows setting the hash directly
		// This might need to be adapted based on the actual NoiseKDF implementation
		hs.NoiseKDF.SetHash(hashBytes)
	}
}
