package ntcp

import (
	"crypto/rand"
	"math/big"

	"github.com/go-i2p/go-i2p/lib/common/data"
	"github.com/go-i2p/go-i2p/lib/common/router_info"
	"github.com/go-i2p/go-i2p/lib/transport/ntcp/handshake"
	"github.com/go-i2p/go-i2p/lib/transport/ntcp/messages"
	"github.com/samber/oops"
	"golang.org/x/crypto/chacha20poly1305"
)

// CreateSessionCreated builds the SessionCreated message (Message 2 in NTCP2 handshake)
// This is sent by Bob to Alice after receiving SessionRequest
func (s *NTCP2Session) CreateSessionCreated(
	handshakeState *handshake.HandshakeState,
	localRouterInfo *router_info.RouterInfo,
) (*messages.SessionCreated, error) {
	// 1. Generate ephemeral key (handshakeState has already done this, we just need to extract it)
	ephemeralKey, err := handshakeState.LocalEphemeral.Public()
	if err != nil {
		return nil, oops.Errorf("failed to get local ephemeral key: %w", err)
	}

	// 2. Create padding according to NTCP2 spec
	// NTCP2 spec recommends 0-31 bytes of random padding
	paddingSize, err := rand.Int(rand.Reader, big.NewInt(32))
	if err != nil {
		return nil, oops.Errorf("failed to generate random padding size: %w", err)
	}

	padding := make([]byte, paddingSize.Int64())
	if _, err := rand.Read(padding); err != nil {
		return nil, oops.Errorf("failed to generate padding: %w", err)
	}

	// 3. Create response options
	timestamp, err := data.DateFromTime(s.GetCurrentTime())
	if err != nil {
		return nil, oops.Errorf("failed to create timestamp: %w", err)
	}
	paddingLen, err := data.NewIntegerFromInt(len(padding), 1)
	if err != nil {
		return nil, oops.Errorf("failed to create padding length: %w", err)
	}

	// Create response options with appropriate fields
	responseOptions := &messages.CreatedOptions{
		PaddingLength: paddingLen,
		Timestamp:     timestamp,
	}

	// 4. Return the complete SessionCreated message
	return &messages.SessionCreated{
		YContent: [32]byte(ephemeralKey.Bytes()), // Y is the obfuscated ephemeral key
		Options:  responseOptions,
		Padding:  padding,
	}, nil
}

// encryptSessionCreatedOptions encrypts the SessionCreated options block using the
// Noise protocol's ChaCha20-Poly1305 AEAD construction as defined in the NTCP2 spec.
// It modifies the sessionCreated message in-place, setting the EncryptedOptions field.
// encryptSessionCreatedOptions encrypts the SessionCreated options block using the
// Noise protocol's ChaCha20-Poly1305 AEAD construction as defined in the NTCP2 spec.
// It returns the encrypted options with authentication tag.
func (s *NTCP2Session) encryptSessionCreatedOptions(
	sessionCreated *messages.SessionCreated,
	obfuscatedY []byte,
	handshakeState *handshake.HandshakeState,
) ([]byte, error) {
	// Serialize options to bytes for encryption
	optionsBytes := sessionCreated.Options.Data()

	// We need to derive encryption key from handshakeState
	// This is done using the shared secret established after processing the X key
	// and using the obfuscatedY as associated data

	// Using message2CipherKey method from the handshakeState if available
	// or we can use the chachaKey directly with appropriate nonce construction
	nonce := make([]byte, 12) // ChaCha20-Poly1305 uses 12-byte nonces

	// In NTCP2, the nonce for message 2 would typically be 0 (first message with this key)
	// Create AEAD cipher with the key from handshake state
	aead, err := chacha20poly1305.New(handshakeState.ChachaKey)
	if err != nil {
		return nil, oops.Errorf("failed to create AEAD cipher: %w", err)
	}

	// Encrypt and authenticate the options block
	// Using the obfuscatedY as associated data ensures cryptographic binding
	// between the key and the encrypted data
	ciphertext := aead.Seal(nil, nonce, optionsBytes, obfuscatedY)

	return ciphertext, nil
}
