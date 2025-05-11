package ntcp

import (
	"crypto/rand"
	"fmt"
	"net"

	"github.com/go-i2p/go-i2p/lib/common/data"
	"github.com/go-i2p/go-i2p/lib/transport/ntcp/handshake"
	"github.com/go-i2p/go-i2p/lib/transport/ntcp/messages"
)

/*
SessionConfirmedProcessor implements NTCP2 Message 3 (SessionConfirmed):
1. Create two separate ChaChaPoly frames for this message
2. For first frame:
	a. Extract local static key (s)
	b. Derive KDF for handshake message 3 part 1
	c. Encrypt static key using ChaCha20-Poly1305
3. For second frame:
	a. Prepare payload with local RouterInfo, options, and padding
	b. Derive KDF for handshake message 3 part 2 using se pattern
	c. Encrypt payload using ChaCha20-Poly1305
4. Assemble final message: encrypted static key frame + encrypted payload frame
5. Write complete message to connection
6. Derive final data phase keys (k_ab, k_ba) using Split() operation
7. Initialize SipHash keys for data phase length obfuscation

SessionConfirmedProcessor processes incoming NTCP2 Message 3 (SessionConfirmed):
1. Read first ChaChaPoly frame containing encrypted static key
2. Derive KDF for handshake message 3 part 1
3. Decrypt and authenticate static key frame
4. Validate decrypted static key is a valid Curve25519 point
5. Read second ChaChaPoly frame with size specified in message 1
6. Derive KDF for handshake message 3 part 2 using se pattern
7. Decrypt and authenticate second frame
8. Extract RouterInfo from decrypted payload
9. Validate RouterInfo matches expected router identity
10. Process any options included in the payload
11. Derive final data phase keys (k_ab, k_ba) using Split() operation
12. Initialize SipHash keys for data phase length obfuscation
13. Mark handshake as complete
*/

type SessionConfirmedProcessor struct {
	*NTCP2Session
}

// CreateMessage implements handshake.HandshakeMessageProcessor.
func (s *SessionConfirmedProcessor) CreateMessage(hs *handshake.HandshakeState) (messages.Message, error) {
	// Create the SessionConfirmed message
	sc := &messages.SessionConfirmed{}

	// Step 1: Get our static key from the handshake state
	// Note: The static key must be encrypted using the handshakeState's WriteMessage
	// but we need to extract it first to store in the result structure
	localKeyPair, err := s.NTCP2Session.localStaticKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get local static keypair: %w", err)
	}

	// Copy the 32-byte static key
	copy(sc.StaticKey[:], localKeyPair[:])

	// Step 2: Set the RouterInfo
	sc.RouterInfo = &s.NTCP2Session.RouterInfo

	// Step 3: Create options with padding settings
	// Use default padding for now - we should make this something we can configure
	paddingLength, err := data.NewIntegerFromInt(calculatePaddingLength(sc.RouterInfo), 1)
	if err != nil {
		return nil, fmt.Errorf("failed to create padding length: %w", err)
	}

	sc.Options = &messages.ConfirmedOptions{
		PaddingLength: paddingLength,
	}

	// Step 4: Generate padding data according to the specified length
	// In a real implementation, this should be cryptographically secure random data
	if paddingLength.Int() > 0 {
		sc.Padding = make([]byte, paddingLength.Int())
		if _, err := rand.Read(sc.Padding); err != nil {
			return nil, fmt.Errorf("failed to generate padding: %w", err)
		}
	}

	// The actual encryption of the message will happen in the calling function
	// using the handshakeState.WriteMessage() method, as it needs to maintain the
	// proper noise protocol state
	return sc, nil
}

// EncryptPayload implements handshake.HandshakeMessageProcessor.
func (s *SessionConfirmedProcessor) EncryptPayload(msg messages.Message, obfuscatedKey []byte, hs *handshake.HandshakeState) ([]byte, error) {
	panic("unimplemented")
}

// GetPadding implements handshake.HandshakeMessageProcessor.
func (s *SessionConfirmedProcessor) GetPadding(msg messages.Message) []byte {
	panic("unimplemented")
}

// MessageType implements handshake.HandshakeMessageProcessor.
func (s *SessionConfirmedProcessor) MessageType() messages.MessageType {
	return messages.MessageTypeSessionConfirmed
}

// ObfuscateKey implements handshake.HandshakeMessageProcessor.
func (s *SessionConfirmedProcessor) ObfuscateKey(msg messages.Message, hs *handshake.HandshakeState) ([]byte, error) {
	panic("unimplemented")
}

// ProcessMessage implements handshake.HandshakeMessageProcessor.
func (s *SessionConfirmedProcessor) ProcessMessage(message messages.Message, hs *handshake.HandshakeState) error {
	panic("unimplemented")
}

// ReadMessage implements handshake.HandshakeMessageProcessor.
func (s *SessionConfirmedProcessor) ReadMessage(conn net.Conn, hs *handshake.HandshakeState) (messages.Message, error) {
	panic("unimplemented")
}

var _ handshake.HandshakeMessageProcessor = (*SessionConfirmedProcessor)(nil)
