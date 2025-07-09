package ntcp

import (
	"crypto/rand"
	"math/big"
	"net"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/go-i2p/lib/transport/ntcp/handshake"
	"github.com/go-i2p/go-i2p/lib/transport/ntcp/messages"
	"github.com/samber/oops"
)

/*
SessionCreatedProcessor implements NTCP2 Message 2 (SessionCreated):
1. Generate ephemeral Y keypair for responder side
2. Calculate current timestamp for clock skew verification
3. Create options block (timestamp, padding length, etc.)
4. Obfuscate Y using AES with same key as message 1
5. Derive KDF for handshake message 2 using established state
6. Encrypt options block using ChaCha20-Poly1305
7. Generate random padding according to negotiated parameters
8. Assemble final message: obfuscated Y + encrypted options + padding
9. Write complete message to connection

SessionCreatedProcessor processes incoming NTCP2 Message 2 (SessionCreated):
1. Read and buffer the fixed-length ephemeral key portion (Y)
2. Deobfuscate Y using AES with same state as message 1
3. Validate the ephemeral key (Y) is a valid Curve25519 point
4. Read the ChaCha20-Poly1305 encrypted options block
5. Derive KDF for handshake message 2 using established state and Y
6. Decrypt and authenticate the options block
7. Extract and validate handshake parameters (timestamp, padding length)
8. Read and validate any padding bytes
9. Compute DH with local ephemeral and remote ephemeral (ee)
10. Check timestamp for acceptable clock skew (±60 seconds?)
11. Adjust local state with received parameters
*/

type SessionCreatedProcessor struct {
	*NTCP2Session
}

// CreateMessage implements handshake.HandshakeMessageProcessor.
func (s *SessionCreatedProcessor) CreateMessage(hs *handshake.HandshakeState) (messages.Message, error) {
	// 1. Generate ephemeral key (handshakeState has already done this, we just need to extract it)
	ephemeralKey, err := s.NTCP2Session.HandshakeState.(*handshake.HandshakeState).LocalEphemeral.Public()
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

// EncryptPayload implements handshake.HandshakeMessageProcessor.
func (s *SessionCreatedProcessor) EncryptPayload(
	msg messages.Message,
	obfuscatedKey []byte,
	hs *handshake.HandshakeState,
) ([]byte, error) {
	created, ok := msg.(*messages.SessionCreated)
	if !ok {
		return nil, oops.Errorf("expected SessionCreated message, got %T", msg)
	}

	return s.NTCP2Session.EncryptWithAssociatedData(
		hs.ChachaKey,
		created.Options.Data(),
		obfuscatedKey,
		0,
	)
}

// ObfuscateKey should follow the same pattern as in SessionRequestProcessor
func (s *SessionCreatedProcessor) ObfuscateKey(msg messages.Message, hs *handshake.HandshakeState) ([]byte, error) {
	created, ok := msg.(*messages.SessionCreated)
	if !ok {
		return nil, oops.Errorf("expected SessionCreated message")
	}

	// Store the ephemeral key in the handshake state for reuse
	hs.LocalEphemeral = curve25519.Curve25519PrivateKey(created.YContent[:])

	return s.NTCP2Session.ObfuscateEphemeral(created.YContent[:])
}

// GetPadding retrieves padding from a message
func (s *SessionCreatedProcessor) GetPadding(msg messages.Message) []byte {
	created, ok := msg.(*messages.SessionCreated)
	if !ok {
		return nil
	}

	return created.Padding
}

// MessageType implements handshake.HandshakeMessageProcessor.
func (s *SessionCreatedProcessor) MessageType() messages.MessageType {
	return messages.MessageTypeSessionCreated
}

// ProcessMessage implements handshake.HandshakeMessageProcessor.
func (s *SessionCreatedProcessor) ProcessMessage(message messages.Message, hs *handshake.HandshakeState) error {
	panic("unimplemented")
}

// ReadMessage implements handshake.HandshakeMessageProcessor.
func (s *SessionCreatedProcessor) ReadMessage(conn net.Conn, hs *handshake.HandshakeState) (messages.Message, error) {
	panic("unimplemented")
}

var _ handshake.HandshakeMessageProcessor = (*SessionCreatedProcessor)(nil)
