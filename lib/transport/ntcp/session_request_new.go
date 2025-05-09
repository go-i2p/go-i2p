package ntcp

import (
	"crypto/rand"
	"math/big"
	"net"

	"github.com/go-i2p/go-i2p/lib/common/data"
	"github.com/go-i2p/go-i2p/lib/transport/ntcp/handshake"
	"github.com/go-i2p/go-i2p/lib/transport/ntcp/messages"
)

/*
SessionRequestProcessor implements NTCP2 Message 1 (SessionRequest):
1. Create session request message with options block (version, padding length, etc.)
2. Set timeout deadline for the connection
3. Obfuscate ephemeral key (X) using AES with Bob's router hash as key
4. Encrypt options block using ChaCha20-Poly1305
5. Assemble final message: obfuscated X + encrypted options + padding
6. Write complete message to connection
*/
type SessionRequestProcessor struct {
	*NTCP2Session
}

// Encrypt implements handshake.HandshakeMessageProcessor.
// Subtle: this method shadows the method (*NTCP2Session).Encrypt of SessionRequestProcessor.NTCP2Session.
func (s *SessionRequestProcessor) Encrypt(msg messages.Message, obfuscatedKey []byte, hs *handshake.HandshakeState) ([]byte, error) {
	panic("unimplemented")
}

// MessageType implements handshake.HandshakeMessageProcessor.
func (s *SessionRequestProcessor) MessageType() messages.MessageType {
	return messages.MessageTypeSessionRequest
}

// ProcessMessage implements handshake.HandshakeMessageProcessor.
func (s *SessionRequestProcessor) ProcessMessage(message messages.Message, hs *handshake.HandshakeState) error {
	panic("unimplemented")
}

// ReadMessage implements handshake.HandshakeMessageProcessor.
func (s *SessionRequestProcessor) ReadMessage(conn net.Conn, hs *handshake.HandshakeState) (messages.Message, error) {
	panic("unimplemented")
}

// CreateMessage implements HandshakeMessageProcessor.
func (s *SessionRequestProcessor) CreateMessage(hs *handshake.HandshakeState) (messages.Message, error) {
	// Get our ephemeral key pair
	ephemeralKey := make([]byte, 32)
	if _, err := rand.Read(ephemeralKey); err != nil {
		return nil, err
	}

	// Add random padding (implementation specific)
	randomInt, err := rand.Int(rand.Reader, big.NewInt(16))
	if err != nil {
		return nil, err
	}

	padding := make([]byte, randomInt.Int64()) // Up to 16 bytes of padding
	if err != nil {
		return nil, err
	}

	netId, err := data.NewIntegerFromInt(2, 1)
	if err != nil {
		return nil, err
	}
	version, err := data.NewIntegerFromInt(2, 1)
	if err != nil {
		return nil, err
	}
	paddingLen, _, err := data.NewInteger([]byte{byte(len(padding))}, 1)
	if err != nil {
		return nil, err
	}
	//message3Part2Len, err := data.NewInteger()
	//if err != nil {
	//	return nil, err
	//}
	timestamp, err := data.DateFromTime(s.GetCurrentTime())
	if err != nil {
		return nil, err
	}
	requestOptions := &messages.RequestOptions{
		NetworkID:       netId,
		ProtocolVersion: version,
		PaddingLength:   paddingLen,
		// Message3Part2Length: ,
		Timestamp: timestamp,
	}

	return &messages.SessionRequest{
		XContent: [32]byte(ephemeralKey),
		Options:  *requestOptions,
		Padding:  padding,
	}, nil
}

// GetPadding implements HandshakeMessageProcessor.
func (s *SessionRequestProcessor) GetPadding(msg messages.Message) []byte {
	panic("unimplemented")
}

// ObfuscateKey implements HandshakeMessageProcessor.
func (s *SessionRequestProcessor) ObfuscateKey(msg messages.Message, hs *handshake.HandshakeState) ([]byte, error) {
	return s.ObfuscateEphemeral(msg.(*messages.SessionRequest).XContent[:])
}

var _ handshake.HandshakeMessageProcessor = (*SessionRequestProcessor)(nil)
