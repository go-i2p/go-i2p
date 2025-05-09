package ntcp

import (
	"net"

	"github.com/go-i2p/go-i2p/lib/transport/ntcp/handshake"
	"github.com/go-i2p/go-i2p/lib/transport/ntcp/messages"
)

type SessionConfirmedProcessor struct {
	*NTCP2Session
}

// CreateMessage implements handshake.HandshakeMessageProcessor.
func (s *SessionConfirmedProcessor) CreateMessage(hs *handshake.HandshakeState) (messages.Message, error) {
	panic("unimplemented")
}

// Encrypt implements handshake.HandshakeMessageProcessor.
// Subtle: this method shadows the method (*NTCP2Session).Encrypt of SessionConfirmedProcessor.NTCP2Session.
func (s *SessionConfirmedProcessor) Encrypt(msg messages.Message, obfuscatedKey []byte, hs *handshake.HandshakeState) ([]byte, error) {
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
