package ntcp

import (
	"net"

	"github.com/go-i2p/go-i2p/lib/transport/ntcp/handshake"
	"github.com/go-i2p/go-i2p/lib/transport/ntcp/messages"
)

type SessionCreatedProcessor struct {
	*NTCP2Session
}

// CreateMessage implements handshake.HandshakeMessageProcessor.
func (s *SessionCreatedProcessor) CreateMessage(hs *handshake.HandshakeState) (messages.Message, error) {
	panic("unimplemented")
}

// Encrypt implements handshake.HandshakeMessageProcessor.
// Subtle: this method shadows the method (*NTCP2Session).Encrypt of SessionCreatedProcessor.NTCP2Session.
func (s *SessionCreatedProcessor) Encrypt(msg messages.Message, obfuscatedKey []byte, hs *handshake.HandshakeState) ([]byte, error) {
	panic("unimplemented")
}

// GetPadding implements handshake.HandshakeMessageProcessor.
func (s *SessionCreatedProcessor) GetPadding(msg messages.Message) []byte {
	panic("unimplemented")
}

// MessageType implements handshake.HandshakeMessageProcessor.
func (s *SessionCreatedProcessor) MessageType() messages.MessageType {
	panic("unimplemented")
}

// ObfuscateKey implements handshake.HandshakeMessageProcessor.
func (s *SessionCreatedProcessor) ObfuscateKey(msg messages.Message, hs *handshake.HandshakeState) ([]byte, error) {
	panic("unimplemented")
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
