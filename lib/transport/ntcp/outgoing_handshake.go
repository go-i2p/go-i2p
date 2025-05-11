package ntcp

import (
	"net"

	"github.com/go-i2p/go-i2p/lib/transport/ntcp/handshake"
	"github.com/go-i2p/go-i2p/lib/transport/ntcp/messages"
	"github.com/samber/oops"
)

// PerformClientHandshake performs the NTCP2 handshake as a client
func (s *NTCP2Session) PerformOutboundHandshake(conn net.Conn) error {
	// Initialize processors if not already done
	if s.Processors == nil {
		s.CreateHandshakeProcessors()
	}

	// Get request processor
	requestProcessor, err := s.GetProcessor(messages.MessageTypeSessionRequest)
	if err != nil {
		return oops.Errorf("failed to get session request processor: %w", err)
	}

	// Create message
	msg, err := requestProcessor.CreateMessage(s.HandshakeState.(*handshake.HandshakeState))
	if err != nil {
		return oops.Errorf("failed to create session request: %w", err)
	}

	// Obfuscate ephemeral key
	obfuscatedKey, err := requestProcessor.ObfuscateKey(msg, s.HandshakeState.(*handshake.HandshakeState))
	if err != nil {
		return oops.Errorf("failed to obfuscate key: %w", err)
	}

	// Encrypt payload
	encryptedPayload, err := requestProcessor.EncryptPayload(msg, obfuscatedKey, s.HandshakeState.(*handshake.HandshakeState))
	if err != nil {
		return oops.Errorf("failed to encrypt payload: %w", err)
	}

	// Write to connection
	if err := s.writeMessageToConn(conn, obfuscatedKey, encryptedPayload, requestProcessor.GetPadding(msg)); err != nil {
		return oops.Errorf("failed to write session request: %w", err)
	}

	// Continue with rest of handshake for SessionCreated and SessionConfirmed messages
	// Similar pattern for each message

	return nil
}

// Helper to write message parts to connection
func (s *NTCP2Session) writeMessageToConn(conn net.Conn, obfuscatedKey, encryptedPayload, padding []byte) error {
	// Calculate total size
	totalSize := len(obfuscatedKey) + len(encryptedPayload)
	if padding != nil {
		totalSize += len(padding)
	}

	// Create buffer and copy data
	message := make([]byte, totalSize)
	offset := 0

	copy(message[offset:], obfuscatedKey)
	offset += len(obfuscatedKey)

	copy(message[offset:], encryptedPayload)
	offset += len(encryptedPayload)

	if padding != nil {
		copy(message[offset:], padding)
	}

	// Write to connection
	_, err := conn.Write(message)
	return err
}
