package ntcp

import (
	"net"

	"github.com/go-i2p/go-i2p/lib/transport/ntcp/handshake"
	"github.com/go-i2p/go-i2p/lib/transport/ntcp/messages"
	"github.com/samber/oops"
)

// PerformOutboundHandshake conducts the NTCP2 handshake as the initiator (client).
// It performs the full 3-message handshake sequence:
// 1. Creates and sends SessionRequest (Message 1)
// 2. Receives and processes SessionCreated (Message 2)
// 3. Creates and sends SessionConfirmed (Message 3)
// After successful completion, the session is established and ready for data exchange.
func (s *NTCP2Session) PerformOutboundHandshake(conn net.Conn) error {
	// Initialize processors if not already done
	if s.Processors == nil {
		s.Processors = make(map[messages.MessageType]handshake.HandshakeMessageProcessor)
		s.Processors[messages.MessageTypeSessionRequest] = &SessionRequestProcessor{NTCP2Session: s}
		s.Processors[messages.MessageTypeSessionCreated] = &SessionCreatedProcessor{NTCP2Session: s}
		s.Processors[messages.MessageTypeSessionConfirmed] = &SessionConfirmedProcessor{NTCP2Session: s}
	}

	// Step 1: Get SessionRequest processor and create Message 1
	requestProcessor, err := s.GetProcessor(messages.MessageTypeSessionRequest)
	if err != nil {
		return oops.Errorf("failed to get session request processor: %w", err)
	}

	// Create and prepare SessionRequest
	msg, err := requestProcessor.CreateMessage(s.HandshakeState.(*handshake.HandshakeState))
	if err != nil {
		return oops.Errorf("failed to create session request: %w", err)
	}

	// Obfuscate ephemeral key
	obfuscatedKey, err := requestProcessor.ObfuscateKey(msg, s.HandshakeState.(*handshake.HandshakeState))
	if err != nil {
		return oops.Errorf("failed to obfuscate ephemeral key: %w", err)
	}

	// Encrypt options payload
	encryptedPayload, err := requestProcessor.EncryptPayload(msg, obfuscatedKey, s.HandshakeState.(*handshake.HandshakeState))
	if err != nil {
		return oops.Errorf("failed to encrypt session request payload: %w", err)
	}

	// Write complete SessionRequest message to connection
	if err := s.writeMessageToConn(conn, obfuscatedKey, encryptedPayload, requestProcessor.GetPadding(msg)); err != nil {
		return oops.Errorf("failed to write session request: %w", err)
	}

	// Step 2: Process SessionCreated (Message 2) from responder
	createdProcessor, err := s.GetProcessor(messages.MessageTypeSessionCreated)
	if err != nil {
		return oops.Errorf("failed to get session created processor: %w", err)
	}

	// Read and decode SessionCreated message
	createdMsg, err := createdProcessor.ReadMessage(conn, s.HandshakeState.(*handshake.HandshakeState))
	if err != nil {
		return oops.Errorf("failed to read session created message: %w", err)
	}

	// Process SessionCreated to update handshake state
	if err := createdProcessor.ProcessMessage(createdMsg, s.HandshakeState.(*handshake.HandshakeState)); err != nil {
		return oops.Errorf("failed to process session created message: %w", err)
	}

	// Step 3: Create and send SessionConfirmed (Message 3)
	confirmedProcessor, err := s.GetProcessor(messages.MessageTypeSessionConfirmed)
	if err != nil {
		return oops.Errorf("failed to get session confirmed processor: %w", err)
	}

	// Create SessionConfirmed message
	confirmedMsg, err := confirmedProcessor.CreateMessage(s.HandshakeState.(*handshake.HandshakeState))
	if err != nil {
		return oops.Errorf("failed to create session confirmed message: %w", err)
	}

	staticKey, err := s.LocalStaticKey()
	if err != nil {
		return oops.Errorf("failed to get local static key: %w", err)
	}

	// Encrypt RouterInfo payload
	encryptedConfirmedPayload, err := confirmedProcessor.EncryptPayload(
		confirmedMsg,
		staticKey[:],
		s.HandshakeState.(*handshake.HandshakeState),
	)
	if err != nil {
		return oops.Errorf("failed to encrypt session confirmed payload: %w", err)
	}

	// Write SessionConfirmed to connection
	if err := s.writeMessageToConn(
		conn,
		staticKey[:],
		encryptedConfirmedPayload,
		confirmedProcessor.GetPadding(confirmedMsg),
	); err != nil {
		return oops.Errorf("failed to write session confirmed message: %w", err)
	}

	// Handshake complete, mark session as established
	return s.HandshakeState.CompleteHandshake()
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
