package ntcp

import (
	"net"

	"github.com/go-i2p/go-i2p/lib/transport/ntcp/handshake"
	"github.com/go-i2p/go-i2p/lib/transport/ntcp/messages"
	"github.com/samber/oops"
)

// PerformIncomingHandshake conducts the NTCP2 handshake as the responder (server).
// It performs the server side of the 3-message handshake sequence:
// 1. Receives and processes SessionRequest (Message 1)
// 2. Creates and sends SessionCreated (Message 2)
// 3. Receives and processes SessionConfirmed (Message 3)
// After successful completion, the session is established and ready for data exchange.
func (s *NTCP2Session) PerformIncomingHandshake(conn net.Conn) error {
	// Initialize processors if not already done
	if s.Processors == nil {
		s.Processors = make(map[messages.MessageType]handshake.HandshakeMessageProcessor)
		s.Processors[messages.MessageTypeSessionRequest] = &SessionRequestProcessor{NTCP2Session: s}
		s.Processors[messages.MessageTypeSessionCreated] = &SessionCreatedProcessor{NTCP2Session: s}
		s.Processors[messages.MessageTypeSessionConfirmed] = &SessionConfirmedProcessor{NTCP2Session: s}
	}

	// Step 1: Process SessionRequest (Message 1) from initiator
	requestProcessor, err := s.GetProcessor(messages.MessageTypeSessionRequest)
	if err != nil {
		return oops.Errorf("failed to get session request processor: %w", err)
	}

	// Read and decode SessionRequest message
	requestMsg, err := requestProcessor.ReadMessage(conn, s.HandshakeState.(*handshake.HandshakeState))
	if err != nil {
		return oops.Errorf("failed to read session request message: %w", err)
	}

	// Process SessionRequest to update handshake state
	if err := requestProcessor.ProcessMessage(requestMsg, s.HandshakeState.(*handshake.HandshakeState)); err != nil {
		return oops.Errorf("failed to process session request message: %w", err)
	}

	// Step 2: Create and send SessionCreated (Message 2)
	createdProcessor, err := s.GetProcessor(messages.MessageTypeSessionCreated)
	if err != nil {
		return oops.Errorf("failed to get session created processor: %w", err)
	}

	// Create SessionCreated message
	createdMsg, err := createdProcessor.CreateMessage(s.HandshakeState.(*handshake.HandshakeState))
	if err != nil {
		return oops.Errorf("failed to create session created message: %w", err)
	}

	// Obfuscate ephemeral key
	obfuscatedKey, err := createdProcessor.ObfuscateKey(createdMsg, s.HandshakeState.(*handshake.HandshakeState))
	if err != nil {
		return oops.Errorf("failed to obfuscate ephemeral key: %w", err)
	}

	// Encrypt payload
	encryptedPayload, err := createdProcessor.EncryptPayload(
		createdMsg,
		obfuscatedKey,
		s.HandshakeState.(*handshake.HandshakeState),
	)
	if err != nil {
		return oops.Errorf("failed to encrypt session created payload: %w", err)
	}

	// Write SessionCreated to connection
	if err := s.WriteMessageToConn(
		conn,
		obfuscatedKey,
		encryptedPayload,
		createdProcessor.GetPadding(createdMsg),
	); err != nil {
		return oops.Errorf("failed to write session created message: %w", err)
	}

	// Step 3: Process SessionConfirmed (Message 3) from initiator
	confirmedProcessor, err := s.GetProcessor(messages.MessageTypeSessionConfirmed)
	if err != nil {
		return oops.Errorf("failed to get session confirmed processor: %w", err)
	}

	// Read and decode SessionConfirmed message
	confirmedMsg, err := confirmedProcessor.ReadMessage(conn, s.HandshakeState.(*handshake.HandshakeState))
	if err != nil {
		return oops.Errorf("failed to read session confirmed message: %w", err)
	}

	// Process SessionConfirmed to finalize handshake state
	if err := confirmedProcessor.ProcessMessage(confirmedMsg, s.HandshakeState.(*handshake.HandshakeState)); err != nil {
		return oops.Errorf("failed to process session confirmed message: %w", err)
	}

	// Handshake complete, mark session as established
	return s.HandshakeState.CompleteHandshake()
}
