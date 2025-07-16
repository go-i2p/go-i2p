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
	if err := s.initializeHandshakeProcessors(); err != nil {
		return err
	}

	if err := s.sendSessionRequest(conn); err != nil {
		return err
	}

	if err := s.processSessionCreated(conn); err != nil {
		return err
	}

	if err := s.sendSessionConfirmed(conn); err != nil {
		return err
	}

	return s.HandshakeState.CompleteHandshake()
}

// initializeHandshakeProcessors sets up the message processors if not already initialized.
func (s *NTCP2Session) initializeHandshakeProcessors() error {
	if s.Processors == nil {
		s.Processors = make(map[messages.MessageType]handshake.HandshakeMessageProcessor)
		s.Processors[messages.MessageTypeSessionRequest] = &SessionRequestProcessor{NTCP2Session: s}
		s.Processors[messages.MessageTypeSessionCreated] = &SessionCreatedProcessor{NTCP2Session: s}
		s.Processors[messages.MessageTypeSessionConfirmed] = &SessionConfirmedProcessor{NTCP2Session: s}
	}
	return nil
}

// sendSessionRequest creates and sends the SessionRequest message (Message 1).
func (s *NTCP2Session) sendSessionRequest(conn net.Conn) error {
	requestProcessor, err := s.GetProcessor(messages.MessageTypeSessionRequest)
	if err != nil {
		return oops.Errorf("failed to get session request processor: %w", err)
	}

	msg, err := requestProcessor.CreateMessage(s.HandshakeState.(*handshake.HandshakeState))
	if err != nil {
		return oops.Errorf("failed to create session request: %w", err)
	}

	obfuscatedKey, err := requestProcessor.ObfuscateKey(msg, s.HandshakeState.(*handshake.HandshakeState))
	if err != nil {
		return oops.Errorf("failed to obfuscate ephemeral key: %w", err)
	}

	encryptedPayload, err := requestProcessor.EncryptPayload(msg, obfuscatedKey, s.HandshakeState.(*handshake.HandshakeState))
	if err != nil {
		return oops.Errorf("failed to encrypt session request payload: %w", err)
	}

	if err := s.WriteMessageToConn(conn, obfuscatedKey, encryptedPayload, requestProcessor.GetPadding(msg)); err != nil {
		return oops.Errorf("failed to write session request: %w", err)
	}

	return nil
}

// processSessionCreated receives and processes the SessionCreated message (Message 2).
func (s *NTCP2Session) processSessionCreated(conn net.Conn) error {
	createdProcessor, err := s.GetProcessor(messages.MessageTypeSessionCreated)
	if err != nil {
		return oops.Errorf("failed to get session created processor: %w", err)
	}

	createdMsg, err := createdProcessor.ReadMessage(conn, s.HandshakeState.(*handshake.HandshakeState))
	if err != nil {
		return oops.Errorf("failed to read session created message: %w", err)
	}

	if err := createdProcessor.ProcessMessage(createdMsg, s.HandshakeState.(*handshake.HandshakeState)); err != nil {
		return oops.Errorf("failed to process session created message: %w", err)
	}

	return nil
}

// sendSessionConfirmed creates and sends the SessionConfirmed message (Message 3).
func (s *NTCP2Session) sendSessionConfirmed(conn net.Conn) error {
	confirmedProcessor, err := s.GetProcessor(messages.MessageTypeSessionConfirmed)
	if err != nil {
		return oops.Errorf("failed to get session confirmed processor: %w", err)
	}

	confirmedMsg, err := confirmedProcessor.CreateMessage(s.HandshakeState.(*handshake.HandshakeState))
	if err != nil {
		return oops.Errorf("failed to create session confirmed message: %w", err)
	}

	staticKey, err := s.LocalStaticKey()
	if err != nil {
		return oops.Errorf("failed to get local static key: %w", err)
	}

	encryptedConfirmedPayload, err := confirmedProcessor.EncryptPayload(
		confirmedMsg,
		staticKey[:],
		s.HandshakeState.(*handshake.HandshakeState),
	)
	if err != nil {
		return oops.Errorf("failed to encrypt session confirmed payload: %w", err)
	}

	if err := s.WriteMessageToConn(
		conn,
		staticKey[:],
		encryptedConfirmedPayload,
		confirmedProcessor.GetPadding(confirmedMsg),
	); err != nil {
		return oops.Errorf("failed to write session confirmed message: %w", err)
	}

	return nil
}
