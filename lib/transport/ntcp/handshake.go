package ntcp

import (
	"net"
	"time"

	"github.com/go-i2p/go-i2p/lib/transport/ntcp/handshake"
	"github.com/go-i2p/go-i2p/lib/transport/ntcp/messages"
	"github.com/samber/oops"
)

// CreateHandshakeProcessors initializes all the handshake message processors
func (s *NTCP2Session) CreateHandshakeProcessors() {
	s.Processors = map[messages.MessageType]handshake.HandshakeMessageProcessor{
		messages.MessageTypeSessionRequest:   &SessionRequestProcessor{NTCP2Session: s},
		messages.MessageTypeSessionCreated:   &SessionCreatedProcessor{NTCP2Session: s},
		messages.MessageTypeSessionConfirmed: &SessionConfirmedProcessor{NTCP2Session: s},
	}
}

// GetProcessor returns the appropriate processor for a message type
func (s *NTCP2Session) GetProcessor(messageType messages.MessageType) (handshake.HandshakeMessageProcessor, error) {
	processor, exists := s.Processors[messageType]
	if !exists {
		return nil, oops.Errorf("no processor for message type: %v", messageType)
	}
	return processor, nil
}

// PerformClientHandshake performs the NTCP2 handshake as a client
func (s *NTCP2Session) PerformClientHandshake(conn net.Conn) error {
	// Initialize processors
	s.CreateHandshakeProcessors()

	// Get request processor
	processor, err := s.GetProcessor(messages.MessageTypeSessionRequest)
	if err != nil {
		return err
	}

	// Create and send SessionRequest
	msg, err := processor.CreateMessage(s.HandshakeState.(*handshake.HandshakeState))
	if err != nil {
		return err
	}

	// Obfuscate key
	obfuscatedKey, err := processor.ObfuscateKey(msg, s.HandshakeState.(*handshake.HandshakeState))
	if err != nil {
		return err
	}

	// Encrypt payload
	// encryptedPayload
	_, err = processor.EncryptPayload(msg, obfuscatedKey, s.HandshakeState.(*handshake.HandshakeState))
	if err != nil {
		return err
	}

	// Write message to connection
	// ... implementation ...

	// Continue with rest of handshake
	// ... implementation ...

	return nil
}

// receiveSessionRequest processes Message 1 (SessionRequest) from remote
func (c *NTCP2Session) receiveSessionRequest(conn net.Conn, hs *handshake.HandshakeState) error {
	log.Debugf("NTCP2: Processing incoming SessionRequest message")

	// Read the ephemeral key (X)
	ephemeralKey, err := c.readEphemeralKey(conn)
	if err != nil {
		return err
	}

	// Process the ephemeral key
	deobfuscatedX, err := c.processEphemeralKey(ephemeralKey, hs)
	if err != nil {
		return err
	}

	// Read and decrypt the options block
	optionsBlock, err := c.readOptionsBlock(conn)
	if err != nil {
		return err
	}

	// Process the options block
	requestOptions, err := c.processOptionsBlock(optionsBlock, ephemeralKey, deobfuscatedX, hs)
	if err != nil {
		return err
	}

	// Read and validate padding if present
	if requestOptions.PaddingLength.Int() > 0 {
		if err := c.readAndValidatePadding(conn, requestOptions.PaddingLength.Int()); err != nil {
			return err
		}
	}

	log.Debugf("NTCP2: SessionRequest processed successfully")
	return nil
}

// sendSessionCreated sends Message 2 (SessionCreated) to the remote peer
func (c *NTCP2Session) sendSessionCreated(conn net.Conn, hs *handshake.HandshakeState) error {
	// Implement according to NTCP2 spec
	// uses CreateSessionCreated from session_created.go
	// see also: session_created.go, messages/session_created.go
	// TODO: Implement Message 2 processing
	log.Debugf("NTCP2: Sending SessionCreated message")

	// 1. Create the SessionCreated message structure
	sessionCreatedMessage, err := c.CreateSessionCreated(hs, hs.RouterInfo)
	if err != nil {
		return oops.Errorf("failed to create session created message: %v", err)
	}

	// 2. Set deadline for the connection
	if err := conn.SetDeadline(time.Now().Add(NTCP2_HANDSHAKE_TIMEOUT)); err != nil {
		return oops.Errorf("failed to set deadline: %v", err)
	}

	// 3. Obfuscate the ephemeral Y key
	obfuscatedY, err := c.ObfuscateEphemeral(sessionCreatedMessage.YContent[:])
	if err != nil {
		return oops.Errorf("failed to obfuscate ephemeral Y key: %v", err)
	}

	// 4. Encrypt options block using ChaCha20-Poly1305
	ciphertext, err := c.encryptSessionCreatedOptions(sessionCreatedMessage, obfuscatedY, hs)
	if err != nil {
		return err
	}

	// 5. Assemble the complete message
	message := append(obfuscatedY, ciphertext...)
	message = append(message, sessionCreatedMessage.Padding...)

	// 6. Write the message to the connection
	if _, err := conn.Write(message); err != nil {
		return oops.Errorf("failed to send session created message: %v", err)
	}

	log.Debugf("NTCP2: SessionCreated message sent successfully")
	return nil
}

// receiveSessionCreated processes Message 2 (SessionCreated) from remote
func (c *NTCP2Session) receiveSessionCreated(conn net.Conn, hs *handshake.HandshakeState) error {
	// Implement according to NTCP2 spec
	// uses CreateSessionCreated from session_created.go
	// see also: session_created.go, messages/session_created.go
	// TODO: Implement Message 2 processing
	return nil
}

// sendSessionConfirm sends Message 3 (SessionConfirm) to the remote peer
func (c *NTCP2Session) sendSessionConfirm(conn net.Conn, hs *handshake.HandshakeState) error {
	// Implement according to NTCP2 spec
	// uses CreateSessionConfirmed from session_confirm.go
	// see also: session_confirmed.go, messages/session_confirmed.go
	// TODO: Implement Message 3 processing
	return nil
}

// receiveSessionConfirm processes Message 3 (SessionConfirm) from remote
func (c *NTCP2Session) receiveSessionConfirm(conn net.Conn, hs *handshake.HandshakeState) error {
	// Implement according to NTCP2 spec
	// uses CreateSessionConfirmed from session_confirm.go
	// see also: session_confirmed.go, messages/session_confirmed.go
	// TODO: Implement Message 3 processing
	return nil
}
