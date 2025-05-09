package ntcp

import (
	"net"
	"time"

	"github.com/go-i2p/go-i2p/lib/transport/ntcp/handshake"
	"github.com/samber/oops"
)

func (c *NTCP2Session) sendHandshakeMessage(conn net.Conn, hs *handshake.HandshakeState, processor handshake.HandshakeMessageProcessor) error {
	// 1. Create message
	message, err := processor.CreateMessage(hs)
	if err != nil {
		return oops.Errorf("failed to create message: %w", err)
	}

	// 2. Set deadline
	if err := conn.SetDeadline(time.Now().Add(NTCP2_HANDSHAKE_TIMEOUT)); err != nil {
		return oops.Errorf("failed to set deadline: %w", err)
	}

	// 3. Obfuscate key
	obfuscatedKey, err := processor.ObfuscateKey(message, hs)
	if err != nil {
		return oops.Errorf("failed to obfuscate key: %w", err)
	}

	// 4. Encrypt options
	ciphertext, err := processor.EncryptPayload(message, obfuscatedKey, hs)
	if err != nil {
		return oops.Errorf("failed to encrypt options: %w", err)
	}

	// 5. Assemble message
	fullMessage := append(obfuscatedKey, ciphertext...)
	fullMessage = append(fullMessage, processor.GetPadding(message)...)

	// 6. Write message
	if _, err := conn.Write(fullMessage); err != nil {
		return oops.Errorf("failed to send message: %w", err)
	}

	return nil
}

// receiveAndProcessHandshakeMessage receives and processes a handshake message using the specified processor
func (s *NTCP2Session) receiveAndProcessHandshakeMessage(
	conn net.Conn,
	hs *handshake.HandshakeState,
	processor handshake.HandshakeMessageProcessor,
) error {
	// 1. Set deadline
	if err := conn.SetDeadline(time.Now().Add(NTCP2_HANDSHAKE_TIMEOUT)); err != nil {
		return oops.Errorf("failed to set deadline: %w", err)
	}

	// 2. Read the message
	message, err := processor.ReadMessage(conn, hs)
	if err != nil {
		return oops.Errorf("failed to read message: %w", err)
	}

	// 3. Process the message
	if err := processor.ProcessMessage(message, hs); err != nil {
		return oops.Errorf("failed to process message: %w", err)
	}

	return nil
}
