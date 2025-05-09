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
	ciphertext, err := processor.EncryptOptions(message, obfuscatedKey, hs)
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

// sendSessionRequest sends Message 1 (SessionRequest) to the remote peer
func (c *NTCP2Session) sendSessionRequest(conn net.Conn, hs *handshake.HandshakeState) error {
	/*
		sendSessionRequest implements NTCP2 Message 1 (SessionRequest):
		1. Create session request message with options block (version, padding length, etc.)
		2. Set timeout deadline for the connection
		3. Obfuscate ephemeral key (X) using AES with Bob's router hash as key
		4. Encrypt options block using ChaCha20-Poly1305
		5. Assemble final message: obfuscated X + encrypted options + padding
		6. Write complete message to connection
	*/
	log.Debugf("NTCP2: Sending SessionRequest message")
	// 1. Create and send X (ephemeral key) | Padding
	// uses CreateSessionRequest from session_request.go
	sessionRequestMessage, err := c.CreateSessionRequest()
	if err != nil {
		return oops.Errorf("failed to create session request: %v", err)
	}
	// 2. Set deadline for the connection
	if err := conn.SetDeadline(time.Now().Add(NTCP2_HANDSHAKE_TIMEOUT)); err != nil {
		return oops.Errorf("failed to set deadline: %v", err)
	}
	// 3. Obfuscate the session request message
	obfuscatedX, err := c.ObfuscateEphemeral(sessionRequestMessage.XContent[:])
	if err != nil {
		return oops.Errorf("failed to obfuscate ephemeral key: %v", err)
	}
	// 4. ChaChaPoly Frame
	// Encrypt options block and authenticate both options and padding
	ciphertext, err := c.encryptSessionRequestOptions(sessionRequestMessage, obfuscatedX)
	if err != nil {
		return err
	}

	// Combine all components into final message
	// 1. Obfuscated X (already in obfuscatedX)
	// 2. ChaCha20-Poly1305 encrypted options with auth tag
	// 3. Authenticated but unencrypted padding
	message := append(obfuscatedX, ciphertext...)
	message = append(message, sessionRequestMessage.Padding...)

	// 5. Write the message to the connection
	if _, err := conn.Write(message); err != nil {
		return oops.Errorf("failed to send session request: %v", err)
	}
	return nil
}

// receiveSessionRequest processes Message 1 (SessionRequest) from remote
func (c *NTCP2Session) receiveSessionRequest(conn net.Conn, hs *handshake.HandshakeState) error {
	/*
		receiveSessionRequest processes incoming NTCP2 Message 1 (SessionRequest):
		1. Read and buffer the fixed-length ephemeral key portion (X)
		2. Deobfuscate X using AES with local router hash as key
		3. Validate the ephemeral key (X) is a valid Curve25519 point
		4. Read the ChaCha20-Poly1305 encrypted options block
		5. Derive KDF for handshake message 1 using X and local static key
		6. Decrypt and authenticate the options block
		7. Extract and validate handshake parameters (timestamp, version, padding length)
		8. Read and validate any padding bytes
		9. Check timestamp for acceptable clock skew (±60 seconds?)
	*/
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
	/*
		sendSessionCreated implements NTCP2 Message 2 (SessionCreated):
		1. Generate ephemeral Y keypair for responder side
		2. Calculate current timestamp for clock skew verification
		3. Create options block (timestamp, padding length, etc.)
		4. Obfuscate Y using AES with same key as message 1
		5. Derive KDF for handshake message 2 using established state
		6. Encrypt options block using ChaCha20-Poly1305
		7. Generate random padding according to negotiated parameters
		8. Assemble final message: obfuscated Y + encrypted options + padding
		9. Write complete message to connection
	*/
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
	/*
		receiveSessionCreated processes incoming NTCP2 Message 2 (SessionCreated):
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
	// Implement according to NTCP2 spec
	// uses CreateSessionCreated from session_created.go
	// see also: session_created.go, messages/session_created.go
	// TODO: Implement Message 2 processing
	return nil
}

// sendSessionConfirm sends Message 3 (SessionConfirm) to the remote peer
func (c *NTCP2Session) sendSessionConfirm(conn net.Conn, hs *handshake.HandshakeState) error {
	/*
		sendSessionConfirm implements NTCP2 Message 3 (SessionConfirmed):
		1. Create two separate ChaChaPoly frames for this message
		2. For first frame:
		   a. Extract local static key (s)
		   b. Derive KDF for handshake message 3 part 1
		   c. Encrypt static key using ChaCha20-Poly1305
		3. For second frame:
		   a. Prepare payload with local RouterInfo, options, and padding
		   b. Derive KDF for handshake message 3 part 2 using se pattern
		   c. Encrypt payload using ChaCha20-Poly1305
		4. Assemble final message: encrypted static key frame + encrypted payload frame
		5. Write complete message to connection
		6. Derive final data phase keys (k_ab, k_ba) using Split() operation
		7. Initialize SipHash keys for data phase length obfuscation
	*/
	// Implement according to NTCP2 spec
	// uses CreateSessionConfirmed from session_confirm.go
	// see also: session_confirmed.go, messages/session_confirmed.go
	// TODO: Implement Message 3 processing
	return nil
}

// receiveSessionConfirm processes Message 3 (SessionConfirm) from remote
func (c *NTCP2Session) receiveSessionConfirm(conn net.Conn, hs *handshake.HandshakeState) error {
	/*
		receiveSessionConfirm processes incoming NTCP2 Message 3 (SessionConfirmed):
		1. Read first ChaChaPoly frame containing encrypted static key
		2. Derive KDF for handshake message 3 part 1
		3. Decrypt and authenticate static key frame
		4. Validate decrypted static key is a valid Curve25519 point
		5. Read second ChaChaPoly frame with size specified in message 1
		6. Derive KDF for handshake message 3 part 2 using se pattern
		7. Decrypt and authenticate second frame
		8. Extract RouterInfo from decrypted payload
		9. Validate RouterInfo matches expected router identity
		10. Process any options included in the payload
		11. Derive final data phase keys (k_ab, k_ba) using Split() operation
		12. Initialize SipHash keys for data phase length obfuscation
		13. Mark handshake as complete
	*/
	// Implement according to NTCP2 spec
	// uses CreateSessionConfirmed from session_confirm.go
	// see also: session_confirmed.go, messages/session_confirmed.go
	// TODO: Implement Message 3 processing
	return nil
}
