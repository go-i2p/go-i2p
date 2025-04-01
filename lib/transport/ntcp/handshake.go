package ntcp

import (
	"crypto/rand"
	"net"
	"time"

	"github.com/go-i2p/go-i2p/lib/common/router_info"
	"github.com/go-i2p/go-i2p/lib/crypto/curve25519"
	"github.com/go-i2p/go-i2p/lib/crypto/types"
	"github.com/samber/oops"
)

// HandshakeState maintains the state for an in-progress handshake
type HandshakeState struct {
	// isInitiator indicates whether this side initiated the handshake
	isInitiator bool
	// localStaticKey is this router's long-term private key
	localStaticKey types.PrivateKey
	// remoteStaticKey is the remote router's long-term public key
	remoteStaticKey types.PublicKey
	// localEphemeral is the temporary private key generated for this handshake
	localEphemeral types.PrivateKey
	// remoteEphemeral is the temporary public key received from remote party
	remoteEphemeral types.PublicKey
	// localPaddingLen is the length of padding bytes we send
	localPaddingLen int
	// remotePaddingLen is the length of padding bytes we received
	remotePaddingLen int
	// chachaKey is the derived ChaCha20 symmetric key for the session
	chachaKey []byte
	// sharedSecret is the Diffie-Hellman shared secret computed during handshake
	sharedSecret []byte
	// timestamp is the Unix timestamp when handshake was initiated
	timestamp uint32
	// routerInfo contains the local router's information
	routerInfo *router_info.RouterInfo
}

// NewHandshakeState creates a new handshake state for initiating a connection
func NewHandshakeState(localKey types.PrivateKey, remoteKey types.PublicKey, ri *router_info.RouterInfo) (*HandshakeState, error) {
	hs := &HandshakeState{
		isInitiator:     true,
		localStaticKey:  localKey,
		remoteStaticKey: remoteKey,
		routerInfo:      ri,
		timestamp:       uint32(time.Now().Unix()),
	}

	// Generate ephemeral keypair
	var err error
	_, hs.localEphemeral, err = curve25519.GenerateKeyPair()
	//GenerateX25519KeyPair()
	if err != nil {
		return nil, oops.Errorf("failed to generate ephemeral key: %v", err)
	}

	// Calculate padding length (random 0-15 bytes)
	paddingBytes := make([]byte, 1)
	if _, err := rand.Read(paddingBytes); err != nil {
		return nil, oops.Errorf("failed to generate padding size: %v", err)
	}
	hs.localPaddingLen = int(paddingBytes[0] % 16)

	return hs, nil
}

// sendSessionRequest sends Message 1 (SessionRequest) to the remote peer
func (c *NTCP2Session) sendSessionRequest(conn net.Conn, hs *HandshakeState) error {
	// Implement according to NTCP2 spec
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
	return oops.Errorf("receiveSessionRequest is not yet implemented")
}

// receiveSessionRequest processes Message 1 (SessionRequest) from remote
func (c *NTCP2Session) receiveSessionRequest(conn net.Conn, hs *HandshakeState) error {
	// Implement according to NTCP2 spec
	// Reference: https://geti2p.net/spec/ntcp2

	// 1. Read the message off the connection
	// Placeholder: Read a fixed-size buffer to simulate message reading
	buffer := make([]byte, 1024)
	if _, err := conn.Read(buffer); err != nil {
		return oops.Errorf("failed to read session request: %v", err)
	}

	// 2. De-obfuscate the ephemeral key
	// Placeholder: Simulate de-obfuscation using a dummy function
	ephemeralKey := buffer[:32] // Assume the first 32 bytes are the ephemeral key
	if deobfuscatedEphemeral, err := c.DeobfuscateEphemeral(ephemeralKey); err != nil {
		return oops.Errorf("failed to de-obfuscate ephemeral key: %v", err)
	} else {
		// Update handshake state with received ephemeral key
		pubKey := curve25519.Curve25519PublicKey(deobfuscatedEphemeral)
		hs.remoteEphemeral = pubKey
	}

	// 3. Decrypt the options block
	// Placeholder: Simulate decryption using a dummy function
	//optionsBlock := buffer[32:64] // Assume the next 32 bytes are the options block
	//if err := c.DecryptOptionsBlock(optionsBlock, hs); err != nil {
	//return oops.Errorf("failed to decrypt options block: %v", err)
	//}

	// 4. Validate the padding
	// Placeholder: Simulate padding validation
	padding := buffer[64:] // Assume the rest is padding
	if len(padding) < hs.remotePaddingLen {
		return oops.Errorf("invalid padding length: expected %d, got %d", hs.remotePaddingLen, len(padding))
	}

	return nil
}

// sendSessionCreated sends Message 2 (SessionCreated) to the remote peer
func (c *NTCP2Session) sendSessionCreated(conn net.Conn, hs *HandshakeState) error {
	// Implement according to NTCP2 spec
	// uses CreateSessionCreated from session_created.go
	return nil
}

// receiveSessionCreated processes Message 2 (SessionCreated) from remote
func (c *NTCP2Session) receiveSessionCreated(conn net.Conn, hs *HandshakeState) error {
	// Implement according to NTCP2 spec
	// TODO: Implement Message 2 processing
	return nil
}

// sendSessionConfirm sends Message 3 (SessionConfirm) to the remote peer
func (c *NTCP2Session) sendSessionConfirm(conn net.Conn, hs *HandshakeState) error {
	// Implement according to NTCP2 spec
	// uses CreateSessionConfirmed from session_confirm.go
	return nil
}

// receiveSessionConfirm processes Message 3 (SessionConfirm) from remote
func (c *NTCP2Session) receiveSessionConfirm(conn net.Conn, hs *HandshakeState) error {
	// Implement according to NTCP2 spec
	// TODO: Implement Message 3 processing
	return nil
}

// deriveSessionKeys computes the session keys from the completed handshake
func (c *NTCP2Session) deriveSessionKeys(hs *HandshakeState) error {
	// Use shared secrets to derive session keys
	// TODO: Implement key derivation according to NTCP2 spec
	return nil
}
