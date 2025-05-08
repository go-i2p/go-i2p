package ntcp

import (
	"crypto/rand"
	"net"
	"time"

	"github.com/go-i2p/go-i2p/lib/common/router_info"
	"github.com/go-i2p/go-i2p/lib/crypto/curve25519"
	"github.com/go-i2p/go-i2p/lib/crypto/types"
	"github.com/samber/oops"
	"golang.org/x/crypto/chacha20poly1305"
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
	// GenerateX25519KeyPair()
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

// DecryptOptionsBlock decrypts the options block from a SessionRequest message
func (c *NTCP2Session) DecryptOptionsBlock(encryptedOptions []byte, obfuscatedX []byte, deobfuscatedX []byte) ([]byte, error) {
	// 1. Derive the ChaCha20-Poly1305 key using the deobfuscated ephemeral key
	chacha20Key, err := c.deriveChacha20Key(deobfuscatedX)
	if err != nil {
		return nil, oops.Errorf("failed to derive ChaCha20 key: %w", err)
	}

	// 2. Create the AEAD cipher for decryption
	aead, err := chacha20poly1305.New(chacha20Key)
	if err != nil {
		return nil, oops.Errorf("failed to create AEAD cipher: %w", err)
	}

	// 3. Nonce for Message 1 is all zeros
	nonce := make([]byte, 12)

	// 4. Decrypt the options data
	// The associated data is the obfuscated ephemeral key
	decryptedOptions, err := aead.Open(nil, nonce, encryptedOptions, obfuscatedX)
	if err != nil {
		return nil, oops.Errorf("failed to decrypt options block: %w", err)
	}

	return decryptedOptions, nil
}
