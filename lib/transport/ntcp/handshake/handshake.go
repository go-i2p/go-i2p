package handshake

import (
	"crypto/rand"
	"net"
	"time"

	"github.com/go-i2p/go-i2p/lib/common/router_info"
	"github.com/go-i2p/go-i2p/lib/crypto/curve25519"
	"github.com/go-i2p/go-i2p/lib/crypto/types"
	"github.com/go-i2p/go-i2p/lib/transport/ntcp/messages"
	"github.com/samber/oops"
)

// HandshakeState maintains the state for an in-progress handshake
type HandshakeState struct {
	// isInitiator indicates whether this side initiated the handshake
	IsInitiator bool
	// localStaticKey is this router's long-term private key
	LocalStaticKey types.PrivateKey
	// remoteStaticKey is the remote router's long-term public key
	RemoteStaticKey types.PublicKey
	// localEphemeral is the temporary private key generated for this handshake
	LocalEphemeral types.PrivateKey
	// remoteEphemeral is the temporary public key received from remote party
	RemoteEphemeral types.PublicKey
	// localPaddingLen is the length of padding bytes we send
	LocalPaddingLen int
	// remotePaddingLen is the length of padding bytes we received
	RemotePaddingLen int
	// chachaKey is the derived ChaCha20 symmetric key for the session
	ChachaKey []byte
	// sharedSecret is the Diffie-Hellman shared secret computed during handshake
	SharedSecret []byte
	// timestamp is the Unix timestamp when handshake was initiated
	Timestamp uint32
	// routerInfo contains the local router's information
	RouterInfo *router_info.RouterInfo
}

// NewHandshakeState creates a new handshake state for initiating a connection
func NewHandshakeState(localKey types.PrivateKey, remoteKey types.PublicKey, ri *router_info.RouterInfo) (*HandshakeState, error) {
	/*
	   NewHandshakeState creates and initializes a handshake state structure for NTCP2:
	   1. Initialize the state with local private key, remote public key, and router info
	   2. Set initiator flag to true (we're starting the connection)
	   3. Record current timestamp for handshake timing
	   4. Generate ephemeral Curve25519 keypair for this session
	   5. Generate random padding length (0-15 bytes) for message obfuscation
	   6. Return the initialized handshake state
	*/
	hs := &HandshakeState{
		IsInitiator:     true,
		LocalStaticKey:  localKey,
		RemoteStaticKey: remoteKey,
		RouterInfo:      ri,
		Timestamp:       uint32(time.Now().Unix()),
	}

	// Generate ephemeral keypair
	var err error
	_, hs.LocalEphemeral, err = curve25519.GenerateKeyPair()
	// GenerateX25519KeyPair()
	if err != nil {
		return nil, oops.Errorf("failed to generate ephemeral key: %v", err)
	}

	// Calculate padding length (random 0-15 bytes)
	paddingBytes := make([]byte, 1)
	if _, err := rand.Read(paddingBytes); err != nil {
		return nil, oops.Errorf("failed to generate padding size: %v", err)
	}
	hs.LocalPaddingLen = int(paddingBytes[0] % 16)

	return hs, nil
}

type HandshakeMessageProcessor interface {
	CreateMessage(hs *HandshakeState) (messages.Message, error)
	ReadMessage(conn net.Conn, hs *HandshakeState) (messages.Message, error)
	ProcessMessage(message messages.Message, hs *HandshakeState) error
	ObfuscateKey(msg messages.Message, hs *HandshakeState) ([]byte, error)
	EncryptPayload(msg messages.Message, obfuscatedKey []byte, hs *HandshakeState) ([]byte, error)
	GetPadding(msg messages.Message) []byte
	MessageType() messages.MessageType
}
