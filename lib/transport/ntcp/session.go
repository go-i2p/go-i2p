package ntcp

import (
	"golang.org/x/crypto/curve25519"

	"github.com/go-i2p/go-i2p/lib/common/router_info"
	"github.com/go-i2p/go-i2p/lib/crypto/aes"
	"github.com/go-i2p/go-i2p/lib/transport/noise"
	"github.com/go-i2p/go-i2p/lib/transport/ntcp/handshake"
	"github.com/go-i2p/go-i2p/lib/transport/ntcp/kdf"
	"github.com/go-i2p/go-i2p/lib/transport/ntcp/messages"
	"github.com/go-i2p/go-i2p/lib/transport/padding"
	"github.com/go-i2p/go-i2p/lib/util/time/sntp"

	"github.com/samber/oops"
)

/*
	Summary of what needs to be done:
	NTCP and SSU2 are both transport protocols based on noise, with additional features designed to prevent p2p traffic from being blocked by firewalls.
	These modifications affect how the Noise handshake takes place, in particular:
	 - Ephemeral keys are transmitted **obfuscated** by encrypting them with the peer's known static public key.
	these modifications are simple enough, but for our purposes we also want to be able to re-use as much code as possible.
	So, what we need to do is devise a means of adding these modifications to the existing NoiseSession implementation.
	We could do this in any number of ways, we could:
	 1. Implement a custom struct that embeds a NoiseSession and overrides the Compose*HandshakeMessage functions
	 2. Modify the NoiseSession handshake functions to allow passing an obfuscation and/or padding function as a parameter
	 3. Modify the NoiseSession implementation to allow replacing the Compose*HandshakeMessage functions with custom ones
	 4. Refactor the NoiseSession implementation to break Compose*HandshakeMessage out into a separate interface, and implement that interface in a custom struct
	Ideally, we're already set up to do #1, but we'll see how it goes.
	Now is the right time to make changes if we need to, go-i2p is the only consumer of go-i2p right now, we can make our lives as easy as we want to.
*/

// NTCP2Session extends the base noise.NoiseSession with NTCP2-specific functionality
type NTCP2Session struct {
	*noise.NoiseSession
	*NTCP2Transport
	// Session keys for encrypted communication
	inboundKey  []byte // Key for decrypting incoming messages
	outboundKey []byte // Key for encrypting outgoing messages
	// Keys for length obfuscation using SipHash
	lengthEncryptKey1 []byte // First SipHash key (k1)
	lengthEncryptKey2 []byte // Second SipHash key (k2)
	// Key for frame obfuscation in data phase
	framingKey      []byte
	paddingStrategy padding.PaddingStrategy
	// Processors for handling handshake messages
	Processors map[messages.MessageType]handshake.HandshakeMessageProcessor
}

// NewNTCP2Session creates a new NTCP2 session using the existing noise implementation
func NewNTCP2Session(routerInfo router_info.RouterInfo) (*NTCP2Session, error) {
	// Create base noise session
	baseNoiseSession, err := noise.NewNoiseTransportSession(routerInfo)
	if err != nil {
		return nil, oops.Errorf("failed to create base noise session: %w", err)
	}

	// We need a router timestamper for the NTCP2 transport
	defaultClient := &sntp.DefaultNTPClient{}
	timestamper := sntp.NewRouterTimestamper(defaultClient)

	// Create the NTCP2Transport component
	ntcpTransport := &NTCP2Transport{
		NoiseTransport: &noise.NoiseTransport{
			RouterInfo: routerInfo,
		},
		RouterTimestamper: timestamper,
		transportStyle:    NTCP_PROTOCOL_NAME,
	}

	// Create and return the session with all components initialized
	return &NTCP2Session{
		NoiseSession:    baseNoiseSession.(*noise.NoiseSession),
		NTCP2Transport:  ntcpTransport,
		paddingStrategy: &padding.NullPaddingStrategy{}, // Default to no padding for simplicity
	}, nil
}

// PeerStaticKey is equal to the NTCP2 peer's static public key, found in their router info
func (s *NTCP2Session) peerStaticKey() ([32]byte, error) {
	for _, addr := range s.RouterInfo.RouterAddresses() {
		transportStyle, err := addr.TransportStyle().Data()
		if err != nil {
			continue
		}
		if transportStyle == NTCP_PROTOCOL_NAME {
			return addr.StaticKey()
		}
	}
	return [32]byte{}, oops.Errorf("Remote static key error")
}

func (s *NTCP2Session) peerStaticIV() ([16]byte, error) {
	for _, addr := range s.RouterInfo.RouterAddresses() {
		transportStyle, err := addr.TransportStyle().Data()
		if err != nil {
			continue
		}
		if transportStyle == NTCP_PROTOCOL_NAME {
			return addr.InitializationVector()
		}
	}
	return [16]byte{}, oops.Errorf("Remote static IV error")
}

func (s *NTCP2Session) buildAesStaticKey() (*aes.AESSymmetricKey, error) {
	staticKey, err := s.peerStaticKey()
	if err != nil {
		return nil, err
	}
	staticIV, err := s.peerStaticIV()
	if err != nil {
		return nil, err
	}
	var AESStaticKey aes.AESSymmetricKey
	AESStaticKey.Key = staticKey[:]
	AESStaticKey.IV = staticIV[:]
	return &AESStaticKey, nil
}

func (c *NTCP2Session) computeSharedSecret(ephemeralKey, param []byte) ([]byte, error) {
	if len(ephemeralKey) != 32 || len(param) != 32 {
		return nil, oops.Errorf("invalid key length, expected 32 bytes")
	}

	// Convert byte slices to X25519 keys
	var ephKey, staticKey [32]byte
	copy(ephKey[:], ephemeralKey)
	copy(staticKey[:], param)
	// Compute the shared secret using X25519
	var sharedSecret [32]byte
	shared, err := curve25519.X25519(ephKey[:], staticKey[:])
	if err != nil {
		return nil, err
	}
	copy(sharedSecret[:], shared)

	return sharedSecret[:], nil
}

// deriveSessionKeys computes the session keys from the completed handshake
func (c *NTCP2Session) deriveSessionKeys(hs *handshake.HandshakeState) error {
	// Create KDF context if not already present
	kdfContext := kdf.NewNTCP2KDF()

	// If we have a handshake hash from the handshake state, use it
	if len(hs.HandshakeHash) > 0 {
		kdfContext.HandshakeHash = hs.HandshakeHash
	}

	// If we have a chaining key from the handshake state, use it
	if len(hs.ChachaKey) > 0 {
		kdfContext.ChainingKey = hs.ChachaKey
	}

	// Derive the final session keys for bidirectional communication
	keyAB, keyBA, err := kdfContext.DeriveKeys()
	if err != nil {
		return oops.Errorf("failed to derive session keys: %w", err)
	}

	// Set the session keys based on whether we're the initiator or responder
	if hs.IsInitiator {
		// For initiator (Alice), outbound = Alice->Bob, inbound = Bob->Alice
		c.outboundKey = keyAB
		c.inboundKey = keyBA
	} else {
		// For responder (Bob), outbound = Bob->Alice, inbound = Alice->Bob
		c.outboundKey = keyBA
		c.inboundKey = keyAB
	}

	// Derive SipHash keys for length obfuscation
	sipHashKey, err := kdfContext.DeriveSipHashKey()
	if err != nil {
		return oops.Errorf("failed to derive SipHash keys: %w", err)
	}

	// SipHash requires two 8-byte keys (k1, k2) and an 8-byte IV
	// The sipHashKey is 16 bytes - first 8 bytes are k1, next 8 bytes are k2
	if len(sipHashKey) < 16 {
		return oops.Errorf("derived SipHash key too short: %d bytes", len(sipHashKey))
	}

	// Set up length obfuscation
	c.lengthEncryptKey1 = sipHashKey[:8]
	c.lengthEncryptKey2 = sipHashKey[8:16]

	// Derive framing key for data phase
	framingKey, err := kdfContext.DeriveFramingKey()
	if err != nil {
		return oops.Errorf("failed to derive framing key: %w", err)
	}
	c.framingKey = framingKey

	// Clear sensitive key material from the KDF context
	// to prevent leaking it in memory
	for i := range kdfContext.ChainingKey {
		kdfContext.ChainingKey[i] = 0
	}

	// For additional security, also clear the handshake state keys
	// that are no longer needed
	for i := range hs.ChachaKey {
		hs.ChachaKey[i] = 0
	}
	hs.ChachaKey = nil

	log.Debugf("NTCP2: Session keys derived successfully")
	return nil
}
