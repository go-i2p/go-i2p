package ntcp

import (
	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/crypto/aes"
	"github.com/go-i2p/go-i2p/lib/transport/noise"
	"github.com/go-i2p/go-i2p/lib/transport/ntcp/handshake"
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

// findNTCP2Address finds the first NTCP2 address in router info
func (s *NTCP2Session) findNTCP2Address() (*router_address.RouterAddress, error) {
	for _, addr := range s.RouterInfo.RouterAddresses() {
		transportStyle, err := addr.TransportStyle().Data()
		if err != nil {
			continue
		}
		if transportStyle == NTCP_PROTOCOL_NAME {
			return addr, nil
		}
	}
	return nil, oops.Errorf("no NTCP2 address found")
}

// peerStaticKey is equal to the NTCP2 peer's static public key, found in their router info
func (s *NTCP2Session) peerStaticKey() ([32]byte, error) {
	addr, err := s.findNTCP2Address()
	if err != nil {
		return [32]byte{}, err
	}
	return addr.StaticKey()
}

func (s *NTCP2Session) peerStaticIV() ([16]byte, error) {
	addr, err := s.findNTCP2Address()
	if err != nil {
		return [16]byte{}, err
	}
	return addr.InitializationVector()
}

func (s *NTCP2Session) buildAesStaticKey() (*aes.AESSymmetricKey, error) {
	addr, err := s.findNTCP2Address()
	if err != nil {
		return nil, err
	}

	staticKey, err := addr.StaticKey()
	if err != nil {
		return nil, err
	}

	staticIV, err := addr.InitializationVector()
	if err != nil {
		return nil, err
	}

	return &aes.AESSymmetricKey{
		Key: staticKey[:],
		IV:  staticIV[:],
	}, nil
}
