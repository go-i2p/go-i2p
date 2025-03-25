package ntcp

import (
	"github.com/go-i2p/go-i2p/lib/common/router_info"
	"github.com/go-i2p/go-i2p/lib/crypto"
	"github.com/go-i2p/go-i2p/lib/transport/noise"
	"github.com/go-i2p/go-i2p/lib/transport/obfs"
	"github.com/go-i2p/go-i2p/lib/transport/padding"

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
	paddingStrategy padding.PaddingStrategy
}

// NewNTCP2Session creates a new NTCP2 session using the existing noise implementation
func NewNTCP2Session(noiseConfig router_info.RouterInfo) (*NTCP2Session, error) {
	baseNoiseSession, err := noise.NewNoiseTransportSession(noiseConfig)
	if err != nil {
		return nil, err
	}

	return &NTCP2Session{
		NoiseSession:    baseNoiseSession.(*noise.NoiseSession),
		paddingStrategy: &padding.NullPaddingStrategy{},
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

// ObfuscateEphemeral implements NTCP2's key obfuscation using AES-256-CBC
func (s *NTCP2Session) ObfuscateEphemeral(ephemeralKey []byte) ([]byte, error) {
	AESStaticKey, err := s.buildAesStaticKey()
	if err != nil {
		return nil, err
	}

	return obfs.ObfuscateEphemeralKey(ephemeralKey, AESStaticKey)
}

// DeobfuscateEphemeral reverses the key obfuscation
func (s *NTCP2Session) DeobfuscateEphemeral(obfuscatedEphemeralKey []byte) ([]byte, error) {
	AESStaticKey, err := s.buildAesStaticKey()
	if err != nil {
		return nil, err
	}

	return obfs.DeobfuscateEphemeralKey(obfuscatedEphemeralKey, AESStaticKey)
}

func (s *NTCP2Session) buildAesStaticKey() (*crypto.AESSymmetricKey, error) {
	staticKey, err := s.peerStaticKey()
	if err != nil {
		return nil, err
	}
	staticIV, err := s.peerStaticIV()
	if err != nil {
		return nil, err
	}
	var AESStaticKey crypto.AESSymmetricKey
	AESStaticKey.Key = staticKey[:]
	AESStaticKey.IV = staticIV[:]
	return &AESStaticKey, nil
}
