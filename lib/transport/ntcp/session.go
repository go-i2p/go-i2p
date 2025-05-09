package ntcp

import (
	"crypto"
	"crypto/hmac"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"

	"github.com/go-i2p/go-i2p/lib/common/router_info"
	"github.com/go-i2p/go-i2p/lib/crypto/aes"
	"github.com/go-i2p/go-i2p/lib/transport/noise"
	"github.com/go-i2p/go-i2p/lib/transport/ntcp/handshake"
	"github.com/go-i2p/go-i2p/lib/transport/ntcp/messages"
	"github.com/go-i2p/go-i2p/lib/transport/obfs"
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
	paddingStrategy padding.PaddingStrategy
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

func (s *NTCP2Session) deriveChacha20Key(ephemeralKey []byte) ([]byte, error) {
	remoteStaticKey, err := s.peerStaticKey()
	if err != nil {
		return nil, err
	}
	// Perform DH between Alice's ephemeral key and Bob's static key
	// This is the "es" operation in Noise XK
	sharedSecret, err := s.computeSharedSecret(ephemeralKey, remoteStaticKey[:])
	if err != nil {
		return nil, err
	}

	// Apply KDF to derive the key
	// This typically involves HKDF with appropriate info string
	hashProtocol := crypto.SHA256
	h := hmac.New(hashProtocol.New, []byte("NTCP2-KDF1"))
	h.Write(sharedSecret)
	return h.Sum(nil)[:32], nil // ChaCha20 requires a 32-byte key
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

func (c *NTCP2Session) encryptSessionRequestOptions(sessionRequestMessage *messages.SessionRequest, obfuscatedX []byte) ([]byte, error) {
	chacha20Key, err := c.deriveChacha20Key(sessionRequestMessage.XContent[:])
	if err != nil {
		return nil, oops.Errorf("failed to derive ChaCha20 key: %v", err)
	}

	// Create AEAD cipher
	aead, err := chacha20poly1305.New(chacha20Key)
	if err != nil {
		return nil, oops.Errorf("failed to create ChaCha20-Poly1305 cipher: %v", err)
	}

	// Prepare the nonce (all zeros for first message)
	nonce := make([]byte, chacha20poly1305.NonceSize)

	// Create associated data (AD) according to NTCP2 spec:
	// AD = obfuscated X value (ensures binding between the AES and ChaCha layers)
	ad := obfuscatedX

	// Encrypt options block and authenticate both options and padding
	// ChaCha20-Poly1305 encrypts plaintext and appends auth tag
	optionsData := sessionRequestMessage.Options.Data()
	ciphertext := aead.Seal(nil, nonce, optionsData, ad)
	return ciphertext, nil
}

// deriveSessionKeys computes the session keys from the completed handshake
func (c *NTCP2Session) deriveSessionKeys(hs *handshake.HandshakeState) error {
	// Use shared secrets to derive session keys
	// TODO: Implement key derivation according to NTCP2 spec
	return nil
}
