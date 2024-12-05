package noise

import (
	"sync"

	"github.com/go-i2p/go-i2p/lib/common/router_info"
	"github.com/go-i2p/logger"

	"github.com/flynn/noise"
)

type HandshakeState struct {
	mutex             sync.Mutex
	ephemeral         *noise.DHKey
	pattern           noise.HandshakePattern
	handshakeComplete bool
	HandKey           noise.DHKey
	*noise.HandshakeState
}

func NewHandshakeState(staticKey noise.DHKey, isInitiator bool) (*HandshakeState, error) {
	hs := &HandshakeState{
		pattern: noise.HandshakeXK,
	}

	config := noise.Config{
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:       hs.pattern,
		Initiator:     isInitiator,
		StaticKeypair: staticKey,
	}

	protocol, err := noise.NewHandshakeState(config)
	if err != nil {
		return nil, err
	}

	hs.HandshakeState = protocol
	return hs, nil
}

// GenerateEphemeral creates the ephemeral keypair that will be used in handshake
// This needs to be separate so NTCP2 can obfuscate it
func (h *HandshakeState) GenerateEphemeral() (*noise.DHKey, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	dhKey, err := noise.DH25519.GenerateKeypair(nil)
	if err != nil {
		return nil, err
	}
	h.ephemeral = &dhKey
	return &dhKey, nil
}

// SetEphemeral allows setting a potentially modified ephemeral key
// This is needed for NTCP2's obfuscation layer
func (h *HandshakeState) SetEphemeral(key *noise.DHKey) error {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	h.ephemeral = key
	return nil
}

func (h *HandshakeState) WriteMessage(payload []byte) ([]byte, *noise.CipherState, *noise.CipherState, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	return h.HandshakeState.WriteMessage(nil, payload)
}

func (h *HandshakeState) ReadMessage(message []byte) ([]byte, *noise.CipherState, *noise.CipherState, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	return h.HandshakeState.ReadMessage(nil, message)
}

var log = logger.GetGoI2PLogger()

func (c *NoiseTransport) Handshake(routerInfo router_info.RouterInfo) error {
	log.WithField("router_info", routerInfo.IdentHash()).Debug("Starting Noise handshake")
	c.Mutex.Lock()
	defer c.Mutex.Unlock()
	session, err := c.getSession(routerInfo)
	if err != nil {
		log.WithError(err).Error("Failed to get session for handshake")
		return err
	}
	log.Debug("Session obtained for handshake")
	// Set handshakeCond to indicate that this goroutine is committing to
	// running the handshake.
	session.(*NoiseSession).Cond = sync.NewCond(&c.Mutex)
	c.Mutex.Unlock()
	session.(*NoiseSession).Mutex.Lock()
	defer session.(*NoiseSession).Mutex.Unlock()
	c.Mutex.Lock()
	log.Debug("Running outgoing handshake")
	if err := session.(*NoiseSession).RunOutgoingHandshake(); err != nil {
		return err
	}
	log.Debug("Outgoing handshake completed successfully")
	// Wake any other goroutines that are waiting for this handshake to
	// complete.
	session.(*NoiseSession).Cond.Broadcast()
	session.(*NoiseSession).Cond = nil
	log.Debug("Noise handshake completed successfully")
	return nil
}
