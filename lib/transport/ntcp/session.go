package ntcp

import (
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/transport"
	"github.com/go-i2p/go-i2p/lib/transport/noise"
)

// Session implements TransportSession
// An established transport session
type Session struct {
	*noise.NoiseSession
}

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

var exampleNTCPSession transport.TransportSession = &Session{}

// Close implements transport.TransportSession.
func (s *Session) Close() error {
	panic("unimplemented")
}

// QueueSendI2NP implements transport.TransportSession.
func (s *Session) QueueSendI2NP(msg i2np.I2NPMessage) {
	panic("unimplemented")
}

// ReadNextI2NP implements transport.TransportSession.
func (s *Session) ReadNextI2NP() (i2np.I2NPMessage, error) {
	panic("unimplemented")
}

// SendQueueSize implements transport.TransportSession.
func (s *Session) SendQueueSize() int {
	panic("unimplemented")
}

