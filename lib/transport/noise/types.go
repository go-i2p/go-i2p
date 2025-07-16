package noise

import (
	"net"

	"github.com/go-i2p/go-i2p/lib/transport"
)

// VerifyCallbackFunc defines a function type for verifying public keys and data
// Moved from: session.go
type VerifyCallbackFunc func(publicKey []byte, data []byte) error

// Example variables for interface compliance testing
// Moved from: transport.go, session.go
var (
	exampleNoiseTransport transport.Transport        = &NoiseTransport{}
	exampleNoiseSession   transport.TransportSession = &NoiseSession{}
)

// ExampleNoiseListener is not a real Noise Listener, do not use it.
// It is exported so that it can be confirmed that the transport
// implements net.Listener
// Moved from: transport.go
var ExampleNoiseListener net.Listener = exampleNoiseTransport

// ExampleNoiseSession is exported for interface compliance testing
// Moved from: session.go
var ExampleNoiseSession net.Conn = exampleNoiseSession.(*NoiseSession)
