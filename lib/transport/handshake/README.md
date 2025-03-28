# handshake
--
    import "github.com/go-i2p/go-i2p/lib/transport/handshake"

![handshake.svg](handshake.svg)



## Usage

#### type HandshakeState

```go
type HandshakeState interface {
	// GenerateEphemeral creates ephemeral keypair
	GenerateEphemeral() (*noise.DHKey, error)

	// WriteMessage creates Noise message
	WriteMessage([]byte) ([]byte, *noise.CipherState, *noise.CipherState, error)

	// HandshakeComplete returns true if handshake is complete
	HandshakeComplete() bool

	// CompleteHandshake completes the handshake
	CompleteHandshake() error
}
```

HandshakeState manages the Noise handshake state



handshake 

github.com/go-i2p/go-i2p/lib/transport/handshake
