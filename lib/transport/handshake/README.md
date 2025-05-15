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

	SetEphemeralTransformer(transformer KeyTransformer)
	GetHandshakeHash() []byte
	SetPrologue(prologue []byte) error
	MixHash(data []byte) error
	MixKey(input []byte) ([]byte, error)
}
```

HandshakeState manages the Noise handshake state

#### type KeyTransformer

```go
type KeyTransformer interface {
	ObfuscateKey(publicKey []byte) ([]byte, error)
	DeobfuscateKey(obfuscatedKey []byte) ([]byte, error)
}
```

KeyTransformer defines operations for transforming keys during handshake

#### type NoOpTransformer

```go
type NoOpTransformer struct{}
```

NoOpTransformer is a default implementation that doesn't transform keys

#### func (*NoOpTransformer) DeobfuscateKey

```go
func (t *NoOpTransformer) DeobfuscateKey(obfuscatedKey []byte) ([]byte, error)
```

#### func (*NoOpTransformer) ObfuscateKey

```go
func (t *NoOpTransformer) ObfuscateKey(publicKey []byte) ([]byte, error)
```



handshake 

github.com/go-i2p/go-i2p/lib/transport/handshake

[go-i2p template file](/template.md)
