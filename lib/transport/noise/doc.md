
# noise

## Overview

The `noise` package implements the Noise Protocol to establish secure, authenticated sessions over TCP. This package includes functions for session management, handshake initiation, packet encryption, decryption, and transport abstraction.


- [handshake.go](#handshakego)
- [i2np.go](#i2npgo)
- [incoming_handshake.go](#incoming_handshakego)
- [outgoing_handshake.go](#outgoing_handshakego)
- [noise_constants.go](#noise_constantsgo)
- [read_session.go](#read_sessiongo)
- [session.go](#sessiongo)
- [transport.go](#transportgo)
- [write_session.go](#write_sessiongo)

---

## handshake.go

Defines the `Handshake` function, which initiates the Noise handshake process for secure, authenticated sessions.

### Package

```go
package noise
```

### Imports

```go
import (
    "sync"
    "github.com/go-i2p/go-i2p/lib/util/logger"
    "github.com/go-i2p/go-i2p/lib/common/router_info"
)
```

### Variables

- **`log`**: Logger instance for capturing debug and error messages related to the handshake process.

### Function: `Handshake`

#### Definition

```go
func (c *NoiseTransport) Handshake(routerInfo router_info.RouterInfo) error
```

#### Parameters
- `routerInfo`: Information about the router with which the handshake is established.

#### Returns
- `error`: Returns `nil` on success, or an error if the handshake fails.

#### Description
The `Handshake` function initiates an authenticated handshake with a router, establishing a secure session.

#### Workflow
1. **Logging Start**: Logs initiation of the handshake.
2. **Lock Mutex**: Locks `c.Mutex` to prevent concurrent access.
3. **Session Retrieval**: Calls `c.getSession(routerInfo)`.
4. **Condition Variable Setup**: Sets a `Cond` for the session.
5. **Outgoing Handshake**: Executes `RunOutgoingHandshake`.
6. **Completion Broadcast**: Broadcasts to waiting goroutines.
7. **Finalize and Unlock**: Logs success.

---

## i2np.go

Provides functions to queue and send I2NP messages using a `NoiseSession`.

### Package

```go
package noise
```

### Imports

```go
import "github.com/go-i2p/go-i2p/lib/i2np"
```

### Functions

#### `QueueSendI2NP`

Queues an I2NP message for sending.

```go
func (s *NoiseSession) QueueSendI2NP(msg i2np.I2NPMessage)
```

#### Parameters
- `msg`: The I2NP message.

---

#### `SendQueueSize`

Returns the size of the send queue.

```go
func (s *NoiseSession) SendQueueSize() int
```

---

#### `ReadNextI2NP`

Attempts to read the next I2NP message from the queue.

```go
func (s *NoiseSession) ReadNextI2NP() (i2np.I2NPMessage, error)
```

---

## incoming_handshake.go

Defines functions for the incoming (receiver) side of the handshake.

### Functions

#### `ComposeReceiverHandshakeMessage`

Creates a receiver handshake message using Noise patterns.

```go
func ComposeReceiverHandshakeMessage(s noise.DHKey, rs []byte, payload []byte, ePrivate []byte) (negData, msg []byte, state *noise.HandshakeState, err error)
```

- **`s`**: Static Diffie-Hellman key.
- **`rs`**: Remote static key.
- **`payload`**: Optional payload data.
- **`ePrivate`**: Private ephemeral key.

---

#### `RunIncomingHandshake`

Executes an incoming handshake process.

```go
func (c *NoiseSession) RunIncomingHandshake() error
```

- Initializes and sends the negotiation data and handshake message.

---

## outgoing_handshake.go

Defines functions for the outgoing (initiator) side of the handshake.

### Functions

#### `ComposeInitiatorHandshakeMessage`

Creates an initiator handshake message.

```go
func ComposeInitiatorHandshakeMessage(s noise.DHKey, rs []byte, payload []byte, ePrivate []byte) (negData, msg []byte, state *noise.HandshakeState, err error)
```

---

#### `RunOutgoingHandshake`

Executes the outgoing handshake process.

```go
func (c *NoiseSession) RunOutgoingHandshake() error
```

- Sends negotiation data and handshake message.

---

## noise_constants.go

Defines constants and utility functions for configuring Noise protocol parameters.

### Constants

```go
const (
    NOISE_DH_CURVE25519 = 1
    NOISE_CIPHER_CHACHAPOLY = 1
    NOISE_HASH_SHA256 = 3
    NOISE_PATTERN_XK = 11
    uint16Size = 2
    MaxPayloadSize = 65537
)
```

### Functions

#### `initNegotiationData`

Initializes negotiation data with default values.

```go
func initNegotiationData(negotiationData []byte) []byte
```

---

## read_session.go

Functions related to reading encrypted data in a Noise session.

### Functions

#### `Read`

Reads from the Noise session.

```go
func (c *NoiseSession) Read(b []byte) (int, error)
```

#### `decryptPacket`

Decrypts a packet.

```go
func (c *NoiseSession) decryptPacket(data []byte) (int, []byte, error)
```

---

## session.go

Defines the `NoiseSession` struct and associated methods for session management.

### Struct: `NoiseSession`

Defines session properties.

```go
type NoiseSession struct {
    // Session properties here
}
```

---

## transport.go

Defines the `NoiseTransport` struct and its methods for session compatibility, accepting connections, etc.

### Struct: `NoiseTransport`

```go
type NoiseTransport struct {
    sync.Mutex
    router_identity.RouterIdentity
    *noise.CipherState
    Listener        net.Listener
    peerConnections map[data.Hash]transport.TransportSession
}
```

#### Methods

- `Compatible`: Checks compatibility.
- `Accept`: Accepts a connection.
- `Addr`: Returns the address.
- `SetIdentity`: Sets the router identity.
- `GetSession`: Obtains a session.

---

## write_session.go

Functions for writing encrypted data in a Noise session.

### Functions

#### `Write`

Writes data in a Noise session.

```go
func (c *NoiseSession) Write(b []byte) (int, error)
```

#### `encryptPacket`

Encrypts a packet.

```go
func (c *NoiseSession) encryptPacket(data []byte) (int, []byte, error)
```