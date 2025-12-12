# transport
--
    import "github.com/go-i2p/go-i2p/lib/transport"

![transport.svg](transport.svg)

Package transport implements I2P transport layer protocols for router-to-router
communication.

# Overview

The transport layer handles encrypted, authenticated connections between I2P
routers. Supported transports:

    - NTCP2: TCP-based transport with Noise protocol encryption
    - SSU2: UDP-based transport (planned)

# Transport Manager

The TransportManager coordinates all transports:

    - Maintains connection pool
    - Routes I2NP messages to appropriate transports
    - Handles connection lifecycle
    - Monitors transport health

# NTCP2 Transport

NTCP2 uses Noise_XK_25519_ChaChaPoly_SHA256:

    - X25519 key exchange
    - ChaCha20-Poly1305 AEAD encryption
    - Session state management
    - I2NP message framing

See lib/transport/ntcp2 for implementation details.

# Thread Safety

TransportManager is safe for concurrent access:

    - Connection map protected by mutex
    - Each transport manages its own connections
    - Message sending is thread-safe

# Usage Example

    // Create transport manager
    tm := transport.NewTransportManager(ourRouterInfo, netdb)

    // Register NTCP2 transport
    ntcp2 := ntcp2.NewTransport(config)
    tm.RegisterTransport(ntcp2)

    // Send message to peer
    peerHash, err := peerRouterInfo.IdentHash()
    if err != nil {
        log.Printf("Failed to get peer hash: %v", err)
        return
    }
    if err := tm.SendMessage(peerHash, i2npMsg); err != nil {
        log.Printf("Failed to send message: %v", err)
    }

    // Stop all transports
    tm.Shutdown()

# Connection Management

Connections are automatically managed:

    - Idle connections closed after timeout
    - Failed connections retried with backoff
    - Connection limits enforced per transport

## Usage

```go
var ErrNoTransportAvailable = oops.Errorf("no transports available")
```
error for when we have no transports available to use

#### type Transport

```go
type Transport interface {
	// Accept accepts an incoming session.
	Accept() (net.Conn, error)

	// Addr returns an
	Addr() net.Addr

	// Set the router identity for this transport.
	// will bind if the underlying socket is not already
	// if the underlying socket is already bound update the RouterIdentity
	// returns any errors that happen if they do
	SetIdentity(ident router_info.RouterInfo) error

	// Obtain a transport session with a router given its RouterInfo.
	// If a session with this router is NOT already made attempt to create one and block until made or until an error happens
	// returns an established TransportSession and nil on success
	// returns nil and an error on error
	GetSession(routerInfo router_info.RouterInfo) (TransportSession, error)

	// return true if a routerInfo is compatible with this transport
	Compatible(routerInfo router_info.RouterInfo) bool

	// close the transport cleanly
	// blocks until done
	// returns an error if one happens
	Close() error

	// get the name of this tranport as a string
	Name() string
}
```


#### type TransportMuxer

```go
type TransportMuxer struct {
}
```

muxes multiple transports into 1 Transport implements transport.Transport

#### func  Mux

```go
func Mux(t ...Transport) (tmux *TransportMuxer)
```
mux a bunch of transports together

#### func (*TransportMuxer) AcceptWithTimeout

```go
func (tmux *TransportMuxer) AcceptWithTimeout(timeout time.Duration) (net.Conn, error)
```
AcceptWithTimeout accepts an incoming connection with a timeout. This method
wraps the blocking Accept() call with a timeout context, enabling graceful
shutdown of session monitoring loops. Returns the connection and nil on success.
Returns nil and context.DeadlineExceeded if the timeout expires. Returns nil and
any other error from the underlying transport Accept().

#### func (*TransportMuxer) Close

```go
func (tmux *TransportMuxer) Close() (err error)
```
close every transport that this transport muxer has

#### func (*TransportMuxer) Compatible

```go
func (tmux *TransportMuxer) Compatible(routerInfo router_info.RouterInfo) bool
```
is there a transport that we mux that is compatible with this router info?

#### func (*TransportMuxer) GetSession

```go
func (tmux *TransportMuxer) GetSession(routerInfo router_info.RouterInfo) (s TransportSession, err error)
```
get a transport session given a router info return session and nil if successful
return nil and ErrNoTransportAvailable if we failed to get a session

#### func (*TransportMuxer) GetTransports

```go
func (tmux *TransportMuxer) GetTransports() []Transport
```
GetTransports returns a copy of the slice of transports in this muxer. This
allows external code to iterate over transports without exposing internal state.

#### func (*TransportMuxer) Name

```go
func (tmux *TransportMuxer) Name() string
```
the name of this transport with the names of all the ones that we mux

#### func (*TransportMuxer) SetIdentity

```go
func (tmux *TransportMuxer) SetIdentity(ident router_info.RouterInfo) (err error)
```
set the identity for every transport

#### type TransportSession

```go
type TransportSession interface {
	// queue an i2np message to be sent over the session
	// will block as long as the send queue is full
	// does not block if the queue is not full
	QueueSendI2NP(msg i2np.I2NPMessage)
	// return how many i2np messages are not completely sent yet
	SendQueueSize() int
	// blocking read the next fully recv'd i2np message from this session
	ReadNextI2NP() (i2np.I2NPMessage, error)
	// close the session cleanly
	// returns any errors that happen while closing the session
	Close() error
}
```

a session between 2 routers for tranmitting i2np messages securly



transport 

github.com/go-i2p/go-i2p/lib/transport

[go-i2p template file](/template.md)
