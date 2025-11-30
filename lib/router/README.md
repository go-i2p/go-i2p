# router
--
    import "github.com/go-i2p/go-i2p/lib/router"

![router.svg](router.svg)

Package router coordinates I2P router subsystems including I2CP server, tunnel
management, NetDB, transport layer, and message routing.

# Router Architecture

The Router integrates multiple subsystems:

    - I2CP server for client applications (localhost:7654)
    - Tunnel pools for anonymized routing
    - NetDB for RouterInfo and LeaseSet storage
    - NTCP2 transport for router-to-router communication
    - Message routing with garlic encryption (ECIES-X25519-AEAD-Ratchet)

# Usage Example

    // Create router
    router, err := router.NewRouter(config)
    if err != nil {
        log.Fatal(err)
    }

    // Start router (non-blocking)
    if err := router.Start(); err != nil {
        log.Fatal(err)
    }

    // Router runs in background...

    // Graceful shutdown
    if err := router.Stop(); err != nil {
        log.Printf("Shutdown error: %v", err)
    }

# Current Status

Core routing functional, I2CP complete, LeaseSet2 supported.

## Usage

#### type InboundMessageHandler

```go
type InboundMessageHandler struct {
}
```

InboundMessageHandler processes inbound tunnel messages and delivers them to
I2CP sessions. This component bridges tunnel endpoints with I2CP client
sessions, enabling end-to-end message delivery from the I2P network to local
applications.

Design: - Maps tunnel IDs to I2CP sessions for message routing - Uses tunnel
endpoints to decrypt incoming TunnelData messages - Delivers decrypted I2NP
messages to appropriate I2CP session queues - Thread-safe for concurrent message
processing

#### func  NewInboundMessageHandler

```go
func NewInboundMessageHandler(sessionManager *i2cp.SessionManager) *InboundMessageHandler
```
NewInboundMessageHandler creates a new inbound message handler

#### func (*InboundMessageHandler) GetTunnelCount

```go
func (h *InboundMessageHandler) GetTunnelCount() int
```
GetTunnelCount returns the number of registered inbound tunnels

#### func (*InboundMessageHandler) GetTunnelSession

```go
func (h *InboundMessageHandler) GetTunnelSession(tunnelID tunnel.TunnelID) (uint16, bool)
```
GetTunnelSession returns the session ID for a given tunnel ID, if registered

#### func (*InboundMessageHandler) HandleTunnelData

```go
func (h *InboundMessageHandler) HandleTunnelData(msg i2np.I2NPMessage) error
```
HandleTunnelData processes an incoming TunnelData message. This is the main
entry point for inbound message delivery.

Process: 1. Extract tunnel ID from the message 2. Find the corresponding session
and endpoint 3. Decrypt the tunnel message using the endpoint 4. Deliver the
decrypted I2NP message to the session

Parameters: - msg: the I2NP TunnelData message to process

Returns an error if processing fails at any step.

Note on the tunnel message format: According to the I2P spec, the wire format
for TunnelData is 1028 bytes:

    [Tunnel ID (4 bytes)] + [Encrypted Data (1024 bytes)]

However, the I2NP TunnelDataMessage only stores [1024]byte. This appears to be a
mismatch in the current implementation. The TunnelDataMessage.Data should
contain the full encrypted tunnel payload INCLUDING the tunnel ID in the first 4
bytes, for a total of 1024 bytes (not 1028). The endpoint expects 1028 bytes, so
we need to pad or reconstruct. For now, we'll work with what we have and pass
the 1024 bytes directly to the endpoint, which will need to be adjusted.

#### func (*InboundMessageHandler) RegisterTunnel

```go
func (h *InboundMessageHandler) RegisterTunnel(tunnelID tunnel.TunnelID, sessionID uint16, endpoint *tunnel.Endpoint) error
```
RegisterTunnel registers an inbound tunnel for a specific I2CP session. This
must be called when a new inbound tunnel is created so that incoming messages
can be routed to the correct session.

Parameters: - tunnelID: the ID of the inbound tunnel - sessionID: the I2CP
session ID that owns this tunnel - endpoint: the tunnel endpoint for decrypting
messages

Returns an error if the tunnel is already registered.

#### func (*InboundMessageHandler) UnregisterTunnel

```go
func (h *InboundMessageHandler) UnregisterTunnel(tunnelID tunnel.TunnelID)
```
UnregisterTunnel removes an inbound tunnel from the handler. This should be
called when a tunnel expires or is destroyed.

#### type LeaseSetPublisher

```go
type LeaseSetPublisher struct {
}
```

LeaseSetPublisher implements i2cp.LeaseSetPublisher interface. It handles
publishing LeaseSets to the local NetDB and distributing them to the I2P network
via DatabaseStore messages.

#### func  NewLeaseSetPublisher

```go
func NewLeaseSetPublisher(r *Router) *LeaseSetPublisher
```
NewLeaseSetPublisher creates a new LeaseSetPublisher for the given router.

#### func (*LeaseSetPublisher) PublishLeaseSet

```go
func (p *LeaseSetPublisher) PublishLeaseSet(key common.Hash, leaseSetData []byte) error
```
PublishLeaseSet publishes a LeaseSet to the network database and I2P network.
This method: 1. Stores the LeaseSet in the local NetDB for local lookups 2.
Creates a DatabaseStore I2NP message 3. Distributes the message to floodfill
routers (future enhancement)

Parameters:

    - key: The destination hash (SHA256 of the destination)
    - leaseSetData: The serialized LeaseSet2 bytes

Returns an error if local storage fails. Network distribution errors are logged
but don't cause failure (the LeaseSet is still available locally).

#### type Router

```go
type Router struct {
	// keystore for router info
	*keys.RouterInfoKeystore
	// multi-transport manager
	*transport.TransportMuxer
	// netdb
	*netdb.StdNetDB
}
```

i2p router type

#### func  CreateRouter

```go
func CreateRouter(cfg *config.RouterConfig) (*Router, error)
```
CreateRouter creates a router with the provided configuration

#### func  FromConfig

```go
func FromConfig(c *config.RouterConfig) (r *Router, err error)
```
create router from configuration

#### func (*Router) Close

```go
func (r *Router) Close() error
```
Close closes any internal state and finalizes router resources so that nothing
can start up again

#### func (*Router) GetSessionByHash

```go
func (r *Router) GetSessionByHash(hash common.Hash) (i2np.TransportSession, error)
```
GetSessionByHash implements SessionProvider interface for DatabaseManager. This
enables the I2NP message processing layer to send responses back through the
router's active transport sessions. NTCP2Session already implements the
i2np.TransportSession interface.

#### func (*Router) Start

```go
func (r *Router) Start()
```
Start starts router mainloop

#### func (*Router) Stop

```go
func (r *Router) Stop()
```
Stop starts stopping internal state of router

#### func (*Router) Wait

```go
func (r *Router) Wait()
```
Wait blocks until router is fully stopped



router 

github.com/go-i2p/go-i2p/lib/router

[go-i2p template file](/template.md)
