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

#### type BandwidthSample

```go
type BandwidthSample struct {
}
```

BandwidthSample represents a single bandwidth measurement at a point in time.

#### type BandwidthTracker

```go
type BandwidthTracker struct {
}
```

BandwidthTracker tracks bandwidth usage over time and calculates rolling
averages. It maintains samples for computing 1-second and 15-second rolling
averages.

#### func  NewBandwidthTracker

```go
func NewBandwidthTracker() *BandwidthTracker
```
NewBandwidthTracker creates a new bandwidth tracker with 1-second sampling.

#### func (*BandwidthTracker) GetRate15s

```go
func (bt *BandwidthTracker) GetRate15s() uint64
```
GetRate15s returns the 15-second rolling average bandwidth rate in bytes per
second.

#### func (*BandwidthTracker) GetRate1s

```go
func (bt *BandwidthTracker) GetRate1s() uint64
```
GetRate1s returns the 1-second rolling average bandwidth rate in bytes per
second.

#### func (*BandwidthTracker) GetRates

```go
func (bt *BandwidthTracker) GetRates() (rate1s, rate15s uint64)
```
GetRates returns the current 1-second and 15-second bandwidth rates in bytes per
second.

#### func (*BandwidthTracker) Start

```go
func (bt *BandwidthTracker) Start(getBandwidth func() (sent, received uint64))
```
Start begins the bandwidth tracking goroutine. The getBandwidth function should
return current cumulative bytes sent/received.

#### func (*BandwidthTracker) Stop

```go
func (bt *BandwidthTracker) Stop()
```
Stop stops the bandwidth tracking goroutine.

#### type GarlicMessageRouter

```go
type GarlicMessageRouter struct {
}
```

GarlicMessageRouter provides router-level garlic message forwarding. It bridges
the gap between message processing (lib/i2np) and router infrastructure (NetDB,
transport, tunnels) to enable delivery of garlic cloves to destinations,
routers, and tunnels beyond LOCAL processing.

This component implements the GarlicCloveForwarder interface and is designed to
be injected into the MessageProcessor via SetCloveForwarder().

Architecture:

    - Receives forwarding requests from MessageProcessor
    - Accesses NetDB for destination/router lookups
    - Uses transport layer for direct router-to-router messaging
    - Uses tunnel pools for destination and tunnel delivery

#### func  NewGarlicMessageRouter

```go
func NewGarlicMessageRouter(
	netdb GarlicNetDB,
	transportMgr *transport.TransportMuxer,
	tunnelPool *tunnel.Pool,
	routerIdentity common.Hash,
) *GarlicMessageRouter
```
NewGarlicMessageRouter creates a new garlic message router with required
dependencies. All parameters are required for full functionality:

    - netdb: For looking up destinations and routers
    - transportMgr: For sending messages to peer routers
    - tunnelPool: For routing messages through tunnels
    - routerIdentity: Our router's hash for reflexive delivery detection

#### func (*GarlicMessageRouter) ForwardThroughTunnel

```go
func (gr *GarlicMessageRouter) ForwardThroughTunnel(
	gatewayHash common.Hash,
	tunnelID tunnel.TunnelID,
	msg i2np.I2NPMessage,
) error
```
ForwardThroughTunnel implements GarlicCloveForwarder interface. Forwards a
message through a tunnel to a gateway (delivery type 0x03).

Process:

    1. Check if gateway_hash == our_router_hash (we are the gateway)
    2. If yes, inject message directly into our tunnel processing via processReflexiveTunnelDelivery()
    3. Otherwise, wrap message in TunnelGateway envelope
    4. Send TunnelGateway message to gateway router via ROUTER delivery

Tunnel delivery is the most common forwarding type in I2P, as most traffic flows
through tunnels for anonymity. The gateway router is responsible for injecting
messages into the tunnel's encryption layers.

#### func (*GarlicMessageRouter) ForwardToDestination

```go
func (gr *GarlicMessageRouter) ForwardToDestination(destHash common.Hash, msg i2np.I2NPMessage) error
```
ForwardToDestination implements GarlicCloveForwarder interface. Forwards a
message to a destination hash (delivery type 0x01).

Process:

    1. Look up destination in NetDB to get LeaseSet
    2. If found: Select a valid lease and route through the tunnel
    3. If not found: Queue message and trigger async LeaseSet lookup
    4. Background processor retries lookups and forwards messages when LeaseSets arrive

Per I2P spec, destinations are identified by their 32-byte hash and are reached
by sending messages through one of their published inbound tunnels.

#### func (*GarlicMessageRouter) ForwardToRouter

```go
func (gr *GarlicMessageRouter) ForwardToRouter(routerHash common.Hash, msg i2np.I2NPMessage) error
```
ForwardToRouter implements GarlicCloveForwarder interface. Forwards a message
directly to a router hash (delivery type 0x02).

Process:

    1. Check if router_hash == our_router_hash (reflexive delivery)
    2. If reflexive, process locally via MessageProcessor
    3. Otherwise, look up router in NetDB to get RouterInfo
    4. Send message via transport layer

Reflexive delivery occurs when a garlic message instructs us to send a clove to
ourselves - this is processed locally to avoid unnecessary network traffic.

#### func (*GarlicMessageRouter) SetMessageProcessor

```go
func (gr *GarlicMessageRouter) SetMessageProcessor(processor *i2np.MessageProcessor)
```
SetMessageProcessor sets a reference to the MessageProcessor for LOCAL delivery
recursion. This enables the router to process messages locally when needed
(e.g., reflexive ROUTER delivery).

#### func (*GarlicMessageRouter) Stop

```go
func (gr *GarlicMessageRouter) Stop()
```
Stop gracefully shuts down the garlic message router. This stops the background
message processing goroutine.

#### type GarlicNetDB

```go
type GarlicNetDB interface {
	GetRouterInfo(hash common.Hash) chan router_info.RouterInfo
	GetLeaseSet(hash common.Hash) chan lease_set.LeaseSet
	StoreRouterInfo(ri router_info.RouterInfo)
	Size() int
	SelectFloodfillRouters(targetHash common.Hash, count int) ([]router_info.RouterInfo, error)
}
```

GarlicNetDB defines the NetDB interface needed for garlic message routing. This
matches the actual StdNetDB implementation which returns channels for async
lookups.

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

#### func (*Router) GetBandwidthRates

```go
func (r *Router) GetBandwidthRates() (rate1s, rate15s uint64)
```
GetBandwidthRates returns the current 1-second and 15-second bandwidth rates.
Returns rates in bytes per second.

#### func (*Router) GetConfig

```go
func (r *Router) GetConfig() *config.RouterConfig
```
GetConfig returns the router configuration for I2PControl.

#### func (*Router) GetGarlicRouter

```go
func (r *Router) GetGarlicRouter() *GarlicMessageRouter
```
GetGarlicRouter returns the garlic router in a thread-safe manner. Returns nil
if the garlic router has not been initialized yet.

#### func (*Router) GetNetDB

```go
func (r *Router) GetNetDB() *netdb.StdNetDB
```
GetNetDB returns the network database for I2PControl statistics collection.
Returns nil if NetDB has not been initialized.

#### func (*Router) GetParticipantManager

```go
func (r *Router) GetParticipantManager() *tunnel.Manager
```
GetParticipantManager returns the participant manager for transit tunnel
tracking. Returns nil if not initialized.

#### func (*Router) GetSessionByHash

```go
func (r *Router) GetSessionByHash(hash common.Hash) (i2np.TransportSession, error)
```
GetSessionByHash implements SessionProvider interface for DatabaseManager. This
enables the I2NP message processing layer to send responses back through the
router's active transport sessions. NTCP2Session already implements the
i2np.TransportSession interface. If no active session exists, it attempts to
establish an outbound connection.

#### func (*Router) GetTransportAddr

```go
func (r *Router) GetTransportAddr() interface{}
```
GetTransportAddr returns the listening address of the first available transport.
This is used by I2PControl to expose NTCP2 port and address information. Returns
nil if no transports are available.

#### func (*Router) GetTunnelManager

```go
func (r *Router) GetTunnelManager() *i2np.TunnelManager
```
GetTunnelManager returns the tunnel manager in a thread-safe manner. Returns nil
if the tunnel manager has not been initialized yet.

#### func (*Router) IsReseeding

```go
func (r *Router) IsReseeding() bool
```
IsReseeding returns whether the router is currently performing a NetDB reseed
operation. Thread-safe access to reseeding state.

#### func (*Router) IsRunning

```go
func (r *Router) IsRunning() bool
```
IsRunning returns whether the router is currently operational. Thread-safe
access to running state.

#### func (*Router) Start

```go
func (r *Router) Start()
```
Start starts router mainloop

#### func (*Router) Stop

```go
func (r *Router) Stop()
```
Stop initiates router shutdown and waits for all goroutines to complete. This
method blocks until the router is fully stopped.

#### func (*Router) Wait

```go
func (r *Router) Wait()
```
Wait blocks until router is fully stopped



router 

github.com/go-i2p/go-i2p/lib/router

[go-i2p template file](/template.md)
