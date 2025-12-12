# tunnel
--
    import "github.com/go-i2p/go-i2p/lib/tunnel"

![tunnel.svg](tunnel.svg)

Package tunnel implements I2P tunnel creation, management, and message routing.

# Overview

Tunnels are the core anonymity mechanism in I2P. This package handles:

    - Tunnel building with encrypted build records
    - Tunnel pool management (inbound and outbound)
    - Message routing through tunnel hops
    - Layered encryption/decryption at each hop
    - Fragment handling for large messages

# Tunnel Architecture

Tunnels are unidirectional paths through the I2P network:

    - Outbound tunnels: Local → Hop1 → Hop2 → ... → Endpoint
    - Inbound tunnels: Gateway → Hop1 → Hop2 → ... → Local

Each tunnel has multiple hops (typically 3) for anonymity.

# Tunnel Roles

Routers can perform three roles in tunnel operation:

    - Gateway: Receives messages from the network and forwards them into
      the tunnel with the first layer of encryption.

    - Participant: Acts as an intermediate hop, removing one layer of
      encryption and forwarding to the next hop. The Participant.Process()
      method handles decryption and extraction of next hop information.

    - Endpoint: Receives messages from the tunnel, removes the final
      encryption layer, and delivers to the destination or local router.

# Thread Safety

TunnelPool is safe for concurrent access:

    - Tunnel list protected by mutex
    - Builder operations are atomic
    - Pool management runs in background goroutine

# Usage Example

    // Create tunnel pool
    pool := tunnel.NewTunnelPool(config, netdb, transport)

    // Build outbound tunnel
    outTunnel, err := pool.BuildOutboundTunnel(3) // 3 hops
    if err != nil {
        log.Printf("Failed to build tunnel: %v", err)
    }

    // Route message through tunnel
    if err := outTunnel.SendMessage(msg); err != nil {
        log.Printf("Failed to send: %v", err)
    }

# Cryptography

Each tunnel hop uses:

    - AES256 for layer encryption
    - HMAC-SHA256 for integrity
    - ElGamal or ECIES for build record encryption

See github.com/go-i2p/crypto for cryptographic primitives.

## Usage

```go
const (
	DT_LOCAL = iota
	DT_TUNNEL
	DT_ROUTER
	DT_UNUSED
)
```

```go
const (
	FIRST_FRAGMENT = iota
	FOLLOW_ON_FRAGMENT
)
```

```go
const (
	FLAG_SIZE                 = 1
	TUNNEL_ID_SIZE            = 4
	HASH_SIZE                 = 32
	DELAY_SIZE                = 1
	MESSAGE_ID_SIZE           = 4
	EXTENDED_OPTIONS_MIN_SIZE = 2
	SIZE_FIELD_SIZE           = 2
)
```

```go
var (
	// ErrNilDecryption is returned when decryption is nil
	ErrNilDecryption = errors.New("decryption tunnel cannot be nil")
	// ErrNilHandler is returned when message handler is nil
	ErrNilHandler = errors.New("message handler cannot be nil")
	// ErrInvalidTunnelData is returned when tunnel data is malformed
	ErrInvalidTunnelData = errors.New("invalid tunnel data")
	// ErrChecksumMismatch is returned when checksum validation fails
	ErrChecksumMismatch = errors.New("tunnel message checksum mismatch")
	// ErrTooManyFragments is returned when fragment number exceeds maximum
	ErrTooManyFragments = errors.New("too many fragments: maximum 63")
	// ErrDuplicateFragment is returned when a fragment is received twice
	ErrDuplicateFragment = errors.New("duplicate fragment received")
)
```

```go
var (
	// ErrNilEncryption is returned when encryption is nil
	ErrNilEncryption = errors.New("encryption tunnel cannot be nil")
	// ErrMessageTooLarge is returned when a message exceeds maximum size
	ErrMessageTooLarge = errors.New("message too large for tunnel")
	// ErrInvalidMessage is returned when message data is invalid
	ErrInvalidMessage = errors.New("invalid I2NP message data")
)
```

```go
var (
	// ErrNilDecryption is returned when decryption is nil
	ErrNilParticipantDecryption = errors.New("participant decryption cannot be nil")

	// ErrInvalidParticipantData is returned when tunnel data is malformed
	ErrInvalidParticipantData = errors.New("invalid participant tunnel data")
)
```

#### type BuildRequestRecord

```go
type BuildRequestRecord struct {
	ReceiveTunnel TunnelID
	OurIdent      common.Hash
	NextTunnel    TunnelID
	NextIdent     common.Hash
	LayerKey      session_key.SessionKey
	IVKey         session_key.SessionKey
	ReplyKey      session_key.SessionKey
	ReplyIV       [16]byte
	Flag          int
	RequestTime   time.Time
	SendMessageID int
	Padding       [29]byte
}
```

BuildRequestRecord contains all the data for a single tunnel hop build request.
This is the cleartext version before encryption. It maps to the I2NP
BuildRequestRecord structure but is defined here to avoid import cycles.

#### type BuildResponse

```go
type BuildResponse struct {
	HopIndex int    // Index of the hop that responded
	Success  bool   // Whether the hop accepted the tunnel
	Reply    []byte // Raw response data
}
```

BuildResponse represents a response from a tunnel hop

#### type BuildTunnelRequest

```go
type BuildTunnelRequest struct {
	HopCount                  int           // Number of hops in the tunnel (1-8)
	IsInbound                 bool          // True for inbound tunnel, false for outbound
	OurIdentity               common.Hash   // Our router identity hash
	ExcludePeers              []common.Hash // Peers to exclude from selection
	ReplyTunnelID             TunnelID      // Tunnel ID for receiving build replies (0 for outbound)
	ReplyGateway              common.Hash   // Gateway hash for build replies (empty for outbound)
	UseShortBuild             bool          // Use Short Tunnel Build (STBM - modern, default true)
	RequireDirectConnectivity bool          // Only select peers with direct NTCP2 connectivity (set true in production)
}
```

BuildTunnelRequest contains the parameters needed to build a tunnel.

BUG FIX: Added RequireDirectConnectivity to enable pre-filtering of
introducer-only peers. This prevents session establishment failures by only
selecting peers with direct NTCP2 addresses. Set to true in production; tests
may leave false to test with mock peers.

#### type BuilderInterface

```go
type BuilderInterface interface {
	// BuildTunnel initiates building a new tunnel with the specified parameters
	BuildTunnel(req BuildTunnelRequest) (TunnelID, error)
}
```

BuilderInterface defines interface for building tunnels

#### type DecryptedTunnelMessage

```go
type DecryptedTunnelMessage [1028]byte
```


#### func (DecryptedTunnelMessage) Checksum

```go
func (decrypted_tunnel_message DecryptedTunnelMessage) Checksum() tunnel.TunnelIV
```

#### func (DecryptedTunnelMessage) DeliveryInstructionsWithFragments

```go
func (decrypted_tunnel_message DecryptedTunnelMessage) DeliveryInstructionsWithFragments() []DeliveryInstructionsWithFragment
```
Returns a slice of DeliveryInstructionWithFragment structures, which all of the
Delivery Instructions in the tunnel message and their corresponding
MessageFragment structures.

#### func (DecryptedTunnelMessage) ID

```go
func (decrypted_tunnel_message DecryptedTunnelMessage) ID() TunnelID
```

#### func (DecryptedTunnelMessage) IV

```go
func (decrypted_tunnel_message DecryptedTunnelMessage) IV() tunnel.TunnelIV
```

#### type DefaultPeerSelector

```go
type DefaultPeerSelector struct {
}
```

DefaultPeerSelector is a simple implementation of PeerSelector that delegates
peer selection to a NetDB-like component (for example lib/netdb.StdNetDB). It
performs basic argument validation and propagates errors from the underlying
selector.

#### func  NewDefaultPeerSelector

```go
func NewDefaultPeerSelector(db NetDBSelector) (*DefaultPeerSelector, error)
```
NewDefaultPeerSelector creates a new DefaultPeerSelector backed by the provided
db. The db must implement SelectPeers with the same signature. Returns an error
if db is nil.

#### func (*DefaultPeerSelector) SelectPeers

```go
func (s *DefaultPeerSelector) SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error)
```
SelectPeers selects peers by delegating to the underlying db selector. Returns
an error for invalid arguments or if the underlying selector fails.

#### type DelayFactor

```go
type DelayFactor byte
```


#### type DeliveryInstructions

```go
type DeliveryInstructions struct {
}
```

DeliveryInstructions represents I2P tunnel message delivery instructions

#### func  NewDeliveryInstructions

```go
func NewDeliveryInstructions(bytes []byte) (*DeliveryInstructions, error)
```
NewDeliveryInstructions creates a new DeliveryInstructions from raw bytes

#### func  NewLocalDeliveryInstructions

```go
func NewLocalDeliveryInstructions(fragmentSize uint16) *DeliveryInstructions
```
NewLocalDeliveryInstructions creates delivery instructions for LOCAL delivery.
LOCAL delivery means the message should be processed locally by the current
router. This is used for both inbound tunnels (standard) and outbound tunnels
(when message arrives at the final hop).

Parameters:

    - fragmentSize: The size of the message fragment to deliver

Returns:

    - *DeliveryInstructions: A new delivery instruction configured for LOCAL delivery

The resulting instruction will have:

    - deliveryType: DT_LOCAL
    - fragmentType: FIRST_FRAGMENT
    - fragmented: false (unfragmented message)
    - hasDelay: false
    - hasExtOptions: false

#### func  NewRouterDeliveryInstructions

```go
func NewRouterDeliveryInstructions(routerHash [32]byte, fragmentSize uint16) *DeliveryInstructions
```
NewRouterDeliveryInstructions creates delivery instructions for ROUTER delivery.
ROUTER delivery sends the message directly to a specific router (not through a
tunnel).

Parameters:

    - routerHash: SHA-256 hash of the destination router's identity
    - fragmentSize: The size of the message fragment

Returns:

    - *DeliveryInstructions: A new delivery instruction configured for ROUTER delivery

#### func  NewTunnelDeliveryInstructions

```go
func NewTunnelDeliveryInstructions(tunnelID uint32, gatewayHash [32]byte, fragmentSize uint16) *DeliveryInstructions
```
NewTunnelDeliveryInstructions creates delivery instructions for TUNNEL delivery.
TUNNEL delivery routes the message to a specific tunnel on a gateway router.

Parameters:

    - tunnelID: The destination tunnel ID
    - gatewayHash: SHA-256 hash of the gateway router's identity
    - fragmentSize: The size of the message fragment

Returns:

    - *DeliveryInstructions: A new delivery instruction configured for TUNNEL delivery

#### func (*DeliveryInstructions) Bytes

```go
func (di *DeliveryInstructions) Bytes() ([]byte, error)
```
Bytes serializes the DeliveryInstructions to bytes

#### func (*DeliveryInstructions) Delay

```go
func (delivery_instructions *DeliveryInstructions) Delay() (delay_factor DelayFactor, err error)
```

#### func (*DeliveryInstructions) DeliveryType

```go
func (delivery_instructions *DeliveryInstructions) DeliveryType() (byte, error)
```
Return the delivery type for these DeliveryInstructions, can be of type
DT_LOCAL, DT_TUNNEL, DT_ROUTER, or DT_UNUSED.

#### func (*DeliveryInstructions) ExtendedOptions

```go
func (delivery_instructions *DeliveryInstructions) ExtendedOptions() (data []byte, err error)
```
Return the Extended Options data if present, or an error if not present.
Extended Options in unimplemented in the Java router and the presence of
extended options will generate a warning.

#### func (*DeliveryInstructions) FragmentNumber

```go
func (delivery_instructions *DeliveryInstructions) FragmentNumber() (int, error)
```
Read the integer stored in the 6-1 bits of a FOLLOW_ON_FRAGMENT's flag,
indicating the fragment number.

#### func (*DeliveryInstructions) FragmentSize

```go
func (delivery_instructions *DeliveryInstructions) FragmentSize() (frag_size uint16, err error)
```
Return the size of the associated I2NP fragment and an error if the data is
unavailable.

#### func (*DeliveryInstructions) Fragmented

```go
func (delivery_instructions *DeliveryInstructions) Fragmented() (bool, error)
```
Returns true if the Delivery Instructions are fragmented or false if the
following data contains the entire message

#### func (*DeliveryInstructions) HasDelay

```go
func (delivery_instructions *DeliveryInstructions) HasDelay() (bool, error)
```
Check if the delay bit is set. This feature in unimplemented in the Java router.

#### func (*DeliveryInstructions) HasExtendedOptions

```go
func (delivery_instructions *DeliveryInstructions) HasExtendedOptions() (bool, error)
```
Check if the extended options bit is set. This feature in unimplemented in the
Java router.

#### func (*DeliveryInstructions) HasHash

```go
func (delivery_instructions *DeliveryInstructions) HasHash() (bool, error)
```

#### func (*DeliveryInstructions) HasTunnelID

```go
func (delivery_instructions *DeliveryInstructions) HasTunnelID() (bool, error)
```
Check if the DeliveryInstructions is of type DT_TUNNEL.

#### func (*DeliveryInstructions) Hash

```go
func (delivery_instructions *DeliveryInstructions) Hash() (hash common.Hash, err error)
```
Return the hash for these DeliveryInstructions, which varies by hash type.

    If the type is DT_TUNNEL, hash is the SHA256 of the gateway router, if
    the type is DT_ROUTER it is the SHA256 of the router.

#### func (*DeliveryInstructions) LastFollowOnFragment

```go
func (delivery_instructions *DeliveryInstructions) LastFollowOnFragment() (bool, error)
```
Read the value of the 0 bit of a FOLLOW_ON_FRAGMENT, which is set to 1 to
indicate the last fragment.

#### func (*DeliveryInstructions) MessageID

```go
func (delivery_instructions *DeliveryInstructions) MessageID() (msgid uint32, err error)
```
Return the I2NP Message ID or 0 and an error if the data is not available for
this DeliveryInstructions.

#### func (*DeliveryInstructions) TunnelID

```go
func (delivery_instructions *DeliveryInstructions) TunnelID() (tunnel_id uint32, err error)
```
Return the tunnel ID in this DeliveryInstructions or 0 and an error if the
DeliveryInstructions are not of type DT_TUNNEL.

#### func (*DeliveryInstructions) Type

```go
func (delivery_instructions *DeliveryInstructions) Type() (int, error)
```
Return if the DeliveryInstructions are of type FIRST_FRAGMENT or
FOLLOW_ON_FRAGMENT.

#### type DeliveryInstructionsWithFragment

```go
type DeliveryInstructionsWithFragment struct {
	DeliveryInstructions *DeliveryInstructions
	MessageFragment      []byte
}
```


#### type EncryptedTunnelMessage

```go
type EncryptedTunnelMessage tunnel.TunnelData
```


#### func (EncryptedTunnelMessage) Data

```go
func (tm EncryptedTunnelMessage) Data() tunnel.TunnelIV
```

#### func (EncryptedTunnelMessage) ID

```go
func (tm EncryptedTunnelMessage) ID() (tid TunnelID)
```

#### func (EncryptedTunnelMessage) IV

```go
func (tm EncryptedTunnelMessage) IV() tunnel.TunnelIV
```

#### type Endpoint

```go
type Endpoint struct {
}
```

Endpoint handles receiving encrypted tunnel messages, decrypting them, and
extracting I2NP messages.

Design decisions: - Simple callback-based message delivery - Works with raw
bytes to avoid import cycles - Uses crypto/tunnel package with ECIES-X25519-AEAD
(ChaCha20/Poly1305) by default - Supports both modern ECIES and legacy
AES-256-CBC for compatibility - Handles fragment reassembly for large messages -
Automatic cleanup of stale fragments (default: 60 seconds) - Thread-safe for
concurrent message processing - Clear error handling and logging

#### func  NewEndpoint

```go
func NewEndpoint(tunnelID TunnelID, decryption tunnel.TunnelEncryptor, handler MessageHandler) (*Endpoint, error)
```
NewEndpoint creates a new tunnel endpoint.

Parameters: - tunnelID: the ID of this tunnel - decryption: the tunnel
decryption object for layered decryption - handler: callback function to process
received I2NP messages

Returns an error if decryption or handler is nil. Starts a background goroutine
to clean up stale fragments.

#### func (*Endpoint) ClearFragments

```go
func (e *Endpoint) ClearFragments()
```
ClearFragments clears all accumulated fragments (useful for cleanup)

#### func (*Endpoint) Receive

```go
func (e *Endpoint) Receive(encryptedData []byte) error
```
Receive processes an encrypted tunnel message.

Process: 1. Decrypt the tunnel message 2. Validate checksum 3. Parse delivery
instructions 4. Extract message fragments 5. Reassemble if fragmented 6. Deliver
to handler

Thread-safe: protects fragment map access with mutex. Returns an error if
processing fails at any step.

#### func (*Endpoint) Stop

```go
func (e *Endpoint) Stop()
```
Stop gracefully shuts down the endpoint and stops the cleanup goroutine. Should
be called when the endpoint is no longer needed to prevent resource leaks.

#### func (*Endpoint) TunnelID

```go
func (e *Endpoint) TunnelID() TunnelID
```
TunnelID returns the ID of this endpoint's tunnel

#### type Gateway

```go
type Gateway struct {
}
```

Gateway handles sending I2NP messages through a tunnel by wrapping them in
tunnel messages and applying encryption.

Design decisions: - Works with raw bytes to avoid import cycles with i2np
package - Uses crypto/tunnel package with ECIES-X25519-AEAD (ChaCha20/Poly1305)
by default - Supports both modern ECIES and legacy AES-256-CBC for compatibility
- Simple interface focused on core functionality - Error handling at each step
with clear error messages

#### func  NewGateway

```go
func NewGateway(tunnelID TunnelID, encryption tunnel.TunnelEncryptor, nextHopID TunnelID) (*Gateway, error)
```
NewGateway creates a new tunnel gateway.

Parameters: - tunnelID: the ID of this tunnel - encryption: the tunnel
encryption object for layered encryption - nextHopID: the tunnel ID to use when
forwarding to the next hop

Returns an error if encryption is nil.

#### func (*Gateway) NextHopID

```go
func (g *Gateway) NextHopID() TunnelID
```
NextHopID returns the tunnel ID used for the next hop

#### func (*Gateway) Send

```go
func (g *Gateway) Send(msgBytes []byte) ([]byte, error)
```
Send wraps an I2NP message (as bytes) in tunnel format and encrypts it.

Parameters: - msgBytes: the serialized I2NP message to send

Process: 1. Validate message size 2. Create delivery instructions 3. Build
tunnel message with padding 4. Calculate checksum 5. Apply encryption

Returns the encrypted tunnel message ready for transmission, or an error.

#### func (*Gateway) TunnelID

```go
func (g *Gateway) TunnelID() TunnelID
```
TunnelID returns the ID of this gateway's tunnel

#### type HealthCheckResult

```go
type HealthCheckResult struct {
	TotalTunnels     int
	ReadyTunnels     int
	TestedTunnels    int
	HealthyTunnels   int
	UnhealthyTunnels int
	AverageLatency   time.Duration
	Results          []TunnelTestResult
}
```

HealthCheckResult summarizes the health of the tunnel pool.

#### type Manager

```go
type Manager struct {
}
```

Manager coordinates all tunnel operations including participant tracking. It
manages the lifecycle of tunnels where this router acts as an intermediate hop.

Design decisions: - Separate tracking for participants (where we relay) vs owned
tunnels (where we originate) - Automatic cleanup of expired participant tunnels
- Thread-safe concurrent access - Simple map-based storage for O(1) lookup

#### func  NewManager

```go
func NewManager() *Manager
```
NewManager creates a new tunnel manager. Starts a background goroutine to clean
up expired participants.

#### func (*Manager) AddParticipant

```go
func (m *Manager) AddParticipant(p *Participant) error
```
AddParticipant registers a new participant tunnel. This is called when this
router accepts a tunnel build request and agrees to relay traffic as an
intermediate hop.

Parameters: - p: the participant tunnel to track

Returns an error if the participant is nil or already exists.

#### func (*Manager) GetParticipant

```go
func (m *Manager) GetParticipant(tunnelID TunnelID) *Participant
```
GetParticipant retrieves a participant tunnel by its ID. Returns nil if no
participant exists with the given ID.

This is used when processing incoming TunnelData messages to find the
appropriate participant to handle decryption and forwarding.

#### func (*Manager) ParticipantCount

```go
func (m *Manager) ParticipantCount() int
```
ParticipantCount returns the current number of participant tunnels. This is
useful for monitoring and statistics.

#### func (*Manager) RemoveParticipant

```go
func (m *Manager) RemoveParticipant(tunnelID TunnelID) bool
```
RemoveParticipant removes a participant tunnel by its tunnel ID. This is called
when a tunnel expires or is no longer needed.

Returns true if the participant was found and removed, false otherwise.

#### func (*Manager) Stop

```go
func (m *Manager) Stop()
```
Stop gracefully stops the tunnel manager. Waits for background goroutines to
finish.

This should be called during router shutdown.

#### type MessageHandler

```go
type MessageHandler func(msgBytes []byte) error
```

MessageHandler is a callback function for processing received I2NP messages. It
receives the unwrapped message bytes and returns an error if processing fails.

#### type NetDBSelector

```go
type NetDBSelector interface {
	SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error)
}
```

NetDBSelector is a minimal interface used by DefaultPeerSelector to delegate
peer selection. Any component that implements SelectPeers(count int, exclude
[]common.Hash) ([]router_info.RouterInfo, error) can be used. This avoids a hard
dependency on a concrete netdb type.

#### type Participant

```go
type Participant struct {
}
```

Participant represents an intermediate hop in an I2P tunnel. It receives
encrypted tunnel messages, decrypts one layer, and forwards them to the next
hop.

Design decisions: - Simple relay logic: decrypt and forward - Uses crypto/tunnel
with ECIES-X25519-AEAD (ChaCha20/Poly1305) by default - Supports both modern
ECIES and legacy AES-256-CBC for compatibility - No message inspection
(maintains tunnel privacy) - Stateless processing for better performance -
Tracks creation time and expiration (tunnels typically last 10 minutes)

#### func  NewParticipant

```go
func NewParticipant(tunnelID TunnelID, decryption tunnel.TunnelEncryptor) (*Participant, error)
```
NewParticipant creates a new tunnel participant.

Parameters: - tunnelID: the tunnel ID for this participant hop - decryption: the
tunnel decryption object for removing one encryption layer

Returns an error if decryption is nil.

Design note: We use TunnelEncryptor interface even though it's called
"decryption" because the interface supports both encrypt and decrypt operations.
The crypto/tunnel package uses the same interface for both directions. The
participant is created with a default lifetime of 10 minutes (standard I2P
tunnel lifetime).

#### func (*Participant) CreatedAt

```go
func (p *Participant) CreatedAt() time.Time
```
CreatedAt returns when this participant tunnel was created.

#### func (*Participant) IsExpired

```go
func (p *Participant) IsExpired(now time.Time) bool
```
IsExpired checks if this participant tunnel has expired. Returns true if the
current time is past createdAt + lifetime.

Parameters: - now: the current time to check against

This is used by the tunnel manager to clean up expired participants.

#### func (*Participant) Process

```go
func (p *Participant) Process(encryptedData []byte) (nextHopID TunnelID, decryptedData []byte, err error)
```
Process handles an incoming encrypted tunnel message.

This function implements the core participant functionality: 1. Validate the
tunnel message format 2. Decrypt one layer of encryption 3. Extract the next hop
tunnel ID 4. Return the partially-decrypted message ready for forwarding

Parameters: - encryptedData: the 1028-byte encrypted tunnel message

Returns: - nextHopID: the tunnel ID for the next hop - decryptedData: the
message with one layer removed (still encrypted for next hops) - error: any
processing error

Design notes: - This is a stateless operation - no state is maintained between
messages - The participant doesn't inspect message contents (privacy by design)
- The tunnel ID in the message header specifies the next hop, not this hop - All
1028 bytes are returned; the next hop will decrypt further

#### func (*Participant) SetLifetime

```go
func (p *Participant) SetLifetime(lifetime time.Duration)
```
SetLifetime updates the lifetime for this participant tunnel. This allows
customization beyond the default 10 minutes if needed.

#### func (*Participant) TunnelID

```go
func (p *Participant) TunnelID() TunnelID
```
TunnelID returns this participant's tunnel ID

#### type PeerSelector

```go
type PeerSelector interface {
	SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error)
}
```

PeerSelector defines interface for selecting peers for tunnel building

#### type PeerTracker

```go
type PeerTracker interface {
	RecordFailure(hash common.Hash, reason string)
	RecordSuccess(hash common.Hash, responseTimeMs int64)
}
```

PeerTracker interface for recording peer connection outcomes. This allows Pool
to report connection results to NetDB for reputation tracking.

#### type Pool

```go
type Pool struct {
}
```

Pool manages a collection of tunnels with automatic maintenance

#### func  NewTunnelPool

```go
func NewTunnelPool(selector PeerSelector) *Pool
```
NewTunnelPool creates a new tunnel pool with the given peer selector and default
configuration

#### func  NewTunnelPoolWithConfig

```go
func NewTunnelPoolWithConfig(selector PeerSelector, config PoolConfig) *Pool
```
NewTunnelPoolWithConfig creates a new tunnel pool with custom configuration

#### func (*Pool) AddTunnel

```go
func (p *Pool) AddTunnel(tunnel *TunnelState)
```
AddTunnel adds a new tunnel to the pool

#### func (*Pool) CleanupExpiredTunnels

```go
func (p *Pool) CleanupExpiredTunnels(maxAge time.Duration)
```
CleanupExpiredTunnels removes tunnels that have been building for too long

#### func (*Pool) CleanupFailedPeers

```go
func (p *Pool) CleanupFailedPeers()
```
CleanupFailedPeers removes failed peer entries that have exceeded the cooldown
period. Should be called periodically as part of pool maintenance.

#### func (*Pool) GetActiveTunnels

```go
func (p *Pool) GetActiveTunnels() []*TunnelState
```
GetActiveTunnels returns all active tunnels

#### func (*Pool) GetFailedPeers

```go
func (p *Pool) GetFailedPeers() []common.Hash
```
GetFailedPeers returns a list of peer hashes currently marked as failed. This is
used to exclude failed peers from tunnel building attempts.

#### func (*Pool) GetPoolStats

```go
func (p *Pool) GetPoolStats() PoolStats
```
GetPoolStats returns statistics about the pool

#### func (*Pool) GetTunnel

```go
func (p *Pool) GetTunnel(id TunnelID) (*TunnelState, bool)
```
GetTunnel retrieves a tunnel by ID

#### func (*Pool) IsPeerFailed

```go
func (p *Pool) IsPeerFailed(peerHash common.Hash) bool
```
IsPeerFailed checks if a peer is currently in the failed state. Returns true if
the peer failed recently and is still in cooldown.

#### func (*Pool) MarkPeerFailed

```go
func (p *Pool) MarkPeerFailed(peerHash common.Hash)
```
BUG FIX #5: Failed peer tracking to avoid retry loops MarkPeerFailed records
that a peer failed to establish a connection. This peer will be avoided for a
cooldown period to prevent wasted retry attempts. If a PeerTracker is
configured, the failure is also reported for reputation tracking.

#### func (*Pool) RemoveTunnel

```go
func (p *Pool) RemoveTunnel(id TunnelID)
```
RemoveTunnel removes a tunnel from the pool

#### func (*Pool) RetryTunnelBuild

```go
func (p *Pool) RetryTunnelBuild(tunnelID TunnelID, isInbound bool, hopCount int) error
```
RetryTunnelBuild retries building a tunnel that previously timed out. This
method is called by the ReplyProcessor when a tunnel build times out and
automatic retry is configured.

Parameters:

    - tunnelID: The ID of the tunnel that timed out (for logging correlation)
    - isInbound: Direction of the tunnel (true=inbound, false=outbound)
    - hopCount: Number of hops for the tunnel

Returns error if the tunnel cannot be built (e.g., peer selection fails).

#### func (*Pool) SelectTunnel

```go
func (p *Pool) SelectTunnel() *TunnelState
```
SelectTunnel selects a tunnel from the pool using round-robin strategy. Returns
nil if no active tunnels are available.

#### func (*Pool) SetPeerTracker

```go
func (p *Pool) SetPeerTracker(tracker PeerTracker)
```
SetPeerTracker sets the peer tracker for NetDB integration. This allows the pool
to report connection results for reputation tracking.

#### func (*Pool) SetTunnelBuilder

```go
func (p *Pool) SetTunnelBuilder(builder BuilderInterface)
```
SetTunnelBuilder sets the tunnel builder for this pool. Must be called before
starting pool maintenance.

#### func (*Pool) StartMaintenance

```go
func (p *Pool) StartMaintenance() error
```
StartMaintenance begins the pool maintenance goroutine. This monitors tunnel
health and builds new tunnels as needed.

#### func (*Pool) Stop

```go
func (p *Pool) Stop()
```
Stop gracefully stops the pool maintenance goroutine

#### type PoolConfig

```go
type PoolConfig struct {
	// MinTunnels is the minimum number of tunnels to maintain
	MinTunnels int
	// MaxTunnels is the maximum number of tunnels to allow
	MaxTunnels int
	// TunnelLifetime is how long tunnels should live before expiring
	TunnelLifetime time.Duration
	// RebuildThreshold is when to start building replacement tunnels (before expiry)
	RebuildThreshold time.Duration
	// BuildRetryDelay is the initial delay before retrying failed builds
	BuildRetryDelay time.Duration
	// MaxBuildRetries is the maximum number of build retries before giving up
	MaxBuildRetries int
	// HopCount is the number of hops for tunnels in this pool
	HopCount int
	// IsInbound indicates if this pool manages inbound tunnels
	IsInbound bool
}
```

PoolConfig defines configuration parameters for a tunnel pool

#### func  DefaultPoolConfig

```go
func DefaultPoolConfig() PoolConfig
```
DefaultPoolConfig returns a configuration with sensible defaults

#### type PoolStats

```go
type PoolStats struct {
	Total      int // Total tunnels in pool
	Active     int // Ready for use
	Building   int // Currently building
	Failed     int // Failed builds
	NearExpiry int // Active but near expiration
}
```

PoolStats contains statistics about a tunnel pool

#### type TunnelBuildResult

```go
type TunnelBuildResult struct {
	TunnelID      TunnelID                 // The generated tunnel ID
	Hops          []router_info.RouterInfo // Selected router hops
	Records       []BuildRequestRecord     // Build records for each hop
	ReplyKeys     []session_key.SessionKey // Reply decryption keys for each hop
	ReplyIVs      [][16]byte               // Reply IVs for each hop
	UseShortBuild bool                     // True if using Short Tunnel Build (STBM), false for Variable Tunnel Build
	IsInbound     bool                     // True if this is an inbound tunnel
}
```

TunnelBuildResult contains the result of building a tunnel request.

#### type TunnelBuildState

```go
type TunnelBuildState int
```

TunnelBuildState represents different states during tunnel building

```go
const (
	TunnelBuilding TunnelBuildState = iota // Tunnel is being built
	TunnelReady                            // Tunnel is ready for use
	TunnelFailed                           // Tunnel build failed
)
```

#### type TunnelBuilder

```go
type TunnelBuilder struct {
}
```

TunnelBuilder handles the creation of tunnel build request messages. It
generates encrypted build records for each hop in a tunnel and constructs
VariableTunnelBuild messages for transmission over the I2P network.

#### func  NewTunnelBuilder

```go
func NewTunnelBuilder(selector PeerSelector) (*TunnelBuilder, error)
```
NewTunnelBuilder creates a new TunnelBuilder with the given peer selector. The
peer selector is used to choose routers for tunnel hops.

Returns an error if the peer selector is nil.

#### func (*TunnelBuilder) CreateBuildRequest

```go
func (tb *TunnelBuilder) CreateBuildRequest(req BuildTunnelRequest) (*TunnelBuildResult, error)
```
CreateBuildRequest generates a complete tunnel build request with encrypted
records.

The process: 1. Select peers for tunnel hops using the peer selector 2. Generate
a unique tunnel ID for this tunnel 3. Create build request records for each hop
with cryptographic keys 4. Prepare reply decryption keys for processing build
replies

Returns TunnelBuildResult with all necessary information, or an error if: -
HopCount is invalid (must be 1-8) - Peer selection fails - Cryptographic key
generation fails

#### type TunnelID

```go
type TunnelID uint32
```


#### type TunnelState

```go
type TunnelState struct {
	ID            TunnelID
	Hops          []common.Hash    // Router hashes for each hop
	State         TunnelBuildState // Current build state
	CreatedAt     time.Time        // When tunnel building started
	ResponseCount int              // Number of responses received
	Responses     []BuildResponse  // Responses from each hop
	IsInbound     bool             // True if this is an inbound tunnel
}
```

TunnelState represents the current state of a tunnel during building

#### type TunnelTestResult

```go
type TunnelTestResult struct {
	TunnelID TunnelID
	Success  bool
	Latency  time.Duration
	Error    error
	TestedAt time.Time
}
```

TunnelTestResult contains the results of a tunnel test.

#### type TunnelTester

```go
type TunnelTester struct {
}
```

TunnelTester validates tunnel health and performance. It sends test messages
through tunnels and measures latency, enabling automatic detection of failed or
slow tunnels.

Design decisions: - Simple echo-based testing (send test message, wait for
reply) - Configurable timeout (default 5 seconds) - Latency tracking for tunnel
selection optimization - Non-blocking test execution (returns immediately,
callbacks for results) - Thread-safe for concurrent testing of multiple tunnels

#### func  NewTunnelTester

```go
func NewTunnelTester(pool *Pool) *TunnelTester
```
NewTunnelTester creates a new tunnel tester for the given pool.

Parameters: - pool: the tunnel pool to test

The tester is created with a default 5-second timeout. Use SetTimeout to
customize.

#### func (*TunnelTester) HealthCheck

```go
func (tt *TunnelTester) HealthCheck() HealthCheckResult
```
HealthCheck performs a comprehensive health check on the tunnel pool.

This tests all ready tunnels and provides statistics: - Total tunnel count -
Number of healthy vs unhealthy tunnels - Average latency across healthy tunnels
- Detailed per-tunnel results

Returns: - HealthCheckResult with complete health statistics

This is useful for: - Monitoring tunnel pool status - Deciding when to build
replacement tunnels - Diagnosing connectivity issues

#### func (*TunnelTester) ReplacementRecommendation

```go
func (tt *TunnelTester) ReplacementRecommendation(results []TunnelTestResult) []TunnelID
```
ReplacementRecommendation analyzes test results and recommends tunnel
replacements.

Returns: - slice of TunnelIDs that should be replaced - tunnels are recommended
for replacement if they:

    - Failed the test
    - Have high latency (>2 seconds)
    - Are near expiration

This is used by the pool maintenance system to proactively replace failing
tunnels before they impact service quality.

#### func (*TunnelTester) SetTimeout

```go
func (tt *TunnelTester) SetTimeout(timeout time.Duration)
```
SetTimeout configures the test timeout. Tests that don't complete within this
duration are marked as failed.

Parameters: - timeout: the maximum time to wait for a test response

#### func (*TunnelTester) TestAllTunnels

```go
func (tt *TunnelTester) TestAllTunnels() []TunnelTestResult
```
TestAllTunnels tests all ready tunnels in the pool.

Returns: - slice of TunnelTestResult for each tunnel tested - tunnels are tested
sequentially to avoid overwhelming the network

Use TestAllTunnelsAsync for concurrent testing.

#### func (*TunnelTester) TestTunnel

```go
func (tt *TunnelTester) TestTunnel(tunnelID TunnelID) TunnelTestResult
```
TestTunnel validates a single tunnel by sending a test message.

This function: 1. Generates a unique test message ID 2. Sends the test message
through the tunnel 3. Waits for an echo response (or timeout) 4. Measures
round-trip latency 5. Returns detailed test results

Parameters: - tunnelID: the ID of the tunnel to test

Returns: - TunnelTestResult with success status, latency, and any errors

Design notes: - This is a blocking call that waits for the test to complete -
For non-blocking tests, use TestTunnelAsync - Test messages are small (1024
bytes) to minimize overhead - Failed tests don't affect tunnel state (read-only
validation)



tunnel 

github.com/go-i2p/go-i2p/lib/tunnel

[go-i2p template file](/template.md)
