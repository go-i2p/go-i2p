# tunnel
--
    import "github.com/go-i2p/go-i2p/lib/tunnel"

![tunnel.svg](tunnel.svg)

i2p garlic tunnel implementation

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

#### type BuildResponse

```go
type BuildResponse struct {
	HopIndex int    // Index of the hop that responded
	Success  bool   // Whether the hop accepted the tunnel
	Reply    []byte // Raw response data
}
```

BuildResponse represents a response from a tunnel hop

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

#### func (*DeliveryInstructions) Bytes

```go
func (di *DeliveryInstructions) Bytes() ([]byte, error)
```
Bytes serializes the DeliveryInstructions to bytes

#### func (DeliveryInstructions) Delay

```go
func (delivery_instructions DeliveryInstructions) Delay() (delay_factor DelayFactor, err error)
```

#### func (DeliveryInstructions) DeliveryType

```go
func (delivery_instructions DeliveryInstructions) DeliveryType() (byte, error)
```
Return the delivery type for these DeliveryInstructions, can be of type
DT_LOCAL, DT_TUNNEL, DT_ROUTER, or DT_UNUSED.

#### func (DeliveryInstructions) ExtendedOptions

```go
func (delivery_instructions DeliveryInstructions) ExtendedOptions() (data []byte, err error)
```
Return the Extended Options data if present, or an error if not present.
Extended Options in unimplemented in the Java router and the presence of
extended options will generate a warning.

#### func (DeliveryInstructions) FragmentNumber

```go
func (delivery_instructions DeliveryInstructions) FragmentNumber() (int, error)
```
Read the integer stored in the 6-1 bits of a FOLLOW_ON_FRAGMENT's flag,
indicating the fragment number.

#### func (DeliveryInstructions) FragmentSize

```go
func (delivery_instructions DeliveryInstructions) FragmentSize() (frag_size uint16, err error)
```
Return the size of the associated I2NP fragment and an error if the data is
unavailable.

#### func (DeliveryInstructions) Fragmented

```go
func (delivery_instructions DeliveryInstructions) Fragmented() (bool, error)
```
Returns true if the Delivery Instructions are fragmented or false if the
following data contains the entire message

#### func (DeliveryInstructions) HasDelay

```go
func (delivery_instructions DeliveryInstructions) HasDelay() (bool, error)
```
Check if the delay bit is set. This feature in unimplemented in the Java router.

#### func (DeliveryInstructions) HasExtendedOptions

```go
func (delivery_instructions DeliveryInstructions) HasExtendedOptions() (bool, error)
```
Check if the extended options bit is set. This feature in unimplemented in the
Java router.

#### func (DeliveryInstructions) HasHash

```go
func (delivery_instructions DeliveryInstructions) HasHash() (bool, error)
```

#### func (DeliveryInstructions) HasTunnelID

```go
func (delivery_instructions DeliveryInstructions) HasTunnelID() (bool, error)
```
Check if the DeliveryInstructions is of type DT_TUNNEL.

#### func (DeliveryInstructions) Hash

```go
func (delivery_instructions DeliveryInstructions) Hash() (hash common.Hash, err error)
```
Return the hash for these DeliveryInstructions, which varies by hash type.

    If the type is DT_TUNNEL, hash is the SHA256 of the gateway router, if
    the type is DT_ROUTER it is the SHA256 of the router.

#### func (DeliveryInstructions) LastFollowOnFragment

```go
func (delivery_instructions DeliveryInstructions) LastFollowOnFragment() (bool, error)
```
Read the value of the 0 bit of a FOLLOW_ON_FRAGMENT, which is set to 1 to
indicate the last fragment.

#### func (DeliveryInstructions) MessageID

```go
func (delivery_instructions DeliveryInstructions) MessageID() (msgid uint32, err error)
```
Return the I2NP Message ID or 0 and an error if the data is not available for
this DeliveryInstructions.

#### func (DeliveryInstructions) TunnelID

```go
func (delivery_instructions DeliveryInstructions) TunnelID() (tunnel_id uint32, err error)
```
Return the tunnel ID in this DeliveryInstructions or 0 and an error if the
DeliveryInstructions are not of type DT_TUNNEL.

#### func (DeliveryInstructions) Type

```go
func (delivery_instructions DeliveryInstructions) Type() (int, error)
```
Return if the DeliveryInstructions are of type FIRST_FRAGMENT or
FOLLOW_ON_FRAGMENT.

#### type DeliveryInstructionsWithFragment

```go
type DeliveryInstructionsWithFragment struct {
	DeliveryInstructions DeliveryInstructions
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


#### type PeerSelector

```go
type PeerSelector interface {
	SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error)
}
```

PeerSelector defines interface for selecting peers for tunnel building

#### type Pool

```go
type Pool struct {
}
```

Pool manages a collection of tunnels

#### func  NewTunnelPool

```go
func NewTunnelPool(selector PeerSelector) *Pool
```
NewTunnelPool creates a new tunnel pool with the given peer selector

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

#### func (*Pool) GetActiveTunnels

```go
func (p *Pool) GetActiveTunnels() []*TunnelState
```
GetActiveTunnels returns all active tunnels

#### func (*Pool) GetTunnel

```go
func (p *Pool) GetTunnel(id TunnelID) (*TunnelState, bool)
```
GetTunnel retrieves a tunnel by ID

#### func (*Pool) RemoveTunnel

```go
func (p *Pool) RemoveTunnel(id TunnelID)
```
RemoveTunnel removes a tunnel from the pool

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
}
```

TunnelState represents the current state of a tunnel during building



tunnel 

github.com/go-i2p/go-i2p/lib/tunnel

[go-i2p template file](/template.md)
