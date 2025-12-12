# netdb
--
    import "github.com/go-i2p/go-i2p/lib/netdb"

![netdb.svg](netdb.svg)

Package netdb implements the Network Database for I2P router information and
lease sets.

The NetDB stores and manages:

    - RouterInfo: Network routing information for I2P routers
    - LeaseSet: Destination lease information for I2P services

# Storage Architecture

The package uses a hybrid storage approach:

    - In-memory cache for fast lookups
    - Filesystem persistence using skiplist structure
    - Automatic expiration and cleanup of stale entries

# Thread Safety

StdNetDB is safe for concurrent access:

    - RouterInfo and LeaseSet maps have separate mutexes
    - Expiry tracking uses read-write mutex for efficiency
    - Background cleanup runs in separate goroutine

# Usage Example

    // Create NetDB
    db := netdb.NewStdNetDB("/path/to/netdb")
    if err := db.Create(); err != nil {
        log.Fatal(err)
    }

    // Store RouterInfo
    hash, err := routerInfo.IdentHash()
    if err != nil {
        log.Fatal(err)
    }
    data, err := routerInfo.Bytes()
    if err != nil {
        log.Fatal(err)
    }
    if err := db.StoreRouterInfo(hash, data, 0); err != nil {
        log.Printf("Failed to store: %v", err)
    }

    // Retrieve RouterInfo
    riChan := db.GetRouterInfo(hash)
    if ri := <-riChan; ri != nil {
        // Use router info
    }

# Reseed and Bootstrap

The package includes reseed functionality to bootstrap the NetDB with initial
router information from trusted sources.

See bootstrap package for reseed client implementation.

# Exploration

The Explorer performs periodic database lookups to discover new routers and
expand NetDB knowledge beyond floodfill routers. Two exploration strategies are
supported:

    - Adaptive (default): Targets sparse regions of the keyspace using
      bucket analysis to efficiently discover routers in under-represented
      areas. Automatically adjusts exploration interval based on NetDB health.

    - Random: Performs lookups for random keys across the entire keyspace.
      Simpler but less efficient than adaptive strategy.

Exploration runs in the background with configurable interval (default: 5
minutes), concurrency (default: 3 parallel lookups), and timeout (default: 30
seconds per lookup).

## Usage

```go
const (
	// NumKademliaBuckets is the number of Kademlia buckets (256 bits = 256 buckets)
	NumKademliaBuckets = 256

	// MinFloodfillsPerBucket is the minimum desired floodfills per bucket
	MinFloodfillsPerBucket = 2
)
```

```go
const CacheFileName = "sizecache.txt"
```
Moved from: std.go name of file to hold precomputed size of netdb

#### type AdaptiveStrategy

```go
type AdaptiveStrategy struct {
}
```

AdaptiveStrategy implements an intelligent exploration strategy that: - Tracks
Kademlia bucket distribution - Identifies gaps in floodfill coverage - Generates
exploration keys targeting sparse regions - Adapts exploration rate based on
NetDB size

#### func  NewAdaptiveStrategy

```go
func NewAdaptiveStrategy(ourHash common.Hash) *AdaptiveStrategy
```
NewAdaptiveStrategy creates a new adaptive exploration strategy

#### func (*AdaptiveStrategy) GenerateExplorationKeys

```go
func (s *AdaptiveStrategy) GenerateExplorationKeys(count int) ([]common.Hash, error)
```
GenerateExplorationKeys generates exploration keys targeting sparse buckets

#### func (*AdaptiveStrategy) GetBucketStats

```go
func (s *AdaptiveStrategy) GetBucketStats(bucketIdx int) BucketStats
```
GetBucketStats returns statistics for a specific bucket

#### func (*AdaptiveStrategy) GetFloodfillGaps

```go
func (s *AdaptiveStrategy) GetFloodfillGaps() []int
```
GetFloodfillGaps returns bucket indices with insufficient floodfill coverage

#### func (*AdaptiveStrategy) GetStats

```go
func (s *AdaptiveStrategy) GetStats() StrategyStats
```
GetStats returns current strategy statistics

#### func (*AdaptiveStrategy) ShouldExplore

```go
func (s *AdaptiveStrategy) ShouldExplore(netdbSize int) bool
```
ShouldExplore determines if exploration is needed

#### func (*AdaptiveStrategy) UpdateStats

```go
func (s *AdaptiveStrategy) UpdateStats(db NetworkDatabase, ourHash common.Hash)
```
UpdateStats refreshes bucket statistics from current NetDB state

#### type BucketStats

```go
type BucketStats struct {
	BucketIndex      int // 0-255, representing the leading bit position
	TotalRouters     int // Total routers in this bucket
	FloodfillRouters int // Floodfill routers in this bucket
}
```

BucketStats tracks statistics for a single Kademlia bucket

#### type ClientNetDB

```go
type ClientNetDB struct {
}
```

ClientNetDB provides a client-focused interface to the network database. It
isolates LeaseSet operations from router operations, allowing clients to manage
destination information without exposing router-level concerns.

Design rationale: - Clients only need LeaseSet operations (destinations,
services) - Prevents clients from accessing/modifying router information -
Enables future optimizations specific to client use cases - Clearer separation
of concerns in the codebase

#### func  NewClientNetDB

```go
func NewClientNetDB(db *StdNetDB) *ClientNetDB
```
NewClientNetDB creates a new client-focused network database view. It wraps an
existing StdNetDB and exposes only LeaseSet-related operations.

#### func (*ClientNetDB) Ensure

```go
func (c *ClientNetDB) Ensure() error
```
Ensure verifies that the underlying database resources exist. This should be
called during initialization.

#### func (*ClientNetDB) GetLeaseSet

```go
func (c *ClientNetDB) GetLeaseSet(hash common.Hash) chan lease_set.LeaseSet
```
GetLeaseSet retrieves a LeaseSet by its hash. Returns a channel that yields the
LeaseSet if found, nil if not found or expired.

#### func (*ClientNetDB) GetLeaseSetBytes

```go
func (c *ClientNetDB) GetLeaseSetBytes(hash common.Hash) ([]byte, error)
```
GetLeaseSetBytes retrieves raw LeaseSet data by its hash. Returns the serialized
LeaseSet bytes and any error encountered.

#### func (*ClientNetDB) GetLeaseSetCount

```go
func (c *ClientNetDB) GetLeaseSetCount() int
```
GetLeaseSetCount returns the number of LeaseSets currently stored. This includes
both active and not-yet-expired LeaseSets.

#### func (*ClientNetDB) Path

```go
func (c *ClientNetDB) Path() string
```
Path returns the filesystem path where the database is stored.

#### func (*ClientNetDB) StoreEncryptedLeaseSet

```go
func (c *ClientNetDB) StoreEncryptedLeaseSet(key common.Hash, data []byte, dataType byte) error
```
StoreEncryptedLeaseSet stores an EncryptedLeaseSet in the database. key is the
blinded destination hash, data is the serialized EncryptedLeaseSet, and dataType
should be 5 for EncryptedLeaseSet.

#### func (*ClientNetDB) StoreLeaseSet

```go
func (c *ClientNetDB) StoreLeaseSet(key common.Hash, data []byte, dataType byte) error
```
StoreLeaseSet stores a LeaseSet in the database. key is the destination hash,
data is the serialized LeaseSet, and dataType indicates the LeaseSet type (1 for
standard LeaseSet).

#### func (*ClientNetDB) StoreLeaseSet2

```go
func (c *ClientNetDB) StoreLeaseSet2(key common.Hash, data []byte, dataType byte) error
```
StoreLeaseSet2 stores a LeaseSet2 in the database. key is the destination hash,
data is the serialized LeaseSet2, and dataType should be 3 for LeaseSet2.

#### func (*ClientNetDB) StoreMetaLeaseSet

```go
func (c *ClientNetDB) StoreMetaLeaseSet(key common.Hash, data []byte, dataType byte) error
```
StoreMetaLeaseSet stores a MetaLeaseSet in the database. key is the destination
hash, data is the serialized MetaLeaseSet, and dataType should be 7 for
MetaLeaseSet.

#### type DestinationResolver

```go
type DestinationResolver struct {
}
```

DestinationResolver resolves I2P destinations to their encryption public keys.
It looks up LeaseSets from the NetDB and extracts the appropriate encryption key
based on the destination's key type (ElGamal for legacy, X25519 for modern).

#### func  NewDestinationResolver

```go
func NewDestinationResolver(netdb interface {
	GetLeaseSet(hash common.Hash) chan lease_set.LeaseSet
	GetLeaseSetBytes(hash common.Hash) ([]byte, error)
},
) *DestinationResolver
```
NewDestinationResolver creates a new destination resolver with the given NetDB.
The netdb parameter must implement GetLeaseSet and GetLeaseSetBytes methods.

#### func (*DestinationResolver) ResolveDestination

```go
func (dr *DestinationResolver) ResolveDestination(destHash common.Hash) ([32]byte, error)
```
ResolveDestination looks up a destination by its hash and returns the encryption
public key. This supports both legacy LeaseSets (with ElGamal keys) and modern
LeaseSet2 (with X25519 keys).

The resolution process: 1. Look up the LeaseSet from NetDB using the destination
hash 2. Extract the encryption key based on the LeaseSet type 3. Return the key
in [32]byte format suitable for ECIES-X25519-AEAD encryption

Returns: - publicKey: The X25519 public key for garlic encryption (32 bytes) -
error: Non-nil if the destination cannot be resolved or has an unsupported key
type

#### type Entry

```go
type Entry struct {
	*router_info.RouterInfo
	*lease_set.LeaseSet
	*lease_set2.LeaseSet2
	*encrypted_leaseset.EncryptedLeaseSet
	*meta_leaseset.MetaLeaseSet
}
```

netdb entry wraps a router info, lease set, lease set2, encrypted lease set, or
meta lease set and provides serialization

#### func (*Entry) ReadFrom

```go
func (e *Entry) ReadFrom(r io.Reader) (err error)
```

#### func (*Entry) WriteTo

```go
func (e *Entry) WriteTo(w io.Writer) error
```
WriteTo writes the Entry to the provided writer.

#### type ExplorationStrategy

```go
type ExplorationStrategy interface {
	// GenerateExplorationKeys generates hashes to explore based on strategy
	GenerateExplorationKeys(count int) ([]common.Hash, error)

	// ShouldExplore determines if exploration is needed based on NetDB state
	ShouldExplore(netdbSize int) bool

	// UpdateStats updates strategy state based on current NetDB
	UpdateStats(db NetworkDatabase, ourHash common.Hash)

	// GetStats returns current strategy statistics
	GetStats() StrategyStats
}
```

ExplorationStrategy defines an interface for different exploration approaches

#### type Explorer

```go
type Explorer struct {
}
```

Explorer handles periodic database exploration to discover new routers. Database
exploration sends DatabaseLookup messages with the exploration flag to discover
non-floodfill routers and expand NetDB knowledge.

#### func  NewExplorer

```go
func NewExplorer(db NetworkDatabase, pool *tunnel.Pool, config ExplorerConfig) *Explorer
```
NewExplorer creates a new database explorer. The explorer performs periodic
lookups to discover new routers and expand the NetDB beyond just floodfill
routers.

#### func (*Explorer) ExploreOnce

```go
func (e *Explorer) ExploreOnce() error
```
ExploreOnce performs a single exploration round and returns immediately. Useful
for testing or manual exploration triggers.

#### func (*Explorer) GetStats

```go
func (e *Explorer) GetStats() ExplorerStats
```
GetStats returns statistics about exploration activity

#### func (*Explorer) Start

```go
func (e *Explorer) Start() error
```
Start begins periodic database exploration. Exploration runs in a background
goroutine until Stop is called.

#### func (*Explorer) Stop

```go
func (e *Explorer) Stop()
```
Stop halts database exploration and waits for in-flight lookups to complete.

#### type ExplorerConfig

```go
type ExplorerConfig struct {
	// Interval between exploration rounds (default: 5 minutes)
	Interval time.Duration

	// MinInterval is the minimum exploration interval when NetDB is sparse (default: 1 minute)
	MinInterval time.Duration

	// MaxInterval is the maximum exploration interval when NetDB is healthy (default: 15 minutes)
	MaxInterval time.Duration

	// Number of concurrent exploration lookups (default: 3)
	Concurrency int

	// Timeout for individual lookups (default: 30 seconds)
	LookupTimeout time.Duration

	// UseAdaptive enables adaptive exploration strategy (default: true)
	// When true, uses bucket-aware exploration targeting sparse regions
	// When false, uses simple random exploration
	UseAdaptive bool

	// OurHash is our router's identity hash for bucket calculations
	// Required for adaptive strategy
	OurHash common.Hash

	// StatsUpdateInterval determines how often to update strategy statistics (default: 1 minute)
	StatsUpdateInterval time.Duration
}
```

ExplorerConfig holds configuration for database exploration

#### func  DefaultExplorerConfig

```go
func DefaultExplorerConfig() ExplorerConfig
```
DefaultExplorerConfig returns the default explorer configuration

#### type ExplorerStats

```go
type ExplorerStats struct {
	Interval         time.Duration
	Concurrency      int
	LookupTimeout    time.Duration
	IsRunning        bool
	UseAdaptive      bool
	TotalRouters     int
	FloodfillRouters int
	SparseBuckets    int
	EmptyBuckets     int
}
```

ExplorerStats contains statistics about explorer activity

#### type KademliaResolver

```go
type KademliaResolver struct {
	// netdb to store result into
	NetworkDatabase
}
```

resolves router infos with recursive kademlia lookup

#### func (*KademliaResolver) Lookup

```go
func (kr *KademliaResolver) Lookup(h common.Hash, timeout time.Duration) (*router_info.RouterInfo, error)
```

#### type LeaseSetEntry

```go
type LeaseSetEntry struct {
	Hash  common.Hash // Hash of the LeaseSet destination
	Entry Entry       // The actual LeaseSet entry (can be LeaseSet, LeaseSet2, EncryptedLeaseSet, or MetaLeaseSet)
}
```

LeaseSetEntry represents a LeaseSet with its hash for iteration. Used by
GetAllLeaseSets() to return all LeaseSets stored in the database.

#### type NetworkDatabase

```go
type NetworkDatabase interface {
	// obtain a RouterInfo by its hash locally
	// return a channel that yields the RouterInfo if found locally
	// return nil if the RouterInfo cannot be found locally
	GetRouterInfo(hash common.Hash) chan router_info.RouterInfo

	// obtain all routerInfos, ordered by their hash
	// return a slice of routerInfos
	GetAllRouterInfos() []router_info.RouterInfo

	// store a router info locally
	StoreRouterInfo(ri router_info.RouterInfo)

	// try obtaining more peers with a bootstrap instance until we get minRouters number of router infos
	// returns error if bootstrap.GetPeers returns an error otherwise returns nil
	Reseed(b bootstrap.Bootstrap, minRouters int) error

	// return how many router infos we have
	Size() int

	// Recaculate size of netdb from backend
	RecalculateSize() error

	// ensure underlying resources exist , i.e. directories, files, configs
	Ensure() error

	// SelectFloodfillRouters selects the closest floodfill routers to a target hash
	// using Kademlia XOR distance metric. Returns up to 'count' closest floodfills.
	SelectFloodfillRouters(targetHash common.Hash, count int) ([]router_info.RouterInfo, error)

	// GetLeaseSetCount returns the number of LeaseSets stored in the database
	GetLeaseSetCount() int

	// GetAllLeaseSets returns all LeaseSets currently stored in the database.
	// Returns a slice containing all LeaseSet entries (LeaseSet, LeaseSet2, EncryptedLeaseSet, MetaLeaseSet).
	// This is used for publishing all LeaseSets to floodfill routers.
	GetAllLeaseSets() []LeaseSetEntry
}
```

Moved from: netdb.go i2p network database, storage of i2p RouterInfos

#### type PeerStats

```go
type PeerStats struct {
	Hash              common.Hash
	SuccessCount      int
	FailureCount      int
	LastSuccess       time.Time
	LastFailure       time.Time
	LastAttempt       time.Time
	ConsecutiveFails  int
	TotalAttempts     int
	AvgResponseTimeMs int64
}
```

PeerStats tracks connection success/failure statistics for a peer. HIGH PRIORITY
FIX #3: Stale peer detection through connection tracking.

#### type PeerTracker

```go
type PeerTracker struct {
}
```

PeerTracker maintains reputation/connectivity statistics for peers. Helps
identify stale peers and prioritize reliable ones for tunnel building. HIGH
PRIORITY FIX #3: Infrastructure for peer reputation scoring.

#### func  NewPeerTracker

```go
func NewPeerTracker() *PeerTracker
```
NewPeerTracker creates a new peer tracking system.

#### func (*PeerTracker) GetReliablePeers

```go
func (pt *PeerTracker) GetReliablePeers(minAttempts int) []common.Hash
```
GetReliablePeers returns a list of peer hashes that are considered reliable.
Reliable peers have: success rate >= 75%, or recent successful connections.

#### func (*PeerTracker) GetStats

```go
func (pt *PeerTracker) GetStats(hash common.Hash) *PeerStats
```
GetStats retrieves statistics for a peer.

#### func (*PeerTracker) GetSuccessRate

```go
func (pt *PeerTracker) GetSuccessRate(hash common.Hash) float64
```
GetSuccessRate calculates the connection success rate for a peer. Returns a
value between 0.0 and 1.0, or -1.0 if no attempts recorded.

#### func (*PeerTracker) GetSummary

```go
func (pt *PeerTracker) GetSummary() map[string]interface{}
```
GetSummary returns overall tracking statistics.

#### func (*PeerTracker) IsLikelyStale

```go
func (pt *PeerTracker) IsLikelyStale(hash common.Hash) bool
```
IsLikelyStale determines if a peer is likely offline/stale based on failure
patterns. A peer is considered stale if: - It has 3+ consecutive failures, OR -
Success rate < 25% with at least 5 attempts, OR - No successful connection in
last hour with recent failures

#### func (*PeerTracker) PruneOldEntries

```go
func (pt *PeerTracker) PruneOldEntries(maxAge time.Duration) int
```
PruneOldEntries removes tracking data for peers not seen recently. Helps prevent
unbounded memory growth.

#### func (*PeerTracker) RecordAttempt

```go
func (pt *PeerTracker) RecordAttempt(hash common.Hash)
```
RecordAttempt records a connection attempt to a peer.

#### func (*PeerTracker) RecordFailure

```go
func (pt *PeerTracker) RecordFailure(hash common.Hash, reason string)
```
RecordFailure records a failed connection attempt to a peer.

#### func (*PeerTracker) RecordSuccess

```go
func (pt *PeerTracker) RecordSuccess(hash common.Hash, responseTimeMs int64)
```
RecordSuccess records a successful connection to a peer.

#### type Publisher

```go
type Publisher struct {
}
```

Publisher handles publishing RouterInfo and LeaseSets to floodfill routers.
Publishing ensures that our router and client destinations can be found by other
routers in the network.

#### func  NewPublisher

```go
func NewPublisher(db NetworkDatabase, pool *tunnel.Pool, transport TransportManager, routerInfoProvider RouterInfoProvider, config PublisherConfig) *Publisher
```
NewPublisher creates a new database publisher. The publisher periodically
distributes RouterInfo and LeaseSets to the closest floodfill routers based on
Kademlia XOR distance.

Parameters:

    - db: NetworkDatabase for floodfill router selection
    - pool: Tunnel pool for sending DatabaseStore messages (can be nil initially)
    - transport: TransportManager for sending I2NP messages to gateway routers (can be nil initially)
    - routerInfoProvider: Provider for accessing local RouterInfo (can be nil if not publishing RouterInfo)
    - config: Publisher configuration (intervals, floodfill count)

#### func (*Publisher) GetStats

```go
func (p *Publisher) GetStats() PublisherStats
```
GetStats returns statistics about publishing activity

#### func (*Publisher) PublishLeaseSet

```go
func (p *Publisher) PublishLeaseSet(hash common.Hash, ls lease_set.LeaseSet) error
```
PublishLeaseSet publishes a specific LeaseSet to floodfill routers. This is the
main publishing logic that sends DatabaseStore messages to the closest floodfill
routers.

#### func (*Publisher) PublishRouterInfo

```go
func (p *Publisher) PublishRouterInfo(ri router_info.RouterInfo) error
```
PublishRouterInfo publishes a specific RouterInfo to floodfill routers

#### func (*Publisher) SetTransport

```go
func (p *Publisher) SetTransport(transport TransportManager)
```
SetTransport sets the transport manager after publisher creation. This allows
the transport to be configured after initial publisher setup.

#### func (*Publisher) Start

```go
func (p *Publisher) Start() error
```
Start begins periodic publishing of RouterInfo and LeaseSets. Publishing runs in
background goroutines until Stop is called.

#### func (*Publisher) Stop

```go
func (p *Publisher) Stop()
```
Stop halts database publishing and waits for in-flight publishes to complete.

#### type PublisherConfig

```go
type PublisherConfig struct {
	// RouterInfoInterval is how often to republish our RouterInfo (default: 30 minutes)
	RouterInfoInterval time.Duration

	// LeaseSetInterval is how often to republish LeaseSets (default: 5 minutes)
	LeaseSetInterval time.Duration

	// FloodfillCount is how many closest floodfills to publish to (default: 4)
	FloodfillCount int
}
```

PublisherConfig holds configuration for database publishing

#### func  DefaultPublisherConfig

```go
func DefaultPublisherConfig() PublisherConfig
```
DefaultPublisherConfig returns the default publisher configuration

#### type PublisherStats

```go
type PublisherStats struct {
	RouterInfoInterval time.Duration
	LeaseSetInterval   time.Duration
	FloodfillCount     int
	IsRunning          bool
}
```

PublisherStats contains statistics about publisher activity

#### type Resolver

```go
type Resolver interface {
	// resolve a router info by hash
	// return a chan that yields the found RouterInfo or nil if it could not be found after timeout
	Lookup(hash common.Hash, timeout time.Duration) (*router_info.RouterInfo, error)
}
```

Moved from: netdb.go resolves unknown RouterInfos given the hash of their
RouterIdentity

#### func  NewKademliaResolver

```go
func NewKademliaResolver(netDb NetworkDatabase, pool *tunnel.Pool) (r Resolver)
```
Moved from: kad.go NewKademliaResolver creates a new resolver that stores result
into a NetworkDatabase and uses a tunnel pool for the lookup

#### type RouterInfoProvider

```go
type RouterInfoProvider interface {
	// GetRouterInfo returns the current RouterInfo for this router.
	// Returns an error if the RouterInfo cannot be constructed or retrieved.
	GetRouterInfo() (*router_info.RouterInfo, error)
}
```

RouterInfoProvider provides access to the local router's RouterInfo. This
interface allows the Publisher to get the current RouterInfo without tight
coupling to the router implementation, enabling easier testing.

#### type RouterNetDB

```go
type RouterNetDB struct {
}
```

RouterNetDB provides a router-focused interface to the network database. It
handles both RouterInfo operations (for routing/peer discovery) and LeaseSet
operations (for all direct router database operations), isolating these from
client operations.

Design rationale: - Routers need RouterInfo for peer discovery and routing
decisions - Routers also need LeaseSet storage/retrieval for direct operations
(floodfill, detached lookups, etc.) - Prevents accidental mixing of router-wide
and client-specific operations - Enables future optimizations specific to router
use cases

#### func  NewRouterNetDB

```go
func NewRouterNetDB(db *StdNetDB) *RouterNetDB
```
NewRouterNetDB creates a new router-focused network database view. It wraps an
existing StdNetDB and exposes only RouterInfo-related operations.

#### func (*RouterNetDB) Ensure

```go
func (r *RouterNetDB) Ensure() error
```
Ensure verifies that the underlying database resources exist. This should be
called during initialization.

#### func (*RouterNetDB) GetAllRouterInfos

```go
func (r *RouterNetDB) GetAllRouterInfos() []router_info.RouterInfo
```
GetAllRouterInfos retrieves all RouterInfo entries from the database. Returns a
slice of RouterInfo entries ordered by hash.

#### func (*RouterNetDB) GetLeaseSet

```go
func (r *RouterNetDB) GetLeaseSet(hash common.Hash) chan lease_set.LeaseSet
```
GetLeaseSet retrieves a LeaseSet by its hash for direct router operations.
Returns a channel that yields the LeaseSet if found, nil if not found or
expired.

#### func (*RouterNetDB) GetLeaseSetBytes

```go
func (r *RouterNetDB) GetLeaseSetBytes(hash common.Hash) ([]byte, error)
```
GetLeaseSetBytes retrieves raw LeaseSet data by its hash for direct router
operations. Returns the serialized LeaseSet bytes and any error encountered.

#### func (*RouterNetDB) GetLeaseSetCount

```go
func (r *RouterNetDB) GetLeaseSetCount() int
```
GetLeaseSetCount returns the number of LeaseSets currently stored.

#### func (*RouterNetDB) GetRouterInfo

```go
func (r *RouterNetDB) GetRouterInfo(hash common.Hash) chan router_info.RouterInfo
```
GetRouterInfo retrieves a RouterInfo by its hash. Returns a channel that yields
the RouterInfo if found, nil if not found.

#### func (*RouterNetDB) GetRouterInfoBytes

```go
func (r *RouterNetDB) GetRouterInfoBytes(hash common.Hash) ([]byte, error)
```
GetRouterInfoBytes retrieves raw RouterInfo data by its hash. Returns the
serialized RouterInfo bytes and any error encountered.

#### func (*RouterNetDB) GetRouterInfoCount

```go
func (r *RouterNetDB) GetRouterInfoCount() int
```
GetRouterInfoCount returns the number of RouterInfo entries currently stored.

#### func (*RouterNetDB) Path

```go
func (r *RouterNetDB) Path() string
```
Path returns the filesystem path where the database is stored.

#### func (*RouterNetDB) RecalculateSize

```go
func (r *RouterNetDB) RecalculateSize() error
```
RecalculateSize recalculates the cached size of the network database.

#### func (*RouterNetDB) Reseed

```go
func (r *RouterNetDB) Reseed(b bootstrap.Bootstrap, minRouters int) error
```
Reseed attempts to populate the database with RouterInfo entries using a
bootstrap instance. It continues until minRouters number of entries are
obtained.

#### func (*RouterNetDB) SelectFloodfillRouters

```go
func (r *RouterNetDB) SelectFloodfillRouters(targetHash common.Hash, count int) ([]router_info.RouterInfo, error)
```
SelectFloodfillRouters selects the closest floodfill routers to a target hash.
Used for LeaseSet and RouterInfo distribution via the DHT.

#### func (*RouterNetDB) SelectPeers

```go
func (r *RouterNetDB) SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error)
```
SelectPeers selects peer RouterInfos for tunnel building based on various
criteria. Returns a slice of RouterInfo entries suitable for tunnel
construction.

#### func (*RouterNetDB) Size

```go
func (r *RouterNetDB) Size() int
```
Size returns the number of RouterInfo entries in the database.

#### func (*RouterNetDB) StoreEncryptedLeaseSet

```go
func (r *RouterNetDB) StoreEncryptedLeaseSet(key common.Hash, data []byte, dataType byte) error
```
StoreEncryptedLeaseSet stores an EncryptedLeaseSet in the database from direct
router operations. key is the blinded destination hash, data is the serialized
EncryptedLeaseSet, and dataType should be 5 for EncryptedLeaseSet.

#### func (*RouterNetDB) StoreLeaseSet

```go
func (r *RouterNetDB) StoreLeaseSet(key common.Hash, data []byte, dataType byte) error
```
StoreLeaseSet stores a LeaseSet in the database from direct router operations.
key is the destination hash, data is the serialized LeaseSet, and dataType
indicates the LeaseSet type (1 for standard LeaseSet).

#### func (*RouterNetDB) StoreLeaseSet2

```go
func (r *RouterNetDB) StoreLeaseSet2(key common.Hash, data []byte, dataType byte) error
```
StoreLeaseSet2 stores a LeaseSet2 in the database from direct router operations.
key is the destination hash, data is the serialized LeaseSet2, and dataType
should be 3 for LeaseSet2.

#### func (*RouterNetDB) StoreMetaLeaseSet

```go
func (r *RouterNetDB) StoreMetaLeaseSet(key common.Hash, data []byte, dataType byte) error
```
StoreMetaLeaseSet stores a MetaLeaseSet in the database from direct router
operations. key is the destination hash, data is the serialized MetaLeaseSet,
and dataType should be 7 for MetaLeaseSet.

#### func (*RouterNetDB) StoreRouterInfo

```go
func (r *RouterNetDB) StoreRouterInfo(key common.Hash, data []byte, dataType byte) error
```
StoreRouterInfo stores a RouterInfo entry in the database. key is the router
identity hash, data is the serialized RouterInfo, and dataType should be 0 for
RouterInfo.

#### type StdNetDB

```go
type StdNetDB struct {
	DB          string
	RouterInfos map[common.Hash]Entry

	LeaseSets map[common.Hash]Entry

	// HIGH PRIORITY FIX #3: Peer connection tracking and reputation
	PeerTracker *PeerTracker // tracks connection success/failure for peers
}
```

standard network database implementation using local filesystem skiplist

#### func  NewStdNetDB

```go
func NewStdNetDB(db string) *StdNetDB
```

#### func (*StdNetDB) CheckFilePathValid

```go
func (db *StdNetDB) CheckFilePathValid(fpath string) bool
```

#### func (*StdNetDB) Create

```go
func (db *StdNetDB) Create() (err error)
```
create base network database directory

#### func (*StdNetDB) Ensure

```go
func (db *StdNetDB) Ensure() (err error)
```
ensure that the network database exists and load existing RouterInfos

#### func (*StdNetDB) Exists

```go
func (db *StdNetDB) Exists() bool
```
return true if the network db directory exists and is writable

#### func (*StdNetDB) GetActivePeerCount

```go
func (db *StdNetDB) GetActivePeerCount() int
```
GetActivePeerCount returns the number of peers with successful connections in
the last hour. Active peers are those we have successfully communicated with
recently, indicating they are currently online and reachable. This is useful for
monitoring network connectivity and determining the health of our peer
connections.

#### func (*StdNetDB) GetAllLeaseSets

```go
func (db *StdNetDB) GetAllLeaseSets() []LeaseSetEntry
```
GetAllLeaseSets returns all LeaseSets currently stored in the database. This
includes all types: LeaseSet, LeaseSet2, EncryptedLeaseSet, and MetaLeaseSet.
The method returns a slice of LeaseSetEntry containing the hash and Entry data.
This is primarily used for publishing all LeaseSets to floodfill routers.

#### func (*StdNetDB) GetAllRouterInfos

```go
func (db *StdNetDB) GetAllRouterInfos() (ri []router_info.RouterInfo)
```

#### func (*StdNetDB) GetEncryptedLeaseSet

```go
func (db *StdNetDB) GetEncryptedLeaseSet(hash common.Hash) (chnl chan encrypted_leaseset.EncryptedLeaseSet)
```
GetEncryptedLeaseSet retrieves an EncryptedLeaseSet from the database by its
hash. Returns a channel that yields the EncryptedLeaseSet or nil if not found.
Checks memory cache first, then loads from filesystem if necessary.

#### func (*StdNetDB) GetEncryptedLeaseSetBytes

```go
func (db *StdNetDB) GetEncryptedLeaseSetBytes(hash common.Hash) ([]byte, error)
```
GetEncryptedLeaseSetBytes retrieves EncryptedLeaseSet data as bytes from the
database. Checks memory cache first, then loads from filesystem if necessary.
Returns serialized EncryptedLeaseSet bytes suitable for network transmission.

#### func (*StdNetDB) GetFastPeerCount

```go
func (db *StdNetDB) GetFastPeerCount() int
```
GetFastPeerCount returns the number of peers with low latency (fast response
times). Fast peers are those with average response times under 500ms, making
them good candidates for tunnel building and high-performance operations.

Classification criteria:

    - Average response time < 500ms
    - Minimum 3 successful connections for statistical significance

#### func (*StdNetDB) GetHighCapacityPeerCount

```go
func (db *StdNetDB) GetHighCapacityPeerCount() int
```
GetHighCapacityPeerCount returns the number of high-capacity peers.
High-capacity peers are reliable routers with good performance and high
availability, making them excellent candidates for important roles like tunnel
building.

Classification criteria:

    - Success rate >= 80%
    - Minimum 5 connection attempts for statistical significance
    - Average response time < 1000ms (1 second)
    - Not marked as stale

#### func (*StdNetDB) GetLeaseSet

```go
func (db *StdNetDB) GetLeaseSet(hash common.Hash) (chnl chan lease_set.LeaseSet)
```
GetLeaseSet retrieves a LeaseSet from the database by its hash. Returns a
channel that yields the LeaseSet or nil if not found. Checks memory cache first,
then loads from filesystem if necessary.

#### func (*StdNetDB) GetLeaseSet2

```go
func (db *StdNetDB) GetLeaseSet2(hash common.Hash) (chnl chan lease_set2.LeaseSet2)
```
GetLeaseSet2 retrieves a LeaseSet2 from the database by its hash. Returns a
channel that yields the LeaseSet2 or nil if not found. Checks memory cache
first, then loads from filesystem if necessary.

#### func (*StdNetDB) GetLeaseSet2Bytes

```go
func (db *StdNetDB) GetLeaseSet2Bytes(hash common.Hash) ([]byte, error)
```
GetLeaseSet2Bytes retrieves LeaseSet2 data as bytes from the database. Checks
memory cache first, then loads from filesystem if necessary. Returns serialized
LeaseSet2 bytes suitable for network transmission.

#### func (*StdNetDB) GetLeaseSetBytes

```go
func (db *StdNetDB) GetLeaseSetBytes(hash common.Hash) ([]byte, error)
```
GetLeaseSetBytes retrieves LeaseSet data as bytes from the database. Checks
memory cache first, then loads from filesystem if necessary. Returns serialized
LeaseSet bytes suitable for network transmission.

#### func (*StdNetDB) GetLeaseSetCount

```go
func (db *StdNetDB) GetLeaseSetCount() int
```
GetLeaseSetCount returns the total number of LeaseSet entries in memory cache.

#### func (*StdNetDB) GetLeaseSetExpirationStats

```go
func (db *StdNetDB) GetLeaseSetExpirationStats() (total, expired int, nextExpiry time.Duration)
```
GetLeaseSetExpirationStats returns statistics about LeaseSet expiration
tracking. Returns total count, expired count, and time until next expiration.

#### func (*StdNetDB) GetMetaLeaseSet

```go
func (db *StdNetDB) GetMetaLeaseSet(hash common.Hash) (chnl chan meta_leaseset.MetaLeaseSet)
```
GetMetaLeaseSet retrieves a MetaLeaseSet from the database by its hash. Returns
a channel that yields the MetaLeaseSet or nil if not found. Checks memory cache
first, then loads from filesystem if necessary.

#### func (*StdNetDB) GetMetaLeaseSetBytes

```go
func (db *StdNetDB) GetMetaLeaseSetBytes(hash common.Hash) ([]byte, error)
```
GetMetaLeaseSetBytes retrieves MetaLeaseSet data as bytes from the database.
Checks memory cache first, then loads from filesystem if necessary. Returns
serialized MetaLeaseSet bytes suitable for network transmission.

#### func (*StdNetDB) GetRouterInfo

```go
func (db *StdNetDB) GetRouterInfo(hash common.Hash) (chnl chan router_info.RouterInfo)
```

#### func (*StdNetDB) GetRouterInfoBytes

```go
func (db *StdNetDB) GetRouterInfoBytes(hash common.Hash) ([]byte, error)
```
GetRouterInfoBytes retrieves RouterInfo data as bytes from the database

#### func (*StdNetDB) GetRouterInfoCount

```go
func (db *StdNetDB) GetRouterInfoCount() int
```
GetRouterInfoCount returns the total number of RouterInfo entries in the
database

#### func (*StdNetDB) Path

```go
func (db *StdNetDB) Path() string
```
get netdb path

#### func (*StdNetDB) RecalculateSize

```go
func (db *StdNetDB) RecalculateSize() error
```
RecalculateSize is maintained for interface compatibility. Since Size() now
operates directly on in-memory data, this is a no-op.

#### func (*StdNetDB) Reseed

```go
func (db *StdNetDB) Reseed(b bootstrap.Bootstrap, minRouters int) (err error)
```
reseed if we have less than minRouters known routers returns error if reseed
failed

#### func (*StdNetDB) Save

```go
func (db *StdNetDB) Save() (err error)
```

#### func (*StdNetDB) SaveEntry

```go
func (db *StdNetDB) SaveEntry(e *Entry) (err error)
```

#### func (*StdNetDB) SelectFloodfillRouters

```go
func (db *StdNetDB) SelectFloodfillRouters(targetHash common.Hash, count int) ([]router_info.RouterInfo, error)
```
SelectFloodfillRouters selects the closest floodfill routers to a target hash
using XOR distance metric (Kademlia-style selection).

This method: 1. Filters all RouterInfos to find only floodfill routers (caps
contains 'f') 2. Calculates XOR distance between target hash and each floodfill
router 3. Returns up to 'count' closest floodfill routers sorted by distance

Parameters:

    - targetHash: The hash to find closest floodfill routers to (e.g., LeaseSet hash)
    - count: Maximum number of floodfill routers to return

Returns:

    - Slice of RouterInfo for closest floodfill routers (may be less than count if insufficient floodfills available)
    - Error if no floodfill routers are available in NetDB

#### func (*StdNetDB) SelectPeers

```go
func (db *StdNetDB) SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error)
```
SelectPeers selects a random subset of peers for tunnel building Filters out
unreachable routers and excludes specified hashes

#### func (*StdNetDB) Size

```go
func (db *StdNetDB) Size() (routers int)
```
Size returns the count of RouterInfos currently stored in the network database.
This is a direct in-memory count and does not require filesystem access.

#### func (*StdNetDB) SkiplistFile

```go
func (db *StdNetDB) SkiplistFile(hash common.Hash) (fpath string)
```
get the skiplist file that a RouterInfo with this hash would go in

#### func (*StdNetDB) SkiplistFileForLeaseSet

```go
func (db *StdNetDB) SkiplistFileForLeaseSet(hash common.Hash) string
```
SkiplistFileForLeaseSet generates the skiplist file path for a LeaseSet
LeaseSets use 'l' prefix instead of 'r' for router infos

#### func (*StdNetDB) StartExpirationCleaner

```go
func (db *StdNetDB) StartExpirationCleaner()
```
StartExpirationCleaner starts a background goroutine that periodically removes
expired LeaseSets. The cleanup runs every minute and removes any LeaseSets whose
expiration time has passed. This method should be called once during NetDB
initialization. Use Stop() to gracefully shut down the cleanup goroutine.

#### func (*StdNetDB) Stop

```go
func (db *StdNetDB) Stop()
```
Stop gracefully shuts down the expiration cleaner goroutine. Blocks until the
cleanup goroutine has exited.

#### func (*StdNetDB) StoreEncryptedLeaseSet

```go
func (db *StdNetDB) StoreEncryptedLeaseSet(key common.Hash, data []byte, dataType byte) error
```
StoreEncryptedLeaseSet stores an EncryptedLeaseSet entry in the database from
I2NP DatabaseStore message. This method validates, parses, caches, and persists
EncryptedLeaseSet data. dataType should be 5 for EncryptedLeaseSet (matching I2P
protocol specification).

#### func (*StdNetDB) StoreLeaseSet

```go
func (db *StdNetDB) StoreLeaseSet(key common.Hash, data []byte, dataType byte) error
```
StoreLeaseSet stores a LeaseSet entry in the database from I2NP DatabaseStore
message. This method validates, parses, caches, and persists LeaseSet data.
dataType should be 1 for standard LeaseSets (matching I2P protocol
specification).

#### func (*StdNetDB) StoreLeaseSet2

```go
func (db *StdNetDB) StoreLeaseSet2(key common.Hash, data []byte, dataType byte) error
```
StoreLeaseSet2 stores a LeaseSet2 entry in the database from I2NP DatabaseStore
message. This method validates, parses, caches, and persists LeaseSet2 data.
dataType should be 3 for LeaseSet2 (matching I2P protocol specification).

#### func (*StdNetDB) StoreMetaLeaseSet

```go
func (db *StdNetDB) StoreMetaLeaseSet(key common.Hash, data []byte, dataType byte) error
```
StoreMetaLeaseSet stores a MetaLeaseSet entry in the database from I2NP
DatabaseStore message. This method validates, parses, caches, and persists
MetaLeaseSet data. dataType should be 7 for MetaLeaseSet (matching I2P protocol
specification).

#### func (*StdNetDB) StoreRouterInfo

```go
func (db *StdNetDB) StoreRouterInfo(key common.Hash, data []byte, dataType byte) error
```
StoreRouterInfo stores a RouterInfo entry in the database from I2NP
DatabaseStore message.

#### type StrategyStats

```go
type StrategyStats struct {
	TotalRouters       int
	FloodfillRouters   int
	SparseBuckets      []int       // Bucket indices with < MinFloodfillsPerBucket floodfills
	EmptyBuckets       []int       // Bucket indices with no routers
	BucketDistribution map[int]int // Bucket index -> router count
}
```

StrategyStats contains statistics about exploration strategy

#### type TransportManager

```go
type TransportManager interface {
	// GetSession obtains a transport session with a router given its RouterInfo.
	// If a session with this router is NOT already made, attempts to create one.
	// Returns an established TransportSession and nil on success.
	// Returns nil and an error on error.
	GetSession(routerInfo router_info.RouterInfo) (TransportSession, error)
}
```

TransportManager provides access to the transport layer for sending I2NP
messages. This interface allows the Publisher to send messages to gateway
routers without tight coupling to the router/transport implementation.

#### type TransportSession

```go
type TransportSession interface {
	// QueueSendI2NP queues an I2NP message to be sent over the session.
	// Will block as long as the send queue is full.
	QueueSendI2NP(msg i2np.I2NPMessage)
}
```

TransportSession represents a session for sending I2NP messages to a router.



netdb 

github.com/go-i2p/go-i2p/lib/netdb

[go-i2p template file](/template.md)
