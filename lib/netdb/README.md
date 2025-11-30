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

## Usage

```go
const CacheFileName = "sizecache.txt"
```
Moved from: std.go name of file to hold precomputed size of netdb

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

	// Number of concurrent exploration lookups (default: 3)
	Concurrency int

	// Timeout for individual lookups (default: 30 seconds)
	LookupTimeout time.Duration
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
	Interval      time.Duration
	Concurrency   int
	LookupTimeout time.Duration
	IsRunning     bool
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

#### type NetworkDatabase

```go
type NetworkDatabase interface {
	// obtain a RouterInfo by its hash locally
	// return a RouterInfo if we found it locally
	// return nil if the RouterInfo cannot be found locally
	GetRouterInfo(hash common.Hash) router_info.RouterInfo

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
}
```

Moved from: netdb.go i2p network database, storage of i2p RouterInfos

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
func NewPublisher(db NetworkDatabase, pool *tunnel.Pool, config PublisherConfig) *Publisher
```
NewPublisher creates a new database publisher. The publisher periodically
distributes RouterInfo and LeaseSets to the closest floodfill routers based on
Kademlia XOR distance.

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
ensure that the network database exists

#### func (*StdNetDB) Exists

```go
func (db *StdNetDB) Exists() bool
```
return true if the network db directory exists and is writable

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
func (db *StdNetDB) RecalculateSize() (err error)
```
recalculateSize recalculates cached size of netdb

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
return how many routers we know about in our network database

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



netdb 

github.com/go-i2p/go-i2p/lib/netdb

[go-i2p template file](/template.md)
