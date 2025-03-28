# netdb
--
    import "github.com/go-i2p/go-i2p/lib/netdb"

![netdb.svg](netdb.svg)



## Usage

```go
const CacheFileName = "sizecache.txt"
```
name of file to hold precomputed size of netdb

#### type Entry

```go
type Entry struct {
	*router_info.RouterInfo
	*lease_set.LeaseSet
}
```

netdb entry wraps a router info and provides serialization

#### func (*Entry) ReadFrom

```go
func (e *Entry) ReadFrom(r io.Reader) (err error)
```

#### func (*Entry) WriteTo

```go
func (e *Entry) WriteTo(w io.Writer) (err error)
```

#### type NetworkDatabase

```go
type NetworkDatabase interface {
	// obtain a RouterInfo by its hash locally
	// return a RouterInfo if we found it locally
	// return nil if the RouterInfo cannot be found locally
	GetRouterInfo(hash common.Hash) router_info.RouterInfo

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
}
```

i2p network database, storage of i2p RouterInfos

#### type Resolver

```go
type Resolver interface {
	// resolve a router info by hash
	// return a chan that yields the found RouterInfo or nil if it could not be found after timeout
	Lookup(hash common.Hash, timeout time.Duration) chan router_info.RouterInfo
}
```

resolves unknown RouterInfos given the hash of their RouterIdentity

#### func  KademliaResolver

```go
func KademliaResolver(netDb NetworkDatabase, pool *tunnel.Pool) (r Resolver)
```
create a new resolver that stores result into a NetworkDatabase and uses a
tunnel pool for the lookup

#### type StdNetDB

```go
type StdNetDB struct {
	DB          string
	RouterInfos map[common.Hash]Entry
	LeaseSets   map[common.Hash]Entry
}
```

standard network database implementation using local filesystem skiplist

#### func  NewStdNetDB

```go
func NewStdNetDB(db string) StdNetDB
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

#### func (*StdNetDB) GetRouterInfo

```go
func (db *StdNetDB) GetRouterInfo(hash common.Hash) (chnl chan router_info.RouterInfo)
```

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



netdb 

github.com/go-i2p/go-i2p/lib/netdb
