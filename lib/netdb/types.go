package netdb

import (
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/bootstrap"
)

// LeaseSetEntry represents a LeaseSet with its hash for iteration.
// Used by GetAllLeaseSets() to return all LeaseSets stored in the database.
type LeaseSetEntry struct {
	Hash  common.Hash // Hash of the LeaseSet destination
	Entry Entry       // The actual LeaseSet entry (can be LeaseSet, LeaseSet2, EncryptedLeaseSet, or MetaLeaseSet)
}

// Moved from: netdb.go
// resolves unknown RouterInfos given the hash of their RouterIdentity
type Resolver interface {
	// resolve a router info by hash
	// return a chan that yields the found RouterInfo or nil if it could not be found after timeout
	Lookup(hash common.Hash, timeout time.Duration) (*router_info.RouterInfo, error)
}

// Moved from: netdb.go
// i2p network database, storage of i2p RouterInfos
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

	// GetAllLeaseSets returns all LeaseSets currently stored in the database.
	// Returns a slice containing all LeaseSet entries (LeaseSet, LeaseSet2, EncryptedLeaseSet, MetaLeaseSet).
	// This is used for publishing all LeaseSets to floodfill routers.
	GetAllLeaseSets() []LeaseSetEntry
}
