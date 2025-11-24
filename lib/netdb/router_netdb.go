package netdb

import (
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/bootstrap"
)

// RouterNetDB provides a router-focused interface to the network database.
// It isolates RouterInfo operations from client operations, allowing the router
// to manage peer information without exposing client-specific concerns.
//
// Design rationale:
// - Routers only need RouterInfo operations (peers, routing, floodfill)
// - Prevents router code from accidentally accessing client LeaseSets
// - Enables future optimizations specific to router use cases
// - Clearer separation between routing and client functionality
type RouterNetDB struct {
	db *StdNetDB
}

// NewRouterNetDB creates a new router-focused network database view.
// It wraps an existing StdNetDB and exposes only RouterInfo-related operations.
func NewRouterNetDB(db *StdNetDB) *RouterNetDB {
	log.Debug("Creating new RouterNetDB")
	return &RouterNetDB{
		db: db,
	}
}

// GetRouterInfo retrieves a RouterInfo by its hash.
// Returns a channel that yields the RouterInfo if found, nil if not found.
func (r *RouterNetDB) GetRouterInfo(hash common.Hash) chan router_info.RouterInfo {
	log.WithField("hash", hash).Debug("RouterNetDB: Getting RouterInfo")
	return r.db.GetRouterInfo(hash)
}

// GetAllRouterInfos retrieves all RouterInfo entries from the database.
// Returns a slice of RouterInfo entries ordered by hash.
func (r *RouterNetDB) GetAllRouterInfos() []router_info.RouterInfo {
	log.Debug("RouterNetDB: Getting all RouterInfos")
	return r.db.GetAllRouterInfos()
}

// StoreRouterInfo stores a RouterInfo entry in the database.
// key is the router identity hash, data is the serialized RouterInfo,
// and dataType should be 0 for RouterInfo.
func (r *RouterNetDB) StoreRouterInfo(key common.Hash, data []byte, dataType byte) error {
	log.WithField("hash", key).Debug("RouterNetDB: Storing RouterInfo")
	return r.db.StoreRouterInfo(key, data, dataType)
}

// GetRouterInfoBytes retrieves raw RouterInfo data by its hash.
// Returns the serialized RouterInfo bytes and any error encountered.
func (r *RouterNetDB) GetRouterInfoBytes(hash common.Hash) ([]byte, error) {
	log.WithField("hash", hash).Debug("RouterNetDB: Getting RouterInfo bytes")
	return r.db.GetRouterInfoBytes(hash)
}

// GetRouterInfoCount returns the number of RouterInfo entries currently stored.
func (r *RouterNetDB) GetRouterInfoCount() int {
	count := r.db.GetRouterInfoCount()
	log.WithField("count", count).Debug("RouterNetDB: RouterInfo count")
	return count
}

// SelectPeers selects peer RouterInfos for tunnel building based on various criteria.
// Returns a slice of RouterInfo entries suitable for tunnel construction.
func (r *RouterNetDB) SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error) {
	log.WithField("count", count).Debug("RouterNetDB: Selecting peers")
	return r.db.SelectPeers(count, exclude)
}

// SelectFloodfillRouters selects the closest floodfill routers to a target hash.
// Used for LeaseSet and RouterInfo distribution via the DHT.
func (r *RouterNetDB) SelectFloodfillRouters(targetHash common.Hash, count int) ([]router_info.RouterInfo, error) {
	log.WithField("target", targetHash).WithField("count", count).Debug("RouterNetDB: Selecting floodfill routers")
	return r.db.SelectFloodfillRouters(targetHash, count)
}

// Reseed attempts to populate the database with RouterInfo entries using a bootstrap instance.
// It continues until minRouters number of entries are obtained.
func (r *RouterNetDB) Reseed(b bootstrap.Bootstrap, minRouters int) error {
	log.WithField("min_routers", minRouters).Debug("RouterNetDB: Reseeding")
	return r.db.Reseed(b, minRouters)
}

// Size returns the number of RouterInfo entries in the database.
func (r *RouterNetDB) Size() int {
	size := r.db.Size()
	log.WithField("size", size).Debug("RouterNetDB: Database size")
	return size
}

// RecalculateSize recalculates the cached size of the network database.
func (r *RouterNetDB) RecalculateSize() error {
	log.Debug("RouterNetDB: Recalculating size")
	return r.db.RecalculateSize()
}

// Ensure verifies that the underlying database resources exist.
// This should be called during initialization.
func (r *RouterNetDB) Ensure() error {
	log.Debug("RouterNetDB: Ensuring database resources")
	return r.db.Ensure()
}

// Path returns the filesystem path where the database is stored.
func (r *RouterNetDB) Path() string {
	return r.db.Path()
}
