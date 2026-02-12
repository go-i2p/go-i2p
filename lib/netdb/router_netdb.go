package netdb

import (
	"fmt"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/lease_set"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/bootstrap"
	"github.com/go-i2p/logger"
)

// RouterNetDB provides a router-focused interface to the network database.
// It handles both RouterInfo operations (for routing/peer discovery) and LeaseSet
// operations (for all direct router database operations), isolating these from client operations.
//
// Design rationale:
// - Routers need RouterInfo for peer discovery and routing decisions
// - Routers also need LeaseSet storage/retrieval for direct operations (floodfill, detached lookups, etc.)
// - Prevents accidental mixing of router-wide and client-specific operations
// - Enables future optimizations specific to router use cases
type RouterNetDB struct {
	db *StdNetDB
}

// NewRouterNetDB creates a new router-focused network database view.
// It wraps an existing StdNetDB and exposes only RouterInfo-related operations.
func NewRouterNetDB(db *StdNetDB) *RouterNetDB {
	log.WithFields(logger.Fields{
		"at":     "NewRouterNetDB",
		"reason": "initialization",
	}).Debug("creating new RouterNetDB")
	return &RouterNetDB{
		db: db,
	}
}

// GetRouterInfo retrieves a RouterInfo by its hash.
// Returns a channel that yields the RouterInfo if found, nil if not found.
func (r *RouterNetDB) GetRouterInfo(hash common.Hash) chan router_info.RouterInfo {
	log.WithFields(logger.Fields{
		"at":     "RouterNetDB.GetRouterInfo",
		"reason": "lookup_requested",
		"hash":   fmt.Sprintf("%x...", hash[:8]),
	}).Debug("getting RouterInfo")
	return r.db.GetRouterInfo(hash)
}

// GetAllRouterInfos retrieves all RouterInfo entries from the database.
// Returns a slice of RouterInfo entries ordered by hash.
func (r *RouterNetDB) GetAllRouterInfos() []router_info.RouterInfo {
	log.Debug("RouterNetDB: Getting all RouterInfos")
	return r.db.GetAllRouterInfos()
}

// Store stores a network database entry, dispatching to the appropriate handler
// based on the data type:
//   - 0: RouterInfo
//   - 1: LeaseSet
//   - 3: LeaseSet2
//   - 5: EncryptedLeaseSet
//   - 7: MetaLeaseSet
func (r *RouterNetDB) Store(key common.Hash, data []byte, dataType byte) error {
	switch dataType {
	case 0:
		log.WithField("hash", key).Debug("RouterNetDB: Storing RouterInfo")
		return r.db.StoreRouterInfoFromMessage(key, data, dataType)
	case 1:
		log.WithField("hash", key).Debug("RouterNetDB: Storing LeaseSet")
		return r.db.StoreLeaseSet(key, data, dataType)
	case 3:
		log.WithField("hash", key).Debug("RouterNetDB: Storing LeaseSet2")
		return r.db.StoreLeaseSet2(key, data, dataType)
	case 5:
		log.WithField("hash", key).Debug("RouterNetDB: Storing EncryptedLeaseSet")
		return r.db.StoreEncryptedLeaseSet(key, data, dataType)
	case 7:
		log.WithField("hash", key).Debug("RouterNetDB: Storing MetaLeaseSet")
		return r.db.StoreMetaLeaseSet(key, data, dataType)
	default:
		return fmt.Errorf("unknown database store type: %d", dataType)
	}
}

// StoreRouterInfoFromMessage stores a RouterInfo entry in the database from an I2NP DatabaseStore message.
// key is the router identity hash, data is the serialized RouterInfo,
// and dataType should be 0 for RouterInfo.
func (r *RouterNetDB) StoreRouterInfoFromMessage(key common.Hash, data []byte, dataType byte) error {
	log.WithField("hash", key).Debug("RouterNetDB: Storing RouterInfo from message")
	return r.db.StoreRouterInfoFromMessage(key, data, dataType)
}

// StoreRouterInfo stores a RouterInfo locally, satisfying the NetworkDatabase interface.
// It delegates to the underlying StdNetDB.StoreRouterInfo.
func (r *RouterNetDB) StoreRouterInfo(ri router_info.RouterInfo) {
	log.Debug("RouterNetDB: Storing RouterInfo")
	r.db.StoreRouterInfo(ri)
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

// ======================================================================
// LeaseSet Operations (for Direct Router Database Operations)
// These handle LeaseSets for floodfill, detached lookups, and direct stores
// ======================================================================

// GetLeaseSet retrieves a LeaseSet by its hash for direct router operations.
// Returns a channel that yields the LeaseSet if found, nil if not found or expired.
func (r *RouterNetDB) GetLeaseSet(hash common.Hash) chan lease_set.LeaseSet {
	log.WithField("hash", hash).Debug("RouterNetDB: Getting LeaseSet for direct operation")
	return r.db.GetLeaseSet(hash)
}

// GetLeaseSetBytes retrieves raw LeaseSet data by its hash for direct router operations.
// Returns the serialized LeaseSet bytes and any error encountered.
func (r *RouterNetDB) GetLeaseSetBytes(hash common.Hash) ([]byte, error) {
	log.WithField("hash", hash).Debug("RouterNetDB: Getting LeaseSet bytes for direct operation")
	return r.db.GetLeaseSetBytes(hash)
}

// GetLeaseSet2Bytes retrieves raw LeaseSet2 data by its hash for direct router operations.
// Returns the serialized LeaseSet2 bytes and any error encountered.
func (r *RouterNetDB) GetLeaseSet2Bytes(hash common.Hash) ([]byte, error) {
	log.WithField("hash", hash).Debug("RouterNetDB: Getting LeaseSet2 bytes for direct operation")
	return r.db.GetLeaseSet2Bytes(hash)
}

// StoreLeaseSet stores a LeaseSet in the database from direct router operations.
// key is the destination hash, data is the serialized LeaseSet,
// and dataType indicates the LeaseSet type (1 for standard LeaseSet).
func (r *RouterNetDB) StoreLeaseSet(key common.Hash, data []byte, dataType byte) error {
	log.WithField("hash", key).Debug("RouterNetDB: Storing LeaseSet from direct operation")
	return r.db.StoreLeaseSet(key, data, dataType)
}

// StoreLeaseSet2 stores a LeaseSet2 in the database from direct router operations.
// key is the destination hash, data is the serialized LeaseSet2,
// and dataType should be 3 for LeaseSet2.
func (r *RouterNetDB) StoreLeaseSet2(key common.Hash, data []byte, dataType byte) error {
	log.WithField("hash", key).Debug("RouterNetDB: Storing LeaseSet2 from direct operation")
	return r.db.StoreLeaseSet2(key, data, dataType)
}

// StoreEncryptedLeaseSet stores an EncryptedLeaseSet in the database from direct router operations.
// key is the blinded destination hash, data is the serialized EncryptedLeaseSet,
// and dataType should be 5 for EncryptedLeaseSet.
func (r *RouterNetDB) StoreEncryptedLeaseSet(key common.Hash, data []byte, dataType byte) error {
	log.WithField("hash", key).Debug("RouterNetDB: Storing EncryptedLeaseSet from direct operation")
	return r.db.StoreEncryptedLeaseSet(key, data, dataType)
}

// StoreMetaLeaseSet stores a MetaLeaseSet in the database from direct router operations.
// key is the destination hash, data is the serialized MetaLeaseSet,
// and dataType should be 7 for MetaLeaseSet.
func (r *RouterNetDB) StoreMetaLeaseSet(key common.Hash, data []byte, dataType byte) error {
	log.WithField("hash", key).Debug("RouterNetDB: Storing MetaLeaseSet from direct operation")
	return r.db.StoreMetaLeaseSet(key, data, dataType)
}

// GetLeaseSetCount returns the number of LeaseSets currently stored.
func (r *RouterNetDB) GetLeaseSetCount() int {
	count := r.db.GetLeaseSetCount()
	log.WithField("count", count).Debug("RouterNetDB: LeaseSet count")
	return count
}
