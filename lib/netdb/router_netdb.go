package netdb

import (
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
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
//
// RouterNetDB embeds *StdNetDB to inherit all non-overridden methods,
// only overriding Store and StoreFromPeer to add custom dispatch logic.
type RouterNetDB struct {
	*StdNetDB
}

// NewRouterNetDB creates a new router-focused network database view.
// It wraps an existing StdNetDB and exposes all database operations.
func NewRouterNetDB(db *StdNetDB) *RouterNetDB {
	log.WithFields(logger.Fields{
		"at":     "NewRouterNetDB",
		"reason": "initialization",
	}).Debug("creating new RouterNetDB")
	return &RouterNetDB{
		StdNetDB: db,
	}
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
		return r.StdNetDB.StoreRouterInfoFromMessage(key, data, dataType)
	case 1:
		return r.StdNetDB.StoreLeaseSet(key, data, dataType)
	case 3:
		return r.StdNetDB.StoreLeaseSet2(key, data, dataType)
	case 5:
		return r.StdNetDB.StoreEncryptedLeaseSet(key, data, dataType)
	case 7:
		return r.StdNetDB.StoreMetaLeaseSet(key, data, dataType)
	default:
		return oops.Errorf("unknown database store type: %d", dataType)
	}
}

// StoreFromPeer stores a network database entry with source peer context.
// Source is currently used for RouterInfo admission fairness.
func (r *RouterNetDB) StoreFromPeer(key common.Hash, data []byte, dataType byte, source common.Hash) error {
	switch dataType {
	case 0:
		return r.StdNetDB.StoreRouterInfoFromMessageWithSource(key, data, dataType, source)
	default:
		return r.Store(key, data, dataType)
	}
}
