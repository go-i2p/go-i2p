package netdb

import (
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/lease_set"
	"github.com/go-i2p/logger"
)

// ClientNetDB provides a client-focused interface to the network database.
// It isolates LeaseSet operations from router operations, allowing clients
// to manage destination information without exposing router-level concerns.
//
// Design rationale:
// - Clients only need LeaseSet operations (destinations, services)
// - Prevents clients from accessing/modifying router information
// - Enables future optimizations specific to client use cases
// - Clearer separation of concerns in the codebase
type ClientNetDB struct {
	db *StdNetDB
}

// NewClientNetDB creates a new client-focused network database view.
// It wraps an existing StdNetDB and exposes only LeaseSet-related operations.
func NewClientNetDB(db *StdNetDB) *ClientNetDB {
	log.WithFields(logger.Fields{
		"at":     "NewClientNetDB",
		"reason": "initialization",
	}).Debug("creating new ClientNetDB")
	return &ClientNetDB{
		db: db,
	}
}

// GetLeaseSet retrieves a LeaseSet by its hash.
// Returns a channel that yields the LeaseSet if found, nil if not found or expired.
func (c *ClientNetDB) GetLeaseSet(hash common.Hash) chan lease_set.LeaseSet {
	return c.db.GetLeaseSet(hash)
}

// GetLeaseSetBytes retrieves raw LeaseSet data by its hash.
// Returns the serialized LeaseSet bytes and any error encountered.
func (c *ClientNetDB) GetLeaseSetBytes(hash common.Hash) ([]byte, error) {
	return c.db.GetLeaseSetBytes(hash)
}

// StoreLeaseSet stores a LeaseSet in the database.
// key is the destination hash, data is the serialized LeaseSet,
// and dataType indicates the LeaseSet type (1 for standard LeaseSet).
func (c *ClientNetDB) StoreLeaseSet(key common.Hash, data []byte, dataType byte) error {
	return c.db.StoreLeaseSet(key, data, dataType)
}

// StoreLeaseSet2 stores a LeaseSet2 in the database.
// key is the destination hash, data is the serialized LeaseSet2,
// and dataType should be 3 for LeaseSet2.
func (c *ClientNetDB) StoreLeaseSet2(key common.Hash, data []byte, dataType byte) error {
	return c.db.StoreLeaseSet2(key, data, dataType)
}

// StoreEncryptedLeaseSet stores an EncryptedLeaseSet in the database.
// key is the blinded destination hash, data is the serialized EncryptedLeaseSet,
// and dataType should be 5 for EncryptedLeaseSet.
func (c *ClientNetDB) StoreEncryptedLeaseSet(key common.Hash, data []byte, dataType byte) error {
	return c.db.StoreEncryptedLeaseSet(key, data, dataType)
}

// StoreMetaLeaseSet stores a MetaLeaseSet in the database.
// key is the destination hash, data is the serialized MetaLeaseSet,
// and dataType should be 7 for MetaLeaseSet.
func (c *ClientNetDB) StoreMetaLeaseSet(key common.Hash, data []byte, dataType byte) error {
	return c.db.StoreMetaLeaseSet(key, data, dataType)
}

// GetLeaseSetCount returns the number of LeaseSets currently stored.
// This includes both active and not-yet-expired LeaseSets.
func (c *ClientNetDB) GetLeaseSetCount() int {
	return c.db.GetLeaseSetCount()
}

// Ensure verifies that the underlying database resources exist.
// This should be called during initialization.
func (c *ClientNetDB) Ensure() error {
	return c.db.Ensure()
}

// Path returns the filesystem path where the database is stored.
func (c *ClientNetDB) Path() string {
	return c.db.Path()
}

// StoreOwnLeaseSet stores a session-created LeaseSet for local use only.
// Delegates to the underlying StdNetDB.
func (c *ClientNetDB) StoreOwnLeaseSet(key common.Hash, data []byte, dataType byte) error {
	return c.db.StoreOwnLeaseSet(key, data, dataType)
}

// GetPublicLeaseSets returns only externally-published LeaseSets that can be served
// to external database lookup queries. Delegates to the underlying StdNetDB.
func (c *ClientNetDB) GetPublicLeaseSets() []LeaseSetEntry {
	return c.db.GetPublicLeaseSets()
}

// IsOwnLeaseSet checks if a LeaseSet was created locally by this router's I2CP session.
// Delegates to the underlying StdNetDB.
func (c *ClientNetDB) IsOwnLeaseSet(hash common.Hash) bool {
	return c.db.IsOwnLeaseSet(hash)
}
