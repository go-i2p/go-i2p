package i2cp

import (
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/logger"
)

// NetDBStore defines the minimal interface needed for storing LeaseSets in the NetDB.
// This is satisfied by *netdb.StdNetDB.
type NetDBStore interface {
	// StoreLeaseSet stores a LeaseSet in the local network database.
	// dataType indicates the LeaseSet type: 1=LeaseSet, 3=LeaseSet2, 5=Encrypted, 7=Meta.
	StoreLeaseSet(key common.Hash, data []byte, dataType byte) error
}

// NetDBLeaseSetPublisher is a default implementation of LeaseSetPublisher that
// stores LeaseSets in the local NetDB. This provides a concrete publisher for
// I2CP sessions that need their LeaseSets to be discoverable locally.
//
// For full network distribution (sending DatabaseStore messages to floodfill routers),
// an extended implementation should also distribute via I2NP DatabaseStore messages.
type NetDBLeaseSetPublisher struct {
	store    NetDBStore
	dataType byte // LeaseSet type (default: 3 for LeaseSet2)
}

// NewNetDBLeaseSetPublisher creates a new publisher that stores LeaseSets in the given NetDB.
// Uses LeaseSet2 (type 3) by default.
func NewNetDBLeaseSetPublisher(store NetDBStore) *NetDBLeaseSetPublisher {
	return &NetDBLeaseSetPublisher{
		store:    store,
		dataType: 3, // LeaseSet2
	}
}

// NewNetDBLeaseSetPublisherWithType creates a new publisher with a specific LeaseSet data type.
// Valid types: 1 (LeaseSet), 3 (LeaseSet2), 5 (EncryptedLeaseSet), 7 (MetaLeaseSet).
func NewNetDBLeaseSetPublisherWithType(store NetDBStore, dataType byte) *NetDBLeaseSetPublisher {
	return &NetDBLeaseSetPublisher{
		store:    store,
		dataType: dataType,
	}
}

// PublishLeaseSet stores the LeaseSet in the local NetDB.
func (p *NetDBLeaseSetPublisher) PublishLeaseSet(key common.Hash, leaseSetData []byte) error {
	log.WithFields(logger.Fields{
		"at":        "NetDBLeaseSetPublisher.PublishLeaseSet",
		"hash":      key,
		"data_size": len(leaseSetData),
		"data_type": p.dataType,
	}).Debug("Publishing LeaseSet to local NetDB")

	if err := p.store.StoreLeaseSet(key, leaseSetData, p.dataType); err != nil {
		log.WithError(err).WithField("hash", key).Error("Failed to publish LeaseSet to NetDB")
		return err
	}

	log.WithFields(logger.Fields{
		"at":   "NetDBLeaseSetPublisher.PublishLeaseSet",
		"hash": key,
	}).Info("LeaseSet published successfully to local NetDB")
	return nil
}

// Compile-time interface check
var _ LeaseSetPublisher = (*NetDBLeaseSetPublisher)(nil)
