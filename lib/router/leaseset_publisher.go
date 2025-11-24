package router

import (
	"fmt"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/logger"
)

// LeaseSetPublisher implements i2cp.LeaseSetPublisher interface.
// It handles publishing LeaseSets to the local NetDB and distributing them
// to the I2P network via DatabaseStore messages.
type LeaseSetPublisher struct {
	router *Router
}

// NewLeaseSetPublisher creates a new LeaseSetPublisher for the given router.
func NewLeaseSetPublisher(r *Router) *LeaseSetPublisher {
	return &LeaseSetPublisher{
		router: r,
	}
}

// PublishLeaseSet publishes a LeaseSet to the network database and I2P network.
// This method:
// 1. Stores the LeaseSet in the local NetDB for local lookups
// 2. Creates a DatabaseStore I2NP message
// 3. Distributes the message to floodfill routers (future enhancement)
//
// Parameters:
//   - key: The destination hash (SHA256 of the destination)
//   - leaseSetData: The serialized LeaseSet2 bytes
//
// Returns an error if local storage fails. Network distribution errors are logged
// but don't cause failure (the LeaseSet is still available locally).
func (p *LeaseSetPublisher) PublishLeaseSet(key common.Hash, leaseSetData []byte) error {
	log.WithFields(logger.Fields{
		"at":   "router.LeaseSetPublisher.PublishLeaseSet",
		"key":  fmt.Sprintf("%x", key[:8]),
		"size": len(leaseSetData),
	}).Debug("publishing_leaseset")

	// Store in local NetDB (dataType=1 indicates LeaseSet)
	if err := p.storeInLocalNetDB(key, leaseSetData); err != nil {
		return fmt.Errorf("failed to store LeaseSet in local NetDB: %w", err)
	}

	// Distribute to network (non-blocking, errors logged but not returned)
	go p.distributeToNetwork(key, leaseSetData)

	log.WithFields(logger.Fields{
		"at":  "router.LeaseSetPublisher.PublishLeaseSet",
		"key": fmt.Sprintf("%x", key[:8]),
	}).Info("leaseset_published")

	return nil
}

// storeInLocalNetDB stores the LeaseSet in the router's local NetDB.
// This makes the LeaseSet immediately available for local lookups.
func (p *LeaseSetPublisher) storeInLocalNetDB(key common.Hash, data []byte) error {
	// dataType=1 indicates LeaseSet (as per I2NP protocol specification)
	const leaseSetDataType = 1

	if err := p.router.StdNetDB.StoreLeaseSet(key, data, leaseSetDataType); err != nil {
		log.WithFields(logger.Fields{
			"at":    "router.LeaseSetPublisher.storeInLocalNetDB",
			"key":   fmt.Sprintf("%x", key[:8]),
			"error": err,
		}).Error("netdb_store_failed")
		return err
	}

	log.WithFields(logger.Fields{
		"at":  "router.LeaseSetPublisher.storeInLocalNetDB",
		"key": fmt.Sprintf("%x", key[:8]),
	}).Debug("leaseset_stored_in_netdb")

	return nil
}

// distributeToNetwork distributes the LeaseSet to floodfill routers on the I2P network.
// This runs asynchronously and logs errors rather than returning them.
//
// Current implementation creates the DatabaseStore message structure.
// Future enhancements will:
// - Select appropriate floodfill routers from NetDB
// - Send DatabaseStore messages via existing transport sessions
// - Handle retry logic for failed distributions
func (p *LeaseSetPublisher) distributeToNetwork(key common.Hash, data []byte) {
	log.WithFields(logger.Fields{
		"at":  "router.LeaseSetPublisher.distributeToNetwork",
		"key": fmt.Sprintf("%x", key[:8]),
	}).Debug("distributing_leaseset_to_network")

	// Create DatabaseStore message for network distribution
	// dataType=1 indicates LeaseSet (bit 0 set, as per I2NP spec)
	const leaseSetDataType = 1
	dbStore := i2np.NewDatabaseStore(key, data, leaseSetDataType)

	// TODO: Select floodfill routers from NetDB
	// For now, we have no floodfill router selection implemented.
	// The LeaseSet is stored locally and available for lookups.
	// Future implementation will:
	// 1. Query NetDB for closest floodfill routers to this key
	// 2. Get active transport sessions to those routers
	// 3. Send DatabaseStore message to each floodfill router
	// 4. Handle responses and retries

	_ = dbStore // Prevent unused variable warning

	log.WithFields(logger.Fields{
		"at":  "router.LeaseSetPublisher.distributeToNetwork",
		"key": fmt.Sprintf("%x", key[:8]),
	}).Debug("network_distribution_deferred")
}
