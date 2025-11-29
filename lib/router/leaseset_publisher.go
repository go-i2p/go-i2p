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
// Process:
// 1. Select closest floodfill routers from NetDB using XOR distance
// 2. Create DatabaseStore I2NP message with the LeaseSet
// 3. Send the message to each floodfill router via existing transport sessions
func (p *LeaseSetPublisher) distributeToNetwork(key common.Hash, data []byte) {
	log.WithFields(logger.Fields{
		"at":  "router.LeaseSetPublisher.distributeToNetwork",
		"key": fmt.Sprintf("%x", key[:8]),
	}).Debug("distributing_leaseset_to_network")

	// Select closest floodfill routers (typically 3-5 routers for redundancy)
	const floodfillCount = 3
	floodfills, err := p.router.StdNetDB.SelectFloodfillRouters(key, floodfillCount)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":    "router.LeaseSetPublisher.distributeToNetwork",
			"key":   fmt.Sprintf("%x", key[:8]),
			"error": err,
		}).Warn("failed_to_select_floodfill_routers")
		return
	}

	// Create DatabaseStore message for network distribution
	// dataType=3 indicates LeaseSet2 (bits 3-0 = 0x03, as per I2NP spec)
	const leaseSet2DataType = 3
	dbStore := i2np.NewDatabaseStore(key, data, leaseSet2DataType)

	// Send to each selected floodfill router
	for _, ffRouter := range floodfills {
		ffHash, _ := ffRouter.IdentHash()
		if err := p.sendToFloodfill(ffHash, dbStore); err != nil {
			log.WithFields(logger.Fields{
				"at":        "router.LeaseSetPublisher.distributeToNetwork",
				"key":       fmt.Sprintf("%x", key[:8]),
				"floodfill": fmt.Sprintf("%x", ffHash[:8]),
				"error":     err,
			}).Warn("failed_to_send_to_floodfill")
			continue
		}

		log.WithFields(logger.Fields{
			"at":        "router.LeaseSetPublisher.distributeToNetwork",
			"key":       fmt.Sprintf("%x", key[:8]),
			"floodfill": fmt.Sprintf("%x", ffHash[:8]),
		}).Debug("leaseset_sent_to_floodfill")
	}

	log.WithFields(logger.Fields{
		"at":                "router.LeaseSetPublisher.distributeToNetwork",
		"key":               fmt.Sprintf("%x", key[:8]),
		"floodfills_sent":   len(floodfills),
		"floodfills_target": floodfillCount,
	}).Info("leaseset_distribution_completed")
}

// sendToFloodfill sends a DatabaseStore message to a specific floodfill router.
// Uses the router's transport layer to send the message via an existing NTCP2 session.
func (p *LeaseSetPublisher) sendToFloodfill(ffHash common.Hash, dbStore *i2np.DatabaseStore) error {
	// Get active session to this floodfill router
	session, err := p.router.GetSessionByHash(ffHash)
	if err != nil {
		return fmt.Errorf("no active session to floodfill router: %w", err)
	}

	// Wrap DatabaseStore in I2NPMessage interface
	msg := i2np.NewBaseI2NPMessage(i2np.I2NP_MESSAGE_TYPE_DATABASE_STORE)
	data, err := dbStore.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal DatabaseStore: %w", err)
	}
	msg.SetData(data)

	// Queue the DatabaseStore message for transmission
	session.QueueSendI2NP(msg)

	return nil
}
