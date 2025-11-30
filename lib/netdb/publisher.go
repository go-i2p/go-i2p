package netdb

import (
	"context"
	"fmt"
	"sync"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/lease_set"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/logger"
)

// Publisher handles publishing RouterInfo and LeaseSets to floodfill routers.
// Publishing ensures that our router and client destinations can be found
// by other routers in the network.
type Publisher struct {
	// netdb for floodfill router selection
	db NetworkDatabase

	// tunnel pool for sending DatabaseStore messages
	pool *tunnel.Pool

	// publishing control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// configuration
	routerInfoInterval time.Duration // how often to republish RouterInfo
	leaseSetInterval   time.Duration // how often to republish LeaseSets
	floodfillCount     int           // how many floodfills to publish to
}

// PublisherConfig holds configuration for database publishing
type PublisherConfig struct {
	// RouterInfoInterval is how often to republish our RouterInfo (default: 30 minutes)
	RouterInfoInterval time.Duration

	// LeaseSetInterval is how often to republish LeaseSets (default: 5 minutes)
	LeaseSetInterval time.Duration

	// FloodfillCount is how many closest floodfills to publish to (default: 4)
	FloodfillCount int
}

// DefaultPublisherConfig returns the default publisher configuration
func DefaultPublisherConfig() PublisherConfig {
	return PublisherConfig{
		RouterInfoInterval: 30 * time.Minute,
		LeaseSetInterval:   5 * time.Minute,
		FloodfillCount:     4,
	}
}

// NewPublisher creates a new database publisher.
// The publisher periodically distributes RouterInfo and LeaseSets to
// the closest floodfill routers based on Kademlia XOR distance.
func NewPublisher(db NetworkDatabase, pool *tunnel.Pool, config PublisherConfig) *Publisher {
	ctx, cancel := context.WithCancel(context.Background())

	return &Publisher{
		db:                 db,
		pool:               pool,
		ctx:                ctx,
		cancel:             cancel,
		routerInfoInterval: config.RouterInfoInterval,
		leaseSetInterval:   config.LeaseSetInterval,
		floodfillCount:     config.FloodfillCount,
	}
}

// Start begins periodic publishing of RouterInfo and LeaseSets.
// Publishing runs in background goroutines until Stop is called.
func (p *Publisher) Start() error {
	if p.pool == nil {
		return fmt.Errorf("tunnel pool required for publishing")
	}

	log.WithFields(logger.Fields{
		"router_info_interval": p.routerInfoInterval,
		"lease_set_interval":   p.leaseSetInterval,
		"floodfill_count":      p.floodfillCount,
	}).Info("Starting database publisher")

	// Start RouterInfo publishing loop
	p.wg.Add(1)
	go p.routerInfoPublishingLoop()

	// Start LeaseSet publishing loop
	p.wg.Add(1)
	go p.leaseSetPublishingLoop()

	return nil
}

// Stop halts database publishing and waits for in-flight publishes to complete.
func (p *Publisher) Stop() {
	log.Info("Stopping database publisher")
	p.cancel()
	p.wg.Wait()
	log.Info("Database publisher stopped")
}

// routerInfoPublishingLoop periodically publishes our RouterInfo
func (p *Publisher) routerInfoPublishingLoop() {
	defer p.wg.Done()

	ticker := time.NewTicker(p.routerInfoInterval)
	defer ticker.Stop()

	// Publish immediately on start
	p.publishOurRouterInfo()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.publishOurRouterInfo()
		}
	}
}

// leaseSetPublishingLoop periodically publishes all LeaseSets
func (p *Publisher) leaseSetPublishingLoop() {
	defer p.wg.Done()

	ticker := time.NewTicker(p.leaseSetInterval)
	defer ticker.Stop()

	// Publish immediately on start
	p.publishAllLeaseSets()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.publishAllLeaseSets()
		}
	}
}

// publishOurRouterInfo publishes our local RouterInfo to floodfill routers
func (p *Publisher) publishOurRouterInfo() {
	// TODO: Get our local RouterInfo from router identity
	// For now, this is a placeholder that logs the intent
	log.Debug("Publishing our RouterInfo (implementation pending)")

	// Implementation would:
	// 1. Get our RouterInfo from router component
	// 2. Calculate hash of our RouterInfo
	// 3. Select closest floodfill routers using SelectFloodfillRouters
	// 4. Send DatabaseStore messages through tunnels to each floodfill
}

// publishAllLeaseSets publishes all LeaseSets in the database
func (p *Publisher) publishAllLeaseSets() {
	log.Debug("Publishing all LeaseSets")

	// Get count of LeaseSets to publish
	count := p.db.GetLeaseSetCount()
	if count == 0 {
		log.Trace("No LeaseSets to publish")
		return
	}

	log.WithField("count", count).Debug("Found LeaseSets to publish")

	// TODO: Iterate through all LeaseSets and publish each one
	// This requires adding a GetAllLeaseSets method to NetworkDatabase interface
	// For now, this logs the intent
}

// PublishLeaseSet publishes a specific LeaseSet to floodfill routers.
// This is the main publishing logic that sends DatabaseStore messages
// to the closest floodfill routers.
func (p *Publisher) PublishLeaseSet(hash common.Hash, ls lease_set.LeaseSet) error {
	log.WithField("hash", fmt.Sprintf("%x", hash[:8])).Debug("Publishing LeaseSet")

	// Validate LeaseSet before attempting serialization
	if err := ls.Validate(); err != nil {
		return fmt.Errorf("invalid LeaseSet: %w", err)
	}

	// Select closest floodfill routers
	floodfills, err := p.selectFloodfillsForPublishing(hash)
	if err != nil {
		return fmt.Errorf("failed to select floodfills: %w", err)
	}

	// Send DatabaseStore message to each selected floodfill
	lsBytes, err := ls.Bytes()
	if err != nil {
		return fmt.Errorf("failed to serialize LeaseSet: %w", err)
	}
	return p.sendDatabaseStoreMessages(hash, lsBytes, floodfills)
}

// PublishRouterInfo publishes a specific RouterInfo to floodfill routers
func (p *Publisher) PublishRouterInfo(ri router_info.RouterInfo) error {
	hash, err := ri.IdentHash()
	if err != nil {
		return fmt.Errorf("failed to get router hash: %w", err)
	}
	log.WithField("hash", fmt.Sprintf("%x", hash[:8])).Debug("Publishing RouterInfo")

	// Select closest floodfill routers
	floodfills, err := p.selectFloodfillsForPublishing(hash)
	if err != nil {
		return fmt.Errorf("failed to select floodfills: %w", err)
	}

	// Send DatabaseStore message to each selected floodfill
	riBytes, err := ri.Bytes()
	if err != nil {
		return fmt.Errorf("failed to serialize RouterInfo: %w", err)
	}
	return p.sendDatabaseStoreMessages(hash, riBytes, floodfills)
}

// selectFloodfillsForPublishing selects the closest floodfills for a given hash
func (p *Publisher) selectFloodfillsForPublishing(hash common.Hash) ([]router_info.RouterInfo, error) {
	floodfills, err := p.db.SelectFloodfillRouters(hash, p.floodfillCount)
	if err != nil {
		log.WithError(err).Error("Failed to select floodfill routers")
		return nil, err
	}

	log.WithFields(logger.Fields{
		"hash":       fmt.Sprintf("%x", hash[:8]),
		"floodfills": len(floodfills),
	}).Debug("Selected floodfill routers for publishing")

	return floodfills, nil
}

// sendDatabaseStoreMessages sends DatabaseStore messages to specified floodfills
func (p *Publisher) sendDatabaseStoreMessages(hash common.Hash, data []byte, floodfills []router_info.RouterInfo) error {
	var wg sync.WaitGroup
	errChan := make(chan error, len(floodfills))

	for _, ff := range floodfills {
		wg.Add(1)
		go func(floodfill router_info.RouterInfo) {
			defer wg.Done()

			if err := p.sendDatabaseStoreToFloodfill(hash, data, floodfill); err != nil {
				errChan <- err
			}
		}(ff)
	}

	wg.Wait()
	close(errChan)

	// Collect any errors
	var errors []error
	for err := range errChan {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		log.WithFields(logger.Fields{
			"hash":   fmt.Sprintf("%x", hash[:8]),
			"errors": len(errors),
			"total":  len(floodfills),
		}).Warn("Some DatabaseStore messages failed to send")
		return fmt.Errorf("failed to send to %d of %d floodfills", len(errors), len(floodfills))
	}

	log.WithFields(logger.Fields{
		"hash":       fmt.Sprintf("%x", hash[:8]),
		"floodfills": len(floodfills),
	}).Debug("Successfully published to all floodfills")

	return nil
}

// sendDatabaseStoreToFloodfill sends a DatabaseStore message to a specific floodfill
func (p *Publisher) sendDatabaseStoreToFloodfill(hash common.Hash, data []byte, floodfill router_info.RouterInfo) error {
	// TODO: Implement actual DatabaseStore message sending through tunnel pool
	// This requires:
	// 1. Creating a DatabaseStore I2NP message
	// 2. Selecting an outbound tunnel from the pool
	// 3. Sending the message through the tunnel to the floodfill router
	// 4. Handling any errors or timeouts

	ffHash, err := floodfill.IdentHash()
	if err != nil {
		return fmt.Errorf("failed to get floodfill hash: %w", err)
	}
	log.WithFields(logger.Fields{
		"data_hash":      fmt.Sprintf("%x", hash[:8]),
		"floodfill_hash": fmt.Sprintf("%x", ffHash[:8]),
	}).Trace("Sending DatabaseStore message to floodfill")

	// Placeholder implementation
	return nil
}

// GetStats returns statistics about publishing activity
func (p *Publisher) GetStats() PublisherStats {
	return PublisherStats{
		RouterInfoInterval: p.routerInfoInterval,
		LeaseSetInterval:   p.leaseSetInterval,
		FloodfillCount:     p.floodfillCount,
		IsRunning:          p.ctx.Err() == nil,
	}
}

// PublisherStats contains statistics about publisher activity
type PublisherStats struct {
	RouterInfoInterval time.Duration
	LeaseSetInterval   time.Duration
	FloodfillCount     int
	IsRunning          bool
}

// Compile-time interface check
var _ interface {
	Start() error
	Stop()
	PublishLeaseSet(hash common.Hash, ls lease_set.LeaseSet) error
	PublishRouterInfo(ri router_info.RouterInfo) error
} = (*Publisher)(nil)
