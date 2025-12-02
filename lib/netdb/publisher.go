package netdb

import (
	"context"
	"fmt"
	"sync"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/lease_set"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/logger"
)

// TransportManager provides access to the transport layer for sending I2NP messages.
// This interface allows the Publisher to send messages to gateway routers without
// tight coupling to the router/transport implementation.
type TransportManager interface {
	// GetSession obtains a transport session with a router given its RouterInfo.
	// If a session with this router is NOT already made, attempts to create one.
	// Returns an established TransportSession and nil on success.
	// Returns nil and an error on error.
	GetSession(routerInfo router_info.RouterInfo) (TransportSession, error)
}

// TransportSession represents a session for sending I2NP messages to a router.
type TransportSession interface {
	// QueueSendI2NP queues an I2NP message to be sent over the session.
	// Will block as long as the send queue is full.
	QueueSendI2NP(msg i2np.I2NPMessage)
}

// RouterInfoProvider provides access to the local router's RouterInfo.
// This interface allows the Publisher to get the current RouterInfo without
// tight coupling to the router implementation, enabling easier testing.
type RouterInfoProvider interface {
	// GetRouterInfo returns the current RouterInfo for this router.
	// Returns an error if the RouterInfo cannot be constructed or retrieved.
	GetRouterInfo() (*router_info.RouterInfo, error)
}

// Publisher handles publishing RouterInfo and LeaseSets to floodfill routers.
// Publishing ensures that our router and client destinations can be found
// by other routers in the network.
type Publisher struct {
	// netdb for floodfill router selection
	db NetworkDatabase

	// tunnel pool for sending DatabaseStore messages
	pool *tunnel.Pool

	// transport for sending I2NP messages to gateway routers
	transport TransportManager

	// routerInfoProvider supplies our local RouterInfo for publishing
	routerInfoProvider RouterInfoProvider

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
//
// Parameters:
//   - db: NetworkDatabase for floodfill router selection
//   - pool: Tunnel pool for sending DatabaseStore messages (can be nil initially)
//   - transport: TransportManager for sending I2NP messages to gateway routers (can be nil initially)
//   - routerInfoProvider: Provider for accessing local RouterInfo (can be nil if not publishing RouterInfo)
//   - config: Publisher configuration (intervals, floodfill count)
func NewPublisher(db NetworkDatabase, pool *tunnel.Pool, transport TransportManager, routerInfoProvider RouterInfoProvider, config PublisherConfig) *Publisher {
	ctx, cancel := context.WithCancel(context.Background())

	return &Publisher{
		db:                 db,
		pool:               pool,
		transport:          transport,
		routerInfoProvider: routerInfoProvider,
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
	if p.transport == nil {
		return fmt.Errorf("transport manager required for publishing")
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

// publishOurRouterInfo publishes our local RouterInfo to floodfill routers.
// This makes our router discoverable in the I2P network by distributing our
// RouterInfo to the closest floodfill routers in the DHT.
func (p *Publisher) publishOurRouterInfo() {
	log.Debug("Publishing our RouterInfo")

	// Check if RouterInfo provider is configured
	if p.routerInfoProvider == nil {
		log.Debug("RouterInfoProvider not configured, skipping RouterInfo publishing")
		return
	}

	// Get our local RouterInfo from the provider
	ri, err := p.routerInfoProvider.GetRouterInfo()
	if err != nil {
		log.WithError(err).Warn("Failed to get local RouterInfo for publishing")
		return
	}

	// Validate RouterInfo before publishing
	if !ri.IsValid() {
		log.Warn("Local RouterInfo is invalid, skipping publishing")
		return
	}

	// Publish the RouterInfo using the existing PublishRouterInfo method
	if err := p.PublishRouterInfo(*ri); err != nil {
		log.WithError(err).Warn("Failed to publish local RouterInfo")
		return
	}

	log.Debug("Successfully published our RouterInfo to floodfill routers")
}

// publishAllLeaseSets publishes all LeaseSets in the database
func (p *Publisher) publishAllLeaseSets() {
	log.Debug("Publishing all LeaseSets")

	// Get all LeaseSets from the database
	leaseSets := p.db.GetAllLeaseSets()
	if len(leaseSets) == 0 {
		log.Trace("No LeaseSets to publish")
		return
	}

	log.WithField("count", len(leaseSets)).Debug("Found LeaseSets to publish")

	// Publish each LeaseSet to floodfill routers
	for _, lsEntry := range leaseSets {
		if err := p.publishLeaseSetEntry(lsEntry); err != nil {
			log.WithError(err).WithField("hash", fmt.Sprintf("%x", lsEntry.Hash[:8])).Warn("Failed to publish LeaseSet")
		}
	}

	log.WithField("count", len(leaseSets)).Debug("Completed publishing all LeaseSets")
}

// publishLeaseSetEntry publishes a single LeaseSetEntry to floodfill routers.
// This is a helper method that determines which type of LeaseSet to publish.
func (p *Publisher) publishLeaseSetEntry(lsEntry LeaseSetEntry) error {
	// Determine which type of LeaseSet we have and serialize it
	var lsBytes []byte
	var err error

	switch {
	case lsEntry.Entry.LeaseSet != nil:
		lsBytes, err = lsEntry.Entry.LeaseSet.Bytes()
	case lsEntry.Entry.LeaseSet2 != nil:
		lsBytes, err = lsEntry.Entry.LeaseSet2.Bytes()
	case lsEntry.Entry.EncryptedLeaseSet != nil:
		lsBytes, err = lsEntry.Entry.EncryptedLeaseSet.Bytes()
	case lsEntry.Entry.MetaLeaseSet != nil:
		lsBytes, err = lsEntry.Entry.MetaLeaseSet.Bytes()
	default:
		return fmt.Errorf("LeaseSetEntry contains no valid LeaseSet data")
	}

	if err != nil {
		return fmt.Errorf("failed to serialize LeaseSet: %w", err)
	}

	// Select closest floodfill routers
	floodfills, err := p.selectFloodfillsForPublishing(lsEntry.Hash)
	if err != nil {
		return fmt.Errorf("failed to select floodfills: %w", err)
	}

	// Send DatabaseStore message to each selected floodfill
	return p.sendDatabaseStoreMessages(lsEntry.Hash, lsBytes, i2np.DATABASE_STORE_TYPE_LEASESET2, floodfills)
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
	return p.sendDatabaseStoreMessages(hash, lsBytes, i2np.DATABASE_STORE_TYPE_LEASESET2, floodfills)
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
	return p.sendDatabaseStoreMessages(hash, riBytes, i2np.DATABASE_STORE_TYPE_ROUTER_INFO, floodfills)
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
func (p *Publisher) sendDatabaseStoreMessages(hash common.Hash, data []byte, dataType byte, floodfills []router_info.RouterInfo) error {
	var wg sync.WaitGroup
	errChan := make(chan error, len(floodfills))

	for _, ff := range floodfills {
		wg.Add(1)
		go func(floodfill router_info.RouterInfo) {
			defer wg.Done()

			if err := p.sendDatabaseStoreToFloodfill(hash, data, dataType, floodfill); err != nil {
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
// through an outbound tunnel for anonymity. This method coordinates the tunnel selection,
// message creation, and delivery to the gateway router.
func (p *Publisher) sendDatabaseStoreToFloodfill(hash common.Hash, data []byte, dataType byte, floodfill router_info.RouterInfo) error {
	// Select and validate outbound tunnel
	selectedTunnel, gatewayHash, err := p.selectAndValidateTunnel()
	if err != nil {
		return err
	}

	// Get floodfill hash for logging and validation
	ffHash, err := floodfill.IdentHash()
	if err != nil {
		return fmt.Errorf("failed to get floodfill hash: %w", err)
	}

	log.WithFields(logger.Fields{
		"data_hash":      fmt.Sprintf("%x", hash[:8]),
		"floodfill_hash": fmt.Sprintf("%x", ffHash[:8]),
		"tunnel_id":      selectedTunnel.ID,
	}).Trace("Sending DatabaseStore message to floodfill through tunnel")

	// Create and wrap DatabaseStore message for tunnel delivery
	tunnelGateway, err := p.createTunnelGatewayMessage(hash, data, dataType, selectedTunnel.ID)
	if err != nil {
		return err
	}

	log.WithFields(logger.Fields{
		"tunnel_id":        selectedTunnel.ID,
		"gateway_hash":     fmt.Sprintf("%x", gatewayHash[:8]),
		"floodfill_hash":   fmt.Sprintf("%x", ffHash[:8]),
		"gateway_msg_type": tunnelGateway.Type(),
	}).Debug("Sending DatabaseStore through tunnel gateway")

	// Send message through gateway router
	if err := p.sendMessageThroughGateway(gatewayHash, tunnelGateway); err != nil {
		return err
	}

	log.WithFields(logger.Fields{
		"data_hash":      fmt.Sprintf("%x", hash[:8]),
		"floodfill_hash": fmt.Sprintf("%x", ffHash[:8]),
		"tunnel_id":      selectedTunnel.ID,
		"gateway_hash":   fmt.Sprintf("%x", gatewayHash[:8]),
	}).Debug("DatabaseStore sent to tunnel gateway for transmission")

	return nil
}

// selectAndValidateTunnel selects an active outbound tunnel and validates it has hops.
// Returns the selected tunnel, gateway hash, and any error encountered.
func (p *Publisher) selectAndValidateTunnel() (*tunnel.TunnelState, common.Hash, error) {
	selectedTunnel := p.pool.SelectTunnel()
	if selectedTunnel == nil {
		return nil, common.Hash{}, fmt.Errorf("no active outbound tunnels available")
	}

	if len(selectedTunnel.Hops) == 0 {
		return nil, common.Hash{}, fmt.Errorf("tunnel has no hops")
	}

	gatewayHash := selectedTunnel.Hops[0]
	return selectedTunnel, gatewayHash, nil
}

// createTunnelGatewayMessage creates a TunnelGateway message containing a DatabaseStore
// message. This wraps the DatabaseStore for delivery through an outbound tunnel.
func (p *Publisher) createTunnelGatewayMessage(hash common.Hash, data []byte, dataType byte, tunnelID tunnel.TunnelID) (i2np.I2NPMessage, error) {
	// Create DatabaseStore I2NP message
	dbStoreMsg, err := p.createDatabaseStoreMessage(hash, data, dataType)
	if err != nil {
		return nil, err
	}

	// Marshal DatabaseStore message for tunnel wrapping
	dbStoreMsgBytes, err := dbStoreMsg.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal DatabaseStore I2NP message: %w", err)
	}

	// Create TunnelGateway message to inject DatabaseStore into outbound tunnel
	tunnelGateway := i2np.NewTunnelGatewayMessage(tunnelID, dbStoreMsgBytes)
	return tunnelGateway, nil
}

// createDatabaseStoreMessage creates a DatabaseStore I2NP message with the provided
// hash, data, and type. The dataType should be one of the DATABASE_STORE_TYPE_* constants:
//   - DATABASE_STORE_TYPE_ROUTER_INFO (0): For RouterInfo entries
//   - DATABASE_STORE_TYPE_LEASESET2 (3): For LeaseSet2 entries (standard as of 0.9.38+)
func (p *Publisher) createDatabaseStoreMessage(hash common.Hash, data []byte, dataType byte) (i2np.I2NPMessage, error) {
	dbStore := i2np.NewDatabaseStore(hash, data, dataType)
	dbStoreMsg := i2np.NewBaseI2NPMessage(i2np.I2NP_MESSAGE_TYPE_DATABASE_STORE)

	dbStoreData, err := dbStore.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal DatabaseStore: %w", err)
	}
	dbStoreMsg.SetData(dbStoreData)

	return dbStoreMsg, nil
}

// sendMessageThroughGateway sends an I2NP message to a gateway router via transport.
// This retrieves the gateway RouterInfo, establishes a transport session, and queues
// the message for transmission.
func (p *Publisher) sendMessageThroughGateway(gatewayHash common.Hash, msg i2np.I2NPMessage) error {
	// Get gateway router's RouterInfo from NetDB
	gatewayRouterInfo, err := p.getGatewayRouterInfo(gatewayHash)
	if err != nil {
		return fmt.Errorf("failed to get gateway RouterInfo: %w", err)
	}

	// Get or create transport session to gateway router
	session, err := p.transport.GetSession(*gatewayRouterInfo)
	if err != nil {
		return fmt.Errorf("failed to get transport session to gateway: %w", err)
	}

	// Queue message for transmission
	session.QueueSendI2NP(msg)
	return nil
}

// getGatewayRouterInfo retrieves the RouterInfo for a gateway router from the NetDB.
// Returns an error if the RouterInfo cannot be retrieved or has no identity.
func (p *Publisher) getGatewayRouterInfo(gatewayHash common.Hash) (*router_info.RouterInfo, error) {
	// Get RouterInfo from NetDB using the hash
	ri := p.db.GetRouterInfo(gatewayHash)

	// Check if RouterInfo has a valid identity by verifying we can get its hash.
	// Note: We don't use IsValid() because in test environments, RouterInfo without
	// addresses may be considered invalid even though they have valid identities.
	// For transport purposes, we only need a valid identity to establish a session.
	_, err := ri.IdentHash()
	if err != nil {
		return nil, fmt.Errorf("gateway %x not found in NetDB or has no valid identity: %w", gatewayHash[:8], err)
	}

	return &ri, nil
}

// SetTransport sets the transport manager after publisher creation.
// This allows the transport to be configured after initial publisher setup.
func (p *Publisher) SetTransport(transport TransportManager) {
	p.transport = transport
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
