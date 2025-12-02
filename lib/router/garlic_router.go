package router

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/lease"
	"github.com/go-i2p/common/lease_set"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/netdb"
	"github.com/go-i2p/go-i2p/lib/transport"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/logger"
)

const (
	// maxPendingMessages limits the number of queued messages per destination
	maxPendingMessages = 100
	// pendingMessageTimeout is how long to wait for a LeaseSet before discarding messages
	pendingMessageTimeout = 30 * time.Second
	// lookupRetryInterval is how often to retry failed lookups
	lookupRetryInterval = 5 * time.Second
)

// pendingMessage represents a message waiting for LeaseSet resolution.
type pendingMessage struct {
	msg      i2np.I2NPMessage // The message to send
	queuedAt time.Time        // When the message was queued
	retryAt  time.Time        // When to retry the lookup
	attempts int              // Number of lookup attempts
}

// GarlicNetDB defines the NetDB interface needed for garlic message routing.
// This matches the actual StdNetDB implementation which returns channels for async lookups.
type GarlicNetDB interface {
	GetRouterInfo(hash common.Hash) chan router_info.RouterInfo
	GetLeaseSet(hash common.Hash) chan lease_set.LeaseSet
	StoreRouterInfo(ri router_info.RouterInfo)
	Size() int
	SelectFloodfillRouters(targetHash common.Hash, count int) ([]router_info.RouterInfo, error)
}

// netDBAdapter wraps netdb.StdNetDB to match the GarlicNetDB interface.
// The main difference is StoreRouterInfo signature - StdNetDB takes (hash, data, type)
// while GarlicNetDB takes just RouterInfo.
type netDBAdapter struct {
	*netdb.StdNetDB
}

// StoreRouterInfo adapts the StdNetDB.StoreRouterInfo method to match GarlicNetDB interface.
// This is a no-op for now as garlic routing doesn't need to store RouterInfos.
func (a *netDBAdapter) StoreRouterInfo(ri router_info.RouterInfo) {
	// No-op: garlic router doesn't need to store RouterInfos, only read them
	// If needed in the future, this could serialize the RouterInfo and call
	// a.StdNetDB.StoreRouterInfo(hash, data, type)
}

// newNetDBAdapter creates an adapter that wraps StdNetDB for use with GarlicMessageRouter.
func newNetDBAdapter(netdb *netdb.StdNetDB) GarlicNetDB {
	return &netDBAdapter{StdNetDB: netdb}
}

// GarlicMessageRouter provides router-level garlic message forwarding.
// It bridges the gap between message processing (lib/i2np) and router
// infrastructure (NetDB, transport, tunnels) to enable delivery of garlic
// cloves to destinations, routers, and tunnels beyond LOCAL processing.
//
// This component implements the GarlicCloveForwarder interface and is designed
// to be injected into the MessageProcessor via SetCloveForwarder().
//
// Architecture:
//   - Receives forwarding requests from MessageProcessor
//   - Accesses NetDB for destination/router lookups
//   - Uses transport layer for direct router-to-router messaging
//   - Uses tunnel pools for destination and tunnel delivery
type GarlicMessageRouter struct {
	// Router infrastructure dependencies
	netdb          GarlicNetDB               // NetDB with LeaseSet support
	transportMgr   *transport.TransportMuxer // Transport for router-to-router messaging
	tunnelPool     *tunnel.Pool              // Tunnel pool for routing through tunnels
	routerIdentity common.Hash               // Our router's identity hash

	// Message processing
	processor *i2np.MessageProcessor // Reference to the processor for LOCAL recursion

	// Destination lookup queue for async LeaseSet resolution
	pendingMsgs  map[common.Hash][]pendingMessage // Messages waiting for LeaseSet lookup
	pendingMutex sync.RWMutex                     // Protects pendingMsgs map
	ctx          context.Context                  // Context for graceful shutdown
	cancel       context.CancelFunc               // Cancel function for shutdown
}

// NewGarlicMessageRouter creates a new garlic message router with required dependencies.
// All parameters are required for full functionality:
//   - netdb: For looking up destinations and routers
//   - transportMgr: For sending messages to peer routers
//   - tunnelPool: For routing messages through tunnels
//   - routerIdentity: Our router's hash for reflexive delivery detection
func NewGarlicMessageRouter(
	netdb GarlicNetDB,
	transportMgr *transport.TransportMuxer,
	tunnelPool *tunnel.Pool,
	routerIdentity common.Hash,
) *GarlicMessageRouter {
	ctx, cancel := context.WithCancel(context.Background())

	gr := &GarlicMessageRouter{
		netdb:          netdb,
		transportMgr:   transportMgr,
		tunnelPool:     tunnelPool,
		routerIdentity: routerIdentity,
		pendingMsgs:    make(map[common.Hash][]pendingMessage),
		ctx:            ctx,
		cancel:         cancel,
	}

	// Start background goroutine to process pending messages
	go gr.processPendingMessages()

	return gr
}

// SetMessageProcessor sets a reference to the MessageProcessor for LOCAL delivery recursion.
// This enables the router to process messages locally when needed (e.g., reflexive ROUTER delivery).
func (gr *GarlicMessageRouter) SetMessageProcessor(processor *i2np.MessageProcessor) {
	gr.processor = processor
}

// ForwardToDestination implements GarlicCloveForwarder interface.
// Forwards a message to a destination hash (delivery type 0x01).
//
// Process:
//  1. Look up destination in NetDB to get LeaseSet
//  2. If found: Select a valid lease and route through the tunnel
//  3. If not found: Queue message and trigger async LeaseSet lookup
//  4. Background processor retries lookups and forwards messages when LeaseSets arrive
//
// Per I2P spec, destinations are identified by their 32-byte hash and are
// reached by sending messages through one of their published inbound tunnels.
func (gr *GarlicMessageRouter) ForwardToDestination(destHash common.Hash, msg i2np.I2NPMessage) error {
	log.WithFields(logger.Fields{
		"dest_hash":    fmt.Sprintf("%x", destHash[:8]),
		"message_type": msg.Type(),
		"message_id":   msg.MessageID(),
	}).Debug("Forwarding garlic clove to destination")

	// Look up LeaseSet with timeout
	leaseSet, shouldQueue := gr.lookupLeaseSetWithTimeout(destHash)
	if shouldQueue {
		return gr.queuePendingMessage(destHash, msg)
	}

	// Validate LeaseSet and extract leases
	leases, err := gr.validateAndExtractLeases(destHash, leaseSet)
	if err != nil {
		return err
	}

	// Select best lease and route message
	return gr.routeMessageThroughLease(destHash, leases, msg)
}

// lookupLeaseSetWithTimeout attempts to retrieve a LeaseSet from NetDB with timeout.
// Returns the LeaseSet and a boolean indicating if the message should be queued.
func (gr *GarlicMessageRouter) lookupLeaseSetWithTimeout(destHash common.Hash) (lease_set.LeaseSet, bool) {
	leaseSetChan := gr.netdb.GetLeaseSet(destHash)
	if leaseSetChan == nil {
		log.WithField("dest_hash", fmt.Sprintf("%x", destHash[:8])).
			Debug("LeaseSet not found, queueing message for async lookup")
		return lease_set.LeaseSet{}, true
	}

	select {
	case ls, ok := <-leaseSetChan:
		if !ok {
			log.WithField("dest_hash", fmt.Sprintf("%x", destHash[:8])).
				Debug("LeaseSet channel closed, queueing message for async lookup")
			return lease_set.LeaseSet{}, true
		}
		return ls, false
	case <-time.After(1 * time.Second):
		log.WithField("dest_hash", fmt.Sprintf("%x", destHash[:8])).
			Debug("Timeout waiting for LeaseSet, queueing message for async lookup")
		return lease_set.LeaseSet{}, true
	}
}

// validateAndExtractLeases validates a LeaseSet and extracts its leases.
// Returns an error if the LeaseSet is invalid or has no valid leases.
func (gr *GarlicMessageRouter) validateAndExtractLeases(destHash common.Hash, leaseSet lease_set.LeaseSet) ([]lease.Lease, error) {
	if !leaseSet.IsValid() {
		return nil, fmt.Errorf("destination %x has invalid LeaseSet", destHash[:8])
	}

	leases, err := leaseSet.Leases()
	if err != nil {
		return nil, fmt.Errorf("failed to extract leases from LeaseSet for %x: %w", destHash[:8], err)
	}

	if len(leases) == 0 {
		return nil, fmt.Errorf("destination %x has no valid leases", destHash[:8])
	}

	return leases, nil
}

// routeMessageThroughLease selects the best lease from available leases and routes
// the message through the corresponding tunnel gateway.
func (gr *GarlicMessageRouter) routeMessageThroughLease(destHash common.Hash, leases []lease.Lease, msg i2np.I2NPMessage) error {
	selectedLease := gr.selectBestLease(leases)
	if selectedLease == nil {
		return fmt.Errorf("no valid lease available for destination %x", destHash[:8])
	}

	gatewayHash := selectedLease.TunnelGateway()
	tunnelID := tunnel.TunnelID(selectedLease.TunnelID())

	log.WithFields(logger.Fields{
		"dest_hash":    fmt.Sprintf("%x", destHash[:8]),
		"gateway_hash": fmt.Sprintf("%x", gatewayHash[:8]),
		"tunnel_id":    tunnelID,
	}).Debug("Selected lease for DESTINATION delivery, routing through tunnel")

	return gr.ForwardThroughTunnel(gatewayHash, tunnelID, msg)
}

// selectBestLease selects the best lease from a list of leases.
// Currently uses a simple heuristic: choose the lease with the newest expiration.
// Future improvements could consider tunnel quality, latency, etc.
func (gr *GarlicMessageRouter) selectBestLease(leases []lease.Lease) *lease.Lease {
	if len(leases) == 0 {
		return nil
	}

	// Find lease with newest expiration (most time remaining)
	var bestLease *lease.Lease
	var newestExpiration time.Time

	now := time.Now()
	for i := range leases {
		leaseDate := leases[i].Date()
		expirationTime := time.Unix(leaseDate.Time().Unix(), 0)

		// Skip expired leases
		if expirationTime.Before(now) {
			continue
		}

		if bestLease == nil || expirationTime.After(newestExpiration) {
			bestLease = &leases[i]
			newestExpiration = expirationTime
		}
	}

	return bestLease
}

// ForwardToRouter implements GarlicCloveForwarder interface.
// Forwards a message directly to a router hash (delivery type 0x02).
//
// Process:
//  1. Check if router_hash == our_router_hash (reflexive delivery)
//  2. If reflexive, process locally via MessageProcessor
//  3. Otherwise, look up router in NetDB to get RouterInfo
//  4. Send message via transport layer
//
// Reflexive delivery occurs when a garlic message instructs us to send a clove
// to ourselves - this is processed locally to avoid unnecessary network traffic.
func (gr *GarlicMessageRouter) ForwardToRouter(routerHash common.Hash, msg i2np.I2NPMessage) error {
	log.WithFields(logger.Fields{
		"router_hash":  fmt.Sprintf("%x", routerHash[:8]),
		"message_type": msg.Type(),
		"message_id":   msg.MessageID(),
	}).Debug("Forwarding garlic clove to router")

	// Check for reflexive delivery (sending to ourselves)
	if err := gr.handleReflexiveDelivery(routerHash, msg); err != nil {
		if err == errNotReflexive {
			// Continue with normal routing
		} else {
			return err
		}
	} else {
		// Successfully handled reflexively
		return nil
	}

	// Look up and validate router information
	routerInfo, err := gr.lookupRouterInfo(routerHash)
	if err != nil {
		return err
	}

	// Send message through transport layer
	if err := gr.sendMessageToRouter(routerHash, routerInfo, msg); err != nil {
		return err
	}

	log.WithFields(logger.Fields{
		"router_hash":  fmt.Sprintf("%x", routerHash[:8]),
		"message_type": msg.Type(),
		"message_id":   msg.MessageID(),
	}).Debug("Successfully queued message to router")

	return nil
}

// errNotReflexive indicates the delivery is not reflexive and should continue normal routing.
var errNotReflexive = fmt.Errorf("not reflexive")

// handleReflexiveDelivery checks if the message is being sent to ourselves and processes it locally.
// Returns nil if the message was successfully processed reflexively.
// Returns errNotReflexive if the delivery is not reflexive and should continue normal routing.
// Returns other errors if reflexive processing failed.
func (gr *GarlicMessageRouter) handleReflexiveDelivery(routerHash common.Hash, msg i2np.I2NPMessage) error {
	if !bytes.Equal(routerHash[:], gr.routerIdentity[:]) {
		return errNotReflexive
	}

	log.Debug("ROUTER delivery is reflexive, processing locally")
	if gr.processor == nil {
		return fmt.Errorf("reflexive delivery failed: processor not configured")
	}

	return gr.processor.ProcessMessage(msg)
}

// lookupRouterInfo retrieves and validates RouterInfo from NetDB.
// Returns the RouterInfo if found and valid, or an error otherwise.
func (gr *GarlicMessageRouter) lookupRouterInfo(routerHash common.Hash) (router_info.RouterInfo, error) {
	routerInfoChan := gr.netdb.GetRouterInfo(routerHash)
	if routerInfoChan == nil {
		return router_info.RouterInfo{}, fmt.Errorf("router %x not found in NetDB", routerHash[:8])
	}

	// Wait for RouterInfo with timeout
	var routerInfo router_info.RouterInfo
	select {
	case ri, ok := <-routerInfoChan:
		if !ok {
			return router_info.RouterInfo{}, fmt.Errorf("router %x RouterInfo channel closed", routerHash[:8])
		}
		routerInfo = ri
	case <-time.After(1 * time.Second):
		return router_info.RouterInfo{}, fmt.Errorf("timeout waiting for router %x RouterInfo", routerHash[:8])
	}

	// Validate RouterInfo
	if !routerInfo.IsValid() {
		return router_info.RouterInfo{}, fmt.Errorf("router %x has invalid RouterInfo", routerHash[:8])
	}

	return routerInfo, nil
}

// sendMessageToRouter establishes a transport session and queues the message for delivery.
// Returns an error if session establishment fails.
func (gr *GarlicMessageRouter) sendMessageToRouter(routerHash common.Hash, routerInfo router_info.RouterInfo, msg i2np.I2NPMessage) error {
	session, err := gr.transportMgr.GetSession(routerInfo)
	if err != nil {
		return fmt.Errorf("failed to get session for router %x: %w", routerHash[:8], err)
	}

	session.QueueSendI2NP(msg)
	return nil
}

// ForwardThroughTunnel implements GarlicCloveForwarder interface.
// Forwards a message through a tunnel to a gateway (delivery type 0x03).
//
// Process:
//  1. Check if gateway_hash == our_router_hash (we are the gateway)
//  2. If yes, inject message directly into our tunnel processing (TODO)
//  3. Otherwise, wrap message in TunnelGateway envelope
//  4. Send TunnelGateway message to gateway router via ROUTER delivery
//
// Tunnel delivery is the most common forwarding type in I2P, as most traffic
// flows through tunnels for anonymity. The gateway router is responsible for
// injecting messages into the tunnel's encryption layers.
func (gr *GarlicMessageRouter) ForwardThroughTunnel(
	gatewayHash common.Hash,
	tunnelID tunnel.TunnelID,
	msg i2np.I2NPMessage,
) error {
	log.WithFields(logger.Fields{
		"gateway_hash": fmt.Sprintf("%x", gatewayHash[:8]),
		"tunnel_id":    tunnelID,
		"message_type": msg.Type(),
		"message_id":   msg.MessageID(),
	}).Debug("Forwarding garlic clove through tunnel")

	// Check if we are the gateway (reflexive tunnel delivery)
	if bytes.Equal(gatewayHash[:], gr.routerIdentity[:]) {
		// We are the gateway - process the TunnelGateway message locally
		log.WithFields(logger.Fields{
			"tunnel_id": tunnelID,
		}).Debug("TUNNEL delivery is reflexive, processing TunnelGateway locally")

		// Create TunnelGateway message for local processing
		msgBytes, err := msg.MarshalBinary()
		if err != nil {
			return fmt.Errorf("failed to marshal message for local tunnel injection: %w", err)
		}

		tunnelGatewayMsg := i2np.NewTunnelGatewayMessage(tunnelID, msgBytes)

		// Process the TunnelGateway message through our message processor
		// This will decrypt tunnel layers and route to final destination
		if gr.processor == nil {
			return fmt.Errorf("message processor not set for local tunnel injection")
		}

		if err := gr.processor.ProcessMessage(tunnelGatewayMsg); err != nil {
			return fmt.Errorf("failed to process local tunnel injection: %w", err)
		}

		log.WithField("tunnel_id", tunnelID).Debug("Successfully injected message into local tunnel")
		return nil
	}

	// Serialize the wrapped message for inclusion in TunnelGateway
	msgBytes, err := msg.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal wrapped message for tunnel: %w", err)
	}

	// Create TunnelGateway message (wraps the original message for tunnel transmission)
	tunnelGatewayMsg := i2np.NewTunnelGatewayMessage(tunnelID, msgBytes)

	log.WithFields(logger.Fields{
		"gateway_hash": fmt.Sprintf("%x", gatewayHash[:8]),
		"tunnel_id":    tunnelID,
		"wrapped_size": len(msgBytes),
	}).Debug("Created TunnelGateway message, forwarding to gateway router")

	// Send TunnelGateway message to gateway router using ROUTER delivery
	return gr.ForwardToRouter(gatewayHash, tunnelGatewayMsg)
}

// Stop gracefully shuts down the garlic message router.
// This stops the background message processing goroutine.
func (gr *GarlicMessageRouter) Stop() {
	if gr.cancel != nil {
		gr.cancel()
	}
}

// processPendingMessages runs in background and periodically processes queued messages.
// It retries LeaseSet lookups and forwards messages once LeaseSets become available.
func (gr *GarlicMessageRouter) processPendingMessages() {
	ticker := time.NewTicker(lookupRetryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-gr.ctx.Done():
			log.Debug("Stopping pending message processor")
			return
		case <-ticker.C:
			gr.retryPendingLookups()
		}
	}
}

// retryPendingLookups attempts to resolve pending destinations and forward queued messages.
func (gr *GarlicMessageRouter) retryPendingLookups() {
	gr.pendingMutex.Lock()
	defer gr.pendingMutex.Unlock()

	now := time.Now()

	for destHash, messages := range gr.pendingMsgs {
		gr.processPendingDestination(destHash, messages, now)
	}
}

// processPendingDestination handles lookup retry and message processing for a single destination.
// It attempts to retrieve the LeaseSet and either forwards queued messages or cleans up expired ones.
func (gr *GarlicMessageRouter) processPendingDestination(destHash common.Hash, messages []pendingMessage, now time.Time) {
	// Skip if no messages for this destination
	if len(messages) == 0 {
		delete(gr.pendingMsgs, destHash)
		return
	}

	// Try to get LeaseSet
	leaseSetChan := gr.netdb.GetLeaseSet(destHash)
	if leaseSetChan == nil {
		// LeaseSet still not found, clean up expired messages
		gr.cleanupExpiredMessages(destHash, messages, now)
		return
	}

	// Attempt to read LeaseSet and process accordingly
	gr.attemptLeaseSetRetrieval(destHash, messages, now, leaseSetChan)
}

// attemptLeaseSetRetrieval tries to retrieve a LeaseSet with a short timeout and processes or cleans up messages.
// This performs a non-blocking read from the LeaseSet channel.
func (gr *GarlicMessageRouter) attemptLeaseSetRetrieval(destHash common.Hash, messages []pendingMessage, now time.Time, leaseSetChan chan lease_set.LeaseSet) {
	select {
	case ls, ok := <-leaseSetChan:
		if !ok {
			gr.cleanupExpiredMessages(destHash, messages, now)
			return
		}

		// LeaseSet found! Process all pending messages
		// Note: processPendingMessagesForDestination will validate the LeaseSet
		// and handle invalid cases by cleaning up the queue
		gr.processPendingMessagesForDestination(destHash, ls, messages)

	default:
		// LeaseSet not immediately available, clean up expired
		gr.cleanupExpiredMessages(destHash, messages, now)
	}
}

// cleanupExpiredMessages removes messages that have exceeded the timeout.
func (gr *GarlicMessageRouter) cleanupExpiredMessages(destHash common.Hash, messages []pendingMessage, now time.Time) {
	validMessages := make([]pendingMessage, 0, len(messages))

	for _, pm := range messages {
		if now.Sub(pm.queuedAt) < pendingMessageTimeout {
			validMessages = append(validMessages, pm)
		} else {
			log.WithFields(logger.Fields{
				"dest_hash": fmt.Sprintf("%x", destHash[:8]),
				"msg_type":  pm.msg.Type(),
				"queued_at": pm.queuedAt,
			}).Warn("Discarding expired pending message")
		}
	}

	if len(validMessages) > 0 {
		gr.pendingMsgs[destHash] = validMessages
	} else {
		delete(gr.pendingMsgs, destHash)
	}
}

// processPendingMessagesForDestination forwards all queued messages for a destination.
func (gr *GarlicMessageRouter) processPendingMessagesForDestination(
	destHash common.Hash,
	leaseSet lease_set.LeaseSet,
	messages []pendingMessage,
) {
	log.WithFields(logger.Fields{
		"dest_hash":     fmt.Sprintf("%x", destHash[:8]),
		"message_count": len(messages),
	}).Info("LeaseSet found, processing pending messages")

	// Get leases from LeaseSet
	leases, err := leaseSet.Leases()
	if err != nil {
		log.WithError(err).Error("Failed to extract leases from LeaseSet")
		delete(gr.pendingMsgs, destHash)
		return
	}

	if len(leases) == 0 {
		log.WithField("dest_hash", fmt.Sprintf("%x", destHash[:8])).
			Warn("LeaseSet has no valid leases")
		delete(gr.pendingMsgs, destHash)
		return
	}

	// Select best lease
	selectedLease := gr.selectBestLease(leases)
	if selectedLease == nil {
		log.WithField("dest_hash", fmt.Sprintf("%x", destHash[:8])).
			Warn("No valid lease available")
		delete(gr.pendingMsgs, destHash)
		return
	}

	// Extract gateway and tunnel ID
	gatewayHash := selectedLease.TunnelGateway()
	tunnelID := tunnel.TunnelID(selectedLease.TunnelID())

	// Forward all pending messages
	for _, pm := range messages {
		err := gr.ForwardThroughTunnel(gatewayHash, tunnelID, pm.msg)
		if err != nil {
			log.WithFields(logger.Fields{
				"dest_hash": fmt.Sprintf("%x", destHash[:8]),
				"msg_type":  pm.msg.Type(),
				"error":     err,
			}).Error("Failed to forward pending message")
		} else {
			log.WithFields(logger.Fields{
				"dest_hash": fmt.Sprintf("%x", destHash[:8]),
				"msg_type":  pm.msg.Type(),
			}).Debug("Successfully forwarded pending message")
		}
	}

	// Remove all processed messages
	delete(gr.pendingMsgs, destHash)
}

// queuePendingMessage adds a message to the pending queue for later delivery.
func (gr *GarlicMessageRouter) queuePendingMessage(destHash common.Hash, msg i2np.I2NPMessage) error {
	gr.pendingMutex.Lock()
	defer gr.pendingMutex.Unlock()

	// Check if we already have too many pending messages for this destination
	if existing, ok := gr.pendingMsgs[destHash]; ok && len(existing) >= maxPendingMessages {
		return fmt.Errorf("too many pending messages for destination %x", destHash[:8])
	}

	// Add message to queue
	pm := pendingMessage{
		msg:      msg,
		queuedAt: time.Now(),
		retryAt:  time.Now().Add(lookupRetryInterval),
		attempts: 1,
	}

	gr.pendingMsgs[destHash] = append(gr.pendingMsgs[destHash], pm)

	log.WithFields(logger.Fields{
		"dest_hash":     fmt.Sprintf("%x", destHash[:8]),
		"message_type":  msg.Type(),
		"pending_count": len(gr.pendingMsgs[destHash]),
	}).Debug("Queued message for pending LeaseSet lookup")

	return nil
}
