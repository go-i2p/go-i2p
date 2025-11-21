package i2np

import (
	"fmt"
	"sync"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/logger"
)

// MessageProcessor demonstrates interface-based message processing
type MessageProcessor struct {
	factory *I2NPMessageFactory
}

// NewMessageProcessor creates a new message processor
func NewMessageProcessor() *MessageProcessor {
	return &MessageProcessor{
		factory: NewI2NPMessageFactory(),
	}
}

// ProcessMessage processes any I2NP message using interfaces
func (p *MessageProcessor) ProcessMessage(msg I2NPMessage) error {
	switch msg.Type() {
	case I2NP_MESSAGE_TYPE_DATA:
		return p.processDataMessage(msg)
	case I2NP_MESSAGE_TYPE_DELIVERY_STATUS:
		return p.processDeliveryStatusMessage(msg)
	case I2NP_MESSAGE_TYPE_TUNNEL_DATA:
		return p.processTunnelDataMessage(msg)
	default:
		return fmt.Errorf("unknown message type: %d", msg.Type())
	}
}

// processDataMessage processes data messages using PayloadCarrier interface
func (p *MessageProcessor) processDataMessage(msg I2NPMessage) error {
	if payloadCarrier, ok := msg.(PayloadCarrier); ok {
		payload := payloadCarrier.GetPayload()
		log.WithField("payload_size", len(payload)).Debug("Processing data message")
		return nil
	}
	return fmt.Errorf("message does not implement PayloadCarrier interface")
}

// processDeliveryStatusMessage processes delivery status messages using StatusReporter interface
func (p *MessageProcessor) processDeliveryStatusMessage(msg I2NPMessage) error {
	if statusReporter, ok := msg.(StatusReporter); ok {
		msgID := statusReporter.GetStatusMessageID()
		timestamp := statusReporter.GetTimestamp()
		log.WithFields(logger.Fields{
			"message_id": msgID,
			"timestamp":  timestamp,
		}).Debug("Processing delivery status")
		return nil
	}
	return fmt.Errorf("message does not implement StatusReporter interface")
}

// processTunnelDataMessage processes tunnel data messages using TunnelCarrier interface
func (p *MessageProcessor) processTunnelDataMessage(msg I2NPMessage) error {
	if tunnelCarrier, ok := msg.(TunnelCarrier); ok {
		data := tunnelCarrier.GetTunnelData()
		log.WithField("data_size", len(data)).Debug("Processing tunnel data message")
		return nil
	}
	return fmt.Errorf("message does not implement TunnelCarrier interface")
}

// buildRequest tracks a pending tunnel build request for correlation with replies.
// This enables matching build replies to the original request and managing timeouts.
type buildRequest struct {
	tunnelID      tunnel.TunnelID          // Unique tunnel ID for this request
	messageID     int                      // I2NP message ID for correlation
	hopCount      int                      // Number of hops in the tunnel
	replyKeys     []session_key.SessionKey // Reply decryption keys for each hop
	replyIVs      [][16]byte               // Reply IVs for each hop
	createdAt     time.Time                // When the request was created
	retryCount    int                      // Number of retry attempts
	useShortBuild bool                     // True if using STBM, false for legacy VTB
}

// TunnelManager coordinates tunnel building and management
type TunnelManager struct {
	pool            *tunnel.Pool
	sessionProvider SessionProvider
	peerSelector    tunnel.PeerSelector
	pendingBuilds   map[int]*buildRequest // Track pending builds by message ID
	buildMutex      sync.RWMutex          // Protect pending builds map
	cleanupTicker   *time.Ticker          // Periodic cleanup of expired requests
	cleanupStop     chan struct{}         // Signal to stop cleanup goroutine
}

// NewTunnelManager creates a new tunnel manager with build request tracking.
// Starts a background goroutine for cleaning up expired build requests.
func NewTunnelManager(peerSelector tunnel.PeerSelector) *TunnelManager {
	pool := tunnel.NewTunnelPool(peerSelector)
	tm := &TunnelManager{
		pool:          pool,
		peerSelector:  peerSelector,
		pendingBuilds: make(map[int]*buildRequest),
		cleanupStop:   make(chan struct{}),
	}

	// Start periodic cleanup of expired build requests (every 30 seconds)
	tm.cleanupTicker = time.NewTicker(30 * time.Second)
	go tm.cleanupExpiredBuilds()

	return tm
}

// Stop gracefully stops the tunnel manager and cleans up resources.
// Should be called when shutting down the router.
func (tm *TunnelManager) Stop() {
	if tm.cleanupTicker != nil {
		tm.cleanupTicker.Stop()
	}
	close(tm.cleanupStop)
	log.Debug("Tunnel manager stopped")
}

// SetSessionProvider sets the session provider for sending tunnel build messages
func (tm *TunnelManager) SetSessionProvider(provider SessionProvider) {
	tm.sessionProvider = provider
}

// BuildTunnelFromRequest builds a tunnel from a BuildTunnelRequest using the tunnel.TunnelBuilder.
// This is the recommended method for building tunnels with proper request tracking and retry support.
//
// The method:
// 1. Uses tunnel.TunnelBuilder to create encrypted build records
// 2. Generates a unique message ID for request/reply correlation
// 3. Tracks the pending build request with reply decryption keys
// 4. Sends the build request via appropriate transport
// 5. Returns the tunnel ID for tracking
func (tm *TunnelManager) BuildTunnelFromRequest(req tunnel.BuildTunnelRequest) (tunnel.TunnelID, error) {
	if tm.peerSelector == nil {
		return 0, fmt.Errorf("no peer selector configured")
	}

	// Create tunnel builder
	builder, err := tunnel.NewTunnelBuilder(tm.peerSelector)
	if err != nil {
		return 0, fmt.Errorf("failed to create tunnel builder: %w", err)
	}

	// Generate build request with encrypted records
	result, err := builder.CreateBuildRequest(req)
	if err != nil {
		return 0, fmt.Errorf("failed to create build request: %w", err)
	}

	// Generate message ID for this build request
	messageID := tm.generateMessageID()

	// Create tunnel state tracking
	tunnelState := &tunnel.TunnelState{
		ID:        result.TunnelID,
		Hops:      make([]common.Hash, len(result.Hops)),
		State:     tunnel.TunnelBuilding,
		CreatedAt: time.Now(),
		Responses: make([]tunnel.BuildResponse, 0, len(result.Hops)),
	}

	// Populate hops with selected peer hashes
	for i, peer := range result.Hops {
		tunnelState.Hops[i] = peer.IdentHash()
	}

	// Add tunnel to pool for tracking
	tm.pool.AddTunnel(tunnelState)

	// Track the pending build request for reply correlation
	tm.buildMutex.Lock()
	tm.pendingBuilds[messageID] = &buildRequest{
		tunnelID:      result.TunnelID,
		messageID:     messageID,
		hopCount:      len(result.Hops),
		replyKeys:     result.ReplyKeys,
		replyIVs:      result.ReplyIVs,
		createdAt:     time.Now(),
		retryCount:    0,
		useShortBuild: result.UseShortBuild,
	}
	tm.buildMutex.Unlock()

	// Send the tunnel build request
	err = tm.sendBuildMessage(result, messageID)
	if err != nil {
		// Clean up on failure
		tm.pool.RemoveTunnel(result.TunnelID)
		tm.buildMutex.Lock()
		delete(tm.pendingBuilds, messageID)
		tm.buildMutex.Unlock()
		return 0, fmt.Errorf("failed to send build request: %w", err)
	}

	log.WithFields(logger.Fields{
		"tunnel_id":  result.TunnelID,
		"message_id": messageID,
		"hop_count":  len(result.Hops),
		"use_stbm":   result.UseShortBuild,
	}).Info("Tunnel build request sent")

	return result.TunnelID, nil
}

// sendBuildMessage sends a tunnel build message (STBM or VTB) based on the result.
func (tm *TunnelManager) sendBuildMessage(result *tunnel.TunnelBuildResult, messageID int) error {
	if tm.sessionProvider == nil {
		return fmt.Errorf("no session provider available")
	}

	// For now, send to the first hop (gateway)
	// In a full implementation, this would be sent through an existing outbound tunnel
	if len(result.Hops) == 0 {
		return fmt.Errorf("no hops in tunnel build result")
	}

	firstHop := result.Hops[0]
	peerHash := firstHop.IdentHash()

	// Get transport session to the gateway
	session, err := tm.sessionProvider.GetSessionByHash(peerHash)
	if err != nil {
		return fmt.Errorf("failed to get session for gateway %x: %w", peerHash[:8], err)
	}

	// Create the appropriate build message based on UseShortBuild flag
	var buildMsg I2NPMessage
	if result.UseShortBuild {
		// Use Short Tunnel Build Message (modern)
		buildMsg = tm.createShortTunnelBuildMessage(result, messageID)
	} else {
		// Use Variable Tunnel Build Message (legacy)
		buildMsg = tm.createVariableTunnelBuildMessage(result, messageID)
	}

	// Queue the message for sending
	session.QueueSendI2NP(buildMsg)

	log.WithFields(logger.Fields{
		"message_id":   messageID,
		"gateway_hash": fmt.Sprintf("%x", peerHash[:8]),
		"message_type": buildMsg.Type(),
		"use_stbm":     result.UseShortBuild,
	}).Debug("Queued tunnel build message")

	return nil
}

// createShortTunnelBuildMessage creates a Short Tunnel Build Message (STBM).
func (tm *TunnelManager) createShortTunnelBuildMessage(result *tunnel.TunnelBuildResult, messageID int) I2NPMessage {
	// Convert tunnel.BuildRequestRecord to i2np.BuildRequestRecord
	i2npRecords := make([]BuildRequestRecord, len(result.Records))
	for i, rec := range result.Records {
		i2npRecords[i] = BuildRequestRecord{
			ReceiveTunnel: rec.ReceiveTunnel,
			OurIdent:      rec.OurIdent,
			NextTunnel:    rec.NextTunnel,
			NextIdent:     rec.NextIdent,
			LayerKey:      rec.LayerKey,
			IVKey:         rec.IVKey,
			ReplyKey:      rec.ReplyKey,
			ReplyIV:       rec.ReplyIV,
			Flag:          rec.Flag,
			RequestTime:   rec.RequestTime,
			SendMessageID: rec.SendMessageID,
			Padding:       rec.Padding,
		}
	}

	// Create Short Tunnel Build (STBM) using the builder constructor
	_ = NewShortTunnelBuilder(i2npRecords) // Will be used for serialization later

	// Wrap in I2NP message
	msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_SHORT_TUNNEL_BUILD)
	msg.SetMessageID(messageID)

	// TODO: Serialize ShortTunnelBuild to bytes and set as message data
	// For now, we'll create a basic message structure

	return msg
}

// createVariableTunnelBuildMessage creates a Variable Tunnel Build Message (legacy).
func (tm *TunnelManager) createVariableTunnelBuildMessage(result *tunnel.TunnelBuildResult, messageID int) I2NPMessage {
	// Convert to fixed 8-record array (pad with empty records if needed)
	var records [8]BuildRequestRecord
	for i := 0; i < 8 && i < len(result.Records); i++ {
		rec := result.Records[i]
		records[i] = BuildRequestRecord{
			ReceiveTunnel: rec.ReceiveTunnel,
			OurIdent:      rec.OurIdent,
			NextTunnel:    rec.NextTunnel,
			NextIdent:     rec.NextIdent,
			LayerKey:      rec.LayerKey,
			IVKey:         rec.IVKey,
			ReplyKey:      rec.ReplyKey,
			ReplyIV:       rec.ReplyIV,
			Flag:          rec.Flag,
			RequestTime:   rec.RequestTime,
			SendMessageID: rec.SendMessageID,
			Padding:       rec.Padding,
		}
	}

	msg := NewTunnelBuildMessage(records)
	msg.SetMessageID(messageID)
	return msg
}

// generateMessageID generates a unique message ID for tracking build requests.
func (tm *TunnelManager) generateMessageID() int {
	// Use time-based ID with some randomness
	// In production, this should be more sophisticated to avoid collisions
	return int(time.Now().UnixNano() & 0x7FFFFFFF)
}

// BuildTunnel builds a tunnel using TunnelBuilder interface
func (tm *TunnelManager) BuildTunnel(builder TunnelBuilder) error {
	if tm.peerSelector == nil {
		return fmt.Errorf("no peer selector configured")
	}

	records := builder.GetBuildRecords()
	count := builder.GetRecordCount()

	if count == 0 {
		return fmt.Errorf("no build records provided")
	}

	// Select peers for tunnel hops (excluding ourselves)
	peers, err := tm.peerSelector.SelectPeers(count, nil)
	if err != nil {
		return fmt.Errorf("failed to select peers for tunnel: %w", err)
	}

	if len(peers) < count {
		return fmt.Errorf("insufficient peers available: need %d, got %d", count, len(peers))
	}

	// Generate tunnel ID for this tunnel
	tunnelID := tm.generateTunnelID()

	// Create tunnel state tracking
	tunnelState := &tunnel.TunnelState{
		ID:        tunnelID,
		Hops:      make([]common.Hash, count),
		State:     tunnel.TunnelBuilding,
		CreatedAt: time.Now(),
		Responses: make([]tunnel.BuildResponse, 0, count),
	}

	// Populate hops with selected peer hashes
	for i, peer := range peers[:count] {
		tunnelState.Hops[i] = peer.IdentHash()
	}

	// Add tunnel to pool for tracking
	tm.pool.AddTunnel(tunnelState)

	// Send build requests to each hop
	return tm.sendTunnelBuildRequests(records, peers[:count], tunnelID)
}

// generateTunnelID generates a new unique tunnel ID
func (tm *TunnelManager) generateTunnelID() tunnel.TunnelID {
	// Simple tunnel ID generation - in production this should be cryptographically secure
	return tunnel.TunnelID(time.Now().UnixNano() & 0xFFFFFFFF)
}

// sendTunnelBuildRequests sends tunnel build requests to each selected peer
func (tm *TunnelManager) sendTunnelBuildRequests(records []BuildRequestRecord, peers []router_info.RouterInfo, tunnelID tunnel.TunnelID) error {
	if tm.sessionProvider == nil {
		return fmt.Errorf("no session provider available for sending tunnel build requests")
	}

	log.WithFields(logger.Fields{
		"tunnel_id":  tunnelID,
		"peer_count": len(peers),
	}).Debug("Sending tunnel build requests")

	// Send build request to each peer
	for i := range records {
		if i >= len(peers) {
			break
		}

		peer := peers[i]
		peerHash := peer.IdentHash()

		// Get transport session to this peer
		session, err := tm.sessionProvider.GetSessionByHash(peerHash)
		if err != nil {
			log.WithFields(logger.Fields{
				"peer_hash": fmt.Sprintf("%x", peerHash[:8]),
				"error":     err,
			}).Warn("Failed to get session for peer")
			continue
		}

		// Create TunnelBuild I2NP message
		var buildRecords [8]BuildRequestRecord
		if i < 8 {
			buildRecords[i] = records[i] // Place this record at the appropriate position
		}

		buildMessage := NewTunnelBuildMessage(buildRecords)
		buildMessage.SetMessageID(int(tunnelID)) // Use tunnel ID as message ID for correlation

		// Send the tunnel build request
		session.QueueSendI2NP(buildMessage)

		log.WithFields(logger.Fields{
			"hop_index":  i,
			"peer_hash":  fmt.Sprintf("%x", peerHash[:8]),
			"message_id": buildMessage.MessageID(),
		}).Debug("Sent tunnel build request to hop")
	}

	log.WithField("tunnel_id", tunnelID).Debug("Tunnel build requests sent")
	return nil
}

// ProcessTunnelReply processes tunnel build replies using TunnelReplyHandler interface.
// This method integrates with the tunnel pool to update tunnel states and handle build completions.
// Uses message ID to correlate the reply with the original build request.
func (tm *TunnelManager) ProcessTunnelReply(handler TunnelReplyHandler, messageID int) error {
	records := handler.GetReplyRecords()
	recordCount := len(records)

	log.WithFields(logger.Fields{
		"record_count": recordCount,
		"message_id":   messageID,
	}).Debug("Processing tunnel reply")

	// Get the pending build request for decryption keys (currently unused but will be needed)
	tm.buildMutex.RLock()
	_, exists := tm.pendingBuilds[messageID]
	tm.buildMutex.RUnlock()

	if !exists {
		log.WithField("message_id", messageID).Warn("No pending build request found for reply - processing without correlation")
		// Continue processing even without pending build (allows testing and handles late replies)
	}

	// Process the reply to get build results
	// TODO: Pass decryption keys (req.replyKeys, req.replyIVs) to handler once interface is updated
	err := handler.ProcessReply()

	// Update tunnel state based on reply processing results
	if tm.pool != nil {
		tm.updateTunnelStatesFromReply(messageID, records, err)
	} else {
		log.Warn("No tunnel pool available for state updates")
	}

	// Remove the pending build request after processing (if it exists)
	if exists {
		tm.buildMutex.Lock()
		delete(tm.pendingBuilds, messageID)
		tm.buildMutex.Unlock()
	}

	return err
}

// updateTunnelStatesFromReply updates tunnel states in the pool based on build reply results.
// Uses message ID to find the matching tunnel via the pending build request.
func (tm *TunnelManager) updateTunnelStatesFromReply(messageID int, records []BuildResponseRecord, replyErr error) {
	// Find the matching tunnel using message ID
	matchingTunnel := tm.findMatchingBuildingTunnel(messageID)

	if matchingTunnel == nil {
		log.WithFields(logger.Fields{
			"message_id":   messageID,
			"record_count": len(records),
		}).Warn("No matching building tunnel found for reply")
		return
	}

	log.WithFields(logger.Fields{
		"tunnel_id":    matchingTunnel.ID,
		"message_id":   messageID,
		"record_count": len(records),
		"success":      replyErr == nil,
	}).Debug("Updating tunnel state from reply")

	// Create build responses from the reply records
	responses := make([]tunnel.BuildResponse, len(records))
	for i, record := range records {
		responses[i] = tunnel.BuildResponse{
			HopIndex: i,
			Success:  record.Reply == TUNNEL_BUILD_REPLY_SUCCESS,
			Reply:    []byte{record.Reply}, // Store the reply byte
		}
	}

	// Update tunnel state based on reply processing result
	if replyErr == nil {
		// All hops accepted - tunnel is ready
		matchingTunnel.State = tunnel.TunnelReady
		matchingTunnel.Responses = responses
		matchingTunnel.ResponseCount = len(responses)

		log.WithFields(logger.Fields{
			"tunnel_id":  matchingTunnel.ID,
			"message_id": messageID,
		}).Info("Tunnel build completed successfully")
	} else {
		// Build failed - mark tunnel as failed
		matchingTunnel.State = tunnel.TunnelFailed
		matchingTunnel.Responses = responses
		matchingTunnel.ResponseCount = len(responses)

		log.WithFields(logger.Fields{
			"tunnel_id":  matchingTunnel.ID,
			"message_id": messageID,
			"error":      replyErr,
		}).Warn("Tunnel build failed")

		// Clean up failed tunnel after a brief delay
		go tm.cleanupFailedTunnel(matchingTunnel.ID)
	}
}

// findMatchingBuildingTunnel finds a tunnel that's currently building based on the message ID.
// Uses the pending builds map to correlate build replies with their original requests.
func (tm *TunnelManager) findMatchingBuildingTunnel(messageID int) *tunnel.TunnelState {
	tm.buildMutex.RLock()
	req, exists := tm.pendingBuilds[messageID]
	tm.buildMutex.RUnlock()

	if !exists {
		log.WithField("message_id", messageID).Warn("No pending build request found for message ID")
		return nil
	}

	// Look up the tunnel state from the pool
	tunnelState, exists := tm.pool.GetTunnel(req.tunnelID)
	if !exists {
		log.WithField("tunnel_id", req.tunnelID).Warn("Tunnel state not found in pool")
		return nil
	}

	log.WithFields(logger.Fields{
		"tunnel_id":  req.tunnelID,
		"message_id": messageID,
		"hop_count":  req.hopCount,
	}).Debug("Found matching building tunnel")

	return tunnelState
}

// cleanupFailedTunnel removes a failed tunnel from the pool after a delay
func (tm *TunnelManager) cleanupFailedTunnel(tunnelID tunnel.TunnelID) {
	// Small delay before cleanup to allow for logging/debugging
	time.Sleep(1 * time.Second)

	if tm.pool != nil {
		tm.pool.RemoveTunnel(tunnelID)
		log.WithField("tunnel_id", tunnelID).Debug("Cleaned up failed tunnel")
	}
}

// cleanupExpiredBuilds periodically removes expired build requests.
// Build requests timeout after 90 seconds per I2P specification.
func (tm *TunnelManager) cleanupExpiredBuilds() {
	for {
		select {
		case <-tm.cleanupTicker.C:
			tm.removeExpiredBuildRequests()
		case <-tm.cleanupStop:
			return
		}
	}
}

// removeExpiredBuildRequests removes build requests older than 90 seconds.
// Also marks corresponding tunnels as failed and removes them from the pool.
func (tm *TunnelManager) removeExpiredBuildRequests() {
	tm.buildMutex.Lock()
	defer tm.buildMutex.Unlock()

	now := time.Now()
	const buildTimeout = 90 * time.Second
	var expired []int

	for msgID, req := range tm.pendingBuilds {
		if now.Sub(req.createdAt) > buildTimeout {
			expired = append(expired, msgID)

			// Mark tunnel as failed in pool
			if tunnelState, exists := tm.pool.GetTunnel(req.tunnelID); exists {
				tunnelState.State = tunnel.TunnelFailed
				log.WithFields(logger.Fields{
					"tunnel_id":  req.tunnelID,
					"message_id": msgID,
					"age":        now.Sub(req.createdAt),
				}).Warn("Tunnel build timed out")

				// Schedule cleanup
				go tm.cleanupFailedTunnel(req.tunnelID)
			}
		}
	}

	// Remove expired requests from map
	for _, msgID := range expired {
		delete(tm.pendingBuilds, msgID)
	}

	if len(expired) > 0 {
		log.WithField("expired_count", len(expired)).Info("Cleaned up expired build requests")
	}
}

// DatabaseManager demonstrates database-related interface usage
type DatabaseManager struct {
	netdb           NetDBStore
	retriever       NetDBRetriever
	sessionProvider SessionProvider
	factory         *I2NPMessageFactory
}

// NetDBStore defines the interface for storing RouterInfo entries
type NetDBStore interface {
	StoreRouterInfo(key common.Hash, data []byte, dataType byte) error
}

// NetDBRetriever defines the interface for retrieving RouterInfo entries
type NetDBRetriever interface {
	GetRouterInfoBytes(hash common.Hash) ([]byte, error)
	GetRouterInfoCount() int
}

// TransportSession defines the interface for sending I2NP messages back to requesters
type TransportSession interface {
	QueueSendI2NP(msg I2NPMessage)
	SendQueueSize() int
}

// SessionProvider defines the interface for obtaining transport sessions
type SessionProvider interface {
	GetSessionByHash(hash common.Hash) (TransportSession, error)
}

// NewDatabaseManager creates a new database manager with NetDB integration
func NewDatabaseManager(netdb NetDBStore) *DatabaseManager {
	return &DatabaseManager{
		netdb:           netdb,
		retriever:       nil, // Will be set later via SetRetriever
		sessionProvider: nil, // Will be set later via SetSessionProvider
		factory:         NewI2NPMessageFactory(),
	}
}

// SetRetriever sets the NetDB retriever for database operations
func (dm *DatabaseManager) SetRetriever(retriever NetDBRetriever) {
	dm.retriever = retriever
}

// SetSessionProvider sets the session provider for sending responses
func (dm *DatabaseManager) SetSessionProvider(provider SessionProvider) {
	dm.sessionProvider = provider
}

// SetPeerSelector sets the peer selector for the TunnelManager
func (mr *MessageRouter) SetPeerSelector(selector tunnel.PeerSelector) {
	mr.tunnelMgr.peerSelector = selector
	if mr.tunnelMgr.pool != nil {
		mr.tunnelMgr.pool = tunnel.NewTunnelPool(selector)
	}
}

// SetSessionProvider configures the session provider for message routing responses.
// This method propagates the SessionProvider to both DatabaseManager and TunnelManager,
// enabling them to send I2NP response messages (DatabaseStore, DatabaseSearchReply, etc.)
// back through the appropriate transport sessions.
// The provider must implement SessionProvider interface with GetSessionByHash method.
func (mr *MessageRouter) SetSessionProvider(provider SessionProvider) {
	// Propagate to DatabaseManager for database operation responses
	mr.dbManager.SetSessionProvider(provider)

	// Propagate to TunnelManager for tunnel build responses
	mr.tunnelMgr.SetSessionProvider(provider)

	log.Debug("Session provider configured for message router")
}

// PerformLookup performs a database lookup using DatabaseReader interface and generates appropriate responses
func (dm *DatabaseManager) PerformLookup(reader DatabaseReader) error {
	key := reader.GetKey()
	from := reader.GetFrom()
	flags := reader.GetFlags()

	log.WithFields(logger.Fields{
		"key":   fmt.Sprintf("%x", key[:8]),
		"from":  fmt.Sprintf("%x", from[:8]),
		"flags": flags,
	}).Debug("Performing database lookup")

	// If no session provider is available, just perform the lookup logic without sending responses
	// This maintains backward compatibility with existing tests
	if dm.sessionProvider == nil {
		log.Debug("No session provider available, performing lookup without sending response")
		if dm.retriever != nil {
			if data, err := dm.retrieveRouterInfo(key); err == nil {
				log.WithField("data_size", len(data)).Debug("RouterInfo found locally")
			} else {
				log.WithField("error", err).Debug("RouterInfo not found locally")
			}
		} else {
			log.Debug("No retriever available, cannot perform lookup")
		}
		return nil
	}

	// Attempt to retrieve RouterInfo from NetDB
	if dm.retriever != nil {
		if data, err := dm.retrieveRouterInfo(key); err == nil {
			// RouterInfo found - send DatabaseStore response
			return dm.sendDatabaseStoreResponse(key, data, from)
		} else {
			log.WithField("error", err).Debug("RouterInfo not found locally for remote lookup")
		}
	} else {
		log.Debug("No retriever available, cannot perform lookup")
	}

	// RouterInfo not found - send DatabaseSearchReply response
	return dm.sendDatabaseSearchReply(key, from)
}

// retrieveRouterInfo attempts to retrieve RouterInfo data from the NetDB
func (dm *DatabaseManager) retrieveRouterInfo(key common.Hash) ([]byte, error) {
	data, err := dm.retriever.GetRouterInfoBytes(key)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve RouterInfo: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("RouterInfo not found for key %x", key[:8])
	}
	return data, nil
}

// sendDatabaseStoreResponse sends a DatabaseStore message back to the requester
func (dm *DatabaseManager) sendDatabaseStoreResponse(key common.Hash, data []byte, to common.Hash) error {
	// Create DatabaseStore message with the found RouterInfo
	response := NewDatabaseStore(key, data, 0) // RouterInfo type is 0
	return dm.sendResponse(response, to)
}

// sendDatabaseSearchReply sends a DatabaseSearchReply when RouterInfo is not found
func (dm *DatabaseManager) sendDatabaseSearchReply(key, to common.Hash) error {
	// Create DatabaseSearchReply with empty peer list (we're not implementing peer suggestions for MVP)
	response := NewDatabaseSearchReply(key, common.Hash{}, []common.Hash{}) // TODO: Should use our router hash as from
	return dm.sendResponse(response, to)
}

// sendResponse sends an I2NP message response using the session provider
func (dm *DatabaseManager) sendResponse(response interface{}, to common.Hash) error {
	if dm.sessionProvider == nil {
		return fmt.Errorf("no session provider available for sending response")
	}

	session, err := dm.sessionProvider.GetSessionByHash(to)
	if err != nil {
		return fmt.Errorf("failed to get session for %x: %w", to[:8], err)
	}

	// Convert response to I2NPMessage interface
	var msg I2NPMessage
	switch r := response.(type) {
	case *DatabaseStore:
		msg = dm.createDatabaseStoreMessage(r)
	case *DatabaseSearchReply:
		msg = dm.createDatabaseSearchReplyMessage(r)
	default:
		return fmt.Errorf("unsupported response type: %T", response)
	}

	// Send the response
	session.QueueSendI2NP(msg)
	log.WithFields(logger.Fields{
		"message_type": msg.Type(),
		"destination":  fmt.Sprintf("%x", to[:8]),
	}).Debug("Queued response message")
	return nil
}

// createDatabaseStoreMessage creates an I2NP message from DatabaseStore
func (dm *DatabaseManager) createDatabaseStoreMessage(store *DatabaseStore) I2NPMessage {
	msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATABASE_STORE)
	if data, err := store.MarshalBinary(); err == nil {
		msg.SetData(data)
	} else {
		log.WithField("error", err).Error("Failed to marshal DatabaseStore")
	}
	return msg
}

// createDatabaseSearchReplyMessage creates an I2NP message from DatabaseSearchReply
func (dm *DatabaseManager) createDatabaseSearchReplyMessage(reply *DatabaseSearchReply) I2NPMessage {
	msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATABASE_SEARCH_REPLY)
	if data, err := reply.MarshalBinary(); err == nil {
		msg.SetData(data)
	} else {
		log.WithField("error", err).Error("Failed to marshal DatabaseSearchReply")
	}
	return msg
}

// StoreData stores data using DatabaseWriter interface and NetDB integration
func (dm *DatabaseManager) StoreData(writer DatabaseWriter) error {
	key := writer.GetStoreKey()
	data := writer.GetStoreData()
	dataType := writer.GetStoreType()

	log.WithFields(logger.Fields{
		"data_size": len(data),
		"data_type": dataType,
		"key":       fmt.Sprintf("%x", key[:8]),
	}).Debug("Storing RouterInfo data")

	if dm.netdb != nil {
		return dm.netdb.StoreRouterInfo(key, data, dataType)
	}

	return fmt.Errorf("no NetDB available for storage")
}

// SessionManager demonstrates session-related interface usage
type SessionManager struct{}

// NewSessionManager creates a new session manager
func NewSessionManager() *SessionManager {
	return &SessionManager{}
}

// ProcessKeys processes session keys using SessionKeyProvider interface
func (sm *SessionManager) ProcessKeys(provider SessionKeyProvider) error {
	replyKey := provider.GetReplyKey()
	layerKey := provider.GetLayerKey()
	ivKey := provider.GetIVKey()

	log.WithFields(logger.Fields{
		"reply_key": fmt.Sprintf("%x", replyKey[:8]),
		"layer_key": fmt.Sprintf("%x", layerKey[:8]),
		"iv_key":    fmt.Sprintf("%x", ivKey[:8]),
	}).Debug("Processing session keys")

	return nil
}

// ProcessTags processes session tags using SessionTagProvider interface
func (sm *SessionManager) ProcessTags(provider SessionTagProvider) error {
	tags := provider.GetReplyTags()
	count := provider.GetTagCount()

	log.WithField("tag_count", count).Debug("Processing session tags")
	for i, tag := range tags {
		if i >= count {
			break
		}
		// Convert session tag to bytes for display
		tagBytes := tag.Bytes()
		log.WithFields(logger.Fields{
			"tag_index": i,
			"tag":       fmt.Sprintf("%x", tagBytes[:8]),
		}).Debug("Processing session tag")
	}

	return nil
}

// MessageRouterConfig represents configuration for message routing
type MessageRouterConfig struct {
	MaxRetries     int
	DefaultTimeout time.Duration
	EnableLogging  bool
}

// MessageRouter demonstrates advanced interface-based routing
type MessageRouter struct {
	config     MessageRouterConfig
	processor  *MessageProcessor
	dbManager  *DatabaseManager
	tunnelMgr  *TunnelManager
	sessionMgr *SessionManager
}

// NewMessageRouter creates a new message router
func NewMessageRouter(config MessageRouterConfig) *MessageRouter {
	return &MessageRouter{
		config:     config,
		processor:  NewMessageProcessor(),
		dbManager:  NewDatabaseManager(nil), // Will be set later via SetNetDB
		tunnelMgr:  NewTunnelManager(nil),   // Will be set later via SetPeerSelector
		sessionMgr: NewSessionManager(),
	}
}

// SetNetDB sets the NetDB store for database operations
func (mr *MessageRouter) SetNetDB(netdb NetDBStore) {
	mr.dbManager = NewDatabaseManager(netdb)
}

// RouteMessage routes messages based on their interfaces
func (mr *MessageRouter) RouteMessage(msg I2NPMessage) error {
	// Log message if enabled
	if mr.config.EnableLogging {
		log.WithFields(logger.Fields{
			"message_type": msg.Type(),
			"message_id":   msg.MessageID(),
		}).Debug("Routing message")
	}

	// Check for expiration
	if time.Now().After(msg.Expiration()) {
		return fmt.Errorf("message %d has expired", msg.MessageID())
	}

	// Process using the appropriate interface
	return mr.processor.ProcessMessage(msg)
}

// RouteDatabaseMessage routes database-related messages
func (mr *MessageRouter) RouteDatabaseMessage(msg interface{}) error {
	if reader, ok := msg.(DatabaseReader); ok {
		return mr.dbManager.PerformLookup(reader)
	}

	if writer, ok := msg.(DatabaseWriter); ok {
		return mr.dbManager.StoreData(writer)
	}

	return fmt.Errorf("message does not implement database interfaces")
}

// RouteTunnelMessage routes tunnel-related messages
func (mr *MessageRouter) RouteTunnelMessage(msg interface{}) error {
	if builder, ok := msg.(TunnelBuilder); ok {
		return mr.tunnelMgr.BuildTunnel(builder)
	}

	if handler, ok := msg.(TunnelReplyHandler); ok {
		// Extract message ID from the message interface
		var messageID int
		if i2npMsg, ok := msg.(I2NPMessage); ok {
			messageID = i2npMsg.MessageID()
		}
		return mr.tunnelMgr.ProcessTunnelReply(handler, messageID)
	}

	return fmt.Errorf("message does not implement tunnel interfaces")
}

// Helper functions have been moved to utils.go
