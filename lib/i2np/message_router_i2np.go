package i2np

import (
	"fmt"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// I2NPMessageDispatcherConfig represents configuration for message routing
type I2NPMessageDispatcherConfig struct {
	MaxRetries     int
	DefaultTimeout time.Duration
	EnableLogging  bool
}

// I2NPMessageDispatcher demonstrates advanced interface-based routing
type I2NPMessageDispatcher struct {
	config    I2NPMessageDispatcherConfig
	processor *MessageProcessor
	dbManager *DatabaseManager
	tunnelMgr *TunnelManager
}

// NewI2NPMessageDispatcher creates a new message router
func NewI2NPMessageDispatcher(config I2NPMessageDispatcherConfig) *I2NPMessageDispatcher {
	return &I2NPMessageDispatcher{
		config:    config,
		processor: NewMessageProcessor(),
		dbManager: NewDatabaseManager(nil), // Will be set later via SetNetDB
		tunnelMgr: NewTunnelManager(nil),   // Will be set later via SetPeerSelector
	}
}

// SetNetDB sets the NetDB store for database operations.
// If the netdb implements FloodfillSelector, it will also be configured for floodfill functionality.
func (mr *I2NPMessageDispatcher) SetNetDB(netdb I2NPNetDBStore) {
	mr.dbManager = NewDatabaseManager(netdb)

	// If NetDB also implements FloodfillSelector, enable floodfill functionality
	if selector, ok := netdb.(FloodfillSelector); ok {
		mr.dbManager.SetFloodfillSelector(selector)
		log.WithFields(logger.Fields{"at": "SetNetDB"}).Debug("Floodfill selector configured for message router")
	}

	// If NetDB also implements NetDBRetriever, configure retriever
	if retriever, ok := netdb.(NetDBRetriever); ok {
		mr.dbManager.SetRetriever(retriever)
		log.WithFields(logger.Fields{"at": "SetNetDB"}).Debug("NetDB retriever configured for message router")
	}

	// Set database manager on processor for DatabaseLookup message handling
	mr.processor.SetDatabaseManager(mr.dbManager)
}

// SetOurRouterHash sets our router's identity hash for use in DatabaseSearchReply messages.
// This should be called during router initialization with the router's own identity hash.
// The hash is used in DatabaseSearchReply "from" field to indicate which router sent the reply.
func (mr *I2NPMessageDispatcher) SetOurRouterHash(hash common.Hash) {
	mr.dbManager.SetOurRouterHash(hash)
	mr.processor.SetOurRouterHash(hash)
	log.WithField("router_hash", fmt.Sprintf("%x", hash[:8])).Debug("Configured router identity for floodfill responses")
}

// SetPeerSelector sets the peer selector for the TunnelManager
func (mr *I2NPMessageDispatcher) SetPeerSelector(selector tunnel.PeerSelector) {
	mr.tunnelMgr.peerSelector = selector
	// Recreate pools with new selector if they exist
	if mr.tunnelMgr.inboundPool != nil || mr.tunnelMgr.outboundPool != nil {
		// Stop existing pools
		if mr.tunnelMgr.inboundPool != nil {
			mr.tunnelMgr.inboundPool.Stop()
		}
		if mr.tunnelMgr.outboundPool != nil {
			mr.tunnelMgr.outboundPool.Stop()
		}
		// Create new pools
		inboundConfig := tunnel.DefaultPoolConfig()
		inboundConfig.IsInbound = true
		mr.tunnelMgr.inboundPool = tunnel.NewTunnelPoolWithConfig(selector, inboundConfig)

		outboundConfig := tunnel.DefaultPoolConfig()
		outboundConfig.IsInbound = false
		mr.tunnelMgr.outboundPool = tunnel.NewTunnelPoolWithConfig(selector, outboundConfig)
	}
}

// SetSessionProvider configures the session provider for message routing responses.
// This method propagates the SessionProvider to both DatabaseManager and TunnelManager,
// enabling them to send I2NP response messages (DatabaseStore, DatabaseSearchReply, etc.)
// back through the appropriate transport sessions.
// The provider must implement SessionProvider interface with GetSessionByHash method.
func (mr *I2NPMessageDispatcher) SetSessionProvider(provider SessionProvider) {
	// Propagate to DatabaseManager for database operation responses
	mr.dbManager.SetSessionProvider(provider)

	// Propagate to TunnelManager for tunnel build responses
	mr.tunnelMgr.SetSessionProvider(provider)

	log.WithFields(logger.Fields{"at": "SetSessionProvider"}).Debug("Session provider configured for message router")
}

// RouteMessage routes messages based on their interfaces
func (mr *I2NPMessageDispatcher) RouteMessage(msg I2NPMessage) error {
	// Log message if enabled
	if mr.config.EnableLogging {
		log.WithFields(logger.Fields{
			"message_type": msg.Type(),
			"message_id":   msg.MessageID(),
		}).Debug("Routing message")
	}

	// Check for expiration
	if time.Now().After(msg.Expiration()) {
		return oops.Errorf("message %d has expired", msg.MessageID())
	}

	// Process using the appropriate interface
	return mr.processor.ProcessMessage(msg)
}

// RouteDatabaseMessage routes database-related messages
func (mr *I2NPMessageDispatcher) RouteDatabaseMessage(msg interface{}) error {
	if reader, ok := msg.(DatabaseReader); ok {
		return mr.dbManager.PerformLookup(reader)
	}

	if writer, ok := msg.(DatabaseWriter); ok {
		return mr.dbManager.StoreData(writer)
	}

	return oops.Errorf("message does not implement database interfaces")
}

// RouteTunnelMessage routes tunnel-related messages
func (mr *I2NPMessageDispatcher) RouteTunnelMessage(msg interface{}) error {
	if builder, ok := msg.(TunnelBuilder); ok {
		return mr.tunnelMgr.BuildTunnelWithBuilder(builder)
	}

	if handler, ok := msg.(TunnelReplyHandler); ok {
		// Extract message ID from the message interface
		var messageID int
		if i2npMsg, ok := msg.(I2NPMessage); ok {
			messageID = i2npMsg.MessageID()
		}
		return mr.tunnelMgr.ProcessTunnelReply(handler, messageID)
	}

	return oops.Errorf("message does not implement tunnel interfaces")
}

// SetTunnelManager replaces the internal TunnelManager with an external one.
// This must be called from the router after r.tunnelManager is created so that
// both the dispatcher and the router share the same pendingBuilds map, enabling
// build-reply correlation (A3 fix).
func (mr *I2NPMessageDispatcher) SetTunnelManager(tm *TunnelManager) {
	mr.tunnelMgr = tm
}

// GetProcessor returns the underlying MessageProcessor for direct access.
// This is used by the router to set up garlic clove forwarding.
func (mr *I2NPMessageDispatcher) GetProcessor() *MessageProcessor {
	return mr.processor
}

// Helper functions have been moved to utils.go
