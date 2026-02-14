package router

import (
	"encoding/binary"
	"fmt"
	"sync"

	cryptotunnel "github.com/go-i2p/crypto/tunnel"
	"github.com/go-i2p/go-i2p/lib/i2cp"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/logger"
)

// InboundMessageHandler processes inbound tunnel messages and delivers them to I2CP sessions.
// This component bridges tunnel endpoints with I2CP client sessions, enabling end-to-end
// message delivery from the I2P network to local applications.
//
// Design:
// - Maps tunnel IDs to I2CP sessions for message routing
// - Uses tunnel endpoints to decrypt incoming TunnelData messages
// - Delivers decrypted I2NP messages to appropriate I2CP session queues
// - Thread-safe for concurrent message processing
type InboundMessageHandler struct {
	mu sync.RWMutex

	// Map tunnel ID to the session that owns it and its endpoint
	tunnelSessions map[tunnel.TunnelID]*inboundTunnelEntry

	// I2CP session manager for looking up sessions
	sessionManager *i2cp.SessionManager
}

// inboundTunnelEntry tracks the session and endpoint for an inbound tunnel
type inboundTunnelEntry struct {
	sessionID uint16
	endpoint  *tunnel.Endpoint
}

// NewInboundMessageHandler creates a new inbound message handler
func NewInboundMessageHandler(sessionManager *i2cp.SessionManager) *InboundMessageHandler {
	log.WithFields(logger.Fields{
		"at":     "NewInboundMessageHandler",
		"reason": "initialization",
	}).Debug("creating inbound message handler")
	return &InboundMessageHandler{
		tunnelSessions: make(map[tunnel.TunnelID]*inboundTunnelEntry),
		sessionManager: sessionManager,
	}
}

// RegisterTunnel registers an inbound tunnel for a specific I2CP session.
// This must be called when a new inbound tunnel is created so that
// incoming messages can be routed to the correct session.
//
// Parameters:
// - tunnelID: the ID of the inbound tunnel
// - sessionID: the I2CP session ID that owns this tunnel
// - endpoint: the tunnel endpoint for decrypting messages
//
// Returns an error if the tunnel is already registered.
func (h *InboundMessageHandler) RegisterTunnel(tunnelID tunnel.TunnelID, sessionID uint16, endpoint *tunnel.Endpoint) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if _, exists := h.tunnelSessions[tunnelID]; exists {
		log.WithFields(logger.Fields{
			"at":         "RegisterTunnel",
			"tunnel_id":  tunnelID,
			"session_id": sessionID,
			"reason":     "tunnel already registered",
		}).Error("Failed to register tunnel")
		return fmt.Errorf("tunnel %d already registered", tunnelID)
	}

	h.tunnelSessions[tunnelID] = &inboundTunnelEntry{
		sessionID: sessionID,
		endpoint:  endpoint,
	}

	log.WithFields(logger.Fields{
		"tunnel_id":  tunnelID,
		"session_id": sessionID,
	}).Debug("Registered inbound tunnel for session")

	return nil
}

// CreateEndpointForSession creates a tunnel endpoint with the message handler
// already wired to deliver decrypted messages to the specified I2CP session.
// The returned endpoint is also registered with this handler.
//
// This is the preferred way to create inbound tunnel endpoints, as it ensures
// the decrypted message delivery pipeline (tunnel → I2CP) is complete.
//
// Parameters:
// - tunnelID: the ID of the inbound tunnel
// - sessionID: the I2CP session ID that owns this tunnel
// - decryption: the tunnel decryption object for layered decryption
//
// Returns the created endpoint or an error if creation or registration fails.
func (h *InboundMessageHandler) CreateEndpointForSession(tunnelID tunnel.TunnelID, sessionID uint16, decryption cryptotunnel.TunnelEncryptor) (*tunnel.Endpoint, error) {
	// Create the message handler that delivers decrypted messages to the I2CP session
	messageHandler := h.createMessageHandler(sessionID)

	// Create the endpoint with the handler wired in
	endpoint, err := tunnel.NewEndpoint(tunnelID, decryption, messageHandler)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":         "CreateEndpointForSession",
			"tunnel_id":  tunnelID,
			"session_id": sessionID,
			"reason":     "endpoint creation failed",
		}).WithError(err).Error("Failed to create endpoint")
		return nil, fmt.Errorf("failed to create endpoint: %w", err)
	}

	// Register the tunnel
	if err := h.RegisterTunnel(tunnelID, sessionID, endpoint); err != nil {
		endpoint.Stop()
		return nil, err
	}

	log.WithFields(logger.Fields{
		"at":         "CreateEndpointForSession",
		"tunnel_id":  tunnelID,
		"session_id": sessionID,
	}).Debug("Created and registered inbound endpoint with I2CP message handler")

	return endpoint, nil
}

// UnregisterTunnel removes an inbound tunnel from the handler.
// This should be called when a tunnel expires or is destroyed.
func (h *InboundMessageHandler) UnregisterTunnel(tunnelID tunnel.TunnelID) {
	h.mu.Lock()
	defer h.mu.Unlock()

	delete(h.tunnelSessions, tunnelID)

	log.WithFields(logger.Fields{
		"at":        "(InboundMessageHandler) UnregisterTunnel",
		"reason":    "tunnel_removed",
		"tunnel_id": tunnelID,
	}).Debug("unregistered inbound tunnel")
}

// HandleTunnelData processes an incoming TunnelData message.
// This is the main entry point for inbound message delivery.
//
// Process:
// 1. Extract tunnel ID from the TunnelCarrier interface
// 2. Find the corresponding session and endpoint
// 3. Decrypt the tunnel message using the endpoint
// 4. Deliver the decrypted I2NP message to the session
//
// Parameters:
// - msg: the I2NP TunnelData message to process
//
// Returns an error if processing fails at any step.
//
// The wire format for TunnelData is 1028 bytes:
//
//	[Tunnel ID (4 bytes)] + [Encrypted Data (1024 bytes)]
//
// HandleTunnelData processes an inbound TunnelData I2NP message by validating,
// looking up the owning session, decrypting, and delivering to the I2CP client.
func (h *InboundMessageHandler) HandleTunnelData(msg i2np.I2NPMessage) error {
	data, tunnelID, err := extractTunnelPayload(msg)
	if err != nil {
		return err
	}

	log.WithFields(logger.Fields{
		"at":        "HandleTunnelData",
		"tunnel_id": tunnelID,
		"data_size": len(data),
	}).Debug("Processing tunnel data message")

	entry, ok := h.lookupTunnelEntry(tunnelID)
	if !ok {
		return nil
	}

	return h.decryptAndDeliver(tunnelID, data, entry)
}

// extractTunnelPayload validates the message type and data size, returning
// the 1024-byte tunnel payload and the tunnel ID.
func extractTunnelPayload(msg i2np.I2NPMessage) ([]byte, tunnel.TunnelID, error) {
	tunnelCarrier, ok := msg.(i2np.TunnelCarrier)
	if !ok {
		log.WithFields(logger.Fields{
			"at":           "HandleTunnelData",
			"message_type": msg.Type(),
			"reason":       "message does not implement TunnelCarrier",
		}).Error("Invalid message type")
		return nil, 0, fmt.Errorf("message does not implement TunnelCarrier interface")
	}

	data := tunnelCarrier.GetTunnelData()
	if len(data) != 1024 {
		log.WithFields(logger.Fields{
			"at":       "HandleTunnelData",
			"expected": 1024,
			"actual":   len(data),
			"reason":   "wrong tunnel data size",
		}).Error("Invalid tunnel data")
		return nil, 0, fmt.Errorf("tunnel data wrong size: expected 1024 bytes, got %d", len(data))
	}

	return data, tunnelCarrier.GetTunnelID(), nil
}

// lookupTunnelEntry finds the session and endpoint registered for a tunnel ID.
// Returns nil and false if the tunnel is not registered (e.g. transit or exploratory).
func (h *InboundMessageHandler) lookupTunnelEntry(tunnelID tunnel.TunnelID) (*inboundTunnelEntry, bool) {
	h.mu.RLock()
	entry, exists := h.tunnelSessions[tunnelID]
	h.mu.RUnlock()

	if !exists {
		log.WithFields(logger.Fields{
			"at":        "(InboundMessageHandler) HandleTunnelData",
			"reason":    "unregistered_tunnel",
			"tunnel_id": tunnelID,
		}).Debug("received TunnelData for unregistered tunnel")
		return nil, false
	}
	return entry, true
}

// decryptAndDeliver reconstructs the wire-format message and passes it to the
// tunnel endpoint for decryption and delivery.
func (h *InboundMessageHandler) decryptAndDeliver(tunnelID tunnel.TunnelID, data []byte, entry *inboundTunnelEntry) error {
	// The endpoint.Receive() expects exactly 1028 bytes: 4-byte tunnel ID + 1024-byte data.
	fullMsg := make([]byte, 1028)
	binary.BigEndian.PutUint32(fullMsg[0:4], uint32(tunnelID))
	copy(fullMsg[4:], data)

	if err := entry.endpoint.Receive(fullMsg); err != nil {
		log.WithFields(logger.Fields{
			"tunnel_id":  tunnelID,
			"session_id": entry.sessionID,
			"error":      err,
		}).Error("Failed to decrypt tunnel message")
		return fmt.Errorf("failed to decrypt tunnel message: %w", err)
	}

	log.WithFields(logger.Fields{
		"tunnel_id":  tunnelID,
		"session_id": entry.sessionID,
	}).Debug("Successfully processed inbound tunnel message")

	return nil
}

// createMessageHandler creates a message handler callback for a specific session.
// This handler is called by the tunnel endpoint when a decrypted message is ready.
//
// The handler:
// 1. Receives the raw I2NP message bytes from the endpoint
// 2. Looks up the I2CP session
// 3. Queues the message for delivery to the client
//
// Returns a MessageHandler callback function.
func (h *InboundMessageHandler) createMessageHandler(sessionID uint16) tunnel.MessageHandler {
	return func(msgBytes []byte) error {
		// Look up the session
		session, ok := h.sessionManager.GetSession(sessionID)
		if !ok {
			log.WithFields(logger.Fields{
				"at":         "createMessageHandler",
				"session_id": sessionID,
				"reason":     "session not found",
			}).Error("Failed to lookup session")
			return fmt.Errorf("session %d not found", sessionID)
		}

		// Queue the message for delivery to the client
		if err := session.QueueIncomingMessage(msgBytes); err != nil {
			log.WithFields(logger.Fields{
				"session_id": sessionID,
				"error":      err,
			}).Error("Failed to queue incoming message")
			return fmt.Errorf("failed to queue message: %w", err)
		}

		log.WithFields(logger.Fields{
			"session_id":   sessionID,
			"message_size": len(msgBytes),
		}).Debug("Queued incoming message for I2CP session")

		return nil
	}
}

// GetTunnelCount returns the number of registered inbound tunnels
func (h *InboundMessageHandler) GetTunnelCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.tunnelSessions)
}

// GetTunnelSession returns the session ID for a given tunnel ID, if registered
func (h *InboundMessageHandler) GetTunnelSession(tunnelID tunnel.TunnelID) (uint16, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	entry, exists := h.tunnelSessions[tunnelID]
	if !exists {
		return 0, false
	}

	return entry.sessionID, true
}
