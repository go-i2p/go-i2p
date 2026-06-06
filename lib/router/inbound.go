package router

import (
	"encoding/binary"
	"sync"

	cryptotunnel "github.com/go-i2p/crypto/tunnel"
	"github.com/go-i2p/go-i2p/lib/i2cp"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// InboundMessageHandler processes inbound tunnel messages and delivers them to I2CP sessions.
// This component bridges tunnel endpoints with I2CP client sessions, enabling end-to-end
// message delivery from the I2P network to local applications.
// It also handles forwarding of transit tunnel data (when this router is an intermediate hop).
//
// Design:
// - Maps tunnel IDs to I2CP sessions for message routing
// - Uses tunnel endpoints to decrypt incoming TunnelData messages
// - Delivers decrypted I2NP messages to appropriate I2CP session queues
// - Forwards transit tunnel messages through the participant manager
// - Thread-safe for concurrent message processing
type InboundMessageHandler struct {
	mu sync.RWMutex

	// Map tunnel ID to the session that owns it and its endpoint
	tunnelSessions map[tunnel.TunnelID]*inboundTunnelEntry

	// I2CP session manager for looking up sessions
	sessionManager *i2cp.SessionManager

	// Participant manager for transit tunnel relaying
	participantManager *tunnel.ParticipantManager

	// Session provider for forwarding transit tunnel messages
	sessionProvider i2np.SessionProvider
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

// SetParticipantManager wires the participant manager for transit tunnel forwarding.
func (h *InboundMessageHandler) SetParticipantManager(pm *tunnel.ParticipantManager) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.participantManager = pm
}

// SetSessionProvider wires the session provider for forwarding transit tunnel messages.
func (h *InboundMessageHandler) SetSessionProvider(sp i2np.SessionProvider) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sessionProvider = sp
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
		return oops.Errorf("tunnel %d already registered", tunnelID)
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
		return nil, oops.Wrapf(err, "failed to create endpoint")
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
// 2. Check if this is a transit tunnel (participant) or inbound endpoint
// 3a. For transit: decrypt one layer and forward to next hop
// 3b. For inbound: decrypt and deliver to I2CP session
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
func (h *InboundMessageHandler) HandleTunnelData(msg i2np.Message) error {
	data, tunnelID, err := extractTunnelPayload(msg)
	if err != nil {
		return err
	}

	log.WithFields(logger.Fields{
		"at":        "HandleTunnelData",
		"tunnel_id": tunnelID,
		"data_size": len(data),
	}).Debug("Processing tunnel data message")

	// Check if this is a transit (participant) tunnel
	if participant := h.getParticipant(tunnelID); participant != nil {
		return h.handleTransitTunnelData(tunnelID, data, participant)
	}

	// Otherwise, handle as inbound endpoint tunnel
	entry, ok := h.lookupTunnelEntry(tunnelID)
	if !ok {
		return nil
	}

	return h.decryptAndDeliver(tunnelID, data, entry)
}

// extractTunnelPayload validates the message type and data size, returning
// the 1024-byte tunnel payload and the tunnel ID.
func extractTunnelPayload(msg i2np.Message) ([]byte, tunnel.TunnelID, error) {
	tunnelCarrier, ok := msg.(i2np.TunnelCarrier)
	if !ok {
		log.WithFields(logger.Fields{
			"at":           "HandleTunnelData",
			"message_type": msg.Type(),
			"reason":       "message does not implement TunnelCarrier",
		}).Error("Invalid message type")
		return nil, 0, oops.Errorf("message does not implement TunnelCarrier interface")
	}

	data := tunnelCarrier.GetTunnelData()
	if len(data) != 1024 {
		log.WithFields(logger.Fields{
			"at":       "HandleTunnelData",
			"expected": 1024,
			"actual":   len(data),
			"reason":   "wrong tunnel data size",
		}).Error("Invalid tunnel data")
		return nil, 0, oops.Errorf("tunnel data wrong size: expected 1024 bytes, got %d", len(data))
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
		return oops.Wrapf(err, "failed to decrypt tunnel message")
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
			return oops.Errorf("session %d not found", sessionID)
		}

		// Queue the message for delivery to the client
		if err := session.QueueIncomingMessage(msgBytes); err != nil {
			log.WithFields(logger.Fields{
				"session_id": sessionID,
				"error":      err,
			}).Error("Failed to queue incoming message")
			return oops.Wrapf(err, "failed to queue message")
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

// getParticipant retrieves a participant tunnel by tunnel ID.
// Returns nil if no participant is registered for this tunnel ID.
func (h *InboundMessageHandler) getParticipant(tunnelID tunnel.TunnelID) *tunnel.Participant {
	if h.participantManager == nil {
		return nil
	}
	return h.participantManager.GetParticipant(tunnelID)
}

// handleTransitTunnelData processes a transit tunnel message by decrypting one layer
// and forwarding to the next hop.
//
// Parameters:
// - tunnelID: the tunnel ID for this transit tunnel
// - data: the 1024-byte encrypted tunnel data
// - participant: the participant tunnel that will decrypt one layer
//
// Returns an error if processing fails.
func (h *InboundMessageHandler) handleTransitTunnelData(tunnelID tunnel.TunnelID, data []byte, participant *tunnel.Participant) error {
	if participant == nil {
		log.WithFields(logger.Fields{
			"at":        "handleTransitTunnelData",
			"tunnel_id": tunnelID,
			"reason":    "nil_participant",
		}).Error("participant tunnel is nil")
		return oops.Errorf("participant tunnel is nil for tunnel %d", tunnelID)
	}

	// Decrypt one layer of encryption
	// Participant.Process returns: (nextHopID, decryptedData, error)
	nextHopID, decrypted, err := participant.Process(data)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "handleTransitTunnelData",
			"tunnel_id": tunnelID,
			"error":     err,
		}).Debug("Failed to decrypt participant tunnel data")
		return oops.Wrapf(err, "failed to decrypt transit tunnel data")
	}

	// Forward to the next hop
	if err := h.forwardToNextHop(nextHopID, decrypted); err != nil {
		log.WithFields(logger.Fields{
			"at":        "handleTransitTunnelData",
			"tunnel_id": tunnelID,
			"error":     err,
		}).Error("Failed to forward decrypted transit data")
		return oops.Wrapf(err, "failed to forward transit tunnel data")
	}

	log.WithFields(logger.Fields{
		"at":          "handleTransitTunnelData",
		"tunnel_id":   tunnelID,
		"next_hop_id": nextHopID,
	}).Debug("Successfully forwarded transit tunnel data")

	return nil
}

// forwardToNextHop sends a decrypted tunnel message to the next hop.
// The message is already decrypted and contains the next hop tunnel ID in the header.
//
// Parameters:
// - nextHopID: the tunnel ID at the next hop
// - decryptedData: the decrypted tunnel message (1028 bytes with next hop tunnel ID in header)
//
// Returns an error if forwarding fails.
//
// NOTE: This is a minimal implementation that currently logs the forward intent.
// Full integration with the transport layer will be added in a future phase
// to actually route the message to the next hop router.
func (h *InboundMessageHandler) forwardToNextHop(nextHopID tunnel.TunnelID, decryptedData []byte) error {
	if nextHopID == 0 {
		// Tunnel ID 0 means deliver to the router (endpoint), not transit
		log.WithFields(logger.Fields{
			"at":     "forwardToNextHop",
			"reason": "tunnel_endpoint_reached",
		}).Debug("transit tunnel reached endpoint (tunnel ID 0)")
		// This case would be handled differently - delivering to the endpoint
		// For now, log it since we're in the transit path
		return oops.Errorf("tunnel endpoint (ID 0) reached in transit forwarding - delivery required")
	}

	// Validate decrypted data size
	if len(decryptedData) != 1028 {
		return oops.Errorf("invalid decrypted data size: expected 1028 bytes, got %d", len(decryptedData))
	}

	log.WithFields(logger.Fields{
		"at":          "forwardToNextHop",
		"next_hop_id": nextHopID,
		"data_size":   len(decryptedData),
		"status":      "forwarding_queued",
	}).Debug("Transit tunnel data ready for forwarding (transport integration pending)")

	// TODO: Implement actual transport forwarding
	// 1. Look up route to next hop router
	// 2. Get/create transport session
	// 3. Wrap in TunnelData message with nextHopID
	// 4. Queue for transmission

	return nil
}
