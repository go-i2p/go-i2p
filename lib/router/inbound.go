package router

import (
	"bytes"
	"encoding/binary"
	"sort"
	"sync"

	common "github.com/go-i2p/common/data"
	cryptotunnel "github.com/go-i2p/crypto/tunnel"
	"github.com/go-i2p/go-i2p/lib/i2cp"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/go-i2p/lib/util/logutil"
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

	// processor is the I2NP message processor used for control-plane (exploratory)
	// tunnel message delivery. Set via SetProcessor after construction.
	processor *i2np.MessageProcessor
}

// SetProcessor wires the I2NP message processor into this handler so that
// decrypted messages from exploratory/reply inbound tunnels (registered via
// RegisterExploratoryTunnel) can be re-dispatched as I2NP messages rather
// than routed to an I2CP session.
func (h *InboundMessageHandler) SetProcessor(p *i2np.MessageProcessor) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.processor = p
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
	if h.sessionManager == nil {
		return nil, oops.Errorf("cannot create endpoint for session %d: I2CP session manager not configured", sessionID)
	}

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
	endpoint.SetForwarder(h)

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
	registeredCount := len(h.tunnelSessions)
	registeredIDs := make([]tunnel.TunnelID, 0, len(h.tunnelSessions))
	if !exists {
		for id := range h.tunnelSessions {
			registeredIDs = append(registeredIDs, id)
		}
	}
	h.mu.RUnlock()

	if !exists {
		sort.Slice(registeredIDs, func(i, j int) bool { return registeredIDs[i] < registeredIDs[j] })
		if len(registeredIDs) > 8 {
			registeredIDs = registeredIDs[:8]
		}
		log.WithFields(logger.Fields{
			"at":                      "(InboundMessageHandler) HandleTunnelData",
			"reason":                  "unregistered_tunnel",
			"tunnel_id":               tunnelID,
			"registered_tunnel_count": registeredCount,
			"registered_tunnel_ids":   registeredIDs,
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
		if h.sessionManager == nil {
			return oops.Errorf("cannot deliver message for session %d: I2CP session manager not configured", sessionID)
		}

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

// passthroughTunnelEncryptor is a no-op TunnelEncryptor used for exploratory /
// reply inbound tunnels where build replies are delivered directly to our router
// by the OBEP (NextIdent = our hash) without passing through the tunnel's
// intermediate hop encryption layers.
type passthroughTunnelEncryptor struct{}

func (p *passthroughTunnelEncryptor) Encrypt(data []byte) ([]byte, error) {
	return data, nil
}

func (p *passthroughTunnelEncryptor) Decrypt(data []byte) ([]byte, error) {
	return data, nil
}

func (p *passthroughTunnelEncryptor) Type() cryptotunnel.TunnelEncryptionType {
	// AES(0) is the passthrough identity type — no real encryption is applied.
	return cryptotunnel.TunnelEncryptionAES
}

// createControlPlaneHandler returns a MessageHandler that deserialises the
// decrypted tunnel payload as an I2NP message and dispatches it through the
// router's MessageProcessor.  This mirrors what tunnelGatewayDispatcher does
// for TunnelGateway messages, but for TunnelData arriving at an exploratory /
// reply inbound endpoint.
func (h *InboundMessageHandler) createControlPlaneHandler(tunnelID tunnel.TunnelID) tunnel.MessageHandler {
	return func(msgBytes []byte) error {
		h.mu.RLock()
		proc := h.processor
		h.mu.RUnlock()

		if proc == nil {
			log.WithFields(logger.Fields{
				"at":     "createControlPlaneHandler",
				"reason": "processor not wired",
			}).Warn("control-plane message received but MessageProcessor is nil — dropping")
			return oops.Errorf("MessageProcessor not wired into InboundMessageHandler")
		}

		// Try full I2NP header first, then fall back to short (9-byte) header.
		inner := &i2np.BaseI2NPMessage{}
		if err := inner.UnmarshalBinary(msgBytes); err != nil {
			if err2 := inner.UnmarshalShortI2NP(msgBytes); err2 != nil {
				log.WithFields(logger.Fields{
					"at":        "createControlPlaneHandler",
					"reason":    "i2np parse failed",
					"msg_len":   len(msgBytes),
					"full_err":  err.Error(),
					"short_err": err2.Error(),
				}).Warn("failed to parse I2NP message from control-plane tunnel payload")
				return oops.Errorf("parse I2NP from control-plane payload: %v", err2)
			}
		}

		if inner.Type() == i2np.I2NPMessageTypeDeliveryStatus {
			log.WithFields(logger.Fields{
				"at":           "createControlPlaneHandler",
				"tunnel_id":    tunnelID,
				"message_type": inner.Type(),
				"message_id":   inner.MessageID(),
				"message_len":  len(msgBytes),
			}).Info("control-plane inbound tunnel delivered DeliveryStatus to processor")
		}

		return proc.ProcessMessage(inner)
	}
}

// RegisterExploratoryTunnel registers an inbound control-plane tunnel so that
// TunnelData messages delivered to it (e.g. build replies forwarded in TUNNEL
// delivery mode by a remote OBEP) are decrypted and dispatched through the
// MessageProcessor rather than silently dropped.
//
// A passthrough (identity) TunnelEncryptor is used because the remote OBEP
// sends TunnelData directly to our router (NextIdent = our hash) without
// layering the encryption of T1's intermediate hops.
func (h *InboundMessageHandler) RegisterExploratoryTunnel(tunnelID tunnel.TunnelID) error {
	endpoint, err := tunnel.NewEndpoint(tunnelID, &passthroughTunnelEncryptor{}, h.createControlPlaneHandler(tunnelID))
	if err != nil {
		return oops.Wrapf(err, "create exploratory endpoint for tunnel %d", tunnelID)
	}
	endpoint.SetForwarder(h)

	if err := h.RegisterTunnel(tunnelID, 0, endpoint); err != nil {
		endpoint.Stop()
		return oops.Wrapf(err, "register exploratory tunnel %d", tunnelID)
	}

	log.WithFields(logger.Fields{
		"at":        "RegisterExploratoryTunnel",
		"tunnel_id": tunnelID,
	}).Debug("registered inbound exploratory tunnel endpoint")

	return nil
}

// RegisterClientTunnel registers an inbound client tunnel endpoint for message delivery to an I2CP session.
// The endpoint is created with a message handler that queues decrypted messages to the owning I2CP session.
// A passthrough (identity) TunnelEncryptor is used because the inbound gateway sends TunnelData
// directly to our router without layering the encryption of intermediate hops.
//
// Parameters:
// - tunnelID: the ID of the inbound tunnel
// - sessionID: the I2CP session ID that owns this tunnel
//
// Returns an error if the tunnel cannot be registered or if the session is not found.
func (h *InboundMessageHandler) RegisterClientTunnel(tunnelID tunnel.TunnelID, sessionID uint16) error {
	if h.sessionManager == nil {
		log.WithFields(logger.Fields{
			"at":         "RegisterClientTunnel",
			"tunnel_id":  tunnelID,
			"session_id": sessionID,
			"reason":     "I2CP session manager not configured",
		}).Error("Failed to register client tunnel")
		return oops.Errorf("cannot register client tunnel %d: I2CP session manager not configured", tunnelID)
	}

	// Keep explicit session existence validation so tunnel builds fail fast when
	// the owning session has already been removed.
	if _, exists := h.sessionManager.GetSession(sessionID); !exists {
		log.WithFields(logger.Fields{
			"at":         "RegisterClientTunnel",
			"tunnel_id":  tunnelID,
			"session_id": sessionID,
			"reason":     "session not found",
		}).Error("Failed to register client tunnel: session not found")
		return oops.Errorf("session %d not found for client tunnel %d", sessionID, tunnelID)
	}

	if _, err := h.CreateEndpointForSession(tunnelID, sessionID, &passthroughTunnelEncryptor{}); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":         "RegisterClientTunnel",
			"tunnel_id":  tunnelID,
			"session_id": sessionID,
			"reason":     "create endpoint for session failed",
		}).Error("Failed to register client tunnel")
		return oops.Wrapf(err, "register client tunnel %d for session %d", tunnelID, sessionID)
	}

	log.WithFields(logger.Fields{
		"at":         "RegisterClientTunnel",
		"tunnel_id":  tunnelID,
		"session_id": sessionID,
	}).Debug("Registered inbound client tunnel endpoint with I2CP message delivery")

	return nil
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

// ForwardToTunnel routes endpoint DTTunnel deliveries via transport by wrapping
// the payload in a TunnelGateway message addressed to the gateway router.
func (h *InboundMessageHandler) ForwardToTunnel(tunnelID uint32, gatewayHash [32]byte, msgBytes []byte) error {
	h.mu.RLock()
	sp := h.sessionProvider
	h.mu.RUnlock()

	if sp == nil {
		return oops.Errorf("session provider not wired for tunnel forwarding")
	}

	gateway := common.Hash(gatewayHash)
	session, err := sp.GetSessionByHash(gateway)
	if err != nil {
		return oops.Wrapf(err, "failed to get session for tunnel forwarding to %s", logutil.HashPrefix(gateway))
	}

	gwMsg := i2np.NewTunnelGatewayMessage(tunnel.TunnelID(tunnelID), msgBytes)
	if err := session.QueueSendI2NP(gwMsg); err != nil {
		return oops.Wrapf(err, "failed to send tunnel forwarding message via %s", logutil.HashPrefix(gateway))
	}

	return nil
}

// ForwardToRouter routes endpoint DTRouter deliveries via transport by parsing
// the I2NP payload and sending it to the target router.
func (h *InboundMessageHandler) ForwardToRouter(routerHash [32]byte, msgBytes []byte) error {
	h.mu.RLock()
	sp := h.sessionProvider
	h.mu.RUnlock()

	if sp == nil {
		return oops.Errorf("session provider not wired for router forwarding")
	}

	target := common.Hash(routerHash)
	session, err := sp.GetSessionByHash(target)
	if err != nil {
		return oops.Wrapf(err, "failed to get session for router forwarding to %s", logutil.HashPrefix(target))
	}

	inner := &i2np.BaseI2NPMessage{}
	if err := inner.UnmarshalBinary(msgBytes); err != nil {
		if err2 := inner.UnmarshalShortI2NP(msgBytes); err2 != nil {
			return oops.Errorf("parse forwarded router message failed (standard: %v, short: %v)", err, err2)
		}
	}

	if err := session.QueueSendI2NP(inner); err != nil {
		return oops.Wrapf(err, "failed to send router forwarding message to %s", logutil.HashPrefix(target))
	}

	return nil
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

	// Participant.Process expects exactly 1028 bytes: 4-byte tunnel ID + 1024-byte data.
	// Reconstruct the wire-format message by prepending the tunnel ID.
	fullMsg := make([]byte, 1028)
	binary.BigEndian.PutUint32(fullMsg[0:4], uint32(tunnelID))
	copy(fullMsg[4:], data)

	// Decrypt one layer of encryption
	// Participant.Process returns: (nextHopID, decryptedData, error)
	nextHopID, decrypted, err := participant.Process(fullMsg)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "handleTransitTunnelData",
			"tunnel_id": tunnelID,
			"error":     err,
		}).Debug("Failed to decrypt participant tunnel data")
		return oops.Wrapf(err, "failed to decrypt transit tunnel data")
	}

	// Forward to the next hop
	if err := h.forwardToNextHop(participant, nextHopID, decrypted); err != nil {
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
// - participant: the participant tunnel that knows about the next hop
// - nextHopID: the tunnel ID at the next hop
// - decryptedData: the decrypted tunnel message (1028 bytes with next hop tunnel ID in header)
//
// Returns an error if forwarding fails.
func (h *InboundMessageHandler) forwardToNextHop(participant *tunnel.Participant, nextHopID tunnel.TunnelID, decryptedData []byte) error {
	// Validate decrypted data size
	if len(decryptedData) != 1028 {
		return oops.Errorf("invalid decrypted data size: expected 1028 bytes, got %d", len(decryptedData))
	}

	// If nextHopID is 0, this reaches the local endpoint (not a transit case)
	// This should not happen in transit forwarding path
	if nextHopID == 0 {
		return oops.Errorf("tunnel endpoint (ID 0) reached in transit forwarding - should not occur")
	}

	// Verify session provider is available
	if h.sessionProvider == nil {
		return oops.Errorf("session provider not wired for transit tunnel forwarding")
	}

	// Get the next hop router identity
	nextHopIdent := participant.NextHopIdent()
	// Check if the identity is empty (zero hash).
	// NOTE: bytes.Equal is safe here because we're comparing a public router hash
	// against a zero value, not secret/auth material. Constant-time comparison
	// is not required for this use case.
	emptyHash := [32]byte{}
	if bytes.Equal(nextHopIdent[:], emptyHash[:]) {
		return oops.Errorf("next hop identity is empty in participant tunnel")
	}

	// Create TunnelData message for forwarding
	// Build the 1024-byte payload from the decrypted data
	payload := [1024]byte{}
	copy(payload[:], decryptedData[4:1028])
	tunnelDataMsg := i2np.NewTunnelDataMessage(nextHopID, payload)

	// Get session to the next hop router
	session, err := h.sessionProvider.GetSessionByHash(nextHopIdent)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":          "forwardToNextHop",
			"next_hop_id": nextHopID,
			"error":       err,
		}).Debug("Failed to get session for transit forwarding (peer may be unavailable)")
		return oops.Wrapf(err, "failed to get session for transit tunnel forwarding with ID %d", nextHopID)
	}

	// Queue the message for transmission
	if err := session.QueueSendI2NP(tunnelDataMsg); err != nil {
		log.WithFields(logger.Fields{
			"at":          "forwardToNextHop",
			"next_hop_id": nextHopID,
			"error":       err,
		}).Error("Failed to queue transit tunnel data for sending")
		return oops.Wrapf(err, "failed to queue transit tunnel data for sending")
	}
	if h.participantManager != nil {
		// Count full tunnel message bytes (tunnel ID + payload) to match relay load.
		h.participantManager.ObserveTransitForwardedBytes(len(decryptedData))
	}

	log.WithFields(logger.Fields{
		"at":          "forwardToNextHop",
		"next_hop_id": nextHopID,
	}).Debug("Successfully queued transit tunnel data for forwarding")

	return nil
}
