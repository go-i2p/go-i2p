package i2cp

import (
	"fmt"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/logger"
)

// MessageRouter handles routing outbound I2CP messages through the I2P network.
// It coordinates garlic encryption, tunnel selection, and message transmission.
//
// Design:
// - Encapsulates the message routing logic in a dedicated component
// - Uses existing garlic session manager for encryption
// - Integrates with tunnel pools for outbound routing
// - Delegates actual transmission to transport layer
type MessageRouter struct {
	garlicSessions *i2np.GarlicSessionManager
	transportSend  TransportSendFunc
}

// TransportSendFunc is a callback function for sending I2NP messages to peers.
// The implementation should handle queueing the message to the appropriate
// transport session (e.g., NTCP2).
//
// Parameters:
// - peerHash: Hash of the destination router (gateway)
// - msg: I2NP message to send
//
// Returns an error if the message cannot be sent.
type TransportSendFunc func(peerHash common.Hash, msg i2np.I2NPMessage) error

// MessageStatusCallback is invoked to notify about message delivery status changes.
// Implementations should handle the callback asynchronously to avoid blocking the router.
//
// Parameters:
// - messageID: Unique identifier for the message (client-provided or generated)
// - statusCode: Status code indicating delivery outcome (see MessageStatus* constants)
// - messageSize: Size of the original message payload in bytes
// - nonce: Optional nonce value (0 if not applicable)
type MessageStatusCallback func(messageID uint32, statusCode uint8, messageSize, nonce uint32)

// NewMessageRouter creates a new message router with the given garlic session manager.
// The transportSend callback will be used to send encrypted messages to the network.
func NewMessageRouter(garlicMgr *i2np.GarlicSessionManager, transportSend TransportSendFunc) *MessageRouter {
	log.WithFields(logger.Fields{
		"at":                 "i2cp.NewMessageRouter",
		"hasGarlicManager":   garlicMgr != nil,
		"hasTransportSender": transportSend != nil,
	}).Info("creating_message_router")

	return &MessageRouter{
		garlicSessions: garlicMgr,
		transportSend:  transportSend,
	}
}

// RouteOutboundMessage routes a message from an I2CP client through the I2P network.
// This implements the complete outbound message flow:
// 1. Check message expiration (if expirationMs > 0)
// 2. Create garlic message with Data clove containing the payload
// 3. Encrypt garlic message for destination using ECIES-X25519-AEAD
// 4. Select outbound tunnel from session's pool
// 5. Send encrypted garlic through tunnel gateway
// 6. Invoke status callback with delivery status
//
// Parameters:
// - session: I2CP session sending the message
// - messageID: Unique identifier for tracking this message
// - destinationHash: Hash of the target I2P destination
// - destinationPubKey: X25519 public key of the destination (for garlic encryption)
// - payload: Raw message data to send
// - expirationMs: Expiration timestamp in milliseconds since epoch (0 = no expiration)
// - statusCallback: Optional callback to notify about delivery status (nil allowed)
//
// Returns an error if routing fails at any step.
func (mr *MessageRouter) RouteOutboundMessage(
	session *Session,
	messageID uint32,
	destinationHash common.Hash,
	destinationPubKey [32]byte,
	payload []byte,
	expirationMs uint64,
	statusCallback MessageStatusCallback,
) error {
	mr.logRoutingStart(session, messageID, destinationHash, payload, expirationMs)

	if err := checkMessageExpiration(session, messageID, expirationMs, payload, statusCallback); err != nil {
		return err
	}

	selectedTunnel, err := mr.validateAndSelectTunnel(session, destinationHash)
	if err != nil {
		notifyStatusCallback(statusCallback, messageID, MessageStatusNoTunnels, payload)
		return err
	}

	garlicMsg, err := mr.buildEncryptedGarlicMessage(session, destinationHash, destinationPubKey, payload)
	if err != nil {
		notifyStatusCallback(statusCallback, messageID, MessageStatusFailure, payload)
		return err
	}

	if err := mr.sendThroughGateway(session, selectedTunnel, destinationHash, garlicMsg); err != nil {
		notifyStatusCallback(statusCallback, messageID, MessageStatusFailure, payload)
		return err
	}

	mr.logSuccessfulRouting(session, selectedTunnel, destinationHash, len(payload))
	notifyStatusCallback(statusCallback, messageID, MessageStatusSuccess, payload)

	return nil
}

// logRoutingStart logs the initiation of outbound message routing.
func (mr *MessageRouter) logRoutingStart(session *Session, messageID uint32, destinationHash common.Hash, payload []byte, expirationMs uint64) {
	log.WithFields(logger.Fields{
		"at":           "i2cp.MessageRouter.RouteOutboundMessage",
		"sessionID":    session.ID(),
		"messageID":    messageID,
		"destination":  fmt.Sprintf("%x", destinationHash[:8]),
		"payloadSize":  len(payload),
		"expirationMs": expirationMs,
	}).Info("routing_outbound_message")
}

// checkMessageExpiration validates the message has not expired and notifies callback on expiration.
func checkMessageExpiration(session *Session, messageID uint32, expirationMs uint64, payload []byte, statusCallback MessageStatusCallback) error {
	if expirationMs == 0 {
		return nil
	}

	currentMs := uint64(time.Now().UnixMilli())
	if currentMs < expirationMs {
		return nil
	}

	log.WithFields(logger.Fields{
		"at":           "i2cp.MessageRouter.RouteOutboundMessage",
		"sessionID":    session.ID(),
		"messageID":    messageID,
		"currentMs":    currentMs,
		"expirationMs": expirationMs,
	}).Warn("message_expired")

	notifyStatusCallback(statusCallback, messageID, MessageStatusFailure, payload)
	return fmt.Errorf("message expired: current=%d, expiration=%d", currentMs, expirationMs)
}

// notifyStatusCallback invokes the status callback if provided.
func notifyStatusCallback(callback MessageStatusCallback, messageID uint32, statusCode uint8, payload []byte) {
	if callback != nil {
		callback(messageID, statusCode, uint32(len(payload)), 0)
	}
}

// validateAndSelectTunnel validates the session has an outbound pool and selects a tunnel.
func (mr *MessageRouter) validateAndSelectTunnel(session *Session, destinationHash common.Hash) (*tunnel.TunnelState, error) {
	outboundPool := session.OutboundPool()
	if outboundPool == nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.MessageRouter.validateAndSelectTunnel",
			"sessionID":   session.ID(),
			"destination": fmt.Sprintf("%x", destinationHash[:8]),
		}).Error("no_outbound_pool")
		return nil, fmt.Errorf("outbound tunnel pool required for session %d", session.ID())
	}

	selectedTunnel := outboundPool.SelectTunnel()
	if selectedTunnel == nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.MessageRouter.validateAndSelectTunnel",
			"sessionID":   session.ID(),
			"destination": fmt.Sprintf("%x", destinationHash[:8]),
		}).Error("no_active_tunnels")
		return nil, fmt.Errorf("insufficient active outbound tunnels for session %d", session.ID())
	}

	if len(selectedTunnel.Hops) == 0 {
		log.WithFields(logger.Fields{
			"at":          "i2cp.MessageRouter.validateAndSelectTunnel",
			"sessionID":   session.ID(),
			"tunnelID":    selectedTunnel.ID,
			"destination": fmt.Sprintf("%x", destinationHash[:8]),
		}).Debug("zero_hop_tunnel_selected")
		// Zero-hop tunnels are valid in I2P (used for testing and
		// low-latency configurations). The message will be delivered
		// directly to the destination without intermediate hops.
	}

	log.WithFields(logger.Fields{
		"at":          "i2cp.MessageRouter.validateAndSelectTunnel",
		"sessionID":   session.ID(),
		"tunnelID":    selectedTunnel.ID,
		"hopCount":    len(selectedTunnel.Hops),
		"tunnelState": selectedTunnel.State,
		"destination": fmt.Sprintf("%x", destinationHash[:8]),
	}).Debug("tunnel_selected_for_routing")

	return selectedTunnel, nil
}

// buildEncryptedGarlicMessage creates and encrypts a garlic message containing the payload.
func (mr *MessageRouter) buildEncryptedGarlicMessage(
	session *Session,
	destinationHash common.Hash,
	destinationPubKey [32]byte,
	payload []byte,
) (i2np.I2NPMessage, error) {
	if mr.garlicSessions == nil {
		return nil, fmt.Errorf("garlic session manager not initialized for session %d", session.ID())
	}

	log.WithFields(logger.Fields{
		"at":          "i2cp.MessageRouter.buildEncryptedGarlicMessage",
		"sessionID":   session.ID(),
		"destination": fmt.Sprintf("%x", destinationHash[:8]),
		"payloadSize": len(payload),
	}).Debug("building_garlic_message")

	dataMsg := i2np.NewDataMessage(payload)

	plaintextGarlic, err := mr.buildPlaintextGarlicMessage(session, destinationHash, dataMsg)
	if err != nil {
		return nil, err
	}

	encryptedGarlic, err := mr.encryptGarlicMessage(session, destinationHash, destinationPubKey, plaintextGarlic)
	if err != nil {
		return nil, err
	}

	log.WithFields(logger.Fields{
		"at":                 "i2cp.MessageRouter.buildEncryptedGarlicMessage",
		"sessionID":          session.ID(),
		"destination":        fmt.Sprintf("%x", destinationHash[:8]),
		"plaintextSize":      len(plaintextGarlic),
		"encryptedSize":      len(encryptedGarlic),
		"encryptionOverhead": len(encryptedGarlic) - len(plaintextGarlic),
	}).Debug("garlic_encrypted_successfully")

	return mr.wrapInGarlicMessage(session, destinationHash, encryptedGarlic)
}

// buildPlaintextGarlicMessage creates a plaintext garlic message with the data clove.
func (mr *MessageRouter) buildPlaintextGarlicMessage(
	session *Session,
	destinationHash common.Hash,
	dataMsg i2np.I2NPMessage,
) ([]byte, error) {
	garlicBuilder, err := i2np.NewGarlicBuilderWithDefaults()
	if err != nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.MessageRouter.buildPlaintextGarlicMessage",
			"sessionID":   session.ID(),
			"error":       err,
			"destination": fmt.Sprintf("%x", destinationHash[:8]),
		}).Error("failed_to_create_garlic_builder")
		return nil, fmt.Errorf("failed to create garlic builder: %w", err)
	}

	if err := garlicBuilder.AddLocalDeliveryClove(dataMsg, 1); err != nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.MessageRouter.buildPlaintextGarlicMessage",
			"sessionID":   session.ID(),
			"error":       err,
			"destination": fmt.Sprintf("%x", destinationHash[:8]),
		}).Error("failed_to_add_garlic_clove")
		return nil, fmt.Errorf("failed to add garlic clove: %w", err)
	}

	plaintextGarlic, err := garlicBuilder.BuildAndSerialize()
	if err != nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.MessageRouter.buildPlaintextGarlicMessage",
			"sessionID":   session.ID(),
			"error":       err,
			"destination": fmt.Sprintf("%x", destinationHash[:8]),
		}).Error("failed_to_build_garlic")
		return nil, fmt.Errorf("failed to build garlic message: %w", err)
	}

	return plaintextGarlic, nil
}

// encryptGarlicMessage encrypts a plaintext garlic message using ECIES-X25519-AEAD.
func (mr *MessageRouter) encryptGarlicMessage(
	session *Session,
	destinationHash common.Hash,
	destinationPubKey [32]byte,
	plaintextGarlic []byte,
) ([]byte, error) {
	encryptedGarlic, err := mr.garlicSessions.EncryptGarlicMessage(
		destinationHash,
		destinationPubKey,
		plaintextGarlic,
	)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.MessageRouter.encryptGarlicMessage",
			"sessionID":   session.ID(),
			"error":       err,
			"destination": fmt.Sprintf("%x", destinationHash[:8]),
		}).Error("failed_to_encrypt_garlic")
		return nil, fmt.Errorf("failed to encrypt garlic message: %w", err)
	}
	return encryptedGarlic, nil
}

// wrapInGarlicMessage wraps encrypted garlic data in an I2NP Garlic message.
func (mr *MessageRouter) wrapInGarlicMessage(
	session *Session,
	destinationHash common.Hash,
	encryptedGarlic []byte,
) (i2np.I2NPMessage, error) {
	garlicMsg, err := i2np.WrapInGarlicMessage(encryptedGarlic)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.MessageRouter.wrapInGarlicMessage",
			"sessionID":   session.ID(),
			"error":       err,
			"destination": fmt.Sprintf("%x", destinationHash[:8]),
		}).Error("failed_to_wrap_garlic")
		return nil, fmt.Errorf("failed to wrap garlic message: %w", err)
	}
	return garlicMsg, nil
}

// sendThroughGateway sends the garlic message to the tunnel gateway.
// For zero-hop tunnels, sends directly to the destination.
func (mr *MessageRouter) sendThroughGateway(
	session *Session,
	selectedTunnel *tunnel.TunnelState,
	destinationHash common.Hash,
	garlicMsg i2np.I2NPMessage,
) error {
	if mr.transportSend == nil {
		return fmt.Errorf("transport send function not initialized for session %d", session.ID())
	}

	// Zero-hop tunnel: send directly to the destination
	targetHash := destinationHash
	if len(selectedTunnel.Hops) > 0 {
		targetHash = selectedTunnel.Hops[0]
	}

	if err := mr.transportSend(targetHash, garlicMsg); err != nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.MessageRouter.sendThroughGateway",
			"sessionID":   session.ID(),
			"tunnelID":    selectedTunnel.ID,
			"target":      fmt.Sprintf("%x", targetHash[:8]),
			"destination": fmt.Sprintf("%x", destinationHash[:8]),
			"zeroHop":     len(selectedTunnel.Hops) == 0,
			"error":       err,
		}).Error("failed_to_send_to_gateway")
		return fmt.Errorf("failed to send message to gateway: %w", err)
	}
	return nil
}

// logSuccessfulRouting logs successful message routing.
func (mr *MessageRouter) logSuccessfulRouting(
	session *Session,
	selectedTunnel *tunnel.TunnelState,
	destinationHash common.Hash,
	payloadSize int,
) {
	gatewayStr := "direct"
	if len(selectedTunnel.Hops) > 0 {
		gatewayStr = fmt.Sprintf("%x", selectedTunnel.Hops[0][:8])
	}
	log.WithFields(logger.Fields{
		"at":          "i2cp.MessageRouter.RouteOutboundMessage",
		"sessionID":   session.ID(),
		"tunnelID":    selectedTunnel.ID,
		"gateway":     gatewayStr,
		"destination": fmt.Sprintf("%x", destinationHash[:8]),
		"payloadSize": payloadSize,
	}).Info("message_routed_successfully")
}

// SendThroughTunnel sends an I2NP message through a specific tunnel.
// This is a lower-level method that can be used when the tunnel is already selected.
//
// Parameters:
// - tunnel: The tunnel to send through
// - msg: The I2NP message to send (already encrypted if needed)
//
// Returns an error if sending fails.
func (mr *MessageRouter) SendThroughTunnel(tunnel *tunnel.TunnelState, msg i2np.I2NPMessage) error {
	if len(tunnel.Hops) == 0 {
		log.WithFields(logger.Fields{
			"at":       "i2cp.MessageRouter.SendThroughTunnel",
			"tunnelID": tunnel.ID,
		}).Error("tunnel_has_no_hops")
		return fmt.Errorf("tunnel hops required for tunnel %d", tunnel.ID)
	}

	gatewayHash := tunnel.Hops[0]
	log.WithFields(logger.Fields{
		"at":       "i2cp.MessageRouter.SendThroughTunnel",
		"tunnelID": tunnel.ID,
		"gateway":  fmt.Sprintf("%x", gatewayHash[:8]),
		"hopCount": len(tunnel.Hops),
	}).Debug("sending_message_through_tunnel")

	err := mr.transportSend(gatewayHash, msg)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":       "i2cp.MessageRouter.SendThroughTunnel",
			"tunnelID": tunnel.ID,
			"gateway":  fmt.Sprintf("%x", gatewayHash[:8]),
			"error":    err.Error(),
		}).Error("failed_to_send_through_tunnel")
	}

	return err
}
