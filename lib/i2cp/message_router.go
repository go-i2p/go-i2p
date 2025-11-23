package i2cp

import (
	"fmt"

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

// NewMessageRouter creates a new message router with the given garlic session manager.
// The transportSend callback will be used to send encrypted messages to the network.
func NewMessageRouter(garlicMgr *i2np.GarlicSessionManager, transportSend TransportSendFunc) *MessageRouter {
	return &MessageRouter{
		garlicSessions: garlicMgr,
		transportSend:  transportSend,
	}
}

// RouteOutboundMessage routes a message from an I2CP client through the I2P network.
// This implements the complete outbound message flow:
// 1. Create garlic message with Data clove containing the payload
// 2. Encrypt garlic message for destination using ECIES-X25519-AEAD
// 3. Select outbound tunnel from session's pool
// 4. Send encrypted garlic through tunnel gateway
//
// Parameters:
// - session: I2CP session sending the message
// - destinationHash: Hash of the target I2P destination
// - destinationPubKey: X25519 public key of the destination (for garlic encryption)
// - payload: Raw message data to send
//
// Returns an error if routing fails at any step.
func (mr *MessageRouter) RouteOutboundMessage(
	session *Session,
	destinationHash common.Hash,
	destinationPubKey [32]byte,
	payload []byte,
) error {
	// Step 1: Validate session has outbound tunnel pool (fail-fast)
	outboundPool := session.OutboundPool()
	if outboundPool == nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.MessageRouter.RouteOutboundMessage",
			"sessionID":   session.ID(),
			"destination": fmt.Sprintf("%x", destinationHash[:8]),
		}).Error("no_outbound_pool")
		return fmt.Errorf("session %d has no outbound tunnel pool", session.ID())
	}

	// Step 2: Select outbound tunnel from session pool (fail-fast)
	selectedTunnel := outboundPool.SelectTunnel()
	if selectedTunnel == nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.MessageRouter.RouteOutboundMessage",
			"sessionID":   session.ID(),
			"destination": fmt.Sprintf("%x", destinationHash[:8]),
		}).Error("no_active_tunnels")
		return fmt.Errorf("no active outbound tunnels available for session %d", session.ID())
	}

	// Step 3: Validate tunnel has hops (fail-fast)
	if len(selectedTunnel.Hops) == 0 {
		log.WithFields(logger.Fields{
			"at":          "i2cp.MessageRouter.RouteOutboundMessage",
			"sessionID":   session.ID(),
			"tunnelID":    selectedTunnel.ID,
			"destination": fmt.Sprintf("%x", destinationHash[:8]),
		}).Error("tunnel_has_no_hops")
		return fmt.Errorf("selected tunnel %d has no hops", selectedTunnel.ID)
	}

	// Step 4: Create Data message with the payload
	dataMsg := i2np.NewDataMessage(payload)

	// Step 2: Build garlic message with Data clove
	garlicBuilder, err := i2np.NewGarlicBuilderWithDefaults()
	if err != nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.MessageRouter.RouteOutboundMessage",
			"sessionID":   session.ID(),
			"error":       err,
			"destination": fmt.Sprintf("%x", destinationHash[:8]),
		}).Error("failed_to_create_garlic_builder")
		return fmt.Errorf("failed to create garlic builder: %w", err)
	}

	// Add data message as local delivery clove
	// The destination will decrypt the garlic and process this clove locally
	if err := garlicBuilder.AddLocalDeliveryClove(dataMsg, 1); err != nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.MessageRouter.RouteOutboundMessage",
			"sessionID":   session.ID(),
			"error":       err,
			"destination": fmt.Sprintf("%x", destinationHash[:8]),
		}).Error("failed_to_add_garlic_clove")
		return fmt.Errorf("failed to add garlic clove: %w", err)
	}

	// Build and serialize the garlic structure (plaintext)
	plaintextGarlic, err := garlicBuilder.BuildAndSerialize()
	if err != nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.MessageRouter.RouteOutboundMessage",
			"sessionID":   session.ID(),
			"error":       err,
			"destination": fmt.Sprintf("%x", destinationHash[:8]),
		}).Error("failed_to_build_garlic")
		return fmt.Errorf("failed to build garlic message: %w", err)
	}

	// Step 3: Encrypt garlic message using ECIES-X25519-AEAD
	encryptedGarlic, err := mr.garlicSessions.EncryptGarlicMessage(
		destinationHash,
		destinationPubKey,
		plaintextGarlic,
	)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.MessageRouter.RouteOutboundMessage",
			"sessionID":   session.ID(),
			"error":       err,
			"destination": fmt.Sprintf("%x", destinationHash[:8]),
		}).Error("failed_to_encrypt_garlic")
		return fmt.Errorf("failed to encrypt garlic message: %w", err)
	}

	// Step 4: Wrap encrypted garlic in I2NP Garlic message
	garlicMsg, err := i2np.WrapInGarlicMessage(encryptedGarlic)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.MessageRouter.RouteOutboundMessage",
			"sessionID":   session.ID(),
			"error":       err,
			"destination": fmt.Sprintf("%x", destinationHash[:8]),
		}).Error("failed_to_wrap_garlic")
		return fmt.Errorf("failed to wrap garlic message: %w", err)
	}

	// Step 5: Send garlic message through tunnel gateway
	// Gateway is the first hop in the outbound tunnel
	gatewayHash := selectedTunnel.Hops[0]

	// Send the garlic message to the gateway router
	if err := mr.transportSend(gatewayHash, garlicMsg); err != nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.MessageRouter.RouteOutboundMessage",
			"sessionID":   session.ID(),
			"tunnelID":    selectedTunnel.ID,
			"gateway":     fmt.Sprintf("%x", gatewayHash[:8]),
			"destination": fmt.Sprintf("%x", destinationHash[:8]),
			"error":       err,
		}).Error("failed_to_send_to_gateway")
		return fmt.Errorf("failed to send message to gateway: %w", err)
	}

	log.WithFields(logger.Fields{
		"at":          "i2cp.MessageRouter.RouteOutboundMessage",
		"sessionID":   session.ID(),
		"tunnelID":    selectedTunnel.ID,
		"gateway":     fmt.Sprintf("%x", gatewayHash[:8]),
		"destination": fmt.Sprintf("%x", destinationHash[:8]),
		"payloadSize": len(payload),
	}).Info("message_routed_successfully")

	return nil
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
		return fmt.Errorf("tunnel %d has no hops", tunnel.ID)
	}

	gatewayHash := tunnel.Hops[0]
	return mr.transportSend(gatewayHash, msg)
}
