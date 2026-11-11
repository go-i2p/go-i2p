package i2cp

import (
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/go-i2p/lib/util/logutil"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// GarlicMessageEncryptor provides garlic message encryption for the message router.
// This interface is satisfied by both *i2np.GarlicSessionManager (the concrete adapter)
// and test mocks. It uses I2P-specific types (common.Hash) at the boundary.
type GarlicMessageEncryptor interface {
	// EncryptGarlicMessage encrypts garlic cloves for a destination.
	// destinationHash: I2P hash identifying the session.
	// destinationPubKey: X25519 public key of the recipient.
	// cloves: one serialized spec-compliant clove payload per clove
	// (DeliveryInstructions + 9-byte short I2NP header + body).
	// Returns encrypted bytes.
	EncryptGarlicMessage(destinationHash common.Hash, destinationPubKey [32]byte, cloves [][]byte) ([]byte, error)
}

// MessageRouter handles routing outbound I2CP messages through the I2P network.
// It coordinates garlic encryption, tunnel selection, and message transmission.
//
// Design:
// - Encapsulates the message routing logic in a dedicated component
// - Uses existing garlic session manager for encryption
// - Integrates with tunnel pools for outbound routing
// - Delegates actual transmission to transport layer
type MessageRouter struct {
	garlicSessions GarlicMessageEncryptor
	transportSend  TransportSendFunc

	// leaseResolver resolves a destination to the inbound tunnel (gateway
	// router + tunnel ID) that can receive for it. Outbound encapsulation needs
	// it to write delivery instructions; without it nothing can be correctly
	// addressed, and sends fail closed.
	leaseResolver DestinationLeaseResolver
}

// DestinationLeaseResolver resolves a destination hash to a current lease, i.e.
// the inbound-tunnel addressing a tunnel message must carry.
// *LeaseResolver implements it.
type DestinationLeaseResolver interface {
	ResolveLease(destHash common.Hash) (LeaseTarget, error)
}

// SetLeaseResolver installs the destination lease resolver used to address
// outbound tunnel messages. Without one, RouteOutboundMessage fails closed
// rather than sending anything.
func (mr *MessageRouter) SetLeaseResolver(resolver DestinationLeaseResolver) {
	if mr == nil {
		return
	}
	mr.leaseResolver = resolver
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
type TransportSendFunc func(peerHash common.Hash, msg i2np.Message) error

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
// Accepts any implementation of GarlicMessageEncryptor, including *i2np.GarlicSessionManager and test mocks.
func NewMessageRouter(garlicMgr GarlicMessageEncryptor, transportSend TransportSendFunc) *MessageRouter {
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

// RouteRequest bundles the parameters for routing an outbound I2CP message.
type RouteRequest struct {
	Session           *Session              // I2CP session sending the message
	MessageID         uint32                // Unique identifier for tracking this message
	DestinationHash   common.Hash           // Hash of the target I2P destination
	DestinationPubKey [32]byte              // X25519 public key of the destination
	Payload           []byte                // Raw message data to send
	ExpirationMs      uint64                // Expiration timestamp in ms since epoch (0 = none)
	Nonce             uint32                // Nonce of the client message, echoed in every status (i2cp.rst:1417-1419)
	StatusCallback    MessageStatusCallback // Optional delivery status callback (nil allowed)
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
// Returns an error if routing fails at any step.
func (mr *MessageRouter) RouteOutboundMessage(req RouteRequest) error {
	mr.logRoutingStart(req.Session, req.MessageID, req.DestinationHash, req.Payload, req.ExpirationMs)

	if err := checkMessageExpiration(req.Session, req.MessageID, req.ExpirationMs, req.Payload, req.Nonce, req.StatusCallback); err != nil {
		return err
	}

	selectedTunnel, err := mr.validateAndSelectTunnel(req.Session, req.DestinationHash)
	if err != nil {
		notifyStatusCallback(req.StatusCallback, req.MessageID, MessageStatusNoTunnels, req.Payload, req.Nonce)
		return err
	}

	garlicMsg, err := mr.buildEncryptedGarlicMessage(req.Session, req.DestinationHash, req.DestinationPubKey, req.Payload)
	if err != nil {
		notifyStatusCallback(req.StatusCallback, req.MessageID, MessageStatusFailure, req.Payload, req.Nonce)
		return err
	}

	if err := mr.sendThroughGateway(req.Session, selectedTunnel, req.DestinationHash, garlicMsg); err != nil {
		notifyStatusCallback(req.StatusCallback, req.MessageID, MessageStatusFailure, req.Payload, req.Nonce)
		return err
	}

	mr.logSuccessfulRouting(req.Session, selectedTunnel, req.DestinationHash, len(req.Payload))
	// Report MessageStatusSuccess (best-effort success) once the message has been
	// encrypted and handed off to the tunnel gateway. Per I2CP specification,
	// SEND_BEST_EFFORT_SUCCESS (status 4) indicates the message was sent through
	// the tunnel subsystem. This does not guarantee end-to-end delivery, but
	// I2CP clients (e.g., i2psnark-standalone) expect this status to track
	// message progress rather than just ACCEPTED (status 1).
	notifyStatusCallback(req.StatusCallback, req.MessageID, MessageStatusSuccess, req.Payload, req.Nonce)

	return nil
}

// logRoutingStart logs the initiation of outbound message routing.
func (mr *MessageRouter) logRoutingStart(session *Session, messageID uint32, destinationHash common.Hash, payload []byte, expirationMs uint64) {
	log.WithFields(logger.Fields{
		"at":           "i2cp.MessageRouter.RouteOutboundMessage",
		"sessionID":    session.ID(),
		"messageID":    messageID,
		"destination":  logutil.HashPrefixPlain(destinationHash),
		"payloadSize":  len(payload),
		"expirationMs": expirationMs,
	}).Debug("routing_outbound_message")
}

// checkMessageExpiration validates the message has not expired and notifies callback on expiration.
func checkMessageExpiration(session *Session, messageID uint32, expirationMs uint64, payload []byte, nonce uint32, statusCallback MessageStatusCallback) error {
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

	notifyStatusCallback(statusCallback, messageID, MessageStatusFailure, payload, nonce)
	return oops.Errorf("message expired: current=%d, expiration=%d", currentMs, expirationMs)
}

// notifyStatusCallback invokes the status callback if provided.
//
// The nonce of the client message that produced this status is passed through
// unchanged: i2cp.rst:1417-1419 ("That message will contain the same nonce sent
// here") and i2cp.rst:1464-1467 for SendMessageExpires. Reporting 0 here would
// make every asynchronous MessageStatus refer to a different message than the
// synchronous "accepted" status, so clients could not correlate them.
func notifyStatusCallback(callback MessageStatusCallback, messageID uint32, statusCode uint8, payload []byte, nonce uint32) {
	if callback != nil {
		callback(messageID, statusCode, uint32(len(payload)), nonce)
	}
}

// validateAndSelectTunnel validates the session has an outbound pool and selects a tunnel.
func (mr *MessageRouter) validateAndSelectTunnel(session *Session, destinationHash common.Hash) (*tunnel.TunnelState, error) {
	outboundPool := session.OutboundPool()
	if outboundPool == nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.MessageRouter.validateAndSelectTunnel",
			"sessionID":   session.ID(),
			"destination": logutil.HashPrefixPlain(destinationHash),
		}).Error("no_outbound_pool")
		return nil, oops.Errorf("outbound tunnel pool required for session %d", session.ID())
	}

	selectedTunnel := outboundPool.SelectTunnel()
	if selectedTunnel == nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.MessageRouter.validateAndSelectTunnel",
			"sessionID":   session.ID(),
			"destination": logutil.HashPrefixPlain(destinationHash),
		}).Error("no_active_tunnels")
		return nil, oops.Errorf("insufficient active outbound tunnels for session %d", session.ID())
	}

	if len(selectedTunnel.Hops) == 0 {
		log.WithFields(logger.Fields{
			"at":          "i2cp.MessageRouter.validateAndSelectTunnel",
			"sessionID":   session.ID(),
			"tunnelID":    selectedTunnel.ID,
			"destination": logutil.HashPrefixPlain(destinationHash),
		}).Error("zero_hop_tunnel_rejected")
		// Zero-hop tunnels are rejected for I2CP client traffic because:
		// 1. Sending directly to a destination hash bypasses I2P's anonymity model,
		//    exposing the sender's real IP to the destination.
		// 2. The destination hash is not a router hash, so transport-level delivery
		//    would fail anyway since transportSend expects routable router hashes.
		// This is consistent with lib/netdb/publisher.go which also rejects zero-hop tunnels.
		return nil, oops.Errorf("zero-hop tunnels are not supported for I2CP client traffic (session %d): anonymity requires at least one hop", session.ID())
	}

	log.WithFields(logger.Fields{
		"at":          "i2cp.MessageRouter.validateAndSelectTunnel",
		"sessionID":   session.ID(),
		"tunnelID":    selectedTunnel.ID,
		"hopCount":    len(selectedTunnel.Hops),
		"tunnelState": selectedTunnel.State,
		"destination": logutil.HashPrefixPlain(destinationHash),
	}).Debug("tunnel_selected_for_routing")

	return selectedTunnel, nil
}

// buildEncryptedGarlicMessage creates and encrypts a garlic message containing the payload.
func (mr *MessageRouter) buildEncryptedGarlicMessage(
	session *Session,
	destinationHash common.Hash,
	destinationPubKey [32]byte,
	payload []byte,
) (i2np.Message, error) {
	if mr.garlicSessions == nil {
		return nil, oops.Errorf("garlic session manager not initialized for session %d", session.ID())
	}

	log.WithFields(logger.Fields{
		"at":          "i2cp.MessageRouter.buildEncryptedGarlicMessage",
		"sessionID":   session.ID(),
		"destination": logutil.HashPrefixPlain(destinationHash),
		"payloadSize": len(payload),
	}).Debug("building_garlic_message")

	dataMsg := i2np.NewDataMessage(payload)

	clovePayloads, err := mr.buildPlaintextGarlicMessage(session, destinationHash, dataMsg)
	if err != nil {
		return nil, err
	}

	encryptedGarlic, err := mr.encryptGarlicMessage(session, destinationHash, destinationPubKey, clovePayloads)
	if err != nil {
		return nil, err
	}

	log.WithFields(logger.Fields{
		"at":            "i2cp.MessageRouter.buildEncryptedGarlicMessage",
		"sessionID":     session.ID(),
		"destination":   logutil.HashPrefixPlain(destinationHash),
		"cloveCount":    len(clovePayloads),
		"encryptedSize": len(encryptedGarlic),
	}).Debug("garlic_encrypted_successfully")

	return mr.wrapInGarlicMessage(session, destinationHash, encryptedGarlic)
}

// buildPlaintextGarlicMessage creates the spec-compliant plaintext garlic clove
// payloads (one per clove: DeliveryInstructions + 9-byte short I2NP header + body).
func (mr *MessageRouter) buildPlaintextGarlicMessage(
	session *Session,
	destinationHash common.Hash,
	dataMsg i2np.Message,
) ([][]byte, error) {
	garlicBuilder, err := i2np.NewGarlicBuilderWithDefaults()
	if err != nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.MessageRouter.buildPlaintextGarlicMessage",
			"sessionID":   session.ID(),
			"error":       err,
			"destination": logutil.HashPrefixPlain(destinationHash),
		}).Error("failed_to_create_garlic_builder")
		return nil, oops.Errorf("failed to create garlic builder: %w", err)
	}

	if err := garlicBuilder.AddLocalDeliveryClove(dataMsg, 1); err != nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.MessageRouter.buildPlaintextGarlicMessage",
			"sessionID":   session.ID(),
			"error":       err,
			"destination": logutil.HashPrefixPlain(destinationHash),
		}).Error("failed_to_add_garlic_clove")
		return nil, oops.Errorf("failed to add garlic clove: %w", err)
	}

	clovePayloads, err := garlicBuilder.BuildClovePayloads()
	if err != nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.MessageRouter.buildPlaintextGarlicMessage",
			"sessionID":   session.ID(),
			"error":       err,
			"destination": logutil.HashPrefixPlain(destinationHash),
		}).Error("failed_to_build_garlic")
		return nil, oops.Errorf("failed to build garlic message: %w", err)
	}

	return clovePayloads, nil
}

// encryptGarlicMessage encrypts garlic clove payloads using ECIES-X25519-AEAD.
func (mr *MessageRouter) encryptGarlicMessage(
	session *Session,
	destinationHash common.Hash,
	destinationPubKey [32]byte,
	clovePayloads [][]byte,
) ([]byte, error) {
	encryptedGarlic, err := mr.garlicSessions.EncryptGarlicMessage(
		destinationHash,
		destinationPubKey,
		clovePayloads,
	)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.MessageRouter.encryptGarlicMessage",
			"sessionID":   session.ID(),
			"error":       err,
			"destination": logutil.HashPrefixPlain(destinationHash),
		}).Error("failed_to_encrypt_garlic")
		return nil, oops.Errorf("failed to encrypt garlic message: %w", err)
	}
	return encryptedGarlic, nil
}

// wrapInGarlicMessage wraps encrypted garlic data in an I2NP Garlic message.
func (mr *MessageRouter) wrapInGarlicMessage(
	session *Session,
	destinationHash common.Hash,
	encryptedGarlic []byte,
) (i2np.Message, error) {
	garlicMsg, err := i2np.WrapInGarlicMessage(encryptedGarlic)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.MessageRouter.wrapInGarlicMessage",
			"sessionID":   session.ID(),
			"error":       err,
			"destination": logutil.HashPrefixPlain(destinationHash),
		}).Error("failed_to_wrap_garlic")
		return nil, oops.Errorf("failed to wrap garlic message: %w", err)
	}
	return garlicMsg, nil
}

// sendThroughGateway encapsulates the garlic message as tunnel traffic and hands
// the resulting records to hop 0 of the selected outbound tunnel.
//
// This is the only correct way to put I2CP traffic on the wire. A tunnel message
// is addressed to a destination's inbound tunnel through delivery instructions,
// carries the payload fragmented to fit 1008-byte layers, and is encrypted once
// per hop in the tunnel so each hop can peel exactly one layer. Handing a bare
// I2NP message to the transport instead — addressed at a hop's router hash with
// no encapsulation — is not a degraded delivery: the hop cannot make sense of
// it, the data is discarded, and because the message went straight to a peer
// over a direct connection it identifies this router as the sender, which
// defeats the whole point of using the overlay.
//
// Returns an error, without sending anything, if the destination has no usable
// lease or the tunnel cannot encrypt as its creator. There is deliberately no
// fallback to an unencapsulated send.
func (mr *MessageRouter) sendThroughGateway(
	session *Session,
	selectedTunnel *tunnel.TunnelState,
	destinationHash common.Hash,
	garlicMsg i2np.Message,
) error {
	if mr.transportSend == nil {
		return oops.Errorf("transport send function not initialized for session %d", session.ID())
	}

	// 1. Resolve where the destination can actually be reached.
	target, err := mr.resolveDestinationLease(session, destinationHash)
	if err != nil {
		return err
	}

	// 2. Get the encryptor for every hop of the outbound tunnel we are sending on.
	gw, err := selectedTunnel.CreatorGateway()
	if err != nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.MessageRouter.sendThroughGateway",
			"sessionID":   session.ID(),
			"tunnelID":    selectedTunnel.ID,
			"hopCount":    len(selectedTunnel.Hops),
			"destination": logutil.HashPrefixPlain(destinationHash),
			"error":       err.Error(),
		}).Error("tunnel_cannot_encrypt_as_creator")
		return oops.Wrapf(err, "outbound tunnel %d cannot encapsulate traffic", selectedTunnel.ID)
	}

	// 3. Serialize the garlic I2NP message; this byte string is the tunnel payload.
	garlicBytes, err := garlicMsg.MarshalBinary()
	if err != nil {
		return oops.Wrapf(err, "failed to serialize garlic message for session %d", session.ID())
	}

	// 4. Build delivery instructions, fragment, and apply every hop's layer.
	records, err := gw.SendWithDelivery(garlicBytes, tunnel.TunnelDelivery(target.TunnelID, [32]byte(target.GatewayHash)))
	if err != nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.MessageRouter.sendThroughGateway",
			"sessionID":   session.ID(),
			"tunnelID":    selectedTunnel.ID,
			"garlicSize":  len(garlicBytes),
			"destination": logutil.HashPrefixPlain(destinationHash),
			"error":       err.Error(),
		}).Error("tunnel_encapsulation_failed")
		return oops.Wrapf(err, "failed to encapsulate message for destination %x", destinationHash[:8])
	}

	// 5. Hand each record to hop 0. The TunnelData header carries hop 0's own
	// receive ID, which is the ID hop 0 registered when it accepted our build.
	hopZero := selectedTunnel.Hops[0]
	hopReceiveID := gw.HopReceiveTunnelID()
	for i, record := range records {
		if err := sendTunnelRecord(mr.transportSend, hopZero, hopReceiveID, record); err != nil {
			return oops.Wrapf(err, "failed to send tunnel record %d/%d to gateway", i+1, len(records))
		}
	}

	log.WithFields(logger.Fields{
		"at":           "i2cp.MessageRouter.sendThroughGateway",
		"sessionID":    session.ID(),
		"tunnelID":     selectedTunnel.ID,
		"hopCount":     len(selectedTunnel.Hops),
		"gateway":      logutil.HashPrefixPlain(hopZero),
		"hopReceiveID": hopReceiveID,
		"destGateway":  logutil.HashPrefixPlain(target.GatewayHash),
		"destTunnelID": target.TunnelID,
		"garlicSize":   len(garlicBytes),
		"recordCount":  len(records),
		"destination":  logutil.HashPrefixPlain(destinationHash),
	}).Debug("message_encapsulated_and_sent_to_tunnel_gateway")
	return nil
}

// sendTunnelRecord wraps one 1028-byte layered tunnel record in a TunnelData
// I2NP message and queues it to the given hop.
//
// The wire format is a 4-byte tunnel ID followed by the remaining 1024 bytes of
// the record; the record's own first 4 bytes are the in-clear next-hop ID that
// hop 0 rewrites when it forwards, so they travel inside the payload rather than
// in the header.
func sendTunnelRecord(send TransportSendFunc, hop common.Hash, hopReceiveID tunnel.TunnelID, record []byte) error {
	if len(record) != tunnel.TunnelMessageSize {
		return oops.Errorf("tunnel record must be %d bytes, got %d", tunnel.TunnelMessageSize, len(record))
	}

	var payload [i2np.TunnelDataPayloadSize]byte
	copy(payload[:], record[tunnel.TunnelIDSize:])

	msg := i2np.NewTunnelDataMessage(hopReceiveID, payload)
	return send(hop, msg)
}

// resolveDestinationLease looks up the inbound tunnel that can receive for a
// destination.
func (mr *MessageRouter) resolveDestinationLease(session *Session, destinationHash common.Hash) (LeaseTarget, error) {
	if mr.leaseResolver == nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.MessageRouter.resolveDestinationLease",
			"sessionID": session.ID(),
		}).Error("lease_resolver_not_configured")
		return LeaseTarget{}, oops.Errorf("no destination lease resolver configured for session %d", session.ID())
	}

	target, err := mr.leaseResolver.ResolveLease(destinationHash)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.MessageRouter.resolveDestinationLease",
			"sessionID":   session.ID(),
			"destination": logutil.HashPrefixPlain(destinationHash),
			"error":       err.Error(),
		}).Debug("destination_lease_unresolved")
		return LeaseTarget{}, oops.Wrapf(err, "cannot address message to destination %x", destinationHash[:8])
	}
	if target.IsZero() {
		return LeaseTarget{}, oops.Errorf("destination %x has an empty lease", destinationHash[:8])
	}
	return target, nil
}

// logSuccessfulRouting logs successful message routing.
// The tunnel is guaranteed to have at least one hop (zero-hop tunnels are rejected earlier).
func (mr *MessageRouter) logSuccessfulRouting(
	session *Session,
	selectedTunnel *tunnel.TunnelState,
	destinationHash common.Hash,
	payloadSize int,
) {
	gatewayStr := logutil.BytePrefix(selectedTunnel.Hops[0][:])
	log.WithFields(logger.Fields{
		"at":          "i2cp.MessageRouter.RouteOutboundMessage",
		"sessionID":   session.ID(),
		"tunnelID":    selectedTunnel.ID,
		"gateway":     gatewayStr,
		"destination": logutil.HashPrefixPlain(destinationHash),
		"payloadSize": payloadSize,
	}).Debug("message_routed_successfully")
}

// SendThroughTunnel encapsulates an I2NP message and sends it through a
// specific outbound tunnel to the given destination lease target.
//
// Parameters:
// - t: the tunnel to send through, which must have retained its build keys
// - msg: the I2NP message to carry as the tunnel payload
// - target: the destination's inbound tunnel addressing, from its lease
//
// The message is fragmented and encrypted once per hop, and each resulting
// record is delivered to hop 0 as TunnelData. There is no unencapsulated
// fallback: see [MessageRouter.sendThroughGateway] for why.
//
// Returns an error if the tunnel has no hops, cannot encrypt as its creator,
// the message cannot be serialized, or a record fails to send.
func (mr *MessageRouter) SendThroughTunnel(t *tunnel.TunnelState, msg i2np.Message, target LeaseTarget) error {
	if t == nil {
		return oops.Errorf("nil tunnel")
	}
	if len(t.Hops) == 0 {
		log.WithFields(logger.Fields{
			"at":       "i2cp.MessageRouter.SendThroughTunnel",
			"tunnelID": t.ID,
		}).Error("tunnel_has_no_hops")
		return oops.Errorf("tunnel hops required for tunnel %d", t.ID)
	}
	if mr.transportSend == nil {
		return oops.Errorf("transport send function not initialized")
	}
	if target.IsZero() {
		return oops.Errorf("destination lease target required to send through tunnel %d", t.ID)
	}

	gw, err := t.CreatorGateway()
	if err != nil {
		return oops.Wrapf(err, "outbound tunnel %d cannot encapsulate traffic", t.ID)
	}

	msgBytes, err := msg.MarshalBinary()
	if err != nil {
		return oops.Wrapf(err, "failed to serialize message for tunnel %d", t.ID)
	}

	records, err := gw.SendWithDelivery(msgBytes, tunnel.TunnelDelivery(target.TunnelID, [32]byte(target.GatewayHash)))
	if err != nil {
		return oops.Wrapf(err, "failed to encapsulate message for tunnel %d", t.ID)
	}

	hopZero := t.Hops[0]
	hopReceiveID := gw.HopReceiveTunnelID()
	for i, record := range records {
		if err := sendTunnelRecord(mr.transportSend, hopZero, hopReceiveID, record); err != nil {
			return oops.Wrapf(err, "failed to send tunnel record %d/%d for tunnel %d", i+1, len(records), t.ID)
		}
	}

	log.WithFields(logger.Fields{
		"at":         "i2cp.MessageRouter.SendThroughTunnel",
		"tunnelID":   t.ID,
		"gateway":    logutil.HashPrefixPlain(hopZero),
		"hopCount":   len(t.Hops),
		"destTunnel": target.TunnelID,
		"recordCnt":  len(records),
	}).Debug("sending_message_through_tunnel")
	return nil
}
