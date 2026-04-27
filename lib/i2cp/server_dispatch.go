package i2cp

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

func (s *Server) handleMessage(conn net.Conn, msg *Message, sessionPtr **Session) (*Message, error) {
	// i2psnark compatibility: Log all incoming messages for debugging
	var currentSessionID uint16
	if *sessionPtr != nil {
		currentSessionID = (*sessionPtr).ID()
	}

	log.WithFields(logger.Fields{
		"at":               "i2cp.Server.handleMessage",
		"msgType":          MessageTypeName(msg.Type),
		"msgTypeID":        msg.Type,
		"msgSessionID":     msg.SessionID,
		"currentSessionID": currentSessionID,
		"payloadSize":      len(msg.Payload),
	}).Debug("processing_i2cp_message")

	switch msg.Type {
	case MessageTypeCreateSession:
		return s.handleCreateSession(msg, sessionPtr)

	case MessageTypeDestroySession:
		return s.handleDestroySession(msg, sessionPtr)

	case MessageTypeReconfigureSession:
		return s.handleReconfigureSession(msg, sessionPtr)

	case MessageTypeCreateLeaseSet:
		return s.handleCreateLeaseSet(msg, sessionPtr)

	case MessageTypeCreateLeaseSet2:
		return s.handleCreateLeaseSet2(msg, sessionPtr)

	case MessageTypeGetDate:
		return s.handleGetDate(msg)

	case MessageTypeGetBandwidthLimits:
		return s.handleGetBandwidthLimits(msg)

	case MessageTypeSendMessage:
		return s.handleSendMessage(msg, sessionPtr)

	case MessageTypeSendMessageExpires:
		return s.handleSendMessageExpires(msg, sessionPtr)

	case MessageTypeDisconnect:
		return s.handleDisconnect(msg, sessionPtr)

	case MessageTypeHostLookup:
		return s.handleHostLookup(conn, msg)

	// Legacy I2CP message types deprecated in v0.9.67. Payload formats differ
	// from their modern equivalents (38/39) so a transparent shim is not safe.
	// Return an explicit error so old clients can be updated.
	case MessageTypeDestLookup:
		log.WithFields(logger.Fields{
			"at":      "i2cp.Server.handleMessage",
			"msgType": MessageTypeName(msg.Type),
		}).Warn("legacy DestLookup (type 34) received; use HostLookup (type 38)")
		return nil, oops.Errorf("legacy message type %d (DestLookup) not supported; use HostLookup (type 38)", msg.Type)

	case MessageTypeBlindingInfo:
		return s.handleBlindingInfo(msg, sessionPtr)

	default:
		// i2psnark compatibility: Log unsupported message types with full context
		log.WithFields(logger.Fields{
			"at":          "i2cp.Server.handleMessage",
			"msgType":     MessageTypeName(msg.Type),
			"msgTypeID":   msg.Type,
			"sessionID":   msg.SessionID,
			"payloadSize": len(msg.Payload),
			"payloadHex":  fmt.Sprintf("%x", msg.Payload[:min(32, len(msg.Payload))]),
		}).Warn("unsupported_message_type")
		return nil, oops.Errorf("unsupported message type: %d", msg.Type)
	}
}

// handleCreateSession creates a new session
func (s *Server) handleCreateSession(msg *Message, sessionPtr **Session) (*Message, error) {
	// Parse and validate session configuration
	dest, config, err := parseSessionConfiguration(msg.Payload)
	if err != nil {
		return nil, oops.Errorf("session configuration error: %w", err)
	}

	// Create session with parsed or default configuration
	// If dest is nil, NewSession will generate a new destination
	session, err := s.manager.CreateSession(dest, config)
	if err != nil {
		return nil, oops.Errorf("failed to create session: %w", err)
	}

	// Configure LeaseSet publisher if available
	if s.leaseSetPublisher != nil {
		session.SetLeaseSetPublisher(s.leaseSetPublisher)
	}

	// Initialize tunnel pools with builders if available
	if err := s.initializeSessionTunnelPools(session, config); err != nil {
		// Log warning but don't fail session creation - pools can be set up later
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.handleCreateSession",
			"sessionID": session.ID(),
			"error":     err.Error(),
		}).Warn("failed to initialize tunnel pools")
	}

	*sessionPtr = session

	// i2psnark compatibility: Log detailed session creation info
	log.WithFields(logger.Fields{
		"at":                     "i2cp.Server.handleCreateSession",
		"sessionID":              session.ID(),
		"inbound_tunnel_length":  config.InboundTunnelLength,
		"outbound_tunnel_length": config.OutboundTunnelLength,
		"inbound_tunnel_count":   config.InboundTunnelCount,
		"outbound_tunnel_count":  config.OutboundTunnelCount,
		"payloadSize":            len(msg.Payload),
		"hasDestination":         dest != nil,
	}).Info("session_created")

	// Build success response
	return buildSessionStatusResponse(session.ID()), nil
}

// parseSessionConfiguration extracts and validates session configuration from payload.
// Returns destination, configuration, and any error encountered during parsing or validation.
// Empty payloads return defaults with no error (backward compatibility with tests).
// Parse or validation failures return an error instead of silently falling back to defaults.
func parseSessionConfiguration(payload []byte) (*destination.Destination, *SessionConfig, error) {
	// Empty payload - use defaults (backward compatibility with tests)
	if len(payload) == 0 {
		log.WithFields(logger.Fields{
			"at":           "parseSessionConfiguration",
			"reason":       "empty_payload_backward_compat",
			"payload_size": 0,
		}).Debug("using default session config")
		return nil, DefaultSessionConfig(), nil
	}

	// Parse destination and session configuration from payload
	dest, config, err := ParseCreateSessionPayload(payload)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":           "parseSessionConfiguration",
			"reason":       "parse_failure",
			"payload_size": len(payload),
			"error":        err.Error(),
		}).Warn("failed to parse create session payload")
		return nil, nil, oops.Errorf("failed to parse session configuration: %w", err)
	}

	// Validate the parsed configuration
	if err := ValidateSessionConfig(config); err != nil {
		log.WithFields(logger.Fields{
			"at":           "parseSessionConfiguration",
			"reason":       "validation_failure",
			"payload_size": len(payload),
			"error":        err.Error(),
		}).Warn("invalid session config")
		return dest, nil, oops.Errorf("invalid session configuration: %w", err)
	}

	return dest, config, nil
}

// initializeSessionTunnelPools creates and configures tunnel pools for a session.

// Per I2CP spec: SessionStatus payload is SessionID(2 bytes) + Status(1 byte)
// Status 1 = Created (session was successfully created)
func buildSessionStatusResponse(sessionID uint16) *Message {
	payload := make([]byte, 3)
	binary.BigEndian.PutUint16(payload[0:2], sessionID) // SessionID
	payload[2] = SessionStatusCreated                   // Status: Created (was incorrectly 0x00/Destroyed)

	return &Message{
		Type:      MessageTypeSessionStatus,
		SessionID: sessionID, // Keep for application logic
		Payload:   payload,
	}
}

// buildMessageStatusResponse creates a MessageStatus message.
// Per I2CP spec, MessageStatus payload format (15 bytes):
// - 2 bytes: Session ID (uint16, big endian)
// - 4 bytes: Message ID (uint32, big endian)
// - 1 byte:  Status code
// - 4 bytes: Message size (uint32, big endian)
// - 4 bytes: Nonce (uint32, big endian)
func buildMessageStatusResponse(sessionID uint16, messageID uint32, statusCode uint8, messageSize, nonce uint32) *Message {
	payload := make([]byte, 15)
	binary.BigEndian.PutUint16(payload[0:2], sessionID)    // SessionID
	binary.BigEndian.PutUint32(payload[2:6], messageID)    // MessageID
	payload[6] = statusCode                                // Status
	binary.BigEndian.PutUint32(payload[7:11], messageSize) // Message size
	binary.BigEndian.PutUint32(payload[11:15], nonce)      // Nonce

	return &Message{
		Type:      MessageTypeMessageStatus,
		SessionID: sessionID, // Keep for application logic
		Payload:   payload,
	}
}

// handleDestroySession destroys a session
func (s *Server) handleDestroySession(msg *Message, sessionPtr **Session) (*Message, error) {
	if *sessionPtr == nil {
		return nil, oops.Errorf("session not active")
	}

	sessionID := (*sessionPtr).ID()

	if err := s.manager.DestroySession(sessionID); err != nil {
		return nil, oops.Errorf("failed to destroy session: %w", err)
	}

	*sessionPtr = nil

	log.WithFields(logger.Fields{
		"at":        "i2cp.Server.handleDestroySession",
		"reason":    "client_requested",
		"sessionID": sessionID,
	}).Info("session_destroyed")

	// Per I2CP spec, SessionStatus payload is SessionID(2 bytes) + Status(1 byte).
	// Status code 0 = Destroyed.
	payload := make([]byte, 3)
	binary.BigEndian.PutUint16(payload[0:2], sessionID)
	payload[2] = SessionStatusDestroyed
	return &Message{
		Type:      MessageTypeSessionStatus,
		SessionID: sessionID,
		Payload:   payload,
	}, nil
}

// stripSessionIDPrefix removes the 2-byte SessionID prefix from the payload.
func stripSessionIDPrefix(payload []byte) ([]byte, error) {
	if len(payload) < 2 {
		return nil, oops.Errorf("ReconfigureSession payload too short: %d bytes (need at least 2 for SessionID)", len(payload))
	}
	return payload[2:], nil
}

// parseAndValidateReconfigPayload parses and validates the reconfigure session payload.
func parseAndValidateReconfigPayload(payloadData []byte) (*SessionConfig, error) {
	newConfig, err := ParseReconfigureSessionPayload(payloadData)
	if err != nil {
		log.WithError(err).Error("failed to parse reconfigure session payload")
		return nil, oops.Errorf("failed to parse reconfigure payload: %w", err)
	}
	if err := ValidateSessionConfig(newConfig); err != nil {
		log.WithError(err).Warn("invalid session config in reconfigure request")
		return nil, oops.Errorf("invalid configuration: %w", err)
	}
	return newConfig, nil
}

// logReconfigSuccess logs a successful session reconfiguration.
func logReconfigSuccess(sessionID uint16, cfg *SessionConfig) {
	log.WithFields(logger.Fields{
		"at":                     "i2cp.Server.handleReconfigureSession",
		"sessionID":              sessionID,
		"inbound_tunnel_length":  cfg.InboundTunnelLength,
		"outbound_tunnel_length": cfg.OutboundTunnelLength,
		"inbound_tunnel_count":   cfg.InboundTunnelCount,
		"outbound_tunnel_count":  cfg.OutboundTunnelCount,
	}).Info("session_reconfigured")
}

func (s *Server) handleReconfigureSession(msg *Message, sessionPtr **Session) (*Message, error) {
	if *sessionPtr == nil {
		return nil, oops.Errorf("session not active")
	}

	payloadData, err := stripSessionIDPrefix(msg.Payload)
	if err != nil {
		return nil, err
	}

	newConfig, err := parseAndValidateReconfigPayload(payloadData)
	if err != nil {
		return nil, err
	}

	if err := (*sessionPtr).Reconfigure(newConfig); err != nil {
		return nil, oops.Errorf("failed to reconfigure session: %w", err)
	}

	if err := s.rebuildSessionTunnelPools(*sessionPtr); err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.handleReconfigureSession",
			"sessionID": (*sessionPtr).ID(),
			"error":     err.Error(),
		}).Warn("failed_to_rebuild_tunnel_pools_after_reconfigure")
	}

	logReconfigSuccess((*sessionPtr).ID(), newConfig)
	return nil, nil
}

// handleCreateLeaseSet creates and publishes a LeaseSet for the session.
// This handler generates a LeaseSet from the session's inbound tunnel pool
// and returns it to the client. In a full implementation, this would also
// publish the LeaseSet to the network database.
func (s *Server) handleCreateLeaseSet(msg *Message, sessionPtr **Session) (*Message, error) {
	if *sessionPtr == nil {
		return nil, oops.Errorf("no active session")
	}

	session := *sessionPtr

	// i2psnark compatibility: Log LeaseSet creation request
	log.WithFields(logger.Fields{
		"at":          "i2cp.Server.handleCreateLeaseSet",
		"sessionID":   session.ID(),
		"payloadSize": len(msg.Payload),
	}).Debug("creating_leaseset")

	// Create LeaseSet from session's inbound tunnels
	leaseSetBytes, err := session.CreateLeaseSet()
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.handleCreateLeaseSet",
			"sessionID": session.ID(),
			"error":     err,
		}).Error("failed_to_create_leaseset")
		return nil, oops.Errorf("failed to create LeaseSet: %w", err)
	}

	log.WithFields(logger.Fields{
		"at":        "i2cp.Server.handleCreateLeaseSet",
		"sessionID": session.ID(),
		"size":      len(leaseSetBytes),
	}).Info("leaseset_created")

	// Publish LeaseSet to network database (NetDB) if publisher is configured.
	// The session's publishLeaseSetToNetwork method:
	// - Calculates the destination hash (SHA256 of destination)
	// - Calls the LeaseSetPublisher.PublishLeaseSet() interface
	// - Returns nil if no publisher configured (allows testing without network)
	// - Logs errors but doesn't fail the operation (LeaseSet is cached locally)
	if err := session.publishLeaseSetToNetwork(leaseSetBytes); err != nil {
		// Log warning but don't fail - LeaseSet creation succeeded
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.handleCreateLeaseSet",
			"sessionID": session.ID(),
			"error":     err,
		}).Warn("failed_to_publish_leaseset_to_network")
	}

	// For I2CP protocol, we don't send a response to CreateLeaseSet
	// The client just needs to know the operation succeeded (no error)
	return nil, nil
}

// handleCreateLeaseSet2 handles CreateLeaseSet2Message (type 41) - modern LeaseSet format.
// This is the modern replacement for CreateLeaseSet (type 5), supporting:
// - LeaseSet2 format (type 3) with modern crypto (X25519/Ed25519)
// - EncryptedLeaseSet (type 5) for destination privacy
// - MetaLeaseSet (type 7) for multiple destinations
// - Multiple encryption keys per destination
//
// Per I2CP v0.9.67 spec:
// "CreateLeaseSet2Message: Create a LeaseSet2. Sent from client to router.
//
//	Supports LeaseSet2, EncryptedLeaseSet, and MetaLeaseSet formats.
//	Use this instead of CreateLeaseSetMessage for all routers 0.9.39+."
//
// Payload format:
//
//	2 bytes: Session ID
//	N bytes: Complete serialized LeaseSet2 (format depends on type byte)
//
// Unlike CreateLeaseSet (type 5), the client provides the complete serialized
// LeaseSet2 structure. The router validates and publishes it to the network.
func (s *Server) handleCreateLeaseSet2(msg *Message, sessionPtr **Session) (*Message, error) {
	if *sessionPtr == nil {
		return nil, oops.Errorf("no active session")
	}

	session := *sessionPtr
	logLeaseSet2Request(session.ID(), len(msg.Payload))

	leaseSetBytes, err := extractLeaseSet2Payload(msg.Payload)
	if err != nil {
		return nil, err
	}

	if err := validateLeaseSet2PayloadSize(session.ID(), leaseSetBytes); err != nil {
		return nil, err
	}

	log.WithFields(logger.Fields{
		"at":        "i2cp.Server.handleCreateLeaseSet2",
		"sessionID": session.ID(),
		"size":      len(leaseSetBytes),
	}).Info("leaseset2_received")

	if err := session.ValidateLeaseSet2Data(leaseSetBytes); err != nil {
		logLeaseSet2ValidationError(session.ID(), err)
		return nil, oops.Errorf("LeaseSet2 validation failed: %w", err)
	}

	session.SetCurrentLeaseSet(leaseSetBytes)
	s.publishLeaseSet2WithLogging(session, leaseSetBytes)

	log.WithFields(logger.Fields{
		"at":        "i2cp.Server.handleCreateLeaseSet2",
		"sessionID": session.ID(),
		"size":      len(leaseSetBytes),
	}).Info("leaseset2_processed")

	return nil, nil
}

// logLeaseSet2Request logs the initial CreateLeaseSet2 request.
func logLeaseSet2Request(sessionID uint16, payloadSize int) {
	log.WithFields(logger.Fields{
		"at":          "i2cp.Server.handleCreateLeaseSet2",
		"sessionID":   sessionID,
		"payloadSize": payloadSize,
	}).Debug("handling_create_leaseset2")
}

// extractLeaseSet2Payload strips the 2-byte SessionID prefix from the payload.
func extractLeaseSet2Payload(payload []byte) ([]byte, error) {
	if len(payload) < 2 {
		return nil, oops.Errorf("CreateLeaseSet2 payload too short: %d bytes (need at least 2 for SessionID)", len(payload))
	}
	return payload[2:], nil
}

// validateLeaseSet2PayloadSize checks the minimum payload size for a valid LeaseSet2.
func validateLeaseSet2PayloadSize(sessionID uint16, leaseSetBytes []byte) error {
	// Minimum LeaseSet2: destination (387+ bytes) + published (8) + expires (2) + flags (2) + leases (1+) ≈ 400 bytes
	if len(leaseSetBytes) < 400 {
		log.WithFields(logger.Fields{
			"at":          "i2cp.Server.handleCreateLeaseSet2",
			"sessionID":   sessionID,
			"payloadSize": len(leaseSetBytes),
		}).Warn("create_leaseset2_payload_too_short")
		return oops.Errorf("CreateLeaseSet2 payload too short: %d bytes (need at least 400)", len(leaseSetBytes))
	}
	return nil
}

// logLeaseSet2ValidationError logs a LeaseSet2 validation failure.
func logLeaseSet2ValidationError(sessionID uint16, err error) {
	log.WithFields(logger.Fields{
		"at":        "i2cp.Server.handleCreateLeaseSet2",
		"sessionID": sessionID,
		"error":     err,
	}).Warn("create_leaseset2_validation_failed")
}

// publishLeaseSet2WithLogging publishes LeaseSet2 to network and logs any errors.
func (s *Server) publishLeaseSet2WithLogging(session *Session, leaseSetBytes []byte) {
	if err := session.publishLeaseSetToNetwork(leaseSetBytes); err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.handleCreateLeaseSet2",
			"sessionID": session.ID(),
			"error":     err,
		}).Warn("failed_to_publish_leaseset2_to_network")
	}
}

// handleGetDate returns the current router time and protocol version.
// Per I2CP v0.9.67 spec (as of router 0.8.7):
// "The two parties' protocol version strings are exchanged in the Get/Set Date Messages.
//
//	Going forward, clients may use this information to communicate correctly with old routers."
//
// SetDate payload format:
//
//	Bytes 0-7:  Current time (milliseconds since epoch, big endian)
//	Bytes 8-9:  Version string length (big endian uint16)
//	Bytes 10+:  Protocol version string (UTF-8)

// parseClientVersion extracts the client protocol version from GetDate payload.
func parseClientVersion(payload []byte) string {
	if len(payload) < 2 {
		return ""
	}
	strLen := binary.BigEndian.Uint16(payload[0:2])
	if len(payload) < 2+int(strLen) {
		return ""
	}
	return string(payload[2 : 2+strLen])
}

// storeClientVersionInSession stores the client version in the session if available.
func (s *Server) storeClientVersionInSession(sessionID uint16, clientVersion string) {
	if sessionID == 0 || clientVersion == "" {
		return
	}
	if session, exists := s.manager.GetSession(sessionID); exists {
		session.SetProtocolVersion(clientVersion)
		log.WithFields(logger.Fields{
			"at":            "i2cp.Server.handleGetDate",
			"sessionID":     sessionID,
			"clientVersion": clientVersion,
		}).Debug("stored_client_protocol_version")
	}
}

// buildSetDatePayload creates the payload for SetDate response.
func buildSetDatePayload(currentTimeMillis int64, versionStr string) []byte {
	versionBytes := []byte(versionStr)
	payload := make([]byte, 8+2+len(versionBytes))
	binary.BigEndian.PutUint64(payload[0:8], uint64(currentTimeMillis))
	binary.BigEndian.PutUint16(payload[8:10], uint16(len(versionBytes)))
	copy(payload[10:], versionBytes)
	return payload
}

func (s *Server) handleGetDate(msg *Message) (*Message, error) {
	clientVersion := parseClientVersion(msg.Payload)

	log.WithFields(logger.Fields{
		"at":            "i2cp.Server.handleGetDate",
		"sessionID":     msg.SessionID,
		"clientVersion": clientVersion,
	}).Debug("handling_get_date_request")

	s.storeClientVersionInSession(msg.SessionID, clientVersion)

	currentTimeMillis := time.Now().UnixMilli()
	versionStr := fmt.Sprintf("%d.%d.%d",
		ProtocolVersionMajor, ProtocolVersionMinor, ProtocolVersionPatch)

	response := &Message{
		Type:      MessageTypeSetDate,
		SessionID: msg.SessionID,
		Payload:   buildSetDatePayload(currentTimeMillis, versionStr),
	}

	log.WithFields(logger.Fields{
		"at":              "i2cp.Server.handleGetDate",
		"reason":          "client_requested",
		"time_millis":     currentTimeMillis,
		"protocolVersion": versionStr,
		"clientVersion":   clientVersion,
	}).Debug("returning router time and version")
	return response, nil
}

// handleGetBandwidthLimits returns bandwidth limits
func (s *Server) handleGetBandwidthLimits(msg *Message) (*Message, error) {
	// I2CP BandwidthLimits format: two 4-byte integers (big endian)
	// [inbound_limit:4][outbound_limit:4]
	// Values are in bytes per second (0 = unlimited)

	var inboundLimit, outboundLimit uint32
	if s.bandwidthProvider != nil {
		inboundLimit, outboundLimit = s.bandwidthProvider.GetBandwidthLimits()
	} else {
		// Fallback: use a conservative default (1 MB/s) when no provider is configured
		inboundLimit = 1024 * 1024
		outboundLimit = 1024 * 1024
	}

	payload := make([]byte, 8)

	// Inbound limit (4 bytes, big endian)
	payload[0] = byte(inboundLimit >> 24)
	payload[1] = byte(inboundLimit >> 16)
	payload[2] = byte(inboundLimit >> 8)
	payload[3] = byte(inboundLimit)

	// Outbound limit (4 bytes, big endian)
	payload[4] = byte(outboundLimit >> 24)
	payload[5] = byte(outboundLimit >> 16)
	payload[6] = byte(outboundLimit >> 8)
	payload[7] = byte(outboundLimit)

	response := &Message{
		Type:      MessageTypeBandwidthLimits,
		SessionID: msg.SessionID,
		Payload:   payload,
	}

	log.WithFields(logger.Fields{
		"at":           "i2cp.Server.handleGetBandwidthLimits",
		"reason":       "client_requested",
		"inbound_bps":  inboundLimit,
		"outbound_bps": outboundLimit,
	}).Debug("returning bandwidth limits")

	return response, nil
}

// handleDisconnect handles a graceful client disconnect request.
// This allows clients to terminate the connection with a reason string.
// The server will:
// 1. Parse the disconnect reason from the payload
// 2. Log the disconnect with the reason
// 3. Clean up the session if one exists
// 4. Return nil to signal connection should be closed (no response sent)
//
// Note: Returning nil from a handler signals the connection should be closed.
func (s *Server) handleDisconnect(msg *Message, sessionPtr **Session) (*Message, error) {
	// Parse disconnect payload
	disconnectMsg, err := ParseDisconnectPayload(msg.Payload)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.Server.handleDisconnect",
			"sessionID":   msg.SessionID,
			"payloadSize": len(msg.Payload),
			"error":       err.Error(),
		}).Error("failed_to_parse_disconnect_payload")
		// Even if parse fails, proceed with disconnect
		disconnectMsg = &DisconnectPayload{Reason: "unknown (parse error)"}
	}

	log.WithFields(logger.Fields{
		"at":        "i2cp.Server.handleDisconnect",
		"sessionID": msg.SessionID,
		"reason":    disconnectMsg.Reason,
	}).Info("client_disconnect_requested")

	// Clean up session if it exists
	if *sessionPtr != nil {
		session := *sessionPtr
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.handleDisconnect",
			"sessionID": session.ID(),
			"reason":    disconnectMsg.Reason,
		}).Info("destroying_session_on_disconnect")

		// Destroy the session (this cleans up resources)
		if err := s.manager.DestroySession(session.ID()); err != nil {
			log.WithFields(logger.Fields{
				"at":        "i2cp.Server.handleDisconnect",
				"sessionID": session.ID(),
				"error":     err.Error(),
			}).Warn("failed_to_destroy_session_on_disconnect")
		}

		// Clear session pointer
		*sessionPtr = nil
	}

	// Return sentinel error to break the connection loop cleanly.
	// No response message is sent — client expects the connection to close.
	return nil, errClientDisconnected
}

// logHostLookupParseError logs an error when parsing host lookup payload fails.
func logHostLookupParseError(sessionID uint16, payloadSize int, err error) {
	log.WithFields(logger.Fields{
		"at":          "i2cp.Server.handleHostLookup",
		"sessionID":   sessionID,
		"payloadSize": payloadSize,
		"error":       err.Error(),
	}).Error("failed_to_parse_host_lookup_payload")
}

// logHostLookupRequest logs a host lookup request.
func logHostLookupRequest(sessionID uint16, lookupMsg *HostLookupPayload) {
	log.WithFields(logger.Fields{
		"at":         "i2cp.Server.handleHostLookup",
		"sessionID":  sessionID,
		"requestID":  lookupMsg.RequestID,
		"lookupType": lookupMsg.LookupType,
		"query":      lookupMsg.Query,
	}).Info("host_lookup_requested")
}

// handleHostnameLookup handles hostname lookup type.
// If a HostnameResolver is configured, the hostname is resolved via the resolver.
// Otherwise, returns HostReplyError indicating the feature is not available.
func (s *Server) handleHostnameLookup(lookupMsg *HostLookupPayload) *HostReplyPayload {
	if s.hostnameResolver == nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.handleHostLookup",
			"requestID": lookupMsg.RequestID,
			"query":     lookupMsg.Query,
		}).Debug("hostname_lookup_not_implemented")
		return &HostReplyPayload{
			RequestID:   lookupMsg.RequestID,
			ResultCode:  HostReplyError,
			Destination: nil,
		}
	}

	destBytes, err := s.hostnameResolver.ResolveHostname(lookupMsg.Query)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.handleHostLookup",
			"requestID": lookupMsg.RequestID,
			"hostname":  lookupMsg.Query,
			"error":     err.Error(),
		}).Debug("hostname_lookup_failed")
		return &HostReplyPayload{
			RequestID:   lookupMsg.RequestID,
			ResultCode:  HostReplyNotFound,
			Destination: nil,
		}
	}

	log.WithFields(logger.Fields{
		"at":        "i2cp.Server.handleHostLookup",
		"requestID": lookupMsg.RequestID,
		"hostname":  lookupMsg.Query,
		"destLen":   len(destBytes),
	}).Debug("hostname_lookup_resolved")
	return &HostReplyPayload{
		RequestID:   lookupMsg.RequestID,
		ResultCode:  HostReplySuccess,
		Destination: destBytes,
	}
}

// handleUnknownLookupType handles unknown lookup types.
func handleUnknownLookupType(lookupMsg *HostLookupPayload) *HostReplyPayload {
	log.WithFields(logger.Fields{
		"at":         "i2cp.Server.handleHostLookup",
		"requestID":  lookupMsg.RequestID,
		"lookupType": lookupMsg.LookupType,
	}).Warn("unknown_lookup_type")
	return &HostReplyPayload{
		RequestID:   lookupMsg.RequestID,
		ResultCode:  HostReplyError,
		Destination: nil,
	}
}

// buildHostReplyMessage constructs the host reply message from payload.
func buildHostReplyMessage(sessionID uint16, replyPayload *HostReplyPayload) (*Message, error) {
	replyData, err := replyPayload.MarshalBinary()
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.handleHostLookup",
			"requestID": replyPayload.RequestID,
			"error":     err.Error(),
		}).Error("failed_to_marshal_host_reply")
		return nil, oops.Errorf("failed to marshal HostReply: %w", err)
	}

	log.WithFields(logger.Fields{
		"at":         "i2cp.Server.handleHostLookup",
		"requestID":  replyPayload.RequestID,
		"resultCode": replyPayload.ResultCode,
	}).Debug("returning_host_reply")

	return &Message{
		Type:      MessageTypeHostReply,
		SessionID: sessionID,
		Payload:   replyData,
	}, nil
}

// handleHostLookup handles a destination lookup request by hash or hostname.
// This allows clients to query for destination information.
//
// Lookup types:
// - Type 0 (hash): Query NetDB for destination by hash
// - Type 1 (hostname): Requires naming service integration (not yet implemented)
//
// For hash lookups, the destination is retrieved from the LeaseSet stored in NetDB.
func (s *Server) handleHostLookup(_ net.Conn, msg *Message) (*Message, error) {
	lookupMsg, err := ParseHostLookupPayload(msg.Payload)
	if err != nil {
		logHostLookupParseError(msg.SessionID, len(msg.Payload), err)
		return nil, oops.Errorf("failed to parse HostLookup payload: %w", err)
	}

	logHostLookupRequest(msg.SessionID, lookupMsg)

	var replyPayload *HostReplyPayload
	switch lookupMsg.LookupType {
	case HostLookupTypeHash:
		replyPayload = s.lookupDestinationByHash(lookupMsg)
	case HostLookupTypeHostname:
		replyPayload = s.handleHostnameLookup(lookupMsg)
	default:
		replyPayload = handleUnknownLookupType(lookupMsg)
	}

	return buildHostReplyMessage(msg.SessionID, replyPayload)
}

// lookupDestinationByHash queries NetDB for a LeaseSet by hash and extracts the destination.
// Returns HostReplyPayload with the destination bytes if found, or an error code if not found.
// parseDestinationHash parses a destination hash from the query string.
// Returns the parsed hash and nil if successful, or a zero hash and an error reply if parsing fails.
func parseDestinationHash(lookupMsg *HostLookupPayload) (common.Hash, *HostReplyPayload) {
	var destHash common.Hash

	if len(lookupMsg.Query) < 64 {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.lookupDestinationByHash",
			"requestID": lookupMsg.RequestID,
			"queryLen":  len(lookupMsg.Query),
		}).Warn("query_too_short_for_hash")
		return destHash, &HostReplyPayload{
			RequestID:   lookupMsg.RequestID,
			ResultCode:  HostReplyError,
			Destination: nil,
		}
	}

	_, err := fmt.Sscanf(lookupMsg.Query[:64], "%x", &destHash)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.lookupDestinationByHash",
			"requestID": lookupMsg.RequestID,
			"query":     lookupMsg.Query,
			"error":     err.Error(),
		}).Warn("invalid_hash_format")
		return destHash, &HostReplyPayload{
			RequestID:   lookupMsg.RequestID,
			ResultCode:  HostReplyError,
			Destination: nil,
		}
	}

	return destHash, nil
}

// queryLeaseSetFromNetDB queries the NetDB for a LeaseSet and extracts the destination.
// Returns the destination bytes and nil if successful, or nil and an error reply if the query fails.
func (s *Server) queryLeaseSetFromNetDB(destHash common.Hash, requestID uint32) ([]byte, *HostReplyPayload) {
	leaseSetBytes, err := s.netdb.GetLeaseSetBytes(destHash)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.lookupDestinationByHash",
			"requestID": requestID,
			"destHash":  fmt.Sprintf("%x", destHash[:8]),
			"error":     err.Error(),
		}).Debug("leaseset_not_found_in_netdb")
		return nil, &HostReplyPayload{
			RequestID:   requestID,
			ResultCode:  HostReplyNotFound,
			Destination: nil,
		}
	}

	destination, err := s.extractDestinationFromLeaseSet(leaseSetBytes)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.lookupDestinationByHash",
			"requestID": requestID,
			"destHash":  fmt.Sprintf("%x", destHash[:8]),
			"error":     err.Error(),
		}).Error("failed_to_extract_destination")
		return nil, &HostReplyPayload{
			RequestID:   requestID,
			ResultCode:  HostReplyError,
			Destination: nil,
		}
	}

	return destination, nil
}

func (s *Server) lookupDestinationByHash(lookupMsg *HostLookupPayload) *HostReplyPayload {
	if s.netdb == nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.lookupDestinationByHash",
			"requestID": lookupMsg.RequestID,
		}).Warn("no_netdb_configured")
		return &HostReplyPayload{
			RequestID:   lookupMsg.RequestID,
			ResultCode:  HostReplyError,
			Destination: nil,
		}
	}

	destHash, errReply := parseDestinationHash(lookupMsg)
	if errReply != nil {
		return errReply
	}

	destination, errReply := s.queryLeaseSetFromNetDB(destHash, lookupMsg.RequestID)
	if errReply != nil {
		return errReply
	}

	log.WithFields(logger.Fields{
		"at":           "i2cp.Server.lookupDestinationByHash",
		"requestID":    lookupMsg.RequestID,
		"destHash":     fmt.Sprintf("%x", destHash[:8]),
		"destByteSize": len(destination),
	}).Info("destination_found")

	return &HostReplyPayload{
		RequestID:   lookupMsg.RequestID,
		ResultCode:  HostReplySuccess,
		Destination: destination,
	}
}

// extractDestinationFromLeaseSet extracts the destination bytes from a LeaseSet.
// The destination is at the beginning of the LeaseSet structure.
// Returns the destination bytes suitable for HostReply, or an error if parsing fails.
func (s *Server) extractDestinationFromLeaseSet(leaseSetBytes []byte) ([]byte, error) {
	// LeaseSet format starts with Destination
	// Destination minimum size is 387 bytes (for standard ElGamal/DSA)
	// But can be larger with key certificates
	if len(leaseSetBytes) < 387 {
		return nil, oops.Errorf("leaseset too small: %d bytes", len(leaseSetBytes))
	}

	// Parse the destination to determine its actual size
	_, remainder, err := destination.ReadDestination(leaseSetBytes)
	if err != nil {
		return nil, oops.Errorf("failed to parse destination: %w", err)
	}

	// Calculate how many bytes the destination occupies
	destSize := len(leaseSetBytes) - len(remainder)

	// Return the destination bytes
	return leaseSetBytes[:destSize], nil
}

// handleBlindingInfo handles blinded destination parameters.
// This allows clients to configure destination blinding for privacy enhancement.
// Blinded destinations rotate daily at UTC midnight to prevent long-term correlation.
//
// Workflow:
// 1. Parse BlindingInfo payload (enabled flag + optional secret)
// 2. Update session configuration with blinding parameters
// 3. If enabled, trigger blinded destination derivation
// 4. Session will automatically use blinded destinations in EncryptedLeaseSets
//
// The session's updateBlindedDestination() handles daily rotation automatically.
func (s *Server) handleBlindingInfo(msg *Message, sessionPtr **Session) (*Message, error) {
	if *sessionPtr == nil {
		return nil, oops.Errorf("session not active")
	}

	session := *sessionPtr

	blindingInfo, err := parseAndLogBlindingInfo(msg, session)
	if err != nil {
		return nil, err
	}

	updateSessionBlindingConfig(session, blindingInfo)

	if err := applyBlindedDestinationUpdate(session, blindingInfo); err != nil {
		return nil, err
	}

	return nil, nil
}

// parseAndLogBlindingInfo parses the BlindingInfo payload and logs the received configuration.
func parseAndLogBlindingInfo(msg *Message, session *Session) (*BlindingInfoPayload, error) {
	blindingInfo, err := ParseBlindingInfoPayload(msg.Payload)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.Server.handleBlindingInfo",
			"sessionID":   session.ID(),
			"payloadSize": len(msg.Payload),
			"error":       err.Error(),
		}).Error("failed_to_parse_blinding_info")
		return nil, oops.Errorf("failed to parse BlindingInfo payload: %w", err)
	}

	log.WithFields(logger.Fields{
		"at":        "i2cp.Server.handleBlindingInfo",
		"sessionID": session.ID(),
		"enabled":   blindingInfo.Enabled,
		"hasSecret": len(blindingInfo.Secret) > 0,
	}).Info("received_blinding_info")

	return blindingInfo, nil
}

// updateSessionBlindingConfig updates the session's blinding configuration based on the received info.
func updateSessionBlindingConfig(session *Session, blindingInfo *BlindingInfoPayload) {
	session.mu.Lock()
	defer session.mu.Unlock()

	session.config.UseEncryptedLeaseSet = blindingInfo.Enabled
	if blindingInfo.Enabled && len(blindingInfo.Secret) > 0 {
		session.config.BlindingSecret = blindingInfo.Secret
		session.blindingSecret = nil
	} else if blindingInfo.Enabled {
		session.config.BlindingSecret = nil
		session.blindingSecret = nil
	} else {
		session.config.BlindingSecret = nil
		session.blindingSecret = nil
		session.blindedDestination = nil
	}
}

// applyBlindedDestinationUpdate triggers blinded destination update if blinding is enabled.
func applyBlindedDestinationUpdate(session *Session, blindingInfo *BlindingInfoPayload) error {
	if !blindingInfo.Enabled {
		return nil
	}

	if err := session.updateBlindedDestination(); err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.handleBlindingInfo",
			"sessionID": session.ID(),
			"error":     err.Error(),
		}).Error("failed_to_update_blinded_destination")
		return oops.Errorf("failed to update blinded destination: %w", err)
	}

	log.WithFields(logger.Fields{
		"at":        "i2cp.Server.handleBlindingInfo",
		"sessionID": session.ID(),
	}).Debug("blinded_destination_updated")

	return nil
}

// handleSendMessage handles a client sending a message to a destination.
// This implements the full message delivery flow with status tracking:
// 1. Parse and validate the SendMessage payload
// 2. Generate unique message ID for tracking
// 3. Send immediate MessageStatus (accepted) to client
// 4. Route message asynchronously with delivery status callbacks
//
// Message routing:
// - Wraps payload in garlic encryption using destination's public key
// - Selects outbound tunnel from session's tunnel pool
// - Sends encrypted garlic through tunnel gateway
// - Reports final status (success/failure) via MessageStatus message
func (s *Server) handleSendMessage(msg *Message, sessionPtr **Session) (*Message, error) {
	session, err := s.validateSessionForSending(sessionPtr)
	if err != nil {
		return nil, err
	}

	sendMsg, err := s.parseSendMessagePayload(msg, session)
	if err != nil {
		return nil, err
	}

	if err := s.validateOutboundPool(session); err != nil {
		return nil, err
	}

	acceptMsg := s.acceptAndRouteMessage(session, sendMsg.Destination, len(sendMsg.Payload), 0,
		logger.Fields{"at": "i2cp.Server.handleSendMessage"},
		func(messageID uint32) { s.routeMessageWithStatus(session, messageID, sendMsg) },
	)
	return acceptMsg, nil
}

// validateSessionForSending validates that a session exists for sending.
func (s *Server) validateSessionForSending(sessionPtr **Session) (*Session, error) {
	if *sessionPtr == nil {
		return nil, oops.Errorf("session not active")
	}
	return *sessionPtr, nil
}

// parseSendMessagePayload parses the SendMessage payload from the message.
// Note: msg.Payload includes the 2-byte SessionID prefix (already extracted by
// ReadMessage into msg.SessionID), so we strip it before parsing the actual
// SendMessage payload which starts with Destination(32 bytes) + Payload.
func (s *Server) parseSendMessagePayload(msg *Message, session *Session) (*SendMessagePayload, error) {
	// i2psnark compatibility: Log SendMessage details before parsing
	log.WithFields(logger.Fields{
		"at":          "i2cp.Server.parseSendMessagePayload",
		"sessionID":   session.ID(),
		"payloadSize": len(msg.Payload),
	}).Debug("parsing_send_message_payload")

	// Strip the 2-byte SessionID prefix from the wire payload.
	// ReadMessage extracts SessionID into msg.SessionID but does not remove it
	// from msg.Payload. ParseSendMessagePayload expects: Destination(32) + Payload.
	if len(msg.Payload) < 2 {
		return nil, oops.Errorf("SendMessage payload too short: %d bytes (need at least 2 for SessionID)", len(msg.Payload))
	}
	payloadData := msg.Payload[2:]

	sendMsg, err := ParseSendMessagePayload(payloadData)
	if err != nil {
		// i2psnark compatibility: Show payload excerpt on parse failure
		excerptLen := min(64, len(msg.Payload))
		log.WithFields(logger.Fields{
			"at":             "i2cp.Server.parseSendMessagePayload",
			"sessionID":      session.ID(),
			"payloadSize":    len(msg.Payload),
			"error":          err,
			"payloadExcerpt": fmt.Sprintf("%x", msg.Payload[:excerptLen]),
		}).Error("failed_to_parse_send_message")
		return nil, oops.Errorf("failed to parse SendMessage payload: %w", err)
	}

	// Validate payload size to prevent exceeding I2CP limits after garlic encryption
	// i2psnark compatibility: Account for overhead from garlic encryption
	// Data message (4 bytes) + garlic encryption (~200 bytes typical)
	// Conservative limit: MaxPayloadSize - 2048 bytes for all overhead
	// Increased overhead budget to accommodate larger i2psnark messages
	const maxSafePayloadSize = MaxPayloadSize - 2048
	if len(sendMsg.Payload) > maxSafePayloadSize {
		// i2psnark compatibility: Log detailed size information for debugging
		log.WithFields(logger.Fields{
			"at":              "i2cp.Server.parseSendMessagePayload",
			"sessionID":       session.ID(),
			"payloadSize":     len(sendMsg.Payload),
			"maxAllowed":      maxSafePayloadSize,
			"maxPayloadSize":  MaxPayloadSize,
			"overhead":        512,
			"destinationHash": fmt.Sprintf("%x", sendMsg.Destination[:8]),
		}).Error("send_message_payload_too_large")
		return nil, oops.Errorf("message payload too large: %d bytes (max %d bytes to allow for encryption overhead)",
			len(sendMsg.Payload), maxSafePayloadSize)
	}

	return sendMsg, nil
}

// validateOutboundPool validates that the session has an outbound tunnel pool.
func (s *Server) validateOutboundPool(session *Session) error {
	outboundPool := session.OutboundPool()
	if outboundPool == nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.validateOutboundPool",
			"sessionID": session.ID(),
		}).Warn("no_outbound_tunnel_pool")
		return oops.Errorf("session %d has no outbound tunnel pool", session.ID())
	}
	return nil
}

// acceptAndRouteMessage handles the common accept-and-route flow for send
// message handlers: generate message ID → log → build acceptance response →
// launch async routing goroutine. Returns the acceptance response message.
func (s *Server) acceptAndRouteMessage(
	session *Session, destination [32]byte, payloadSize int, nonce uint32,
	extraFields logger.Fields, routeAsync func(messageID uint32),
) *Message {
	messageID := s.nextMessageID.Add(1)

	fields := logger.Fields{
		"sessionID":   session.ID(),
		"messageID":   messageID,
		"destination": fmt.Sprintf("%x", destination[:8]),
		"payloadSize": payloadSize,
	}
	for k, v := range extraFields {
		fields[k] = v
	}
	log.WithFields(fields).Debug("message_accepted")

	acceptMsg := buildMessageStatusResponse(
		session.ID(), messageID, MessageStatusAccepted, uint32(payloadSize), nonce,
	)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		routeAsync(messageID)
	}()

	return acceptMsg
}

// handleSendMessageExpires handles SendMessageExpires (type 36) messages.
// This is an enhanced version of SendMessage that includes expiration time and delivery flags.
// The message will not be sent if it has already expired when processing begins.
func (s *Server) handleSendMessageExpires(msg *Message, sessionPtr **Session) (*Message, error) {
	session, err := s.validateSessionForSending(sessionPtr)
	if err != nil {
		return nil, err
	}

	// Parse SendMessageExpires payload
	sendMsgExpires, err := s.parseSendMessageExpiresPayload(msg, session)
	if err != nil {
		return nil, err
	}

	if err := s.validateOutboundPool(session); err != nil {
		return nil, err
	}

	acceptMsg := s.acceptAndRouteMessage(session, sendMsgExpires.Destination, len(sendMsgExpires.Payload), sendMsgExpires.Nonce,
		logger.Fields{
			"at":         "i2cp.Server.handleSendMessageExpires",
			"nonce":      sendMsgExpires.Nonce,
			"flags":      sendMsgExpires.Flags,
			"expiration": sendMsgExpires.Expiration,
		},
		func(messageID uint32) { s.routeMessageExpiresWithStatus(session, messageID, sendMsgExpires) },
	)
	return acceptMsg, nil
}

// parseSendMessageExpiresPayload parses the SendMessageExpires payload from the message.
// Note: msg.Payload includes the 2-byte SessionID prefix (already extracted by
// ReadMessage into msg.SessionID), so we strip it before parsing the actual
// SendMessageExpires payload which starts with Destination(32 bytes) + Payload + Nonce + Expiration.
func (s *Server) parseSendMessageExpiresPayload(msg *Message, session *Session) (*SendMessageExpiresPayload, error) {
	log.WithFields(logger.Fields{
		"at":          "i2cp.Server.parseSendMessageExpiresPayload",
		"sessionID":   session.ID(),
		"payloadSize": len(msg.Payload),
	}).Debug("parsing_send_message_expires_payload")

	// Strip the 2-byte SessionID prefix from the wire payload.
	// ReadMessage extracts SessionID into msg.SessionID but does not remove it
	// from msg.Payload. ParseSendMessageExpiresPayload expects:
	// Destination(32) + PayloadLen(4) + Payload + Nonce(4) + Expiration(8).
	if len(msg.Payload) < 2 {
		return nil, oops.Errorf("SendMessageExpires payload too short: %d bytes (need at least 2 for SessionID)", len(msg.Payload))
	}
	payloadData := msg.Payload[2:]

	sendMsg, err := ParseSendMessageExpiresPayload(payloadData)
	if err != nil {
		excerptLen := min(64, len(msg.Payload))
		log.WithFields(logger.Fields{
			"at":             "i2cp.Server.parseSendMessageExpiresPayload",
			"sessionID":      session.ID(),
			"payloadSize":    len(msg.Payload),
			"error":          err,
			"payloadExcerpt": fmt.Sprintf("%x", msg.Payload[:excerptLen]),
		}).Error("failed_to_parse_send_message_expires")
		return nil, oops.Errorf("failed to parse SendMessageExpires payload: %w", err)
	}

	// Validate payload size (same limits as SendMessage)
	const maxSafePayloadSize = MaxPayloadSize - 2048
	if len(sendMsg.Payload) > maxSafePayloadSize {
		log.WithFields(logger.Fields{
			"at":              "i2cp.Server.parseSendMessageExpiresPayload",
			"sessionID":       session.ID(),
			"payloadSize":     len(sendMsg.Payload),
			"maxAllowed":      maxSafePayloadSize,
			"maxPayloadSize":  MaxPayloadSize,
			"destinationHash": fmt.Sprintf("%x", sendMsg.Destination[:8]),
		}).Error("send_message_expires_payload_too_large")
		return nil, oops.Errorf("message payload too large: %d bytes (max %d bytes to allow for encryption overhead)",
			len(sendMsg.Payload), maxSafePayloadSize)
	}

	return sendMsg, nil
}

// routeMessageExpiresWithStatus routes a SendMessageExpires message asynchronously with
// delivery status tracking and expiration checking.
func (s *Server) routeMessageExpiresWithStatus(session *Session, messageID uint32, sendMsg *SendMessageExpiresPayload) {
	log.WithFields(logger.Fields{
		"at":          "i2cp.Server.routeMessageExpiresWithStatus",
		"sessionID":   session.ID(),
		"messageID":   messageID,
		"destination": fmt.Sprintf("%x", sendMsg.Destination[:8]),
		"payloadSize": len(sendMsg.Payload),
		"expiration":  sendMsg.Expiration,
		"nonce":       sendMsg.Nonce,
	}).Info("routing_message_expires")

	statusCallback := s.buildStatusCallback(session, sendMsg.Nonce)

	destPubKey, err := s.resolveDestinationKey(sendMsg.Destination)
	if err != nil {
		logDestinationResolutionFailure("routeMessageExpiresWithStatus", session.ID(), messageID, sendMsg.Destination, err)
		statusCallback(messageID, MessageStatusNoLeaseSet, uint32(len(sendMsg.Payload)), sendMsg.Nonce)
		return
	}

	s.dispatchToMessageRouter("routeMessageExpiresWithStatus", session, messageID, sendMsg.Destination, destPubKey, sendMsg.Payload, sendMsg.Expiration, statusCallback)
}

// routeMessageWithStatus routes a message asynchronously with delivery status tracking.
// This method is called from a goroutine and handles the complete routing flow including
// status callbacks to notify the client of delivery success/failure.
func (s *Server) routeMessageWithStatus(session *Session, messageID uint32, sendMsg *SendMessagePayload) {
	log.WithFields(logger.Fields{
		"at":          "i2cp.Server.routeMessageWithStatus",
		"sessionID":   session.ID(),
		"messageID":   messageID,
		"destination": fmt.Sprintf("%x", sendMsg.Destination[:8]),
		"payloadSize": len(sendMsg.Payload),
	}).Debug("routing_message_async")

	statusCallback := s.buildStatusCallback(session, 0)

	destPubKey, err := s.resolveDestinationKey(sendMsg.Destination)
	if err != nil {
		logDestinationResolutionFailure("routeMessageWithStatus", session.ID(), messageID, sendMsg.Destination, err)
		statusCallback(messageID, MessageStatusNoLeaseSet, uint32(len(sendMsg.Payload)), 0)
		return
	}

	if s.messageRouter == nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.Server.routeMessageWithStatus",
			"sessionID":   session.ID(),
			"messageID":   messageID,
			"destination": fmt.Sprintf("%x", sendMsg.Destination[:8]),
		}).Warn("no_message_router_message_queued")
		statusCallback(messageID, MessageStatusFailure, uint32(len(sendMsg.Payload)), 0)
		return
	}

	s.dispatchToMessageRouter("routeMessageWithStatus", session, messageID, sendMsg.Destination, destPubKey, sendMsg.Payload, 0, statusCallback)
}

// buildStatusCallback creates a status callback that sends a MessageStatus response
// to the client. The fixedNonce is used for SendMessageExpires; pass 0 for SendMessage.
func (s *Server) buildStatusCallback(session *Session, fixedNonce uint32) func(uint32, uint8, uint32, uint32) {
	return func(msgID uint32, statusCode uint8, messageSize, nonce uint32) {
		effectiveNonce := nonce
		if fixedNonce != 0 {
			effectiveNonce = fixedNonce
		}
		statusMsg := buildMessageStatusResponse(session.ID(), msgID, statusCode, messageSize, effectiveNonce)
		s.sendStatusToClient(session, statusMsg)
	}
}

// logDestinationResolutionFailure logs an error when a destination key cannot be resolved.
func logDestinationResolutionFailure(caller string, sessionID uint16, messageID uint32, destination common.Hash, err error) {
	log.WithFields(logger.Fields{
		"at":          "i2cp.Server." + caller,
		"sessionID":   sessionID,
		"messageID":   messageID,
		"destination": fmt.Sprintf("%x", destination[:8]),
		"error":       err.Error(),
	}).Error("failed_to_resolve_destination_key")
}

// dispatchToMessageRouter routes a message through the message router if available.
// Logs routing failures but does not return errors since the status callback
// is already invoked by RouteOutboundMessage.
func (s *Server) dispatchToMessageRouter(caller string, session *Session, messageID uint32, destination common.Hash, destPubKey [32]byte, payload []byte, expiration uint64, statusCallback func(uint32, uint8, uint32, uint32)) {
	if s.messageRouter == nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.Server." + caller,
			"sessionID":   session.ID(),
			"messageID":   messageID,
			"destination": fmt.Sprintf("%x", destination[:8]),
		}).Warn("no_message_router_configured")
		return
	}

	err := s.messageRouter.RouteOutboundMessage(RouteRequest{
		Session:           session,
		MessageID:         messageID,
		DestinationHash:   destination,
		DestinationPubKey: destPubKey,
		Payload:           payload,
		ExpirationMs:      expiration,
		StatusCallback:    statusCallback,
	})
	if err != nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.Server." + caller,
			"sessionID":   session.ID(),
			"messageID":   messageID,
			"destination": fmt.Sprintf("%x", destination[:8]),
			"error":       err.Error(),
		}).Error("failed_to_route_message")
	}
}

// sendStatusToClient sends a MessageStatus message to the client connection.
func (s *Server) sendStatusToClient(session *Session, statusMsg *Message) {
	s.mu.RLock()
	conn, exists := s.sessionConns[session.ID()]
	writeMu := s.connWriteMu[session.ID()]
	s.mu.RUnlock()

	if !exists || writeMu == nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.sendStatusToClient",
			"sessionID": session.ID(),
		}).Warn("no_connection_for_status_message")
		return
	}

	data, err := statusMsg.MarshalBinary()
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.sendStatusToClient",
			"sessionID": session.ID(),
			"error":     err.Error(),
		}).Error("failed_to_marshal_status_message")
		return
	}

	writeMu.Lock()
	_, err = conn.Write(data)
	writeMu.Unlock()
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.sendStatusToClient",
			"sessionID": session.ID(),
			"error":     err.Error(),
		}).Error("failed_to_send_status_message")
	}
}
