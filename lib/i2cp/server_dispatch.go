package i2cp

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/go-i2p/lib/util/logutil"
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

	case MessageTypeBlindingInfo:
		return s.handleBlindingInfo(msg, sessionPtr)

	default:
		// i2cp.rst:228-229: routers "generally disconnect the session upon
		// reception of an unsupported message". Returning the terminal sentinel
		// makes runConnectionLoop close the socket instead of skipping the
		// message and continuing on the same connection.
		log.WithFields(logger.Fields{
			"at":          "i2cp.Server.handleMessage",
			"msgType":     MessageTypeName(msg.Type),
			"msgTypeID":   msg.Type,
			"sessionID":   msg.SessionID,
			"payloadSize": len(msg.Payload),
			"payloadHex":  fmt.Sprintf("%x", msg.Payload[:min(32, len(msg.Payload))]),
		}).Warn("unsupported_message_type_disconnecting")
		return nil, oops.Wrapf(errUnsupportedMessageType, "unsupported message type: %d", msg.Type)
	}
}

// handleCreateSession creates a new session
func (s *Server) handleCreateSession(msg *Message, sessionPtr **Session) (*Message, error) {
	// Parse and validate session configuration
	dest, config, err := parseSessionConfiguration(msg.Payload)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":    "i2cp.Server.handleCreateSession",
			"error": err.Error(),
		}).Warn("invalid_create_session_payload")
		return buildSessionStatusResponseWithCode(0, SessionStatusInvalid), nil
	}

	// Create session with parsed or default configuration
	// If dest is nil, NewSession will generate a new destination
	session, err := s.manager.CreateSession(dest, config)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":    "i2cp.Server.handleCreateSession",
			"error": err.Error(),
		}).Warn("session_creation_refused")
		return buildSessionStatusResponseWithCode(0, SessionStatusRefused), nil
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
// Parse or validation failures return an error.
func parseSessionConfiguration(payload []byte) (*destination.Destination, *SessionConfig, error) {
	// Parse destination and signed session configuration from payload.
	// Strict behavior requires date+signature verification.
	dest, config, err := ParseCreateSessionSignedPayload(payload)
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
func buildSessionStatusResponseWithCode(sessionID uint16, status uint8) *Message {
	payload := make([]byte, 3)
	binary.BigEndian.PutUint16(payload[0:2], sessionID) // SessionID
	payload[2] = status

	return &Message{
		Type:      MessageTypeSessionStatus,
		SessionID: sessionID, // Keep for application logic
		Payload:   payload,
	}
}

// buildSessionStatusResponse creates a successful "created" session status response.
func buildSessionStatusResponse(sessionID uint16) *Message {
	return buildSessionStatusResponseWithCode(sessionID, SessionStatusCreated)
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

// handleDestroySession destroys a session.
//
// i2cp.rst:798 — "The router at this point should release all resources related
// to the session."
// i2cp.rst:802-804 — the current-version router behaviour: "The router never
// sends a SessionStatus(Destroyed) response. If no sessions are left, it sends a
// DisconnectMessage_. If there are subsessions or the primary session is
// remaining, it does not reply."
// i2cp.rst:828-829 — the DisconnectMessage "ends all sessions on that
// connection. The socket will be closed shortly."
//
// This router keeps at most one session per connection (a destroy of the primary
// is a destroy of the connection's sessions, i2cp.rst:813-815), so after the
// destroy no sessions are left and the prescribed reply is a DisconnectMessage
// followed by closing the socket — not SessionStatus(Destroyed).
func (s *Server) handleDestroySession(msg *Message, sessionPtr **Session) (*Message, error) {
	if *sessionPtr == nil {
		return nil, oops.Errorf("session not active")
	}

	sessionID := (*sessionPtr).ID()

	if err := s.manager.DestroySession(sessionID); err != nil {
		return nil, oops.Errorf("failed to destroy session: %w", err)
	}

	// Drop any BlindingInfo advice recorded under this session so a departing
	// client's per-client decryption keys are not retained.
	s.forgetBlindingAdviceForSession(sessionID)

	// The session is gone: stop routing async MessageStatus writes to it and
	// release the connection's ownership of the session so cleanupIdleSessions
	// cannot race with the deferred connection cleanup.
	s.forgetSessionConnection(sessionID)

	*sessionPtr = nil

	log.WithFields(logger.Fields{
		"at":        "i2cp.Server.handleDestroySession",
		"reason":    "client_requested",
		"sessionID": sessionID,
	}).Info("session_destroyed")

	disconnect, err := s.buildDisconnectMessage("session destroyed")
	if err != nil {
		// Still close the socket; a failure to encode the reason must not leave
		// the connection half-open.
		return nil, oops.Wrapf(errCloseAfterResponse, "failed to build disconnect message: %w", err)
	}
	return disconnect, oops.Wrapf(errCloseAfterResponse, "session %d destroyed", sessionID)
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
		return buildSessionStatusResponseWithCode(0, SessionStatusInvalid), nil
	}

	parsedSessionID, parsedDest, newConfig, err := ParseReconfigureSessionSignedPayload(msg.Payload)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":    "i2cp.Server.handleReconfigureSession",
			"error": err.Error(),
		}).Warn("invalid_signed_reconfigure_payload")
		return buildSessionStatusResponseWithCode((*sessionPtr).ID(), SessionStatusInvalid), nil
	}

	if parsedSessionID != (*sessionPtr).ID() {
		log.WithFields(logger.Fields{
			"at":              "i2cp.Server.handleReconfigureSession",
			"sessionID":       (*sessionPtr).ID(),
			"parsedSessionID": parsedSessionID,
		}).Warn("reconfigure_session_id_mismatch")
		return buildSessionStatusResponseWithCode((*sessionPtr).ID(), SessionStatusInvalid), nil
	}

	if !(*sessionPtr).Destination().Equals(parsedDest) {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.handleReconfigureSession",
			"sessionID": (*sessionPtr).ID(),
		}).Warn("reconfigure_destination_mismatch")
		return buildSessionStatusResponseWithCode((*sessionPtr).ID(), SessionStatusInvalid), nil
	}

	if err := ValidateSessionConfig(newConfig); err != nil {
		log.WithError(err).Warn("invalid session config in reconfigure request")
		return buildSessionStatusResponseWithCode((*sessionPtr).ID(), SessionStatusInvalid), nil
	}

	if err := (*sessionPtr).Reconfigure(newConfig); err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.handleReconfigureSession",
			"sessionID": (*sessionPtr).ID(),
			"error":     err.Error(),
		}).Warn("failed_to_reconfigure_session")
		return buildSessionStatusResponseWithCode((*sessionPtr).ID(), SessionStatusInvalid), nil
	}

	if err := s.rebuildSessionTunnelPools(*sessionPtr); err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.handleReconfigureSession",
			"sessionID": (*sessionPtr).ID(),
			"error":     err.Error(),
		}).Warn("failed_to_rebuild_tunnel_pools_after_reconfigure")
	}

	logReconfigSuccess((*sessionPtr).ID(), newConfig)
	return buildSessionStatusResponseWithCode((*sessionPtr).ID(), SessionStatusUpdated), nil
}

// handleCreateLeaseSet is a no-op drop for the deprecated CreateLeaseSet
// message (type 4).
//
// The I2CP spec marks CreateLeaseSetMessage DEPRECATED ("Use
// CreateLeaseSet2Message with all routers 0.9.39 or higher"). Its wire contents
// are the client's own LeaseSet plus the matching [PrivateKey]_, which the
// router must publish verbatim - the earlier behavior here instead generated a
// LeaseSet from the session's tunnels and discarded the client's payload. That
// noncompliant path is replaced by handleCreateLeaseSet2 (type 41), which
// consumes the client-supplied LeaseSet2 and private keys correctly.
//
// A modern router keeps accepting the deprecated message for legacy clients
// without disconnecting them (consistent with how the deprecated 528-byte
// build messages are handled in the I2NP layer), so this logs and drops it.
// Legacy clients that only speak type 4 should upgrade to type 41.
func (s *Server) handleCreateLeaseSet(msg *Message, sessionPtr **Session) (*Message, error) {
	var sessionID uint16
	if *sessionPtr != nil {
		sessionID = (*sessionPtr).ID()
	}

	log.WithFields(logger.Fields{
		"at":          "i2cp.Server.handleCreateLeaseSet",
		"sessionID":   sessionID,
		"payloadSize": len(msg.Payload),
	}).Debug("dropping deprecated CreateLeaseSet (type 4); use CreateLeaseSet2 (type 41)")

	return nil, nil
}

// handleCreateLeaseSet2 handles CreateLeaseSet2Message (type 41).
//
// i2cp.rst:658-677 — the payload is:
//
//  1. Session ID
//  2. One byte type of lease set to follow.
//     Type 1 is a LeaseSet (deprecated)
//     Type 3 is a LeaseSet2
//     Type 5 is an EncryptedLeaseSet
//     Type 7 is a MetaLeaseSet
//  3. LeaseSet / LeaseSet2 / EncryptedLeaseSet / MetaLeaseSet
//  4. One byte number of private keys to follow.
//  5. PrivateKey list, one per public key in the lease set, in the same order
//     (not present for Meta LS2)
//
// The store type byte is not decorative: it selects which structure follows, and
// therefore the framing, the validation, the NetDB record type and the lookup key
// the record is published under. Framing and structural parsing are delegated to
// the upstream go-i2p/common lease-set packages (see leaseset_store.go).
//
// i2cp.rst:660 — "MetaLeaseSet is not yet supported via I2CP", so store type 7 is
// rejected rather than stored as something the router cannot use.
func (s *Server) handleCreateLeaseSet2(msg *Message, sessionPtr **Session) (*Message, error) {
	if *sessionPtr == nil {
		return nil, oops.Errorf("no active session")
	}

	session := *sessionPtr
	logLeaseSet2Request(session.ID(), len(msg.Payload))

	// SessionID(2) + store type(1)
	if len(msg.Payload) < 3 {
		return nil, oops.Errorf("CreateLeaseSet2 payload too short: %d bytes (need at least 3 for SessionID+StoreType)", len(msg.Payload))
	}

	// The one byte after the SessionID names the structure that follows
	// (i2cp.rst:666-672).
	storeType := LeaseSetStoreType(msg.Payload[2])
	if err := storeType.validate(); err != nil {
		return nil, oops.Wrapf(err, "CreateLeaseSet2")
	}

	leaseSetBytes, remainder, err := frameLeaseSetByStoreType(msg.Payload[3:], storeType)
	if err != nil {
		return nil, err
	}

	// Parse private keys from the bytes following the lease set (field 4/5).
	privKeys, err := parseCreateLeaseSet2PrivateKeys(remainder, storeType)
	if err != nil {
		return nil, err
	}

	log.WithFields(logger.Fields{
		"at":             "i2cp.Server.handleCreateLeaseSet2",
		"sessionID":      session.ID(),
		"storeType":      uint8(storeType),
		"leaseSetType":   storeType.name(),
		"leaseSetSize":   len(leaseSetBytes),
		"numPrivateKeys": len(privKeys),
	}).Debug("leaseset_received")

	if err := validateLeaseSetForSession(session, storeType, leaseSetBytes); err != nil {
		logLeaseSet2ValidationError(session.ID(), err)
		return nil, oops.Errorf("%s validation failed: %w", storeType.name(), err)
	}

	// Store private keys in session for decryption of inbound messages
	if len(privKeys) > 0 {
		if err := session.StorePrivateKeys(privKeys); err != nil {
			log.WithFields(logger.Fields{
				"at":        "i2cp.Server.handleCreateLeaseSet2",
				"sessionID": session.ID(),
				"error":     err.Error(),
			}).Warn("failed_to_store_private_keys")
			// Don't fail on private key storage error; continue with LeaseSet
		}
	}

	session.SetCurrentLeaseSetWithType(leaseSetBytes, storeType)
	s.publishLeaseSetWithLogging(session, storeType, leaseSetBytes)

	log.WithFields(logger.Fields{
		"at":        "i2cp.Server.handleCreateLeaseSet2",
		"sessionID": session.ID(),
		"type":      storeType.name(),
		"size":      len(leaseSetBytes),
	}).Info("leaseset_processed")

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

// parseCreateLeaseSet2PrivateKeys reads the trailing "One byte number of private
// keys to follow" plus the [PrivateKey]_ list of i2cp.rst:673-681:
//
//   - Encryption type (2 byte Integer)
//   - Encryption key length (2 byte Integer)
//   - Encryption PrivateKey (number of bytes specified)
//
// The list is not present for MetaLeaseSet (i2cp.rst:677), so a declared count
// for that type is a framing error rather than something to ignore.
func parseCreateLeaseSet2PrivateKeys(remainder []byte, storeType LeaseSetStoreType) (map[uint16][]byte, error) {
	if len(remainder) == 0 {
		return nil, nil
	}

	numPrivateKeys := int(remainder[0])
	if numPrivateKeys == 0 {
		return nil, nil
	}

	if !storeType.allowsPrivateKeys() {
		return nil, oops.Errorf("CreateLeaseSet2: %s does not carry private keys but payload declares %d",
			storeType.name(), numPrivateKeys)
	}

	privateKeys := make(map[uint16][]byte, numPrivateKeys)
	offset := 1
	for i := 0; i < numPrivateKeys; i++ {
		if offset+4 > len(remainder) {
			return nil, oops.Errorf("CreateLeaseSet2: truncated private key header at index %d (offset %d, %d bytes available)",
				i, offset, len(remainder))
		}

		keyType := binary.BigEndian.Uint16(remainder[offset : offset+2])
		offset += 2
		keyLen := int(binary.BigEndian.Uint16(remainder[offset : offset+2]))
		offset += 2

		if offset+keyLen > len(remainder) {
			return nil, oops.Errorf("CreateLeaseSet2: truncated private key data for type %d (need %d bytes, %d available)",
				keyType, keyLen, len(remainder)-offset)
		}

		keyData := make([]byte, keyLen)
		copy(keyData, remainder[offset:offset+keyLen])
		offset += keyLen
		privateKeys[keyType] = keyData
	}

	return privateKeys, nil
}

// logLeaseSet2ValidationError logs a CreateLeaseSet2 validation failure.
func logLeaseSet2ValidationError(sessionID uint16, err error) {
	log.WithFields(logger.Fields{
		"at":        "i2cp.Server.handleCreateLeaseSet2",
		"sessionID": sessionID,
		"error":     err,
	}).Warn("create_leaseset2_validation_failed")
}

// publishLeaseSetWithLogging publishes the lease set to the network under the key
// and record type implied by its store type, and logs any errors.
func (s *Server) publishLeaseSetWithLogging(session *Session, storeType LeaseSetStoreType, leaseSetBytes []byte) {
	if err := session.publishLeaseSetToNetwork(leaseSetBytes); err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.handleCreateLeaseSet2",
			"sessionID": session.ID(),
			"type":      storeType.name(),
			"error":     err,
		}).Warn("failed_to_publish_leaseset_to_network")
	}
}

// handleGetDate returns the current router time and protocol version.
// Per I2CP v0.9.67 spec (as of router 0.8.7):
// "The two parties' protocol version strings are exchanged in the Get/Set Date Messages.
//
//	Going forward, clients may use this information to communicate correctly with old routers."
//
// SetDate payload format (i2cp.rst "SetDateMessage": 1. Date, 2. I2CP API
// Version [String]):
//
//	Bytes 0-7:  Current time (milliseconds since epoch, big endian)
//	Byte  8:    Version string length (1 byte, per common-structures.rst)
//	Bytes 9+:   Protocol version string (UTF-8)

// parseClientVersion extracts the client protocol version from GetDate payload.
// The version is an I2P [String]: the first byte is the number of bytes in the
// string, not a 2-byte big-endian length (common-structures.rst).
func parseClientVersion(payload []byte) string {
	str, _, err := common.ReadI2PString(payload)
	if err != nil {
		return ""
	}
	version, err := str.Data()
	if err != nil {
		return ""
	}
	return version
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
// The I2CP API Version is an I2P [String] (1-byte length prefix) per
// common-structures.rst, not a 2-byte length-prefixed string.
func buildSetDatePayload(currentTimeMillis int64, versionStr string) []byte {
	str, err := common.NewI2PString(versionStr)
	if err != nil {
		// The version string is internally generated ("major.minor.patch") and
		// far below the 255-byte String limit; degrade to an empty String rather
		// than failing the whole date exchange.
		log.WithError(err).WithFields(logger.Fields{
			"at":          "i2cp.buildSetDatePayload",
			"version_str": versionStr,
		}).Warn("version string too long for I2P String; sending empty version")
		str = common.I2PString{0x00}
	}

	payload := make([]byte, 8+len(str))
	binary.BigEndian.PutUint64(payload[0:8], uint64(currentTimeMillis))
	copy(payload[8:], str)
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

// bytesPerSecToKBps converts a byte-per-second rate into the KBps unit the
// BandwidthLimits message requires (i2cp.rst:497-502).
//
// The provider's math.MaxUint32 "unlimited" sentinel is forwarded unchanged:
// dividing it would turn an "I have no limit" answer into a large but finite
// number, which is exactly the kind of value a client throttles itself against.
// A zero rate stays zero. Rounds to nearest so a 1500 B/s limit does not report
// as 1 KBps-1.
func bytesPerSecToKBps(bytesPerSec uint32) uint32 {
	if bytesPerSec == math.MaxUint32 {
		return math.MaxUint32
	}
	if bytesPerSec == 0 {
		return 0
	}
	return (bytesPerSec + i2cpKiB/2) / i2cpKiB
}

// i2cpKiB is the bytes-per-KB divisor for I2CP bandwidth conversions. The spec's
// KBps tracks the router's own byte-rate accounting, which is binary (see
// lib/config BandwidthClassFromRate, which divides by 1024).
const i2cpKiB = 1024

// handleGetBandwidthLimits returns bandwidth limits
// Per I2CP v0.9.67 spec, returns 64 bytes of bandwidth data (16 × uint32 big endian)
func (s *Server) handleGetBandwidthLimits(msg *Message) (*Message, error) {
	// I2CP BandwidthLimits format per spec:
	// [inbound_limit:4][outbound_limit:4][spare:56]
	// The 16 uint32 values represent various bandwidth-related metrics.
	// Currently only inbound and outbound limits are populated; rest are zero-filled.
	//
	// The wire unit is KBps, not bytes per second (i2cp.rst:497-502 labels all
	// six defined limits "(KBps)"). The provider reports the router's configured
	// MaxBandwidth in bytes per second (lib/config/router.go:72), so the value is
	// converted here at the wire boundary. Reporting the raw byte rate overstated
	// every limit by 1024x, which makes clients compute a wildly optimistic
	// throughput budget. The provider's MaxUint32 "unlimited" sentinel is passed
	// through untouched rather than divided down into a finite-looking number.
	var inboundBytes, outboundBytes uint32
	if s.bandwidthProvider != nil {
		inboundBytes, outboundBytes = s.bandwidthProvider.GetBandwidthLimits()
	} else {
		// Fallback: use a conservative default (1 MB/s) when no provider is configured
		inboundBytes = 1024 * 1024
		outboundBytes = 1024 * 1024
	}

	inboundLimit := bytesPerSecToKBps(inboundBytes)
	outboundLimit := bytesPerSecToKBps(outboundBytes)

	// Per I2CP spec: BandwidthLimits is 64 bytes (16 uint32 values, big endian)
	payload := make([]byte, 64)

	// First uint32 (bytes 0-3): Inbound limit (KBps)
	binary.BigEndian.PutUint32(payload[0:4], inboundLimit)

	// Second uint32 (bytes 4-7): Outbound limit (KBps)
	binary.BigEndian.PutUint32(payload[4:8], outboundLimit)

	// Remaining 56 bytes (bytes 8-63): Zero-filled for future use
	// (Already initialized to zero by make())

	response := &Message{
		Type:      MessageTypeBandwidthLimits,
		SessionID: msg.SessionID,
		Payload:   payload,
	}

	log.WithFields(logger.Fields{
		"at":            "i2cp.Server.handleGetBandwidthLimits",
		"reason":        "client_requested",
		"inbound_kbps":  inboundLimit,
		"outbound_kbps": outboundLimit,
		"payloadSize":   len(payload),
	}).Debug("returning_bandwidth_limits")

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
		s.forgetBlindingAdviceForSession(session.ID())

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
	}).Debug("host_lookup_requested")
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
		return newErrorReply(lookupMsg.SessionID, lookupMsg.RequestID, HostReplyError)
	}

	destBytes, err := s.hostnameResolver.ResolveHostname(lookupMsg.Query)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.handleHostLookup",
			"requestID": lookupMsg.RequestID,
			"hostname":  lookupMsg.Query,
			"error":     err.Error(),
		}).Debug("hostname_lookup_failed")
		return newErrorReply(lookupMsg.SessionID, lookupMsg.RequestID, HostReplyNotFound)
	}

	log.WithFields(logger.Fields{
		"at":        "i2cp.Server.handleHostLookup",
		"requestID": lookupMsg.RequestID,
		"hostname":  lookupMsg.Query,
		"destLen":   len(destBytes),
	}).Debug("hostname_lookup_resolved")
	return &HostReplyPayload{
		SessionID:   lookupMsg.SessionID,
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
	return newErrorReply(lookupMsg.SessionID, lookupMsg.RequestID, HostReplyError)
}

// buildHostReplyMessage constructs the host reply message from payload.
func buildHostReplyMessage(sessionID uint16, replyPayload *HostReplyPayload) (*Message, error) {
	replyPayload.SessionID = sessionID

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
// - Type 1 (hostname): Resolved via the configured HostnameResolver
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
// newErrorReply creates an error HostReplyPayload with the given error code.
func newErrorReply(sessionID uint16, requestID uint32, code uint8) *HostReplyPayload {
	return &HostReplyPayload{
		SessionID:   sessionID,
		RequestID:   requestID,
		ResultCode:  code,
		Destination: nil,
	}
}

// parseDestinationHash parses a destination hash from the query string.
// Returns the parsed hash and nil if successful, or a zero hash and an error reply if parsing fails.
func parseDestinationHash(lookupMsg *HostLookupPayload) (common.Hash, *HostReplyPayload) {
	var destHash common.Hash

	if len(lookupMsg.Hash) == len(destHash) {
		copy(destHash[:], lookupMsg.Hash)
		return destHash, nil
	}

	if len(lookupMsg.Query) < 64 {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.lookupDestinationByHash",
			"requestID": lookupMsg.RequestID,
			"queryLen":  len(lookupMsg.Query),
		}).Warn("query_too_short_for_hash")
		return destHash, newErrorReply(lookupMsg.SessionID, lookupMsg.RequestID, HostReplyError)
	}

	_, err := fmt.Sscanf(lookupMsg.Query[:64], "%x", &destHash)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.lookupDestinationByHash",
			"requestID": lookupMsg.RequestID,
			"query":     lookupMsg.Query,
			"error":     err.Error(),
		}).Warn("invalid_hash_format")
		return destHash, newErrorReply(lookupMsg.SessionID, lookupMsg.RequestID, HostReplyError)
	}

	return destHash, nil
}

// queryLeaseSetFromNetDB queries the NetDB for a LeaseSet and extracts the destination.
// Returns the destination bytes and nil if successful, or nil and an error reply if the query fails.
func (s *Server) queryLeaseSetFromNetDB(destHash common.Hash, sessionID uint16, requestID uint32) ([]byte, *HostReplyPayload) {
	leaseSetBytes, err := s.netdb.GetLeaseSetBytes(destHash)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.lookupDestinationByHash",
			"requestID": requestID,
			"destHash":  logutil.HashPrefixPlain(destHash),
			"error":     err.Error(),
		}).Debug("leaseset_not_found_in_netdb")
		return nil, newErrorReply(sessionID, requestID, HostReplyNotFound)
	}

	destination, err := s.extractDestinationFromLeaseSet(leaseSetBytes)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.lookupDestinationByHash",
			"requestID": requestID,
			"destHash":  logutil.HashPrefixPlain(destHash),
			"error":     err.Error(),
		}).Error("failed_to_extract_destination")
		return nil, newErrorReply(sessionID, requestID, HostReplyError)
	}

	return destination, nil
}

func (s *Server) lookupDestinationByHash(lookupMsg *HostLookupPayload) *HostReplyPayload {
	if s.netdb == nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.lookupDestinationByHash",
			"requestID": lookupMsg.RequestID,
		}).Warn("no_netdb_configured")
		return newErrorReply(lookupMsg.SessionID, lookupMsg.RequestID, HostReplyError)
	}

	destHash, errReply := parseDestinationHash(lookupMsg)
	if errReply != nil {
		return errReply
	}

	destination, errReply := s.queryLeaseSetFromNetDB(destHash, lookupMsg.SessionID, lookupMsg.RequestID)
	if errReply != nil {
		return errReply
	}

	log.WithFields(logger.Fields{
		"at":           "i2cp.Server.lookupDestinationByHash",
		"requestID":    lookupMsg.RequestID,
		"destHash":     logutil.HashPrefixPlain(destHash),
		"destByteSize": len(destination),
	}).Debug("destination_found")

	return &HostReplyPayload{
		SessionID:   lookupMsg.SessionID,
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

// handleBlindingInfo records a client's advice that a peer Destination is
// blinded (a new-format "b33" address), together with the optional per-client
// decryption key and lookup password.
//
// Per the I2CP spec (BlindingInfoMessage, since 0.9.43): "Advise the router
// that a Destination is blinded, with optional lookup password and optional
// private key for decryption... The router does not send a reply to this
// message." The advice concerns the *peer* the client will send to — it is not
// a switch for the session's own EncryptedLeaseSet, so this handler stores it
// for blinded-destination resolution and leaves the session's own configuration
// untouched.
func (s *Server) handleBlindingInfo(msg *Message, sessionPtr **Session) (*Message, error) {
	if *sessionPtr == nil {
		return nil, oops.Errorf("session not active")
	}

	session := *sessionPtr

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

	// The message's session ID is taken from the first two payload bytes (see
	// extractSessionIDFromPayload), so it always equals the parsed value for a
	// wire message. The guard only fires for a hand-constructed Message whose
	// header disagrees with its payload, which must not be trusted.
	if msg.SessionID != blindingInfo.SessionID {
		log.WithFields(logger.Fields{
			"at":             "i2cp.Server.handleBlindingInfo",
			"sessionID":      session.ID(),
			"payloadSession": blindingInfo.SessionID,
		}).Warn("blinding_info_session_id_mismatch")
		return nil, oops.Errorf("BlindingInfo session ID %d does not match message session %d",
			blindingInfo.SessionID, msg.SessionID)
	}

	destHash, err := blindedPeerHash(blindingInfo)
	if err != nil {
		return nil, err
	}

	s.storeBlindingAdvice(destHash, blindingInfo)

	log.WithFields(logger.Fields{
		"at":         "i2cp.Server.handleBlindingInfo",
		"sessionID":  session.ID(),
		"peer":       logutil.HashPrefixPlain(destHash),
		"endpoint":   blindingInfo.Endpoint,
		"sigType":    blindingInfo.SigType,
		"expiration": blindingInfo.Expiration,
		"perClient":  blindingInfo.IsPerClient(),
		"secret":     blindingInfo.RequiresSecret(),
	}).Info("blinding_info_recorded")

	// The router does not reply to BlindingInfo.
	return nil, nil
}

// storeBlindingAdvice remembers blinding advice for a peer destination hash.
func (s *Server) storeBlindingAdvice(destHash common.Hash, info *BlindingInfoPayload) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.blindingAdvice == nil {
		s.blindingAdvice = make(map[common.Hash]*BlindingInfoPayload)
	}
	s.blindingAdvice[destHash] = info
}

// BlindingAdviceFor returns the blinding advice recorded for a peer
// destination hash, if any. Resolution and lookup paths consult it to learn
// that an address is blinded and to obtain the per-client secret.
func (s *Server) BlindingAdviceFor(destHash common.Hash) (*BlindingInfoPayload, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	info, ok := s.blindingAdvice[destHash]
	return info, ok
}

// forgetBlindingAdviceForSession drops any advice recorded for a session that
// is going away, so a departing client's per-client keys are not retained.
func (s *Server) forgetBlindingAdviceForSession(sessionID uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for hash, info := range s.blindingAdvice {
		if info.SessionID == sessionID {
			delete(s.blindingAdvice, hash)
		}
	}
}

// blindedPeerHash derives the destination hash the advice applies to, from the
// endpoint field. A hash endpoint is already the answer; a Destination endpoint
// is hashed; a sig-type+key endpoint is hashed over the blinded signing public
// key (the NetDB lookup key for a blinded destination).
func blindedPeerHash(info *BlindingInfoPayload) (common.Hash, error) {
	switch info.Endpoint {
	case BlindingEndpointHash:
		var h common.Hash
		copy(h[:], info.Hash)
		return h, nil

	case BlindingEndpointDestination:
		dest, _, err := destination.ReadDestination(info.Destination)
		if err != nil {
			return common.Hash{}, oops.Wrapf(err, "BlindingInfo destination endpoint")
		}
		h, err := dest.Hash()
		if err != nil {
			return common.Hash{}, oops.Wrapf(err, "BlindingInfo destination hash")
		}
		return h, nil

	case BlindingEndpointSigTypeKey:
		// The blinded signing public key is what a "b33" address encodes; the
		// NetDB key is SHA-256 of that key.
		return common.HashData(info.Pubkey), nil

	case BlindingEndpointHostname:
		return common.Hash{}, oops.Errorf(
			"BlindingInfo hostname endpoint %q cannot be resolved to a destination hash without an address book", info.Hostname,
		)

	default:
		return common.Hash{}, oops.Errorf("unsupported BlindingInfo endpoint type: %d", info.Endpoint)
	}
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

	// Extract destination hash for routing
	destHash, err := sendMsg.Destination.Hash()
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.handleSendMessage",
			"sessionID": session.ID(),
			"error":     err.Error(),
		}).Error("failed_to_compute_destination_hash")
		return nil, oops.Errorf("failed to compute destination hash: %w", err)
	}

	acceptMsg := s.acceptAndRouteMessage(
		session, destHash, len(sendMsg.Payload), sendMsg.Nonce,
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
// SendMessage payload per I2CP spec.
func (s *Server) parseSendMessagePayload(msg *Message, session *Session) (*SendMessagePayload, error) {
	// i2psnark compatibility: Log SendMessage details before parsing
	log.WithFields(logger.Fields{
		"at":          "i2cp.Server.parseSendMessagePayload",
		"sessionID":   session.ID(),
		"payloadSize": len(msg.Payload),
	}).Debug("parsing_send_message_payload")

	// Strip the 2-byte SessionID prefix from the wire payload.
	// ReadMessage extracts SessionID into msg.SessionID but does not remove it
	// from msg.Payload. ParseSendMessagePayload expects: Destination + PayloadLen + Payload + Nonce.
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

	// Validate destination is set
	// Note: destination.Destination is a value type, so we check for zero value instead
	destHash, err := sendMsg.Destination.Hash()
	if err != nil {
		return nil, oops.Errorf("failed to compute destination hash: %w", err)
	}

	if err := validateSendPayloadSizeWithContext(
		"i2cp.Server.parseSendMessagePayload",
		session.ID(),
		destHash,
		len(sendMsg.Payload),
		"send_message_payload_too_large",
	); err != nil {
		return nil, err
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
// launch async routing goroutine. Returns the acceptance response message, or
// nil when the client asked for no status at all.
//
// i2cp.rst:1417-1419: "As soon as the SendMessageMessage_ arrives fully intact,
// the router should return a MessageStatusMessage_ stating that it has been
// accepted for delivery. That message will contain the same nonce sent here."
//
// i2cp.rst:1426-1429: "a nonce value of 0 is allowed, and tells to the router
// that it should not send either MessageStatusMessage_, i.e. it acts as if
// i2cp.messageReliability=none for this message only." The message is still
// routed; only the status reporting is suppressed.
//
// i2cp.rst:1423-1424: "the router does not send either MessageStatusMessage_ if
// i2cp.messageReliability=none".
//
// i2cp.rst:1431-1437: in a messageReliability=none session a nonzero nonce opts
// back in to the later success/failure status, but not the "accepted" one.
func (s *Server) acceptAndRouteMessage(
	session *Session, destination [32]byte, payloadSize int, nonce uint32,
	extraFields logger.Fields, routeAsync func(messageID uint32),
) *Message {
	messageID := s.nextMessageID.Add(1)

	fields := logger.Fields{
		"sessionID":   session.ID(),
		"messageID":   messageID,
		"destination": logutil.HashPrefixPlain(destination),
		"payloadSize": payloadSize,
		"nonce":       nonce,
	}
	for k, v := range extraFields {
		fields[k] = v
	}
	log.WithFields(fields).Debug("message_accepted")

	var acceptMsg *Message
	if sendStatusRequested(nonce, session.MessageReliability(), true) {
		acceptMsg = buildMessageStatusResponse(
			session.ID(), messageID, MessageStatusAccepted, uint32(payloadSize), nonce,
		)
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		routeAsync(messageID)
	}()

	return acceptMsg
}

// sendStatusRequested decides whether a MessageStatusMessage_ is sent to the
// client for a message with the given nonce, in a session with the given
// i2cp.messageReliability value.
//
// nonce 0 always means "send no status" (i2cp.rst:1426-1429, :1472-1475).
// In a messageReliability=none session no status is sent either, except that a
// nonzero nonce requests the later success/failure status only, never the
// "accepted" one (i2cp.rst:1423-1424, :1431-1437, :1477-1483).
//
// accepted distinguishes the synchronous "accepted" status from the
// asynchronous delivery status.
func sendStatusRequested(nonce uint32, reliability string, accepted bool) bool {
	if nonce == 0 {
		return false
	}
	if reliability == MessageReliabilityNone && accepted {
		return false
	}
	return true
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

	// Extract destination hash for routing
	destHash, err := sendMsgExpires.Destination.Hash()
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.handleSendMessageExpires",
			"sessionID": session.ID(),
			"error":     err.Error(),
		}).Error("failed_to_compute_destination_hash")
		return nil, oops.Errorf("failed to compute destination hash: %w", err)
	}

	acceptMsg := s.acceptAndRouteMessage(
		session, destHash, len(sendMsgExpires.Payload), sendMsgExpires.Nonce,
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
// SendMessageExpires payload per I2CP spec.
func (s *Server) parseSendMessageExpiresPayload(msg *Message, session *Session) (*SendMessageExpiresPayload, error) {
	log.WithFields(logger.Fields{
		"at":          "i2cp.Server.parseSendMessageExpiresPayload",
		"sessionID":   session.ID(),
		"payloadSize": len(msg.Payload),
	}).Debug("parsing_send_message_expires_payload")

	// Strip the 2-byte SessionID prefix from the wire payload.
	// ReadMessage extracts SessionID into msg.SessionID but does not remove it
	// from msg.Payload. ParseSendMessageExpiresPayload expects:
	// Destination + PayloadLen + Payload + Nonce + Flags + Expiration.
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

	// Validate destination is set
	// Note: destination.Destination is a value type, so we check for zero value instead
	destHash, err := sendMsg.Destination.Hash()
	if err != nil {
		return nil, oops.Errorf("failed to compute destination hash: %w", err)
	}

	if err := validateSendPayloadSizeWithContext(
		"i2cp.Server.parseSendMessageExpiresPayload",
		session.ID(),
		destHash,
		len(sendMsg.Payload),
		"send_message_expires_payload_too_large",
	); err != nil {
		return nil, err
	}

	return sendMsg, nil
}

// validateSendPayloadSizeWithContext validates SendMessage-like payload sizes
// using the shared encryption-overhead safety budget used by SendMessage and
// SendMessageExpires parsing paths.
func validateSendPayloadSizeWithContext(
	at string,
	sessionID uint16,
	destination common.Hash,
	payloadSize int,
	logReason string,
) error {
	// Account for post-parse overhead from garlic wrapping/encryption.
	const maxSafePayloadSize = MaxPayloadSize - 2048
	if payloadSize <= maxSafePayloadSize {
		return nil
	}

	log.WithFields(logger.Fields{
		"at":              at,
		"sessionID":       sessionID,
		"payloadSize":     payloadSize,
		"maxAllowed":      maxSafePayloadSize,
		"maxPayloadSize":  MaxPayloadSize,
		"overhead":        512,
		"destinationHash": logutil.HashPrefixPlain(destination),
	}).Error(logReason)

	return oops.Errorf(
		"message payload too large: %d bytes (max %d bytes to allow for encryption overhead)",
		payloadSize,
		maxSafePayloadSize,
	)
}

// routeMessageExpiresWithStatus routes a SendMessageExpires message asynchronously with
// delivery status tracking and expiration checking.
func (s *Server) routeMessageExpiresWithStatus(session *Session, messageID uint32, sendMsg *SendMessageExpiresPayload) {
	// Extract destination hash for routing
	destHash, err := sendMsg.Destination.Hash()
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.routeMessageExpiresWithStatus",
			"sessionID": session.ID(),
			"messageID": messageID,
			"error":     err.Error(),
		}).Error("failed_to_compute_destination_hash")
		statusCallback := s.buildStatusCallback(session)
		statusCallback(messageID, MessageStatusNoLeaseSet, uint32(len(sendMsg.Payload)), sendMsg.Nonce)
		return
	}

	log.WithFields(logger.Fields{
		"at":          "i2cp.Server.routeMessageExpiresWithStatus",
		"sessionID":   session.ID(),
		"messageID":   messageID,
		"destination": logutil.HashPrefixPlain(destHash),
		"payloadSize": len(sendMsg.Payload),
		"expiration":  sendMsg.Expiration,
		"nonce":       sendMsg.Nonce,
	}).Debug("routing_message_expires")

	statusCallback := s.buildStatusCallback(session)

	destPubKey, err := s.resolveDestinationKey(destHash)
	if err != nil {
		logDestinationResolutionFailure("routeMessageExpiresWithStatus", session.ID(), messageID, destHash, err)
		statusCallback(messageID, MessageStatusNoLeaseSet, uint32(len(sendMsg.Payload)), sendMsg.Nonce)
		return
	}

	s.dispatchToMessageRouter("routeMessageExpiresWithStatus", session, messageID, destHash, destPubKey, sendMsg.Payload, sendMsg.Expiration, sendMsg.Nonce, statusCallback)
}

// routeMessageWithStatus routes a message asynchronously with delivery status tracking.
// This method is called from a goroutine and handles the complete routing flow including
// status callbacks to notify the client of delivery success/failure.
func (s *Server) routeMessageWithStatus(session *Session, messageID uint32, sendMsg *SendMessagePayload) {
	// Extract destination hash for routing
	destHash, err := sendMsg.Destination.Hash()
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.routeMessageWithStatus",
			"sessionID": session.ID(),
			"messageID": messageID,
			"error":     err.Error(),
		}).Error("failed_to_compute_destination_hash")
		statusCallback := s.buildStatusCallback(session)
		statusCallback(messageID, MessageStatusNoLeaseSet, uint32(len(sendMsg.Payload)), sendMsg.Nonce)
		return
	}

	log.WithFields(logger.Fields{
		"at":          "i2cp.Server.routeMessageWithStatus",
		"sessionID":   session.ID(),
		"messageID":   messageID,
		"destination": logutil.HashPrefixPlain(destHash),
		"payloadSize": len(sendMsg.Payload),
		"nonce":       sendMsg.Nonce,
	}).Debug("routing_message_async")

	statusCallback := s.buildStatusCallback(session)

	destPubKey, err := s.resolveDestinationKey(destHash)
	if err != nil {
		logDestinationResolutionFailure("routeMessageWithStatus", session.ID(), messageID, destHash, err)
		statusCallback(messageID, MessageStatusNoLeaseSet, uint32(len(sendMsg.Payload)), sendMsg.Nonce)
		return
	}

	if s.messageRouter == nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.Server.routeMessageWithStatus",
			"sessionID":   session.ID(),
			"messageID":   messageID,
			"destination": logutil.HashPrefixPlain(destHash),
		}).Warn("no_message_router_message_queued")
		statusCallback(messageID, MessageStatusFailure, uint32(len(sendMsg.Payload)), sendMsg.Nonce)
		return
	}

	s.dispatchToMessageRouter("routeMessageWithStatus", session, messageID, destHash, destPubKey, sendMsg.Payload, 0, sendMsg.Nonce, statusCallback)
}

// buildStatusCallback creates a status callback that sends the asynchronous
// delivery MessageStatus response to the client.
//
// The nonce carried in the status is the nonce of the client message the status
// refers to (i2cp.rst:1417-1419: "That message will contain the same nonce sent
// here", and the same rule for SendMessageExpires at :1464-1467), so it is taken
// from the callback argument, which the message router propagates from
// RouteRequest.Nonce. A nonce of 0 means the client asked for no status at all,
// so nothing is sent (i2cp.rst:1426-1429).
func (s *Server) buildStatusCallback(session *Session) func(uint32, uint8, uint32, uint32) {
	return func(msgID uint32, statusCode uint8, messageSize, nonce uint32) {
		if !sendStatusRequested(nonce, session.MessageReliability(), false) {
			return
		}
		statusMsg := buildMessageStatusResponse(session.ID(), msgID, statusCode, messageSize, nonce)
		s.sendStatusToClient(session, statusMsg)
	}
}

// logDestinationResolutionFailure logs an error when a destination key cannot be resolved.
func logDestinationResolutionFailure(caller string, sessionID uint16, messageID uint32, destination common.Hash, err error) {
	log.WithFields(logger.Fields{
		"at":          "i2cp.Server." + caller,
		"sessionID":   sessionID,
		"messageID":   messageID,
		"destination": logutil.HashPrefixPlain(destination),
		"error":       err.Error(),
	}).Error("failed_to_resolve_destination_key")
}

// dispatchToMessageRouter routes a message through the message router if available.
// Logs routing failures but does not return errors since the status callback
// is already invoked by RouteOutboundMessage.
func (s *Server) dispatchToMessageRouter(caller string, session *Session, messageID uint32, destination common.Hash, destPubKey [32]byte, payload []byte, expiration uint64, nonce uint32, statusCallback func(uint32, uint8, uint32, uint32)) {
	if s.messageRouter == nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.Server." + caller,
			"sessionID":   session.ID(),
			"messageID":   messageID,
			"destination": logutil.HashPrefixPlain(destination),
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
		Nonce:             nonce,
		StatusCallback:    statusCallback,
	})
	if err != nil {
		log.WithFields(logger.Fields{
			"at":          "i2cp.Server." + caller,
			"sessionID":   session.ID(),
			"messageID":   messageID,
			"destination": logutil.HashPrefixPlain(destination),
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

	s.applyWriteDeadline(conn)

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
