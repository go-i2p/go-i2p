// Package i2cp implements the I2P Client Protocol (I2CP) v2.10.0.
//
// I2CP is the protocol used by client applications to communicate with the I2P router.
// It allows clients to create sessions, send messages, and receive messages through the I2P network.
//
// Protocol Overview:
// - TCP-based client-server protocol (default port: 7654)
// - Each message has: type (1 byte), session ID (2 bytes), length (4 bytes), payload
// - Session IDs 0x0000 and 0xFFFF are reserved
// - Supports authentication, tunnel management, and message delivery
package i2cp

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/go-i2p/logger"
)

// Message type constants as defined in I2CP v2.10.0
const (
	// Session management
	MessageTypeCreateSession      = 1 // Client -> Router: Create new session
	MessageTypeSessionStatus      = 2 // Router -> Client: Session creation result
	MessageTypeReconfigureSession = 3 // Client -> Router: Update session config
	MessageTypeDestroySession     = 4 // Client -> Router: Terminate session

	// LeaseSet management
	MessageTypeCreateLeaseSet          = 5  // Client -> Router: Publish LeaseSet (deprecated)
	MessageTypeRequestLeaseSet         = 6  // Router -> Client: Request LeaseSet update
	MessageTypeRequestVariableLeaseSet = 37 // Router -> Client: Request LeaseSet (with lease data)
	MessageTypeCreateLeaseSet2         = 41 // Client -> Router: Publish LeaseSet2 (modern, v0.9.39+)

	// Message delivery
	MessageTypeSendMessage        = 7  // Client -> Router: Send message to destination
	MessageTypeMessagePayload     = 8  // Router -> Client: Received message
	MessageTypeMessageStatus      = 22 // Router -> Client: Message delivery status
	MessageTypeDisconnect         = 30 // Client -> Router: Graceful disconnect
	MessageTypeSendMessageExpires = 36 // Client -> Router: Send message with TTL

	// Status and information
	MessageTypeGetBandwidthLimits = 9  // Client -> Router: Query bandwidth
	MessageTypeBandwidthLimits    = 10 // Router -> Client: Bandwidth limits response
	MessageTypeGetDate            = 11 // Client -> Router: Query router time
	MessageTypeSetDate            = 12 // Router -> Client: Current router time

	// Naming service (modern types)
	MessageTypeHostLookup = 38 // Client -> Router: Destination lookup by hash or hostname
	MessageTypeHostReply  = 39 // Router -> Client: Destination lookup result

	// Advanced features
	MessageTypeBlindingInfo = 42 // Client -> Router: Blinded destination parameters

	// Deprecated/legacy message types
	MessageTypeHostLookupDeprecated = 13 // Deprecated in v2.10.0, use type 38
	MessageTypeHostReplyDeprecated  = 14 // Deprecated in v2.10.0, use type 39
)

// Reserved session IDs
const (
	SessionIDReservedControl   = 0x0000 // Control messages (pre-session)
	SessionIDReservedBroadcast = 0xFFFF // Broadcast to all sessions
)

// Protocol version constants
const (
	ProtocolVersionMajor = 2
	ProtocolVersionMinor = 10
	ProtocolVersionPatch = 0
)

// MessageStatus codes as defined in I2CP specification.
// These codes indicate the delivery status of messages sent via SendMessage.
const (
	// MessageStatusAccepted indicates the message was accepted for delivery.
	// Sent immediately when SendMessage is received.
	MessageStatusAccepted = 1

	// MessageStatusSuccess indicates the message was successfully delivered.
	// Sent after routing completes successfully.
	MessageStatusSuccess = 4

	// MessageStatusFailure indicates the message delivery failed.
	// Generic failure status.
	MessageStatusFailure = 5

	// MessageStatusNoTunnels indicates delivery failed due to no available tunnels.
	// Sent when the session has no outbound tunnels.
	MessageStatusNoTunnels = 16

	// MessageStatusNoLeaseSet indicates delivery failed due to missing LeaseSet.
	// Sent when the destination's LeaseSet cannot be found.
	MessageStatusNoLeaseSet = 21
)

// Protocol limits as per I2CP specification
const (
	// MaxPayloadSize is the maximum size for I2CP message payloads.
	// i2psnark compatibility: The I2CP wire format uses a 4-byte length field (uint32),
	// theoretically supporting up to 4 GB. Java I2P routers accept payloads larger than
	// 64 KB. i2psnark-standalone sends payloads exceeding 65535 bytes for file transfers.
	// Setting limit to 256 KB (262144 bytes) to match Java I2P behavior while preventing
	// memory exhaustion attacks. This allows i2psnark to function properly while maintaining
	// reasonable DoS protection.
	MaxPayloadSize = 262144 // 256 KB

	// MaxMessageSize is the maximum total I2CP message size including header.
	// Header: type(1) + sessionID(2) + length(4) = 7 bytes
	MaxMessageSize = 7 + MaxPayloadSize

	// DefaultPayloadSize is the typical payload size for most I2CP messages.
	// Payloads exceeding this threshold trigger warning logs.
	DefaultPayloadSize = 8192 // 8 KB

	// MessageReadTimeout is the maximum time allowed to read a complete message.
	// This prevents slow-send attacks where attackers claim large payloads
	// but drip-feed data slowly to exhaust connection resources.
	MessageReadTimeout = 30 // seconds
)

// Message represents a generic I2CP message
type Message struct {
	Type      uint8  // Message type
	SessionID uint16 // Session identifier
	Payload   []byte // Message payload
}

// MarshalBinary serializes the I2CP message to wire format
// Format: type(1) + sessionID(2) + length(4) + payload(variable)
func (m *Message) MarshalBinary() ([]byte, error) {
	if m.Payload == nil {
		m.Payload = []byte{}
	}

	// Validate payload size per I2CP specification
	payloadLen := len(m.Payload)
	if payloadLen > MaxPayloadSize {
		return nil, fmt.Errorf("i2cp message payload too large: %d bytes (max %d bytes per I2CP spec)", payloadLen, MaxPayloadSize)
	}

	// Calculate total message size
	totalLen := 1 + 2 + 4 + payloadLen

	result := make([]byte, totalLen)

	// Type (1 byte)
	result[0] = m.Type

	// Session ID (2 bytes, big endian)
	binary.BigEndian.PutUint16(result[1:3], m.SessionID)

	// Payload length (4 bytes, big endian)
	binary.BigEndian.PutUint32(result[3:7], uint32(payloadLen))

	// Payload
	if payloadLen > 0 {
		copy(result[7:], m.Payload)
	}

	return result, nil
}

// UnmarshalBinary deserializes an I2CP message from wire format
func (m *Message) UnmarshalBinary(data []byte) error {
	if len(data) < 7 {
		return fmt.Errorf("i2cp message too short: need at least 7 bytes, got %d", len(data))
	}

	// Parse type
	m.Type = data[0]

	// Parse session ID
	m.SessionID = binary.BigEndian.Uint16(data[1:3])

	// Parse payload length
	payloadLen := binary.BigEndian.Uint32(data[3:7])

	// Validate total length
	expectedTotal := 7 + payloadLen
	if uint32(len(data)) < expectedTotal {
		return fmt.Errorf("i2cp message truncated: expected %d bytes, got %d", expectedTotal, len(data))
	}

	// Extract payload
	if payloadLen > 0 {
		m.Payload = make([]byte, payloadLen)
		copy(m.Payload, data[7:7+payloadLen])
	} else {
		m.Payload = []byte{}
	}

	return nil
}

// ReadMessage reads a complete I2CP message from a reader
func ReadMessage(r io.Reader) (*Message, error) {
	connInfo := "unknown"
	if conn, ok := r.(net.Conn); ok {
		connInfo = conn.RemoteAddr().String()
	}

	setReaderDeadline(r)

	header, err := readMessageHeader(r)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":         "i2cp.ReadMessage",
			"remoteAddr": connInfo,
			"error":      err.Error(),
		}).Debug("failed_to_read_header")
		return nil, err
	}

	msgType, sessionID, payloadLen := parseMessageHeader(header)

	if err := validatePayloadSize(payloadLen); err != nil {
		// Enhanced logging for Issue #5: I2CP Payload Size Exceeded
		// i2psnark compatibility: Log full header details for debugging oversized payloads
		log.WithFields(logger.Fields{
			"at":         "i2cp.ReadMessage",
			"phase":      "i2cp_message_parsing",
			"remoteAddr": connInfo,
			"msgType":    MessageTypeName(msgType),
			"msgTypeID":  msgType,
			"sessionID":  sessionID,
			"payloadLen": payloadLen,
			"maxAllowed": MaxPayloadSize,
			"exceeded":   payloadLen - MaxPayloadSize,
			"headerHex":  fmt.Sprintf("%x", header),
			"reason":     "client sent message exceeding I2CP spec limit (256KB)",
			"impact":     "connection will be terminated to prevent DoS",
		}).Error("payload_size_exceeded_max - client may need reconfiguration")
		return nil, err
	}

	logLargePayload(payloadLen, msgType, sessionID)

	payload, err := readMessagePayload(r, payloadLen)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":         "i2cp.ReadMessage",
			"remoteAddr": connInfo,
			"msgType":    MessageTypeName(msgType),
			"sessionID":  sessionID,
			"payloadLen": payloadLen,
			"error":      err.Error(),
		}).Debug("failed_to_read_payload")
		return nil, err
	}

	log.WithFields(logger.Fields{
		"at":         "i2cp.ReadMessage",
		"remoteAddr": connInfo,
		"msgType":    MessageTypeName(msgType),
		"sessionID":  sessionID,
		"payloadLen": payloadLen,
	}).Debug("message_read_successfully")

	return &Message{
		Type:      msgType,
		SessionID: sessionID,
		Payload:   payload,
	}, nil
}

// setReaderDeadline sets a read deadline on the connection to prevent slow-send attacks.
// The deadline is only applied when the reader is a net.Conn.
func setReaderDeadline(r io.Reader) {
	conn, ok := r.(net.Conn)
	if !ok {
		return
	}

	deadline := time.Now().Add(MessageReadTimeout * time.Second)
	if err := conn.SetReadDeadline(deadline); err != nil {
		// Log but don't fail - deadline setting is defensive, not critical
		log.WithError(err).Debug("failed_to_set_read_deadline")
	}
}

// readMessageHeader reads the I2CP message header from the reader.
// Per I2CP spec: length(4 bytes) + type(1 byte) = 5 bytes total header.
// The session ID is NOT part of the common header - it's in the message body for messages that use it.
func readMessageHeader(r io.Reader) ([]byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("failed to read I2CP header: %w", err)
	}
	return header, nil
}

// parseMessageHeader extracts the payload length and message type from the header bytes.
// Per I2CP spec: header is length(4) + type(1), NOT type + sessionID + length.
func parseMessageHeader(header []byte) (msgType uint8, sessionID uint16, payloadLen uint32) {
	// Correct I2CP wire format: length(4 bytes big-endian) + type(1 byte)
	payloadLen = binary.BigEndian.Uint32(header[0:4])
	msgType = header[4]
	sessionID = 0 // Session ID is NOT in the header, it's in the message body

	// i2psnark compatibility: Debug log all message headers to identify patterns
	// Log at debug level for normal messages, but include size category for analysis
	sizeCategory := "small"
	if payloadLen > DefaultPayloadSize && payloadLen <= 65535 {
		sizeCategory = "medium"
	} else if payloadLen > 65535 && payloadLen <= MaxPayloadSize {
		sizeCategory = "large"
	} else if payloadLen > MaxPayloadSize {
		sizeCategory = "oversized"
	}

	log.WithFields(logger.Fields{
		"at":           "i2cp.parseMessageHeader",
		"msgType":      MessageTypeName(msgType),
		"msgTypeID":    msgType,
		"sessionID":    sessionID,
		"payloadLen":   payloadLen,
		"sizeCategory": sizeCategory,
		"headerHex":    fmt.Sprintf("%x", header),
	}).Debug("parsed_message_header")

	return
}

// validatePayloadSize checks if the payload length exceeds the maximum allowed size per I2CP specification.
func validatePayloadSize(payloadLen uint32) error {
	if payloadLen > MaxPayloadSize {
		return fmt.Errorf("i2cp message payload too large: %d bytes (max %d bytes per I2CP spec)", payloadLen, MaxPayloadSize)
	}
	return nil
}

// logLargePayload logs a warning when the payload size exceeds the default threshold,
// which may indicate an attack or misconfiguration.
func logLargePayload(payloadLen uint32, msgType uint8, sessionID uint16) {
	if payloadLen <= DefaultPayloadSize {
		return
	}

	log.WithFields(map[string]interface{}{
		"at":          "i2cp.ReadMessage",
		"payloadLen":  payloadLen,
		"msgType":     MessageTypeName(msgType),
		"msgTypeID":   msgType,
		"sessionID":   sessionID,
		"threshold":   DefaultPayloadSize,
		"percentOver": fmt.Sprintf("%.1f%%", float64(payloadLen-DefaultPayloadSize)/float64(DefaultPayloadSize)*100),
	}).Warn("large_i2cp_payload")
}

// readMessagePayload reads the message payload from the reader based on the specified length.
func readMessagePayload(r io.Reader, payloadLen uint32) ([]byte, error) {
	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, fmt.Errorf("failed to read I2CP payload: %w", err)
		}
	}
	return payload, nil
}

// WriteMessage writes a complete I2CP message to a writer
func WriteMessage(w io.Writer, msg *Message) error {
	connInfo := "unknown"
	if conn, ok := w.(net.Conn); ok {
		connInfo = conn.RemoteAddr().String()
	}

	log.WithFields(logger.Fields{
		"at":          "i2cp.WriteMessage",
		"remoteAddr":  connInfo,
		"msgType":     MessageTypeName(msg.Type),
		"sessionID":   msg.SessionID,
		"payloadSize": len(msg.Payload),
	}).Debug("writing_message")

	data, err := msg.MarshalBinary()
	if err != nil {
		log.WithFields(logger.Fields{
			"at":    "i2cp.WriteMessage",
			"error": err.Error(),
		}).Error("failed_to_marshal_message")
		return fmt.Errorf("failed to marshal I2CP message: %w", err)
	}

	if _, err := w.Write(data); err != nil {
		log.WithFields(logger.Fields{
			"at":         "i2cp.WriteMessage",
			"remoteAddr": connInfo,
			"msgType":    MessageTypeName(msg.Type),
			"error":      err.Error(),
		}).Error("failed_to_write_message_data")
		return fmt.Errorf("failed to write I2CP message: %w", err)
	}

	log.WithFields(logger.Fields{
		"at":         "i2cp.WriteMessage",
		"remoteAddr": connInfo,
		"msgType":    MessageTypeName(msg.Type),
		"totalBytes": len(data),
	}).Debug("message_written_successfully")

	return nil
}

// MessageTypeName returns a human-readable name for the message type
func MessageTypeName(msgType uint8) string {
	switch msgType {
	case MessageTypeCreateSession:
		return "CreateSession"
	case MessageTypeSessionStatus:
		return "SessionStatus"
	case MessageTypeReconfigureSession:
		return "ReconfigureSession"
	case MessageTypeDestroySession:
		return "DestroySession"
	case MessageTypeCreateLeaseSet:
		return "CreateLeaseSet"
	case MessageTypeRequestLeaseSet:
		return "RequestLeaseSet"
	case MessageTypeRequestVariableLeaseSet:
		return "RequestVariableLeaseSet"
	case MessageTypeCreateLeaseSet2:
		return "CreateLeaseSet2"
	case MessageTypeSendMessage:
		return "SendMessage"
	case MessageTypeMessagePayload:
		return "MessagePayload"
	case MessageTypeMessageStatus:
		return "MessageStatus"
	case MessageTypeDisconnect:
		return "Disconnect"
	case MessageTypeSendMessageExpires:
		return "SendMessageExpires"
	case MessageTypeGetBandwidthLimits:
		return "GetBandwidthLimits"
	case MessageTypeBandwidthLimits:
		return "BandwidthLimits"
	case MessageTypeGetDate:
		return "GetDate"
	case MessageTypeSetDate:
		return "SetDate"
	case MessageTypeHostLookup:
		return "HostLookup"
	case MessageTypeHostReply:
		return "HostReply"
	case MessageTypeBlindingInfo:
		return "BlindingInfo"
	case MessageTypeHostLookupDeprecated:
		return "HostLookup (deprecated)"
	case MessageTypeHostReplyDeprecated:
		return "HostReply (deprecated)"
	default:
		return fmt.Sprintf("Unknown(%d)", msgType)
	}
}
