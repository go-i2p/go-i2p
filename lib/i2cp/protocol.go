// Package i2cp implements the I2P Client Protocol (I2CP) v0.9.67.
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
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Message type constants as defined in I2CP v0.9.67
const (
	// Session management - PER I2CP SPEC v0.9.67
	MessageTypeCreateSession      uint8 = 1  // Client -> Router: Create new session
	MessageTypeSessionStatus      uint8 = 20 // Router -> Client: Session creation result (SPEC: 20, was 2)
	MessageTypeReconfigureSession uint8 = 2  // Client -> Router: Update session config (SPEC: 2, was 3)
	MessageTypeDestroySession     uint8 = 3  // Client -> Router: Terminate session (SPEC: 3, was 4)

	// LeaseSet management
	MessageTypeCreateLeaseSet          uint8 = 4  // Client -> Router: Publish LeaseSet (SPEC: 4, was 5)
	MessageTypeRequestLeaseSet         uint8 = 21 // Router -> Client: Request LeaseSet update (SPEC: 21, was 6)
	MessageTypeRequestVariableLeaseSet uint8 = 37 // Router -> Client: Request LeaseSet (with lease data)
	MessageTypeCreateLeaseSet2         uint8 = 41 // Client -> Router: Publish LeaseSet2 (modern, v0.9.39+)

	// Message delivery
	MessageTypeSendMessage        uint8 = 5  // Client -> Router: Send message to destination (SPEC: 5, was 7)
	MessageTypeMessagePayload     uint8 = 31 // Router -> Client: Received message (SPEC: 31, was 8)
	MessageTypeMessageStatus      uint8 = 22 // Router -> Client: Message delivery status
	MessageTypeDisconnect         uint8 = 30 // Client -> Router: Graceful disconnect
	MessageTypeSendMessageExpires uint8 = 36 // Client -> Router: Send message with TTL

	// Status and information
	MessageTypeGetBandwidthLimits uint8 = 8  // Client -> Router: Query bandwidth (SPEC: 8, was 9)
	MessageTypeBandwidthLimits    uint8 = 23 // Router -> Client: Bandwidth limits response (SPEC: 23, was 10)
	MessageTypeGetDate            uint8 = 32 // Client -> Router: Query router time (SPEC: 32, was 11)
	MessageTypeSetDate            uint8 = 33 // Router -> Client: Current router time (SPEC: 33, was 12)

	// Naming service (modern types)
	//
	// Only the HostLookup/HostReply pair is implemented. Its predecessors,
	// DestLookup (34) and DestReply (35), are not: the spec designates the newer
	// pair as preferred ("HostLookupMessage_ is preferred as of release 0.9.11",
	// i2cp.rst:754) and notes the older pair "do not contain Session IDs"
	// (i2cp.rst:212-213), so a client speaking 34/35 gets an unsupported-message
	// response rather than a lookup.
	//
	// Worth stating precisely because it is easy to get wrong: the message-type
	// registry (i2cp.rst:457-481) tags types 4, 6, 7, 21 and 29 "deprecated" and
	// gives 34/35 only a "Since" value (0.7). 34/35 are therefore legacy and
	// superseded, NOT deprecated, and there is no "must implement" sentence for
	// them either — which is why this gap is minor rather than a violation.
	MessageTypeHostLookup uint8 = 38 // Client -> Router: Destination lookup by hash or hostname
	MessageTypeHostReply  uint8 = 39 // Router -> Client: Destination lookup result

	// Advanced features
	MessageTypeBlindingInfo uint8 = 42 // Client -> Router: Blinded destination parameters
)

// messageTypeNames maps message type constants to human-readable names.
var messageTypeNames = map[uint8]string{
	MessageTypeCreateSession:           "CreateSession",
	MessageTypeSessionStatus:           "SessionStatus",
	MessageTypeReconfigureSession:      "ReconfigureSession",
	MessageTypeDestroySession:          "DestroySession",
	MessageTypeCreateLeaseSet:          "CreateLeaseSet",
	MessageTypeRequestLeaseSet:         "RequestLeaseSet",
	MessageTypeRequestVariableLeaseSet: "RequestVariableLeaseSet",
	MessageTypeCreateLeaseSet2:         "CreateLeaseSet2",
	MessageTypeSendMessage:             "SendMessage",
	MessageTypeMessagePayload:          "MessagePayload",
	MessageTypeMessageStatus:           "MessageStatus",
	MessageTypeDisconnect:              "Disconnect",
	MessageTypeSendMessageExpires:      "SendMessageExpires",
	MessageTypeGetBandwidthLimits:      "GetBandwidthLimits",
	MessageTypeBandwidthLimits:         "BandwidthLimits",
	MessageTypeGetDate:                 "GetDate",
	MessageTypeSetDate:                 "SetDate",
	MessageTypeHostLookup:              "HostLookup",
	MessageTypeHostReply:               "HostReply",
	MessageTypeBlindingInfo:            "BlindingInfo",
}

// Reserved session IDs
const (
	SessionIDReservedControl   = 0x0000 // Control messages (pre-session)
	SessionIDReservedBroadcast = 0xFFFF // Broadcast to all sessions
)

// SessionStatus status codes per I2CP spec v0.9.67
const (
	SessionStatusDestroyed uint8 = 0 // Session has been destroyed
	SessionStatusCreated   uint8 = 1 // Session has been created successfully
	SessionStatusUpdated   uint8 = 2 // Session has been updated/reconfigured
	SessionStatusInvalid   uint8 = 3 // Session request was invalid
	SessionStatusRefused   uint8 = 4 // Session request was refused
)

// Protocol version constants
const (
	ProtocolVersionMajor = 0
	ProtocolVersionMinor = 9
	ProtocolVersionPatch = 67
)

// Expected protocol version values for testing and validation.
// These constants define the expected I2CP API version that this implementation supports.
const (
	ExpectedProtocolVersionMajor = 0
	ExpectedProtocolVersionMinor = 9
	ExpectedProtocolVersionPatch = 67
)

// MessageStatus codes as defined in I2CP specification.
// These codes indicate the delivery status of messages sent via SendMessage.
const (
	// MessageStatusAccepted indicates the message was accepted for delivery.
	// Sent immediately when SendMessage is received.
	MessageStatusAccepted uint8 = 1

	// MessageStatusSuccess indicates the message was successfully delivered.
	// Sent after routing completes successfully.
	MessageStatusSuccess uint8 = 4

	// MessageStatusFailure indicates the message delivery failed.
	// Generic failure status.
	MessageStatusFailure uint8 = 5

	// MessageStatusNoTunnels indicates delivery failed due to no available tunnels.
	// Sent when the session has no outbound tunnels.
	MessageStatusNoTunnels uint8 = 16

	// MessageStatusNoLeaseSet indicates delivery failed due to missing LeaseSet.
	// Sent when the destination's LeaseSet cannot be found.
	MessageStatusNoLeaseSet uint8 = 21
)

// Protocol limits as per I2CP specification
const (
	// MaxPayloadSize is the maximum size for I2CP message payloads.
	// i2pd authoritative behavior limits I2CP message payloads to 65535 bytes
	// (I2CP_MAX_MESSAGE_LENGTH in i2pd/libi2pd_client/I2CP.h).
	MaxPayloadSize = 65535

	// MaxMessageSize is the maximum total I2CP message size including header.
	// Header per I2CP spec: length(4) + type(1) = 5 bytes
	MaxMessageSize = 5 + MaxPayloadSize

	// DefaultPayloadSize is the typical payload size for most I2CP messages.
	// Payloads exceeding this threshold trigger warning logs.
	DefaultPayloadSize = 8192 // 8 KB

	// MessageReadTimeout is the maximum time allowed to read the bytes of a
	// single I2CP message once its header has been read. This prevents
	// slow-send attacks where attackers claim large payloads but drip-feed
	// data slowly to exhaust connection resources.
	//
	// This bounds only the per-message byte read (header + payload), not the
	// idle gap between messages. The idle gap is bounded separately by
	// ServerConfig.ReadTimeout (see readClientMessage). A timeout while
	// waiting for a header is not an error — the connection stays open and
	// the deadline is re-armed. A timeout during body/flag/payload
	// continuation IS fatal.
	MessageReadTimeout = 30 // seconds
)

// errIdleTimeout is returned when the idle gap between messages exceeds the
// configured ReadTimeout. It is not a terminal error: the caller re-arms the
// deadline and continues reading rather than closing the connection.
// Distinguish from slow-send timeouts using errors.Is — never string comparison.
var errIdleTimeout = errors.New("i2cp idle read timeout")

// Message represents a generic I2CP message.
// Wire format per I2CP spec: length(4) + type(1) + payload(variable)
// SessionID is NOT in the wire format - it's managed at the connection/session layer.
type Message struct {
	Type      uint8  // Message type
	SessionID uint16 // Session identifier (application-level, not in wire format)
	Payload   []byte // Message payload
}

// MarshalBinary serializes the I2CP message to wire format.
// Format: length(4) + type(1) + payload(variable). The Session ID is not part
// of the wire framing (i2cp.rst); for message types that carry it, it is the
// first 2 bytes of the payload and is recovered by ReadMessage.
func (m *Message) MarshalBinary() ([]byte, error) {
	if m.Payload == nil {
		m.Payload = []byte{}
	}

	// Validate payload size per I2CP specification
	payloadLen := len(m.Payload)
	if err := validatePayloadSize(uint32(payloadLen)); err != nil {
		return nil, err
	}

	// Per I2CP spec: wire format is length(4) + type(1) + payload
	// Session ID is NOT in the wire format - it's handled at the message layer
	totalLen := messageHeaderSize + payloadLen

	result := make([]byte, totalLen)

	// Payload length (4 bytes, big endian)
	binary.BigEndian.PutUint32(result[0:messageLengthFieldSize], uint32(payloadLen))

	// Type (1 byte)
	result[messageLengthFieldSize] = m.Type

	// Payload
	if payloadLen > 0 {
		copy(result[messageHeaderSize:], m.Payload)
	}

	return result, nil
}

// UnmarshalBinary deserializes an I2CP message from wire format
// Per I2CP spec: wire format is length(4) + type(1) + payload
func (m *Message) UnmarshalBinary(data []byte) error {
	payloadLen, err := validateUnmarshalHeader(data)
	if err != nil {
		return err
	}

	// Parse type (1 byte)
	m.Type = data[messageLengthFieldSize]

	// Session ID is NOT in wire format - it must be set by the caller from context
	m.SessionID = 0

	// Extract payload
	if payloadLen > 0 {
		m.Payload = make([]byte, payloadLen)
		copy(m.Payload, data[messageHeaderSize:messageHeaderSize+payloadLen])
	} else {
		m.Payload = []byte{}
	}

	return nil
}

// validateUnmarshalHeader validates the fixed I2CP header of data and returns the
// declared payload length. It guards against short buffers, oversized payloads
// (unbounded allocation), and truncated buffers, using 64-bit arithmetic to avoid
// uint32 wraparound on the total-length check.
func validateUnmarshalHeader(data []byte) (uint32, error) {
	if len(data) < messageHeaderSize {
		return 0, oops.Errorf("i2cp message too short: need at least %d bytes for header, got %d", messageHeaderSize, len(data))
	}

	payloadLen := binary.BigEndian.Uint32(data[0:messageLengthFieldSize])
	if err := validatePayloadSize(payloadLen); err != nil {
		return 0, err
	}

	expectedTotal := uint64(payloadLen) + messageHeaderSize
	if uint64(len(data)) < expectedTotal {
		return 0, oops.Errorf("i2cp message truncated: expected %d bytes, got %d", expectedTotal, len(data))
	}

	return payloadLen, nil
}

// ReadMessage reads a complete I2CP message from a reader.
//
// Deadline semantics:
//   - The header read is NOT deadline-bounded: the idle gap between messages
//     is controlled by the caller via ServerConfig.ReadTimeout (applied in
//     readClientMessage). A timeout while waiting for a header is not an
//     error — the caller re-arms and continues.
//   - Once the header has been read, a per-message deadline of
//     payloadReadTimeout bounds the payload read. It is refreshed on each
//     body read so a client drip-feeding bytes is still cut off (the stated
//     anti-slow-send purpose), while the gap between messages is not bounded
//     by it.
//   - ctx, when non-nil, cancels a blocked header read so shutdown does not
//     have to wait out a deadline.
//
// A timeout while waiting for a header is NOT an error: re-arm and continue,
// do not close the connection, do not log at warn level per occurrence. A
// timeout during body/flag/payload continuation IS fatal.
func ReadMessage(ctx context.Context, r io.Reader, payloadReadTimeout time.Duration) (*Message, error) {
	connInfo := identifyConnection(r)

	// Read header WITHOUT per-message deadline - this bounds the idle gap
	// between messages. The caller (readClientMessage) sets the idle timeout
	// via ServerConfig.ReadTimeout. ctx cancellation aborts a blocked header
	// read so shutdown does not wait out a deadline.
	header, err := readMessageHeaderWithContext(ctx, r)
	if err != nil {
		logHeaderReadFailure(connInfo, err)
		return nil, err
	}

	msgType, sessionID, payloadLen := parseMessageHeader(header)

	if err := validatePayloadSize(payloadLen); err != nil {
		logPayloadSizeExceeded(connInfo, msgType, sessionID, payloadLen, header)
		return nil, err
	}

	logLargePayload(payloadLen, msgType, sessionID)

	// Set per-message deadline for payload read only, refreshing on each
	// body read so a drip-feeding client is still cut off.
	payload, err := readMessagePayload(r, payloadLen, payloadReadTimeout)
	if err != nil {
		logPayloadReadFailure(connInfo, msgType, sessionID, payloadLen, err)
		return nil, err
	}

	sessionID = extractSessionIDFromPayload(msgType, payload)

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

// readMessageHeaderWithContext reads the I2CP message header from the reader.
// Per I2CP spec: header is length(4) + type(1) = 5 bytes total.
//
// The header read is NOT deadline-bounded by MessageReadTimeout: the idle gap
// between messages is controlled separately by ServerConfig.ReadTimeout. ctx
// cancellation aborts a blocked header read so shutdown does not wait out a
// deadline. A timeout while waiting for a header is not an error — the caller
// re-arms and continues.
func readMessageHeaderWithContext(ctx context.Context, r io.Reader) ([]byte, error) {
	header := make([]byte, messageHeaderSize)

	// If ctx is already cancelled, fail fast without blocking.
	if ctx != nil {
		select {
		case <-ctx.Done():
			return nil, oops.Errorf("failed to read I2CP header: %w", ctx.Err())
		default:
		}
	}

	// Watch ctx in a goroutine that sets a past read deadline to unblock a
	// blocked header read when shutdown cancels the context. The goroutine
	// exits as soon as the read completes (done channel closes), so it does
	// not leak during normal operation.
	done := make(chan struct{})
	var readErr error
	var n int

	go func() {
		n, readErr = io.ReadFull(r, header)
		close(done)
	}()

	if ctx != nil {
		select {
		case <-done:
			// Read completed before ctx cancellation.
		case <-ctx.Done():
			// Unblock the blocked read by setting a past deadline.
			if conn, ok := r.(net.Conn); ok {
				_ = conn.SetReadDeadline(time.Now())
			}
			<-done // wait for the read goroutine to observe the deadline and exit
		}
	} else {
		<-done
	}

	if readErr != nil {
		return nil, oops.Errorf("failed to read I2CP header: %w", readErr)
	}
	if n != messageHeaderSize {
		return nil, oops.Errorf("i2cp message too short: need at least %d bytes for header, got %d", messageHeaderSize, n)
	}
	return header, nil
}

// setPayloadReadDeadline sets a read deadline on the connection for payload reads only.
// This prevents slow-send attacks where attackers claim large payloads
// but drip-feed data slowly to exhaust connection resources.
func setPayloadReadDeadline(r io.Reader, timeout time.Duration) error {
	conn, ok := r.(net.Conn)
	if !ok {
		return nil
	}

	deadline := time.Now().Add(timeout)
	if err := conn.SetReadDeadline(deadline); err != nil {
		// Log but don't fail - deadline setting is defensive, not critical
		log.WithError(err).Debug("failed_to_set_payload_read_deadline")
		return nil
	}

	return nil
}

// identifyConnection returns a human-readable identifier for the reader's remote address.
func identifyConnection(r io.Reader) string {
	if conn, ok := r.(net.Conn); ok {
		return conn.RemoteAddr().String()
	}
	return "unknown"
}

// logHeaderReadFailure logs a debug message when the I2CP header cannot be read.
func logHeaderReadFailure(connInfo string, err error) {
	log.WithFields(logger.Fields{
		"at":         "i2cp.ReadMessage",
		"remoteAddr": connInfo,
		"error":      err.Error(),
	}).Debug("failed_to_read_header")
}

// logPayloadSizeExceeded logs an error when the payload size exceeds the I2CP spec limit.
func logPayloadSizeExceeded(connInfo string, msgType uint8, sessionID uint16, payloadLen uint32, header []byte) {
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
}

// logPayloadReadFailure logs a debug message when the payload bytes cannot be read.
func logPayloadReadFailure(connInfo string, msgType uint8, sessionID uint16, payloadLen uint32, err error) {
	log.WithFields(logger.Fields{
		"at":         "i2cp.ReadMessage",
		"remoteAddr": connInfo,
		"msgType":    MessageTypeName(msgType),
		"sessionID":  sessionID,
		"payloadLen": payloadLen,
		"error":      err.Error(),
	}).Debug("failed_to_read_payload")
}

// extractSessionIDFromPayload extracts SessionID from message payload for message types that include it.
// Per I2CP spec: Some message types have SessionID as first 2 bytes of payload.
// Message types with SessionID in payload:
//   - SessionStatus (type 20): SessionID(2) + Status(1)
//   - MessageStatus (type 22): SessionID(2) + MessageID(4) + Status(1) + Size(4) + Nonce(4)
//   - MessagePayload (type 31): SessionID(2) + MessageID(4) + payload_data
//   - ReconfigureSession (type 2): SessionID(2) + config_data
//   - DestroySession (type 3): SessionID(2)
//   - SendMessage (type 5): SessionID(2) + message_data
//   - CreateLeaseSet (type 4): SessionID(2) + leaseset_data
//   - SendMessageExpires (type 36): SessionID(2) + message_data
//   - HostLookup (type 38): SessionID(2) + RequestID(4) + Timeout(4) + Type(1) + query
//     Per i2cp.rst, "The session ID and request ID will be returned in the
//     HostReplyMessage_", so the HostLookup Session ID must be carried through to
//     the reply rather than left at zero.
func extractSessionIDFromPayload(msgType uint8, payload []byte) uint16 {
	// Messages that include SessionID in payload
	switch msgType {
	case MessageTypeSessionStatus,
		MessageTypeMessageStatus,
		MessageTypeMessagePayload,
		MessageTypeReconfigureSession,
		MessageTypeDestroySession,
		MessageTypeSendMessage,
		MessageTypeCreateLeaseSet,
		MessageTypeCreateLeaseSet2,
		MessageTypeSendMessageExpires,
		MessageTypeBlindingInfo,
		MessageTypeHostLookup:
		if len(payload) >= sessionIDFieldSize {
			return binary.BigEndian.Uint16(payload[0:sessionIDFieldSize])
		}
	}
	// Messages without SessionID in payload (e.g., CreateSession, GetDate)
	return 0
}

// readMessageHeader reads the I2CP message header from the reader.
// Per I2CP spec: header is length(4) + type(1) = 5 bytes total.
func readMessageHeader(r io.Reader) ([]byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, oops.Errorf("failed to read I2CP header: %w", err)
	}
	return header, nil
}

// parseMessageHeader extracts the payload length and message type from the header bytes.
// Per I2CP spec: header is length(4) + type(1). Session ID is NOT in the header.
func parseMessageHeader(header []byte) (msgType uint8, sessionID uint16, payloadLen uint32) {
	// Correct I2CP wire format: length(4 bytes big-endian) + type(1 byte)
	payloadLen = binary.BigEndian.Uint32(header[0:messageLengthFieldSize])
	msgType = header[messageLengthFieldSize]
	sessionID = 0 // Session ID is NOT in the header

	// i2psnark compatibility: Log message type and category at debug level.
	// Excludes exact payloadLen and header hex to avoid traffic-correlation fingerprints
	// in debug logs. See anonymity-safe-logging policy.
	//
	// Two categories only: MaxPayloadSize is the spec ceiling, so a payload above
	// it is oversized and one at or below it is within the protocol. The previous
	// "large" tier tested `payloadLen > 65535 && payloadLen <= MaxPayloadSize`,
	// which is empty because MaxPayloadSize is 65535.
	sizeCategory := "small"
	if payloadLen > DefaultPayloadSize && payloadLen <= MaxPayloadSize {
		sizeCategory = "medium"
	} else if payloadLen > MaxPayloadSize {
		sizeCategory = "oversized"
	}

	log.WithFields(logger.Fields{
		"at":           "i2cp.parseMessageHeader",
		"msgType":      MessageTypeName(msgType),
		"msgTypeID":    msgType,
		"sessionID":    sessionID,
		"sizeCategory": sizeCategory,
	}).Debug("parsed_message_header")

	return msgType, sessionID, payloadLen
}

// validatePayloadSize checks if the payload length exceeds the maximum allowed size per I2CP specification.
func validatePayloadSize(payloadLen uint32) error {
	if payloadLen > MaxPayloadSize {
		return oops.Errorf("i2cp message payload too large: %d bytes (max %d bytes per I2CP spec)", payloadLen, MaxPayloadSize)
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
// Defense-in-depth: Validates payload size before allocation to prevent memory exhaustion attacks.
//
// The per-message deadline is refreshed on each body read so a client
// drip-feeding bytes is still cut off (the stated anti-slow-send purpose),
// while the gap between messages is not bounded by it.
func readMessagePayload(r io.Reader, payloadLen uint32, payloadReadTimeout time.Duration) ([]byte, error) {
	// Validate payload size before allocation (defense-in-depth)
	// Even though caller should validate, we check here to prevent misuse
	if err := validatePayloadSize(payloadLen); err != nil {
		return nil, err
	}

	// Safe to allocate after validation
	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		if err := readFullWithDeadlineRefresh(r, payload, payloadReadTimeout); err != nil {
			return nil, oops.Errorf("failed to read I2CP payload: %w", err)
		}
	}
	return payload, nil
}

// readFullWithDeadlineRefresh reads exactly len(buf) bytes from r, refreshing
// the read deadline on each underlying read so a drip-feeding client is still
// cut off by the per-message deadline. Returns io.ErrUnexpectedEOF or the
// underlying read error if the stream ends early or errors.
func readFullWithDeadlineRefresh(r io.Reader, buf []byte, payloadReadTimeout time.Duration) error {
	conn, hasDeadline := r.(net.Conn)
	total := 0
	for total < len(buf) {
		if hasDeadline && payloadReadTimeout > 0 {
			// Refresh the per-message deadline on each body read so a
			// drip-feeding client is still cut off.
			if err := conn.SetReadDeadline(time.Now().Add(payloadReadTimeout)); err != nil {
				log.WithError(err).Debug("failed_to_refresh_payload_read_deadline")
			}
		}
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			if err == io.EOF && total < len(buf) {
				return io.ErrUnexpectedEOF
			}
			return err
		}
	}
	return nil
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
		return oops.Errorf("failed to marshal I2CP message: %w", err)
	}

	if _, err := w.Write(data); err != nil {
		log.WithFields(logger.Fields{
			"at":         "i2cp.WriteMessage",
			"remoteAddr": connInfo,
			"msgType":    MessageTypeName(msg.Type),
			"error":      err.Error(),
		}).Error("failed_to_write_message_data")
		return oops.Errorf("failed to write I2CP message: %w", err)
	}

	log.WithFields(logger.Fields{
		"at":         "i2cp.WriteMessage",
		"remoteAddr": connInfo,
		"msgType":    MessageTypeName(msg.Type),
		"totalBytes": len(data),
	}).Debug("message_written_successfully")

	return nil
}

// MessageTypeName returns a human-readable name for the message type.
func MessageTypeName(msgType uint8) string {
	if name, ok := messageTypeNames[msgType]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(%d)", msgType)
}
