package i2cp

import (
	"encoding/binary"
	"encoding/hex"
	"math"

	commondata "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// SendMessagePayload represents the payload structure of a SendMessage (type 5) message.
// This structure follows the I2CP v0.9.67 specification for client-to-router message delivery.
//
// Format per I2CP spec:
//
//	Destination: full I2P Destination (variable length, typically ~387+ bytes)
//	PayloadLen: uint32 (4 bytes, big endian) - length of message payload
//	Payload: []byte (variable length, max 256 KB) - actual message data to send
//	Nonce: uint32 (4 bytes, big endian) - random nonce for delivery status correlation
//
// The router will wrap this payload in garlic encryption and route it through
// the outbound tunnel pool to the specified destination.
//
// IMPORTANT: Per I2CP wire format, the total payload size is limited to MaxPayloadSize
// (currently 256 KB for i2psnark compatibility). Client applications like i2psnark may
// send payloads larger than the original 64 KB limit.
type SendMessagePayload struct {
	Destination destination.Destination // Full I2P Destination of target
	Payload     []byte                  // Message data to send (variable length, max 256 KB)
	Nonce       uint32                  // Random nonce for message identification and status correlation
}

// ParseSendMessagePayload deserializes a SendMessage payload from wire format.
// Returns an error if the payload is too short or malformed.
//
// Wire format per I2CP spec:
//
//	bytes 0+:      Destination (variable length, typically ~387+ bytes)
//	bytes N:N+4:   Payload length (4 bytes, big endian)
//	bytes N+4+M:   Message payload (M bytes, as specified by PayloadLen)
//	bytes N+4+M+4: Nonce (4 bytes, big endian)
func ParseSendMessagePayload(rawData []byte) (*SendMessagePayload, error) {
	if len(rawData) < 4 {
		return nil, oops.Errorf("send message payload too short: need at least 4 bytes for destination+length, got %d", len(rawData))
	}

	// Parse destination (variable-length structure)
	dest, remaining, err := destination.ReadDestination(rawData)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":       "i2cp.ParseSendMessagePayload",
			"dataSize": len(rawData),
			"error":    err.Error(),
		}).Error("failed_to_parse_destination")
		return nil, oops.Errorf("failed to parse destination: %w", err)
	}

	// Need at least 4 (payload length) + 4 (nonce) bytes remaining
	if len(remaining) < 8 {
		return nil, oops.Errorf("send message payload too short after destination: need at least 8 bytes for length+nonce, got %d", len(remaining))
	}

	// Parse payload length (4 bytes, big endian)
	payloadLen := binary.BigEndian.Uint32(remaining[0:4])
	if err := validatePayloadSize(payloadLen); err != nil {
		return nil, err
	}

	// Verify enough data for payload + nonce
	if len(remaining) < 4+int(payloadLen)+4 {
		return nil, oops.Errorf("send message truncated: need %d bytes, got %d", 4+payloadLen+4, len(remaining))
	}

	// Extract payload
	payloadStart := 4
	payloadEnd := 4 + int(payloadLen)
	payload := make([]byte, payloadLen)
	copy(payload, remaining[payloadStart:payloadEnd])

	// Extract nonce (at offset 4 + payloadLen)
	nonce := binary.BigEndian.Uint32(remaining[payloadEnd : payloadEnd+4])

	smp := &SendMessagePayload{
		Destination: dest,
		Payload:     payload,
		Nonce:       nonce,
	}

	log.WithFields(logger.Fields{
		"at":          "i2cp.ParseSendMessagePayload",
		"payloadSize": len(payload),
		"nonce":       nonce,
	}).Debug("parsed_send_message_payload")

	return smp, nil
}

// MarshalBinary serializes the SendMessagePayload to wire format.
// Returns the serialized bytes ready to be sent as an I2CP message payload.
func (smp *SendMessagePayload) MarshalBinary() ([]byte, error) {
	// Serialize destination
	destBytes, err := smp.Destination.Bytes()
	if err != nil {
		return nil, oops.Errorf("failed to serialize destination: %w", err)
	}

	// Calculate total size: destBytes + 4 (length) + payloadLen + 4 (nonce)
	totalSize := len(destBytes) + 4 + len(smp.Payload) + 4
	result := make([]byte, totalSize)

	// Write destination
	copy(result[0:], destBytes)
	offset := len(destBytes)

	// Write payload length
	binary.BigEndian.PutUint32(result[offset:offset+4], uint32(len(smp.Payload)))
	offset += 4

	// Write payload
	if len(smp.Payload) > 0 {
		copy(result[offset:], smp.Payload)
		offset += len(smp.Payload)
	}

	// Write nonce
	binary.BigEndian.PutUint32(result[offset:offset+4], smp.Nonce)

	log.WithFields(logger.Fields{
		"at":          "i2cp.SendMessagePayload.MarshalBinary",
		"payloadSize": len(smp.Payload),
		"nonce":       smp.Nonce,
		"totalSize":   totalSize,
	}).Debug("marshaled_send_message_payload")

	return result, nil
}

// MessagePayloadPayload represents the payload structure of a MessagePayload (type 31) message.
// This structure follows the I2CP v0.9.67 specification for router-to-client message delivery.
//
// Format per I2CP spec:
//
//	SessionID: uint16 (2 bytes) - session identifier (part of wire format, not common header)
//	MessageID: uint32 (4 bytes) - unique identifier for this message
//	PayloadLen: uint32 (4 bytes, big endian) - length of decrypted message data
//	Payload: []byte (variable length) - decrypted message data
//
// The router sends this to the client after receiving and decrypting a message
// from the I2P network destined for the client's destination.
//
// IMPORTANT: Per I2CP wire format, the total payload size is limited to MaxPayloadSize
// (currently 256 KB for i2psnark compatibility). Messages larger than this limit cannot
// be delivered via I2CP and must be fragmented at the application layer by the sender.
type MessagePayloadPayload struct {
	SessionID uint16 // Session identifier (included in wire format)
	MessageID uint32 // Unique message identifier
	Payload   []byte // Decrypted message data (variable length, max 256 KB)
}

// ParseMessagePayloadPayload deserializes a MessagePayload payload from wire format.
// Returns an error if the payload is too short or malformed.
//
// Wire format per I2CP spec:
//
//	bytes 0-1:   SessionID (2 bytes, big endian)
//	bytes 2-5:   MessageID (4 bytes, big endian)
//	bytes 6-9:   Payload length (4 bytes, big endian)
//	bytes 10+:   Message payload (variable length)
func ParseMessagePayloadPayload(data []byte) (*MessagePayloadPayload, error) {
	// Minimum size: 2 (SessionID) + 4 (MessageID) + 4 (PayloadLen) = 10 bytes
	if len(data) < 10 {
		log.WithFields(logger.Fields{
			"at":       "i2cp.ParseMessagePayloadPayload",
			"dataSize": len(data),
			"required": 10,
		}).Error("message_payload_too_short")
		return nil, oops.Errorf("message payload too short: need at least 10 bytes (SessionID + MessageID + PayloadLen), got %d", len(data))
	}

	mpp := &MessagePayloadPayload{}

	// Parse session ID (first 2 bytes, big endian)
	mpp.SessionID = binary.BigEndian.Uint16(data[0:2])

	// Parse message ID (next 4 bytes, big endian)
	mpp.MessageID = binary.BigEndian.Uint32(data[2:6])

	// Parse payload length (next 4 bytes, big endian)
	payloadLen := binary.BigEndian.Uint32(data[6:10])
	if err := validatePayloadSize(payloadLen); err != nil {
		return nil, err
	}

	// Verify enough data for payload
	if len(data) < 10+int(payloadLen) {
		return nil, oops.Errorf("message payload truncated: need %d bytes total, got %d", 10+payloadLen, len(data))
	}

	// Extract payload
	if payloadLen > 0 {
		mpp.Payload = make([]byte, payloadLen)
		copy(mpp.Payload, data[10:10+payloadLen])
	} else {
		mpp.Payload = []byte{}
	}

	log.WithFields(logger.Fields{
		"at":          "i2cp.ParseMessagePayloadPayload",
		"sessionID":   mpp.SessionID,
		"messageID":   mpp.MessageID,
		"payloadSize": payloadLen,
	}).Debug("parsed_message_payload")

	return mpp, nil
}

// MarshalBinary serializes the MessagePayloadPayload to wire format.
// Returns the serialized bytes ready to be sent as an I2CP message payload.
func (mpp *MessagePayloadPayload) MarshalBinary() ([]byte, error) {
	// Calculate total size: 2 (session ID) + 4 (message ID) + 4 (payload length) + len(payload)
	totalSize := 10 + len(mpp.Payload)
	result := make([]byte, totalSize)

	// Write session ID (big endian)
	binary.BigEndian.PutUint16(result[0:2], mpp.SessionID)

	// Write message ID (big endian)
	binary.BigEndian.PutUint32(result[2:6], mpp.MessageID)

	// Write payload length (big endian)
	binary.BigEndian.PutUint32(result[6:10], uint32(len(mpp.Payload)))

	// Write payload
	if len(mpp.Payload) > 0 {
		copy(result[10:], mpp.Payload)
	}

	log.WithFields(logger.Fields{
		"at":          "i2cp.MessagePayloadPayload.MarshalBinary",
		"sessionID":   mpp.SessionID,
		"messageID":   mpp.MessageID,
		"payloadSize": len(mpp.Payload),
		"totalSize":   totalSize,
	}).Debug("marshaled_message_payload")

	return result, nil
}

// SendMessageExpiresPayload represents the payload structure of a SendMessageExpires (type 36) message.
// This is an enhanced version of SendMessage that includes expiration time and delivery flags.
//
// Format per I2CP v0.9.67 specification:
//
//	Destination: full I2P Destination (variable length, typically ~387+ bytes)
//	PayloadLen: uint32 (4 bytes, big endian) - length of message payload
//	Payload: []byte (variable length) - actual message data to send
//	Nonce: uint32 (4 bytes) - random nonce for message identification
//	Flags: uint16 (2 bytes) - delivery flags (currently unused, set to 0)
//	Expiration: uint64 (6 bytes) - expiration timestamp (milliseconds since epoch, only lower 48 bits used)
//
// The Expiration field is a 48-bit timestamp (6 bytes) representing milliseconds since Unix epoch.
// Messages that have passed their expiration time will not be sent and will receive a failure status.
//
// Flags field is reserved for future use (e.g., priority, encryption options).
// Currently should be set to 0.
type SendMessageExpiresPayload struct {
	Destination destination.Destination // Full I2P Destination of target
	Payload     []byte                  // Message data to send (variable length, max 256 KB)
	Nonce       uint32                  // Random nonce for message identification
	Flags       uint16                  // Delivery flags (reserved, set to 0)
	Expiration  uint64                  // Expiration time in milliseconds since epoch (48-bit)
}

// ParseSendMessageExpiresPayload deserializes a SendMessageExpires payload from wire format.
// Returns an error if the payload is too short or malformed.
//
// Wire format per I2CP spec:
//
//	bytes 0+:      Destination (variable length, typically ~387+ bytes)
//	bytes N:N+4:   Payload length (4 bytes, big endian)
//	bytes N+4+M:   Message payload (M bytes, as specified by PayloadLen)
//	bytes N+4+M+4: Nonce (4 bytes, big endian)
//	bytes N+4+M+8: Flags (2 bytes, big endian)
//	bytes N+4+M+10: Expiration (6 bytes, big endian, 48-bit timestamp)
func ParseSendMessageExpiresPayload(rawData []byte) (*SendMessageExpiresPayload, error) {
	if len(rawData) < 4 {
		return nil, oops.Errorf("send message expires payload too short: need at least 4 bytes for destination+length, got %d", len(rawData))
	}

	// Parse destination (variable-length structure)
	dest, remaining, err := destination.ReadDestination(rawData)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":       "i2cp.ParseSendMessageExpiresPayload",
			"dataSize": len(rawData),
			"error":    err.Error(),
		}).Error("failed_to_parse_destination")
		return nil, oops.Errorf("failed to parse destination: %w", err)
	}

	// Need at least 4 (payload length) + 4 (nonce) + 2 (flags) + 6 (expiration) = 16 bytes remaining
	if len(remaining) < 16 {
		return nil, oops.Errorf("send message expires payload too short after destination: need at least 16 bytes for length+nonce+flags+expiration, got %d", len(remaining))
	}

	// Parse payload length (4 bytes, big endian)
	payloadLen := binary.BigEndian.Uint32(remaining[0:4])
	if err := validatePayloadSize(payloadLen); err != nil {
		return nil, err
	}

	// Verify enough data for payload + nonce + flags + expiration
	if len(remaining) < 4+int(payloadLen)+12 {
		return nil, oops.Errorf("send message expires truncated: need %d bytes, got %d", 4+payloadLen+12, len(remaining))
	}

	// Extract payload
	payloadStart := 4
	payloadEnd := 4 + int(payloadLen)
	payload := make([]byte, payloadLen)
	copy(payload, remaining[payloadStart:payloadEnd])

	// Extract nonce, flags, and expiration from fixed fields after payload
	fixedStart := payloadEnd
	nonce := binary.BigEndian.Uint32(remaining[fixedStart : fixedStart+4])
	flags := binary.BigEndian.Uint16(remaining[fixedStart+4 : fixedStart+6])

	// Parse 48-bit expiration (6 bytes) into uint64
	expBytes := remaining[fixedStart+6 : fixedStart+12]
	expiration := uint64(expBytes[0])<<40 |
		uint64(expBytes[1])<<32 |
		uint64(expBytes[2])<<24 |
		uint64(expBytes[3])<<16 |
		uint64(expBytes[4])<<8 |
		uint64(expBytes[5])

	smp := &SendMessageExpiresPayload{
		Destination: dest,
		Payload:     payload,
		Nonce:       nonce,
		Flags:       flags,
		Expiration:  expiration,
	}

	log.WithFields(logger.Fields{
		"at":          "i2cp.ParseSendMessageExpiresPayload",
		"payloadSize": len(payload),
		"nonce":       nonce,
		"flags":       flags,
		"expiration":  expiration,
	}).Debug("parsed_send_message_expires_payload")

	return smp, nil
}

// MarshalBinary serializes the SendMessageExpiresPayload to wire format.
// Returns the serialized bytes ready to be sent as an I2CP message payload.
func (smp *SendMessageExpiresPayload) MarshalBinary() ([]byte, error) {
	// Serialize destination
	destBytes, err := smp.Destination.Bytes()
	if err != nil {
		return nil, oops.Errorf("failed to serialize destination: %w", err)
	}

	// Calculate total size: destBytes + 4 (length) + payloadLen + 4 (nonce) + 2 (flags) + 6 (expiration)
	totalSize := len(destBytes) + 4 + len(smp.Payload) + 12
	result := make([]byte, totalSize)

	// Write destination
	copy(result[0:], destBytes)
	offset := len(destBytes)

	// Write payload length
	binary.BigEndian.PutUint32(result[offset:offset+4], uint32(len(smp.Payload)))
	offset += 4

	// Write payload
	if len(smp.Payload) > 0 {
		copy(result[offset:], smp.Payload)
		offset += len(smp.Payload)
	}

	// Write nonce (4 bytes, big endian)
	binary.BigEndian.PutUint32(result[offset:offset+4], smp.Nonce)
	offset += 4

	// Write flags (2 bytes, big endian)
	binary.BigEndian.PutUint16(result[offset:offset+2], smp.Flags)
	offset += 2

	// Write expiration (6 bytes, big endian, 48-bit)
	result[offset] = byte(smp.Expiration >> 40)
	result[offset+1] = byte(smp.Expiration >> 32)
	result[offset+2] = byte(smp.Expiration >> 24)
	result[offset+3] = byte(smp.Expiration >> 16)
	result[offset+4] = byte(smp.Expiration >> 8)
	result[offset+5] = byte(smp.Expiration)

	log.WithFields(logger.Fields{
		"at":          "i2cp.SendMessageExpiresPayload.MarshalBinary",
		"payloadSize": len(smp.Payload),
		"nonce":       smp.Nonce,
		"flags":       smp.Flags,
		"expiration":  smp.Expiration,
		"totalSize":   totalSize,
	}).Debug("marshaled_send_message_expires_payload")

	return result, nil
}

// DisconnectPayload represents the payload structure of a Disconnect (type 30) message.
// This message allows graceful connection termination with a reason string.
//
// Format per I2CP v0.9.67 specification:
//
//	ReasonLength: uint16 (2 bytes) - length of reason string in bytes
//	Reason: string (variable length) - UTF-8 encoded disconnect reason
//
// Common disconnect reasons:
// - "client shutdown" - Normal client termination
// - "timeout" - Connection timeout
// - "protocol error" - Invalid message received
// - "version mismatch" - Incompatible protocol version
//
// The server should clean up all session resources and close the connection
// after receiving this message.
type DisconnectPayload struct {
	Reason string // UTF-8 disconnect reason string
}

// ParseDisconnectPayload deserializes a Disconnect payload from wire format.
// Returns an error if the payload is too short or malformed.
//
// Wire format:
//
//	bytes 0-1:  Reason length (uint16, big endian)
//	bytes 2+:   Reason string (UTF-8, length specified by bytes 0-1)
func ParseDisconnectPayload(data []byte) (*DisconnectPayload, error) {
	// Minimum size: 2 bytes for length field
	// Reason can be empty (0 bytes), so minimum is exactly 2
	if len(data) < 2 {
		log.WithFields(logger.Fields{
			"at":       "i2cp.ParseDisconnectPayload",
			"dataSize": len(data),
			"required": 2,
		}).Error("disconnect_payload_too_short")
		return nil, oops.Errorf("disconnect payload too short: need at least 2 bytes for length, got %d", len(data))
	}

	dp := &DisconnectPayload{}

	// Parse reason length (first 2 bytes, big endian)
	reasonLen := binary.BigEndian.Uint16(data[0:2])

	// Validate we have enough bytes for the reason string
	if len(data) < 2+int(reasonLen) {
		log.WithFields(logger.Fields{
			"at":          "i2cp.ParseDisconnectPayload",
			"dataSize":    len(data),
			"reasonLen":   reasonLen,
			"requiredLen": 2 + int(reasonLen),
		}).Error("disconnect_payload_incomplete")
		return nil, oops.Errorf("disconnect payload incomplete: need %d bytes for reason, got %d", 2+int(reasonLen), len(data))
	}

	// Parse reason string (UTF-8)
	if reasonLen > 0 {
		dp.Reason = string(data[2 : 2+reasonLen])
	} else {
		dp.Reason = ""
	}

	log.WithFields(logger.Fields{
		"at":        "i2cp.ParseDisconnectPayload",
		"reasonLen": reasonLen,
		"reason":    dp.Reason,
	}).Debug("parsed_disconnect_payload")

	return dp, nil
}

// MarshalBinary serializes the DisconnectPayload to wire format.
// Returns the serialized bytes ready to be sent as an I2CP message payload.
func (dp *DisconnectPayload) MarshalBinary() ([]byte, error) {
	// Calculate total size: 2 (length) + len(reason)
	reasonBytes := []byte(dp.Reason)
	if len(reasonBytes) > math.MaxUint16 {
		return nil, oops.Errorf("disconnect reason too long: %d bytes (max %d)", len(reasonBytes), math.MaxUint16)
	}
	totalSize := 2 + len(reasonBytes)
	result := make([]byte, totalSize)

	// Write reason length (big endian)
	binary.BigEndian.PutUint16(result[0:2], uint16(len(reasonBytes)))

	// Write reason string
	if len(reasonBytes) > 0 {
		copy(result[2:], reasonBytes)
	}

	log.WithFields(logger.Fields{
		"at":        "i2cp.DisconnectPayload.MarshalBinary",
		"reason":    dp.Reason,
		"reasonLen": len(reasonBytes),
		"totalSize": totalSize,
	}).Debug("marshaled_disconnect_payload")

	return result, nil
}

// HostLookupPayload represents the payload structure of a HostLookup (type 38) message.
// This message allows clients to query for destination information by hash or hostname.
//
// Format per I2CP v0.9.67 specification:
//
//	RequestID: uint32 (4 bytes) - unique request identifier for matching reply
//	LookupType: uint16 (2 bytes) - 0=hash lookup, 1=hostname lookup
//	QueryLength: uint16 (2 bytes) - length of query string in bytes
//	Query: string (variable length) - hash or hostname to lookup
//
// Lookup types:
// - 0: Hash lookup - Query is base32 destination hash
// - 1: Hostname lookup - Query is .i2p hostname
//
// The server will return a HostReply message with the same RequestID.
type HostLookupPayload struct {
	SessionID uint16 // Session ID (i2pd wire shape)
	RequestID uint32 // Unique request identifier
	TimeoutMs uint32 // Timeout in milliseconds (i2pd wire shape)

	LookupType uint16 // 0=hash, 1=hostname (encoded as one byte on wire)
	Query      string // Hash or hostname to lookup
	Hash       []byte // Raw 32-byte hash for hash lookups when provided on-wire
}

const (
	// HostLookupTypeHash requests a destination lookup by hash value.
	HostLookupTypeHash     uint16 = 0 // Lookup by destination hash
	HostLookupTypeHostname uint16 = 1 // Lookup by hostname
)

// ParseHostLookupPayload deserializes a HostLookup payload from wire format.
// Returns an error if the payload is too short or malformed.
//
// Wire format (i2pd authoritative shape):
//
//	bytes 0-1:   SessionID (uint16, big endian)
//	bytes 2-5:   RequestID (uint32, big endian)
//	bytes 6-9:   TimeoutMs (uint32, big endian)
//	byte  10:    LookupType (0=hash, 1=hostname)
//	bytes 11+:   Query payload (32-byte hash or I2PString hostname)
func ParseHostLookupPayload(data []byte) (*HostLookupPayload, error) {
	parsed, err := parseCanonicalHostLookupPayload(data)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":       "i2cp.ParseHostLookupPayload",
			"dataSize": len(data),
			"error":    err.Error(),
		}).Error("host_lookup_payload_parse_failed")
		return nil, err
	}
	return parsed, nil
}

func parseCanonicalHostLookupPayload(data []byte) (*HostLookupPayload, error) {
	if len(data) < 11 {
		return nil, oops.Errorf("host lookup payload too short: need at least 11 bytes for canonical format, got %d", len(data))
	}

	hlp := &HostLookupPayload{
		SessionID:  binary.BigEndian.Uint16(data[0:2]),
		RequestID:  binary.BigEndian.Uint32(data[2:6]),
		TimeoutMs:  binary.BigEndian.Uint32(data[6:10]),
		LookupType: uint16(data[10]),
	}

	body := data[11:]
	switch hlp.LookupType {
	case HostLookupTypeHash:
		if len(body) < 32 {
			return nil, oops.Errorf("host lookup hash payload too short: need 32 bytes, got %d", len(body))
		}
		hlp.Hash = make([]byte, 32)
		copy(hlp.Hash, body[:32])
		hlp.Query = hex.EncodeToString(hlp.Hash)
	case HostLookupTypeHostname:
		str, _, err := commondata.ReadI2PString(body)
		if err != nil {
			return nil, oops.Errorf("failed to parse host lookup hostname: %w", err)
		}
		hostname, err := str.Data()
		if err != nil {
			return nil, oops.Errorf("failed to decode host lookup hostname: %w", err)
		}
		hlp.Query = hostname
	default:
		return nil, oops.Errorf("unsupported host lookup type: %d", hlp.LookupType)
	}

	log.WithFields(logger.Fields{
		"at":         "i2cp.ParseHostLookupPayload",
		"sessionID":  hlp.SessionID,
		"timeoutMs":  hlp.TimeoutMs,
		"requestID":  hlp.RequestID,
		"lookupType": hlp.LookupType,
		"queryLen":   len(hlp.Query),
	}).Debug("parsed_host_lookup_payload")

	return hlp, nil
}

// MarshalBinary serializes the HostLookupPayload to wire format.
// Returns the serialized bytes ready to be sent as an I2CP message payload.
func (hlp *HostLookupPayload) MarshalBinary() ([]byte, error) {
	var body []byte
	switch hlp.LookupType {
	case HostLookupTypeHash:
		if len(hlp.Hash) == 32 {
			body = make([]byte, 32)
			copy(body, hlp.Hash)
		} else {
			hashHex := hlp.Query
			if len(hashHex) < 64 {
				return nil, oops.Errorf("host lookup hash query too short: need 64 hex chars, got %d", len(hashHex))
			}
			decoded, err := hex.DecodeString(hashHex[:64])
			if err != nil {
				return nil, oops.Errorf("invalid host lookup hash encoding: %w", err)
			}
			if len(decoded) != 32 {
				return nil, oops.Errorf("invalid host lookup hash size: %d", len(decoded))
			}
			body = decoded
		}
	case HostLookupTypeHostname:
		i2pStr, err := commondata.ToI2PString(hlp.Query)
		if err != nil {
			return nil, oops.Errorf("invalid host lookup hostname encoding: %w", err)
		}
		body = i2pStr
	default:
		return nil, oops.Errorf("unsupported host lookup type: %d", hlp.LookupType)
	}

	totalSize := 2 + 4 + 4 + 1 + len(body)
	result := make([]byte, totalSize)
	binary.BigEndian.PutUint16(result[0:2], hlp.SessionID)
	binary.BigEndian.PutUint32(result[2:6], hlp.RequestID)
	binary.BigEndian.PutUint32(result[6:10], hlp.TimeoutMs)
	result[10] = byte(hlp.LookupType)
	copy(result[11:], body)

	log.WithFields(logger.Fields{
		"at":         "i2cp.HostLookupPayload.MarshalBinary",
		"sessionID":  hlp.SessionID,
		"timeoutMs":  hlp.TimeoutMs,
		"requestID":  hlp.RequestID,
		"lookupType": hlp.LookupType,
		"queryLen":   len(hlp.Query),
		"query":      hlp.Query,
		"totalSize":  totalSize,
	}).Debug("marshaled_host_lookup_payload")

	return result, nil
}

// HostReplyPayload represents the payload structure of a HostReply (type 39) message.
// This is the server's response to a HostLookup request.
//
// Format per I2CP v0.9.67 specification:
//
//	RequestID: uint32 (4 bytes) - matches the RequestID from HostLookup
//	ResultCode: uint8 (1 byte) - 0=success, non-zero=error code
//	Destination: []byte (variable, 387+ bytes if found) - full destination (optional)
//
// Result codes:
// - 0: Success - destination found
// - 1: Not found - destination does not exist
// - 2: Timeout - lookup timed out
// - 3: Error - generic error during lookup
//
// If ResultCode is 0 (success), Destination contains the full destination structure.
// If ResultCode is non-zero, Destination is empty.
type HostReplyPayload struct {
	SessionID   uint16 // Session ID that served the lookup (i2pd wire shape)
	RequestID   uint32 // Matches RequestID from HostLookup
	ResultCode  uint8  // 0=success, non-zero=error
	Destination []byte // Full destination (empty if error)
}

const (
	// HostReplySuccess indicates that the requested destination was found.
	HostReplySuccess  uint8 = 0 // Destination found
	HostReplyNotFound uint8 = 1 // Destination not found
	HostReplyTimeout  uint8 = 2 // Lookup timed out
	HostReplyError    uint8 = 3 // Generic error
)

// ParseHostReplyPayload deserializes a HostReply payload from wire format.
// Returns an error if the payload is too short or malformed.
//
// Wire format:
//
//	bytes 0-1:   SessionID (uint16, big endian)
//	bytes 2-5:   RequestID (uint32, big endian)
//	byte 6:      ResultCode (uint8)
//	bytes 7+:    Destination (optional, only if ResultCode=0)
func ParseHostReplyPayload(data []byte) (*HostReplyPayload, error) {
	// Minimum size: 2 (sessionID) + 4 (requestID) + 1 (resultCode) = 7 bytes
	if len(data) < 7 {
		log.WithFields(logger.Fields{
			"at":       "i2cp.ParseHostReplyPayload",
			"dataSize": len(data),
			"required": 7,
		}).Error("host_reply_payload_too_short")
		return nil, oops.Errorf("host reply payload too short: need at least 7 bytes, got %d", len(data))
	}

	hrp := &HostReplyPayload{}

	// Parse session ID (first 2 bytes, big endian)
	hrp.SessionID = binary.BigEndian.Uint16(data[0:2])

	// Parse request ID (next 4 bytes, big endian)
	hrp.RequestID = binary.BigEndian.Uint32(data[2:6])

	// Parse result code (byte 6)
	hrp.ResultCode = data[6]

	// Parse destination (remaining bytes, if any)
	if len(data) > 7 {
		hrp.Destination = make([]byte, len(data)-7)
		copy(hrp.Destination, data[7:])
	}

	log.WithFields(logger.Fields{
		"at":         "i2cp.ParseHostReplyPayload",
		"sessionID":  hrp.SessionID,
		"requestID":  hrp.RequestID,
		"resultCode": hrp.ResultCode,
		"destSize":   len(hrp.Destination),
	}).Debug("parsed_host_reply_payload")

	return hrp, nil
}

// MarshalBinary serializes the HostReplyPayload to wire format.
// Returns the serialized bytes ready to be sent as an I2CP message payload.
func (hrp *HostReplyPayload) MarshalBinary() ([]byte, error) {
	totalSize := 2 + 4 + 1 + len(hrp.Destination) // sessionID + requestID + resultCode + destination
	result := make([]byte, totalSize)

	// Write session ID (big endian)
	binary.BigEndian.PutUint16(result[0:2], hrp.SessionID)

	// Write request ID (big endian)
	binary.BigEndian.PutUint32(result[2:6], hrp.RequestID)

	// Write result code
	result[6] = hrp.ResultCode

	// Write destination (if present)
	if len(hrp.Destination) > 0 {
		copy(result[7:], hrp.Destination)
	}

	log.WithFields(logger.Fields{
		"at":         "i2cp.HostReplyPayload.MarshalBinary",
		"sessionID":  hrp.SessionID,
		"requestID":  hrp.RequestID,
		"resultCode": hrp.ResultCode,
		"destSize":   len(hrp.Destination),
		"totalSize":  totalSize,
	}).Debug("marshaled_host_reply_payload")

	return result, nil
}

// BlindingInfoPayload represents the payload structure of a BlindingInfo (type 42) message.
// This message allows clients to configure destination blinding parameters.
//
// Wire format:
//
//	1 byte:  Blinding enabled flag (0x00 = disabled, 0x01 = enabled)
//	N bytes: Blinding secret (optional, 32 bytes if provided; 0 bytes to use random)
//
// If enabled flag is 0x00, no secret is expected and blinding will be disabled.
// If enabled flag is 0x01 and no secret follows, a random secret will be generated.
// If enabled flag is 0x01 and 32 bytes follow, that secret will be used.
type BlindingInfoPayload struct {
	Enabled bool   // Whether destination blinding is enabled
	Secret  []byte // Blinding secret (nil = generate random, empty = disabled)
}

// ParseBlindingInfoPayload deserializes a BlindingInfo payload from wire format.
// Minimum size: 1 byte (enabled flag)
// Maximum size: 33 bytes (flag + 32-byte secret)
func ParseBlindingInfoPayload(data []byte) (*BlindingInfoPayload, error) {
	if len(data) < 1 {
		log.WithFields(logger.Fields{
			"at":       "i2cp.ParseBlindingInfoPayload",
			"dataSize": len(data),
		}).Error("payload_too_short")
		return nil, oops.Errorf("BlindingInfo payload too short: need at least 1 byte, got %d", len(data))
	}

	bip := &BlindingInfoPayload{}
	bip.Enabled = data[0] != 0x00

	// If enabled and secret provided, extract it
	if bip.Enabled && len(data) > 1 {
		if len(data) != 33 {
			log.WithFields(logger.Fields{
				"at":       "i2cp.ParseBlindingInfoPayload",
				"dataSize": len(data),
			}).Error("invalid_secret_length")
			return nil, oops.Errorf("BlindingInfo secret must be 32 bytes, got %d", len(data)-1)
		}
		bip.Secret = make([]byte, 32)
		copy(bip.Secret, data[1:33])
	}

	log.WithFields(logger.Fields{
		"at":        "i2cp.ParseBlindingInfoPayload",
		"enabled":   bip.Enabled,
		"hasSecret": len(bip.Secret) > 0,
		"dataSize":  len(data),
	}).Debug("parsed_blinding_info_payload")

	return bip, nil
}

// MarshalBinary serializes the BlindingInfoPayload to wire format.
func (bip *BlindingInfoPayload) MarshalBinary() ([]byte, error) {
	var result []byte

	// Enabled flag
	if bip.Enabled {
		result = append(result, 0x01)
	} else {
		result = append(result, 0x00)
	}

	// Secret (if provided and enabled)
	if bip.Enabled && len(bip.Secret) > 0 {
		if len(bip.Secret) != 32 {
			return nil, oops.Errorf("BlindingInfo secret must be 32 bytes, got %d", len(bip.Secret))
		}
		result = append(result, bip.Secret...)
	}

	log.WithFields(logger.Fields{
		"at":        "i2cp.BlindingInfoPayload.MarshalBinary",
		"enabled":   bip.Enabled,
		"hasSecret": len(bip.Secret) > 0,
		"totalSize": len(result),
	}).Debug("marshaled_blinding_info_payload")

	return result, nil
}
