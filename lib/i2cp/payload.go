package i2cp

import (
	"encoding/binary"
	"fmt"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/logger"
)

// SendMessagePayload represents the payload structure of a SendMessage (type 7) message.
// This structure follows the I2CP v0.9.67 specification for client-to-router message delivery.
//
// Format:
//
//	SessionID: uint16 (already in Message header)
//	Destination: Hash (32 bytes) - SHA256 hash of target destination
//	Payload: []byte (variable length) - actual message data to send
//
// The router will wrap this payload in garlic encryption and route it through
// the outbound tunnel pool to the specified destination.
//
// IMPORTANT: Per I2CP wire format, the total payload size is limited to MaxPayloadSize
// (currently 256 KB for i2psnark compatibility). Client applications like i2psnark may
// send payloads larger than the original 64 KB limit. Applications requiring larger
// messages should fragment them at the application layer, though i2psnark file transfers
// can use the full 256 KB limit.
type SendMessagePayload struct {
	Destination data.Hash // 32-byte SHA256 hash of target destination
	Payload     []byte    // Message data to send (variable length, max 256 KB)
}

// ParseSendMessagePayload deserializes a SendMessage payload from wire format.
// Returns an error if the payload is too short or malformed.
//
// Wire format:
//
//	bytes 0-31:  Destination hash (32 bytes)
//	bytes 32+:   Message payload (variable length)
func ParseSendMessagePayload(data []byte) (*SendMessagePayload, error) {
	// Minimum size: 32 bytes for destination hash
	// Payload can be empty (0 bytes), so minimum is exactly 32
	if len(data) < 32 {
		log.WithFields(logger.Fields{
			"at":       "i2cp.ParseSendMessagePayload",
			"dataSize": len(data),
			"required": 32,
		}).Error("send_message_payload_too_short")
		return nil, fmt.Errorf("send message payload too short: need at least 32 bytes for destination, got %d", len(data))
	}

	smp := &SendMessagePayload{}

	// Parse destination hash (first 32 bytes)
	copy(smp.Destination[:], data[0:32])

	// Parse message payload (remaining bytes)
	payloadLen := len(data) - 32
	if payloadLen > 0 {
		smp.Payload = make([]byte, payloadLen)
		copy(smp.Payload, data[32:])
	} else {
		smp.Payload = []byte{}
	}

	log.WithFields(logger.Fields{
		"at":          "i2cp.ParseSendMessagePayload",
		"destination": fmt.Sprintf("%x", smp.Destination[:8]),
		"payloadSize": payloadLen,
	}).Debug("parsed_send_message_payload")

	return smp, nil
}

// MarshalBinary serializes the SendMessagePayload to wire format.
// Returns the serialized bytes ready to be sent as an I2CP message payload.
func (smp *SendMessagePayload) MarshalBinary() ([]byte, error) {
	// Calculate total size: 32 (destination) + len(payload)
	totalSize := 32 + len(smp.Payload)
	result := make([]byte, totalSize)

	// Write destination hash
	copy(result[0:32], smp.Destination[:])

	// Write payload
	if len(smp.Payload) > 0 {
		copy(result[32:], smp.Payload)
	}

	log.WithFields(logger.Fields{
		"at":          "i2cp.SendMessagePayload.MarshalBinary",
		"destination": fmt.Sprintf("%x", smp.Destination[:8]),
		"payloadSize": len(smp.Payload),
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
//	bytes 6+:    Message payload (variable length)
func ParseMessagePayloadPayload(data []byte) (*MessagePayloadPayload, error) {
	// Minimum size: 2 bytes SessionID + 4 bytes MessageID = 6 bytes
	// Payload can be empty (0 bytes), so minimum is exactly 6
	if len(data) < 6 {
		log.WithFields(logger.Fields{
			"at":       "i2cp.ParseMessagePayloadPayload",
			"dataSize": len(data),
			"required": 6,
		}).Error("message_payload_too_short")
		return nil, fmt.Errorf("message payload too short: need at least 6 bytes (SessionID + MessageID), got %d", len(data))
	}

	mpp := &MessagePayloadPayload{}

	// Parse session ID (first 2 bytes, big endian)
	mpp.SessionID = binary.BigEndian.Uint16(data[0:2])

	// Parse message ID (next 4 bytes, big endian)
	mpp.MessageID = binary.BigEndian.Uint32(data[2:6])

	// Parse message payload (remaining bytes)
	payloadLen := len(data) - 6
	if payloadLen > 0 {
		mpp.Payload = make([]byte, payloadLen)
		copy(mpp.Payload, data[6:])
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
	// Calculate total size: 2 (session ID) + 4 (message ID) + len(payload)
	totalSize := 6 + len(mpp.Payload)
	result := make([]byte, totalSize)

	// Write session ID (big endian)
	binary.BigEndian.PutUint16(result[0:2], mpp.SessionID)

	// Write message ID (big endian)
	binary.BigEndian.PutUint32(result[2:6], mpp.MessageID)

	// Write payload
	if len(mpp.Payload) > 0 {
		copy(result[6:], mpp.Payload)
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
//	Destination: Hash (32 bytes) - SHA256 hash of target destination
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
	Destination data.Hash // 32-byte SHA256 hash of target destination
	Payload     []byte    // Message data to send (variable length, max 256 KB)
	Nonce       uint32    // Random nonce for message identification
	Flags       uint16    // Delivery flags (reserved, set to 0)
	Expiration  uint64    // Expiration time in milliseconds since epoch (48-bit)
}

// ParseSendMessageExpiresPayload deserializes a SendMessageExpires payload from wire format.
// Returns an error if the payload is too short or malformed.
//
// Wire format:
//
//	bytes 0-31:      Destination hash (32 bytes)
//	bytes 32-(N-13): Message payload (variable length)
//	bytes (N-12)-(N-9): Nonce (4 bytes, big endian)
//	bytes (N-8)-(N-7):  Flags (2 bytes, big endian)
//	bytes (N-6)-(N-1):  Expiration (6 bytes, big endian, 48-bit timestamp)
//
// Where N is the total payload size.
func ParseSendMessageExpiresPayload(data []byte) (*SendMessageExpiresPayload, error) {
	// Minimum size: 32 (destination) + 0 (payload) + 4 (nonce) + 2 (flags) + 6 (expiration) = 44 bytes
	minSize := 32 + 4 + 2 + 6 // 44 bytes
	if len(data) < minSize {
		log.WithFields(logger.Fields{
			"at":       "i2cp.ParseSendMessageExpiresPayload",
			"dataSize": len(data),
			"required": minSize,
		}).Error("send_message_expires_payload_too_short")
		return nil, fmt.Errorf("send message expires payload too short: need at least %d bytes, got %d", minSize, len(data))
	}

	smp := &SendMessageExpiresPayload{}

	// Parse destination hash (first 32 bytes)
	copy(smp.Destination[:], data[0:32])

	// Parse message payload (variable middle section)
	// The fixed fields (nonce, flags, expiration) are at the end
	payloadLen := len(data) - 32 - 12 // total - destination - (nonce+flags+expiration)
	if payloadLen > 0 {
		smp.Payload = make([]byte, payloadLen)
		copy(smp.Payload, data[32:32+payloadLen])
	} else {
		smp.Payload = []byte{}
	}

	// Parse fixed fields at the end
	offset := 32 + payloadLen
	smp.Nonce = binary.BigEndian.Uint32(data[offset : offset+4])
	smp.Flags = binary.BigEndian.Uint16(data[offset+4 : offset+6])

	// Parse 48-bit expiration (6 bytes) into uint64
	// Read 6 bytes and shift into 64-bit value
	expBytes := data[offset+6 : offset+12]
	smp.Expiration = uint64(expBytes[0])<<40 |
		uint64(expBytes[1])<<32 |
		uint64(expBytes[2])<<24 |
		uint64(expBytes[3])<<16 |
		uint64(expBytes[4])<<8 |
		uint64(expBytes[5])

	log.WithFields(logger.Fields{
		"at":          "i2cp.ParseSendMessageExpiresPayload",
		"destination": fmt.Sprintf("%x", smp.Destination[:8]),
		"payloadSize": payloadLen,
		"nonce":       smp.Nonce,
		"flags":       smp.Flags,
		"expiration":  smp.Expiration,
	}).Debug("parsed_send_message_expires_payload")

	return smp, nil
}

// MarshalBinary serializes the SendMessageExpiresPayload to wire format.
// Returns the serialized bytes ready to be sent as an I2CP message payload.
func (smp *SendMessageExpiresPayload) MarshalBinary() ([]byte, error) {
	// Calculate total size: 32 (destination) + len(payload) + 4 (nonce) + 2 (flags) + 6 (expiration)
	totalSize := 32 + len(smp.Payload) + 12
	result := make([]byte, totalSize)

	// Write destination hash
	copy(result[0:32], smp.Destination[:])

	// Write payload
	offset := 32
	if len(smp.Payload) > 0 {
		copy(result[offset:], smp.Payload)
		offset += len(smp.Payload)
	}

	// Write nonce (4 bytes, big endian)
	binary.BigEndian.PutUint32(result[offset:offset+4], smp.Nonce)

	// Write flags (2 bytes, big endian)
	binary.BigEndian.PutUint16(result[offset+4:offset+6], smp.Flags)

	// Write expiration (6 bytes, big endian, 48-bit)
	result[offset+6] = byte(smp.Expiration >> 40)
	result[offset+7] = byte(smp.Expiration >> 32)
	result[offset+8] = byte(smp.Expiration >> 24)
	result[offset+9] = byte(smp.Expiration >> 16)
	result[offset+10] = byte(smp.Expiration >> 8)
	result[offset+11] = byte(smp.Expiration)

	log.WithFields(logger.Fields{
		"at":          "i2cp.SendMessageExpiresPayload.MarshalBinary",
		"destination": fmt.Sprintf("%x", smp.Destination[:8]),
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
		return nil, fmt.Errorf("disconnect payload too short: need at least 2 bytes for length, got %d", len(data))
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
		return nil, fmt.Errorf("disconnect payload incomplete: need %d bytes for reason, got %d", 2+int(reasonLen), len(data))
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
	RequestID  uint32 // Unique request identifier
	LookupType uint16 // 0=hash, 1=hostname
	Query      string // Hash or hostname to lookup
}

const (
	HostLookupTypeHash     = 0 // Lookup by destination hash
	HostLookupTypeHostname = 1 // Lookup by hostname
)

// ParseHostLookupPayload deserializes a HostLookup payload from wire format.
// Returns an error if the payload is too short or malformed.
//
// Wire format:
//
//	bytes 0-3:   RequestID (uint32, big endian)
//	bytes 4-5:   LookupType (uint16, big endian)
//	bytes 6-7:   Query length (uint16, big endian)
//	bytes 8+:    Query string (length specified by bytes 6-7)
func ParseHostLookupPayload(data []byte) (*HostLookupPayload, error) {
	// Minimum size: 4 (requestID) + 2 (type) + 2 (length) = 8 bytes
	if len(data) < 8 {
		log.WithFields(logger.Fields{
			"at":       "i2cp.ParseHostLookupPayload",
			"dataSize": len(data),
			"required": 8,
		}).Error("host_lookup_payload_too_short")
		return nil, fmt.Errorf("host lookup payload too short: need at least 8 bytes, got %d", len(data))
	}

	hlp := &HostLookupPayload{}

	// Parse request ID (first 4 bytes, big endian)
	hlp.RequestID = binary.BigEndian.Uint32(data[0:4])

	// Parse lookup type (bytes 4-5, big endian)
	hlp.LookupType = binary.BigEndian.Uint16(data[4:6])

	// Parse query length (bytes 6-7, big endian)
	queryLen := binary.BigEndian.Uint16(data[6:8])

	// Validate we have enough bytes for the query string
	if len(data) < 8+int(queryLen) {
		log.WithFields(logger.Fields{
			"at":          "i2cp.ParseHostLookupPayload",
			"dataSize":    len(data),
			"queryLen":    queryLen,
			"requiredLen": 8 + int(queryLen),
		}).Error("host_lookup_payload_incomplete")
		return nil, fmt.Errorf("host lookup payload incomplete: need %d bytes for query, got %d", 8+int(queryLen), len(data))
	}

	// Parse query string
	if queryLen > 0 {
		hlp.Query = string(data[8 : 8+queryLen])
	} else {
		hlp.Query = ""
	}

	log.WithFields(logger.Fields{
		"at":         "i2cp.ParseHostLookupPayload",
		"requestID":  hlp.RequestID,
		"lookupType": hlp.LookupType,
		"queryLen":   queryLen,
		"query":      hlp.Query,
	}).Debug("parsed_host_lookup_payload")

	return hlp, nil
}

// MarshalBinary serializes the HostLookupPayload to wire format.
// Returns the serialized bytes ready to be sent as an I2CP message payload.
func (hlp *HostLookupPayload) MarshalBinary() ([]byte, error) {
	queryBytes := []byte(hlp.Query)
	totalSize := 4 + 2 + 2 + len(queryBytes) // requestID + type + length + query
	result := make([]byte, totalSize)

	// Write request ID (big endian)
	binary.BigEndian.PutUint32(result[0:4], hlp.RequestID)

	// Write lookup type (big endian)
	binary.BigEndian.PutUint16(result[4:6], hlp.LookupType)

	// Write query length (big endian)
	binary.BigEndian.PutUint16(result[6:8], uint16(len(queryBytes)))

	// Write query string
	if len(queryBytes) > 0 {
		copy(result[8:], queryBytes)
	}

	log.WithFields(logger.Fields{
		"at":         "i2cp.HostLookupPayload.MarshalBinary",
		"requestID":  hlp.RequestID,
		"lookupType": hlp.LookupType,
		"queryLen":   len(queryBytes),
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
	RequestID   uint32 // Matches RequestID from HostLookup
	ResultCode  uint8  // 0=success, non-zero=error
	Destination []byte // Full destination (empty if error)
}

const (
	HostReplySuccess  = 0 // Destination found
	HostReplyNotFound = 1 // Destination not found
	HostReplyTimeout  = 2 // Lookup timed out
	HostReplyError    = 3 // Generic error
)

// ParseHostReplyPayload deserializes a HostReply payload from wire format.
// Returns an error if the payload is too short or malformed.
//
// Wire format:
//
//	bytes 0-3:   RequestID (uint32, big endian)
//	byte 4:      ResultCode (uint8)
//	bytes 5+:    Destination (optional, only if ResultCode=0)
func ParseHostReplyPayload(data []byte) (*HostReplyPayload, error) {
	// Minimum size: 4 (requestID) + 1 (resultCode) = 5 bytes
	if len(data) < 5 {
		log.WithFields(logger.Fields{
			"at":       "i2cp.ParseHostReplyPayload",
			"dataSize": len(data),
			"required": 5,
		}).Error("host_reply_payload_too_short")
		return nil, fmt.Errorf("host reply payload too short: need at least 5 bytes, got %d", len(data))
	}

	hrp := &HostReplyPayload{}

	// Parse request ID (first 4 bytes, big endian)
	hrp.RequestID = binary.BigEndian.Uint32(data[0:4])

	// Parse result code (byte 4)
	hrp.ResultCode = data[4]

	// Parse destination (remaining bytes, if any)
	if len(data) > 5 {
		hrp.Destination = make([]byte, len(data)-5)
		copy(hrp.Destination, data[5:])
	}

	log.WithFields(logger.Fields{
		"at":         "i2cp.ParseHostReplyPayload",
		"requestID":  hrp.RequestID,
		"resultCode": hrp.ResultCode,
		"destSize":   len(hrp.Destination),
	}).Debug("parsed_host_reply_payload")

	return hrp, nil
}

// MarshalBinary serializes the HostReplyPayload to wire format.
// Returns the serialized bytes ready to be sent as an I2CP message payload.
func (hrp *HostReplyPayload) MarshalBinary() ([]byte, error) {
	totalSize := 4 + 1 + len(hrp.Destination) // requestID + resultCode + destination
	result := make([]byte, totalSize)

	// Write request ID (big endian)
	binary.BigEndian.PutUint32(result[0:4], hrp.RequestID)

	// Write result code
	result[4] = hrp.ResultCode

	// Write destination (if present)
	if len(hrp.Destination) > 0 {
		copy(result[5:], hrp.Destination)
	}

	log.WithFields(logger.Fields{
		"at":         "i2cp.HostReplyPayload.MarshalBinary",
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
		return nil, fmt.Errorf("BlindingInfo payload too short: need at least 1 byte, got %d", len(data))
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
			return nil, fmt.Errorf("BlindingInfo secret must be 32 bytes, got %d", len(data)-1)
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
			return nil, fmt.Errorf("BlindingInfo secret must be 32 bytes, got %d", len(bip.Secret))
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
