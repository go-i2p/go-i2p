package i2cp

import (
	"encoding/binary"
	"encoding/hex"

	commondata "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/key_certificate"
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
	if len(rawData) < payloadLengthFieldSize {
		return nil, oops.Errorf("send message payload too short: need at least %d bytes for destination+length, got %d", payloadLengthFieldSize, len(rawData))
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

	// Need at least payload length + nonce bytes remaining
	if len(remaining) < sendMessageMinTrailingSize {
		return nil, oops.Errorf("send message payload too short after destination: need at least %d bytes for length+nonce, got %d", sendMessageMinTrailingSize, len(remaining))
	}

	// Parse payload length (4 bytes, big endian)
	payloadLen := binary.BigEndian.Uint32(remaining[0:payloadLengthFieldSize])
	if err := validatePayloadSize(payloadLen); err != nil {
		return nil, err
	}

	// Verify enough data for payload + nonce
	if len(remaining) < payloadLengthFieldSize+int(payloadLen)+nonceFieldSize {
		return nil, oops.Errorf("send message truncated: need %d bytes, got %d", payloadLengthFieldSize+payloadLen+nonceFieldSize, len(remaining))
	}

	// Extract payload
	payloadStart := payloadLengthFieldSize
	payloadEnd := payloadLengthFieldSize + int(payloadLen)
	payload := make([]byte, payloadLen)
	copy(payload, remaining[payloadStart:payloadEnd])

	// Extract nonce (at offset 4 + payloadLen)
	nonce := binary.BigEndian.Uint32(remaining[payloadEnd : payloadEnd+nonceFieldSize])

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

	// Calculate total size: destBytes + length + payloadLen + nonce
	totalSize := len(destBytes) + payloadLengthFieldSize + len(smp.Payload) + nonceFieldSize
	result := make([]byte, totalSize)

	// Write destination
	copy(result[0:], destBytes)
	offset := len(destBytes)

	// Write payload length
	binary.BigEndian.PutUint32(result[offset:offset+payloadLengthFieldSize], uint32(len(smp.Payload)))
	offset += payloadLengthFieldSize

	// Write payload
	if len(smp.Payload) > 0 {
		copy(result[offset:], smp.Payload)
		offset += len(smp.Payload)
	}

	// Write nonce
	binary.BigEndian.PutUint32(result[offset:offset+nonceFieldSize], smp.Nonce)

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
	// Minimum size: SessionID + MessageID + PayloadLen
	if len(data) < messagePayloadHeaderSize {
		log.WithFields(logger.Fields{
			"at":       "i2cp.ParseMessagePayloadPayload",
			"dataSize": len(data),
			"required": messagePayloadHeaderSize,
		}).Error("message_payload_too_short")
		return nil, oops.Errorf("message payload too short: need at least %d bytes (SessionID + MessageID + PayloadLen), got %d", messagePayloadHeaderSize, len(data))
	}

	mpp := &MessagePayloadPayload{}

	// Parse session ID (first 2 bytes, big endian)
	mpp.SessionID = binary.BigEndian.Uint16(data[0:sessionIDFieldSize])

	// Parse message ID (next 4 bytes, big endian)
	mpp.MessageID = binary.BigEndian.Uint32(data[sessionIDFieldSize : sessionIDFieldSize+messageIDFieldSize])

	// Parse payload length (next 4 bytes, big endian)
	payloadLenOffset := sessionIDFieldSize + messageIDFieldSize
	payloadLen := binary.BigEndian.Uint32(data[payloadLenOffset : payloadLenOffset+payloadLengthFieldSize])
	if err := validatePayloadSize(payloadLen); err != nil {
		return nil, err
	}

	// Verify enough data for payload
	if len(data) < messagePayloadHeaderSize+int(payloadLen) {
		return nil, oops.Errorf("message payload truncated: need %d bytes total, got %d", messagePayloadHeaderSize+payloadLen, len(data))
	}

	// Extract payload
	if payloadLen > 0 {
		mpp.Payload = make([]byte, payloadLen)
		copy(mpp.Payload, data[messagePayloadHeaderSize:messagePayloadHeaderSize+int(payloadLen)])
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
	// Calculate total size: session ID + message ID + payload length + payload
	totalSize := messagePayloadHeaderSize + len(mpp.Payload)
	result := make([]byte, totalSize)

	// Write session ID (big endian)
	binary.BigEndian.PutUint16(result[0:sessionIDFieldSize], mpp.SessionID)

	// Write message ID (big endian)
	binary.BigEndian.PutUint32(result[sessionIDFieldSize:sessionIDFieldSize+messageIDFieldSize], mpp.MessageID)

	// Write payload length (big endian)
	payloadLenOffset := sessionIDFieldSize + messageIDFieldSize
	binary.BigEndian.PutUint32(result[payloadLenOffset:payloadLenOffset+payloadLengthFieldSize], uint32(len(mpp.Payload)))

	// Write payload
	if len(mpp.Payload) > 0 {
		copy(result[messagePayloadHeaderSize:], mpp.Payload)
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
	if len(rawData) < payloadLengthFieldSize {
		return nil, oops.Errorf("send message expires payload too short: need at least %d bytes for destination+length, got %d", payloadLengthFieldSize, len(rawData))
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

	// Need at least length + nonce + flags + expiration bytes remaining
	if len(remaining) < sendMessageExpiresMinTrailingSize {
		return nil, oops.Errorf("send message expires payload too short after destination: need at least %d bytes for length+nonce+flags+expiration, got %d", sendMessageExpiresMinTrailingSize, len(remaining))
	}

	// Parse payload length (4 bytes, big endian)
	payloadLen := binary.BigEndian.Uint32(remaining[0:payloadLengthFieldSize])
	if err := validatePayloadSize(payloadLen); err != nil {
		return nil, err
	}

	// Verify enough data for payload + nonce + flags + expiration
	if len(remaining) < payloadLengthFieldSize+int(payloadLen)+nonceFieldSize+flagsFieldSize+expirationFieldSize {
		return nil, oops.Errorf("send message expires truncated: need %d bytes, got %d", payloadLengthFieldSize+payloadLen+nonceFieldSize+flagsFieldSize+expirationFieldSize, len(remaining))
	}

	// Extract payload
	payloadStart := payloadLengthFieldSize
	payloadEnd := payloadLengthFieldSize + int(payloadLen)
	payload := make([]byte, payloadLen)
	copy(payload, remaining[payloadStart:payloadEnd])

	// Extract nonce, flags, and expiration from fixed fields after payload
	fixedStart := payloadEnd
	nonce := binary.BigEndian.Uint32(remaining[fixedStart : fixedStart+nonceFieldSize])
	flags := binary.BigEndian.Uint16(remaining[fixedStart+nonceFieldSize : fixedStart+nonceFieldSize+flagsFieldSize])

	// Parse 48-bit expiration into uint64
	expBytes := remaining[fixedStart+nonceFieldSize+flagsFieldSize : fixedStart+nonceFieldSize+flagsFieldSize+expirationFieldSize]
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

	// Calculate total size: destBytes + length + payloadLen + nonce + flags + expiration
	totalSize := len(destBytes) + payloadLengthFieldSize + len(smp.Payload) +
		nonceFieldSize + flagsFieldSize + expirationFieldSize
	result := make([]byte, totalSize)

	// Write destination
	copy(result[0:], destBytes)
	offset := len(destBytes)

	// Write payload length
	binary.BigEndian.PutUint32(result[offset:offset+payloadLengthFieldSize], uint32(len(smp.Payload)))
	offset += payloadLengthFieldSize

	// Write payload
	if len(smp.Payload) > 0 {
		copy(result[offset:], smp.Payload)
		offset += len(smp.Payload)
	}

	// Write nonce (4 bytes, big endian)
	binary.BigEndian.PutUint32(result[offset:offset+nonceFieldSize], smp.Nonce)
	offset += nonceFieldSize

	// Write flags (2 bytes, big endian)
	binary.BigEndian.PutUint16(result[offset:offset+flagsFieldSize], smp.Flags)
	offset += flagsFieldSize

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
// Wire format (I2P [String], per common-structures.rst):
//
//	byte 0:     Reason length (0-255)
//	bytes 1+:   Reason string (UTF-8, length specified by byte 0)
func ParseDisconnectPayload(data []byte) (*DisconnectPayload, error) {
	// Minimum size: 1 byte for the String length prefix.
	// Reason can be empty (0 bytes), so minimum is exactly 1.
	if len(data) < 1 {
		log.WithFields(logger.Fields{
			"at":       "i2cp.ParseDisconnectPayload",
			"dataSize": len(data),
			"required": 1,
		}).Error("disconnect_payload_too_short")
		return nil, oops.Errorf("disconnect payload too short: need at least 1 byte for length, got %d", len(data))
	}

	dp := &DisconnectPayload{}

	// The reason is an I2P [String]: the first byte is the number of bytes in
	// the string (common-structures.rst), not a 2-byte big-endian length.
	str, _, err := commondata.ReadI2PString(data)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":       "i2cp.ParseDisconnectPayload",
			"dataSize": len(data),
			"error":    err.Error(),
		}).Error("disconnect_payload_invalid_string")
		return nil, oops.Wrapf(err, "invalid disconnect reason string")
	}
	// A zero-length String is valid on the wire (the spec allows 0-255 bytes);
	// I2PString.Data() returns ("", nil) for that case.
	reason, err := str.Data()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to decode disconnect reason")
	}
	dp.Reason = reason

	log.WithFields(logger.Fields{
		"at":        "i2cp.ParseDisconnectPayload",
		"reasonLen": len(dp.Reason),
		"reason":    dp.Reason,
	}).Debug("parsed_disconnect_payload")

	return dp, nil
}

// MarshalBinary serializes the DisconnectPayload to wire format.
// Returns the serialized bytes ready to be sent as an I2CP message payload.
// The reason is an I2P [String] (1-byte length prefix, 0-255 bytes) per
// common-structures.rst, so encoding is delegated to common/data.NewI2PString,
// which enforces the 255-byte limit.
func (dp *DisconnectPayload) MarshalBinary() ([]byte, error) {
	str, err := commondata.NewI2PString(dp.Reason)
	if err != nil {
		return nil, oops.Wrapf(err, "disconnect reason cannot be encoded as I2P String")
	}

	result := make([]byte, len(str))
	copy(result, str)

	log.WithFields(logger.Fields{
		"at":        "i2cp.DisconnectPayload.MarshalBinary",
		"reason":    dp.Reason,
		"reasonLen": len(dp.Reason),
		"totalSize": len(result),
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
// - 2: Hash lookup, also return the LeaseSet options (0.9.66+)
// - 3: Hostname lookup, also return the LeaseSet options (0.9.66+)
// - 4: Destination lookup, also return the LeaseSet options (0.9.66+)
//
// The server will return a HostReply message with the same RequestID.
type HostLookupPayload struct {
	SessionID uint16 // Session ID (i2pd wire shape)
	RequestID uint32 // Unique request identifier
	TimeoutMs uint32 // Timeout in milliseconds (i2pd wire shape)

	// LookupType is encoded as one byte on the wire.
	LookupType uint16
	Query      string // Hash (hex) or hostname to lookup
	Hash       []byte // Raw 32-byte hash for hash and destination lookups
	// Destination holds the raw Destination for lookup type 4. The router
	// resolves it by hashing, so Hash is populated from it during parse.
	Destination []byte
}

// Lookup types per i2cp.rst "HostLookupMessage". Types 2-4 (0.9.66+, proposal
// 167) request the same keys as 0/1 but additionally require the router to fetch
// the LeaseSet and return its options Mapping; a router that does not implement
// them must reply with code 7 rather than dropping the connection.
const (
	// HostLookupTypeHash requests a destination lookup by hash value.
	HostLookupTypeHash uint16 = 0
	// HostLookupTypeHostname requests a lookup by hostname String.
	HostLookupTypeHostname uint16 = 1
	// HostLookupTypeHashWithOptions looks up by Hash and returns the LeaseSet
	// options Mapping (0.9.66+).
	HostLookupTypeHashWithOptions uint16 = 2
	// HostLookupTypeHostnameWithOptions looks up by hostname String and returns
	// the LeaseSet options Mapping (0.9.66+).
	HostLookupTypeHostnameWithOptions uint16 = 3
	// HostLookupTypeDestination looks up by full Destination and returns the
	// LeaseSet options Mapping (0.9.66+).
	HostLookupTypeDestination uint16 = 4
)

// lookupTypeRequestsOptions reports whether the type asks for the LeaseSet
// options Mapping to be returned (proposal 167 types 2-4).
func lookupTypeRequestsOptions(t uint16) bool {
	return t == HostLookupTypeHashWithOptions ||
		t == HostLookupTypeHostnameWithOptions ||
		t == HostLookupTypeDestination
}

// lookupTypeIsHashKeyed reports whether the lookup resolves to a destination
// hash: types 0 and 2 carry a hash directly, and type 4 carries a Destination
// whose hash is computed at parse time.
func lookupTypeIsHashKeyed(t uint16) bool {
	return t == HostLookupTypeHash ||
		t == HostLookupTypeHashWithOptions ||
		t == HostLookupTypeDestination
}

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
	if len(data) < hostLookupHeaderSize {
		return nil, oops.Errorf("host lookup payload too short: need at least %d bytes for canonical format, got %d", hostLookupHeaderSize, len(data))
	}

	requestIDOffset := sessionIDFieldSize
	timeoutOffset := requestIDOffset + requestIDFieldSize
	lookupTypeOffset := timeoutOffset + timeoutMSFieldSize

	hlp := &HostLookupPayload{
		SessionID:  binary.BigEndian.Uint16(data[0:requestIDOffset]),
		RequestID:  binary.BigEndian.Uint32(data[requestIDOffset:timeoutOffset]),
		TimeoutMs:  binary.BigEndian.Uint32(data[timeoutOffset:lookupTypeOffset]),
		LookupType: uint16(data[lookupTypeOffset]),
	}

	body := data[hostLookupHeaderSize:]
	switch hlp.LookupType {
	case HostLookupTypeHash, HostLookupTypeHashWithOptions:
		if len(body) < hashSize {
			return nil, oops.Errorf("host lookup hash payload too short: need %d bytes, got %d", hashSize, len(body))
		}
		hlp.Hash = make([]byte, hashSize)
		copy(hlp.Hash, body[:hashSize])
		hlp.Query = hex.EncodeToString(hlp.Hash)
	case HostLookupTypeHostname, HostLookupTypeHostnameWithOptions:
		str, _, err := commondata.ReadI2PString(body)
		if err != nil {
			return nil, oops.Errorf("failed to parse host lookup hostname: %w", err)
		}
		hostname, err := str.Data()
		if err != nil {
			return nil, oops.Errorf("failed to decode host lookup hostname: %w", err)
		}
		hlp.Query = hostname
	case HostLookupTypeDestination:
		// Item 5 is a full Destination. Keep the bytes for the caller and set
		// Query to its hash in hex so the existing hash path can serve it.
		dest, _, err := destination.ReadDestination(body)
		if err != nil {
			return nil, oops.Errorf("failed to parse host lookup destination: %w", err)
		}
		destBytes, err := dest.Bytes()
		if err != nil {
			return nil, oops.Errorf("failed to re-serialize host lookup destination: %w", err)
		}
		hlp.Destination = destBytes
		hash, err := dest.Hash()
		if err != nil {
			return nil, oops.Errorf("failed to hash host lookup destination: %w", err)
		}
		hlp.Hash = hash[:]
		hlp.Query = hex.EncodeToString(hlp.Hash)
	default:
		// An unknown lookup type must be answered with result code 7, not
		// rejected: a parse error propagates out of the message handler and the
		// connection loop closes the socket, which would disconnect any client
		// that tries a lookup type newer than this router. Keep the header so
		// the dispatcher can reply with the request ID the client is waiting on;
		// the query body is left unparsed because its shape is unknown.
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
	case HostLookupTypeHash, HostLookupTypeHashWithOptions:
		if len(hlp.Hash) == hashSize {
			body = make([]byte, hashSize)
			copy(body, hlp.Hash)
		} else {
			hashHex := hlp.Query
			if len(hashHex) < hashHexLen {
				return nil, oops.Errorf("host lookup hash query too short: need %d hex chars, got %d", hashHexLen, len(hashHex))
			}
			decoded, err := hex.DecodeString(hashHex[:hashHexLen])
			if err != nil {
				return nil, oops.Errorf("invalid host lookup hash encoding: %w", err)
			}
			if len(decoded) != hashSize {
				return nil, oops.Errorf("invalid host lookup hash size: %d", len(decoded))
			}
			body = decoded
		}
	case HostLookupTypeHostname, HostLookupTypeHostnameWithOptions:
		i2pStr, err := commondata.ToI2PString(hlp.Query)
		if err != nil {
			return nil, oops.Errorf("invalid host lookup hostname encoding: %w", err)
		}
		body = i2pStr
	case HostLookupTypeDestination:
		if len(hlp.Destination) == 0 {
			return nil, oops.Errorf("host lookup type 4 requires a Destination")
		}
		body = hlp.Destination
	default:
		return nil, oops.Errorf("unsupported host lookup type: %d", hlp.LookupType)
	}

	totalSize := hostLookupHeaderSize + len(body)
	result := make([]byte, totalSize)
	offset := 0
	binary.BigEndian.PutUint16(result[offset:offset+sessionIDFieldSize], hlp.SessionID)
	offset += sessionIDFieldSize
	binary.BigEndian.PutUint32(result[offset:offset+requestIDFieldSize], hlp.RequestID)
	offset += requestIDFieldSize
	binary.BigEndian.PutUint32(result[offset:offset+timeoutMSFieldSize], hlp.TimeoutMs)
	offset += timeoutMSFieldSize
	result[offset] = byte(hlp.LookupType)
	offset++
	copy(result[offset:], body)

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
// Result codes are defined by i2cp.rst ("HostReplyMessage"); see
// HostReplySuccess and friends below. Codes 2-5 exist for "b33" (blinded)
// lookups as of 0.9.43 and codes 6-7 for the proposal 167 lookup types as of
// 0.9.66; a client uses 2/3/4 to learn it must supply a lookup password and/or
// a client private key before the record can be decrypted.
//
// If ResultCode is 0 (success), Destination contains the full destination structure.
// If ResultCode is non-zero, Destination is empty.
type HostReplyPayload struct {
	SessionID   uint16 // Session ID that served the lookup (i2pd wire shape)
	RequestID   uint32 // Matches RequestID from HostLookup
	ResultCode  uint8  // 0=success, non-zero=error
	Destination []byte // Full destination (empty if error)
	// Options is the LeaseSet options Mapping, spec item 5: present only on
	// success and only for lookup types 2-4, and an empty Mapping (two zero
	// bytes) when the LeaseSet carries no options or is a version 1 LeaseSet.
	Options []byte
}

// splitHostReplyTail divides the bytes after the result code into a Destination
// and the options Mapping that follows it (spec items 4 and 5). The Destination
// is parsed structurally rather than by assuming a length, so the split is exact
// for every key type. A tail that does not parse as Destination || Mapping is
// returned as-is with no options, which keeps replies from older routers (and
// replies that carry no Mapping) readable instead of failing the whole message.
func splitHostReplyTail(tail []byte) (dest, options []byte) {
	if len(tail) == 0 {
		return nil, nil
	}

	_, remainder, err := destination.ReadDestination(tail)
	if err != nil || len(remainder) > len(tail) {
		return tail, nil
	}
	destLen := len(tail) - len(remainder)

	// A Destination with nothing after it is a complete reply for lookup types
	// 0 and 1; there is no Mapping to split off.
	if len(remainder) == 0 {
		return tail[:destLen], nil
	}

	if _, _, err := commondata.ReadMapping(remainder); err != nil {
		// Trailing bytes are not a Mapping: treat the whole tail as opaque so
		// the destination still reaches the client.
		return tail, nil
	}

	return tail[:destLen], remainder
}

// HostReply result codes, per i2cp.rst "HostReplyMessage" contents item 3.
// The spec defines exactly one generic-failure code (1); 2-7 each carry a
// specific meaning a client acts on, so they must not be used as catch-alls.
const (
	// HostReplySuccess indicates that the requested destination was found.
	HostReplySuccess uint8 = 0 // Destination found
	// HostReplyFailure is the generic failure code ("1 indicates a generic
	// failure"). Also covers "not found" -- the spec defines no separate code
	// for it, so a lookup with no result must not use the blinded-lookup codes.
	HostReplyFailure uint8 = 1
	// HostReplyNotFound is an alias for HostReplyFailure, kept for readability at
	// "no such destination" call sites. The spec defines exactly one generic
	// failure code (1); codes 2-7 each carry a specific meaning.
	HostReplyNotFound = HostReplyFailure
	// HostReplyPasswordRequired means the record needs a lookup password the
	// client did not supply (0.9.43+, "b33" blinded lookups).
	HostReplyPasswordRequired uint8 = 2
	// HostReplyPrivateKeyRequired means the record needs a client private key
	// the client did not supply (0.9.43+, per-client authorized EncryptedLeaseSet).
	HostReplyPrivateKeyRequired uint8 = 3
	// HostReplyPasswordAndKeyRequired means both are needed (0.9.43+).
	HostReplyPasswordAndKeyRequired uint8 = 4
	// HostReplyDecryptionFailure means the record was found but could not be
	// decrypted -- typically a wrong password or private key (0.9.43+).
	HostReplyDecryptionFailure uint8 = 5
	// HostReplyLeaseSetLookupFailure means the destination was found but its
	// LeaseSet could not be retrieved (0.9.66+, proposal 167 lookup types 2-4).
	HostReplyLeaseSetLookupFailure uint8 = 6
	// HostReplyLookupTypeUnsupported means the router does not implement the
	// requested lookup type (0.9.66+).
	HostReplyLookupTypeUnsupported uint8 = 7
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
	// Minimum size: sessionID + requestID + resultCode
	if len(data) < hostReplyHeaderSize {
		log.WithFields(logger.Fields{
			"at":       "i2cp.ParseHostReplyPayload",
			"dataSize": len(data),
			"required": hostReplyHeaderSize,
		}).Error("host_reply_payload_too_short")
		return nil, oops.Errorf("host reply payload too short: need at least %d bytes, got %d", hostReplyHeaderSize, len(data))
	}

	hrp := &HostReplyPayload{}

	// Parse session ID (first 2 bytes, big endian)
	hrp.SessionID = binary.BigEndian.Uint16(data[0:sessionIDFieldSize])

	// Parse request ID (next 4 bytes, big endian)
	hrp.RequestID = binary.BigEndian.Uint32(data[sessionIDFieldSize : sessionIDFieldSize+requestIDFieldSize])

	// Parse result code (byte 6)
	hrp.ResultCode = data[sessionIDFieldSize+requestIDFieldSize]

	// Parse destination and options Mapping (remaining bytes, if any).
	if len(data) > hostReplyHeaderSize {
		tail := make([]byte, len(data)-hostReplyHeaderSize)
		copy(tail, data[hostReplyHeaderSize:])
		hrp.Destination, hrp.Options = splitHostReplyTail(tail)
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
	// The options Mapping is only meaningful alongside a Destination (spec items
	// 4 and 5 are both "only present if result code is zero"), so dropping it on
	// an error reply cannot produce a message a client would misparse.
	options := hrp.Options
	if len(hrp.Destination) == 0 {
		options = nil
	}

	totalSize := 2 + 4 + 1 + len(hrp.Destination) + len(options)
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

	// Write options Mapping (lookup types 2-4 only)
	if len(options) > 0 {
		copy(result[7+len(hrp.Destination):], options)
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

// BlindingInfo endpoint types (I2CP spec BlindingInfoMessage contents field 3).
const (
	BlindingEndpointHash        = 0 // Endpoint is a 32-byte destination hash
	BlindingEndpointHostname    = 1 // Endpoint is a hostname String
	BlindingEndpointDestination = 2 // Endpoint is a binary Destination
	BlindingEndpointSigTypeKey  = 3 // Endpoint is a 2-byte sig type + SigningPublicKey
)

// BlindingInfo flag bits (I2CP spec BlindingInfoMessage contents field 2).
const (
	blindingFlagPerClient  = 0x01 // bit 0: 0 for everybody, 1 for per-client
	blindingAuthSchemeMask = 0x0E // bits 3-1: authentication scheme (000 DH/none, 001 PSK)
	blindingFlagSecret     = 0x10 // bit 4: 1 if a lookup secret/password is required

	// blindingReservedBitsMask covers bits 7-5, which the spec leaves unset. A
	// client that sets any of them is speaking a dialect this router cannot
	// interpret, so the payload is rejected rather than silently ignored.
	blindingReservedBitsMask = 0xE0
)

// BlindingInfo authentication scheme values, held in flag bits 3-1 and read by
// BlindingInfoPayload.AuthScheme. These are the scheme field values, not the
// Layer 1 auth types in common/encrypted_leaseset: DH is 000 and PSK is 001, so
// the mapping to ENCRYPTED_LEASESET_AUTH_TYPE_* is done explicitly where advice
// is converted into a decryption credential.
const (
	blindingAuthSchemeDH  uint8 = 0 // 000: DH client authentication (or none)
	blindingAuthSchemePSK uint8 = 1 // 001: PSK client authentication
)

// BlindingInfoPayload represents the payload structure of a BlindingInfo (type 42)
// message.
//
// The message advises the router that a *peer* Destination is blinded (a "b33"
// new-format address), optionally supplying the per-client authentication secret
// (lookup password) and the per-client decryption private key. It is the
// programmatic counterpart to a Host Lookup of a blinded address, which has no
// way to carry the secret/private key. See proposals 123 and 149.
//
// Wire format (I2P spec, i2p2www/spec/i2cp.rst "BlindingInfoMessage"):
//
//	2 bytes: Session ID
//	1 byte:  Flags
//	           bit 0   0 = everybody, 1 = per-client
//	           bits 3-1 authentication scheme when bit 0 is 1 (000 DH/none, 001 PSK)
//	           bit 4   1 = secret required
//	           bits 7-5 unused, must be 0
//	1 byte:  Endpoint type (0 hash, 1 hostname String, 2 Destination, 3 sig type + key)
//	2 bytes: Blinded signature type
//	4 bytes: Expiration, seconds since epoch
//	Endpoint: as specified by the endpoint type
//	[PrivateKey] Decryption key: 32-byte ECIES_X25519 private key, little-endian
//	           - only present when flag bit 0 is 1
//	[String]   Lookup password    - only present when flag bit 4 is 1
type BlindingInfoPayload struct {
	SessionID   uint16 // Session ID (contents field 1)
	Flags       uint8  // Flag byte (contents field 2)
	Endpoint    uint8  // Endpoint type (contents field 3)
	SigType     uint16 // Blinded signature type (contents field 4)
	Expiration  uint32 // Seconds since epoch (contents field 5)
	Hash        []byte // Type 0 endpoint: 32-byte destination hash
	Hostname    string // Type 1 endpoint: hostname
	Destination []byte // Type 2 endpoint: serialized Destination
	PubkeyType  uint16 // Type 3 endpoint: signing public key type
	Pubkey      []byte // Type 3 endpoint: signing public key bytes
	PrivateKey  []byte // Decryption key, present iff flag bit 0 is set
	Password    string // Lookup password, present iff flag bit 4 is set
}

// IsPerClient reports whether the per-client flag (bit 0) is set.
func (bip *BlindingInfoPayload) IsPerClient() bool {
	return bip.Flags&blindingFlagPerClient != 0
}

// RequiresSecret reports whether the secret-required flag (bit 4) is set.
func (bip *BlindingInfoPayload) RequiresSecret() bool {
	return bip.Flags&blindingFlagSecret != 0
}

// AuthScheme returns the 3-bit authentication scheme from bits 3-1.
func (bip *BlindingInfoPayload) AuthScheme() uint8 {
	return (bip.Flags & blindingAuthSchemeMask) >> 1
}

// ParseBlindingInfoPayload deserializes a BlindingInfo payload from wire format.
// Minimum size: 10 bytes (session ID + flags + endpoint type + sig type + expiration).
func ParseBlindingInfoPayload(data []byte) (*BlindingInfoPayload, error) {
	if len(data) < blindingInfoMinSize {
		log.WithFields(logger.Fields{
			"at":       "i2cp.ParseBlindingInfoPayload",
			"dataSize": len(data),
		}).Error("payload_too_short")
		return nil, oops.Errorf("BlindingInfo payload too short: need at least %d bytes, got %d", blindingInfoMinSize, len(data))
	}

	// Prefix layout: sessionID(2) flags(1) endpoint(1) sigType(2) expiration(4).
	flagsOffset := sessionIDFieldSize
	endpointOffset := flagsOffset + blindingFlagsFieldSize
	sigTypeOffset := endpointOffset + blindingEndpointTypeFieldSize
	expirationOffset := sigTypeOffset + sigTypeFieldSize

	bip := &BlindingInfoPayload{
		SessionID:  binary.BigEndian.Uint16(data[0:flagsOffset]),
		Flags:      data[flagsOffset],
		Endpoint:   data[endpointOffset],
		SigType:    binary.BigEndian.Uint16(data[sigTypeOffset:expirationOffset]),
		Expiration: binary.BigEndian.Uint32(data[expirationOffset:blindingInfoMinSize]),
	}

	if bip.Flags&blindingReservedBitsMask != 0 {
		return nil, oops.Errorf("BlindingInfo flags bits 7-5 must be zero, got 0x%02X", bip.Flags)
	}

	body := data[blindingInfoMinSize:]
	rest, err := bip.parseEndpoint(body)
	if err != nil {
		return nil, err
	}

	rest, err = bip.parseOptionalTrailing(rest)
	if err != nil {
		return nil, err
	}

	if len(rest) != 0 {
		return nil, oops.Errorf("BlindingInfo payload has %d trailing byte(s)", len(rest))
	}

	log.WithFields(logger.Fields{
		"at":         "i2cp.ParseBlindingInfoPayload",
		"sessionID":  bip.SessionID,
		"flags":      bip.Flags,
		"endpoint":   bip.Endpoint,
		"sigType":    bip.SigType,
		"expiration": bip.Expiration,
		"perClient":  bip.IsPerClient(),
		"secret":     bip.RequiresSecret(),
		"dataSize":   len(data),
	}).Debug("parsed_blinding_info_payload")

	return bip, nil
}

// parseEndpoint decodes the endpoint field per its type, returning the
// unconsumed remainder.
func (bip *BlindingInfoPayload) parseEndpoint(body []byte) ([]byte, error) {
	switch bip.Endpoint {
	case BlindingEndpointHash:
		if len(body) < hashSize {
			return nil, oops.Errorf("BlindingInfo hash endpoint needs %d bytes, got %d", hashSize, len(body))
		}
		bip.Hash = make([]byte, hashSize)
		copy(bip.Hash, body[:hashSize])
		return body[hashSize:], nil

	case BlindingEndpointHostname:
		str, remainder, err := commondata.ReadI2PString(body)
		if err != nil {
			return nil, oops.Wrapf(err, "BlindingInfo hostname endpoint")
		}
		hostname, err := str.Data()
		if err != nil {
			return nil, oops.Wrapf(err, "BlindingInfo hostname endpoint decode")
		}
		bip.Hostname = hostname
		return remainder, nil

	case BlindingEndpointDestination:
		// A Destination is a variable-length KeysAndCert; ReadDestination
		// reports the remainder, so no separate length field is needed.
		dest, remainder, err := destination.ReadDestination(body)
		if err != nil {
			return nil, oops.Wrapf(err, "BlindingInfo destination endpoint")
		}
		destBytes, err := dest.Bytes()
		if err != nil {
			return nil, oops.Wrapf(err, "BlindingInfo destination endpoint serialize")
		}
		bip.Destination = destBytes
		return remainder, nil

	case BlindingEndpointSigTypeKey:
		if len(body) < sigTypeFieldSize {
			return nil, oops.Errorf("BlindingInfo sig-type endpoint needs a %d-byte signature type", sigTypeFieldSize)
		}
		bip.PubkeyType = binary.BigEndian.Uint16(body[0:sigTypeFieldSize])
		keyLen, err := signingPublicKeySize(int(bip.PubkeyType))
		if err != nil {
			return nil, oops.Wrapf(err, "BlindingInfo sig-type endpoint")
		}
		if len(body[sigTypeFieldSize:]) < keyLen {
			return nil, oops.Errorf("BlindingInfo signing public key needs %d bytes, got %d", keyLen, len(body[sigTypeFieldSize:]))
		}
		bip.Pubkey = make([]byte, keyLen)
		copy(bip.Pubkey, body[sigTypeFieldSize:sigTypeFieldSize+keyLen])
		return body[sigTypeFieldSize+keyLen:], nil

	default:
		return nil, oops.Errorf("unsupported BlindingInfo endpoint type: %d", bip.Endpoint)
	}
}

// parseOptionalTrailing decodes the private key (present iff per-client) and
// the lookup password (present iff secret required), returning the remainder.
func (bip *BlindingInfoPayload) parseOptionalTrailing(rest []byte) ([]byte, error) {
	if bip.IsPerClient() {
		if len(rest) < x25519KeySize {
			return nil, oops.Errorf("BlindingInfo per-client decryption key needs %d bytes, got %d", x25519KeySize, len(rest))
		}
		bip.PrivateKey = make([]byte, x25519KeySize)
		copy(bip.PrivateKey, rest[:x25519KeySize])
		rest = rest[x25519KeySize:]
	}

	if bip.RequiresSecret() {
		str, remainder, err := commondata.ReadI2PString(rest)
		if err != nil {
			return nil, oops.Wrapf(err, "BlindingInfo lookup password")
		}
		password, err := str.Data()
		if err != nil {
			return nil, oops.Wrapf(err, "BlindingInfo lookup password decode")
		}
		bip.Password = password
		return remainder, nil
	}

	return rest, nil
}

// signingPublicKeySize returns the on-wire size of a signing public key for the
// given I2P signing key type, using the authoritative key-size table.
func signingPublicKeySize(sigType int) (int, error) {
	info, ok := key_certificate.SigningKeySizes[sigType]
	if !ok {
		return 0, oops.Errorf("unknown BlindingInfo signing key type %d", sigType)
	}
	return info.SigningPublicKeySize, nil
}

// MarshalBinary serializes the BlindingInfoPayload to wire format, mirroring
// ParseBlindingInfoPayload.
func (bip *BlindingInfoPayload) MarshalBinary() ([]byte, error) {
	result := make([]byte, 10)
	binary.BigEndian.PutUint16(result[0:2], bip.SessionID)
	result[2] = bip.Flags
	result[3] = bip.Endpoint
	binary.BigEndian.PutUint16(result[4:6], bip.SigType)
	binary.BigEndian.PutUint32(result[6:10], bip.Expiration)

	endpoint, err := bip.marshalEndpoint()
	if err != nil {
		return nil, err
	}
	result = append(result, endpoint...)

	if bip.IsPerClient() {
		if len(bip.PrivateKey) != x25519KeySize {
			return nil, oops.Errorf("BlindingInfo decryption key must be %d bytes, got %d", x25519KeySize, len(bip.PrivateKey))
		}
		result = append(result, bip.PrivateKey...)
	}

	if bip.RequiresSecret() {
		str, err := commondata.ToI2PString(bip.Password)
		if err != nil {
			return nil, oops.Wrapf(err, "BlindingInfo lookup password")
		}
		result = append(result, str...)
	}

	return result, nil
}

// marshalEndpoint serializes the endpoint field per its type.
func (bip *BlindingInfoPayload) marshalEndpoint() ([]byte, error) {
	switch bip.Endpoint {
	case BlindingEndpointHash:
		if len(bip.Hash) != hashSize {
			return nil, oops.Errorf("BlindingInfo hash endpoint must be %d bytes, got %d", hashSize, len(bip.Hash))
		}
		return bip.Hash, nil

	case BlindingEndpointHostname:
		str, err := commondata.ToI2PString(bip.Hostname)
		if err != nil {
			return nil, oops.Wrapf(err, "BlindingInfo hostname endpoint")
		}
		return []byte(str), nil

	case BlindingEndpointDestination:
		if len(bip.Destination) == 0 {
			return nil, oops.Errorf("BlindingInfo destination endpoint is empty")
		}
		return bip.Destination, nil

	case BlindingEndpointSigTypeKey:
		keyLen, err := signingPublicKeySize(int(bip.PubkeyType))
		if err != nil {
			return nil, err
		}
		if len(bip.Pubkey) != keyLen {
			return nil, oops.Errorf("BlindingInfo signing public key must be %d bytes, got %d", keyLen, len(bip.Pubkey))
		}
		out := make([]byte, sigTypeFieldSize+len(bip.Pubkey))
		binary.BigEndian.PutUint16(out[0:sigTypeFieldSize], bip.PubkeyType)
		copy(out[sigTypeFieldSize:], bip.Pubkey)
		return out, nil

	default:
		return nil, oops.Errorf("unsupported BlindingInfo endpoint type: %d", bip.Endpoint)
	}
}
