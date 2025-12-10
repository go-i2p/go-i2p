package i2np

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/logger"

	"github.com/go-i2p/common/certificate"
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/samber/oops"
)

// GarlicBuilder provides methods to construct encrypted garlic messages.
// Garlic messages wrap I2NP messages with delivery instructions and encryption,
// enabling end-to-end encrypted communication through I2P tunnels.
//
// The builder supports:
// - Multiple cloves per garlic message
// - Various delivery instruction types (LOCAL, DESTINATION, ROUTER, TUNNEL)
// - Expiration and message ID management
type GarlicBuilder struct {
	cloves      []GarlicClove
	certificate certificate.Certificate
	messageID   int
	expiration  time.Time
}

// NewGarlicBuilder creates a new garlic message builder.
// messageID: Unique identifier for this garlic message (for tracking/ACKs)
// expiration: Time when this garlic message should no longer be processed
func NewGarlicBuilder(messageID int, expiration time.Time) *GarlicBuilder {
	log.WithFields(logger.Fields{
		"at":         "NewGarlicBuilder",
		"message_id": messageID,
		"expiration": expiration,
	}).Debug("Creating new garlic message builder")
	return &GarlicBuilder{
		cloves:      make([]GarlicClove, 0),
		certificate: *certificate.NewCertificate(),
		messageID:   messageID,
		expiration:  expiration,
	}
}

// NewGarlicBuilderWithDefaults creates a garlic builder with sensible defaults:
// - Random message ID
// - Expiration set to 10 seconds from now
func NewGarlicBuilderWithDefaults() (*GarlicBuilder, error) {
	log.WithField("at", "NewGarlicBuilderWithDefaults").Debug("Creating garlic builder with defaults")
	// Generate random message ID (4 bytes)
	msgIDBytes := make([]byte, 4)
	if _, err := rand.Read(msgIDBytes); err != nil {
		log.WithError(err).Error("Failed to generate random message ID")
		return nil, oops.Wrapf(err, "failed to generate random message ID")
	}
	messageID := int(binary.BigEndian.Uint32(msgIDBytes))

	// Default expiration: 10 seconds from now (typical for garlic messages)
	expiration := time.Now().Add(10 * time.Second)

	log.WithFields(logger.Fields{
		"message_id": messageID,
		"expiration": expiration,
	}).Debug("Generated default garlic builder parameters")
	return NewGarlicBuilder(messageID, expiration), nil
}

// AddClove adds a garlic clove to the message.
// The clove wraps an I2NP message with delivery instructions.
//
// deliveryInstructions: How to deliver the wrapped message (LOCAL, DESTINATION, ROUTER, TUNNEL)
// message: The I2NP message to wrap
// cloveID: Unique identifier for this clove
// cloveExpiration: When this clove expires (typically same as or before garlic message expiration)
func (gb *GarlicBuilder) AddClove(
	deliveryInstructions GarlicCloveDeliveryInstructions,
	message I2NPMessage,
	cloveID int,
	cloveExpiration time.Time,
) error {
	log.WithFields(logger.Fields{
		"at":       "AddClove",
		"clove_id": cloveID,
		"flag":     fmt.Sprintf("0x%02x", deliveryInstructions.Flag),
	}).Debug("Adding clove to garlic message")

	if message == nil {
		log.WithField("at", "AddClove").Error("Attempted to add nil I2NP message")
		return oops.Errorf("cannot add nil I2NP message to garlic clove")
	}

	// Validate expiration (clove should not outlive garlic message)
	if cloveExpiration.After(gb.expiration) {
		log.WithFields(logger.Fields{
			"at":                "AddClove",
			"clove_expiration":  cloveExpiration,
			"garlic_expiration": gb.expiration,
			"reason":            "clove expiration after garlic expiration",
		}).Error("Invalid clove expiration")
		return oops.Errorf("clove expiration (%v) cannot be after garlic message expiration (%v)",
			cloveExpiration, gb.expiration)
	}

	clove := GarlicClove{
		DeliveryInstructions: deliveryInstructions,
		I2NPMessage:          message,
		CloveID:              cloveID,
		Expiration:           cloveExpiration,
		Certificate:          *certificate.NewCertificate(),
	}

	gb.cloves = append(gb.cloves, clove)
	log.WithFields(logger.Fields{
		"at":          "AddClove",
		"clove_count": len(gb.cloves),
	}).Debug("Clove added successfully")
	return nil
}

// AddLocalDeliveryClove adds a clove with LOCAL delivery instructions.
// This is the simplest delivery type - the message is processed locally by the recipient.
//
// message: The I2NP message to wrap
// cloveID: Unique identifier for this clove
func (gb *GarlicBuilder) AddLocalDeliveryClove(message I2NPMessage, cloveID int) error {
	instructions := GarlicCloveDeliveryInstructions{
		Flag: 0x00, // Delivery type: LOCAL (bits 6-5 = 0x00)
	}

	return gb.AddClove(instructions, message, cloveID, gb.expiration)
}

// AddTunnelDeliveryClove adds a clove with TUNNEL delivery instructions.
// The message will be forwarded through the specified tunnel to the gateway router.
//
// message: The I2NP message to wrap
// cloveID: Unique identifier for this clove
// gatewayHash: SHA256 hash of the tunnel gateway router
// tunnelID: Destination tunnel ID
func (gb *GarlicBuilder) AddTunnelDeliveryClove(
	message I2NPMessage,
	cloveID int,
	gatewayHash common.Hash,
	tunnelID tunnel.TunnelID,
) error {
	instructions := GarlicCloveDeliveryInstructions{
		Flag:     0x60, // Delivery type: TUNNEL (bits 6-5 = 0x11 = 0x60)
		Hash:     gatewayHash,
		TunnelID: tunnelID,
	}

	return gb.AddClove(instructions, message, cloveID, gb.expiration)
}

// AddDestinationDeliveryClove adds a clove with DESTINATION delivery instructions.
// The message will be delivered to the specified I2P destination.
//
// message: The I2NP message to wrap
// cloveID: Unique identifier for this clove
// destinationHash: SHA256 hash of the destination
func (gb *GarlicBuilder) AddDestinationDeliveryClove(
	message I2NPMessage,
	cloveID int,
	destinationHash common.Hash,
) error {
	instructions := GarlicCloveDeliveryInstructions{
		Flag: 0x20, // Delivery type: DESTINATION (bits 6-5 = 0x01 = 0x20)
		Hash: destinationHash,
	}

	return gb.AddClove(instructions, message, cloveID, gb.expiration)
}

// AddRouterDeliveryClove adds a clove with ROUTER delivery instructions.
// The message will be delivered to the specified router.
//
// message: The I2NP message to wrap
// cloveID: Unique identifier for this clove
// routerHash: SHA256 hash of the destination router
func (gb *GarlicBuilder) AddRouterDeliveryClove(
	message I2NPMessage,
	cloveID int,
	routerHash common.Hash,
) error {
	instructions := GarlicCloveDeliveryInstructions{
		Flag: 0x40, // Delivery type: ROUTER (bits 6-5 = 0x10 = 0x40)
		Hash: routerHash,
	}

	return gb.AddClove(instructions, message, cloveID, gb.expiration)
}

// Build constructs the unencrypted Garlic message structure.
// This produces a Garlic object ready for encryption.
// The actual encryption is handled by SessionManager (ECIES-X25519-AEAD-Ratchet).
func (gb *GarlicBuilder) Build() (*Garlic, error) {
	log.WithFields(logger.Fields{
		"at":          "Build",
		"clove_count": len(gb.cloves),
		"message_id":  gb.messageID,
	}).Debug("Building garlic message")

	if len(gb.cloves) == 0 {
		log.WithField("at", "Build").Error("Cannot build garlic with zero cloves")
		return nil, oops.Errorf("cannot build garlic message with zero cloves")
	}

	if len(gb.cloves) > 255 {
		log.WithFields(logger.Fields{
			"at":          "Build",
			"clove_count": len(gb.cloves),
			"max_cloves":  255,
			"reason":      "exceeded maximum clove count",
		}).Error("Too many cloves in garlic message")
		return nil, oops.Errorf("garlic message cannot contain more than 255 cloves, got %d", len(gb.cloves))
	}

	garlic := &Garlic{
		Count:       len(gb.cloves),
		Cloves:      gb.cloves,
		Certificate: gb.certificate,
		MessageID:   gb.messageID,
		Expiration:  gb.expiration,
	}

	log.WithField("at", "Build").Debug("Garlic message built successfully")
	return garlic, nil
}

// BuildAndSerialize constructs the garlic message and serializes it to bytes.
// This produces the plaintext garlic payload ready for encryption.
//
// Returns the serialized plaintext garlic message (unencrypted).
func (gb *GarlicBuilder) BuildAndSerialize() ([]byte, error) {
	log.WithField("at", "BuildAndSerialize").Debug("Building and serializing garlic message")

	garlic, err := gb.Build()
	if err != nil {
		log.WithError(err).Error("Failed to build garlic message")
		return nil, oops.Wrapf(err, "failed to build garlic message")
	}

	payload, err := serializeGarlic(garlic)
	if err != nil {
		log.WithError(err).Error("Failed to serialize garlic message")
		return nil, oops.Wrapf(err, "failed to serialize garlic message")
	}

	log.WithFields(logger.Fields{
		"at":           "BuildAndSerialize",
		"payload_size": len(payload),
	}).Debug("Garlic message serialized successfully")
	return payload, nil
}

// serializeGarlic converts a Garlic structure to its wire format (unencrypted).
//
// Wire format:
// +----+----+----+----+----+----+----+----+
// | num|  clove 1                         |
// +----+                                  +
// |                                       |
// ~   (variable length)                  ~
// |                                       |
// +----+----+----+----+----+----+----+----+
// |         clove 2 ...                   |
// ~                                       ~
// |                                       |
// +----+----+----+----+----+----+----+----+
// | Certificate  |   Message_ID      |
// +----+----+----+----+----+----+----+----+
//
//	Expiration               |
//
// +----+----+----+----+----+----+----+
//
// num: 1 byte (number of cloves)
// clove: variable length (delivery instructions + I2NP message + metadata)
// Certificate: 3 bytes (always NULL in current implementation)
// Message_ID: 4 bytes
// Expiration: 8 bytes (milliseconds since epoch)
func serializeGarlic(garlic *Garlic) ([]byte, error) {
	log.WithFields(logger.Fields{
		"at":          "serializeGarlic",
		"clove_count": garlic.Count,
	}).Debug("Serializing garlic message")

	if garlic == nil {
		log.WithField("at", "serializeGarlic").Error("Attempted to serialize nil garlic")
		return nil, oops.Errorf("cannot serialize nil garlic message")
	}

	// Estimate buffer size (cloves are variable length, so this is approximate)
	estimatedSize := 1 + (len(garlic.Cloves) * 100) + 3 + 4 + 8
	buf := make([]byte, 0, estimatedSize)

	// Write clove count (1 byte)
	buf = append(buf, byte(garlic.Count))

	// Serialize each clove
	for i, clove := range garlic.Cloves {
		cloveBytes, err := serializeGarlicClove(&clove)
		if err != nil {
			return nil, oops.Wrapf(err, "failed to serialize garlic clove %d", i)
		}
		buf = append(buf, cloveBytes...)
	}

	// Write certificate (3 bytes - always NULL)
	certBytes := garlic.Certificate.Bytes()
	buf = append(buf, certBytes...)

	// Write message ID (4 bytes, big-endian)
	msgIDBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(msgIDBytes, uint32(garlic.MessageID))
	buf = append(buf, msgIDBytes...)

	// Write expiration (8 bytes, milliseconds since epoch)
	expirationBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(expirationBytes, uint64(garlic.Expiration.UnixMilli()))
	buf = append(buf, expirationBytes...)

	return buf, nil
}

// serializeGarlicClove converts a GarlicClove to its wire format.
//
// Wire format:
// +----+----+----+----+----+----+----+----+
// | Delivery Instructions                 |
// ~   (variable: 1, 33, or 37 bytes)     ~
// |                                       |
// +----+----+----+----+----+----+----+----+
// | I2NP Message                          |
// ~   (variable length)                  ~
// |                                       |
// +----+----+----+----+----+----+----+----+
// |    Clove ID       |     Expiration
// +----+----+----+----+----+----+----+----+
//
//	| Certificate  |
//
// +----+----+----+----+----+----+----+
func serializeGarlicClove(clove *GarlicClove) ([]byte, error) {
	if clove == nil {
		return nil, oops.Errorf("cannot serialize nil garlic clove")
	}

	buf := make([]byte, 0, 128)

	// Serialize delivery instructions
	instructionsBytes, err := serializeDeliveryInstructions(&clove.DeliveryInstructions)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to serialize delivery instructions")
	}
	buf = append(buf, instructionsBytes...)

	// Serialize I2NP message
	if clove.I2NPMessage == nil {
		return nil, oops.Errorf("garlic clove contains nil I2NP message")
	}
	messageBytes, err := clove.I2NPMessage.MarshalBinary()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to serialize I2NP message")
	}
	buf = append(buf, messageBytes...)

	// Write clove ID (4 bytes)
	cloveIDBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(cloveIDBytes, uint32(clove.CloveID))
	buf = append(buf, cloveIDBytes...)

	// Write expiration (8 bytes, milliseconds since epoch)
	expirationBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(expirationBytes, uint64(clove.Expiration.UnixMilli()))
	buf = append(buf, expirationBytes...)

	// Write certificate (3 bytes - always NULL)
	certBytes := clove.Certificate.Bytes()
	buf = append(buf, certBytes...)

	return buf, nil
}

// serializeDeliveryInstructions converts delivery instructions to wire format.
//
// Wire format (variable length):
// +----+----+----+----+----+----+----+----+
// |flag|                                  |
// +----+  Session Key (optional, 32B)    +
// |                                       |
// +                                       +
// |                                       |
// +    +----+----+----+----+--------------+
// |    |  To Hash (optional, 32B)        |
// +----+                                  +
// |                                       |
// +                                       +
// |                                       |
// +    +----+----+----+----+--------------+
// |    |  Tunnel ID (opt, 4B) | Delay (opt, 4B)
// +----+----+----+----+----+----+----+----+
//
// flag: 1 byte (delivery type, encryption flag, delay flag)
// Typical lengths: 1 byte (LOCAL), 33 bytes (DESTINATION/ROUTER), 37 bytes (TUNNEL)
func serializeDeliveryInstructions(di *GarlicCloveDeliveryInstructions) ([]byte, error) {
	if di == nil {
		return nil, oops.Errorf("cannot serialize nil delivery instructions")
	}

	buf := initializeBufferWithFlag(di.Flag)
	deliveryType := extractDeliveryType(di.Flag)

	if err := appendEncryptionKeyIfNeeded(di, &buf); err != nil {
		return nil, err
	}

	if err := appendHashForDeliveryType(di, deliveryType, &buf); err != nil {
		return nil, err
	}

	appendTunnelIDIfNeeded(di, deliveryType, &buf)
	appendDelayIfNeeded(di, &buf)

	return buf, nil
}

// initializeBufferWithFlag creates a buffer with the flag byte.
func initializeBufferWithFlag(flag byte) []byte {
	buf := make([]byte, 0, 37) // Max possible size
	return append(buf, flag)
}

// extractDeliveryType extracts the delivery type from flag bits 6-5.
func extractDeliveryType(flag byte) byte {
	return (flag >> 5) & 0x03
}

// appendEncryptionKeyIfNeeded adds session key to buffer if encryption flag is set.
func appendEncryptionKeyIfNeeded(di *GarlicCloveDeliveryInstructions, buf *[]byte) error {
	encrypted := (di.Flag >> 7) & 0x01
	if encrypted == 1 {
		if len(di.SessionKey) != session_key.SESSION_KEY_SIZE {
			return oops.Errorf("session key must be %d bytes when encryption flag is set",
				session_key.SESSION_KEY_SIZE)
		}
		*buf = append(*buf, di.SessionKey[:]...)
	}
	return nil
}

// appendHashForDeliveryType adds hash to buffer for DESTINATION, ROUTER, or TUNNEL delivery.
func appendHashForDeliveryType(di *GarlicCloveDeliveryInstructions, deliveryType byte, buf *[]byte) error {
	if deliveryType == 0x01 || deliveryType == 0x02 || deliveryType == 0x03 {
		if len(di.Hash) != 32 {
			return oops.Errorf("hash must be 32 bytes for delivery type %d", deliveryType)
		}
		*buf = append(*buf, di.Hash[:]...)
	}
	return nil
}

// appendTunnelIDIfNeeded adds tunnel ID to buffer for TUNNEL delivery type.
func appendTunnelIDIfNeeded(di *GarlicCloveDeliveryInstructions, deliveryType byte, buf *[]byte) {
	if deliveryType == 0x03 {
		tunnelIDBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(tunnelIDBytes, uint32(di.TunnelID))
		*buf = append(*buf, tunnelIDBytes...)
	}
}

// appendDelayIfNeeded adds delay to buffer if delay flag is set.
func appendDelayIfNeeded(di *GarlicCloveDeliveryInstructions, buf *[]byte) {
	delayIncluded := (di.Flag >> 4) & 0x01
	if delayIncluded == 1 {
		delayBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(delayBytes, uint32(di.Delay))
		*buf = append(*buf, delayBytes...)
	}
}

// Helper functions for creating common delivery instruction patterns

// NewLocalDeliveryInstructions creates delivery instructions for local processing.
func NewLocalDeliveryInstructions() GarlicCloveDeliveryInstructions {
	return GarlicCloveDeliveryInstructions{
		Flag: 0x00, // LOCAL delivery (bits 6-5 = 0x00)
	}
}

// NewTunnelDeliveryInstructions creates delivery instructions for tunnel delivery.
// gatewayHash: SHA256 hash of the tunnel gateway router
// tunnelID: Destination tunnel ID
func NewTunnelDeliveryInstructions(gatewayHash common.Hash, tunnelID tunnel.TunnelID) GarlicCloveDeliveryInstructions {
	return GarlicCloveDeliveryInstructions{
		Flag:     0x60, // TUNNEL delivery (bits 6-5 = 0x11 = 0x60)
		Hash:     gatewayHash,
		TunnelID: tunnelID,
	}
}

// NewDestinationDeliveryInstructions creates delivery instructions for destination delivery.
// destinationHash: SHA256 hash of the destination
func NewDestinationDeliveryInstructions(destinationHash common.Hash) GarlicCloveDeliveryInstructions {
	return GarlicCloveDeliveryInstructions{
		Flag: 0x20, // DESTINATION delivery (bits 6-5 = 0x01 = 0x20)
		Hash: destinationHash,
	}
}

// NewRouterDeliveryInstructions creates delivery instructions for router delivery.
// routerHash: SHA256 hash of the destination router
func NewRouterDeliveryInstructions(routerHash common.Hash) GarlicCloveDeliveryInstructions {
	return GarlicCloveDeliveryInstructions{
		Flag: 0x40, // ROUTER delivery (bits 6-5 = 0x10 = 0x40)
		Hash: routerHash,
	}
}

// DeserializeGarlic parses a decrypted garlic message from bytes with validation.
// This function enforces security limits to prevent resource exhaustion attacks.
//
// Security validations:
// - Maximum clove count (64) to prevent memory exhaustion
// - Maximum nesting depth (3) to prevent stack overflow from recursive garlic
// - Proper bounds checking for all fields
//
// Returns the parsed Garlic structure or an error if validation fails.
func DeserializeGarlic(data []byte, nestingDepth int) (*Garlic, error) {
	log.WithFields(logger.Fields{
		"at":            "DeserializeGarlic",
		"data_size":     len(data),
		"nesting_depth": nestingDepth,
	}).Debug("Deserializing garlic message")

	const (
		MaxGarlicCloves       = 64            // Practical limit for clove count
		MaxGarlicNestingDepth = 3             // Prevent infinite recursion
		MinGarlicSize         = 1 + 3 + 4 + 8 // num(1) + cert(3) + msgID(4) + exp(8)
	)

	// Validate garlic structure
	if err := validateGarlicStructure(data, nestingDepth, MinGarlicSize, MaxGarlicNestingDepth); err != nil {
		log.WithError(err).Error("Garlic structure validation failed")
		return nil, err
	}

	// Parse garlic components
	garlic, err := parseGarlicStructure(data, nestingDepth, MaxGarlicCloves)
	if err != nil {
		log.WithError(err).Error("Failed to parse garlic structure")
		return nil, err
	}

	log.WithFields(logger.Fields{
		"at":          "DeserializeGarlic",
		"clove_count": garlic.Count,
		"message_id":  garlic.MessageID,
	}).Debug("Garlic message deserialized successfully")
	return garlic, nil
}

// validateGarlicStructure validates nesting depth and data size.
func validateGarlicStructure(data []byte, nestingDepth, minSize, maxDepth int) error {
	if err := validateGarlicNestingDepth(nestingDepth, maxDepth); err != nil {
		return err
	}
	return validateGarlicDataSize(data, minSize)
}

// parseGarlicStructure parses all garlic components and builds the structure.
func parseGarlicStructure(data []byte, nestingDepth, maxCloves int) (*Garlic, error) {
	cloveCount, offset, err := parseGarlicCloveCount(data, maxCloves)
	if err != nil {
		return nil, err
	}

	cloves, offset, err := parseGarlicCloves(data, offset, cloveCount, nestingDepth)
	if err != nil {
		return nil, err
	}

	cert, messageID, expiration, err := parseGarlicMetadata(data, offset)
	if err != nil {
		return nil, err
	}

	return &Garlic{
		Count:       cloveCount,
		Cloves:      cloves,
		Certificate: cert,
		MessageID:   messageID,
		Expiration:  expiration,
	}, nil
}

// validateGarlicNestingDepth checks if the nesting depth exceeds the maximum allowed.
func validateGarlicNestingDepth(nestingDepth, maxDepth int) error {
	if nestingDepth > maxDepth {
		return oops.Errorf("garlic nesting depth exceeded: %d > %d", nestingDepth, maxDepth)
	}
	return nil
}

// validateGarlicDataSize checks if the data buffer meets the minimum size requirement.
func validateGarlicDataSize(data []byte, minSize int) error {
	if len(data) < minSize {
		return oops.Errorf("garlic data too short: need at least %d bytes, got %d", minSize, len(data))
	}
	return nil
}

// parseGarlicCloveCount reads and validates the clove count from the data buffer.
func parseGarlicCloveCount(data []byte, maxCloves int) (int, int, error) {
	cloveCount := int(data[0])
	if cloveCount > maxCloves {
		return 0, 0, oops.Errorf("garlic clove count too high: %d > %d (possible resource exhaustion attack)", cloveCount, maxCloves)
	}
	return cloveCount, 1, nil
}

// parseGarlicCloves parses all cloves from the data buffer starting at the given offset.
func parseGarlicCloves(data []byte, offset, cloveCount, nestingDepth int) ([]GarlicClove, int, error) {
	cloves := make([]GarlicClove, cloveCount)
	for i := 0; i < cloveCount; i++ {
		clove, bytesRead, err := deserializeGarlicClove(data[offset:], nestingDepth)
		if err != nil {
			return nil, 0, oops.Wrapf(err, "failed to parse clove %d", i)
		}
		cloves[i] = *clove
		offset += bytesRead
	}
	return cloves, offset, nil
}

// parseGarlicMetadata parses the certificate, message ID, and expiration from the data buffer.
func parseGarlicMetadata(data []byte, offset int) (certificate.Certificate, int, time.Time, error) {
	const metadataSize = 3 + 4 + 8 // cert(3) + msgID(4) + exp(8)

	if len(data) < offset+metadataSize {
		return certificate.Certificate{}, 0, time.Time{}, oops.Errorf("insufficient data for garlic trailer: need %d bytes, have %d", metadataSize, len(data)-offset)
	}

	cert := *certificate.NewCertificate()
	offset += 3

	messageID := int(binary.BigEndian.Uint32(data[offset : offset+4]))
	offset += 4

	expirationMs := binary.BigEndian.Uint64(data[offset : offset+8])
	expiration := time.UnixMilli(int64(expirationMs))

	return cert, messageID, expiration, nil
}

// deserializeGarlicClove parses a single garlic clove from bytes.
// Returns the clove, number of bytes consumed, and any error.
func deserializeGarlicClove(data []byte, nestingDepth int) (*GarlicClove, int, error) {
	if len(data) < 1 {
		return nil, 0, oops.Errorf("clove data too short")
	}

	offset := 0

	// Parse delivery instructions
	di, bytesRead, err := deserializeDeliveryInstructions(data[offset:])
	if err != nil {
		return nil, 0, oops.Wrapf(err, "failed to parse delivery instructions")
	}
	offset += bytesRead

	// Parse and skip I2NP message
	messageLength, err := readI2NPMessageLength(data, offset)
	if err != nil {
		return nil, 0, err
	}
	offset += messageLength

	// Parse clove metadata
	cloveID, expiration, cert, err := parseCloveMetadata(data, offset)
	if err != nil {
		return nil, 0, err
	}
	offset += 4 + 8 + 3 // clove ID + expiration + certificate

	return &GarlicClove{
		DeliveryInstructions: *di,
		I2NPMessage:          nil, // Would be populated by full I2NP parser
		CloveID:              cloveID,
		Expiration:           expiration,
		Certificate:          cert,
	}, offset, nil
}

// readI2NPMessageLength validates I2NP message header and returns total message length.
// Standard I2NP header structure:
//   - type (1 byte) at offset 0
//   - msg_id (4 bytes) at offset 1-4
//   - expiration (8 bytes) at offset 5-12
//   - size (2 bytes) at offset 13-14
//   - checksum (1 byte) at offset 15
//   - data (size bytes) at offset 16+
func readI2NPMessageLength(data []byte, offset int) (int, error) {
	if len(data) < offset+16 {
		return 0, oops.Errorf("insufficient data for I2NP message header (need %d bytes, have %d)", offset+16, len(data))
	}

	// Read message size from I2NP header (bytes 13-14 from start of message)
	messageSize, err := ReadI2NPNTCPMessageSize(data[offset:])
	if err != nil {
		return 0, oops.Wrapf(err, "failed to read I2NP message size")
	}

	// Total I2NP message length = 16-byte header + message data
	messageLength := 16 + messageSize

	// Validate we have enough data for the complete message
	if len(data) < offset+messageLength {
		return 0, oops.Errorf("insufficient data for I2NP message (need %d bytes, have %d)", offset+messageLength, len(data))
	}

	return messageLength, nil
}

// parseCloveMetadata extracts clove ID, expiration, and certificate from clove trailer.
func parseCloveMetadata(data []byte, offset int) (int, time.Time, certificate.Certificate, error) {
	// Ensure enough data for clove ID + expiration + certificate
	if len(data) < offset+4+8+3 {
		return 0, time.Time{}, certificate.Certificate{}, oops.Errorf("insufficient data for clove trailer")
	}

	// Read clove ID (4 bytes)
	cloveID := int(binary.BigEndian.Uint32(data[offset : offset+4]))

	// Read expiration (8 bytes)
	expirationMs := binary.BigEndian.Uint64(data[offset+4 : offset+12])
	expiration := time.UnixMilli(int64(expirationMs))

	// Read certificate (3 bytes)
	cert := *certificate.NewCertificate()

	return cloveID, expiration, cert, nil
}

// deserializeDeliveryInstructions parses delivery instructions from bytes.
// Returns the instructions, number of bytes consumed, and any error.
func deserializeDeliveryInstructions(data []byte) (*GarlicCloveDeliveryInstructions, int, error) {
	if len(data) < 1 {
		return nil, 0, oops.Errorf("delivery instructions data too short")
	}

	flag := data[0]
	offset := 1

	di := &GarlicCloveDeliveryInstructions{
		Flag: flag,
	}

	deliveryType := (flag >> 5) & 0x03
	bytesRead, err := parseDeliveryTypeData(di, deliveryType, data[offset:])
	if err != nil {
		return nil, 0, err
	}
	offset += bytesRead

	bytesRead, err = parseOptionalDelayField(di, flag, data[offset:])
	if err != nil {
		return nil, 0, err
	}
	offset += bytesRead

	return di, offset, nil
}

// parseDeliveryTypeData parses the delivery type specific data from bytes.
// Returns the number of bytes consumed and any error.
func parseDeliveryTypeData(di *GarlicCloveDeliveryInstructions, deliveryType byte, data []byte) (int, error) {
	switch deliveryType {
	case 0x00: // LOCAL - no additional data
		return 0, nil
	case 0x01: // DESTINATION - 32 byte hash
		return parseHashData(di, data, "DESTINATION")
	case 0x02: // ROUTER - 32 byte hash
		return parseHashData(di, data, "ROUTER")
	case 0x03: // TUNNEL - 32 byte hash + 4 byte tunnel ID
		return parseTunnelData(di, data)
	default:
		return 0, nil
	}
}

// parseHashData parses a 32-byte hash for DESTINATION or ROUTER delivery types.
// Returns the number of bytes consumed and any error.
func parseHashData(di *GarlicCloveDeliveryInstructions, data []byte, deliveryTypeName string) (int, error) {
	if len(data) < 32 {
		return 0, oops.Errorf("insufficient data for %s hash", deliveryTypeName)
	}
	copy(di.Hash[:], data[0:32])
	return 32, nil
}

// parseTunnelData parses TUNNEL delivery type data (32-byte hash + 4-byte tunnel ID).
// Returns the number of bytes consumed and any error.
func parseTunnelData(di *GarlicCloveDeliveryInstructions, data []byte) (int, error) {
	if len(data) < 36 {
		return 0, oops.Errorf("insufficient data for TUNNEL hash and ID")
	}
	copy(di.Hash[:], data[0:32])
	di.TunnelID = tunnel.TunnelID(binary.BigEndian.Uint32(data[32:36]))
	return 36, nil
}

// parseOptionalDelayField parses the optional delay field if present.
// Returns the number of bytes consumed and any error.
func parseOptionalDelayField(di *GarlicCloveDeliveryInstructions, flag byte, data []byte) (int, error) {
	delayIncluded := (flag >> 4) & 0x01
	if delayIncluded != 1 {
		return 0, nil
	}

	if len(data) < 4 {
		return 0, oops.Errorf("insufficient data for delay field")
	}
	di.Delay = int(binary.BigEndian.Uint32(data[0:4]))
	return 4, nil
}
