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
	"github.com/go-i2p/go-i2p/lib/tunnel/buildrecord"
	"github.com/samber/oops"
)

const (
	// MaxGarlicCloves is the maximum number of cloves in a garlic message.
	// This limit prevents memory exhaustion from excessively large clove lists.
	MaxGarlicCloves = 64

	// MaxGarlicNestingDepth is the maximum depth of nested garlic messages.
	// Used by parse-time depth guards to prevent stack overflow and recursion bombs.
	MaxGarlicNestingDepth = 3
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
	messageID := int(binary.BigEndian.Uint32(msgIDBytes) & 0x7FFFFFFF)

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
	message Message,
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
		Message:              message,
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
func (gb *GarlicBuilder) AddLocalDeliveryClove(message Message, cloveID int) error {
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
	message Message,
	cloveID int,
	gatewayHash common.Hash,
	tunnelID buildrecord.TunnelID,
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
	message Message,
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
	message Message,
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

// BuildClovePayloads constructs the garlic message and returns one spec-compliant
// clove payload per clove. Each payload is: DeliveryInstructions + 9-byte short
// I2NP header (type || msgID || exp-seconds) + I2NP body (extends to end).
//
// Per the ECIES-X25519-AEAD-Ratchet spec (ratchet.md §Garlic Clove), each clove
// is contained in its own type-11 payload block. The Clove Set format (count byte,
// certificate, garlic-level msgID/expiration) is NOT used.
//
// Returns one byte slice per clove, ready to be wrapped as individual
// BlockGarlicClove entries in the ratchet payload.
func (gb *GarlicBuilder) BuildClovePayloads() ([][]byte, error) {
	log.WithField("at", "BuildClovePayloads").Debug("Building spec-compliant clove payloads")

	garlic, err := gb.Build()
	if err != nil {
		log.WithError(err).Error("Failed to build garlic message")
		return nil, oops.Wrapf(err, "failed to build garlic message")
	}

	payloads := make([][]byte, 0, len(garlic.Cloves))
	for i, clove := range garlic.Cloves {
		cloveBytes, err := serializeGarlicClove(&clove)
		if err != nil {
			return nil, oops.Wrapf(err, "failed to serialize garlic clove %d", i)
		}
		payloads = append(payloads, cloveBytes)
	}

	log.WithFields(logger.Fields{
		"at":          "BuildClovePayloads",
		"clove_count": len(payloads),
	}).Debug("Spec-compliant clove payloads built successfully")
	return payloads, nil
}

// serializeGarlicClove converts a GarlicClove to its wire format.
//
// Spec-compliant wire format (per ecies.rst "Garlic Clove block"):
// +----+----+----+----+----+----+----+----+
// | Delivery Instructions                 |
// ~   (variable: 1, 33, or 37 bytes)     ~
// |                                       |
// +----+----+----+----+----+----+----+----+
// | Type(1) | MsgID(4) | ShortExp(4)     |
// +----+----+----+----+----+----+----+----+
// | Body (payload from MarshalBinary)     |
// ~   (variable length)                  ~
// |                                       |
// +----+----+----+----+----+----+----+----+
//
// The 9-byte short I2NP header replaces the legacy 16-byte standard
// header + clove ID + expiration + certificate trailer.
func serializeGarlicClove(clove *GarlicClove) ([]byte, error) {
	if clove == nil {
		return nil, oops.Errorf("cannot serialize nil garlic clove")
	}

	if clove.Message == nil {
		return nil, oops.Errorf("garlic clove contains nil I2NP message")
	}

	buf := make([]byte, 0, 128)

	// Serialize delivery instructions
	instructionsBytes, err := serializeDeliveryInstructions(&clove.DeliveryInstructions)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to serialize delivery instructions")
	}
	buf = append(buf, instructionsBytes...)

	// Write the 9-byte short I2NP header: type(1) + msgID(4) + shortExp(4).
	// The short I2NP header carries the embedded I2NP message's own expiration
	// (seconds since epoch), not the garlic-level expiration.
	header := make([]byte, 9)
	header[0] = byte(clove.Message.Type())
	binary.BigEndian.PutUint32(header[1:5], uint32(clove.Message.MessageID()))
	binary.BigEndian.PutUint32(header[5:9], uint32(clove.Message.Expiration().Unix()))
	buf = append(buf, header...)

	// Write the body: raw payload bytes (no standard 16-byte I2NP header,
	// no length prefix). Per the ECIES spec, the I2NP message body extends
	// to the end of the block; the block's own size field delimits it.
	var bodyData []byte
	if carrier, ok := clove.Message.(DataCarrier); ok {
		bodyData = carrier.GetData()
	}
	buf = append(buf, bodyData...)

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
func NewTunnelDeliveryInstructions(gatewayHash common.Hash, tunnelID buildrecord.TunnelID) GarlicCloveDeliveryInstructions {
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
	hash, _, err := common.ReadHash(data)
	if err != nil {
		return 0, oops.Errorf("insufficient data for %s hash", deliveryTypeName)
	}
	di.Hash = hash
	return 32, nil
}

// parseTunnelData parses TUNNEL delivery type data (32-byte hash + 4-byte tunnel ID).
// Returns the number of bytes consumed and any error.
func parseTunnelData(di *GarlicCloveDeliveryInstructions, data []byte) (int, error) {
	if len(data) < 36 {
		return 0, oops.Errorf("insufficient data for TUNNEL hash and ID")
	}
	hash, remainder, err := common.ReadHash(data)
	if err != nil {
		return 0, oops.Errorf("insufficient data for TUNNEL hash and ID")
	}
	di.Hash = hash
	di.TunnelID = buildrecord.TunnelID(binary.BigEndian.Uint32(remainder[:4]))
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
