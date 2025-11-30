package i2np

import (
	"github.com/go-i2p/crypto/rand"
	"encoding/binary"
	"time"

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
	// Generate random message ID (4 bytes)
	msgIDBytes := make([]byte, 4)
	if _, err := rand.Read(msgIDBytes); err != nil {
		return nil, oops.Wrapf(err, "failed to generate random message ID")
	}
	messageID := int(binary.BigEndian.Uint32(msgIDBytes))

	// Default expiration: 10 seconds from now (typical for garlic messages)
	expiration := time.Now().Add(10 * time.Second)

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
	if message == nil {
		return oops.Errorf("cannot add nil I2NP message to garlic clove")
	}

	// Validate expiration (clove should not outlive garlic message)
	if cloveExpiration.After(gb.expiration) {
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
	if len(gb.cloves) == 0 {
		return nil, oops.Errorf("cannot build garlic message with zero cloves")
	}

	if len(gb.cloves) > 255 {
		return nil, oops.Errorf("garlic message cannot contain more than 255 cloves, got %d", len(gb.cloves))
	}

	garlic := &Garlic{
		Count:       len(gb.cloves),
		Cloves:      gb.cloves,
		Certificate: gb.certificate,
		MessageID:   gb.messageID,
		Expiration:  gb.expiration,
	}

	return garlic, nil
}

// BuildAndSerialize constructs the garlic message and serializes it to bytes.
// This produces the plaintext garlic payload ready for encryption.
//
// Returns the serialized plaintext garlic message (unencrypted).
func (gb *GarlicBuilder) BuildAndSerialize() ([]byte, error) {
	garlic, err := gb.Build()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to build garlic message")
	}

	payload, err := serializeGarlic(garlic)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to serialize garlic message")
	}

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
	if garlic == nil {
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
