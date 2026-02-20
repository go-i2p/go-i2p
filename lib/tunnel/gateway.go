package tunnel

import (
	"github.com/go-i2p/crypto/types"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/crypto/tunnel"
	"github.com/go-i2p/logger"
)

// Gateway handles sending I2NP messages through a tunnel
// by wrapping them in tunnel messages and applying encryption.
//
// Design decisions:
// - Works with raw bytes to avoid import cycles with i2np package
// - Uses crypto/tunnel package with ECIES-X25519-AEAD (ChaCha20/Poly1305) by default
// - Supports both modern ECIES and legacy AES-256-CBC for compatibility
// - Simple interface focused on core functionality
// - Error handling at each step with clear error messages
// - Supports DT_LOCAL, DT_TUNNEL, and DT_ROUTER delivery types
// - Fragments oversized messages across multiple tunnel messages
type Gateway struct {
	tunnelID   TunnelID
	encryption tunnel.TunnelEncryptor
	nextHopID  TunnelID
	msgIDSeq   uint32     // monotonic message ID counter for fragmentation
	encMu      sync.Mutex // protects concurrent calls to encryption.Encrypt
}

var (
	// ErrNilEncryption is returned when encryption is nil
	ErrNilEncryption = errors.New("encryption tunnel cannot be nil")
	// ErrMessageTooLarge is returned when a message exceeds maximum size
	ErrMessageTooLarge = errors.New("message too large for tunnel")
	// ErrInvalidMessage is returned when message data is invalid
	ErrInvalidMessage = errors.New("invalid I2NP message data")
)

const (
	// maxTunnelPayload is the maximum size of data (delivery instructions + message)
	// that can fit in a tunnel message after accounting for:
	// tunnel ID (4) + IV (16) + checksum (4) + zero byte separator (1) = 25 bytes overhead
	// Total tunnel message = 1028 bytes, so max data = 1028 - 25 = 1003
	maxTunnelPayload = 1028 - 4 - 16 - 4 - 1 // 1003 bytes for delivery instructions + message
)

// NewGateway creates a new tunnel gateway.
//
// Parameters:
// - tunnelID: the ID of this tunnel
// - encryption: the tunnel encryption object for layered encryption
// - nextHopID: the tunnel ID to use when forwarding to the next hop
//
// Returns an error if encryption is nil.
func NewGateway(tunnelID TunnelID, encryption tunnel.TunnelEncryptor, nextHopID TunnelID) (*Gateway, error) {
	if encryption == nil {
		log.WithFields(logger.Fields{
			"at":        "NewGateway",
			"tunnel_id": tunnelID,
			"reason":    "nil encryption",
		}).Error("Failed to create gateway")
		return nil, ErrNilEncryption
	}

	gw := &Gateway{
		tunnelID:   tunnelID,
		encryption: encryption,
		nextHopID:  nextHopID,
	}

	log.WithFields(logger.Fields{
		"at":        "NewGateway",
		"reason":    "outbound_gateway_created",
		"tunnel_id": tunnelID,
	}).Debug("created tunnel gateway")
	return gw, nil
}

// Send wraps an I2NP message (as bytes) in tunnel format and encrypts it.
//
// Parameters:
// - msgBytes: the serialized I2NP message to send
//
// Process:
// 1. Validate message size
// 2. Create delivery instructions
// 3. Build tunnel message with padding
// 4. Calculate checksum
// 5. Apply encryption
//
// Returns the encrypted tunnel message ready for transmission, or an error.
func (g *Gateway) Send(msgBytes []byte) ([]byte, error) {
	log.WithFields(logger.Fields{
		"at":        "Gateway.Send",
		"tunnel_id": g.tunnelID,
		"msg_size":  len(msgBytes),
	}).Debug("Sending message through tunnel gateway")

	if len(msgBytes) == 0 {
		log.WithFields(logger.Fields{
			"at":        "Gateway.Send",
			"tunnel_id": g.tunnelID,
			"reason":    "empty message",
		}).Error("Invalid message")
		return nil, ErrInvalidMessage
	}

	// Create simple delivery instructions for local delivery (type DT_LOCAL)
	deliveryInstructions, err := g.createDeliveryInstructions(msgBytes)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "Gateway.Send",
			"tunnel_id": g.tunnelID,
		}).WithError(err).Error("Failed to create delivery instructions")
		return nil, err
	}

	// Build the tunnel message
	tunnelMsg, err := g.buildTunnelMessage(deliveryInstructions, msgBytes)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "Gateway.Send",
			"tunnel_id": g.tunnelID,
		}).WithError(err).Error("Failed to build tunnel message")
		return nil, err
	}

	// Encrypt the tunnel message
	encrypted, err := g.encryptTunnelMessage(tunnelMsg)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "Gateway.Send",
			"tunnel_id": g.tunnelID,
		}).WithError(err).Error("Failed to encrypt tunnel message")
		return nil, err
	}

	log.WithFields(logger.Fields{
		"at":        "(Gateway) Send",
		"reason":    "message_sent",
		"tunnel_id": g.tunnelID,
	}).Debug("successfully sent message through gateway")
	return encrypted, nil
}

// DeliveryConfig specifies the delivery type and addressing for a tunnel message.
type DeliveryConfig struct {
	// DeliveryType: DT_LOCAL (0), DT_TUNNEL (1), or DT_ROUTER (2)
	DeliveryType byte
	// TunnelID is the destination tunnel ID (required for DT_TUNNEL)
	TunnelID uint32
	// Hash is the gateway router hash (DT_TUNNEL) or destination router hash (DT_ROUTER)
	Hash [32]byte
}

// LocalDelivery returns a DeliveryConfig for DT_LOCAL delivery.
func LocalDelivery() DeliveryConfig {
	return DeliveryConfig{DeliveryType: DT_LOCAL}
}

// TunnelDelivery returns a DeliveryConfig for DT_TUNNEL delivery.
func TunnelDelivery(tunnelID uint32, gatewayHash [32]byte) DeliveryConfig {
	return DeliveryConfig{
		DeliveryType: DT_TUNNEL,
		TunnelID:     tunnelID,
		Hash:         gatewayHash,
	}
}

// RouterDelivery returns a DeliveryConfig for DT_ROUTER delivery.
func RouterDelivery(routerHash [32]byte) DeliveryConfig {
	return DeliveryConfig{
		DeliveryType: DT_ROUTER,
		Hash:         routerHash,
	}
}

// deliveryInstructionsSize returns the byte size of delivery instructions for a given config.
func deliveryInstructionsSize(dc DeliveryConfig, fragmented bool) int {
	// flag(1) + size(2) = 3 bytes base
	size := 3
	if dc.DeliveryType == DT_TUNNEL {
		size += 4 + 32 // tunnel ID + hash
	} else if dc.DeliveryType == DT_ROUTER {
		size += 32 // hash
	}
	if fragmented {
		size += 4 // message ID
	}
	return size
}

// maxPayloadForDelivery returns the maximum message payload that fits in a single tunnel
// message for the given delivery type (without fragmentation).
func maxPayloadForDelivery(dc DeliveryConfig) int {
	return maxTunnelPayload - deliveryInstructionsSize(dc, false)
}

// SendWithDelivery sends an I2NP message with the specified delivery type.
// Supports DT_LOCAL, DT_TUNNEL, and DT_ROUTER delivery types.
// Automatically fragments messages that exceed the tunnel payload limit.
//
// Returns a slice of encrypted tunnel messages (one per fragment), or an error.
func (g *Gateway) SendWithDelivery(msgBytes []byte, dc DeliveryConfig) ([][]byte, error) {
	if len(msgBytes) == 0 {
		return nil, ErrInvalidMessage
	}

	maxSingle := maxPayloadForDelivery(dc)

	// If the message fits in a single tunnel message, send without fragmentation
	if len(msgBytes) <= maxSingle {
		di, err := g.createDeliveryInstructionsForConfig(dc, msgBytes, false, 0)
		if err != nil {
			return nil, err
		}
		encrypted, err := g.buildAndEncrypt(di, msgBytes)
		if err != nil {
			return nil, err
		}
		return [][]byte{encrypted}, nil
	}

	// Fragment the message across multiple tunnel messages
	return g.sendFragmented(msgBytes, dc)
}

// sendFragmented splits a message into fragments and sends each as a separate tunnel message.
func (g *Gateway) sendFragmented(msgBytes []byte, dc DeliveryConfig) ([][]byte, error) {
	msgID := atomic.AddUint32(&g.msgIDSeq, 1)

	firstPayloadMax, followPayloadMax, err := g.calculateFragmentSizes(dc)
	if err != nil {
		return nil, err
	}

	// Check if it actually fits in the first fragment after all
	if len(msgBytes) <= firstPayloadMax {
		return g.sendSingleFragment(msgBytes, dc)
	}

	followOnCount, err := g.validateFragmentCount(len(msgBytes), firstPayloadMax, followPayloadMax)
	if err != nil {
		return nil, err
	}

	results, err := g.buildFirstFragment(msgBytes[:firstPayloadMax], dc, msgID)
	if err != nil {
		return nil, err
	}

	followOnResults, err := g.buildFollowOnFragments(msgBytes, firstPayloadMax, followPayloadMax, msgID, followOnCount)
	if err != nil {
		return nil, err
	}
	results = append(results, followOnResults...)

	log.WithFields(logger.Fields{
		"at":             "sendFragmented",
		"tunnel_id":      g.tunnelID,
		"total_size":     len(msgBytes),
		"fragment_count": len(results),
		"msg_id":         msgID,
	}).Debug("Fragmented message across tunnel messages")

	return results, nil
}

// calculateFragmentSizes computes the maximum payload sizes for first and
// follow-on fragments based on the delivery configuration.
func (g *Gateway) calculateFragmentSizes(dc DeliveryConfig) (firstPayloadMax, followPayloadMax int, err error) {
	firstDISize := deliveryInstructionsSize(dc, true)
	firstPayloadMax = maxTunnelPayload - firstDISize
	if firstPayloadMax <= 0 {
		return 0, 0, ErrMessageTooLarge
	}
	const followOnHeaderSize = 7
	followPayloadMax = maxTunnelPayload - followOnHeaderSize
	return firstPayloadMax, followPayloadMax, nil
}

// sendSingleFragment builds and encrypts a single unfragmented tunnel message.
func (g *Gateway) sendSingleFragment(msgBytes []byte, dc DeliveryConfig) ([][]byte, error) {
	di, err := g.createDeliveryInstructionsForConfig(dc, msgBytes, false, 0)
	if err != nil {
		return nil, err
	}
	encrypted, err := g.buildAndEncrypt(di, msgBytes)
	if err != nil {
		return nil, err
	}
	return [][]byte{encrypted}, nil
}

// validateFragmentCount calculates the number of follow-on fragments needed
// and returns an error if the message is too large.
func (g *Gateway) validateFragmentCount(msgLen, firstPayloadMax, followPayloadMax int) (int, error) {
	remaining := msgLen - firstPayloadMax
	followOnCount := (remaining + followPayloadMax - 1) / followPayloadMax
	if followOnCount > 63 {
		return 0, ErrMessageTooLarge
	}
	return followOnCount, nil
}

// buildFirstFragment creates the first fragment with full delivery instructions.
func (g *Gateway) buildFirstFragment(firstData []byte, dc DeliveryConfig, msgID uint32) ([][]byte, error) {
	di, err := g.createDeliveryInstructionsForConfig(dc, firstData, true, msgID)
	if err != nil {
		return nil, err
	}
	encrypted, err := g.buildAndEncrypt(di, firstData)
	if err != nil {
		return nil, err
	}
	return [][]byte{encrypted}, nil
}

// buildFollowOnFragments creates all follow-on fragment tunnel messages.
func (g *Gateway) buildFollowOnFragments(msgBytes []byte, offset, followPayloadMax int, msgID uint32, count int) ([][]byte, error) {
	results := make([][]byte, 0, count)
	for fragNum := 1; offset < len(msgBytes); fragNum++ {
		end := offset + followPayloadMax
		if end > len(msgBytes) {
			end = len(msgBytes)
		}

		fragData := msgBytes[offset:end]
		isLast := end >= len(msgBytes)

		followDI, err := g.createFollowOnInstructions(msgID, fragNum, isLast, fragData)
		if err != nil {
			return nil, err
		}
		encrypted, err := g.buildAndEncrypt(followDI, fragData)
		if err != nil {
			return nil, err
		}
		results = append(results, encrypted)
		offset = end
	}
	return results, nil
}

// buildAndEncrypt builds a tunnel message from delivery instructions and payload, then encrypts it.
func (g *Gateway) buildAndEncrypt(di, payload []byte) ([]byte, error) {
	tunnelMsg, err := g.buildTunnelMessage(di, payload)
	if err != nil {
		return nil, err
	}
	return g.encryptTunnelMessage(tunnelMsg)
}

// createDeliveryInstructionsForConfig creates delivery instructions for any delivery type.
func (g *Gateway) createDeliveryInstructionsForConfig(dc DeliveryConfig, msgBytes []byte, fragmented bool, msgID uint32) ([]byte, error) {
	var di *DeliveryInstructions

	switch dc.DeliveryType {
	case DT_TUNNEL:
		di = NewTunnelDeliveryInstructions(dc.TunnelID, dc.Hash, uint16(len(msgBytes)))
	case DT_ROUTER:
		di = NewRouterDeliveryInstructions(dc.Hash, uint16(len(msgBytes)))
	default: // DT_LOCAL
		di = NewLocalDeliveryInstructions(uint16(len(msgBytes)))
	}

	if fragmented {
		di.fragmented = true
		di.messageID = msgID
	}

	data, err := di.Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize delivery instructions: %w", err)
	}
	return data, nil
}

// createFollowOnInstructions creates follow-on fragment delivery instructions.
func (g *Gateway) createFollowOnInstructions(msgID uint32, fragNum int, isLast bool, fragData []byte) ([]byte, error) {
	di := &DeliveryInstructions{
		fragmentType:   FOLLOW_ON_FRAGMENT,
		fragmentNumber: fragNum,
		lastFragment:   isLast,
		messageID:      msgID,
		fragmentSize:   uint16(len(fragData)),
	}

	data, err := di.Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize follow-on fragment instructions: %w", err)
	}
	return data, nil
}

// createDeliveryInstructions creates DT_LOCAL delivery instructions for a message.
// For messages that exceed the single-message limit, use SendWithDelivery which
// supports fragmentation automatically.
func (g *Gateway) createDeliveryInstructions(msgBytes []byte) ([]byte, error) {
	if len(msgBytes) > maxTunnelPayload-3 {
		log.WithFields(logger.Fields{
			"at":       "createDeliveryInstructions",
			"msg_size": len(msgBytes),
			"max_size": maxTunnelPayload - 3,
			"reason":   "use SendWithDelivery for fragmentation",
		}).Error("Message exceeds tunnel payload limit")
		return nil, ErrMessageTooLarge
	}

	instructions := make([]byte, 3)

	// Byte 0: flags - DT_LOCAL (0) and not fragmented
	instructions[0] = DT_LOCAL

	// Bytes 1-2: message size
	binary.BigEndian.PutUint16(instructions[1:3], uint16(len(msgBytes)))

	return instructions, nil
}

// buildTunnelMessage constructs a complete tunnel message with padding and checksum.
// Tunnel message structure:
// [Tunnel ID (4)] [IV (16)] [Checksum (4)] [Padding (variable)] [0x00] [Instructions] [Message]
func (g *Gateway) buildTunnelMessage(deliveryInstructions, msgBytes []byte) ([]byte, error) {
	totalSize := 1028 // Fixed tunnel message size
	msg := make([]byte, totalSize)

	g.writeTunnelID(msg)

	if err := g.writeIV(msg); err != nil {
		return nil, err
	}

	dataSize := len(deliveryInstructions) + len(msgBytes)
	paddingSize := totalSize - 24 - 1 - dataSize // -1 for zero byte

	if err := g.validatePaddingSize(paddingSize, dataSize, totalSize); err != nil {
		return nil, err
	}

	if err := g.writeRandomPadding(msg, paddingSize); err != nil {
		return nil, err
	}

	g.writePayload(msg, paddingSize, deliveryInstructions, msgBytes)
	g.writeChecksum(msg, paddingSize)

	return msg, nil
}

// writeTunnelID writes the tunnel ID to the message header.
func (g *Gateway) writeTunnelID(msg []byte) {
	binary.BigEndian.PutUint32(msg[0:4], uint32(g.nextHopID))
}

// writeIV generates a random 16-byte IV and writes it to bytes 4-19.
// The IV is used as part of the tunnel message checksum calculation
// and provides randomization for the encryption layer.
func (g *Gateway) writeIV(msg []byte) error {
	if _, err := rand.Read(msg[4:20]); err != nil {
		log.WithFields(logger.Fields{
			"at":     "buildTunnelMessage",
			"reason": "failed to generate random IV",
			"error":  err,
		}).Error("IV generation failed")
		return err
	}
	return nil
}

// validatePaddingSize checks if the padding size is valid.
func (g *Gateway) validatePaddingSize(paddingSize, dataSize, totalSize int) error {
	if paddingSize < 0 {
		log.WithFields(logger.Fields{
			"at":         "buildTunnelMessage",
			"data_size":  dataSize,
			"total_size": totalSize,
			"reason":     "negative padding size",
		}).Error("Message too large for tunnel")
		return ErrMessageTooLarge
	}
	return nil
}

// writeRandomPadding generates and writes random non-zero padding bytes.
// Uses crypto/rand for cryptographically secure random padding.
// I2P spec requires non-zero padding bytes.
func (g *Gateway) writeRandomPadding(msg []byte, paddingSize int) error {
	if paddingSize <= 0 {
		return nil
	}

	paddingBytes := msg[24 : 24+paddingSize]
	if _, err := rand.Read(paddingBytes); err != nil {
		log.WithFields(logger.Fields{
			"at":     "buildTunnelMessage",
			"reason": "failed to generate random padding",
			"error":  err,
		}).Error("Random padding generation failed")
		return err
	}

	replaceZeroPaddingBytes(paddingBytes)
	return nil
}

// replaceZeroPaddingBytes replaces any zero bytes in the padding with random non-zero values.
// I2P spec requires all padding bytes to be non-zero.
func replaceZeroPaddingBytes(paddingBytes []byte) {
	for i := range paddingBytes {
		if paddingBytes[i] == 0 {
			paddingBytes[i] = generateNonZeroByte()
		}
	}
}

// generateNonZeroByte returns a cryptographically random byte in the range [1, 255].
// Falls back to 0x01 if random generation fails or after maxAttempts iterations.
func generateNonZeroByte() byte {
	const maxAttempts = 256
	var b [1]byte
	for i := 0; i < maxAttempts; i++ {
		if _, err := rand.Read(b[:]); err != nil {
			return 1
		}
		if b[0] != 0 {
			return b[0]
		}
	}
	return 1 // Fallback after exhausting attempts (statistically impossible)
}

// writePayload writes the zero separator, delivery instructions, and message to the buffer.
func (g *Gateway) writePayload(msg []byte, paddingSize int, deliveryInstructions, msgBytes []byte) {
	// Zero byte separator
	msg[24+paddingSize] = 0x00

	// Delivery instructions and message
	offset := 24 + paddingSize + 1
	copy(msg[offset:], deliveryInstructions)
	copy(msg[offset+len(deliveryInstructions):], msgBytes)
}

// writeChecksum calculates and writes the checksum.
// Per I2P spec §tunnel-message: "The checksum does NOT cover the padding or
// the zero byte. Take the message starting at the first delivery instructions,
// concatenate the IV, and take the Hash of that."
// Checksum is the first 4 bytes of SHA256(delivery_instructions_and_fragments + IV).
func (g *Gateway) writeChecksum(msg []byte, paddingSize int) {
	// Data after the zero byte separator: delivery instructions + message fragments
	dataStart := 24 + paddingSize + 1 // checksum(4) ends at 24, then padding, then 0x00
	data := msg[dataStart:]
	iv := msg[4:20]
	buf := make([]byte, len(data)+len(iv))
	copy(buf, data)
	copy(buf[len(data):], iv)
	hash := types.SHA256(buf)
	copy(msg[20:24], hash[:4])
}

// encryptTunnelMessage applies tunnel encryption to the message.
// Supports both modern ECIES-X25519 and legacy AES-256-CBC encryption.
func (g *Gateway) encryptTunnelMessage(msg []byte) ([]byte, error) {
	// Use the crypto/tunnel package to encrypt
	// Modern ECIES-X25519 uses ChaCha20/Poly1305 AEAD
	// Legacy AES uses AES-256-CBC with dual-layer encryption

	// Serialize concurrent encryption calls to protect stateful TunnelEncryptor
	// implementations. Current implementations (AES, ECIES) are stateless,
	// but the interface contract does not guarantee this.
	g.encMu.Lock()
	defer g.encMu.Unlock()

	// The TunnelEncryptor interface now returns errors for better error handling
	encrypted, err := g.encryption.Encrypt(msg)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":     "(Gateway) encryptMessage",
			"reason": "encryption_failed",
			"error":  err.Error(),
		}).Error("failed to encrypt tunnel message")
		return nil, err
	}

	return encrypted, nil
}

// TunnelID returns the ID of this gateway's tunnel
func (g *Gateway) TunnelID() TunnelID {
	return g.tunnelID
}

// NextHopID returns the tunnel ID used for the next hop
func (g *Gateway) NextHopID() TunnelID {
	return g.nextHopID
}
