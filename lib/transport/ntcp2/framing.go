package ntcp2

import (
	"fmt"
	"io"
	"net"

	"github.com/go-i2p/go-i2p/lib/i2np"
)

// FrameI2NPMessageAsBlock frames an I2NP message using NTCP2 block format.
// The message is serialized with a 9-byte short header and wrapped in a type-3
// (I2NP) block. The result can be combined with other blocks via SerializeBlocks.
//
// Spec reference: https://geti2p.net/spec/ntcp2#data-phase
func FrameI2NPMessageAsBlock(msg i2np.I2NPMessage) ([]byte, error) {
	log.WithField("message_type", msg.Type()).Debug("Framing I2NP message as NTCP2 block")

	// Use the short I2NP header format for NTCP2 blocks
	baseMsg, ok := msg.(*i2np.BaseI2NPMessage)
	if !ok {
		// Fall back to standard marshal for non-base messages
		data, err := msg.MarshalBinary()
		if err != nil {
			log.WithError(err).Error("Failed to marshal I2NP message")
			return nil, err
		}
		block := NewI2NPBlock(data)
		return SerializeBlocks(block), nil
	}

	shortData, err := baseMsg.MarshalShortI2NP()
	if err != nil {
		log.WithError(err).Error("Failed to marshal I2NP message with short header")
		return nil, err
	}

	// Wrap in I2NP block and serialize
	block := NewI2NPBlock(shortData)
	payload := SerializeBlocks(block)

	log.WithFields(map[string]interface{}{
		"message_type":   msg.Type(),
		"short_data_len": len(shortData),
		"block_payload":  len(payload),
	}).Debug("I2NP message framed as NTCP2 block successfully")

	return payload, nil
}

// FrameI2NPMessage frames an I2NP message using legacy 4-byte length prefix format.
// Deprecated: Use FrameI2NPMessageAsBlock for NTCP2 spec-compliant framing.
func FrameI2NPMessage(msg i2np.I2NPMessage) ([]byte, error) {
	log.WithField("message_type", msg.Type()).Debug("Framing I2NP message")

	// Convert I2NP message to bytes
	data, err := msg.MarshalBinary()
	if err != nil {
		log.WithError(err).Error("Failed to marshal I2NP message")
		return nil, err
	}

	// Create a framed message with length prefix
	length := len(data)
	framedMessage := make([]byte, 4+length)
	copy(framedMessage[4:], data)

	// Write the length prefix
	framedMessage[0] = byte(length >> 24)
	framedMessage[1] = byte(length >> 16)
	framedMessage[2] = byte(length >> 8)
	framedMessage[3] = byte(length)

	log.WithFields(map[string]interface{}{
		"message_type":   msg.Type(),
		"message_length": length,
		"framed_length":  len(framedMessage),
	}).Debug("I2NP message framed successfully")
	return framedMessage, nil
}

// Unframe I2NP messages from NTCP2 data stream
func UnframeI2NPMessage(conn net.Conn) (i2np.I2NPMessage, error) {
	// Read the next message from the connection
	unframer := NewI2NPUnframer(conn)
	return unframer.ReadNextMessage()
}

// Stream-based unframing for continuous reading
type I2NPUnframer struct {
	conn           net.Conn
	bytesRead      int // Track bytes read in last operation
	totalBytesRead int // Track cumulative bytes read
}

func NewI2NPUnframer(conn net.Conn) *I2NPUnframer {
	return &I2NPUnframer{
		conn:           conn,
		bytesRead:      0,
		totalBytesRead: 0,
	}
}

// BytesRead returns the number of bytes read during the last ReadNextMessage call
func (u *I2NPUnframer) BytesRead() int {
	return u.bytesRead
}

func (u *I2NPUnframer) ReadNextMessage() (i2np.I2NPMessage, error) {
	log.Debug("Reading next framed message from connection")

	// Reset byte counter for this read operation
	u.bytesRead = 0

	// Read the NTCP2 length prefix (4 bytes)
	lengthBuf := make([]byte, 4)
	if err := u.readFull(lengthBuf); err != nil {
		log.WithError(err).Error("Failed to read message length prefix")
		return nil, err
	}

	// Extract length from big-endian bytes
	length := int(lengthBuf[0])<<24 | int(lengthBuf[1])<<16 | int(lengthBuf[2])<<8 | int(lengthBuf[3])
	log.WithField("message_length", length).Debug("Read message length prefix")

	// Validate message length to prevent memory exhaustion attacks
	// NTCP2 limit is approximately 64KB - 20 = 65516 bytes per I2NP specification
	const maxI2NPMessageSize = 65516
	if length > maxI2NPMessageSize || length < 0 {
		log.WithFields(map[string]interface{}{
			"length":   length,
			"max_size": maxI2NPMessageSize,
		}).Error("Message length exceeds maximum allowed size")
		return nil, fmt.Errorf("message length %d exceeds max %d", length, maxI2NPMessageSize)
	}

	// Read the I2NP message data
	messageBuf := make([]byte, length)
	if err := u.readFull(messageBuf); err != nil {
		log.WithError(err).WithField("expected_length", length).Error("Failed to read message data")
		return nil, err
	}

	// Unmarshal the I2NP message
	msg := &i2np.BaseI2NPMessage{}
	if err := msg.UnmarshalBinary(messageBuf); err != nil {
		log.WithError(err).WithField("message_length", length).Error("Failed to unmarshal I2NP message")
		return nil, err
	}

	log.WithFields(map[string]interface{}{
		"message_type":   msg.Type(),
		"message_length": length,
		"bytes_read":     u.bytesRead,
	}).Debug("Successfully read and unframed I2NP message")
	return msg, nil
}

func (u *I2NPUnframer) readFull(buf []byte) error {
	n, err := io.ReadFull(u.conn, buf)
	u.bytesRead += n
	u.totalBytesRead += n
	return err
}

// BlockUnframer reads NTCP2 block-framed data from a connection and extracts
// I2NP messages. It handles all block types per the NTCP2 spec.
type BlockUnframer struct {
	conn           net.Conn
	bytesRead      int // Track bytes read in last operation
	totalBytesRead int // Track cumulative bytes read
	// bufferedMsgs holds I2NP messages extracted from multi-block frames
	bufferedMsgs []i2np.I2NPMessage
	// BlockCallback is called for non-I2NP blocks (DateTime, Options, etc.)
	BlockCallback func(block Block)
}

// NewBlockUnframer creates an unframer for NTCP2 block-based protocol.
func NewBlockUnframer(conn net.Conn) *BlockUnframer {
	return &BlockUnframer{
		conn:         conn,
		bufferedMsgs: nil,
	}
}

// BytesRead returns the number of bytes read during the last ReadNextMessage call.
func (u *BlockUnframer) BytesRead() int {
	return u.bytesRead
}

// ReadNextMessage reads and parses the next NTCP2 frame, returning the first
// I2NP message found. Non-I2NP blocks are passed to BlockCallback if set.
// Multiple I2NP messages in a single frame are buffered for subsequent calls.
func (u *BlockUnframer) ReadNextMessage() (i2np.I2NPMessage, error) {
	// Return buffered messages first
	if len(u.bufferedMsgs) > 0 {
		msg := u.bufferedMsgs[0]
		u.bufferedMsgs = u.bufferedMsgs[1:]
		return msg, nil
	}

	u.bytesRead = 0

	// Read frame data from the connection
	// The NTCP2Conn.Read() handles SipHash length deobfuscation and AEAD decryption,
	// returning the decrypted payload which contains concatenated blocks.
	payload, err := u.readFrame()
	if err != nil {
		return nil, err
	}

	// Parse blocks from the decrypted payload
	blocks, err := ParseBlocks(payload)
	if err != nil {
		log.WithError(err).Error("Failed to parse NTCP2 blocks")
		return nil, fmt.Errorf("failed to parse NTCP2 blocks: %w", err)
	}

	// Process blocks, extracting I2NP messages
	var firstMsg i2np.I2NPMessage
	for _, block := range blocks {
		switch block.Type {
		case BlockTypeI2NP:
			msg, err := u.parseI2NPBlock(block.Data)
			if err != nil {
				log.WithError(err).Warn("Failed to parse I2NP block, skipping")
				continue
			}
			if firstMsg == nil {
				firstMsg = msg
			} else {
				u.bufferedMsgs = append(u.bufferedMsgs, msg)
			}
		case BlockTypeTermination:
			log.Debug("Received termination block")
			if u.BlockCallback != nil {
				u.BlockCallback(block)
			}
			return nil, io.EOF
		default:
			// DateTime, Options, Padding, RouterInfo - pass to callback
			if u.BlockCallback != nil {
				u.BlockCallback(block)
			}
		}
	}

	if firstMsg == nil {
		// No I2NP message in this frame, read another
		return u.ReadNextMessage()
	}

	return firstMsg, nil
}

// readFrame reads a single frame from the connection.
// Since NTCP2Conn.Read() returns decrypted payload data, we need to read
// whatever is available in a single read operation.
func (u *BlockUnframer) readFrame() ([]byte, error) {
	// NTCP2Conn.Read() returns decrypted frame payload
	// Max frame payload is ~64KB, allocate a buffer for it
	buf := make([]byte, 65536)
	n, err := u.conn.Read(buf)
	if err != nil {
		return nil, err
	}
	u.bytesRead = n
	u.totalBytesRead += n
	return buf[:n], nil
}

// parseI2NPBlock parses an I2NP message from block data using short header format.
func (u *BlockUnframer) parseI2NPBlock(data []byte) (i2np.I2NPMessage, error) {
	if len(data) < i2np.ShortI2NPHeaderSize {
		return nil, fmt.Errorf("I2NP block data too short: %d bytes", len(data))
	}

	msg := &i2np.BaseI2NPMessage{}
	if err := msg.UnmarshalShortI2NP(data); err != nil {
		return nil, err
	}

	log.WithFields(map[string]interface{}{
		"message_type": msg.Type(),
		"message_id":   msg.MessageID(),
		"data_len":     len(data),
	}).Debug("Parsed I2NP message from block")

	return msg, nil
}
