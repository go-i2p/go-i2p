package ntcp2

import (
	"io"
	"net"

	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// FrameI2NPMessageAsBlock frames an I2NP message using NTCP2 block format.
// The message is serialized with a 9-byte short header and wrapped in a type-3
// (I2NP) block. The result can be combined with other blocks via SerializeBlocks.
// The 9-byte short header is mandatory for every NTCP2 data-phase I2NP block,
// regardless of the concrete message type. i2pd reconstructs the full 16-byte
// header by reading the 9-byte short header and adding 7 bytes (NTCP2.cpp
// FromNTCP2); sending a 16-byte standard header here would shift the payload by
// 7 bytes and corrupt every message. The 16-byte standard header is only used
// for tunnel-delivered messages (inside TunnelGateway/TunnelData), never here.
// Spec reference: https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ntcp2.rst
func FrameI2NPMessageAsBlock(msg i2np.Message) ([]byte, error) {
	log.WithField("message_type", msg.Type()).Debug("Framing I2NP message as NTCP2 block")

	// Use the short I2NP header format for NTCP2 blocks. MarshalMessageShort
	// handles every concrete message type uniformly (BaseI2NPMessage and typed
	// structs such as *DatabaseStore alike).
	shortData, err := i2np.MarshalMessageShort(msg)
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

// BlockUnframer reads NTCP2 block-framed data from a connection and extracts
// I2NP messages. It handles all block types per the NTCP2 spec.
type BlockUnframer struct {
	conn           net.Conn
	bytesRead      int // Track bytes read in last operation
	totalBytesRead int // Track cumulative bytes read
	// bufferedMsgs holds I2NP messages extracted from multi-block frames
	bufferedMsgs []i2np.Message
	// BlockCallback is called for non-I2NP blocks (DateTime, Options, etc.)
	BlockCallback func(block Block)
}

// NewBlockUnframer creates an unframer for NTCP2 block-based protocol.
// It parses the spec-compliant block format used in the NTCP2 data phase,
// including the 2-byte SipHash-obfuscated length field. See also [BlockUnframer] and [Block].
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

// ReadNextMessage reads and parses NTCP2 frames until an I2NP message is found
// or the connection is closed. Non-I2NP blocks are passed to BlockCallback.
// Multiple I2NP messages in a single frame are buffered for subsequent calls.
// Uses an iterative loop rather than recursion so that a peer sending an
// unbounded stream of non-I2NP (e.g. padding-only) frames cannot cause a
// goroutine stack overflow.
func (u *BlockUnframer) ReadNextMessage() (i2np.Message, error) {
	for {
		// Return buffered messages first
		if len(u.bufferedMsgs) > 0 {
			msg := u.bufferedMsgs[0]
			u.bufferedMsgs = u.bufferedMsgs[1:]
			return msg, nil
		}

		u.bytesRead = 0

		// Read frame data from the connection.
		// NTCP2Conn.Read() handles SipHash length deobfuscation and AEAD
		// decryption, returning the decrypted payload containing blocks.
		payload, err := u.readFrame()
		if err != nil {
			return nil, err
		}

		// Parse blocks from the decrypted payload
		blocks, err := ParseBlocks(payload)
		if err != nil {
			log.WithError(err).Error("Failed to parse NTCP2 blocks")
			return nil, oops.Wrapf(err, "failed to parse NTCP2 blocks")
		}

		// Enforce the spec's data-phase block ordering rules before any block
		// is processed (ntcp2.rst:1455-1469, :1675, :1742): padding must be
		// last, at most one padding block, termination last except for
		// padding. A violation is fatal to the connection.
		if err := ValidateDataPhaseBlockOrder(blocks); err != nil {
			log.WithError(err).Warn("NTCP2 frame violates block ordering rules, dropping connection")
			return nil, oops.Wrapf(err, "invalid NTCP2 block ordering")
		}

		// Process blocks, extracting I2NP messages
		firstMsg, terminated := u.processBlocks(blocks)
		if terminated {
			return nil, io.EOF
		}

		if firstMsg != nil {
			return firstMsg, nil
		}
		// No I2NP message in this frame — loop to read the next frame
	}
}

// processBlocks handles each block type, returning the first I2NP message found
// and whether a termination block was received. Additional I2NP messages are buffered.
func (u *BlockUnframer) processBlocks(blocks []Block) (firstMsg i2np.Message, terminated bool) {
	for _, block := range blocks {
		msg, term := u.processBlock(block)
		if term {
			return nil, true
		}
		if msg != nil {
			if firstMsg == nil {
				firstMsg = msg
			} else {
				u.bufferedMsgs = append(u.bufferedMsgs, msg)
			}
		}
	}
	return firstMsg, false
}

// processBlock handles a single NTCP2 block by type.
// Returns an I2NP message if this is an I2NP block, and terminated=true if termination.
func (u *BlockUnframer) processBlock(block Block) (msg i2np.Message, terminated bool) {
	switch block.Type {
	case BlockTypeI2NP:
		parsedMsg, err := u.parseI2NPBlock(block.Data)
		if err != nil {
			log.WithError(err).Warn("Failed to parse I2NP block, skipping")
			return nil, false
		}
		return parsedMsg, false
	case BlockTypeTermination:
		log.WithFields(logger.Fields{"at": "processBlock"}).Debug("Received termination block")
		if u.BlockCallback != nil {
			u.BlockCallback(block)
		}
		return nil, true
	default:
		// DateTime, Options, Padding, RouterInfo - pass to callback
		if u.BlockCallback != nil {
			u.BlockCallback(block)
		}
		return nil, false
	}
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
func (u *BlockUnframer) parseI2NPBlock(data []byte) (i2np.Message, error) {
	if len(data) < i2np.ShortI2NPHeaderSize {
		return nil, oops.Errorf("I2NP block data too short: %d bytes", len(data))
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
