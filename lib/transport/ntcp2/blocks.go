package ntcp2

import (
	"encoding/binary"
	"fmt"
	"time"
)

// NTCP2 data-phase block types per the specification.
//
// Spec reference: https://geti2p.net/spec/ntcp2#data-phase
//
// After the Noise XK handshake completes, both peers exchange AEAD-encrypted
// frames. Each decrypted frame payload consists of one or more concatenated
// blocks. Every block begins with a 3-byte header: [type:1][size:2].
const (
	// BlockTypeDateTime is a DateTime block (type 0).
	// Payload: 4 bytes, unsigned big-endian Unix epoch seconds.
	BlockTypeDateTime byte = 0

	// BlockTypeOptions is an Options block (type 1).
	// Payload: variable length, contains padding/traffic negotiation params.
	BlockTypeOptions byte = 1

	// BlockTypeRouterInfo is a RouterInfo block (type 2).
	// Payload: 1-byte flag + gzip-compressed or raw RouterInfo.
	BlockTypeRouterInfo byte = 2

	// BlockTypeI2NP is an I2NP message block (type 3).
	// Payload: 9-byte short I2NP header + message body.
	BlockTypeI2NP byte = 3

	// BlockTypeTermination is a Termination block (type 4).
	// Payload: version(4) + networkID(1) + time(4) + reason(1) = 10 bytes.
	BlockTypeTermination byte = 4

	// BlockTypePadding is a Padding block (type 254).
	// Payload: arbitrary bytes, ignored by the receiver.
	BlockTypePadding byte = 254
)

// blockHeaderSize is the size of a block header: type (1 byte) + size (2 bytes).
const blockHeaderSize = 3

// Block represents a single parsed NTCP2 data-phase block.
type Block struct {
	// Type is the block type identifier (0–4, 254).
	Type byte

	// Data is the block payload (excluding the 3-byte header).
	Data []byte
}

// ParseBlocks parses a decrypted data-phase frame payload into individual blocks.
// The payload consists of zero or more concatenated [type:1][size:2][data:size] blocks.
// Unknown block types are preserved (returned with their raw data) so the caller
// can decide how to handle them. Returns an error if the payload is truncated.
func ParseBlocks(payload []byte) ([]Block, error) {
	var blocks []Block
	offset := 0

	for offset < len(payload) {
		// Need at least 3 bytes for the block header
		if offset+blockHeaderSize > len(payload) {
			return blocks, fmt.Errorf("truncated block header at offset %d (have %d bytes, need %d)",
				offset, len(payload)-offset, blockHeaderSize)
		}

		blockType := payload[offset]
		blockSize := int(binary.BigEndian.Uint16(payload[offset+1 : offset+3]))
		offset += blockHeaderSize

		if offset+blockSize > len(payload) {
			return blocks, fmt.Errorf("truncated block data at offset %d: type=%d, declared size=%d, available=%d",
				offset-blockHeaderSize, blockType, blockSize, len(payload)-offset)
		}

		data := make([]byte, blockSize)
		copy(data, payload[offset:offset+blockSize])
		blocks = append(blocks, Block{Type: blockType, Data: data})
		offset += blockSize
	}

	return blocks, nil
}

// SerializeBlocks serializes one or more blocks into a single data-phase frame
// payload suitable for writing via NTCP2Conn.Write().
func SerializeBlocks(blocks ...Block) []byte {
	// Calculate total size
	totalSize := 0
	for _, b := range blocks {
		totalSize += blockHeaderSize + len(b.Data)
	}

	payload := make([]byte, totalSize)
	offset := 0
	for _, b := range blocks {
		payload[offset] = b.Type
		binary.BigEndian.PutUint16(payload[offset+1:offset+3], uint16(len(b.Data)))
		copy(payload[offset+blockHeaderSize:], b.Data)
		offset += blockHeaderSize + len(b.Data)
	}

	return payload
}

// NewDateTimeBlock creates a DateTime block (type 0) containing the current
// Unix epoch timestamp as 4 big-endian bytes.
func NewDateTimeBlock() Block {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, uint32(time.Now().Unix()))
	return Block{Type: BlockTypeDateTime, Data: data}
}

// ParseDateTimeBlock extracts the Unix epoch timestamp from a DateTime block's data.
// Returns an error if the data is not exactly 4 bytes.
func ParseDateTimeBlock(data []byte) (time.Time, error) {
	if len(data) != 4 {
		return time.Time{}, fmt.Errorf("DateTime block data must be 4 bytes, got %d", len(data))
	}
	epoch := binary.BigEndian.Uint32(data)
	return time.Unix(int64(epoch), 0), nil
}

// NewI2NPBlock creates an I2NP message block (type 3) from raw I2NP message bytes.
// The caller is responsible for providing the short I2NP header + message body.
func NewI2NPBlock(i2npData []byte) Block {
	return Block{Type: BlockTypeI2NP, Data: i2npData}
}

// NewPaddingBlock creates a Padding block (type 254) with the specified number
// of zero bytes. The receiver ignores the content.
func NewPaddingBlock(size int) Block {
	return Block{Type: BlockTypePadding, Data: make([]byte, size)}
}

// NewRouterInfoBlock creates a RouterInfo block (type 2) with a flag byte
// prepended. Per the spec, the flag byte indicates how the RouterInfo is encoded:
//
//	0x00 = uncompressed
//	0x01 = gzip compressed
//	bit 1 (0x02) = flood request (peer should flood this RouterInfo)
func NewRouterInfoBlock(routerInfoBytes []byte, flag byte) Block {
	data := make([]byte, 1+len(routerInfoBytes))
	data[0] = flag
	copy(data[1:], routerInfoBytes)
	return Block{Type: BlockTypeRouterInfo, Data: data}
}

// BlockTypeString returns a human-readable name for a block type.
func BlockTypeString(blockType byte) string {
	switch blockType {
	case BlockTypeDateTime:
		return "DateTime"
	case BlockTypeOptions:
		return "Options"
	case BlockTypeRouterInfo:
		return "RouterInfo"
	case BlockTypeI2NP:
		return "I2NP"
	case BlockTypeTermination:
		return "Termination"
	case BlockTypePadding:
		return "Padding"
	default:
		return fmt.Sprintf("Unknown(%d)", blockType)
	}
}
