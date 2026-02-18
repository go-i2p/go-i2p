package ntcp2

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Block parsing tests ---

func TestParseBlocks_Empty(t *testing.T) {
	blocks, err := ParseBlocks([]byte{})
	assert.NoError(t, err)
	assert.Empty(t, blocks)
}

func TestParseBlocks_SingleBlock(t *testing.T) {
	// DateTime block: type=0, size=4, data=4 bytes of timestamp
	payload := make([]byte, 7) // 3 header + 4 data
	payload[0] = BlockTypeDateTime
	binary.BigEndian.PutUint16(payload[1:3], 4)
	binary.BigEndian.PutUint32(payload[3:7], uint32(time.Now().Unix()))

	blocks, err := ParseBlocks(payload)
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	assert.Equal(t, BlockTypeDateTime, blocks[0].Type)
	assert.Len(t, blocks[0].Data, 4)
}

func TestParseBlocks_MultipleBlocks(t *testing.T) {
	// Build: DateTime block + Padding block + I2NP block
	dateTimeData := make([]byte, 4)
	binary.BigEndian.PutUint32(dateTimeData, uint32(time.Now().Unix()))

	paddingData := make([]byte, 16)
	i2npData := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

	blocks := []Block{
		{Type: BlockTypeDateTime, Data: dateTimeData},
		{Type: BlockTypePadding, Data: paddingData},
		{Type: BlockTypeI2NP, Data: i2npData},
	}

	payload := SerializeBlocks(blocks...)
	parsed, err := ParseBlocks(payload)
	require.NoError(t, err)
	require.Len(t, parsed, 3)

	assert.Equal(t, BlockTypeDateTime, parsed[0].Type)
	assert.Equal(t, dateTimeData, parsed[0].Data)

	assert.Equal(t, BlockTypePadding, parsed[1].Type)
	assert.Len(t, parsed[1].Data, 16)

	assert.Equal(t, BlockTypeI2NP, parsed[2].Type)
	assert.Equal(t, i2npData, parsed[2].Data)
}

func TestParseBlocks_TruncatedHeader(t *testing.T) {
	// Only 2 bytes — need 3 for header
	_, err := ParseBlocks([]byte{0x00, 0x04})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "truncated block header")
}

func TestParseBlocks_TruncatedData(t *testing.T) {
	// Header says 10 bytes of data, but only 3 available
	payload := []byte{BlockTypeI2NP, 0x00, 0x0A, 0x01, 0x02, 0x03}
	_, err := ParseBlocks(payload)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "truncated block data")
}

func TestParseBlocks_ZeroSizeBlock(t *testing.T) {
	// A block with 0-byte payload is valid (e.g., empty padding)
	payload := []byte{BlockTypePadding, 0x00, 0x00}
	blocks, err := ParseBlocks(payload)
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	assert.Equal(t, BlockTypePadding, blocks[0].Type)
	assert.Len(t, blocks[0].Data, 0)
}

func TestParseBlocks_UnknownType(t *testing.T) {
	// Unknown block type 42 should be preserved
	payload := []byte{42, 0x00, 0x02, 0xAA, 0xBB}
	blocks, err := ParseBlocks(payload)
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	assert.Equal(t, byte(42), blocks[0].Type)
	assert.Equal(t, []byte{0xAA, 0xBB}, blocks[0].Data)
}

// --- Block serialization tests ---

func TestSerializeBlocks_RoundTrip(t *testing.T) {
	original := []Block{
		NewDateTimeBlock(),
		NewPaddingBlock(32),
		NewI2NPBlock([]byte{0xDE, 0xAD, 0xBE, 0xEF}),
	}

	payload := SerializeBlocks(original...)
	parsed, err := ParseBlocks(payload)
	require.NoError(t, err)
	require.Len(t, parsed, len(original))

	for i, orig := range original {
		assert.Equal(t, orig.Type, parsed[i].Type)
		assert.Equal(t, orig.Data, parsed[i].Data)
	}
}

func TestSerializeBlocks_Empty(t *testing.T) {
	payload := SerializeBlocks()
	assert.Empty(t, payload)
}

// --- Block constructors ---

func TestNewDateTimeBlock(t *testing.T) {
	block := NewDateTimeBlock()
	assert.Equal(t, BlockTypeDateTime, block.Type)
	assert.Len(t, block.Data, 4)

	ts, err := ParseDateTimeBlock(block.Data)
	require.NoError(t, err)

	// Should be within 2 seconds of now
	now := time.Now()
	assert.WithinDuration(t, now, ts, 2*time.Second)
}

func TestParseDateTimeBlock_InvalidSize(t *testing.T) {
	_, err := ParseDateTimeBlock([]byte{0x01, 0x02})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be 4 bytes")
}

func TestNewPaddingBlock(t *testing.T) {
	block := NewPaddingBlock(64)
	assert.Equal(t, BlockTypePadding, block.Type)
	assert.Len(t, block.Data, 64)
	// All zeros
	for _, b := range block.Data {
		assert.Equal(t, byte(0), b)
	}
}

func TestNewRouterInfoBlock(t *testing.T) {
	ri := []byte{0x01, 0x02, 0x03}
	block := NewRouterInfoBlock(ri, 0x01) // gzip flag
	assert.Equal(t, BlockTypeRouterInfo, block.Type)
	assert.Len(t, block.Data, 4) // 1 flag + 3 RI
	assert.Equal(t, byte(0x01), block.Data[0])
	assert.Equal(t, ri, block.Data[1:])
}

func TestBlockTypeString(t *testing.T) {
	tests := []struct {
		blockType byte
		expected  string
	}{
		{BlockTypeDateTime, "DateTime"},
		{BlockTypeOptions, "Options"},
		{BlockTypeRouterInfo, "RouterInfo"},
		{BlockTypeI2NP, "I2NP"},
		{BlockTypeTermination, "Termination"},
		{BlockTypePadding, "Padding"},
		{99, "Unknown(99)"},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expected, BlockTypeString(tt.blockType))
	}
}

// --- Termination block integration with block framing ---

func TestTerminationBlockInSerializedPayload(t *testing.T) {
	termBlock := BuildTerminationBlock(TerminationNormalClose)
	// BuildTerminationBlock already includes the block header, so it should
	// be parseable directly
	blocks, err := ParseBlocks(termBlock)
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	assert.Equal(t, BlockTypeTermination, blocks[0].Type)
	assert.Equal(t, TerminationNormalClose, blocks[0].Data[len(blocks[0].Data)-1])
}
