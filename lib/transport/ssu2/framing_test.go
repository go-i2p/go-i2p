package ssu2

import (
	"errors"
	"testing"

	"github.com/go-i2p/go-i2p/lib/i2np"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failMarshalMsg is a minimal I2NPMessage whose MarshalBinary always fails.
type failMarshalMsg struct {
	i2np.Message
}

func (f *failMarshalMsg) MarshalBinary() ([]byte, error) {
	return nil, errors.New("marshal error")
}

func TestFrameI2NPToBlock(t *testing.T) {
	msg := i2np.NewBaseI2NPMessage(i2np.I2NPMessageTypeData)
	msg.SetData([]byte("test payload"))
	block, err := FrameI2NPToBlock(msg)
	require.NoError(t, err)
	assert.Equal(t, ssu2noise.BlockTypeI2NPMessage, block.Type)
	assert.NotEmpty(t, block.Data)
}

func TestParseI2NPFromBlock(t *testing.T) {
	msg := i2np.NewBaseI2NPMessage(i2np.I2NPMessageTypeData)
	msg.SetData([]byte("test payload"))
	block, err := FrameI2NPToBlock(msg)
	require.NoError(t, err)
	parsed, err := ParseI2NPFromBlock(block)
	require.NoError(t, err)
	assert.Equal(t, msg.Type(), parsed.Type())
	assert.Equal(t, msg.MessageID(), parsed.MessageID())
}

func TestParseI2NPFromBlock_WrongType(t *testing.T) {
	block := ssu2noise.NewSSU2Block(ssu2noise.BlockTypePadding, []byte("data"))
	_, err := ParseI2NPFromBlock(block)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected block type")
}

func TestParseI2NPFromBlock_EmptyData(t *testing.T) {
	block := ssu2noise.NewSSU2Block(ssu2noise.BlockTypeI2NPMessage, nil)
	_, err := ParseI2NPFromBlock(block)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestFrameI2NPForSSU2Roundtrip(t *testing.T) {
	msg := i2np.NewBaseI2NPMessage(i2np.I2NPMessageTypeDeliveryStatus)
	msg.SetData([]byte("delivery-data"))
	data, err := FrameI2NPForSSU2(msg)
	require.NoError(t, err)
	assert.NotEmpty(t, data)
	parsed, err := ParseI2NPFromSSU2(data)
	require.NoError(t, err)
	assert.Equal(t, msg.Type(), parsed.Type())
}

func TestParseI2NPFromSSU2_EmptyData(t *testing.T) {
	_, err := ParseI2NPFromSSU2(nil)
	assert.Error(t, err)
}

func TestNewDateTimeBlock(t *testing.T) {
	block := NewDateTimeBlock()
	assert.Equal(t, ssu2noise.BlockTypeDateTime, block.Type)
	assert.Len(t, block.Data, 4)
}

func TestNewPaddingBlock(t *testing.T) {
	block := NewPaddingBlock(32)
	assert.Equal(t, ssu2noise.BlockTypePadding, block.Type)
	assert.Len(t, block.Data, 32)
}

// TestFrameI2NPToBlock_MarshalError verifies that FrameI2NPToBlock propagates
// a MarshalBinary error from the message.
func TestFrameI2NPToBlock_MarshalError(t *testing.T) {
	msg := &failMarshalMsg{}
	_, err := FrameI2NPToBlock(msg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "marshal error")
}

// TestFrameI2NPForSSU2_MarshalError verifies that FrameI2NPForSSU2 propagates
// a MarshalBinary error from the message.
func TestFrameI2NPForSSU2_MarshalError(t *testing.T) {
	msg := &failMarshalMsg{}
	_, err := FrameI2NPForSSU2(msg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "marshal error")
}

// TestParseACKBlock_WraparoundCheck verifies that ParseACKBlock correctly handles
// the case where FirstPacketNum is near the uint32 maximum and expanding the packet
// range would cause integer wraparound. This is a security-relevant test: a malicious
// peer sending FirstPacketNum=0xFFFFFFF8 with NackCount>0 should not wrap into low
// packet numbers.
func TestParseACKBlock_WraparoundCheck(t *testing.T) {
	// Create an ACK block with FirstPacketNum near maximum
	// 0xFFFFFFF8 = 4294967288; with NackCount=1, we'd normally expand to 4294967296 (wraps to 0)
	data := make([]byte, 6) // 4 bytes (FirstPacketNum) + 1 byte (NackCount) + 1 byte (nack field)
	firstPacketNum := uint32(0xFFFFFFF8)
	data[0] = byte(firstPacketNum >> 24)
	data[1] = byte(firstPacketNum >> 16)
	data[2] = byte(firstPacketNum >> 8)
	data[3] = byte(firstPacketNum)
	data[4] = 1    // NackCount = 1 (one nack field)
	data[5] = 0x00 // Nack field: 0x00 means all 8 packets are ACKed

	block := ssu2noise.NewSSU2Block(ssu2noise.BlockTypeACK, data)
	info, err := ParseACKBlock(block)
	require.NoError(t, err)

	// Verify the AckedRange does NOT wrap past 0xFFFFFFFF
	// Should contain [0xFFFFFFF8, 0xFFFFFFF9, ..., 0xFFFFFFFF], but NOT 0x00000000, 0x00000001, etc.
	assert.Greater(t, len(info.AckedRange), 0, "should have at least one ACKed packet")
	for _, pkt := range info.AckedRange {
		assert.GreaterOrEqual(t, pkt, firstPacketNum, "ACKed packet should not wrap past maximum")
	}
	// With FirstPacketNum=0xFFFFFFF8 and NackCount=1 with all bits 0, we expect 8 packets ACKed
	// but stopping before wraparound, so we should get 8 packets: [0xFFFFFFF8...0xFFFFFFFF]
	assert.Len(t, info.AckedRange, 8, "should ACK exactly 8 packets up to 0xFFFFFFFF")
}
