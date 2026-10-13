// Tests for I2NP-to-block framing. Validates that I2NP messages are wrapped
// into SSU2 blocks and back, and that ACK block parsing handles packet
// number ranges without integer wraparound.

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

// TestParseACKBlock_SpecExample verifies that ParseACKBlock correctly parses
// the example from the SSU2 spec: ACK 10 9 8 6 5 2 1 0, NACK 7 4 3.
// Wire format: AckThrough=10, acnt=2, range(1,2), range(2,3).
// See [I2P Spec: SSU2 Ack Block](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ssu2.rst#ack).
func TestParseACKBlock_SpecExample(t *testing.T) {
	// Build the block data:
	// AckThrough=10 (4 bytes BE), acnt=2, range(nack=1,ack=2), range(nack=2,ack=3)
	data := []byte{
		0x00, 0x00, 0x00, 0x0A, // AckThrough = 10
		0x02,       // acnt = 2 (packets 9, 8 also acked)
		0x01, 0x02, // range: nack 7, ack 6 5
		0x02, 0x03, // range: nack 4 3, ack 2 1 0
	}

	block := ssu2noise.NewSSU2Block(ssu2noise.BlockTypeACK, data)
	info, err := ParseACKBlock(block)
	require.NoError(t, err)

	assert.Equal(t, uint32(10), info.AckThrough)
	assert.Equal(t, uint8(2), info.AckCount)
	assert.Len(t, info.Ranges, 2)
	assert.Equal(t, ACKRange{NackCount: 1, AckCount: 2}, info.Ranges[0])
	assert.Equal(t, ACKRange{NackCount: 2, AckCount: 3}, info.Ranges[1])

	// Verify the expanded acked range matches the spec example
	expected := []uint32{10, 9, 8, 6, 5, 2, 1, 0}
	assert.Equal(t, expected, info.AckedRange)
}

// TestParseACKBlock_MinimumSize verifies that a minimal ACK block (5 bytes,
// no ranges) correctly acks only the AckThrough packet.
func TestParseACKBlock_MinimumSize(t *testing.T) {
	// AckThrough=100, acnt=0, no ranges
	data := []byte{
		0x00, 0x00, 0x00, 0x64, // AckThrough = 100
		0x00, // acnt = 0
	}

	block := ssu2noise.NewSSU2Block(ssu2noise.BlockTypeACK, data)
	info, err := ParseACKBlock(block)
	require.NoError(t, err)

	assert.Equal(t, uint32(100), info.AckThrough)
	assert.Equal(t, uint8(0), info.AckCount)
	assert.Empty(t, info.Ranges)
	assert.Equal(t, []uint32{100}, info.AckedRange)
}

// TestParseACKBlock_UnderflowProtection verifies that ParseACKBlock does not
// underflow below packet number 0 when ranges extend past the start of the
// packet number space. A malicious peer sending large nack/ack counts with
// a low AckThrough should not cause integer underflow.
func TestParseACKBlock_UnderflowProtection(t *testing.T) {
	// AckThrough=5, acnt=3, range(nack=0, ack=255)
	// This would try to ack 5,4,3,2,1,0 then continue with 255 more (underflow)
	data := []byte{
		0x00, 0x00, 0x00, 0x05, // AckThrough = 5
		0x03,       // acnt = 3 (packets 4, 3, 2)
		0x00, 0xFF, // range: nack 0, ack 255
	}

	block := ssu2noise.NewSSU2Block(ssu2noise.BlockTypeACK, data)
	info, err := ParseACKBlock(block)
	require.NoError(t, err)

	// Should ack 5, 4, 3, 2 (from acnt), then 1, 0 (from range, stops at 0)
	// Total: 6 packets, all >= 0
	assert.Equal(t, []uint32{5, 4, 3, 2, 1, 0}, info.AckedRange)
}

// TestParseACKBlock_WrongType verifies that ParseACKBlock rejects blocks
// with an incorrect type.
func TestParseACKBlock_WrongType(t *testing.T) {
	block := ssu2noise.NewSSU2Block(ssu2noise.BlockTypePadding, make([]byte, 5))
	_, err := ParseACKBlock(block)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected ACK block")
}

// TestParseACKBlock_TooShort verifies that ParseACKBlock rejects blocks
// with fewer than 5 bytes of data.
func TestParseACKBlock_TooShort(t *testing.T) {
	block := ssu2noise.NewSSU2Block(ssu2noise.BlockTypeACK, make([]byte, 4))
	_, err := ParseACKBlock(block)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}
