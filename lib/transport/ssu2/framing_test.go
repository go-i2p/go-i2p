package ssu2

import (
	"testing"

	"github.com/go-i2p/go-i2p/lib/i2np"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
