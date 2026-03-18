package ssu2

import (
	"testing"

	"github.com/go-i2p/go-i2p/lib/i2np"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFragmentI2NPMessage_NoFragmentation(t *testing.T) {
	msg := i2np.NewBaseI2NPMessage(i2np.I2NPMessageTypeData)
	msg.SetData([]byte("small payload"))
	blocks, err := FragmentI2NPMessage(msg, maxSSU2PayloadIPv4)
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	assert.Equal(t, ssu2noise.BlockTypeI2NPMessage, blocks[0].Type)
}

func TestFragmentI2NPMessage_RequiresFragmentation(t *testing.T) {
	msg := i2np.NewBaseI2NPMessage(i2np.I2NPMessageTypeData)
	largePayload := make([]byte, 2000)
	for i := range largePayload {
		largePayload[i] = byte(i % 256)
	}
	msg.SetData(largePayload)
	blocks, err := FragmentI2NPMessage(msg, 200)
	require.NoError(t, err)
	require.Greater(t, len(blocks), 1)
	assert.Equal(t, ssu2noise.BlockTypeFirstFragment, blocks[0].Type)
	for i := 1; i < len(blocks); i++ {
		assert.Equal(t, ssu2noise.BlockTypeFollowOnFragment, blocks[i].Type)
	}
}

func TestFragmentData_Roundtrip(t *testing.T) {
	data := make([]byte, 500)
	for i := range data {
		data[i] = byte(i % 256)
	}
	messageID := uint32(12345)
	blocks, err := fragmentData(data, messageID, 100)
	require.NoError(t, err)
	require.Greater(t, len(blocks), 1)
	first := blocks[0]
	assert.Equal(t, ssu2noise.BlockTypeFirstFragment, first.Type)
	assert.True(t, len(first.Data) >= 8, "first fragment must have at least 8 bytes header")
}

func TestBuildFirstFragment(t *testing.T) {
	data := []byte("hello")
	block := buildFirstFragment(42, 100, data)
	assert.Equal(t, ssu2noise.BlockTypeFirstFragment, block.Type)
	assert.Len(t, block.Data, 8+len(data))
}

func TestBuildFollowOnFragment(t *testing.T) {
	data := []byte("world")
	block := buildFollowOnFragment(42, 1, data)
	assert.Equal(t, ssu2noise.BlockTypeFollowOnFragment, block.Type)
	assert.Len(t, block.Data, 5+len(data))
}

func TestFragmentData_TooSmallPayload(t *testing.T) {
	data := make([]byte, 100)
	_, err := fragmentData(data, 1, 5)
	assert.Error(t, err)
}
