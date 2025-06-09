package i2np

import (
	"testing"

	common "github.com/go-i2p/go-i2p/lib/common/data"
	"github.com/go-i2p/go-i2p/lib/common/session_key"

	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
)

func TestReadGarlicCloveDeliveryInstructionsFlagTooLittleData(t *testing.T) {
	assert := assert.New(t)

	length, flag, err := readGarlicCloveDeliveryInstructionsFlag([]byte{})
	assert.Equal(0, length)
	assert.Equal(byte(0), flag)
	assert.Equal(ERR_GARLIC_CLOVE_DELIVERY_INSTRUCTIONS_NOT_ENOUGH_DATA, err)
}

func TestReadGarlicCloveDeliveryInstructionsFlagValidData(t *testing.T) {
	assert := assert.New(t)

	data := make([]byte, 1)
	data[0] = 0x31
	length, flag, err := readGarlicCloveDeliveryInstructionsFlag(data)
	expected := byte(data[0])

	assert.Equal(1, length)
	assert.Equal(expected, flag)
	assert.Equal(nil, err)
}

func TestReadGarlicCloveDeliveryInstructionsSessionKeyTooLittleData(t *testing.T) {
	assert := assert.New(t)

	length, sessionKey, err := readGarlicCloveDeliveryInstructionsSessionKey(1, []byte{0x13, 0x31, 0x53, 0x12})
	assert.Equal(1, length)
	assert.Equal(session_key.SessionKey{}, sessionKey)
	assert.Equal(ERR_GARLIC_CLOVE_DELIVERY_INSTRUCTIONS_NOT_ENOUGH_DATA, err)
}

func TestReadGarlicCloveDeliveryInstructionsSessionKeyValidData(t *testing.T) {
	assert := assert.New(t)

	length := 1
	data := make([]byte, length)
	expectedData := make([]byte, 32)
	expectedData[13] = 0x11
	expectedData[19] = 0x33
	data = append(data, expectedData...)
	length, sessionKey, err := readGarlicCloveDeliveryInstructionsSessionKey(length, data)

	assert.Equal(33, length)
	assert.Equal(session_key.SessionKey(expectedData), sessionKey)
	assert.Equal(nil, err)
}

func TestReadGarlicCloveDeliveryInstructionsHashTooLittleData(t *testing.T) {
	assert := assert.New(t)

	length := 33
	data := make([]byte, length)
	data = append(data, []byte{0x33, 0x13, 0x11}...)
	length, hash, err := readGarlicCloveDeliveryInstructionsHash(length, data)
	assert.Equal(33, length)
	assert.Equal(common.Hash{}, hash)
	assert.Equal(ERR_GARLIC_CLOVE_DELIVERY_INSTRUCTIONS_NOT_ENOUGH_DATA, err)
}

func TestReadGarlicCloveDeliveryInstructionsHashValidData(t *testing.T) {
	assert := assert.New(t)

	length := 33
	data := make([]byte, length)
	expectedData := make([]byte, 32)
	expectedData[11] = 0x32
	expectedData[22] = 0x23
	data = append(data, expectedData...)
	length, hash, err := readGarlicCloveDeliveryInstructionsHash(length, data)

	assert.Equal(65, length)
	assert.Equal(common.Hash(expectedData), hash)
	assert.Equal(nil, err)
}

func TestReadGarlicCloveDeliveryInstructionsTunnelIDTooLittleData(t *testing.T) {
	assert := assert.New(t)

	length := 65
	data := make([]byte, length)
	data = append(data, []byte{0x33, 0x13}...)
	length, tunnelID, err := readGarlicCloveDeliveryInstructionsTunnelID(length, data)

	assert.Equal(65, length)
	assert.Equal(tunnel.TunnelID(0), tunnelID)
	assert.Equal(ERR_GARLIC_CLOVE_DELIVERY_INSTRUCTIONS_NOT_ENOUGH_DATA, err)
}

func TestReadGarlicCloveDeliveryInstructionsTunnelIDValidData(t *testing.T) {
	assert := assert.New(t)

	length := 65
	data := make([]byte, length)
	expectedData := []byte{0x34, 0x13, 0x31, 0x46}
	data = append(data, expectedData...)
	length, tunnelID, err := readGarlicCloveDeliveryInstructionsTunnelID(length, data)

	expectedTunnelID := tunnel.TunnelID(
		common.Integer(expectedData).Int(),
	)
	assert.Equal(69, length)
	assert.Equal(expectedTunnelID, tunnelID)
	assert.Equal(nil, err)
}

func TestReadGarlicCloveDeliveryInstructionsDelayTooLittleData(t *testing.T) {
	assert := assert.New(t)

	length := 69
	data := make([]byte, length)
	data = append(data, []byte{0x33, 0x13}...)
	length, delay, err := readGarlicCloveDeliveryInstructionsDelay(length, data)

	assert.Equal(69, length)
	assert.Equal(0, delay)
	assert.Equal(ERR_GARLIC_CLOVE_DELIVERY_INSTRUCTIONS_NOT_ENOUGH_DATA, err)
}

func TestReadGarlicCloveDeliveryInstructionsDelayValidData(t *testing.T) {
	assert := assert.New(t)

	length := 69
	data := make([]byte, length)
	expectedData := []byte{0x44, 0x69, 0x64, 0x96}
	data = append(data, expectedData...)
	length, delay, err := readGarlicCloveDeliveryInstructionsDelay(length, data)

	expectedDelay := common.Integer(expectedData).Int()
	assert.Equal(73, length)
	assert.Equal(expectedDelay, delay)
	assert.Equal(nil, err)
}

func TestReadGarlicCloveDeliveryInstructionsTooLittleData(t *testing.T) {
	assert := assert.New(t)

	flagData := byte(0xff)
	sessionKeyData := make([]byte, 32)
	sessionKeyData[4] = 0x3f
	hashData := []byte{0x34, 0x31}
	data := []byte{}
	data = append(data, flagData)
	data = append(data, sessionKeyData...)
	data = append(data, hashData...)

	instructions, err := ReadGarlicCloveDeliveryInstructions(data)
	assert.Equal(flagData, instructions.Flag)
	assert.Equal(session_key.SessionKey(sessionKeyData), instructions.SessionKey)
	assert.Equal(common.Hash{}, instructions.Hash)
	assert.Equal(ERR_GARLIC_CLOVE_DELIVERY_INSTRUCTIONS_NOT_ENOUGH_DATA, err)
}

func TestReadGarlicCloveDeliveryInstructionsValidData(t *testing.T) {
	assert := assert.New(t)

	withSessionKey := byte(0x1 << 7)
	deliveryType := byte(TUNNEL << 5)
	withDelay := byte(0x1 << 4)

	flagData := withSessionKey | deliveryType | withDelay
	sessionKeyData := make([]byte, 32)
	sessionKeyData[4] = 0x30
	sessionKeyData[13] = 0x51
	hashData := make([]byte, 32)
	hashData[4] = 0x53
	hashData[15] = 0x11
	tunnelIDData := []byte{0x3c, 0xbe, 0xfe, 0xfe}
	delayData := []byte{0x11, 0x22, 0x52, 0x31}

	data := []byte{}
	data = append(data, flagData)
	data = append(data, sessionKeyData...)
	data = append(data, hashData...)
	data = append(data, tunnelIDData...)
	data = append(data, delayData...)

	expectedTunnelID := tunnel.TunnelID(
		common.Integer(tunnelIDData).Int(),
	)
	expectedDelay := common.Integer(delayData).Int()
	instructions, err := ReadGarlicCloveDeliveryInstructions(data)
	assert.Equal(flagData, instructions.Flag)
	assert.Equal(session_key.SessionKey(sessionKeyData), instructions.SessionKey)
	assert.Equal(common.Hash(hashData), instructions.Hash)
	assert.Equal(expectedTunnelID, instructions.TunnelID)
	assert.Equal(expectedDelay, instructions.Delay)
	assert.Equal(nil, err)
}
