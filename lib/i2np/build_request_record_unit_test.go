package i2np

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadBuildRequestRecordTooLittleData(t *testing.T) {
	assert := assert.New(t)

	_, err := ReadBuildRequestRecord([]byte{0x01})
	assert.Equal(ErrBuildRequestRecordNotEnoughData, err)
}

func TestReadBuildRequestRecordValidReceiveTunnel(t *testing.T) {
	assert := assert.New(t)

	data := make([]byte, 222)
	data[0] = 0x00
	data[1] = 0x00
	data[2] = 0x00
	data[3] = 0x01
	rec, err := ReadBuildRequestRecord(data)
	assert.Nil(err)
	assert.Equal(uint32(1), uint32(rec.ReceiveTunnel))
}
