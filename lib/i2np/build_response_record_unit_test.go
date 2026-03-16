package i2np

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
)

func TestReadBuildResponseRecordHashTooLittleData(t *testing.T) {
	assert := assert.New(t)

	hash, err := readBuildResponseRecordHash([]byte{0x01})
	assert.Equal(common.Hash{}, hash)
	assert.Equal(ErrBuildResponseRecordNotEnoughData, err)
}

func TestReadBuildResponseRecordHashValidData(t *testing.T) {
	assert := assert.New(t)

	data := make([]byte, 32)
	data[31] = 0x31
	res_hash, err := readBuildResponseRecordHash(data)
	hash := common.Hash(data)

	assert.Equal(res_hash, hash)
	assert.Equal(nil, err)
}

func TestReadBuildResponseRecordRandomDataTooLittleData(t *testing.T) {
	assert := assert.New(t)

	hash := make([]byte, 32)
	data := append(hash, 0x01)
	random_data, err := readBuildResponseRecordRandomData(data)
	assert.Equal([495]byte{}, random_data)
	assert.Equal(ErrBuildResponseRecordNotEnoughData, err)
}

func TestReadBuildResponseRecordRandomDataValidData(t *testing.T) {
	assert := assert.New(t)

	_, random_data, data := buildResponseRecordTestData(0x13)
	res_random_data, err := readBuildResponseRecordRandomData(data)
	assert.Equal([495]byte(random_data), res_random_data)
	assert.Equal(nil, err)
}

func TestReadBuildResponseRecordReplyTooLittleData(t *testing.T) {
	assert := assert.New(t)

	_, _, data := buildResponseRecordTestData(0x00)

	res_reply, err := readBuildResponseRecordReply(data)
	assert.Equal(byte(0), res_reply)
	assert.Equal(ErrBuildResponseRecordNotEnoughData, err)
}

func TestReadBuildResponseRecordReplyValidData(t *testing.T) {
	assert := assert.New(t)

	_, _, data := buildResponseRecordTestData(0x13)
	reply := byte(37)
	data = append(data, reply)

	res_reply, err := readBuildResponseRecordReply(data)
	assert.Equal(reply, res_reply)
	assert.Equal(nil, err)
}

func TestReadBuildResponseRecordTooLittleData(t *testing.T) {
	assert := assert.New(t)

	hash := make([]byte, 32)
	hash[31] = 0x31
	data := append(hash, 0x01)
	build_response_record, err := ReadBuildResponseRecord(data)

	assert.Equal(common.Hash(hash), build_response_record.Hash)
	assert.Equal([495]byte{}, build_response_record.RandomData)
	assert.Equal(ErrBuildResponseRecordNotEnoughData, err)
}

func TestReadBuildResponseRecordValidData(t *testing.T) {
	assert := assert.New(t)

	hash, random_data, data := buildResponseRecordTestData(0x12)
	reply := byte(37)
	data = append(data, reply)

	build_response_record, err := ReadBuildResponseRecord(data)

	assert.Equal(common.Hash(hash), build_response_record.Hash)
	assert.Equal([495]byte(random_data), build_response_record.RandomData)
	assert.Equal(reply, build_response_record.Reply)
	assert.Equal(nil, err)
}
