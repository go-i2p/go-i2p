package i2np

import (
	"testing"

	common "github.com/go-i2p/go-i2p/lib/common/data"
	"github.com/stretchr/testify/assert"
)

func TestReadBuildResponseRecordHashTooLittleData(t *testing.T) {
	assert := assert.New(t)

	hash, err := readBuildResponseRecordHash([]byte{0x01})
	assert.Equal(common.Hash{}, hash)
	assert.Equal(ERR_BUILD_REQUEST_RECORD_NOT_ENOUGH_DATA, err)
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
	assert.Equal(ERR_BUILD_REQUEST_RECORD_NOT_ENOUGH_DATA, err)
}

func TestReadBuildResponseRecordRandomDataValidData(t *testing.T) {
	assert := assert.New(t)

	hash := make([]byte, 32) 
	hash[31] = 0x13
	random_data := make([]byte, 495)
	random_data[493] = 0x33
	random_data[494] = 0x74
	data := append(hash, random_data...)
	res_random_data, err := readBuildResponseRecordRandomData(data)
	assert.Equal([495]byte(random_data), res_random_data)
	assert.Equal(nil, err)
}

func TestReadBuildResponseRecordReplyTooLittleData(t *testing.T) {
	assert := assert.New(t)

	hash := make([]byte, 32) 
	random_data := make([]byte, 495)
	random_data[493] = 0x33
	random_data[494] = 0x74
	data := append(hash, random_data...)

	res_reply, err := readBuildResponseRecordReply(data)
	assert.Equal(byte(0), res_reply)
	assert.Equal(ERR_BUILD_REQUEST_RECORD_NOT_ENOUGH_DATA, err)
}


func TestReadBuildResponseRecordReplyValidData(t *testing.T) {
	assert := assert.New(t)

	hash := make([]byte, 32) 
	hash[31] = 0x13
	random_data := make([]byte, 495)
	random_data[493] = 0x33
	random_data[494] = 0x74
	reply := byte(37)
	data := append(hash, random_data...)
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
	assert.Equal(ERR_BUILD_REQUEST_RECORD_NOT_ENOUGH_DATA, err)
}

func TestReadBuildResponseRecordValidData(t *testing.T) {
	assert := assert.New(t)

	hash := make([]byte, 32)
	hash[31] = 0x12
	random_data := make([]byte, 495)
	random_data[493] = 0x33
	random_data[494] = 0x74
	reply := byte(37)
	data := append(hash, random_data...)
	data = append(data, reply)

	build_response_record, err := ReadBuildResponseRecord(data)

	assert.Equal(common.Hash(hash), build_response_record.Hash)
	assert.Equal([495]byte(random_data), build_response_record.RandomData)
	assert.Equal(reply, build_response_record.Reply)
	assert.Equal(nil, err)
}
