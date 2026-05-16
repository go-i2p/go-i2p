package buildrecord

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
)

func TestReadBuildRequestRecordReceiveTunnelTooLittleData(t *testing.T) {
	assert := assert.New(t)

	receive_tunnel, err := readReceiveTunnel([]byte{0x01})
	assert.Equal(TunnelID(0), receive_tunnel)
	assert.Equal(ErrNotEnoughData, err)
}

func TestReadBuildRequestRecordReceiveTunnelValidData(t *testing.T) {
	assert := assert.New(t)

	receive_tunnel, err := readReceiveTunnel([]byte{0x00, 0x00, 0x00, 0x01})
	assert.Equal(TunnelID(1), receive_tunnel)
	assert.Equal(nil, err)
}

func buildOurIdentTestData(length int, fill byte) ([]byte, []byte) {
	// ReceiveTunnel occupies bytes 0-3; OurIdent starts at byte 4
	data := make([]byte, 4+length)
	ident := make([]byte, length)
	for i := range ident {
		ident[i] = fill
	}
	copy(data[4:], ident)
	return data, ident
}

func TestReadBuildRequestRecordOurIdentTooLittleData(t *testing.T) {
	assert := assert.New(t)

	build_request_record, _ := buildOurIdentTestData(31, 0x01)
	read_ident, err := readOurIdent(build_request_record)
	hash := common.Hash{}
	assert.Equal(hash, read_ident)
	assert.Equal(ErrNotEnoughData, err)
}

func TestReadBuildRequestRecordOurIdentValidData(t *testing.T) {
	assert := assert.New(t)

	build_request_record, our_ident := buildOurIdentTestData(32, 0x01)
	read_ident, err := readOurIdent(build_request_record)
	hash := common.Hash{}
	copy(hash[:], our_ident)
	assert.Equal(hash, read_ident)
	assert.Equal(nil, err)
}
