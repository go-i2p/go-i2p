package i2np

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
)

func TestReadBuildRequestRecordReceiveTunnelTooLittleData(t *testing.T) {
	assert := assert.New(t)

	receive_tunnel, err := readBuildRequestRecordReceiveTunnel([]byte{0x01})
	assert.Equal(tunnel.TunnelID(0), receive_tunnel)
	assert.Equal(ERR_BUILD_REQUEST_RECORD_NOT_ENOUGH_DATA, err)
}

func TestReadBuildRequestRecordReceiveTunnelValidData(t *testing.T) {
	assert := assert.New(t)

	receive_tunnel, err := readBuildRequestRecordReceiveTunnel([]byte{0x00, 0x00, 0x00, 0x01})
	assert.Equal(tunnel.TunnelID(1), receive_tunnel)
	assert.Equal(nil, err)
}

func TestReadBuildRequestRecordOurIdentTooLittleData(t *testing.T) {
	assert := assert.New(t)

	build_request_record, _ := buildOurIdentTestData(31, 0x01)
	read_ident, err := readBuildRequestRecordOurIdent(build_request_record)
	hash := common.Hash{}
	assert.Equal(hash, read_ident)
	assert.Equal(ERR_BUILD_REQUEST_RECORD_NOT_ENOUGH_DATA, err)
}

func TestReadBuildRequestRecordOurIdentValidData(t *testing.T) {
	assert := assert.New(t)

	build_request_record, our_ident := buildOurIdentTestData(32, 0x01)
	read_ident, err := readBuildRequestRecordOurIdent(build_request_record)
	hash := common.Hash{}
	copy(hash[:], our_ident)
	assert.Equal(hash, read_ident)
	assert.Equal(nil, err)
}
