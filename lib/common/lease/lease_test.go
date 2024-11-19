package lease

import (
	"testing"
	"github.com/stretchr/testify/assert"

	. "github.com/go-i2p/go-i2p/lib/common/data"
)

func TestTunnelGateway(t *testing.T) {
	assert := assert.New(t)

	expectedTunnelGatewayBytes := []byte("example_32_bytes_hash_to_test_00")

	var lease_bytes []byte
	lease_bytes = append(lease_bytes, expectedTunnelGatewayBytes...)
	lease_bytes = append(lease_bytes, make([]byte, LEASE_SIZE - LEASE_TUNNEL_GW_SIZE)...)
	lease := Lease(lease_bytes)

	tunnelGateway := lease.TunnelGateway()
	assert.ElementsMatch(tunnelGateway.Bytes(), expectedTunnelGatewayBytes)
}

func TestTunnelID(t *testing.T) {
	assert := assert.New(t)

	expectedTunnelIDBytes := []byte{0x21, 0x37, 0x31, 0x33}

	var lease_bytes []byte
	lease_bytes = append(lease_bytes, make([]byte, LEASE_TUNNEL_GW_SIZE)...)
	lease_bytes = append(lease_bytes, expectedTunnelIDBytes...)
	lease_bytes = append(lease_bytes, make([]byte, LEASE_SIZE - LEASE_TUNNEL_ID_SIZE - LEASE_TUNNEL_GW_SIZE)...)
	lease := Lease(lease_bytes)

	tunnelID := lease.TunnelID()
	assert.Equal(tunnelID, uint32(Integer(expectedTunnelIDBytes).Int()))
}

func TestDate(t *testing.T) {
	assert := assert.New(t)

	expectedDateBytes := []byte{0x21, 0x37, 0x31, 0x33, 0x16, 0x93, 0x13, 0x28}

	var lease_bytes []byte
	lease_bytes = append(lease_bytes, make([]byte, LEASE_TUNNEL_GW_SIZE + LEASE_TUNNEL_ID_SIZE)...)
	lease_bytes = append(lease_bytes, expectedDateBytes...)
	lease := Lease(lease_bytes)

	date := lease.Date()
	assert.ElementsMatch(date.Bytes(), expectedDateBytes)
}
