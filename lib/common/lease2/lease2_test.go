package lease2

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	. "github.com/go-i2p/go-i2p/lib/common/data"
)

func createLease2FromBytes(t *testing.T, leaseBytes []byte) Lease2 {
	assert.Equal(t, LEASE2_SIZE, len(leaseBytes), "Lease2 byte slice must be exactly LEASE2_SIZE bytes")
	var lease Lease2
	copy(lease[:], leaseBytes)
	return lease
}

// TestTunnelGateway verifies that the TunnelGateway() method correctly retrieves the gateway hash.
func TestLease2TunnelGateway(t *testing.T) {
	assert := assert.New(t)

	expectedTunnelGatewayBytes := make([]byte, LEASE2_TUNNEL_GW_SIZE)
	copy(expectedTunnelGatewayBytes, []byte("example_32_bytes_hash_to_test_00!!")) // Ensure exactly 32 bytes

	leaseBytes := make([]byte, LEASE2_SIZE)
	copy(leaseBytes[:LEASE2_TUNNEL_GW_SIZE], expectedTunnelGatewayBytes)

	lease := createLease2FromBytes(t, leaseBytes)

	tunnelGateway := lease.TunnelGateway()

	assert.True(bytes.Equal(tunnelGateway[:], expectedTunnelGatewayBytes), "TunnelGateway bytes do not match")
}

// TestTunnelID verifies that the TunnelID() method correctly parses the tunnel ID.
func TestLease2TunnelID(t *testing.T) {
	assert := assert.New(t)

	expectedTunnelIDBytes := []byte{0x21, 0x37, 0x31, 0x33}
	expectedTunnelID := binary.BigEndian.Uint32(expectedTunnelIDBytes)

	leaseBytes := make([]byte, LEASE2_SIZE)
	copy(leaseBytes[LEASE2_TUNNEL_GW_SIZE:LEASE2_TUNNEL_GW_SIZE+LEASE2_TUNNEL_ID_SIZE], expectedTunnelIDBytes)

	lease := createLease2FromBytes(t, leaseBytes)

	tunnelID := lease.TunnelID()

	assert.Equal(tunnelID, expectedTunnelID, "TunnelID does not match")
}

// TestEndDate verifies that the EndDate() method correctly interprets the end date.
func TestLease2EndDate(t *testing.T) {
	assert := assert.New(t)

	expectedSeconds := uint32(1672531199) // Corresponds to 2023-01-01T00:59:59Z
	expectedEndDate := time.Unix(int64(expectedSeconds), 0).UTC()

	expectedEndDateBytes := make([]byte, LEASE2_END_DATE_SIZE)
	binary.BigEndian.PutUint32(expectedEndDateBytes, expectedSeconds)

	leaseBytes := make([]byte, LEASE2_SIZE)
	copy(leaseBytes[LEASE2_TUNNEL_GW_SIZE+LEASE2_TUNNEL_ID_SIZE:], expectedEndDateBytes)

	lease := createLease2FromBytes(t, leaseBytes)

	endDate := lease.EndDate()

	assert.True(endDate.Equal(expectedEndDate), "EndDate does not match")
}

// TestReadLease2 verifies that the ReadLease2 function correctly parses a Lease2 from a byte slice.
func TestReadLease2(t *testing.T) {
	assert := assert.New(t)

	var gatewayHash Hash
	copy(gatewayHash[:], []byte("sample_32_bytes_gateway_hash_test!!")) // 32 bytes

	tunnelID := uint32(54321)
	endDateSeconds := uint32(1704067200) // 2024-01-01T00:00:00Z
	endDate := time.Unix(int64(endDateSeconds), 0).UTC()

	tunnelIDBytes := make([]byte, LEASE2_TUNNEL_ID_SIZE)
	binary.BigEndian.PutUint32(tunnelIDBytes, tunnelID)

	endDateBytes := make([]byte, LEASE2_END_DATE_SIZE)
	binary.BigEndian.PutUint32(endDateBytes, endDateSeconds)

	leaseBytes := make([]byte, LEASE2_SIZE)
	copy(leaseBytes[:LEASE2_TUNNEL_GW_SIZE], gatewayHash[:])
	copy(leaseBytes[LEASE2_TUNNEL_GW_SIZE:LEASE2_TUNNEL_GW_SIZE+LEASE2_TUNNEL_ID_SIZE], tunnelIDBytes)
	copy(leaseBytes[LEASE2_TUNNEL_GW_SIZE+LEASE2_TUNNEL_ID_SIZE:], endDateBytes)

	extraBytes := []byte("extra_data_after_lease")

	data := append(leaseBytes, extraBytes...)

	parsedLease, remainder, err := ReadLease2(data)
	assert.NoError(err, "ReadLease2 should not return an error")
	assert.Equal(Lease2(leaseBytes), parsedLease, "Parsed Lease2 does not match expected Lease2")
	assert.Equal(extraBytes, remainder, "Remainder bytes do not match expected extra bytes")

	assert.True(parsedLease.TunnelGateway().Equals(gatewayHash), "Parsed TunnelGateway does not match")
	assert.Equal(parsedLease.TunnelID(), tunnelID, "Parsed TunnelID does not match")
	assert.True(parsedLease.EndDate().Equal(endDate), "Parsed EndDate does not match")
}

// TestNewLease2 verifies that the NewLease2 constructor correctly creates a Lease2 instance.
func TestNewLease2(t *testing.T) {
	assert := assert.New(t)

	var gatewayHash Hash
	copy(gatewayHash[:], []byte("constructor_32_bytes_gateway_hash!!")) // 32 bytes

	tunnelID := uint32(98765)
	endDate := time.Date(2025, time.December, 31, 23, 59, 59, 0, time.UTC)
	//endDateSeconds := uint32(endDate.Unix())

	lease, err := NewLease2(gatewayHash, tunnelID, endDate)
	assert.NoError(err, "NewLease2 should not return an error")
	assert.NotNil(lease, "NewLease2 should return a non-nil Lease2")

	assert.True(lease.TunnelGateway().Equals(gatewayHash), "TunnelGateway does not match")
	assert.Equal(lease.TunnelID(), tunnelID, "TunnelID does not match")
	assert.True(lease.EndDate().Equal(endDate), "EndDate does not match")
}

// TestString verifies that the String() method returns the correct human-readable representation.
func TestLease2String(t *testing.T) {
	assert := assert.New(t)

	var gatewayHash Hash
	copy(gatewayHash[:], []byte("string_32_bytes_gateway_hash_test!!!")) // 32 bytes

	tunnelID := uint32(112233)
	endDateSeconds := uint32(1735689600) // 2025-01-01T00:00:00Z
	endDate := time.Unix(int64(endDateSeconds), 0).UTC()

	leaseBytes := make([]byte, LEASE2_SIZE)
	copy(leaseBytes[:LEASE2_TUNNEL_GW_SIZE], gatewayHash[:])

	tunnelIDBytes := make([]byte, LEASE2_TUNNEL_ID_SIZE)
	binary.BigEndian.PutUint32(tunnelIDBytes, tunnelID)
	copy(leaseBytes[LEASE2_TUNNEL_GW_SIZE:LEASE2_TUNNEL_GW_SIZE+LEASE2_TUNNEL_ID_SIZE], tunnelIDBytes)

	endDateBytes := make([]byte, LEASE2_END_DATE_SIZE)
	binary.BigEndian.PutUint32(endDateBytes, endDateSeconds)
	copy(leaseBytes[LEASE2_TUNNEL_GW_SIZE+LEASE2_TUNNEL_ID_SIZE:], endDateBytes)

	lease := createLease2FromBytes(t, leaseBytes)

	expectedTunnelGWHex := hex.EncodeToString(gatewayHash[:])
	expectedString := fmt.Sprintf("Lease2{TunnelGateway: %s, TunnelID: %d, EndDate: %s}",
		expectedTunnelGWHex,
		tunnelID,
		endDate.Format(time.RFC3339),
	)

	assert.Equal(expectedString, lease.String(), "String() method does not return expected value")
}

// TestNewLease2FromBytes verifies that the NewLease2FromBytes function correctly creates a Lease2 instance from bytes.
func TestNewLease2FromBytes(t *testing.T) {
	assert := assert.New(t)

	var gatewayHash Hash
	copy(gatewayHash[:], []byte("frombytes_32_bytes_gateway_hash_test!!"))

	tunnelID := uint32(445566)
	endDateSeconds := uint32(1893456000) // 2030-01-01T00:00:00Z
	endDate := time.Unix(int64(endDateSeconds), 0).UTC()

	tunnelIDBytes := make([]byte, LEASE2_TUNNEL_ID_SIZE)
	binary.BigEndian.PutUint32(tunnelIDBytes, tunnelID)

	endDateBytes := make([]byte, LEASE2_END_DATE_SIZE)
	binary.BigEndian.PutUint32(endDateBytes, endDateSeconds)

	leaseBytes := make([]byte, LEASE2_SIZE)
	copy(leaseBytes[:LEASE2_TUNNEL_GW_SIZE], gatewayHash[:])
	copy(leaseBytes[LEASE2_TUNNEL_GW_SIZE:LEASE2_TUNNEL_GW_SIZE+LEASE2_TUNNEL_ID_SIZE], tunnelIDBytes)
	copy(leaseBytes[LEASE2_TUNNEL_GW_SIZE+LEASE2_TUNNEL_ID_SIZE:], endDateBytes)

	extraBytes := []byte("additional_data_after_lease2")
	data := append(leaseBytes, extraBytes...)

	lease, remainder, err := NewLease2FromBytes(data)
	assert.NoError(err, "NewLease2FromBytes should not return an error")
	assert.NotNil(lease, "NewLease2FromBytes should return a non-nil Lease2")
	assert.Equal(extraBytes, remainder, "Remainder bytes do not match expected extra bytes")

	assert.True(lease.TunnelGateway().Equals(gatewayHash), "TunnelGateway does not match")
	assert.Equal(lease.TunnelID(), tunnelID, "TunnelID does not match")
	assert.True(lease.EndDate().Equal(endDate), "EndDate does not match")
}
