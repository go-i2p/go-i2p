package i2np

import (
	"testing"

	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
)

func TestTunnelData_TunnelID(t *testing.T) {
	var td TunnelData
	// Manually set tunnel ID bytes (big-endian 0x00 0x00 0x30 0x39 = 12345)
	td[0] = 0x00
	td[1] = 0x00
	td[2] = 0x30
	td[3] = 0x39

	assert.Equal(t, tunnel.TunnelID(12345), td.TunnelID())
}

func TestTunnelData_Data(t *testing.T) {
	var td TunnelData
	// Fill the data portion (bytes 4-1027) with a pattern
	for i := 4; i < 1028; i++ {
		td[i] = byte(i % 256)
	}

	data := td.Data()
	assert.Equal(t, 1024, len(data))
	for i := 0; i < 1024; i++ {
		assert.Equal(t, byte((i+4)%256), data[i], "mismatch at index %d", i)
	}
}

func TestTunnelData_SetTunnelID(t *testing.T) {
	var td TunnelData
	td.SetTunnelID(tunnel.TunnelID(67890))

	assert.Equal(t, tunnel.TunnelID(67890), td.TunnelID())
	// Verify raw bytes (67890 = 0x00 0x01 0x09 0x32)
	assert.Equal(t, byte(0x00), td[0])
	assert.Equal(t, byte(0x01), td[1])
	assert.Equal(t, byte(0x09), td[2])
	assert.Equal(t, byte(0x32), td[3])
}

func TestTunnelData_SetData(t *testing.T) {
	var td TunnelData
	var data [1024]byte
	for i := range data {
		data[i] = byte(i % 256)
	}

	td.SetData(data)

	got := td.Data()
	assert.Equal(t, data, got)
}

func TestTunnelData_SetTunnelID_DoesNotClobberData(t *testing.T) {
	var td TunnelData
	var data [1024]byte
	for i := range data {
		data[i] = 0xAB
	}
	td.SetData(data)
	td.SetTunnelID(tunnel.TunnelID(999))

	// Data should be unchanged
	got := td.Data()
	assert.Equal(t, data, got)
	// Tunnel ID should be set
	assert.Equal(t, tunnel.TunnelID(999), td.TunnelID())
}

func TestTunnelData_SetData_DoesNotClobberTunnelID(t *testing.T) {
	var td TunnelData
	td.SetTunnelID(tunnel.TunnelID(42))

	var data [1024]byte
	data[0] = 0xFF
	td.SetData(data)

	// Tunnel ID should be unchanged
	assert.Equal(t, tunnel.TunnelID(42), td.TunnelID())
	// Data should be set
	got := td.Data()
	assert.Equal(t, data, got)
}

func TestTunnelData_ZeroValue(t *testing.T) {
	var td TunnelData
	assert.Equal(t, tunnel.TunnelID(0), td.TunnelID())
	assert.Equal(t, [1024]byte{}, td.Data())
}
