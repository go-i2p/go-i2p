package tunnel

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewLocalDeliveryInstructions tests creation of LOCAL delivery instructions
func TestNewLocalDeliveryInstructions(t *testing.T) {
	assert := assert.New(t)

	// Test creating LOCAL delivery instructions
	fragmentSize := uint16(1000)
	di := NewLocalDeliveryInstructions(fragmentSize)

	require.NotNil(t, di, "DeliveryInstructions should not be nil")
	assert.Equal(FIRST_FRAGMENT, di.fragmentType, "Should be first fragment")
	assert.Equal(byte(DT_LOCAL), di.deliveryType, "Should be LOCAL delivery type")
	assert.False(di.hasDelay, "Should not have delay")
	assert.False(di.fragmented, "Should not be fragmented")
	assert.False(di.hasExtOptions, "Should not have extended options")
	assert.Equal(fragmentSize, di.fragmentSize, "Fragment size should match")
}

// TestLocalDeliveryInstructionsSerialization tests serializing LOCAL delivery instructions
func TestLocalDeliveryInstructionsSerialization(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	fragmentSize := uint16(512)
	di := NewLocalDeliveryInstructions(fragmentSize)

	// Serialize to bytes
	bytes, err := di.Bytes()
	require.NoError(err, "Serialization should succeed")

	// LOCAL delivery should be compact: flag(1) + size(2) = 3 bytes
	assert.Equal(3, len(bytes), "LOCAL delivery should be 3 bytes")

	// Check flag byte: DT_LOCAL (0x00 << 4) = 0x00
	assert.Equal(byte(0x00), bytes[0], "Flag should be 0x00 for unfragmented LOCAL")

	// Check fragment size (big-endian)
	size := uint16(bytes[1])<<8 | uint16(bytes[2])
	assert.Equal(fragmentSize, size, "Fragment size should match")
}

// TestLocalDeliveryInstructionsRoundTrip tests serialization and deserialization
func TestLocalDeliveryInstructionsRoundTrip(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	fragmentSize := uint16(800)
	original := NewLocalDeliveryInstructions(fragmentSize)

	// Serialize
	bytes, err := original.Bytes()
	require.NoError(err, "Serialization should succeed")

	// Deserialize
	parsed, err := NewDeliveryInstructions(bytes)
	require.NoError(err, "Deserialization should succeed")

	// Verify all fields match
	assert.Equal(original.fragmentType, parsed.fragmentType)
	assert.Equal(original.deliveryType, parsed.deliveryType)
	assert.Equal(original.hasDelay, parsed.hasDelay)
	assert.Equal(original.fragmented, parsed.fragmented)
	assert.Equal(original.hasExtOptions, parsed.hasExtOptions)
	assert.Equal(original.fragmentSize, parsed.fragmentSize)
}

// TestNewTunnelDeliveryInstructions tests creation of TUNNEL delivery instructions
func TestNewTunnelDeliveryInstructions(t *testing.T) {
	assert := assert.New(t)

	tunnelID := uint32(12345)
	gatewayHash := [32]byte{}
	for i := 0; i < 32; i++ {
		gatewayHash[i] = byte(i)
	}
	fragmentSize := uint16(900)

	di := NewTunnelDeliveryInstructions(tunnelID, gatewayHash, fragmentSize)

	require.NotNil(t, di, "DeliveryInstructions should not be nil")
	assert.Equal(FIRST_FRAGMENT, di.fragmentType)
	assert.Equal(byte(DT_TUNNEL), di.deliveryType)
	assert.Equal(tunnelID, di.tunnelID)
	assert.Equal(gatewayHash[:], di.hash[:])
	assert.Equal(fragmentSize, di.fragmentSize)
	assert.False(di.hasDelay)
	assert.False(di.fragmented)
	assert.False(di.hasExtOptions)
}

// TestTunnelDeliveryInstructionsSerialization tests TUNNEL delivery serialization
func TestTunnelDeliveryInstructionsSerialization(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	tunnelID := uint32(0xABCD1234)
	gatewayHash := [32]byte{}
	for i := 0; i < 32; i++ {
		gatewayHash[i] = byte(0xFF - i)
	}
	fragmentSize := uint16(1000)

	di := NewTunnelDeliveryInstructions(tunnelID, gatewayHash, fragmentSize)

	bytes, err := di.Bytes()
	require.NoError(err, "Serialization should succeed")

	// TUNNEL delivery: flag(1) + tunnelID(4) + hash(32) + size(2) = 39 bytes
	assert.Equal(39, len(bytes), "TUNNEL delivery should be 39 bytes")

	// Check flag byte: DT_TUNNEL (0x01 << 4) = 0x10
	assert.Equal(byte(0x10), bytes[0], "Flag should be 0x10 for TUNNEL delivery")

	// Verify tunnel ID
	tunnelIDParsed := uint32(bytes[1])<<24 | uint32(bytes[2])<<16 | uint32(bytes[3])<<8 | uint32(bytes[4])
	assert.Equal(tunnelID, tunnelIDParsed)

	// Verify hash
	for i := 0; i < 32; i++ {
		assert.Equal(gatewayHash[i], bytes[5+i], "Hash byte %d should match", i)
	}
}

// TestTunnelDeliveryInstructionsRoundTrip tests TUNNEL round-trip
func TestTunnelDeliveryInstructionsRoundTrip(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	tunnelID := uint32(99999)
	gatewayHash := [32]byte{0xAA, 0xBB, 0xCC, 0xDD}
	fragmentSize := uint16(750)

	original := NewTunnelDeliveryInstructions(tunnelID, gatewayHash, fragmentSize)

	bytes, err := original.Bytes()
	require.NoError(err)

	parsed, err := NewDeliveryInstructions(bytes)
	require.NoError(err)

	assert.Equal(original.fragmentType, parsed.fragmentType)
	assert.Equal(original.deliveryType, parsed.deliveryType)
	assert.Equal(original.tunnelID, parsed.tunnelID)
	assert.Equal(original.hash, parsed.hash)
	assert.Equal(original.fragmentSize, parsed.fragmentSize)
}

// TestNewRouterDeliveryInstructions tests creation of ROUTER delivery instructions
func TestNewRouterDeliveryInstructions(t *testing.T) {
	assert := assert.New(t)

	routerHash := [32]byte{}
	for i := 0; i < 32; i++ {
		routerHash[i] = byte(255 - i)
	}
	fragmentSize := uint16(600)

	di := NewRouterDeliveryInstructions(routerHash, fragmentSize)

	require.NotNil(t, di)
	assert.Equal(FIRST_FRAGMENT, di.fragmentType)
	assert.Equal(byte(DT_ROUTER), di.deliveryType)
	assert.Equal(routerHash[:], di.hash[:])
	assert.Equal(fragmentSize, di.fragmentSize)
	assert.False(di.hasDelay)
	assert.False(di.fragmented)
	assert.False(di.hasExtOptions)
}

// TestRouterDeliveryInstructionsSerialization tests ROUTER delivery serialization
func TestRouterDeliveryInstructionsSerialization(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	routerHash := [32]byte{}
	for i := 0; i < 32; i++ {
		routerHash[i] = byte(i * 7 % 256)
	}
	fragmentSize := uint16(450)

	di := NewRouterDeliveryInstructions(routerHash, fragmentSize)

	bytes, err := di.Bytes()
	require.NoError(err)

	// ROUTER delivery: flag(1) + hash(32) + size(2) = 35 bytes
	assert.Equal(35, len(bytes), "ROUTER delivery should be 35 bytes")

	// Check flag byte: DT_ROUTER (0x02 << 4) = 0x20
	assert.Equal(byte(0x20), bytes[0], "Flag should be 0x20 for ROUTER delivery")

	// Verify hash
	for i := 0; i < 32; i++ {
		assert.Equal(routerHash[i], bytes[1+i])
	}
}

// TestRouterDeliveryInstructionsRoundTrip tests ROUTER round-trip
func TestRouterDeliveryInstructionsRoundTrip(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	routerHash := [32]byte{0x11, 0x22, 0x33, 0x44, 0x55}
	fragmentSize := uint16(300)

	original := NewRouterDeliveryInstructions(routerHash, fragmentSize)

	bytes, err := original.Bytes()
	require.NoError(err)

	parsed, err := NewDeliveryInstructions(bytes)
	require.NoError(err)

	assert.Equal(original.fragmentType, parsed.fragmentType)
	assert.Equal(original.deliveryType, parsed.deliveryType)
	assert.Equal(original.hash, parsed.hash)
	assert.Equal(original.fragmentSize, parsed.fragmentSize)
}

// TestDeliveryInstructionsVariousSizes tests different fragment sizes
func TestDeliveryInstructionsVariousSizes(t *testing.T) {
	testCases := []uint16{
		1,      // Minimum
		512,    // Common
		1000,   // Near maximum
		65535,  // Maximum uint16
	}

	for _, size := range testCases {
		t.Run(string(rune(size)), func(t *testing.T) {
			di := NewLocalDeliveryInstructions(size)
			bytes, err := di.Bytes()
			require.NoError(t, err)

			parsed, err := NewDeliveryInstructions(bytes)
			require.NoError(t, err)
			assert.Equal(t, size, parsed.fragmentSize)
		})
	}
}

// Benchmarks
func BenchmarkNewLocalDeliveryInstructions(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewLocalDeliveryInstructions(1000)
	}
}

func BenchmarkLocalDeliverySerialize(b *testing.B) {
	di := NewLocalDeliveryInstructions(1000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = di.Bytes()
	}
}

func BenchmarkLocalDeliveryRoundTrip(b *testing.B) {
	di := NewLocalDeliveryInstructions(1000)
	bytes, _ := di.Bytes()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewDeliveryInstructions(bytes)
	}
}
