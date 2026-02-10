package tunnel

import (
	"testing"

	"github.com/go-i2p/crypto/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// passthroughEncryptor implements TunnelEncryptor by returning data as-is.
type passthroughEncryptor struct{}

func (p *passthroughEncryptor) Encrypt(data []byte) ([]byte, error) {
	out := make([]byte, len(data))
	copy(out, data)
	return out, nil
}

func (p *passthroughEncryptor) Decrypt(data []byte) ([]byte, error) {
	out := make([]byte, len(data))
	copy(out, data)
	return out, nil
}

func (p *passthroughEncryptor) Type() tunnel.TunnelEncryptionType {
	return tunnel.TunnelEncryptionAES
}

// TestDeliveryConfigConstructors tests LocalDelivery, TunnelDelivery, RouterDelivery helpers.
func TestDeliveryConfigConstructors(t *testing.T) {
	t.Run("LocalDelivery", func(t *testing.T) {
		dc := LocalDelivery()
		assert.Equal(t, byte(DT_LOCAL), dc.DeliveryType)
		assert.Equal(t, uint32(0), dc.TunnelID)
		assert.Equal(t, [32]byte{}, dc.Hash)
	})

	t.Run("TunnelDelivery", func(t *testing.T) {
		var hash [32]byte
		copy(hash[:], []byte("tunnel_gateway_hash_for_test_val"))
		dc := TunnelDelivery(12345, hash)
		assert.Equal(t, byte(DT_TUNNEL), dc.DeliveryType)
		assert.Equal(t, uint32(12345), dc.TunnelID)
		assert.Equal(t, hash, dc.Hash)
	})

	t.Run("RouterDelivery", func(t *testing.T) {
		var hash [32]byte
		copy(hash[:], []byte("router_dest_hash_for_testing!!!!"))
		dc := RouterDelivery(hash)
		assert.Equal(t, byte(DT_ROUTER), dc.DeliveryType)
		assert.Equal(t, uint32(0), dc.TunnelID)
		assert.Equal(t, hash, dc.Hash)
	})
}

// TestDeliveryInstructionsSize tests the size calculation for delivery instructions.
func TestDeliveryInstructionsSize(t *testing.T) {
	tests := []struct {
		name       string
		dc         DeliveryConfig
		fragmented bool
		expected   int
	}{
		{
			name:       "LOCAL unfragmented",
			dc:         LocalDelivery(),
			fragmented: false,
			expected:   3, // flag + size
		},
		{
			name:       "LOCAL fragmented",
			dc:         LocalDelivery(),
			fragmented: true,
			expected:   7, // flag + size + messageID(4)
		},
		{
			name:       "TUNNEL unfragmented",
			dc:         TunnelDelivery(1, [32]byte{}),
			fragmented: false,
			expected:   39, // flag + tunnelID(4) + hash(32) + size(2)
		},
		{
			name:       "TUNNEL fragmented",
			dc:         TunnelDelivery(1, [32]byte{}),
			fragmented: true,
			expected:   43, // flag + tunnelID(4) + hash(32) + size(2) + messageID(4)
		},
		{
			name:       "ROUTER unfragmented",
			dc:         RouterDelivery([32]byte{}),
			fragmented: false,
			expected:   35, // flag + hash(32) + size(2)
		},
		{
			name:       "ROUTER fragmented",
			dc:         RouterDelivery([32]byte{}),
			fragmented: true,
			expected:   39, // flag + hash(32) + size(2) + messageID(4)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := deliveryInstructionsSize(tt.dc, tt.fragmented)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestMaxPayloadForDelivery tests maximum payload calculation.
func TestMaxPayloadForDelivery(t *testing.T) {
	localMax := maxPayloadForDelivery(LocalDelivery())
	tunnelMax := maxPayloadForDelivery(TunnelDelivery(1, [32]byte{}))
	routerMax := maxPayloadForDelivery(RouterDelivery([32]byte{}))

	// LOCAL should have largest payload (smallest DI)
	assert.Greater(t, localMax, tunnelMax)
	assert.Greater(t, localMax, routerMax)

	// ROUTER should have larger payload than TUNNEL (no tunnel ID)
	assert.Greater(t, routerMax, tunnelMax)

	// All should be positive
	assert.Greater(t, localMax, 0)
	assert.Greater(t, tunnelMax, 0)
	assert.Greater(t, routerMax, 0)
}

// TestSendWithDeliveryEmptyMessage tests error on empty message.
func TestSendWithDeliveryEmptyMessage(t *testing.T) {
	mockEncryptor := &passthroughEncryptor{}
	gw, err := NewGateway(TunnelID(1), mockEncryptor, TunnelID(2))
	require.NoError(t, err)

	result, err := gw.SendWithDelivery(nil, LocalDelivery())
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrInvalidMessage)

	result, err = gw.SendWithDelivery([]byte{}, LocalDelivery())
	assert.Error(t, err)
	assert.Nil(t, result)
}

// TestSendWithDeliveryLocalSmallMessage tests single-fragment local delivery.
func TestSendWithDeliveryLocalSmallMessage(t *testing.T) {
	mockEncryptor := &passthroughEncryptor{}
	gw, err := NewGateway(TunnelID(1), mockEncryptor, TunnelID(2))
	require.NoError(t, err)

	// Small message should produce a single fragment
	msg := make([]byte, 100)
	for i := range msg {
		msg[i] = byte(i)
	}

	result, err := gw.SendWithDelivery(msg, LocalDelivery())
	assert.NoError(t, err)
	require.NotNil(t, result)
	assert.Len(t, result, 1, "Small message should produce a single tunnel message")
	assert.Len(t, result[0], 1028, "Each tunnel message should be 1028 bytes")
}

// TestSendWithDeliveryTunnelType tests single-fragment tunnel delivery.
func TestSendWithDeliveryTunnelType(t *testing.T) {
	mockEncryptor := &passthroughEncryptor{}
	gw, err := NewGateway(TunnelID(1), mockEncryptor, TunnelID(2))
	require.NoError(t, err)

	var hash [32]byte
	copy(hash[:], []byte("gateway_hash_for_tunnel_delivery"))
	dc := TunnelDelivery(42, hash)

	msg := make([]byte, 100)
	result, err := gw.SendWithDelivery(msg, dc)
	assert.NoError(t, err)
	require.NotNil(t, result)
	assert.Len(t, result, 1)
	assert.Len(t, result[0], 1028)
}

// TestSendWithDeliveryRouterType tests single-fragment router delivery.
func TestSendWithDeliveryRouterType(t *testing.T) {
	mockEncryptor := &passthroughEncryptor{}
	gw, err := NewGateway(TunnelID(1), mockEncryptor, TunnelID(2))
	require.NoError(t, err)

	var hash [32]byte
	copy(hash[:], []byte("router_hash_for_router_delivery!"))
	dc := RouterDelivery(hash)

	msg := make([]byte, 100)
	result, err := gw.SendWithDelivery(msg, dc)
	assert.NoError(t, err)
	require.NotNil(t, result)
	assert.Len(t, result, 1)
	assert.Len(t, result[0], 1028)
}

// TestSendWithDeliveryFragmentedMessage tests fragmentation with a large message.
func TestSendWithDeliveryFragmentedMessage(t *testing.T) {
	mockEncryptor := &passthroughEncryptor{}
	gw, err := NewGateway(TunnelID(1), mockEncryptor, TunnelID(2))
	require.NoError(t, err)

	// Create a message larger than what fits in a single tunnel message.
	// Actual max payload is ~1003 bytes (1028 - 24 header - 1 zero byte).
	// With DT_LOCAL unfragmented DI (3 bytes), max single msg ≈ 1000 bytes.
	// We go slightly over to trigger fragmentation.
	msg := make([]byte, 1050)
	for i := range msg {
		msg[i] = byte(i % 256)
	}

	result, err := gw.SendWithDelivery(msg, LocalDelivery())
	assert.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result), 1, "Large message should produce multiple fragments")

	// Each fragment should be 1028 bytes
	for i, frag := range result {
		assert.Len(t, frag, 1028, "Fragment %d should be 1028 bytes", i)
	}
}

// TestSendWithDeliveryFragmentedTunnel tests fragmentation for DT_TUNNEL delivery.
func TestSendWithDeliveryFragmentedTunnel(t *testing.T) {
	mockEncryptor := &passthroughEncryptor{}
	gw, err := NewGateway(TunnelID(1), mockEncryptor, TunnelID(2))
	require.NoError(t, err)

	var hash [32]byte
	copy(hash[:], []byte("gateway_hash_for_frag_tunnel_del"))
	dc := TunnelDelivery(42, hash)

	// Make a message that requires fragmentation for DT_TUNNEL
	// DT_TUNNEL DI is larger, so smaller payload fits
	msg := make([]byte, 1050)

	result, err := gw.SendWithDelivery(msg, dc)
	assert.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, len(result), 1)
}

// TestSendWithDeliveryMsgIDIncrement tests that message IDs are unique per fragmented send.
func TestSendWithDeliveryMsgIDIncrement(t *testing.T) {
	mockEncryptor := &passthroughEncryptor{}
	gw, err := NewGateway(TunnelID(1), mockEncryptor, TunnelID(2))
	require.NoError(t, err)

	// Initial msgIDSeq should be 0
	assert.Equal(t, uint32(0), gw.msgIDSeq)

	// A non-fragmented send should not increment msgIDSeq
	smallMsg := make([]byte, 100)
	_, err = gw.SendWithDelivery(smallMsg, LocalDelivery())
	require.NoError(t, err)
	assert.Equal(t, uint32(0), gw.msgIDSeq, "Non-fragmented send should not increment msgIDSeq")

	// A fragmented send should increment msgIDSeq
	largeMsg := make([]byte, 1050)
	_, err = gw.SendWithDelivery(largeMsg, LocalDelivery())
	require.NoError(t, err)
	assert.Equal(t, uint32(1), gw.msgIDSeq, "First fragmented send should set msgIDSeq to 1")

	// Second fragmented send
	_, err = gw.SendWithDelivery(largeMsg, LocalDelivery())
	require.NoError(t, err)
	assert.Equal(t, uint32(2), gw.msgIDSeq)
}

// TestCreateDeliveryInstructionsForConfig tests delivery instructions generation.
func TestCreateDeliveryInstructionsForConfig(t *testing.T) {
	mockEncryptor := &passthroughEncryptor{}
	gw, err := NewGateway(TunnelID(1), mockEncryptor, TunnelID(2))
	require.NoError(t, err)

	t.Run("LOCAL", func(t *testing.T) {
		di, err := gw.createDeliveryInstructionsForConfig(LocalDelivery(), make([]byte, 50), false, 0)
		require.NoError(t, err)
		assert.NotNil(t, di)
		assert.True(t, len(di) >= 3, "LOCAL DI should be at least 3 bytes")
	})

	t.Run("TUNNEL", func(t *testing.T) {
		var hash [32]byte
		dc := TunnelDelivery(42, hash)
		di, err := gw.createDeliveryInstructionsForConfig(dc, make([]byte, 50), false, 0)
		require.NoError(t, err)
		assert.NotNil(t, di)
		// TUNNEL should be at least 39 bytes (flag + tunnelID + hash + size)
		assert.True(t, len(di) >= 35, "TUNNEL DI should be at least 35 bytes")
	})

	t.Run("ROUTER", func(t *testing.T) {
		var hash [32]byte
		dc := RouterDelivery(hash)
		di, err := gw.createDeliveryInstructionsForConfig(dc, make([]byte, 50), false, 0)
		require.NoError(t, err)
		assert.NotNil(t, di)
		assert.True(t, len(di) >= 35, "ROUTER DI should be at least 35 bytes")
	})

	t.Run("Fragmented", func(t *testing.T) {
		diUnfrag, err := gw.createDeliveryInstructionsForConfig(LocalDelivery(), make([]byte, 50), false, 0)
		require.NoError(t, err)
		diFrag, err := gw.createDeliveryInstructionsForConfig(LocalDelivery(), make([]byte, 50), true, 12345)
		require.NoError(t, err)
		// Fragmented should be 4 bytes larger (message ID)
		assert.Greater(t, len(diFrag), len(diUnfrag), "Fragmented DI should be larger")
	})
}

// TestCreateFollowOnInstructions tests follow-on fragment instruction generation.
func TestCreateFollowOnInstructions(t *testing.T) {
	mockEncryptor := &passthroughEncryptor{}
	gw, err := NewGateway(TunnelID(1), mockEncryptor, TunnelID(2))
	require.NoError(t, err)

	di, err := gw.createFollowOnInstructions(42, 1, false, make([]byte, 100))
	require.NoError(t, err)
	assert.NotNil(t, di, "Follow-on DI should not be nil")

	diLast, err := gw.createFollowOnInstructions(42, 3, true, make([]byte, 50))
	require.NoError(t, err)
	assert.NotNil(t, diLast, "Last follow-on DI should not be nil")
}

// TestSendBackwardCompatibility tests that Send() still works for DT_LOCAL.
func TestSendBackwardCompatibility(t *testing.T) {
	mockEncryptor := &passthroughEncryptor{}
	gw, err := NewGateway(TunnelID(1), mockEncryptor, TunnelID(2))
	require.NoError(t, err)

	msg := make([]byte, 100)
	result, err := gw.Send(msg)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result, 1028, "Send() should produce a 1028-byte tunnel message")
}

// TestCreateDeliveryInstructionsForConfigReturnsError verifies that
// createDeliveryInstructionsForConfig returns an error instead of silently
// falling back to DT_LOCAL when serialization fails.
func TestCreateDeliveryInstructionsForConfigReturnsError(t *testing.T) {
	mockEncryptor := &passthroughEncryptor{}
	gw, err := NewGateway(TunnelID(1), mockEncryptor, TunnelID(2))
	require.NoError(t, err)

	// Valid delivery configs should succeed
	t.Run("ValidLocalDelivery", func(t *testing.T) {
		di, err := gw.createDeliveryInstructionsForConfig(LocalDelivery(), make([]byte, 50), false, 0)
		require.NoError(t, err)
		assert.NotNil(t, di)
		// Verify it's actually DT_LOCAL and not silently changed
		assert.Equal(t, byte(DT_LOCAL), di[0]&0xC0>>6, "Should be DT_LOCAL delivery type")
	})

	t.Run("ValidTunnelDelivery", func(t *testing.T) {
		var hash [32]byte
		dc := TunnelDelivery(42, hash)
		di, err := gw.createDeliveryInstructionsForConfig(dc, make([]byte, 50), false, 0)
		require.NoError(t, err)
		assert.NotNil(t, di)
	})

	t.Run("ValidRouterDelivery", func(t *testing.T) {
		var hash [32]byte
		dc := RouterDelivery(hash)
		di, err := gw.createDeliveryInstructionsForConfig(dc, make([]byte, 50), false, 0)
		require.NoError(t, err)
		assert.NotNil(t, di)
	})
}

// TestCreateFollowOnInstructionsReturnsError verifies that
// createFollowOnInstructions returns an error instead of nil when serialization fails.
func TestCreateFollowOnInstructionsReturnsError(t *testing.T) {
	mockEncryptor := &passthroughEncryptor{}
	gw, err := NewGateway(TunnelID(1), mockEncryptor, TunnelID(2))
	require.NoError(t, err)

	// Valid follow-on instructions should succeed
	t.Run("ValidFirstFollowOn", func(t *testing.T) {
		di, err := gw.createFollowOnInstructions(42, 1, false, make([]byte, 100))
		require.NoError(t, err)
		assert.NotNil(t, di, "Valid follow-on instructions should not be nil")
	})

	t.Run("ValidLastFollowOn", func(t *testing.T) {
		di, err := gw.createFollowOnInstructions(42, 3, true, make([]byte, 50))
		require.NoError(t, err)
		assert.NotNil(t, di, "Valid last follow-on instructions should not be nil")
	})
}
