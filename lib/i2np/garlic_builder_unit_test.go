package i2np

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGarlicBuilder(t *testing.T) {
	messageID := 12345
	expiration := time.Now().Add(10 * time.Second)

	builder := NewGarlicBuilder(messageID, expiration)
	require.NotNil(t, builder, "NewGarlicBuilder returned nil")

	assert.Equal(t, messageID, builder.messageID, "message ID")
	assert.True(t, builder.expiration.Equal(expiration), "expiration")
	assert.Empty(t, builder.cloves, "initial cloves")
}

func TestNewGarlicBuilderWithDefaults(t *testing.T) {
	builder, err := NewGarlicBuilderWithDefaults()
	require.NoError(t, err)
	require.NotNil(t, builder)

	assert.NotZero(t, builder.messageID, "message ID should be non-zero")
	assert.True(t, builder.expiration.After(time.Now()), "expiration should be in future")

	expectedExpiration := time.Now().Add(10 * time.Second)
	diff := builder.expiration.Sub(expectedExpiration)
	assert.InDelta(t, 0, diff.Seconds(), 1.0, "expiration should be ~10s from now")
}

func TestAddLocalDeliveryClove(t *testing.T) {
	builder, err := NewGarlicBuilderWithDefaults()
	require.NoError(t, err)

	message := createTestDataMessage(t, []byte("test payload"))
	cloveID := 1

	require.NoError(t, builder.AddLocalDeliveryClove(message, cloveID))
	require.Len(t, builder.cloves, 1)

	clove := builder.cloves[0]
	assert.Equal(t, cloveID, clove.CloveID, "clove ID")
	assert.Equal(t, byte(0x00), clove.DeliveryInstructions.Flag, "LOCAL delivery flag")
}

func TestAddTunnelDeliveryClove(t *testing.T) {
	builder, err := NewGarlicBuilderWithDefaults()
	require.NoError(t, err)

	message := createTestDataMessage(t, []byte("test payload"))
	cloveID := 2
	gatewayHash := createTestHash()
	tunnelID := tunnel.TunnelID(12345)

	require.NoError(t, builder.AddTunnelDeliveryClove(message, cloveID, gatewayHash, tunnelID))
	require.Len(t, builder.cloves, 1)

	clove := builder.cloves[0]
	assert.Equal(t, byte(0x60), clove.DeliveryInstructions.Flag, "TUNNEL delivery flag")
	assert.Equal(t, gatewayHash, clove.DeliveryInstructions.Hash, "gateway hash")
	assert.Equal(t, tunnelID, clove.DeliveryInstructions.TunnelID, "tunnel ID")
}

func TestAddHashedDeliveryClove(t *testing.T) {
	tests := []struct {
		name         string
		addClove     func(*GarlicBuilder, I2NPMessage, int, common.Hash) error
		cloveID      int
		expectedFlag byte
		flagLabel    string
	}{
		{
			name:         "destination",
			addClove:     (*GarlicBuilder).AddDestinationDeliveryClove,
			cloveID:      3,
			expectedFlag: 0x20,
			flagLabel:    "DESTINATION",
		},
		{
			name:         "router",
			addClove:     (*GarlicBuilder).AddRouterDeliveryClove,
			cloveID:      4,
			expectedFlag: 0x40,
			flagLabel:    "ROUTER",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder, err := NewGarlicBuilderWithDefaults()
			require.NoError(t, err)

			message := createTestDataMessage(t, []byte("test payload"))
			hash := createTestHash()

			require.NoError(t, tt.addClove(builder, message, tt.cloveID, hash))

			clove := builder.cloves[0]
			assert.Equal(t, tt.expectedFlag, clove.DeliveryInstructions.Flag, "%s delivery flag", tt.flagLabel)
			assert.Equal(t, hash, clove.DeliveryInstructions.Hash, "%s hash", tt.flagLabel)
		})
	}
}

func TestAddClove_NilMessage(t *testing.T) {
	builder, err := NewGarlicBuilderWithDefaults()
	require.NoError(t, err)

	instructions := NewLocalDeliveryInstructions()
	assert.Error(t, builder.AddClove(instructions, nil, 1, time.Now()), "expected error for nil message")
}

func TestAddClove_ExpirationValidation(t *testing.T) {
	expiration := time.Now().Add(10 * time.Second)
	builder := NewGarlicBuilder(1, expiration)

	message := createTestDataMessage(t, []byte("test"))
	instructions := NewLocalDeliveryInstructions()

	cloveExpiration := expiration.Add(1 * time.Second)
	assert.Error(t, builder.AddClove(instructions, message, 1, cloveExpiration),
		"expected error when clove expiration is after garlic expiration")
}

func TestBuild_EmptyCloves(t *testing.T) {
	builder, err := NewGarlicBuilderWithDefaults()
	require.NoError(t, err)

	_, err = builder.Build()
	assert.Error(t, err, "expected error for zero cloves")
}

func TestBuild_TooManyCloves(t *testing.T) {
	builder, err := NewGarlicBuilderWithDefaults()
	require.NoError(t, err)

	message := createTestDataMessage(t, []byte("test"))
	for i := 0; i < 256; i++ {
		require.NoError(t, builder.AddLocalDeliveryClove(message, i), "clove %d", i)
	}

	_, err = builder.Build()
	assert.Error(t, err, "expected error for >255 cloves")
}

func TestBuild_Success(t *testing.T) {
	messageID := 12345
	expiration := time.Now().Add(10 * time.Second)
	builder := NewGarlicBuilder(messageID, expiration)

	message1 := createTestDataMessage(t, []byte("payload 1"))
	message2 := createTestDataMessage(t, []byte("payload 2"))

	require.NoError(t, builder.AddLocalDeliveryClove(message1, 1))
	require.NoError(t, builder.AddLocalDeliveryClove(message2, 2))

	garlic, err := builder.Build()
	require.NoError(t, err)
	require.NotNil(t, garlic)

	assert.Equal(t, 2, garlic.Count, "clove count")
	assert.Len(t, garlic.Cloves, 2, "cloves")
	assert.Equal(t, messageID, garlic.MessageID, "message ID")
	assert.True(t, garlic.Expiration.Equal(expiration), "expiration")
}

func TestBuildAndSerialize(t *testing.T) {
	builder, err := NewGarlicBuilderWithDefaults()
	require.NoError(t, err)

	message := createTestDataMessage(t, []byte("test payload"))
	require.NoError(t, builder.AddLocalDeliveryClove(message, 1))

	payload, err := builder.BuildAndSerialize()
	require.NoError(t, err)
	assert.NotEmpty(t, payload, "payload should not be empty")
	assert.Equal(t, byte(1), payload[0], "clove count byte")
}

func TestSerializeGarlic_NilInput(t *testing.T) {
	_, err := serializeGarlic(nil)
	assert.Error(t, err, "expected error for nil garlic")
}

func TestSerializeGarlicClove_NilInput(t *testing.T) {
	_, err := serializeGarlicClove(nil)
	assert.Error(t, err, "expected error for nil clove")
}

func TestSerializeGarlicClove_NilMessage(t *testing.T) {
	clove := &GarlicClove{
		DeliveryInstructions: NewLocalDeliveryInstructions(),
		I2NPMessage:          nil,
		CloveID:              1,
		Expiration:           time.Now(),
	}
	_, err := serializeGarlicClove(clove)
	assert.Error(t, err, "expected error for nil message")
}

func TestSerializeDeliveryInstructions_Local(t *testing.T) {
	instructions := NewLocalDeliveryInstructions()
	serialized, err := serializeDeliveryInstructions(&instructions)
	require.NoError(t, err)

	assert.Len(t, serialized, 1, "local delivery should be 1 byte")
	assert.Equal(t, byte(0x00), serialized[0], "flag")
}

func TestSerializeDeliveryInstructions_Destination(t *testing.T) {
	destHash := createTestHash()
	instructions := NewDestinationDeliveryInstructions(destHash)

	serialized, err := serializeDeliveryInstructions(&instructions)
	require.NoError(t, err)

	assert.Len(t, serialized, 33, "destination delivery should be 33 bytes")
	assert.Equal(t, byte(0x20), serialized[0], "flag")
	assert.True(t, bytes.Equal(destHash[:], serialized[1:33]), "hash mismatch")
}

func TestSerializeDeliveryInstructions_Router(t *testing.T) {
	routerHash := createTestHash()
	instructions := NewRouterDeliveryInstructions(routerHash)

	serialized, err := serializeDeliveryInstructions(&instructions)
	require.NoError(t, err)

	assert.Len(t, serialized, 33, "router delivery should be 33 bytes")
	assert.Equal(t, byte(0x40), serialized[0], "flag")
}

func TestSerializeDeliveryInstructions_Tunnel(t *testing.T) {
	gatewayHash := createTestHash()
	tunnelID := tunnel.TunnelID(98765)
	instructions := NewTunnelDeliveryInstructions(gatewayHash, tunnelID)

	serialized, err := serializeDeliveryInstructions(&instructions)
	require.NoError(t, err)

	assert.Len(t, serialized, 37, "tunnel delivery should be 37 bytes")
	assert.Equal(t, byte(0x60), serialized[0], "flag")
	assert.Equal(t, uint32(tunnelID), binary.BigEndian.Uint32(serialized[33:37]), "tunnel ID")
}

func TestSerializeDeliveryInstructions_NilInput(t *testing.T) {
	_, err := serializeDeliveryInstructions(nil)
	assert.Error(t, err, "expected error for nil")
}

func TestGarlicSerialization_RoundTrip(t *testing.T) {
	builder, err := NewGarlicBuilderWithDefaults()
	require.NoError(t, err)

	message1 := createTestDataMessage(t, []byte("local payload"))
	message2 := createTestDataMessage(t, []byte("tunnel payload"))
	message3 := createTestDataMessage(t, []byte("destination payload"))

	require.NoError(t, builder.AddLocalDeliveryClove(message1, 1))

	gatewayHash := createTestHash()
	tunnelID := tunnel.TunnelID(12345)
	require.NoError(t, builder.AddTunnelDeliveryClove(message2, 2, gatewayHash, tunnelID))

	destHash := createTestHash()
	require.NoError(t, builder.AddDestinationDeliveryClove(message3, 3, destHash))

	payload, err := builder.BuildAndSerialize()
	require.NoError(t, err)

	assert.Greater(t, len(payload), 16, "payload too small")
	assert.Equal(t, byte(3), payload[0], "clove count")

	t.Logf("Serialized garlic message: %d bytes", len(payload))
}

// Helper functions

func createTestDataMessage(t *testing.T, payload []byte) *DataMessage {
	t.Helper()
	msg := NewDataMessage(payload)
	msg.SetMessageID(1)
	msg.SetExpiration(time.Now().Add(10 * time.Second))
	return msg
}

func createTestHash() common.Hash {
	var hash common.Hash
	for i := 0; i < 32; i++ {
		hash[i] = byte(i)
	}
	return hash
}
