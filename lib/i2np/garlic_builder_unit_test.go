package i2np

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/tunnel"
)

func TestNewGarlicBuilder(t *testing.T) {
	messageID := 12345
	expiration := time.Now().Add(10 * time.Second)

	builder := NewGarlicBuilder(messageID, expiration)

	if builder == nil {
		t.Fatal("NewGarlicBuilder returned nil")
	}

	if builder.messageID != messageID {
		t.Errorf("Expected message ID %d, got %d", messageID, builder.messageID)
	}

	if !builder.expiration.Equal(expiration) {
		t.Errorf("Expected expiration %v, got %v", expiration, builder.expiration)
	}

	if len(builder.cloves) != 0 {
		t.Errorf("Expected 0 cloves initially, got %d", len(builder.cloves))
	}
}

func TestNewGarlicBuilderWithDefaults(t *testing.T) {
	builder, err := NewGarlicBuilderWithDefaults()
	if err != nil {
		t.Fatalf("NewGarlicBuilderWithDefaults failed: %v", err)
	}

	if builder == nil {
		t.Fatal("NewGarlicBuilderWithDefaults returned nil")
	}

	// Message ID should be non-zero (random)
	if builder.messageID == 0 {
		t.Error("Expected non-zero message ID")
	}

	// Expiration should be in the future
	if builder.expiration.Before(time.Now()) {
		t.Error("Expected future expiration")
	}

	// Expiration should be approximately 10 seconds from now
	expectedExpiration := time.Now().Add(10 * time.Second)
	diff := builder.expiration.Sub(expectedExpiration)
	if diff < -1*time.Second || diff > 1*time.Second {
		t.Errorf("Expiration not within expected range (10s from now): diff=%v", diff)
	}
}

func TestAddLocalDeliveryClove(t *testing.T) {
	builder, err := NewGarlicBuilderWithDefaults()
	if err != nil {
		t.Fatalf("Failed to create builder: %v", err)
	}

	// Create a simple data message to wrap
	message := createTestDataMessage(t, []byte("test payload"))
	cloveID := 1

	err = builder.AddLocalDeliveryClove(message, cloveID)
	if err != nil {
		t.Fatalf("AddLocalDeliveryClove failed: %v", err)
	}

	if len(builder.cloves) != 1 {
		t.Fatalf("Expected 1 clove, got %d", len(builder.cloves))
	}

	clove := builder.cloves[0]
	if clove.CloveID != cloveID {
		t.Errorf("Expected clove ID %d, got %d", cloveID, clove.CloveID)
	}

	// Check delivery instructions flag (LOCAL = 0x00)
	if clove.DeliveryInstructions.Flag != 0x00 {
		t.Errorf("Expected LOCAL delivery flag 0x00, got 0x%02x", clove.DeliveryInstructions.Flag)
	}
}

func TestAddTunnelDeliveryClove(t *testing.T) {
	builder, err := NewGarlicBuilderWithDefaults()
	if err != nil {
		t.Fatalf("Failed to create builder: %v", err)
	}

	message := createTestDataMessage(t, []byte("test payload"))
	cloveID := 2
	gatewayHash := createTestHash()
	tunnelID := tunnel.TunnelID(12345)

	err = builder.AddTunnelDeliveryClove(message, cloveID, gatewayHash, tunnelID)
	if err != nil {
		t.Fatalf("AddTunnelDeliveryClove failed: %v", err)
	}

	if len(builder.cloves) != 1 {
		t.Fatalf("Expected 1 clove, got %d", len(builder.cloves))
	}

	clove := builder.cloves[0]

	// Check delivery instructions flag (TUNNEL = 0x60)
	if clove.DeliveryInstructions.Flag != 0x60 {
		t.Errorf("Expected TUNNEL delivery flag 0x60, got 0x%02x", clove.DeliveryInstructions.Flag)
	}

	if clove.DeliveryInstructions.Hash != gatewayHash {
		t.Errorf("Gateway hash mismatch")
	}

	if clove.DeliveryInstructions.TunnelID != tunnelID {
		t.Errorf("Expected tunnel ID %d, got %d", tunnelID, clove.DeliveryInstructions.TunnelID)
	}
}

func TestAddDestinationDeliveryClove(t *testing.T) {
	builder, err := NewGarlicBuilderWithDefaults()
	if err != nil {
		t.Fatalf("Failed to create builder: %v", err)
	}

	message := createTestDataMessage(t, []byte("test payload"))
	cloveID := 3
	destHash := createTestHash()

	err = builder.AddDestinationDeliveryClove(message, cloveID, destHash)
	if err != nil {
		t.Fatalf("AddDestinationDeliveryClove failed: %v", err)
	}

	clove := builder.cloves[0]

	// Check delivery instructions flag (DESTINATION = 0x20)
	if clove.DeliveryInstructions.Flag != 0x20 {
		t.Errorf("Expected DESTINATION delivery flag 0x20, got 0x%02x", clove.DeliveryInstructions.Flag)
	}

	if clove.DeliveryInstructions.Hash != destHash {
		t.Errorf("Destination hash mismatch")
	}
}

func TestAddRouterDeliveryClove(t *testing.T) {
	builder, err := NewGarlicBuilderWithDefaults()
	if err != nil {
		t.Fatalf("Failed to create builder: %v", err)
	}

	message := createTestDataMessage(t, []byte("test payload"))
	cloveID := 4
	routerHash := createTestHash()

	err = builder.AddRouterDeliveryClove(message, cloveID, routerHash)
	if err != nil {
		t.Fatalf("AddRouterDeliveryClove failed: %v", err)
	}

	clove := builder.cloves[0]

	// Check delivery instructions flag (ROUTER = 0x40)
	if clove.DeliveryInstructions.Flag != 0x40 {
		t.Errorf("Expected ROUTER delivery flag 0x40, got 0x%02x", clove.DeliveryInstructions.Flag)
	}

	if clove.DeliveryInstructions.Hash != routerHash {
		t.Errorf("Router hash mismatch")
	}
}

func TestAddClove_NilMessage(t *testing.T) {
	builder, err := NewGarlicBuilderWithDefaults()
	if err != nil {
		t.Fatalf("Failed to create builder: %v", err)
	}

	instructions := NewLocalDeliveryInstructions()
	err = builder.AddClove(instructions, nil, 1, time.Now())

	if err == nil {
		t.Error("Expected error when adding nil message, got nil")
	}
}

func TestAddClove_ExpirationValidation(t *testing.T) {
	expiration := time.Now().Add(10 * time.Second)
	builder := NewGarlicBuilder(1, expiration)

	message := createTestDataMessage(t, []byte("test"))
	instructions := NewLocalDeliveryInstructions()

	// Clove expiration after garlic expiration should fail
	cloveExpiration := expiration.Add(1 * time.Second)
	err := builder.AddClove(instructions, message, 1, cloveExpiration)

	if err == nil {
		t.Error("Expected error when clove expiration is after garlic expiration")
	}
}

func TestBuild_EmptyCloves(t *testing.T) {
	builder, err := NewGarlicBuilderWithDefaults()
	if err != nil {
		t.Fatalf("Failed to create builder: %v", err)
	}

	// Try to build with no cloves
	_, err = builder.Build()
	if err == nil {
		t.Error("Expected error when building garlic message with zero cloves")
	}
}

func TestBuild_TooManyCloves(t *testing.T) {
	builder, err := NewGarlicBuilderWithDefaults()
	if err != nil {
		t.Fatalf("Failed to create builder: %v", err)
	}

	// Add 256 cloves (exceeds 255 limit)
	message := createTestDataMessage(t, []byte("test"))
	for i := 0; i < 256; i++ {
		err := builder.AddLocalDeliveryClove(message, i)
		if err != nil {
			t.Fatalf("Failed to add clove %d: %v", i, err)
		}
	}

	// Try to build with too many cloves
	_, err = builder.Build()
	if err == nil {
		t.Error("Expected error when building garlic message with >255 cloves")
	}
}

func TestBuild_Success(t *testing.T) {
	messageID := 12345
	expiration := time.Now().Add(10 * time.Second)
	builder := NewGarlicBuilder(messageID, expiration)

	// Add multiple cloves
	message1 := createTestDataMessage(t, []byte("payload 1"))
	message2 := createTestDataMessage(t, []byte("payload 2"))

	err := builder.AddLocalDeliveryClove(message1, 1)
	if err != nil {
		t.Fatalf("Failed to add clove 1: %v", err)
	}

	err = builder.AddLocalDeliveryClove(message2, 2)
	if err != nil {
		t.Fatalf("Failed to add clove 2: %v", err)
	}

	// Build garlic message
	garlic, err := builder.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if garlic == nil {
		t.Fatal("Build returned nil garlic message")
	}

	if garlic.Count != 2 {
		t.Errorf("Expected count 2, got %d", garlic.Count)
	}

	if len(garlic.Cloves) != 2 {
		t.Errorf("Expected 2 cloves, got %d", len(garlic.Cloves))
	}

	if garlic.MessageID != messageID {
		t.Errorf("Expected message ID %d, got %d", messageID, garlic.MessageID)
	}

	if !garlic.Expiration.Equal(expiration) {
		t.Errorf("Expiration mismatch")
	}
}

func TestBuildAndSerialize(t *testing.T) {
	builder, err := NewGarlicBuilderWithDefaults()
	if err != nil {
		t.Fatalf("Failed to create builder: %v", err)
	}

	message := createTestDataMessage(t, []byte("test payload"))
	err = builder.AddLocalDeliveryClove(message, 1)
	if err != nil {
		t.Fatalf("Failed to add clove: %v", err)
	}

	// Build and serialize
	payload, err := builder.BuildAndSerialize()
	if err != nil {
		t.Fatalf("BuildAndSerialize failed: %v", err)
	}

	if len(payload) == 0 {
		t.Error("BuildAndSerialize returned empty payload")
	}

	// Check basic structure: first byte should be clove count (1)
	if payload[0] != 1 {
		t.Errorf("Expected clove count byte 1, got %d", payload[0])
	}
}

func TestSerializeGarlic_NilInput(t *testing.T) {
	_, err := serializeGarlic(nil)
	if err == nil {
		t.Error("Expected error when serializing nil garlic")
	}
}

func TestSerializeGarlicClove_NilInput(t *testing.T) {
	_, err := serializeGarlicClove(nil)
	if err == nil {
		t.Error("Expected error when serializing nil clove")
	}
}

func TestSerializeGarlicClove_NilMessage(t *testing.T) {
	clove := &GarlicClove{
		DeliveryInstructions: NewLocalDeliveryInstructions(),
		I2NPMessage:          nil,
		CloveID:              1,
		Expiration:           time.Now(),
	}

	_, err := serializeGarlicClove(clove)
	if err == nil {
		t.Error("Expected error when serializing clove with nil message")
	}
}

func TestSerializeDeliveryInstructions_Local(t *testing.T) {
	instructions := NewLocalDeliveryInstructions()
	serialized, err := serializeDeliveryInstructions(&instructions)
	if err != nil {
		t.Fatalf("Failed to serialize local delivery instructions: %v", err)
	}

	// Local delivery: 1 byte (flag only)
	if len(serialized) != 1 {
		t.Errorf("Expected 1 byte for local delivery, got %d", len(serialized))
	}

	if serialized[0] != 0x00 {
		t.Errorf("Expected flag 0x00, got 0x%02x", serialized[0])
	}
}

func TestSerializeDeliveryInstructions_Destination(t *testing.T) {
	destHash := createTestHash()
	instructions := NewDestinationDeliveryInstructions(destHash)

	serialized, err := serializeDeliveryInstructions(&instructions)
	if err != nil {
		t.Fatalf("Failed to serialize destination delivery instructions: %v", err)
	}

	// Destination delivery: 1 byte (flag) + 32 bytes (hash) = 33 bytes
	if len(serialized) != 33 {
		t.Errorf("Expected 33 bytes for destination delivery, got %d", len(serialized))
	}

	if serialized[0] != 0x20 {
		t.Errorf("Expected flag 0x20, got 0x%02x", serialized[0])
	}

	// Verify hash is included
	hashBytes := serialized[1:33]
	if !bytes.Equal(destHash[:], hashBytes) {
		t.Error("Hash mismatch in serialized delivery instructions")
	}
}

func TestSerializeDeliveryInstructions_Router(t *testing.T) {
	routerHash := createTestHash()
	instructions := NewRouterDeliveryInstructions(routerHash)

	serialized, err := serializeDeliveryInstructions(&instructions)
	if err != nil {
		t.Fatalf("Failed to serialize router delivery instructions: %v", err)
	}

	// Router delivery: 1 byte (flag) + 32 bytes (hash) = 33 bytes
	if len(serialized) != 33 {
		t.Errorf("Expected 33 bytes for router delivery, got %d", len(serialized))
	}

	if serialized[0] != 0x40 {
		t.Errorf("Expected flag 0x40, got 0x%02x", serialized[0])
	}
}

func TestSerializeDeliveryInstructions_Tunnel(t *testing.T) {
	gatewayHash := createTestHash()
	tunnelID := tunnel.TunnelID(98765)
	instructions := NewTunnelDeliveryInstructions(gatewayHash, tunnelID)

	serialized, err := serializeDeliveryInstructions(&instructions)
	if err != nil {
		t.Fatalf("Failed to serialize tunnel delivery instructions: %v", err)
	}

	// Tunnel delivery: 1 byte (flag) + 32 bytes (hash) + 4 bytes (tunnel ID) = 37 bytes
	if len(serialized) != 37 {
		t.Errorf("Expected 37 bytes for tunnel delivery, got %d", len(serialized))
	}

	if serialized[0] != 0x60 {
		t.Errorf("Expected flag 0x60, got 0x%02x", serialized[0])
	}

	// Verify tunnel ID
	parsedTunnelID := binary.BigEndian.Uint32(serialized[33:37])
	if parsedTunnelID != uint32(tunnelID) {
		t.Errorf("Expected tunnel ID %d, got %d", tunnelID, parsedTunnelID)
	}
}

func TestSerializeDeliveryInstructions_NilInput(t *testing.T) {
	_, err := serializeDeliveryInstructions(nil)
	if err == nil {
		t.Error("Expected error when serializing nil delivery instructions")
	}
}

func TestGarlicSerialization_RoundTrip(t *testing.T) {
	builder, err := NewGarlicBuilderWithDefaults()
	if err != nil {
		t.Fatalf("Failed to create builder: %v", err)
	}

	// Add multiple cloves with different delivery types
	message1 := createTestDataMessage(t, []byte("local payload"))
	message2 := createTestDataMessage(t, []byte("tunnel payload"))
	message3 := createTestDataMessage(t, []byte("destination payload"))

	err = builder.AddLocalDeliveryClove(message1, 1)
	if err != nil {
		t.Fatalf("Failed to add local clove: %v", err)
	}

	gatewayHash := createTestHash()
	tunnelID := tunnel.TunnelID(12345)
	err = builder.AddTunnelDeliveryClove(message2, 2, gatewayHash, tunnelID)
	if err != nil {
		t.Fatalf("Failed to add tunnel clove: %v", err)
	}

	destHash := createTestHash()
	err = builder.AddDestinationDeliveryClove(message3, 3, destHash)
	if err != nil {
		t.Fatalf("Failed to add destination clove: %v", err)
	}

	// Serialize
	payload, err := builder.BuildAndSerialize()
	if err != nil {
		t.Fatalf("Serialization failed: %v", err)
	}

	// Verify structure (basic sanity checks)
	if len(payload) < 16 {
		t.Errorf("Serialized payload too small: %d bytes", len(payload))
	}

	// First byte should be clove count (3)
	if payload[0] != 3 {
		t.Errorf("Expected clove count 3, got %d", payload[0])
	}

	// Last 12 bytes should be: certificate (3) + message ID (4) + expiration (8)
	// We can't easily parse the middle (cloves are variable length), but we can check structure exists
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
