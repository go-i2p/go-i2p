package tunnel

import (
	"encoding/binary"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/crypto/rand"
)

// =============================================================================
// Benchmarks for lib/tunnel package
// =============================================================================
// Collected from builder, delivery, hash, and participant benchmarks.

// ---------------------------------------------------------------------------
// Builder benchmarks
// ---------------------------------------------------------------------------

// BenchmarkGenerateHopTunnelIDs benchmarks per-hop tunnel ID generation
func BenchmarkGenerateHopTunnelIDs(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = generateHopTunnelIDs(3)
	}
}

// BenchmarkCreateBuildRequest benchmarks build request creation (minimal version)
func BenchmarkCreateBuildRequest(b *testing.B) {
	selector := &mockBuilderPeerSelector{
		peers: make([]router_info.RouterInfo, 3),
		err:   nil,
	}
	builder, _ := NewTunnelBuilder(selector)

	req := BuildTunnelRequest{
		HopCount:  3,
		IsInbound: false,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = builder.CreateBuildRequest(req)
	}
}

// BenchmarkGenerateTunnelID benchmarks tunnel ID generation
func BenchmarkGenerateTunnelID(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = generateTunnelID()
	}
}

// BenchmarkGenerateSessionKey benchmarks session key generation
func BenchmarkGenerateSessionKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = generateSessionKey()
	}
}

// ---------------------------------------------------------------------------
// Delivery benchmarks
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Hash extraction benchmarks
// ---------------------------------------------------------------------------

// BenchmarkHashDTRouter measures performance of hash extraction for DT_ROUTER delivery type.
func BenchmarkHashDTRouter(b *testing.B) {
	expectedHash := common.Hash{}
	if _, err := rand.Read(expectedHash[:]); err != nil {
		b.Fatalf("Failed to generate random hash: %v", err)
	}

	flag := byte(0x40) // DT_ROUTER (2 << 5)
	instructions := make([]byte, FLAG_SIZE+HASH_SIZE+SIZE_FIELD_SIZE)
	instructions[0] = flag
	copy(instructions[FLAG_SIZE:FLAG_SIZE+HASH_SIZE], expectedHash[:])
	instructions[FLAG_SIZE+HASH_SIZE] = 0x00
	instructions[FLAG_SIZE+HASH_SIZE+1] = 0x10

	di, err := NewDeliveryInstructions(instructions)
	if err != nil {
		b.Fatalf("Failed to create DeliveryInstructions: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = di.Hash()
	}
}

// BenchmarkHashDTTunnel measures performance of hash extraction for DT_TUNNEL delivery type.
func BenchmarkHashDTTunnel(b *testing.B) {
	di, _ := createDTTunnelDeliveryInstructions(b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = di.Hash()
	}
}

// ---------------------------------------------------------------------------
// Participant benchmarks
// ---------------------------------------------------------------------------

// BenchmarkParticipantProcess benchmarks the message processing
func BenchmarkParticipantProcess(b *testing.B) {
	p, aesEncryptor := createTestParticipant(b, 1000)

	// Create test message (1008-byte payload)
	payload := make([]byte, 1008)
	binary.BigEndian.PutUint32(payload[:4], 2000)
	for i := 4; i < len(payload); i++ {
		payload[i] = byte(i % 256)
	}

	// Encrypt it (produces 1028-byte tunnel message)
	encryptedData, err := aesEncryptor.Encrypt(payload)
	if err != nil {
		b.Fatalf("failed to encrypt: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		data := make([]byte, len(encryptedData))
		copy(data, encryptedData)
		_, _, err := p.Process(data)
		if err != nil {
			b.Fatalf("process failed: %v", err)
		}
	}
}
