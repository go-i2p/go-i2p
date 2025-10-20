package tunnel

import (
	"crypto/rand"
	"testing"

	common "github.com/go-i2p/common/data"
)

// TestHashDTRouter verifies hash extraction for DT_ROUTER delivery type.
// For DT_ROUTER, hash starts immediately after FLAG_SIZE.
func TestHashDTRouter(t *testing.T) {
	// Create test hash
	expectedHash := common.Hash{}
	if _, err := rand.Read(expectedHash[:]); err != nil {
		t.Fatalf("Failed to generate random hash: %v", err)
	}

	// Build DT_ROUTER delivery instructions
	// Flag byte: delivery type = 0x01 (DT_ROUTER) << 5 = 0x20
	flag := byte(0x20)
	instructions := make([]byte, FLAG_SIZE+HASH_SIZE+SIZE_FIELD_SIZE)
	instructions[0] = flag
	copy(instructions[FLAG_SIZE:FLAG_SIZE+HASH_SIZE], expectedHash[:])
	// Add dummy size field
	instructions[FLAG_SIZE+HASH_SIZE] = 0x00
	instructions[FLAG_SIZE+HASH_SIZE+1] = 0x10

	di := DeliveryInstructions(instructions)
	hash, err := di.Hash()
	if err != nil {
		t.Fatalf("Hash() failed for DT_ROUTER: %v", err)
	}

	if hash != expectedHash {
		t.Errorf("Hash mismatch for DT_ROUTER\nExpected: %x\nGot:      %x", expectedHash, hash)
	}
}

// TestHashDTTunnel verifies hash extraction for DT_TUNNEL delivery type.
// For DT_TUNNEL, hash starts after FLAG_SIZE + TUNNEL_ID_SIZE.
// This test validates the variable shadowing fix.
func TestHashDTTunnel(t *testing.T) {
	// Create test hash
	expectedHash := common.Hash{}
	if _, err := rand.Read(expectedHash[:]); err != nil {
		t.Fatalf("Failed to generate random hash: %v", err)
	}

	// Build DT_TUNNEL delivery instructions
	// Flag byte: delivery type = 0x01 (DT_TUNNEL) in bits 5-4
	// DT_TUNNEL is value 1, so (1 << 4) = 0x10
	flag := byte(0x10)
	instructions := make([]byte, FLAG_SIZE+TUNNEL_ID_SIZE+HASH_SIZE+SIZE_FIELD_SIZE)
	instructions[0] = flag

	// Add tunnel ID (4 bytes)
	instructions[1] = 0x12
	instructions[2] = 0x34
	instructions[3] = 0x56
	instructions[4] = 0x78

	// Add hash after tunnel ID
	copy(instructions[FLAG_SIZE+TUNNEL_ID_SIZE:FLAG_SIZE+TUNNEL_ID_SIZE+HASH_SIZE], expectedHash[:])

	// Add dummy size field
	instructions[FLAG_SIZE+TUNNEL_ID_SIZE+HASH_SIZE] = 0x00
	instructions[FLAG_SIZE+TUNNEL_ID_SIZE+HASH_SIZE+1] = 0x10

	di := DeliveryInstructions(instructions)
	hash, err := di.Hash()
	if err != nil {
		t.Fatalf("Hash() failed for DT_TUNNEL: %v", err)
	}

	if hash != expectedHash {
		t.Errorf("Hash mismatch for DT_TUNNEL\nExpected: %x\nGot:      %x", expectedHash, hash)
	}
}

// TestHashDTLocalError verifies that Hash() returns an error for DT_LOCAL
// delivery type, as local delivery doesn't include a hash field.
func TestHashDTLocalError(t *testing.T) {
	// Build DT_LOCAL delivery instructions (flag = 0x00)
	instructions := make([]byte, FLAG_SIZE+SIZE_FIELD_SIZE)
	instructions[0] = 0x00 // DT_LOCAL
	instructions[1] = 0x00
	instructions[2] = 0x10

	di := DeliveryInstructions(instructions)
	_, err := di.Hash()
	if err == nil {
		t.Error("Expected Hash() to fail for DT_LOCAL, but it succeeded")
	}
}

// TestHashInsufficientDataDTRouter verifies error handling when
// delivery instructions don't contain enough data for DT_ROUTER hash.
func TestHashInsufficientDataDTRouter(t *testing.T) {
	// Build incomplete DT_ROUTER delivery instructions (missing hash data)
	flag := byte(0x20)                         // DT_ROUTER
	instructions := make([]byte, FLAG_SIZE+10) // Only 10 bytes instead of 32
	instructions[0] = flag

	di := DeliveryInstructions(instructions)
	_, err := di.Hash()
	if err == nil {
		t.Error("Expected Hash() to fail for insufficient DT_ROUTER data, but it succeeded")
	}
}

// TestHashInsufficientDataDTTunnel verifies error handling when
// delivery instructions don't contain enough data for DT_TUNNEL hash.
func TestHashInsufficientDataDTTunnel(t *testing.T) {
	// Build incomplete DT_TUNNEL delivery instructions
	flag := byte(0x20)                                        // DT_TUNNEL
	instructions := make([]byte, FLAG_SIZE+TUNNEL_ID_SIZE+10) // Only 10 bytes of hash instead of 32
	instructions[0] = flag

	di := DeliveryInstructions(instructions)
	_, err := di.Hash()
	if err == nil {
		t.Error("Expected Hash() to fail for insufficient DT_TUNNEL data, but it succeeded")
	}
}

// TestHashEmptyInstructions verifies error handling for empty delivery instructions.
func TestHashEmptyInstructions(t *testing.T) {
	di := DeliveryInstructions([]byte{})
	_, err := di.Hash()
	if err == nil {
		t.Error("Expected Hash() to fail for empty instructions, but it succeeded")
	}
}

// TestHashVariousDTRouterHashes verifies correct extraction of different hash values
// for DT_ROUTER delivery type to ensure no offset calculation errors.
func TestHashVariousDTRouterHashes(t *testing.T) {
	testCases := []struct {
		name string
		hash common.Hash
	}{
		{"all-zeros", common.Hash{}},
		{"all-ones", func() common.Hash {
			h := common.Hash{}
			for i := range h {
				h[i] = 0xFF
			}
			return h
		}()},
		{"sequential", func() common.Hash {
			h := common.Hash{}
			for i := range h {
				h[i] = byte(i)
			}
			return h
		}()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Build DT_ROUTER delivery instructions
			flag := byte(0x20)
			instructions := make([]byte, FLAG_SIZE+HASH_SIZE+SIZE_FIELD_SIZE)
			instructions[0] = flag
			copy(instructions[FLAG_SIZE:FLAG_SIZE+HASH_SIZE], tc.hash[:])
			instructions[FLAG_SIZE+HASH_SIZE] = 0x00
			instructions[FLAG_SIZE+HASH_SIZE+1] = 0x10

			di := DeliveryInstructions(instructions)
			hash, err := di.Hash()
			if err != nil {
				t.Fatalf("Hash() failed: %v", err)
			}

			if hash != tc.hash {
				t.Errorf("Hash mismatch\nExpected: %x\nGot:      %x", tc.hash, hash)
			}
		})
	}
}

// TestHashVariousDTTunnelHashes verifies correct extraction of different hash values
// for DT_TUNNEL delivery type, validating the variable shadowing fix.
func TestHashVariousDTTunnelHashes(t *testing.T) {
	testCases := []struct {
		name string
		hash common.Hash
	}{
		{"all-zeros", common.Hash{}},
		{"all-ones", func() common.Hash {
			h := common.Hash{}
			for i := range h {
				h[i] = 0xFF
			}
			return h
		}()},
		{"sequential", func() common.Hash {
			h := common.Hash{}
			for i := range h {
				h[i] = byte(i)
			}
			return h
		}()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Build DT_TUNNEL delivery instructions
			// DT_TUNNEL (value 1) in bits 5-4: (1 << 4) = 0x10
			flag := byte(0x10)
			instructions := make([]byte, FLAG_SIZE+TUNNEL_ID_SIZE+HASH_SIZE+SIZE_FIELD_SIZE)
			instructions[0] = flag

			// Add tunnel ID
			instructions[1] = 0xAA
			instructions[2] = 0xBB
			instructions[3] = 0xCC
			instructions[4] = 0xDD

			// Add hash
			copy(instructions[FLAG_SIZE+TUNNEL_ID_SIZE:FLAG_SIZE+TUNNEL_ID_SIZE+HASH_SIZE], tc.hash[:])

			// Add size field
			instructions[FLAG_SIZE+TUNNEL_ID_SIZE+HASH_SIZE] = 0x00
			instructions[FLAG_SIZE+TUNNEL_ID_SIZE+HASH_SIZE+1] = 0x10

			di := DeliveryInstructions(instructions)
			hash, err := di.Hash()
			if err != nil {
				t.Fatalf("Hash() failed: %v", err)
			}

			if hash != tc.hash {
				t.Errorf("Hash mismatch\nExpected: %x\nGot:      %x", tc.hash, hash)
			}
		})
	}
}

// BenchmarkHashDTRouter measures performance of hash extraction for DT_ROUTER delivery type.
func BenchmarkHashDTRouter(b *testing.B) {
	expectedHash := common.Hash{}
	rand.Read(expectedHash[:])

	flag := byte(0x20)
	instructions := make([]byte, FLAG_SIZE+HASH_SIZE+SIZE_FIELD_SIZE)
	instructions[0] = flag
	copy(instructions[FLAG_SIZE:FLAG_SIZE+HASH_SIZE], expectedHash[:])
	instructions[FLAG_SIZE+HASH_SIZE] = 0x00
	instructions[FLAG_SIZE+HASH_SIZE+1] = 0x10

	di := DeliveryInstructions(instructions)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = di.Hash()
	}
}

// BenchmarkHashDTTunnel measures performance of hash extraction for DT_TUNNEL delivery type.
func BenchmarkHashDTTunnel(b *testing.B) {
	expectedHash := common.Hash{}
	rand.Read(expectedHash[:])

	// DT_TUNNEL (value 1) in bits 5-4: (1 << 4) = 0x10
	flag := byte(0x10)
	instructions := make([]byte, FLAG_SIZE+TUNNEL_ID_SIZE+HASH_SIZE+SIZE_FIELD_SIZE)
	instructions[0] = flag
	instructions[1] = 0x12
	instructions[2] = 0x34
	instructions[3] = 0x56
	instructions[4] = 0x78
	copy(instructions[FLAG_SIZE+TUNNEL_ID_SIZE:FLAG_SIZE+TUNNEL_ID_SIZE+HASH_SIZE], expectedHash[:])
	instructions[FLAG_SIZE+TUNNEL_ID_SIZE+HASH_SIZE] = 0x00
	instructions[FLAG_SIZE+TUNNEL_ID_SIZE+HASH_SIZE+1] = 0x10

	di := DeliveryInstructions(instructions)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = di.Hash()
	}
}
