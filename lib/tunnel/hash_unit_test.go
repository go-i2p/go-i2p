package tunnel

import (
	"testing"

	"github.com/go-i2p/crypto/rand"

	common "github.com/go-i2p/common/data"
)

// createDTTunnelDeliveryInstructions builds a DTTunnel delivery instruction
// with a random hash, returning the DeliveryInstructions and the expected hash.
func createDTTunnelDeliveryInstructions(tb testing.TB) (*DeliveryInstructions, common.Hash) {
	tb.Helper()
	expectedHash := common.Hash{}
	if _, err := rand.Read(expectedHash[:]); err != nil {
		tb.Fatalf("Failed to generate random hash: %v", err)
	}
	flag := byte(0x20) // DTTunnel (1 << 5)
	instructions := make([]byte, FlagSize+TunnelIDSize+HashSize+SizeFieldSize)
	instructions[0] = flag
	instructions[1] = 0x12
	instructions[2] = 0x34
	instructions[3] = 0x56
	instructions[4] = 0x78
	copy(instructions[FlagSize+TunnelIDSize:FlagSize+TunnelIDSize+HashSize], expectedHash[:])
	instructions[FlagSize+TunnelIDSize+HashSize] = 0x00
	instructions[FlagSize+TunnelIDSize+HashSize+1] = 0x10
	di, err := NewDeliveryInstructions(instructions)
	if err != nil {
		tb.Fatalf("Failed to create DeliveryInstructions: %v", err)
	}
	return di, expectedHash
}

// createDTRouterDeliveryInstructions builds a DTRouter delivery instruction
// with a random hash, returning the DeliveryInstructions and the expected hash.
func createDTRouterDeliveryInstructions(tb testing.TB) (*DeliveryInstructions, common.Hash) {
	tb.Helper()
	expectedHash := common.Hash{}
	if _, err := rand.Read(expectedHash[:]); err != nil {
		tb.Fatalf("Failed to generate random hash: %v", err)
	}
	flag := byte(0x40) // DTRouter (2 << 5)
	instructions := make([]byte, FlagSize+HashSize+SizeFieldSize)
	instructions[0] = flag
	copy(instructions[FlagSize:FlagSize+HashSize], expectedHash[:])
	instructions[FlagSize+HashSize] = 0x00
	instructions[FlagSize+HashSize+1] = 0x10
	di, err := NewDeliveryInstructions(instructions)
	if err != nil {
		tb.Fatalf("Failed to create DeliveryInstructions: %v", err)
	}
	return di, expectedHash
}

// TestHashDTRouter verifies hash extraction for DTRouter delivery type.
// For DTRouter, hash starts immediately after FlagSize.
func TestHashDTRouter(t *testing.T) {
	di, expectedHash := createDTRouterDeliveryInstructions(t)

	hash, err := di.Hash()
	if err != nil {
		t.Fatalf("Hash() failed for DTRouter: %v", err)
	}

	if hash != expectedHash {
		t.Errorf("Hash mismatch for DTRouter\nExpected: %x\nGot:      %x", expectedHash, hash)
	}
}

// TestHashDTTunnel verifies hash extraction for DTTunnel delivery type.
// For DTTunnel, hash starts after FlagSize + TunnelIDSize.
// This test validates the variable shadowing fix.
func TestHashDTTunnel(t *testing.T) {
	di, expectedHash := createDTTunnelDeliveryInstructions(t)

	hash, err := di.Hash()
	if err != nil {
		t.Fatalf("Hash() failed for DTTunnel: %v", err)
	}

	if hash != expectedHash {
		t.Errorf("Hash mismatch for DTTunnel\nExpected: %x\nGot:      %x", expectedHash, hash)
	}
}

// TestHashDTLocalError verifies that Hash() returns an error for DTLocal
// delivery type, as local delivery doesn't include a hash field.
func TestHashDTLocalError(t *testing.T) {
	// Build DTLocal delivery instructions (flag = 0x00)
	instructions := make([]byte, FlagSize+SizeFieldSize)
	instructions[0] = 0x00 // DTLocal
	instructions[1] = 0x00
	instructions[2] = 0x10

	di, err := NewDeliveryInstructions(instructions)
	if err != nil {
		t.Fatalf("Failed to create DeliveryInstructions: %v", err)
	}
	_, err = di.Hash()
	if err == nil {
		t.Error("Expected Hash() to fail for DTLocal, but it succeeded")
	}
}

// TestHashInsufficientDataDTRouter verifies error handling when
// delivery instructions don't contain enough data for DTRouter hash.
func TestHashInsufficientDataDTRouter(t *testing.T) {
	// Build incomplete DTRouter delivery instructions (missing hash data)
	flag := byte(0x40)                        // DTRouter (2 << 5)
	instructions := make([]byte, FlagSize+10) // Only 10 bytes instead of 32
	instructions[0] = flag

	_, err := NewDeliveryInstructions(instructions)
	if err == nil {
		t.Error("Expected NewDeliveryInstructions to fail for insufficient DTRouter data, but it succeeded")
	}
}

// TestHashInsufficientDataDTTunnel verifies error handling when
// delivery instructions don't contain enough data for DTTunnel hash.
func TestHashInsufficientDataDTTunnel(t *testing.T) {
	// Build incomplete DTTunnel delivery instructions
	flag := byte(0x20)                                     // DTTunnel (1 << 5)
	instructions := make([]byte, FlagSize+TunnelIDSize+10) // Only 10 bytes of hash instead of 32
	instructions[0] = flag

	_, err := NewDeliveryInstructions(instructions)
	if err == nil {
		t.Error("Expected NewDeliveryInstructions to fail for insufficient DTTunnel data, but it succeeded")
	}
}

// TestHashEmptyInstructions verifies error handling for empty delivery instructions.
func TestHashEmptyInstructions(t *testing.T) {
	di, err := NewDeliveryInstructions([]byte{})
	_, err = di.Hash()
	if err == nil {
		t.Error("Expected Hash() to fail for empty instructions, but it succeeded")
	}
}

// TestHashVariousDTRouterHashes verifies correct extraction of different hash values
// for DTRouter delivery type to ensure no offset calculation errors.
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
			// Build DTRouter delivery instructions
			flag := byte(0x40) // DTRouter (2 << 5)
			instructions := make([]byte, FlagSize+HashSize+SizeFieldSize)
			instructions[0] = flag
			copy(instructions[FlagSize:FlagSize+HashSize], tc.hash[:])
			instructions[FlagSize+HashSize] = 0x00
			instructions[FlagSize+HashSize+1] = 0x10

			di, err := NewDeliveryInstructions(instructions)
			if err != nil {
				t.Fatalf("Failed to create DeliveryInstructions: %v", err)
			}
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
// for DTTunnel delivery type, validating the variable shadowing fix.
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
			// Build DTTunnel delivery instructions
			// DTTunnel (value 1) in bits 6-5: (1 << 5) = 0x20
			flag := byte(0x20)
			instructions := make([]byte, FlagSize+TunnelIDSize+HashSize+SizeFieldSize)
			instructions[0] = flag

			// Add tunnel ID
			instructions[1] = 0xAA
			instructions[2] = 0xBB
			instructions[3] = 0xCC
			instructions[4] = 0xDD

			// Add hash
			copy(instructions[FlagSize+TunnelIDSize:FlagSize+TunnelIDSize+HashSize], tc.hash[:])

			// Add size field
			instructions[FlagSize+TunnelIDSize+HashSize] = 0x00
			instructions[FlagSize+TunnelIDSize+HashSize+1] = 0x10

			di, err := NewDeliveryInstructions(instructions)
			if err != nil {
				t.Fatalf("Failed to create DeliveryInstructions: %v", err)
			}
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
