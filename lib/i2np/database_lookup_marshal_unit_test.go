package i2np

import (
	"bytes"
	"testing"

	common "github.com/go-i2p/common/data"
)

// TestNewDatabaseLookup validates that NewDatabaseLookup sets the Key, From,
// and Flags fields correctly for each lookup type (RouterInfo, LeaseSet,
// Exploration) and that the excluded-peer count is derived from the slice
// length.
func TestNewDatabaseLookup(t *testing.T) {
	key := common.Hash{1, 2, 3, 4, 5, 6, 7, 8}
	from := common.Hash{9, 10, 11, 12, 13, 14, 15, 16}

	t.Run("BasicRouterInfoLookup", func(t *testing.T) {
		lookup := NewDatabaseLookup(key, from, DatabaseLookupFlagTypeRI, nil)

		if lookup.Key != key {
			t.Error("Key should match")
		}
		if lookup.From != from {
			t.Error("From should match")
		}
		if lookup.Flags != (DatabaseLookupFlagDirect | DatabaseLookupFlagTypeRI) {
			t.Errorf("Expected flags 0x%02x, got 0x%02x", DatabaseLookupFlagDirect|DatabaseLookupFlagTypeRI, lookup.Flags)
		}
		if lookup.Size != 0 {
			t.Error("Size should be 0 with nil excluded peers")
		}
	})

	t.Run("WithExcludedPeers", func(t *testing.T) {
		excluded := []common.Hash{{1}, {2}, {3}}
		lookup := NewDatabaseLookup(key, from, DatabaseLookupFlagTypeRI, excluded)

		if lookup.Size != 3 {
			t.Errorf("Expected Size 3, got %d", lookup.Size)
		}
		if len(lookup.ExcludedPeers) != 3 {
			t.Errorf("Expected 3 excluded peers, got %d", len(lookup.ExcludedPeers))
		}
	})

	t.Run("LeaseSetLookup", func(t *testing.T) {
		lookup := NewDatabaseLookup(key, from, DatabaseLookupFlagTypeLS, nil)

		expectedFlags := DatabaseLookupFlagDirect | DatabaseLookupFlagTypeLS
		if lookup.Flags != expectedFlags {
			t.Errorf("Expected flags 0x%02x, got 0x%02x", expectedFlags, lookup.Flags)
		}
	})

	t.Run("ExplorationLookup", func(t *testing.T) {
		lookup := NewDatabaseLookup(key, from, DatabaseLookupFlagTypeExploration, nil)

		expectedFlags := DatabaseLookupFlagDirect | DatabaseLookupFlagTypeExploration
		if lookup.Flags != expectedFlags {
			t.Errorf("Expected flags 0x%02x, got 0x%02x", expectedFlags, lookup.Flags)
		}
	})
}

// TestNewDatabaseLookupWithTunnel validates that the tunnel-reply constructor
// sets the tunnel delivery flag (bit 0), stores the reply tunnel ID, and uses
// the reply gateway's identity hash as the From field.
func TestNewDatabaseLookupWithTunnel(t *testing.T) {
	key := common.Hash{1, 2, 3, 4}
	gateway := common.Hash{5, 6, 7, 8}
	tunnelID := [4]byte{0, 0, 1, 2}

	lookup := NewDatabaseLookupWithTunnel(key, gateway, tunnelID, DatabaseLookupFlagTypeRI, nil)

	if lookup.Flags&DatabaseLookupFlagTunnel == 0 {
		t.Error("Tunnel flag should be set")
	}
	if lookup.ReplyTunnelID != tunnelID {
		t.Error("ReplyTunnelID should match")
	}
	if lookup.From != gateway {
		t.Error("From should be the gateway hash")
	}
}

// TestDatabaseLookupMarshalBinary validates the wire layout produced by
// MarshalBinary: key(32) + from(32) + flags(1) + [reply_tunnelId(4)] +
// size(2, big-endian) + excluded peers, with each field at its spec offset.
func TestDatabaseLookupMarshalBinary(t *testing.T) {
	key := common.Hash{1, 2, 3, 4}
	from := common.Hash{5, 6, 7, 8}

	t.Run("DirectReplyNoExcluded", func(t *testing.T) {
		lookup := NewDatabaseLookup(key, from, DatabaseLookupFlagTypeRI, nil)

		data, err := lookup.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary failed: %v", err)
		}

		// Expected size: key(32) + from(32) + flags(1) + size(2) = 67
		expectedSize := 32 + 32 + 1 + 2
		if len(data) != expectedSize {
			t.Errorf("Expected size %d, got %d", expectedSize, len(data))
		}

		// Verify key
		if !bytes.Equal(data[0:32], key[:]) {
			t.Error("Key not serialized correctly")
		}

		// Verify from
		if !bytes.Equal(data[32:64], from[:]) {
			t.Error("From not serialized correctly")
		}

		// Verify flags
		expectedFlags := byte(DatabaseLookupFlagDirect | DatabaseLookupFlagTypeRI)
		if data[64] != expectedFlags {
			t.Errorf("Expected flags 0x%02x, got 0x%02x", expectedFlags, data[64])
		}

		// Verify size (should be 0)
		if data[65] != 0 || data[66] != 0 {
			t.Error("Size should be 0")
		}
	})

	t.Run("TunnelReply", func(t *testing.T) {
		tunnelID := [4]byte{0, 0, 1, 2}
		lookup := NewDatabaseLookupWithTunnel(key, from, tunnelID, DatabaseLookupFlagTypeRI, nil)

		data, err := lookup.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary failed: %v", err)
		}

		// Expected size: key(32) + from(32) + flags(1) + tunnelID(4) + size(2) = 71
		expectedSize := 32 + 32 + 1 + 4 + 2
		if len(data) != expectedSize {
			t.Errorf("Expected size %d, got %d", expectedSize, len(data))
		}

		// Verify tunnel ID position (after flags)
		if !bytes.Equal(data[65:69], tunnelID[:]) {
			t.Error("TunnelID not serialized correctly")
		}
	})

	t.Run("WithExcludedPeers", func(t *testing.T) {
		excluded := []common.Hash{{1}, {2}}
		lookup := NewDatabaseLookup(key, from, DatabaseLookupFlagTypeRI, excluded)

		data, err := lookup.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary failed: %v", err)
		}

		// Expected size: key(32) + from(32) + flags(1) + size(2) + excluded(2*32) = 131
		expectedSize := 32 + 32 + 1 + 2 + (2 * 32)
		if len(data) != expectedSize {
			t.Errorf("Expected size %d, got %d", expectedSize, len(data))
		}

		// Verify size
		if data[65] != 0 || data[66] != 2 {
			t.Errorf("Size should be 2, got %d%d", data[65], data[66])
		}
	})
}

// TestDatabaseLookupRoundTrip validates that MarshalBinary output is a valid
// I2NP wire format: the serialized bytes are checked field-by-field at their
// spec offsets (key, from, flags, big-endian size, excluded peers) so that a
// spec-compliant implementation can parse them.
func TestDatabaseLookupRoundTrip(t *testing.T) {
	key := common.Hash{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	from := common.Hash{17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	excluded := []common.Hash{{100, 101}, {200, 201}}

	original := NewDatabaseLookup(key, from, DatabaseLookupFlagTypeRI, excluded)

	// Marshal
	data, err := original.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	// Expected size: key(32) + from(32) + flags(1) + size(2) + excluded(2*32)
	expectedSize := 32 + 32 + 1 + 2 + 2*32
	if len(data) != expectedSize {
		t.Fatalf("Data size: got %d bytes, expected %d", len(data), expectedSize)
	}

	// Parse the wire bytes back and compare every field.
	parsed, err := ReadDatabaseLookup(data)
	if err != nil {
		t.Fatalf("ReadDatabaseLookup failed: %v", err)
	}

	if parsed.Key != key {
		t.Error("Key mismatch in round trip")
	}
	if parsed.From != from {
		t.Error("From mismatch in round trip")
	}
	if parsed.Flags != original.Flags {
		t.Errorf("Flags mismatch: expected 0x%02x, got 0x%02x", original.Flags, parsed.Flags)
	}
	if parsed.Size != 2 {
		t.Errorf("Size mismatch: expected 2, got %d", parsed.Size)
	}
	if len(parsed.ExcludedPeers) != 2 {
		t.Fatalf("ExcludedPeers count: expected 2, got %d", len(parsed.ExcludedPeers))
	}
	if parsed.ExcludedPeers[0] != excluded[0] || parsed.ExcludedPeers[1] != excluded[1] {
		t.Error("Excluded peer mismatch in round trip")
	}
}

// TestDatabaseLookupFlagConstants validates that the flag constants match the
// I2NP spec bit layout: bit 0 delivery (Direct=0x00, Tunnel=0x01), bits 3-2
// lookup type (Normal=0x00, LeaseSet=0x04, RouterInfo=0x08, Exploration=0x0C),
// and bit 4 ECIES (0x10).
func TestDatabaseLookupFlagConstants(t *testing.T) {
	// Direct should be 0x00 (bit 0 = 0)
	if DatabaseLookupFlagDirect != 0x00 {
		t.Errorf("Direct flag should be 0x00, got 0x%02x", DatabaseLookupFlagDirect)
	}

	// Tunnel should be 0x01 (bit 0 = 1)
	if DatabaseLookupFlagTunnel != 0x01 {
		t.Errorf("Tunnel flag should be 0x01, got 0x%02x", DatabaseLookupFlagTunnel)
	}

	// Type Normal should be 0x00 (bits 3-2 = 00)
	if DatabaseLookupFlagTypeNormal != 0x00 {
		t.Errorf("TypeNormal flag should be 0x00, got 0x%02x", DatabaseLookupFlagTypeNormal)
	}

	// Type LS should be 0x04 (bits 3-2 = 01)
	if DatabaseLookupFlagTypeLS != 0x04 {
		t.Errorf("TypeLS flag should be 0x04, got 0x%02x", DatabaseLookupFlagTypeLS)
	}

	// Type RI should be 0x08 (bits 3-2 = 10)
	if DatabaseLookupFlagTypeRI != 0x08 {
		t.Errorf("TypeRI flag should be 0x08, got 0x%02x", DatabaseLookupFlagTypeRI)
	}

	// Type Exploration should be 0x0C (bits 3-2 = 11)
	if DatabaseLookupFlagTypeExploration != 0x0C {
		t.Errorf("TypeExploration flag should be 0x0C, got 0x%02x", DatabaseLookupFlagTypeExploration)
	}

	// ECIES should be 0x10 (bit 4 = 1)
	if DatabaseLookupFlagECIES != 0x10 {
		t.Errorf("ECIES flag should be 0x10, got 0x%02x", DatabaseLookupFlagECIES)
	}
}

// TestDatabaseSearchReplyUnmarshalBinary validates that a DatabaseSearchReply
// payload (key(32) + count(1) + peer_hashes(count*32) + from(32)) round-trips
// through MarshalPayload/UnmarshalBinary, and that malformed payloads (too
// short, truncated peer hashes) are rejected.
func TestDatabaseSearchReplyUnmarshalBinary(t *testing.T) {
	t.Run("ValidReply", func(t *testing.T) {
		key := common.Hash{1, 2, 3, 4}
		from := common.Hash{5, 6, 7, 8}
		peers := []common.Hash{{9, 10}, {11, 12}}

		original := NewDatabaseSearchReply(key, from, peers)
		// Use MarshalPayload for round-trip with UnmarshalBinary
		// (MarshalBinary now includes the I2NP header)
		data, err := original.MarshalPayload()
		if err != nil {
			t.Fatalf("MarshalPayload failed: %v", err)
		}

		parsed := &DatabaseSearchReply{}
		if err := parsed.UnmarshalBinary(data); err != nil {
			t.Fatalf("UnmarshalBinary failed: %v", err)
		}

		if parsed.Key != key {
			t.Error("Key mismatch")
		}
		if parsed.From != from {
			t.Error("From mismatch")
		}
		if parsed.Count != 2 {
			t.Errorf("Expected count 2, got %d", parsed.Count)
		}
		if len(parsed.PeerHashes) != 2 {
			t.Errorf("Expected 2 peer hashes, got %d", len(parsed.PeerHashes))
		}
	})

	t.Run("TooShort", func(t *testing.T) {
		data := make([]byte, 50) // Less than minimum 65 bytes
		parsed := &DatabaseSearchReply{}
		err := parsed.UnmarshalBinary(data)
		if err == nil {
			t.Error("Should fail on too short data")
		}
	})

	t.Run("TruncatedPeerHashes", func(t *testing.T) {
		// Create valid header but truncate peer hashes
		// key(32) + count(1) + from(32) = 65 bytes minimum, but count says there are peers
		data := make([]byte, 66)
		data[32] = 5 // count = 5 peers (would need 32*5 more bytes)

		parsed := &DatabaseSearchReply{}
		err := parsed.UnmarshalBinary(data)
		if err == nil {
			t.Error("Should fail on truncated peer hashes")
		}
	})
}

// TestReadDatabaseSearchReply validates that the ReadDatabaseSearchReply
// convenience function parses a payload-only DatabaseSearchReply and returns
// the original key and from fields.
func TestReadDatabaseSearchReply(t *testing.T) {
	key := common.Hash{1, 2, 3, 4}
	from := common.Hash{5, 6, 7, 8}
	peers := []common.Hash{{9, 10}}

	original := NewDatabaseSearchReply(key, from, peers)
	// ReadDatabaseSearchReply expects payload-only data
	data, _ := original.MarshalPayload()

	result, err := ReadDatabaseSearchReply(data)
	if err != nil {
		t.Fatalf("ReadDatabaseSearchReply failed: %v", err)
	}

	if result.Key != key {
		t.Error("Key mismatch")
	}
	if result.From != from {
		t.Error("From mismatch")
	}
}

