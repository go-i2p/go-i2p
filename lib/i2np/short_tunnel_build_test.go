package i2np

import (
	"testing"
)

// TestShortTunnelBuild tests Short Tunnel Build message creation
func TestShortTunnelBuild(t *testing.T) {
	// Create test records
	records := make([]BuildRequestRecord, 3)

	builder := NewShortTunnelBuilder(records)

	if builder == nil {
		t.Fatal("expected non-nil builder")
	}

	stb, ok := builder.(*ShortTunnelBuild)
	if !ok {
		t.Fatal("builder is not ShortTunnelBuild type")
	}

	if stb.GetRecordCount() != 3 {
		t.Errorf("expected 3 records, got %d", stb.GetRecordCount())
	}

	retrievedRecords := stb.GetBuildRecords()
	if len(retrievedRecords) != 3 {
		t.Errorf("expected 3 build records, got %d", len(retrievedRecords))
	}
}

// TestShortTunnelBuildReply tests Short Tunnel Build Reply message creation
func TestShortTunnelBuildReply(t *testing.T) {
	// Create test response records
	records := make([]BuildResponseRecord, 3)

	reply := NewShortTunnelBuildReply(records)

	if reply == nil {
		t.Fatal("expected non-nil reply")
	}

	if reply.GetRecordCount() != 3 {
		t.Errorf("expected 3 records, got %d", reply.GetRecordCount())
	}

	retrievedRecords := reply.GetResponseRecords()
	if len(retrievedRecords) != 3 {
		t.Errorf("expected 3 response records, got %d", len(retrievedRecords))
	}
}

// TestShortTunnelBuildInterface verifies TunnelBuilder interface satisfaction
func TestShortTunnelBuildInterface(t *testing.T) {
	records := make([]BuildRequestRecord, 1)

	builder := NewShortTunnelBuilder(records)

	if builder == nil {
		t.Fatal("expected non-nil builder")
	}

	if builder.GetRecordCount() != 1 {
		t.Errorf("expected 1 record, got %d", builder.GetRecordCount())
	}
}

// TestMessageTypeConstants verifies STBM message type constants are defined
func TestMessageTypeConstants(t *testing.T) {
	if I2NP_MESSAGE_TYPE_SHORT_TUNNEL_BUILD != 25 {
		t.Errorf("SHORT_TUNNEL_BUILD should be 25, got %d", I2NP_MESSAGE_TYPE_SHORT_TUNNEL_BUILD)
	}

	if I2NP_MESSAGE_TYPE_SHORT_TUNNEL_BUILD_REPLY != 26 {
		t.Errorf("SHORT_TUNNEL_BUILD_REPLY should be 26, got %d", I2NP_MESSAGE_TYPE_SHORT_TUNNEL_BUILD_REPLY)
	}
}
