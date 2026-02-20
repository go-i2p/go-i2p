package i2np

import (
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/tunnel"
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

// TestShortBuildRecordSize verifies the constant matches the I2P specification
func TestShortBuildRecordSize(t *testing.T) {
	if ShortBuildRecordSize != 218 {
		t.Errorf("ShortBuildRecordSize should be 218, got %d", ShortBuildRecordSize)
	}
	if StandardBuildRecordSize != 528 {
		t.Errorf("StandardBuildRecordSize should be 528, got %d", StandardBuildRecordSize)
	}
	if ShortBuildRecordCleartextLen != 154 {
		t.Errorf("ShortBuildRecordCleartextLen should be 154, got %d", ShortBuildRecordCleartextLen)
	}
	// Verify: encrypted size = cleartext + header (toPeer 16 + ephKey 32 + MAC 16 = 64)
	if ShortBuildRecordSize != ShortBuildRecordCleartextLen+ShortRecordHeaderSize {
		t.Errorf("ShortBuildRecordSize (%d) should equal ShortBuildRecordCleartextLen (%d) + ShortRecordHeaderSize (%d)",
			ShortBuildRecordSize, ShortBuildRecordCleartextLen, ShortRecordHeaderSize)
	}
}

// TestShortBytesLength verifies ShortBytes returns exactly 218 bytes
func TestShortBytesLength(t *testing.T) {
	record := BuildRequestRecord{
		ReceiveTunnel: tunnel.TunnelID(12345),
		NextTunnel:    tunnel.TunnelID(67890),
		RequestTime:   time.Now(),
		SendMessageID: 42,
	}
	copy(record.OurIdent[:], make([]byte, 32))
	copy(record.NextIdent[:], make([]byte, 32))

	shortData := record.ShortBytes()
	if len(shortData) != ShortBuildRecordSize {
		t.Errorf("ShortBytes() returned %d bytes, expected %d", len(shortData), ShortBuildRecordSize)
	}
}

// TestShortBytesVsStandardBytes verifies short records are smaller than standard
func TestShortBytesVsStandardBytes(t *testing.T) {
	record := BuildRequestRecord{
		ReceiveTunnel: tunnel.TunnelID(100),
		NextTunnel:    tunnel.TunnelID(200),
		RequestTime:   time.Now(),
		SendMessageID: 1,
	}

	standardData := record.Bytes()
	shortData := record.ShortBytes()

	if len(standardData) != StandardBuildRecordCleartextLen {
		t.Errorf("Bytes() returned %d bytes, expected %d", len(standardData), StandardBuildRecordCleartextLen)
	}
	if len(shortData) != ShortBuildRecordSize {
		t.Errorf("ShortBytes() returned %d bytes, expected %d", len(shortData), ShortBuildRecordSize)
	}
	if len(shortData) >= len(standardData) {
		t.Errorf("Short record (%d bytes) should be smaller than standard cleartext (%d bytes)",
			len(shortData), len(standardData))
	}
}

// TestShortTunnelBuildBytesRecordSize verifies Bytes() uses 218-byte records
func TestShortTunnelBuildBytesRecordSize(t *testing.T) {
	records := make([]BuildRequestRecord, 4)
	for i := range records {
		records[i] = BuildRequestRecord{
			ReceiveTunnel: tunnel.TunnelID(i + 1),
			NextTunnel:    tunnel.TunnelID(i + 100),
			RequestTime:   time.Now(),
			SendMessageID: i,
		}
	}

	builder := NewShortTunnelBuilder(records)
	stb := builder.(*ShortTunnelBuild)
	data := stb.Bytes()

	// Expected size: 1 byte count + 4 * 218 bytes per record
	expectedSize := 1 + (4 * ShortBuildRecordSize)
	if len(data) != expectedSize {
		t.Errorf("ShortTunnelBuild.Bytes() returned %d bytes, expected %d (1 + 4*%d)",
			len(data), expectedSize, ShortBuildRecordSize)
	}

	// Verify count byte
	if data[0] != 4 {
		t.Errorf("Record count byte should be 4, got %d", data[0])
	}
}

// TestShortBytesFieldLayout verifies the short record cleartext field positions
func TestShortBytesFieldLayout(t *testing.T) {
	var ourIdent common.Hash
	for i := range ourIdent {
		ourIdent[i] = byte(0xAA)
	}
	var nextIdent common.Hash
	for i := range nextIdent {
		nextIdent[i] = byte(0xBB)
	}

	record := BuildRequestRecord{
		ReceiveTunnel: tunnel.TunnelID(0x01020304),
		NextTunnel:    tunnel.TunnelID(0x05060708),
		OurIdent:      ourIdent,
		NextIdent:     nextIdent,
		Flag:          0x80,                  // inbound gateway flag
		RequestTime:   time.Unix(60*1000, 0), // 1000 minutes since epoch
		SendMessageID: 0x0A0B0C0D,
	}

	data := record.ShortBytes()

	// toPeer: first 16 bytes should be truncated OurIdent
	for i := 0; i < 16; i++ {
		if data[i] != 0xAA {
			t.Errorf("toPeer byte %d: expected 0xAA, got 0x%02X", i, data[i])
			break
		}
	}

	// Ephemeral key (offset 16-48): should be zeroed (placeholder)
	for i := 16; i < 48; i++ {
		if data[i] != 0 {
			t.Errorf("Ephemeral key byte %d: expected 0x00, got 0x%02X", i, data[i])
			break
		}
	}

	// Payload offset 48: next_ident at payload+8 = offset 56
	for i := 56; i < 88; i++ {
		if data[i] != 0xBB {
			t.Errorf("NextIdent byte %d: expected 0xBB, got 0x%02X", i, data[i])
			break
		}
	}

	// Flag at payload+40 = offset 88
	if data[88] != 0x80 {
		t.Errorf("Flag: expected 0x80, got 0x%02X", data[88])
	}
}
