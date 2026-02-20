package i2np

import (
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTunnelBuildMessage_SerializeDeserialize tests round-trip serialization
func TestTunnelBuildMessage_SerializeDeserialize(t *testing.T) {
	// Create test records with known values
	records := createKnownValueBuildRequestRecords()

	// Create message
	originalMsg := NewTunnelBuildMessage(records)
	originalMsg.SetMessageID(42)

	// Verify data was serialized
	data := originalMsg.GetData()
	require.Equal(t, 8*528, len(data), "Data should be 8 records * 528 bytes each")

	// Verify first record's cleartext is in the data
	firstRecordCleartext := records[0].Bytes()
	assert.Equal(t, firstRecordCleartext, data[0:222], "First record cleartext should match")

	// Marshal to wire format
	wireData, err := originalMsg.MarshalBinary()
	require.NoError(t, err)
	require.True(t, len(wireData) > 16, "Wire data should include I2NP header")

	// Unmarshal into new message
	newMsg := &TunnelBuildMessage{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_TUNNEL_BUILD),
	}
	err = newMsg.UnmarshalBinary(wireData)
	require.NoError(t, err)

	// Verify message fields
	assert.Equal(t, originalMsg.Type(), newMsg.Type())
	assert.Equal(t, originalMsg.MessageID(), newMsg.MessageID())
	assert.Equal(t, 8, newMsg.GetRecordCount())

	// Verify each record was preserved
	newRecords := newMsg.GetBuildRecords()
	for i := 0; i < 8; i++ {
		assert.Equal(t, records[i].ReceiveTunnel, newRecords[i].ReceiveTunnel, "Record %d ReceiveTunnel mismatch", i)
		assert.Equal(t, records[i].NextTunnel, newRecords[i].NextTunnel, "Record %d NextTunnel mismatch", i)
		assert.Equal(t, records[i].OurIdent, newRecords[i].OurIdent, "Record %d OurIdent mismatch", i)
		assert.Equal(t, records[i].NextIdent, newRecords[i].NextIdent, "Record %d NextIdent mismatch", i)
		assert.Equal(t, records[i].Flag, newRecords[i].Flag, "Record %d Flag mismatch", i)
		assert.Equal(t, records[i].SendMessageID, newRecords[i].SendMessageID, "Record %d SendMessageID mismatch", i)
	}
}

// TestTunnelBuildMessage_RecordSerialization tests individual record serialization
func TestTunnelBuildMessage_RecordSerialization(t *testing.T) {
	records := createKnownValueBuildRequestRecords()
	msg := NewTunnelBuildMessage(records)

	data := msg.GetData()

	// Verify each record's serialization in the data
	for i := 0; i < 8; i++ {
		expectedCleartext := records[i].Bytes()
		actualCleartext := data[i*528 : i*528+222]

		assert.Equal(t, expectedCleartext, actualCleartext, "Record %d cleartext mismatch", i)

		// Verify padding is random (non-zero) per spec requirement
		padding := data[i*528+222 : (i+1)*528]
		allZero := true
		for _, b := range padding {
			if b != 0 {
				allZero = false
				break
			}
		}
		assert.False(t, allZero, "Record %d padding should be random, not all zeros", i)
	}
}

// TestTunnelBuildMessage_EmptyRecords tests handling of empty/zero records
func TestTunnelBuildMessage_EmptyRecords(t *testing.T) {
	var records [8]BuildRequestRecord

	msg := NewTunnelBuildMessage(records)

	// Should still create valid message structure
	assert.Equal(t, I2NP_MESSAGE_TYPE_TUNNEL_BUILD, msg.Type())
	assert.Equal(t, 8, msg.GetRecordCount())
	assert.Equal(t, 8*528, len(msg.GetData()))
}

// TestTunnelBuildMessage_InvalidDataSize tests error handling for invalid data size
func TestTunnelBuildMessage_InvalidDataSize(t *testing.T) {
	msg := &TunnelBuildMessage{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_TUNNEL_BUILD),
	}

	// Set invalid data size
	msg.SetData(make([]byte, 100))

	// Create wire format
	wireData, err := msg.MarshalBinary()
	require.NoError(t, err)

	// Try to unmarshal - should fail due to wrong size
	newMsg := &TunnelBuildMessage{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_TUNNEL_BUILD),
	}
	err = newMsg.UnmarshalBinary(wireData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid TunnelBuild data size")
}

// TestTunnelBuildMessage_RecordParsing tests that parsed records match original
func TestTunnelBuildMessage_RecordParsing(t *testing.T) {
	// Create records with specific test values
	records := [8]BuildRequestRecord{
		{
			ReceiveTunnel: tunnel.TunnelID(1000),
			NextTunnel:    tunnel.TunnelID(2000),
			OurIdent:      hashFromString("ident_0"),
			NextIdent:     hashFromString("next_0"),
			LayerKey:      sessionKeyFromString("layer_0"),
			IVKey:         sessionKeyFromString("iv_0"),
			ReplyKey:      sessionKeyFromString("reply_0"),
			Flag:          1,
			RequestTime:   time.Unix(3600*100, 0), // 100 hours since epoch
			SendMessageID: 5000,
		},
	}

	// Fill remaining records with zeros (simpler test)
	msg := NewTunnelBuildMessage(records)

	// Get the data and parse it back
	data := msg.GetData()

	// Parse first record manually
	parsedRecord, err := ReadBuildRequestRecord(data[0:528])
	require.NoError(t, err)

	// Verify parsed record matches original
	assert.Equal(t, records[0].ReceiveTunnel, parsedRecord.ReceiveTunnel)
	assert.Equal(t, records[0].NextTunnel, parsedRecord.NextTunnel)
	assert.Equal(t, records[0].OurIdent, parsedRecord.OurIdent)
	assert.Equal(t, records[0].NextIdent, parsedRecord.NextIdent)
	assert.Equal(t, records[0].Flag, parsedRecord.Flag)
	assert.Equal(t, records[0].SendMessageID, parsedRecord.SendMessageID)

	// Time should match (hours since epoch)
	expectedHours := records[0].RequestTime.Unix() / 3600
	actualHours := parsedRecord.RequestTime.Unix() / 3600
	assert.Equal(t, expectedHours, actualHours, "RequestTime hours mismatch")
}

// TestTunnelBuild_GetBuildRecords tests TunnelBuild interface
func TestTunnelBuild_GetBuildRecords(t *testing.T) {
	records := createKnownValueBuildRequestRecords()
	tb := NewTunnelBuilder(records)

	buildRecords := tb.GetBuildRecords()
	assert.Equal(t, 8, len(buildRecords))
	assert.Equal(t, 8, tb.GetRecordCount())

	// Verify records match
	for i := 0; i < 8; i++ {
		assert.Equal(t, records[i].ReceiveTunnel, buildRecords[i].ReceiveTunnel)
	}
}

// TestTunnelBuildMessage_Interfaces verifies all interfaces are satisfied
func TestTunnelBuildMessage_Interfaces(t *testing.T) {
	records := createKnownValueBuildRequestRecords()
	msg := NewTunnelBuildMessage(records)

	// Verify I2NPMessage interface
	assert.Equal(t, I2NP_MESSAGE_TYPE_TUNNEL_BUILD, msg.Type())
	assert.NotNil(t, msg.GetData())

	// Verify TunnelBuilder interface
	assert.Equal(t, 8, msg.GetRecordCount())
	assert.Equal(t, 8, len(msg.GetBuildRecords()))

	// Verify MessageSerializer interface
	data, err := msg.MarshalBinary()
	assert.NoError(t, err)
	assert.NotNil(t, data)
}

// TestTunnelBuildMessage_DataConsistency tests that data field matches records
func TestTunnelBuildMessage_DataConsistency(t *testing.T) {
	records := createKnownValueBuildRequestRecords()
	msg := NewTunnelBuildMessage(records)

	actualData := msg.GetData()
	require.Len(t, actualData, 8*528, "Total data length must be 8*528 bytes")

	// Verify each record's 222-byte cleartext matches, and that the
	// remaining 306-byte padding region is not all zeros (random fill).
	for i := 0; i < 8; i++ {
		cleartext := records[i].Bytes()
		slotStart := i * 528
		assert.Equal(t, cleartext, actualData[slotStart:slotStart+222],
			"Record %d cleartext should match", i)

		padding := actualData[slotStart+222 : slotStart+528]
		allZero := true
		for _, b := range padding {
			if b != 0 {
				allZero = false
				break
			}
		}
		assert.False(t, allZero, "Record %d padding should be random, not all zeros", i)
	}
}

// Helper functions

// createKnownValueBuildRequestRecords creates records with deterministic test values
func createKnownValueBuildRequestRecords() [8]BuildRequestRecord {
	var records [8]BuildRequestRecord

	for i := 0; i < 8; i++ {
		records[i] = BuildRequestRecord{
			ReceiveTunnel: tunnel.TunnelID(1000 + i),
			NextTunnel:    tunnel.TunnelID(2000 + i),
			OurIdent:      hashFromString("our_ident_" + string(rune('0'+i))),
			NextIdent:     hashFromString("next_ident_" + string(rune('0'+i))),
			LayerKey:      sessionKeyFromString("layer_key_" + string(rune('0'+i))),
			IVKey:         sessionKeyFromString("iv_key_" + string(rune('0'+i))),
			ReplyKey:      sessionKeyFromString("reply_key_" + string(rune('0'+i))),
			ReplyIV:       ivFromString("reply_iv_" + string(rune('0'+i))),
			Flag:          i % 2,                           // Alternate 0 and 1
			RequestTime:   time.Unix(3600*int64(100+i), 0), // Hours since epoch
			SendMessageID: 5000 + i,
		}

		// Set padding with known values for testing
		for j := 0; j < 29; j++ {
			records[i].Padding[j] = byte(i*29 + j)
		}
	}

	return records
}

// hashFromString creates a Hash from a string (for testing)
func hashFromString(s string) common.Hash {
	var hash common.Hash
	copy(hash[:], []byte(s))
	return hash
}

// sessionKeyFromString creates a SessionKey from a string (for testing)
func sessionKeyFromString(s string) session_key.SessionKey {
	var key session_key.SessionKey
	copy(key[:], []byte(s))
	return key
}

// ivFromString creates a 16-byte IV from a string (for testing)
func ivFromString(s string) [16]byte {
	var iv [16]byte
	copy(iv[:], []byte(s))
	return iv
}

// Benchmark tests

func BenchmarkTunnelBuildMessage_Create(b *testing.B) {
	records := createKnownValueBuildRequestRecords()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewTunnelBuildMessage(records)
	}
}

func BenchmarkTunnelBuildMessage_MarshalUnmarshal(b *testing.B) {
	records := createKnownValueBuildRequestRecords()
	msg := NewTunnelBuildMessage(records)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		data, _ := msg.MarshalBinary()

		newMsg := &TunnelBuildMessage{
			BaseI2NPMessage: NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_TUNNEL_BUILD),
		}
		_ = newMsg.UnmarshalBinary(data)
	}
}

func BenchmarkTunnelBuildMessage_Serialize(b *testing.B) {
	records := createKnownValueBuildRequestRecords()
	msg := NewTunnelBuildMessage(records)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = msg.MarshalBinary()
	}
}
