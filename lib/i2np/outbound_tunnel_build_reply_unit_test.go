// Tests for I2NP OutboundTunnelBuildReply message serialization and deserialization.
package i2np

import (
	"testing"
)

// TestOutboundTunnelBuildReplyImplementsTunnelReplyHandler verifies interface satisfaction
func TestOutboundTunnelBuildReplyImplementsTunnelReplyHandler(t *testing.T) {
	// This should compile if OutboundTunnelBuildReply implements TunnelReplyHandler
	var _ TunnelReplyHandler = (*OutboundTunnelBuildReply)(nil)
}

// TestNewOutboundTunnelBuildReply tests the constructor
func TestNewOutboundTunnelBuildReply(t *testing.T) {
	records := []BuildResponseRecord{
		createTestBuildResponseRecord(TunnelBuildReplySuccess),
		createTestBuildResponseRecord(TunnelBuildReplySuccess),
	}

	reply := NewOutboundTunnelBuildReply(records)

	if reply == nil {
		t.Fatal("NewOutboundTunnelBuildReply returned nil")
	}

	if reply.Count != 2 {
		t.Errorf("Expected Count=2, got %d", reply.Count)
	}

	if len(reply.BuildResponseRecords) != 2 {
		t.Errorf("Expected 2 records, got %d", len(reply.BuildResponseRecords))
	}
}

// TestOutboundTunnelBuildReplyGetReplyRecords tests the GetReplyRecords method
func TestOutboundTunnelBuildReplyGetReplyRecords(t *testing.T) {
	records := []BuildResponseRecord{
		createTestBuildResponseRecord(TunnelBuildReplySuccess),
		createTestBuildResponseRecord(TunnelBuildReplyProbabilisticReject),
	}

	reply := NewOutboundTunnelBuildReply(records)
	replyRecords := reply.GetReplyRecords()

	if len(replyRecords) != 2 {
		t.Errorf("Expected 2 records from GetReplyRecords, got %d", len(replyRecords))
	}

	// Verify records are the same
	if replyRecords[0].Reply != TunnelBuildReplySuccess {
		t.Errorf("Expected first record Reply=%d, got %d", TunnelBuildReplySuccess, replyRecords[0].Reply)
	}

	if replyRecords[1].Reply != TunnelBuildReplyProbabilisticReject {
		t.Errorf("Expected second record Reply=%d, got %d", TunnelBuildReplyProbabilisticReject, replyRecords[1].Reply)
	}
}

// TestOutboundTunnelBuildReplyProcessReplyAllSuccess tests ProcessReply with all hops accepting
func TestOutboundTunnelBuildReplyProcessReplyAllSuccess(t *testing.T) {
	records := []BuildResponseRecord{
		createTestBuildResponseRecord(TunnelBuildReplySuccess),
		createTestBuildResponseRecord(TunnelBuildReplySuccess),
		createTestBuildResponseRecord(TunnelBuildReplySuccess),
	}

	reply := NewOutboundTunnelBuildReply(records)
	err := reply.ProcessReply()
	if err != nil {
		t.Errorf("ProcessReply should succeed when all hops accept, got error: %v", err)
	}
}

// TestOutboundTunnelBuildReplyProcessReplyWithRejection tests ProcessReply with rejections
func TestOutboundTunnelBuildReplyProcessReplyWithRejection(t *testing.T) {
	records := []BuildResponseRecord{
		createTestBuildResponseRecord(TunnelBuildReplySuccess),
		createTestBuildResponseRecord(TunnelBuildReplyProbabilisticReject), // One hop rejects
		createTestBuildResponseRecord(TunnelBuildReplySuccess),
	}

	reply := NewOutboundTunnelBuildReply(records)
	err := reply.ProcessReply()

	if err == nil {
		t.Error("ProcessReply should fail when any hop rejects")
	}

	expectedSubstring := "1 of 3 hops rejected"
	if !containsSubstring(err.Error(), expectedSubstring) {
		t.Errorf("Error should contain '%s', got: %s", expectedSubstring, err.Error())
	}
}

// TestOutboundTunnelBuildReplyProcessReplyAllRejected tests ProcessReply when all hops reject
func TestOutboundTunnelBuildReplyProcessReplyAllRejected(t *testing.T) {
	records := []BuildResponseRecord{
		createTestBuildResponseRecord(TunnelBuildReplyTransientOverload),
		createTestBuildResponseRecord(TunnelBuildReplyBandwidth),
	}

	reply := NewOutboundTunnelBuildReply(records)
	err := reply.ProcessReply()

	if err == nil {
		t.Error("ProcessReply should fail when all hops reject")
	}

	expectedSubstring := "2 of 2 hops rejected"
	if !containsSubstring(err.Error(), expectedSubstring) {
		t.Errorf("Error should contain '%s', got: %s", expectedSubstring, err.Error())
	}
}

// TestOutboundTunnelBuildReplyProcessReplyNoRecords tests ProcessReply with empty records
func TestOutboundTunnelBuildReplyProcessReplyNoRecords(t *testing.T) {
	reply := &OutboundTunnelBuildReply{
		Count:                0,
		BuildResponseRecords: []BuildResponseRecord{},
	}

	err := reply.ProcessReply()

	if err == nil {
		t.Error("ProcessReply should fail with no records")
	}

	expectedSubstring := "no response records"
	if !containsSubstring(err.Error(), expectedSubstring) {
		t.Errorf("Error should contain '%s', got: %s", expectedSubstring, err.Error())
	}
}

// TestOutboundTunnelBuildReplyProcessReplyCountMismatch tests ProcessReply with count mismatch
func TestOutboundTunnelBuildReplyProcessReplyCountMismatch(t *testing.T) {
	reply := &OutboundTunnelBuildReply{
		Count: 5, // Claims 5 records
		BuildResponseRecords: []BuildResponseRecord{
			createTestBuildResponseRecord(TunnelBuildReplySuccess),
			createTestBuildResponseRecord(TunnelBuildReplySuccess),
		}, // Actually has 2 records
	}

	err := reply.ProcessReply()

	if err == nil {
		t.Error("ProcessReply should fail with count mismatch")
	}

	expectedSubstring := "count mismatch"
	if !containsSubstring(err.Error(), expectedSubstring) {
		t.Errorf("Error should contain '%s', got: %s", expectedSubstring, err.Error())
	}
}

// TestOutboundTunnelBuildReplyGetRecordCount tests GetRecordCount method
func TestOutboundTunnelBuildReplyGetRecordCount(t *testing.T) {
	records := []BuildResponseRecord{
		createTestBuildResponseRecord(TunnelBuildReplySuccess),
		createTestBuildResponseRecord(TunnelBuildReplySuccess),
		createTestBuildResponseRecord(TunnelBuildReplySuccess),
	}

	reply := NewOutboundTunnelBuildReply(records)

	if reply.GetRecordCount() != 3 {
		t.Errorf("Expected GetRecordCount()=3, got %d", reply.GetRecordCount())
	}
}

// TestOutboundTunnelBuildReplyVariousReplyCodes tests handling of various reply codes
func TestOutboundTunnelBuildReplyVariousReplyCodes(t *testing.T) {
	testCases := []struct {
		name       string
		replyCode  byte
		shouldPass bool
	}{
		{"Success", TunnelBuildReplySuccess, true},
		{"Reject", TunnelBuildReplyProbabilisticReject, false},
		{"Overload", TunnelBuildReplyTransientOverload, false},
		{"Bandwidth", TunnelBuildReplyBandwidth, false},
		{"Critical", TunnelBuildReplyCritical, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			records := []BuildResponseRecord{
				createTestBuildResponseRecord(tc.replyCode),
			}

			reply := NewOutboundTunnelBuildReply(records)
			err := reply.ProcessReply()

			if tc.shouldPass && err != nil {
				t.Errorf("Expected success for reply code %d, got error: %v", tc.replyCode, err)
			}

			if !tc.shouldPass && err == nil {
				t.Errorf("Expected failure for reply code %d, but got success", tc.replyCode)
			}
		})
	}
}

// Helper function to create a test BuildResponseRecord with correct hash
func createTestBuildResponseRecord(replyCode byte) BuildResponseRecord {
	var randomData [495]byte
	// Fill with some test data
	for i := range randomData {
		randomData[i] = byte(i % 256)
	}

	return newTestBuildResponseRecord(replyCode, randomData)
}

// Helper function to check if a string contains a substring
func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
