package i2np

import (
	"testing"
)

// TestShortTunnelBuildReplyImplementsTunnelReplyHandler verifies interface satisfaction
func TestShortTunnelBuildReplyImplementsTunnelReplyHandler(t *testing.T) {
	// This should compile if ShortTunnelBuildReply implements TunnelReplyHandler
	var _ TunnelReplyHandler = (*ShortTunnelBuildReply)(nil)
}

// TestNewShortTunnelBuildReply tests the constructor
func TestNewShortTunnelBuildReply(t *testing.T) {
	records := []BuildResponseRecord{
		createTestBuildResponseRecord(TunnelBuildReplySuccess),
		createTestBuildResponseRecord(TunnelBuildReplySuccess),
	}

	reply := NewShortTunnelBuildReply(records)

	if reply == nil {
		t.Fatal("NewShortTunnelBuildReply returned nil")
	}

	if reply.Count != 2 {
		t.Errorf("Expected Count=2, got %d", reply.Count)
	}

	if len(reply.BuildResponseRecords) != 2 {
		t.Errorf("Expected 2 records, got %d", len(reply.BuildResponseRecords))
	}
}

// TestShortTunnelBuildReplyGetReplyRecords tests the GetReplyRecords method
func TestShortTunnelBuildReplyGetReplyRecords(t *testing.T) {
	records := []BuildResponseRecord{
		createTestBuildResponseRecord(TunnelBuildReplySuccess),
		createTestBuildResponseRecord(TunnelBuildReplyReject),
	}

	reply := NewShortTunnelBuildReply(records)
	replyRecords := reply.GetReplyRecords()

	if len(replyRecords) != 2 {
		t.Errorf("Expected 2 records from GetReplyRecords, got %d", len(replyRecords))
	}

	// Verify records are the same
	if replyRecords[0].Reply != TunnelBuildReplySuccess {
		t.Errorf("Expected first record Reply=%d, got %d", TunnelBuildReplySuccess, replyRecords[0].Reply)
	}

	if replyRecords[1].Reply != TunnelBuildReplyReject {
		t.Errorf("Expected second record Reply=%d, got %d", TunnelBuildReplyReject, replyRecords[1].Reply)
	}
}

// TestShortTunnelBuildReplyGetResponseRecords tests backward compatibility
func TestShortTunnelBuildReplyGetResponseRecords(t *testing.T) {
	records := []BuildResponseRecord{
		createTestBuildResponseRecord(TunnelBuildReplySuccess),
	}

	reply := NewShortTunnelBuildReply(records)

	// Both methods should return the same data
	responseRecords := reply.GetResponseRecords()
	replyRecords := reply.GetReplyRecords()

	if len(responseRecords) != len(replyRecords) {
		t.Errorf("GetResponseRecords and GetReplyRecords return different lengths: %d vs %d",
			len(responseRecords), len(replyRecords))
	}
}

// TestShortTunnelBuildReplyProcessReplyAllSuccess tests ProcessReply with all hops accepting
func TestShortTunnelBuildReplyProcessReplyAllSuccess(t *testing.T) {
	records := []BuildResponseRecord{
		createTestBuildResponseRecord(TunnelBuildReplySuccess),
		createTestBuildResponseRecord(TunnelBuildReplySuccess),
		createTestBuildResponseRecord(TunnelBuildReplySuccess),
	}

	reply := NewShortTunnelBuildReply(records)
	err := reply.ProcessReply()
	if err != nil {
		t.Errorf("ProcessReply should succeed when all hops accept, got error: %v", err)
	}
}

// TestShortTunnelBuildReplyProcessReplyWithRejection tests ProcessReply with rejections
func TestShortTunnelBuildReplyProcessReplyWithRejection(t *testing.T) {
	records := []BuildResponseRecord{
		createTestBuildResponseRecord(TunnelBuildReplySuccess),
		createTestBuildResponseRecord(TunnelBuildReplyReject), // One hop rejects
		createTestBuildResponseRecord(TunnelBuildReplySuccess),
	}

	reply := NewShortTunnelBuildReply(records)
	err := reply.ProcessReply()

	if err == nil {
		t.Error("ProcessReply should fail when any hop rejects")
	}

	expectedSubstring := "1 of 3 hops rejected"
	if !containsSubstring(err.Error(), expectedSubstring) {
		t.Errorf("Error should contain '%s', got: %s", expectedSubstring, err.Error())
	}
}

// TestShortTunnelBuildReplyProcessReplyAllRejected tests ProcessReply when all hops reject
func TestShortTunnelBuildReplyProcessReplyAllRejected(t *testing.T) {
	records := []BuildResponseRecord{
		createTestBuildResponseRecord(TunnelBuildReplyOverload),
		createTestBuildResponseRecord(TunnelBuildReplyBandwidth),
	}

	reply := NewShortTunnelBuildReply(records)
	err := reply.ProcessReply()

	if err == nil {
		t.Error("ProcessReply should fail when all hops reject")
	}

	expectedSubstring := "2 of 2 hops rejected"
	if !containsSubstring(err.Error(), expectedSubstring) {
		t.Errorf("Error should contain '%s', got: %s", expectedSubstring, err.Error())
	}
}

// TestShortTunnelBuildReplyProcessReplyNoRecords tests ProcessReply with empty records
func TestShortTunnelBuildReplyProcessReplyNoRecords(t *testing.T) {
	reply := &ShortTunnelBuildReply{
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

// TestShortTunnelBuildReplyProcessReplyCountMismatch tests ProcessReply with count mismatch
func TestShortTunnelBuildReplyProcessReplyCountMismatch(t *testing.T) {
	reply := &ShortTunnelBuildReply{
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

// TestShortTunnelBuildReplyGetRecordCount tests GetRecordCount method
func TestShortTunnelBuildReplyGetRecordCount(t *testing.T) {
	records := []BuildResponseRecord{
		createTestBuildResponseRecord(TunnelBuildReplySuccess),
		createTestBuildResponseRecord(TunnelBuildReplySuccess),
		createTestBuildResponseRecord(TunnelBuildReplySuccess),
	}

	reply := NewShortTunnelBuildReply(records)

	if reply.GetRecordCount() != 3 {
		t.Errorf("Expected GetRecordCount()=3, got %d", reply.GetRecordCount())
	}
}

// TestShortTunnelBuildReplyVariousReplyCodes tests handling of various reply codes
func TestShortTunnelBuildReplyVariousReplyCodes(t *testing.T) {
	testCases := []struct {
		name       string
		replyCode  byte
		shouldPass bool
	}{
		{"Success", TunnelBuildReplySuccess, true},
		{"Reject", TunnelBuildReplyReject, false},
		{"Overload", TunnelBuildReplyOverload, false},
		{"Bandwidth", TunnelBuildReplyBandwidth, false},
		{"Invalid", TunnelBuildReplyInvalid, false},
		{"Expired", TunnelBuildReplyExpired, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			records := []BuildResponseRecord{
				createTestBuildResponseRecord(tc.replyCode),
			}

			reply := NewShortTunnelBuildReply(records)
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

	return CreateBuildResponseRecord(replyCode, randomData)
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
