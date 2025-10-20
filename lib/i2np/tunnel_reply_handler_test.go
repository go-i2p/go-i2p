package i2np

import (
	"fmt"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
)

// TestTunnelBuildReply_ProcessReply_AllSuccess tests successful tunnel build with all hops accepting
func TestTunnelBuildReply_ProcessReply_AllSuccess(t *testing.T) {
	reply := createSuccessfulTunnelBuildReply()

	err := reply.ProcessReply()

	assert.NoError(t, err, "ProcessReply should succeed when all hops accept")
}

// TestTunnelBuildReply_ProcessReply_AllReject tests tunnel build failure with all hops rejecting
func TestTunnelBuildReply_ProcessReply_AllReject(t *testing.T) {
	reply := createRejectedTunnelBuildReply()

	err := reply.ProcessReply()

	assert.Error(t, err, "ProcessReply should fail when all hops reject")
	assert.Contains(t, err.Error(), "tunnel build failed")
	// The error message will contain the first hop's rejection, not the count
	assert.Contains(t, err.Error(), "rejected request")
}

// TestTunnelBuildReply_ProcessReply_MixedResponses tests tunnel build with mixed success/failure
func TestTunnelBuildReply_ProcessReply_MixedResponses(t *testing.T) {
	reply := createMixedTunnelBuildReply()

	err := reply.ProcessReply()

	assert.Error(t, err, "ProcessReply should fail when not all hops accept")
	assert.Contains(t, err.Error(), "tunnel build failed")
}

// TestTunnelBuildReply_ProcessReply_SingleFailure tests tunnel build with one hop failure
func TestTunnelBuildReply_ProcessReply_SingleFailure(t *testing.T) {
	reply := createSingleFailureTunnelBuildReply()

	err := reply.ProcessReply()

	assert.Error(t, err, "ProcessReply should fail when any hop rejects")
	assert.Contains(t, err.Error(), "router overloaded")
}

// TestTunnelBuildReply_ProcessReply_UnknownReplyCode tests handling of unknown reply codes
func TestTunnelBuildReply_ProcessReply_UnknownReplyCode(t *testing.T) {
	reply := createUnknownReplyCodeTunnelBuildReply()

	err := reply.ProcessReply()

	assert.Error(t, err, "ProcessReply should fail with unknown reply codes")
	assert.Contains(t, err.Error(), "unknown reply code")
}

// TestTunnelBuildReply_ProcessReply_EmptyHash tests handling of invalid response records
func TestTunnelBuildReply_ProcessReply_EmptyHash(t *testing.T) {
	reply := createEmptyHashTunnelBuildReply()

	err := reply.ProcessReply()

	assert.Error(t, err, "ProcessReply should fail with empty hash records")
	assert.Contains(t, err.Error(), "empty hash")
}

// TestVariableTunnelBuildReply_ProcessReply_AllSuccess tests successful variable tunnel build
func TestVariableTunnelBuildReply_ProcessReply_AllSuccess(t *testing.T) {
	reply := createSuccessfulVariableTunnelBuildReply(3)

	err := reply.ProcessReply()

	assert.NoError(t, err, "ProcessReply should succeed when all hops accept")
}

// TestVariableTunnelBuildReply_ProcessReply_CountMismatch tests count field validation
func TestVariableTunnelBuildReply_ProcessReply_CountMismatch(t *testing.T) {
	reply := createSuccessfulVariableTunnelBuildReply(3)
	reply.Count = 5 // Mismatch with actual record count

	err := reply.ProcessReply()

	assert.Error(t, err, "ProcessReply should fail with count mismatch")
	assert.Contains(t, err.Error(), "count mismatch")
}

// TestVariableTunnelBuildReply_ProcessReply_EmptyRecords tests handling of empty tunnel
func TestVariableTunnelBuildReply_ProcessReply_EmptyRecords(t *testing.T) {
	reply := &VariableTunnelBuildReply{
		Count:                0,
		BuildResponseRecords: []BuildResponseRecord{},
	}

	err := reply.ProcessReply()

	assert.Error(t, err, "ProcessReply should fail with no records")
	assert.Contains(t, err.Error(), "no response records")
}

// TestVariableTunnelBuildReply_ProcessReply_MixedResponses tests variable tunnel with mixed responses
func TestVariableTunnelBuildReply_ProcessReply_MixedResponses(t *testing.T) {
	reply := createMixedVariableTunnelBuildReply(4)

	err := reply.ProcessReply()

	assert.Error(t, err, "ProcessReply should fail when not all hops accept")
	assert.Contains(t, err.Error(), "variable tunnel build failed")
}

// TestVariableTunnelBuildReply_ProcessReply_SingleHop tests single hop variable tunnel
func TestVariableTunnelBuildReply_ProcessReply_SingleHop(t *testing.T) {
	reply := createSuccessfulVariableTunnelBuildReply(1)

	err := reply.ProcessReply()

	assert.NoError(t, err, "ProcessReply should succeed with single hop")
}

// TestTunnelBuildReply_ValidateResponseRecord tests response record validation
func TestTunnelBuildReply_ValidateResponseRecord(t *testing.T) {
	reply := &TunnelBuildReply{}

	// Valid record
	validRecord := createValidResponseRecord()
	err := reply.validateResponseRecord(validRecord)
	assert.NoError(t, err, "Valid record should pass validation")

	// Invalid record with empty hash
	invalidRecord := BuildResponseRecord{
		Hash:       common.Hash{}, // All zeros
		RandomData: [495]byte{},
		Reply:      TUNNEL_BUILD_REPLY_SUCCESS,
	}
	err = reply.validateResponseRecord(invalidRecord)
	assert.Error(t, err, "Invalid record with empty hash should fail validation")
	assert.Contains(t, err.Error(), "empty hash")
}

// TestProcessHopResponse_AllReplyCodes tests processing of all defined reply codes
func TestProcessHopResponse_AllReplyCodes(t *testing.T) {
	reply := &TunnelBuildReply{}

	testCases := []struct {
		replyCode     byte
		expectSuccess bool
		expectError   bool
		errorContains string
	}{
		{TUNNEL_BUILD_REPLY_SUCCESS, true, false, ""},
		{TUNNEL_BUILD_REPLY_REJECT, false, true, "rejected request"},
		{TUNNEL_BUILD_REPLY_OVERLOAD, false, true, "router overloaded"},
		{TUNNEL_BUILD_REPLY_BANDWIDTH, false, true, "insufficient bandwidth"},
		{TUNNEL_BUILD_REPLY_INVALID, false, true, "invalid request data"},
		{TUNNEL_BUILD_REPLY_EXPIRED, false, true, "request expired"},
		{0xFF, false, true, "unknown reply code"}, // Unknown code
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("ReplyCode_%02x", tc.replyCode), func(t *testing.T) {
			record := createValidResponseRecord()
			record.Reply = tc.replyCode

			success, err := reply.processHopResponse(0, record)

			assert.Equal(t, tc.expectSuccess, success, "Success result should match expected")

			if tc.expectError {
				assert.Error(t, err, "Should return error for reply code %02x", tc.replyCode)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains, "Error should contain expected text")
				}
			} else {
				assert.NoError(t, err, "Should not return error for reply code %02x", tc.replyCode)
			}
		})
	}
}

// TestTunnelReplyHandler_InterfaceCompliance tests interface satisfaction
func TestTunnelReplyHandler_InterfaceCompliance(t *testing.T) {
	// Test TunnelBuildReply interface compliance
	var handler TunnelReplyHandler = &TunnelBuildReply{}
	assert.NotNil(t, handler, "TunnelBuildReply should implement TunnelReplyHandler")

	records := handler.GetReplyRecords()
	assert.Equal(t, 8, len(records), "TunnelBuildReply should return 8 records")

	err := handler.ProcessReply()
	assert.Error(t, err, "Empty TunnelBuildReply should fail processing")

	// Test VariableTunnelBuildReply interface compliance
	var variableHandler TunnelReplyHandler = &VariableTunnelBuildReply{}
	assert.NotNil(t, variableHandler, "VariableTunnelBuildReply should implement TunnelReplyHandler")

	variableRecords := variableHandler.GetReplyRecords()
	assert.Equal(t, 0, len(variableRecords), "Empty VariableTunnelBuildReply should return 0 records")

	err = variableHandler.ProcessReply()
	assert.Error(t, err, "Empty VariableTunnelBuildReply should fail processing")
}

// Helper functions for creating test data

// createSuccessfulTunnelBuildReply creates a TunnelBuildReply where all hops accepted
func createSuccessfulTunnelBuildReply() *TunnelBuildReply {
	var reply TunnelBuildReply
	for i := 0; i < 8; i++ {
		reply[i] = createValidResponseRecord()
		reply[i].Reply = TUNNEL_BUILD_REPLY_SUCCESS
	}
	return &reply
}

// createRejectedTunnelBuildReply creates a TunnelBuildReply where all hops rejected
func createRejectedTunnelBuildReply() *TunnelBuildReply {
	var reply TunnelBuildReply
	for i := 0; i < 8; i++ {
		reply[i] = createValidResponseRecord()
		reply[i].Reply = TUNNEL_BUILD_REPLY_REJECT
	}
	return &reply
}

// createMixedTunnelBuildReply creates a TunnelBuildReply with mixed responses
func createMixedTunnelBuildReply() *TunnelBuildReply {
	var reply TunnelBuildReply
	replyCodes := []byte{
		TUNNEL_BUILD_REPLY_SUCCESS,
		TUNNEL_BUILD_REPLY_SUCCESS,
		TUNNEL_BUILD_REPLY_REJECT,
		TUNNEL_BUILD_REPLY_SUCCESS,
		TUNNEL_BUILD_REPLY_OVERLOAD,
		TUNNEL_BUILD_REPLY_SUCCESS,
		TUNNEL_BUILD_REPLY_BANDWIDTH,
		TUNNEL_BUILD_REPLY_SUCCESS,
	}

	for i, replyCode := range replyCodes {
		reply[i] = createValidResponseRecord()
		reply[i].Reply = replyCode
	}
	return &reply
}

// createSingleFailureTunnelBuildReply creates a TunnelBuildReply with one failure
func createSingleFailureTunnelBuildReply() *TunnelBuildReply {
	var reply TunnelBuildReply
	for i := 0; i < 8; i++ {
		reply[i] = createValidResponseRecord()
		if i == 3 {
			reply[i].Reply = TUNNEL_BUILD_REPLY_OVERLOAD // One failure
		} else {
			reply[i].Reply = TUNNEL_BUILD_REPLY_SUCCESS
		}
	}
	return &reply
}

// createUnknownReplyCodeTunnelBuildReply creates a TunnelBuildReply with unknown reply code
func createUnknownReplyCodeTunnelBuildReply() *TunnelBuildReply {
	var reply TunnelBuildReply
	for i := 0; i < 8; i++ {
		reply[i] = createValidResponseRecord()
		if i == 0 {
			reply[i].Reply = 0xFF // Unknown reply code
		} else {
			reply[i].Reply = TUNNEL_BUILD_REPLY_SUCCESS
		}
	}
	return &reply
}

// createEmptyHashTunnelBuildReply creates a TunnelBuildReply with empty hash
func createEmptyHashTunnelBuildReply() *TunnelBuildReply {
	var reply TunnelBuildReply
	for i := 0; i < 8; i++ {
		if i == 0 {
			reply[i] = BuildResponseRecord{
				Hash:       common.Hash{}, // Empty hash
				RandomData: [495]byte{},
				Reply:      TUNNEL_BUILD_REPLY_SUCCESS,
			}
		} else {
			reply[i] = createValidResponseRecord()
			reply[i].Reply = TUNNEL_BUILD_REPLY_SUCCESS
		}
	}
	return &reply
}

// createSuccessfulVariableTunnelBuildReply creates a successful VariableTunnelBuildReply
func createSuccessfulVariableTunnelBuildReply(hopCount int) *VariableTunnelBuildReply {
	records := make([]BuildResponseRecord, hopCount)
	for i := 0; i < hopCount; i++ {
		records[i] = createValidResponseRecord()
		records[i].Reply = TUNNEL_BUILD_REPLY_SUCCESS
	}

	return &VariableTunnelBuildReply{
		Count:                hopCount,
		BuildResponseRecords: records,
	}
}

// createMixedVariableTunnelBuildReply creates a VariableTunnelBuildReply with mixed responses
func createMixedVariableTunnelBuildReply(hopCount int) *VariableTunnelBuildReply {
	records := make([]BuildResponseRecord, hopCount)
	replyCodes := []byte{
		TUNNEL_BUILD_REPLY_SUCCESS,
		TUNNEL_BUILD_REPLY_REJECT,
		TUNNEL_BUILD_REPLY_SUCCESS,
		TUNNEL_BUILD_REPLY_OVERLOAD,
	}

	for i := 0; i < hopCount; i++ {
		records[i] = createValidResponseRecord()
		records[i].Reply = replyCodes[i%len(replyCodes)]
	}

	return &VariableTunnelBuildReply{
		Count:                hopCount,
		BuildResponseRecords: records,
	}
}

// createValidResponseRecord creates a valid BuildResponseRecord for testing
func createValidResponseRecord() BuildResponseRecord {
	var hash common.Hash
	copy(hash[:], "test_hash_value_1234567890123456") // Non-zero hash

	var randomData [495]byte
	copy(randomData[:], "test_random_data_for_response_record")

	return BuildResponseRecord{
		Hash:       hash,
		RandomData: randomData,
		Reply:      TUNNEL_BUILD_REPLY_SUCCESS,
	}
}

// Benchmark tests for performance validation

func BenchmarkTunnelBuildReply_ProcessReply_Success(b *testing.B) {
	reply := createSuccessfulTunnelBuildReply()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = reply.ProcessReply()
	}
}

func BenchmarkTunnelBuildReply_ProcessReply_Mixed(b *testing.B) {
	reply := createMixedTunnelBuildReply()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = reply.ProcessReply()
	}
}

func BenchmarkVariableTunnelBuildReply_ProcessReply_Success(b *testing.B) {
	reply := createSuccessfulVariableTunnelBuildReply(5)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = reply.ProcessReply()
	}
}
