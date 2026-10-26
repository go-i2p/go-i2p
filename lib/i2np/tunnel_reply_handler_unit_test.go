// Tests for the tunnel build reply handler that processes incoming replies.
package i2np

import (
	"fmt"
	"testing"

	"github.com/go-i2p/crypto/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	assert.Contains(t, err.Error(), "rejected with code 10")
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
	assert.Contains(t, err.Error(), "rejected with code 20")
}

// TestTunnelBuildReply_ProcessReply_UnknownReplyCode tests handling of unknown reply codes
func TestTunnelBuildReply_ProcessReply_UnknownReplyCode(t *testing.T) {
	reply := createUnknownReplyCodeTunnelBuildReply()

	err := reply.ProcessReply()

	assert.Error(t, err, "ProcessReply should fail with unknown reply codes")
	assert.Contains(t, err.Error(), "rejected with code 255")
}

// TestTunnelBuildReply_ProcessReply_ZeroHashAccepted documents that a short
// tunnel build reply slot legitimately carries no hash field: the decrypted
// 218-byte slot is a 202-byte cleartext whose only semantic content is the
// 1-byte reply code, so record.Hash stays zero. verifyRecordIntegrity must
// skip the hash check for such records rather than reject them.
func TestTunnelBuildReply_ProcessReply_ZeroHashAccepted(t *testing.T) {
	reply := createEmptyHashTunnelBuildReply()

	err := reply.ProcessReply()

	assert.NoError(t, err, "zero-hash STBM reply records must not be rejected on hash grounds")
}

// TestTunnelBuildReply_ProcessReply_HashMismatchRejected verifies that when a
// record does carry a hash, an integrity mismatch is rejected.
func TestTunnelBuildReply_ProcessReply_HashMismatchRejected(t *testing.T) {
	records := make([]BuildResponseRecord, 2)
	records[0] = createValidResponseRecordWithReply(TunnelBuildReplySuccess)
	records[1] = createValidResponseRecordWithReply(TunnelBuildReplySuccess)
	// Corrupt the second record's hash so it no longer covers RandomData||Reply.
	records[1].Hash[0] ^= 0xFF

	reply := &OutboundTunnelBuildReply{Count: 2, BuildResponseRecords: records}

	err := reply.ProcessReply()
	assert.Error(t, err, "a populated but mismatched record hash must fail integrity")
	assert.Contains(t, err.Error(), "hash mismatch")
}

// TestOutboundTunnelBuildReplyExtra_ProcessReply_AllSuccess tests successful short tunnel build
func TestOutboundTunnelBuildReplyExtra_ProcessReply_AllSuccess(t *testing.T) {
	reply := createSuccessfulOutboundTunnelBuildReply(3)

	err := reply.ProcessReply()

	assert.NoError(t, err, "ProcessReply should succeed when all hops accept")
}

// TestOutboundTunnelBuildReplyExtra_ProcessReply_CountMismatch tests count field validation
func TestOutboundTunnelBuildReplyExtra_ProcessReply_CountMismatch(t *testing.T) {
	reply := createSuccessfulOutboundTunnelBuildReply(3)
	reply.Count = 5 // Mismatch with actual record count

	err := reply.ProcessReply()

	assert.Error(t, err, "ProcessReply should fail with count mismatch")
	assert.Contains(t, err.Error(), "count mismatch")
}

// TestOutboundTunnelBuildReplyExtra_ProcessReply_EmptyRecords tests handling of empty tunnel
func TestOutboundTunnelBuildReplyExtra_ProcessReply_EmptyRecords(t *testing.T) {
	reply := &OutboundTunnelBuildReply{
		Count:                0,
		BuildResponseRecords: []BuildResponseRecord{},
	}

	err := reply.ProcessReply()

	assert.Error(t, err, "ProcessReply should fail with no records")
	assert.Contains(t, err.Error(), "no response records")
}

// TestOutboundTunnelBuildReplyExtra_ProcessReply_MixedResponses tests short tunnel with mixed responses
func TestOutboundTunnelBuildReplyExtra_ProcessReply_MixedResponses(t *testing.T) {
	reply := createMixedOutboundTunnelBuildReply(4)

	err := reply.ProcessReply()

	assert.Error(t, err, "ProcessReply should fail when not all hops accept")
	assert.Contains(t, err.Error(), "short tunnel build failed")
}

// TestOutboundTunnelBuildReplyExtra_ProcessReply_SingleHop tests single hop short tunnel
func TestOutboundTunnelBuildReplyExtra_ProcessReply_SingleHop(t *testing.T) {
	reply := createSuccessfulOutboundTunnelBuildReply(1)

	err := reply.ProcessReply()

	assert.NoError(t, err, "ProcessReply should succeed with single hop")
}

// TestVerifyRecordIntegrity_ShortPathIsNoop covers the live reply integrity
// behaviour that replaced the removed ValidateBuildResponseRecord helper. A
// short (STBM) reply record has no hash field, so the hash check is skipped:
// integrity comes from the ChaCha20-Poly1305 tag on the 218-byte encrypted
// slot (tunnel-creation-ecies.rst:729-741, :758-770).
func TestVerifyRecordIntegrity_ShortPathIsNoop(t *testing.T) {
	reply := &OutboundTunnelBuildReply{}
	short := BuildResponseRecord{Reply: byte(TunnelBuildReplySuccess)}
	require.NoError(t, reply.verifyRecordIntegrity(0, short),
		"a short reply record with no hash must pass (AEAD provides integrity)")
}

// TestVerifyRecordIntegrity_LongLayoutStillVerified keeps the deprecated
// long-record hash rule enforced for any record that does carry a hash, so the
// integrity check a peer would expect is not silently dropped.
func TestVerifyRecordIntegrity_LongLayoutStillVerified(t *testing.T) {
	reply := &OutboundTunnelBuildReply{}

	randomData := [495]byte{}
	for i := range randomData {
		randomData[i] = byte(i)
	}
	toHash := make([]byte, 496)
	copy(toHash[:495], randomData[:])
	toHash[495] = byte(TunnelBuildReplySuccess)

	good := BuildResponseRecord{Hash: types.SHA256(toHash), RandomData: randomData, Reply: byte(TunnelBuildReplySuccess)}
	require.NoError(t, reply.verifyRecordIntegrity(0, good), "matching hash must verify")

	bad := good
	bad.Reply = byte(TunnelBuildReplyBandwidth)
	require.Error(t, reply.verifyRecordIntegrity(0, bad), "hash must not match a tampered reply byte")
}

// TestProcessHopResponse_AllReplyCodes tests processing of all defined reply codes
func TestProcessHopResponse_AllReplyCodes(t *testing.T) {
	reply := &OutboundTunnelBuildReply{}

	testCases := []struct {
		replyCode     byte
		expectSuccess bool
		expectError   bool
		errorContains string
	}{
		{TunnelBuildReplySuccess, true, false, ""},
		{TunnelBuildReplyProbabilisticReject, false, true, "rejected with code 10"},
		{TunnelBuildReplyTransientOverload, false, true, "rejected with code 20"},
		{TunnelBuildReplyBandwidth, false, true, "rejected with code 30"},
		{TunnelBuildReplyCritical, false, true, "rejected with code 50"},
		{0xFF, false, true, "rejected with code 255"}, // Non-standard code is still a rejection
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("ReplyCode_%02x", tc.replyCode), func(t *testing.T) {
			record := createValidResponseRecordWithReply(tc.replyCode)

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
	// Test OutboundTunnelBuildReply interface compliance
	var variableHandler TunnelReplyHandler = &OutboundTunnelBuildReply{}
	assert.NotNil(t, variableHandler, "OutboundTunnelBuildReply should implement TunnelReplyHandler")

	variableRecords := variableHandler.GetReplyRecords()
	assert.Equal(t, 0, len(variableRecords), "Empty OutboundTunnelBuildReply should return 0 records")

	err := variableHandler.ProcessReply()
	assert.Error(t, err, "Empty OutboundTunnelBuildReply should fail processing")
}
