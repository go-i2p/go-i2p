package i2np

import (
	"errors"
	"fmt"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupBuildReplyTest creates a MessageProcessor wired to a mock forwarder and
// participant manager.  accept controls whether the participant manager accepts
// build requests.
func setupBuildReplyTest(t *testing.T, accept bool) (*MessageProcessor, *mockBuildReplyForwarder, *mockParticipantManager) {
	t.Helper()
	processor := NewMessageProcessor()
	fwd := newMockBuildReplyForwarder()
	pm := newMockParticipantManager(accept)
	processor.SetBuildReplyForwarder(fwd)
	processor.SetParticipantManager(pm)
	return processor, fwd, pm
}

func TestBuildReplyForwarderInterface(t *testing.T) {
	t.Run("interface_compiles", func(t *testing.T) {
		// Verify the interface can be implemented
		var _ BuildReplyForwarder = (*mockBuildReplyForwarder)(nil)
	})
}

func TestProcessSingleBuildRecord_AcceptedRequest(t *testing.T) {
	processor, mockForwarder, mockParticipant := setupBuildReplyTest(t, true)

	record := processDirectBuildRecord(t, processor, 1001)

	// Verify
	assert.Equal(t, 1, mockParticipant.getRegisteredCount(), "Participant should be registered")

	routerCalls := mockForwarder.getRouterCalls()
	assert.Len(t, routerCalls, 1, "Should have one router forward call")

	if len(routerCalls) > 0 {
		assert.Equal(t, record.NextIdent, routerCalls[0].routerHash, "Router hash should match NextIdent")
		assert.Equal(t, 1001, routerCalls[0].messageID, "Message ID should match")
		assert.NotEmpty(t, routerCalls[0].encryptedRecords, "Encrypted records should not be empty")
		// ChaCha20-Poly1305 produces 544 bytes (528 + 16 auth tag)
		assert.Equal(t, 544, len(routerCalls[0].encryptedRecords), "Encrypted reply should be 544 bytes")
	}
}

func TestProcessSingleBuildRecord_RejectedRequest(t *testing.T) {
	processor, mockForwarder, mockParticipant := setupBuildReplyTest(t, false)
	mockParticipant.rejectCode = TUNNEL_BUILD_REPLY_OVERLOAD
	mockParticipant.rejectReason = "router overloaded"

	processDirectBuildRecord(t, processor, 1002)

	// Verify
	assert.Equal(t, 0, mockParticipant.getRegisteredCount(), "Participant should not be registered when rejected")

	routerCalls := mockForwarder.getRouterCalls()
	assert.Len(t, routerCalls, 1, "Should still forward rejection reply")
}

func TestProcessSingleBuildRecord_TunnelForwarding(t *testing.T) {
	processor, mockForwarder, _ := setupBuildReplyTest(t, true)

	record := createTestBuildRequestRecord(t)
	record.NextTunnel = tunnel.TunnelID(67890) // Non-zero means tunnel forwarding
	messageID := 1003

	// Execute
	processor.processSingleBuildRecord(messageID, 0, record, false)

	// Verify
	tunnelCalls := mockForwarder.getTunnelCalls()
	assert.Len(t, tunnelCalls, 1, "Should have one tunnel forward call")

	if len(tunnelCalls) > 0 {
		assert.Equal(t, record.NextIdent, tunnelCalls[0].gatewayHash, "Gateway hash should match NextIdent")
		assert.Equal(t, record.NextTunnel, tunnelCalls[0].tunnelID, "Tunnel ID should match NextTunnel")
		assert.Equal(t, messageID, tunnelCalls[0].messageID, "Message ID should match")
	}

	routerCalls := mockForwarder.getRouterCalls()
	assert.Len(t, routerCalls, 0, "Should not use router forwarding when tunnel is specified")
}

func TestProcessSingleBuildRecord_NoForwarder(t *testing.T) {
	// Setup - no forwarder set
	processor := NewMessageProcessor()
	mockParticipant := newMockParticipantManager(true)

	processor.SetParticipantManager(mockParticipant)
	// Note: No SetBuildReplyForwarder called

	record := createTestBuildRequestRecord(t)
	messageID := 1004

	// Execute - should not panic, just log warning
	processor.processSingleBuildRecord(messageID, 0, record, false)

	// Verify - participant should still be registered even without forwarder
	assert.Equal(t, 1, mockParticipant.getRegisteredCount(), "Participant should still be registered")
}

func TestGenerateAndSendBuildReply_EncryptionWorks(t *testing.T) {
	processor, mockForwarder, _ := setupBuildReplyTest(t, true)

	record := createTestBuildRequestRecord(t)
	record.NextTunnel = 0 // Force direct router forwarding
	messageID := 1005

	// Execute
	err := processor.generateAndSendBuildReply(messageID, 0, record, TUNNEL_BUILD_REPLY_SUCCESS, false)

	// Verify
	require.NoError(t, err, "Should successfully generate and send reply")

	routerCalls := mockForwarder.getRouterCalls()
	require.Len(t, routerCalls, 1, "Should have one forward call")

	// Verify the encrypted reply can be decrypted
	encryptedReply := routerCalls[0].encryptedRecords
	crypto := NewBuildRecordCrypto()

	decrypted, err := crypto.DecryptReplyRecord(encryptedReply, record.ReplyKey, record.ReplyIV)
	require.NoError(t, err, "Should be able to decrypt the reply")
	assert.Equal(t, byte(TUNNEL_BUILD_REPLY_SUCCESS), decrypted.Reply, "Reply code should be SUCCESS")
}

func TestGenerateAndSendBuildReply_AllReplyCodes(t *testing.T) {
	testCases := []struct {
		name      string
		replyCode byte
	}{
		{"SUCCESS", TUNNEL_BUILD_REPLY_SUCCESS},
		{"REJECT", TUNNEL_BUILD_REPLY_REJECT},
		{"OVERLOAD", TUNNEL_BUILD_REPLY_OVERLOAD},
		{"BANDWIDTH", TUNNEL_BUILD_REPLY_BANDWIDTH},
		{"INVALID", TUNNEL_BUILD_REPLY_INVALID},
		{"EXPIRED", TUNNEL_BUILD_REPLY_EXPIRED},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			processor, mockForwarder, _ := setupBuildReplyTest(t, true)

			record := createTestBuildRequestRecord(t)
			record.NextTunnel = 0 // Force direct router forwarding

			err := processor.generateAndSendBuildReply(1, 0, record, tc.replyCode, false)
			require.NoError(t, err)

			routerCalls := mockForwarder.getRouterCalls()
			require.Len(t, routerCalls, 1)

			// Verify the encrypted reply has correct reply code
			crypto := NewBuildRecordCrypto()
			decrypted, err := crypto.DecryptReplyRecord(routerCalls[0].encryptedRecords, record.ReplyKey, record.ReplyIV)
			require.NoError(t, err)
			assert.Equal(t, tc.replyCode, decrypted.Reply, "Reply code should match")
		})
	}
}

func TestForwardBuildReply_RouterForwardError(t *testing.T) {
	// Setup
	processor := NewMessageProcessor()
	mockForwarder := newMockBuildReplyForwarder()
	mockForwarder.forwardToRouterErr = errors.New("network error")

	processor.SetBuildReplyForwarder(mockForwarder)

	record := createTestBuildRequestRecord(t)
	record.NextTunnel = 0 // Direct router forwarding

	// Execute
	err := processor.forwardBuildReply(1, record, []byte("test-encrypted-data"), false)

	// Verify
	assert.Error(t, err, "Should return error from forwarder")
	assert.Contains(t, err.Error(), "network error")
}

func TestForwardBuildReply_TunnelForwardError(t *testing.T) {
	// Setup
	processor := NewMessageProcessor()
	mockForwarder := newMockBuildReplyForwarder()
	mockForwarder.forwardToTunnelErr = errors.New("tunnel error")

	processor.SetBuildReplyForwarder(mockForwarder)

	record := createTestBuildRequestRecord(t)
	record.NextTunnel = tunnel.TunnelID(12345) // Tunnel forwarding

	// Execute
	err := processor.forwardBuildReply(1, record, []byte("test-encrypted-data"), false)

	// Verify
	assert.Error(t, err, "Should return error from forwarder")
	assert.Contains(t, err.Error(), "tunnel error")
}

func TestMultipleBuildRecords_Processing(t *testing.T) {
	processor, mockForwarder, mockParticipant := setupBuildReplyTest(t, true)

	// Set our router hash so records are processed.
	var ourHash common.Hash
	copy(ourHash[:], []byte("test-router-hash-32-bytes-long!"))
	processor.SetOurRouterHash(ourHash)

	// Create multiple records — all destined for us.
	records := make([]BuildRequestRecord, 5)
	for i := 0; i < 5; i++ {
		records[i] = createTestBuildRequestRecord(t)
		records[i].OurIdent = ourHash
		if i%2 == 0 {
			records[i].NextTunnel = 0 // Router forwarding
		} else {
			records[i].NextTunnel = tunnel.TunnelID(1000 + i) // Tunnel forwarding
		}
	}

	messageID := 2000

	// Execute
	processor.processAllBuildRecords(messageID, records, false)

	// Verify
	assert.Equal(t, 5, mockParticipant.getRegisteredCount(), "All participants should be registered")

	routerCalls := mockForwarder.getRouterCalls()
	tunnelCalls := mockForwarder.getTunnelCalls()

	// 3 records with NextTunnel=0 (indices 0, 2, 4)
	assert.Len(t, routerCalls, 3, "Should have 3 router forward calls")
	// 2 records with NextTunnel!=0 (indices 1, 3)
	assert.Len(t, tunnelCalls, 2, "Should have 2 tunnel forward calls")
}

func TestSetBuildReplyForwarder(t *testing.T) {
	processor := NewMessageProcessor()
	assert.Nil(t, processor.buildReplyForwarder, "Initially should be nil")

	mockForwarder := newMockBuildReplyForwarder()
	processor.SetBuildReplyForwarder(mockForwarder)

	assert.NotNil(t, processor.buildReplyForwarder, "Should be set after call")
}

func TestBuildRecordCrypto_InitializedInProcessor(t *testing.T) {
	processor := NewMessageProcessor()
	assert.NotNil(t, processor.buildRecordCrypto, "BuildRecordCrypto should be initialized by default")
}

// TestProcessSingleBuildRecord_RegisterParticipantFailure verifies that when
// ProcessBuildRequest accepts a record but RegisterParticipant fails, a rejection
// reply is sent instead of a false success reply. Previously, the code sent
// TUNNEL_BUILD_REPLY_SUCCESS even when registration failed, creating phantom tunnels.
func TestProcessSingleBuildRecord_RegisterParticipantFailure(t *testing.T) {
	processor, mockForwarder, mockParticipant := setupBuildReplyTest(t, true)
	mockParticipant.registerErr = fmt.Errorf("participant slots exhausted")

	processDirectBuildRecord(t, processor, 3001)

	// Registration was attempted but failed.
	assert.Equal(t, 1, mockParticipant.getRegisteredCount(),
		"RegisterParticipant should have been called")

	// A reply should still be forwarded (the rejection reply).
	routerCalls := mockForwarder.getRouterCalls()
	assert.Len(t, routerCalls, 1, "Should still forward a reply even on registration failure")
}

// TestHandleAcceptedBuildRecord_ReturnsError verifies that handleAcceptedBuildRecord
// returns an error when RegisterParticipant fails, allowing the caller to send
// a rejection reply.
func TestHandleAcceptedBuildRecord_ReturnsError(t *testing.T) {
	processor := NewMessageProcessor()
	mockParticipant := newMockParticipantManager(true)
	processor.SetParticipantManager(mockParticipant)

	record := createTestBuildRequestRecord(t)

	// Success case: no registration error.
	err := processor.handleAcceptedBuildRecord(1, 0, record)
	assert.NoError(t, err, "Should succeed when RegisterParticipant succeeds")

	// Failure case: registration error.
	mockParticipant.registerErr = fmt.Errorf("slots full")
	err = processor.handleAcceptedBuildRecord(2, 0, record)
	assert.Error(t, err, "Should return error when RegisterParticipant fails")
	assert.Contains(t, err.Error(), "RegisterParticipant failed")
}
