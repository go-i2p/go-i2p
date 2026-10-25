// Tests for generating and encrypting short (STBM) tunnel build replies.
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

// newSingleSlotSTBMRaw builds a valid one-record STBM message body:
// [count:1][slot:218]. The slot is opaque filler; the reply builder preserves
// the non-own slots and replaces our own slot with the encrypted reply.
func newSingleSlotSTBMRaw() []byte {
	raw := make([]byte, 1+ShortBuildRecordSize)
	raw[0] = 1
	for i := 1; i < len(raw); i++ {
		raw[i] = byte(i % 251)
	}
	return raw
}

// newTestSTBMSlotCrypto returns per-slot Noise-derived crypto plus the raw
// record it corresponds to, so a generated reply can be decrypted back.
func newTestSTBMSlotCrypto() stbmSlotCrypto {
	var c stbmSlotCrypto
	for i := range c.replyKey {
		c.replyKey[i] = byte(i + 1)
	}
	for i := range c.noiseHash {
		c.noiseHash[i] = byte(200 - i)
	}
	return c
}

// decryptReplySlot decodes the reply code from our own slot of a generated
// short build reply, mirroring the creator-side decryption.
func decryptReplySlot(t *testing.T, reply []byte, crypto stbmSlotCrypto, index int) byte {
	t.Helper()
	slotOffset := 1 + index*ShortBuildRecordSize
	require.Greater(t, len(reply), slotOffset+ShortBuildRecordSize-1, "reply too short")
	cleartext, err := decryptSTBMReplySlot(reply[slotOffset:], crypto.replyKey, crypto.noiseHash, index)
	require.NoError(t, err, "should decrypt our reply slot")
	return cleartext[201]
}

func TestBuildReplyForwarderInterface(t *testing.T) {
	t.Run("interface_compiles", func(t *testing.T) {
		var _ BuildReplyForwarder = (*mockBuildReplyForwarder)(nil)
	})
}

// Validates that an accepted build record is registered and its encrypted
// reply uses the short-record wire format: 1-byte count + N x 218-byte slots.
func TestProcessSingleBuildRecord_AcceptedRequest(t *testing.T) {
	processor, mockForwarder, mockParticipant := setupBuildReplyTest(t, true)
	crypto := newTestSTBMSlotCrypto()
	processor.stbmSlotCrypto = map[int]stbmSlotCrypto{0: crypto}

	record := processDirectBuildRecord(t, processor, 1001)

	assert.Equal(t, 1, mockParticipant.getRegisteredCount(), "Participant should be registered")

	routerCalls := mockForwarder.getRouterCalls()
	assert.Len(t, routerCalls, 1, "Should have one router forward call")

	require.NotEmpty(t, routerCalls)
	assert.Equal(t, record.NextIdent, routerCalls[0].routerHash, "Router hash should match NextIdent")
	assert.Equal(t, 1001, routerCalls[0].messageID, "Message ID should match")
	assert.NotEmpty(t, routerCalls[0].encryptedRecords, "Encrypted records should not be empty")
	assert.Equal(t, 1+ShortBuildRecordSize, len(routerCalls[0].encryptedRecords),
		"Short reply should be count(1) + one 218-byte slot")
	assert.Equal(t, byte(1), routerCalls[0].encryptedRecords[0], "count byte should be 1")
	assert.Equal(t, byte(TunnelBuildReplySuccess), decryptReplySlot(t, routerCalls[0].encryptedRecords, crypto, 0),
		"Reply code should be SUCCESS")
}

// Validates that a rejected build record is not registered as a participant
// but a rejection reply is still forwarded to the next hop.
func TestProcessSingleBuildRecord_RejectedRequest(t *testing.T) {
	processor, mockForwarder, mockParticipant := setupBuildReplyTest(t, false)
	mockParticipant.rejectCode = TunnelBuildReplyTransientOverload
	mockParticipant.rejectReason = "router overloaded"
	processor.stbmSlotCrypto = map[int]stbmSlotCrypto{0: newTestSTBMSlotCrypto()}

	processDirectBuildRecord(t, processor, 1002)

	assert.Equal(t, 0, mockParticipant.getRegisteredCount(), "Participant should not be registered when rejected")

	routerCalls := mockForwarder.getRouterCalls()
	assert.Len(t, routerCalls, 1, "Should still forward rejection reply")
}

// Validates that a build record with a non-zero NextTunnel is forwarded
// through the tunnel instead of directly to the next router.
func TestProcessSingleBuildRecord_TunnelForwarding(t *testing.T) {
	processor, mockForwarder, _ := setupBuildReplyTest(t, true)
	processor.stbmSlotCrypto = map[int]stbmSlotCrypto{0: newTestSTBMSlotCrypto()}

	record := createTestBuildRequestRecord(t)
	record.NextTunnel = tunnel.TunnelID(67890) // Non-zero means tunnel forwarding
	messageID := 1003

	processor.processSingleBuildRecord(messageID, 0, record, newSingleSlotSTBMRaw(), 25)

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
	processor := NewMessageProcessor()
	mockParticipant := newMockParticipantManager(true)
	processor.SetParticipantManager(mockParticipant)
	processor.stbmSlotCrypto = map[int]stbmSlotCrypto{0: newTestSTBMSlotCrypto()}
	// Note: No SetBuildReplyForwarder called

	record := createTestBuildRequestRecord(t)

	// Execute - should not panic, just log warning
	processor.processSingleBuildRecord(1004, 0, record, newSingleSlotSTBMRaw(), 25)

	assert.Equal(t, 1, mockParticipant.getRegisteredCount(), "Participant should still be registered")
}

// Validates that a generated short build reply decrypts with the slot's
// Noise-derived reply key and carries the expected reply code.
func TestGenerateAndSendBuildReply_EncryptionWorks(t *testing.T) {
	processor, mockForwarder, _ := setupBuildReplyTest(t, true)
	crypto := newTestSTBMSlotCrypto()
	processor.stbmSlotCrypto = map[int]stbmSlotCrypto{0: crypto}

	record := createTestBuildRequestRecord(t)
	record.NextTunnel = 0 // Force direct router forwarding

	err := processor.generateAndSendBuildReply(1005, 0, record, TunnelBuildReplySuccess, 0, newSingleSlotSTBMRaw(), 25)
	require.NoError(t, err, "Should successfully generate and send reply")

	routerCalls := mockForwarder.getRouterCalls()
	require.Len(t, routerCalls, 1, "Should have one forward call")

	assert.Equal(t, byte(TunnelBuildReplySuccess), decryptReplySlot(t, routerCalls[0].encryptedRecords, crypto, 0),
		"Reply code should be SUCCESS")
}

// Validates that every tunnel build reply code round-trips through the short
// reply encryption unchanged.
func TestGenerateAndSendBuildReply_AllReplyCodes(t *testing.T) {
	testCases := []struct {
		name      string
		replyCode byte
	}{
		{"SUCCESS", TunnelBuildReplySuccess},
		{"REJECT", TunnelBuildReplyProbabilisticReject},
		{"OVERLOAD", TunnelBuildReplyTransientOverload},
		{"BANDWIDTH", TunnelBuildReplyBandwidth},
		{"CRITICAL", TunnelBuildReplyCritical},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			processor, mockForwarder, _ := setupBuildReplyTest(t, true)
			crypto := newTestSTBMSlotCrypto()
			processor.stbmSlotCrypto = map[int]stbmSlotCrypto{0: crypto}

			record := createTestBuildRequestRecord(t)
			record.NextTunnel = 0

			err := processor.generateAndSendBuildReply(1, 0, record, tc.replyCode, 0, newSingleSlotSTBMRaw(), 25)
			require.NoError(t, err)

			routerCalls := mockForwarder.getRouterCalls()
			require.Len(t, routerCalls, 1)

			assert.Equal(t, tc.replyCode, decryptReplySlot(t, routerCalls[0].encryptedRecords, crypto, 0),
				"Reply code should match")
		})
	}
}

func TestForwardBuildReply_RouterForwardError(t *testing.T) {
	processor := NewMessageProcessor()
	mockForwarder := newMockBuildReplyForwarder()
	mockForwarder.forwardToRouterErr = errors.New("network error")

	processor.SetBuildReplyForwarder(mockForwarder)

	record := createTestBuildRequestRecord(t)
	record.NextTunnel = 0

	err := processor.forwardBuildReply(1, record, []byte("test-encrypted-data"), 25)

	assert.Error(t, err, "Should return error from forwarder")
	assert.Contains(t, err.Error(), "network error")
}

func TestForwardBuildReply_TunnelForwardError(t *testing.T) {
	processor := NewMessageProcessor()
	mockForwarder := newMockBuildReplyForwarder()
	mockForwarder.forwardToTunnelErr = errors.New("tunnel error")

	processor.SetBuildReplyForwarder(mockForwarder)

	record := createTestBuildRequestRecord(t)
	record.NextTunnel = tunnel.TunnelID(12345)

	err := processor.forwardBuildReply(1, record, []byte("test-encrypted-data"), 25)

	assert.Error(t, err, "Should return error from forwarder")
	assert.Contains(t, err.Error(), "tunnel error")
}

// Validates that a build request with multiple records splits correctly
// between router and tunnel forwarding.
func TestMultipleBuildRecords_Processing(t *testing.T) {
	processor, mockForwarder, mockParticipant := setupBuildReplyTest(t, true)

	var ourHash common.Hash
	copy(ourHash[:], []byte("test-router-hash-32-bytes-long!"))
	processor.SetOurRouterHash(ourHash)
	processor.stbmSlotCrypto = map[int]stbmSlotCrypto{}
	for i := 0; i < 5; i++ {
		processor.stbmSlotCrypto[i] = newTestSTBMSlotCrypto()
	}

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

	// A five-record STBM body so each slot index is in range.
	raw := make([]byte, 1+5*ShortBuildRecordSize)
	raw[0] = 5
	for i := 1; i < len(raw); i++ {
		raw[i] = byte(i % 197)
	}

	processor.processAllBuildRecords(2000, records, raw, 25)

	assert.Equal(t, 5, mockParticipant.getRegisteredCount(), "All participants should be registered")

	routerCalls := mockForwarder.getRouterCalls()
	tunnelCalls := mockForwarder.getTunnelCalls()

	assert.Len(t, routerCalls, 3, "Should have 3 router forward calls")
	assert.Len(t, tunnelCalls, 2, "Should have 2 tunnel forward calls")
}

func TestSetBuildReplyForwarder(t *testing.T) {
	processor := NewMessageProcessor()
	assert.Nil(t, processor.buildReplyForwarder, "Initially should be nil")

	mockForwarder := newMockBuildReplyForwarder()
	processor.SetBuildReplyForwarder(mockForwarder)

	assert.NotNil(t, processor.buildReplyForwarder, "Should be set after call")
}

// TestProcessSingleBuildRecord_RegisterParticipantFailure verifies that when
// ProcessBuildRequest accepts a record but RegisterParticipant fails, a rejection
// reply is sent instead of a false success reply. Previously, the code sent
// TunnelBuildReplySuccess even when registration failed, creating phantom tunnels.
func TestProcessSingleBuildRecord_RegisterParticipantFailure(t *testing.T) {
	processor, mockForwarder, mockParticipant := setupBuildReplyTest(t, true)
	mockParticipant.registerErr = fmt.Errorf("participant slots exhausted")
	processor.stbmSlotCrypto = map[int]stbmSlotCrypto{0: newTestSTBMSlotCrypto()}

	processDirectBuildRecord(t, processor, 3001)

	assert.Equal(t, 1, mockParticipant.getRegisteredCount(),
		"RegisterParticipant should have been called")

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

	err := processor.handleAcceptedBuildRecord(1, 0, record)
	assert.NoError(t, err, "Should succeed when RegisterParticipant succeeds")

	mockParticipant.registerErr = fmt.Errorf("slots full")
	err = processor.handleAcceptedBuildRecord(2, 0, record)
	assert.Error(t, err, "Should return error when RegisterParticipant fails")
	assert.Contains(t, err.Error(), "RegisterParticipant failed")
}
