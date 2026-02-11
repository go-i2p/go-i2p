package i2np

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
)

// TestProcessAllBuildRecords_FiltersRecordsNotForUs verifies that when our
// router hash is set, only records with OurIdent matching our hash are processed.
// Before the fix, ALL records were processed, causing spurious accept/reject
// decisions for records destined for other routers.
func TestProcessAllBuildRecords_FiltersRecordsNotForUs(t *testing.T) {
	processor := NewMessageProcessor()
	mockForwarder := newMockBuildReplyForwarder()
	mockParticipant := newMockParticipantManager(true)
	processor.SetBuildReplyForwarder(mockForwarder)
	processor.SetParticipantManager(mockParticipant)

	// Set our router hash.
	var ourHash common.Hash
	copy(ourHash[:], []byte("our-router-hash-value-32-bytes!!"))
	processor.SetOurRouterHash(ourHash)

	// Create 5 records — only 1 has OurIdent matching our hash.
	records := make([]BuildRequestRecord, 5)
	for i := range records {
		records[i] = createTestBuildRequestRecord(t)
		records[i].NextTunnel = 0
		// Set a different OurIdent for all records.
		copy(records[i].OurIdent[:], []byte("other-router-hash-different-32!!"))
	}
	// Mark record 2 as ours.
	records[2].OurIdent = ourHash

	processor.processAllBuildRecords(42, records, false)

	// Only 1 record should be processed (registered).
	assert.Equal(t, 1, mockParticipant.getRegisteredCount(),
		"Only the record destined for us should be processed")

	routerCalls := mockForwarder.getRouterCalls()
	assert.Len(t, routerCalls, 1, "Should forward reply for exactly one record")
}

// TestProcessAllBuildRecords_NoFilterWhenHashUnset verifies backward compatibility:
// when our router hash is not set (zero), all records are still processed.
func TestProcessAllBuildRecords_NoFilterWhenHashUnset(t *testing.T) {
	processor := NewMessageProcessor()
	mockForwarder := newMockBuildReplyForwarder()
	mockParticipant := newMockParticipantManager(true)
	processor.SetBuildReplyForwarder(mockForwarder)
	processor.SetParticipantManager(mockParticipant)

	// Do NOT set our router hash — it stays zero.

	records := make([]BuildRequestRecord, 3)
	for i := range records {
		records[i] = createTestBuildRequestRecord(t)
		records[i].NextTunnel = 0
	}

	processor.processAllBuildRecords(43, records, false)

	// Without a hash filter, all records should be processed (backward compat).
	assert.Equal(t, 3, mockParticipant.getRegisteredCount(),
		"All records should be processed when our hash is not set")
}

// TestForwardBuildReply_UsesIsShortBuild verifies that the isShortBuild
// parameter is correctly passed through to the build reply forwarder
// instead of being hardcoded to false.
func TestForwardBuildReply_UsesIsShortBuild(t *testing.T) {
	processor := NewMessageProcessor()
	mockForwarder := newMockBuildReplyForwarder()
	processor.SetBuildReplyForwarder(mockForwarder)

	record := createTestBuildRequestRecord(t)
	record.NextTunnel = 0

	// Forward with isShortBuild=true.
	err := processor.forwardBuildReply(1, record, []byte("encrypted"), true)
	assert.NoError(t, err)

	routerCalls := mockForwarder.getRouterCalls()
	assert.Len(t, routerCalls, 1)
	assert.True(t, routerCalls[0].isShortBuild,
		"isShortBuild=true should be passed to ForwardBuildReplyToRouter")

	// Forward with isShortBuild=false.
	err = processor.forwardBuildReply(2, record, []byte("encrypted"), false)
	assert.NoError(t, err)

	routerCalls = mockForwarder.getRouterCalls()
	assert.Len(t, routerCalls, 2)
	assert.False(t, routerCalls[1].isShortBuild,
		"isShortBuild=false should be passed to ForwardBuildReplyToRouter")
}

// TestForwardBuildReply_TunnelUsesIsShortBuild verifies tunnel forwarding
// also passes isShortBuild correctly.
func TestForwardBuildReply_TunnelUsesIsShortBuild(t *testing.T) {
	processor := NewMessageProcessor()
	mockForwarder := newMockBuildReplyForwarder()
	processor.SetBuildReplyForwarder(mockForwarder)

	record := createTestBuildRequestRecord(t)
	record.NextTunnel = 12345 // Force tunnel forwarding

	err := processor.forwardBuildReply(1, record, []byte("encrypted"), true)
	assert.NoError(t, err)

	tunnelCalls := mockForwarder.getTunnelCalls()
	assert.Len(t, tunnelCalls, 1)
	assert.True(t, tunnelCalls[0].isShortBuild,
		"isShortBuild=true should be passed to ForwardBuildReplyThroughTunnel")
}
