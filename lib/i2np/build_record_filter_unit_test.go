package i2np

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
)

// TestProcessAllBuildRecords_FiltersRecordsNotForUs verifies that when our
// router hash is set, only records with OurIdent matching our hash are processed.
// Before the fix, ALL records were processed, causing spurious accept/reject
// decisions for records destined for other routers.
func TestProcessAllBuildRecords_FiltersRecordsNotForUs(t *testing.T) {
	processor, mockForwarder, mockParticipant := setupBuildReplyTest(t, true)

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

// TestProcessAllBuildRecords_NoProcessingWhenHashUnset verifies that when
// our router hash is not set (zero), NO records are processed. This prevents
// the router from incorrectly participating in all hops of a tunnel build
// when its identity is unknown.
func TestProcessAllBuildRecords_NoProcessingWhenHashUnset(t *testing.T) {
	processor, mockForwarder, mockParticipant := setupBuildReplyTest(t, true)

	// Do NOT set our router hash — it stays zero.

	records := make([]BuildRequestRecord, 3)
	for i := range records {
		records[i] = createTestBuildRequestRecord(t)
		records[i].NextTunnel = 0
	}

	processor.processAllBuildRecords(43, records, false)

	// With zero hash, NO records should be processed (safety guard).
	assert.Equal(t, 0, mockParticipant.getRegisteredCount(),
		"No records should be processed when our router hash is not set (zero)")

	routerCalls := mockForwarder.getRouterCalls()
	assert.Len(t, routerCalls, 0, "No replies should be forwarded when hash is zero")
}

// TestForwardBuildReply_UsesIsShortBuild verifies that the isShortBuild
// parameter is correctly passed through to the build reply forwarder
// instead of being hardcoded to false.
func TestForwardBuildReply_IsShortBuildPropagation(t *testing.T) {
	tests := []struct {
		name         string
		nextTunnel   tunnel.TunnelID
		isShortBuild bool
		checkRouter  bool // true = check router calls, false = check tunnel calls
	}{
		{"Router_ShortTrue", 0, true, true},
		{"Router_ShortFalse", 0, false, true},
		{"Tunnel_ShortTrue", 12345, true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processor, mockForwarder := setupProcessorWithForwarder(t)
			record := createTestBuildRequestRecord(t)
			record.NextTunnel = tt.nextTunnel

			err := processor.forwardBuildReply(1, record, []byte("encrypted"), tt.isShortBuild)
			assert.NoError(t, err)

			if tt.checkRouter {
				routerCalls := mockForwarder.getRouterCalls()
				assert.Len(t, routerCalls, 1)
				assert.Equal(t, tt.isShortBuild, routerCalls[0].isShortBuild,
					"isShortBuild should be passed to ForwardBuildReplyToRouter")
			} else {
				tunnelCalls := mockForwarder.getTunnelCalls()
				assert.Len(t, tunnelCalls, 1)
				assert.Equal(t, tt.isShortBuild, tunnelCalls[0].isShortBuild,
					"isShortBuild should be passed to ForwardBuildReplyThroughTunnel")
			}
		})
	}
}
