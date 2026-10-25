// Tests for build record filtering in short tunnel build processing.
package i2np

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTryParseAndAppendRecord_RejectsForeignRecord verifies the fail-closed
// rule from the ECIES tunnel-creation spec: a record whose 16-byte toPeer
// prefix is not our router hash is never accepted, and a record addressed to
// us is only accepted if it decrypts under our static key. Accepting a record
// on cleartext fields alone would let any peer register a transit tunnel with
// attacker-chosen layer, IV and reply keys.
func TestTryParseAndAppendRecord_RejectsForeignRecord(t *testing.T) {
	processor, _, mockParticipant := setupBuildReplyTest(t, true)

	var ourHash common.Hash
	copy(ourHash[:], []byte("our-router-hash-value-32-bytes!!"))
	processor.SetOurRouterHash(ourHash)
	var testPriv [32]byte
	for i := range testPriv {
		testPriv[i] = byte(i + 1)
	}
	processor.SetOurPrivateKey(testPriv[:])

	// A record addressed to some other router.
	foreign := make([]byte, ShortBuildRecordSize)
	copy(foreign, []byte("not-our-router-hash-prefix-32byt"))
	for i := 16; i < len(foreign); i++ {
		foreign[i] = byte(i)
	}

	var records []BuildRequestRecord
	processor.tryParseAndAppendRecord(&records, foreign, 0)
	assert.Empty(t, records, "record with a foreign toPeer prefix must be dropped")

	// A record addressed to us but not validly encrypted must also be dropped.
	mine := make([]byte, ShortBuildRecordSize)
	copy(mine, ourHash[:16])
	for i := 16; i < len(mine); i++ {
		mine[i] = byte(i * 7)
	}
	processor.tryParseAndAppendRecord(&records, mine, 0)
	assert.Empty(t, records, "unauthenticated record addressed to us must be dropped")

	assert.Equal(t, 0, mockParticipant.getRegisteredCount(),
		"no participant may be registered from a rejected record")
}

// TestProcessAllBuildRecords_NoProcessingWhenHashUnset verifies that when
// our router hash is not set (zero), NO records are processed. This prevents
// the router from incorrectly participating in tunnel builds when its
// identity is unknown.
func TestProcessAllBuildRecords_NoProcessingWhenHashUnset(t *testing.T) {
	processor, mockForwarder, mockParticipant := setupBuildReplyTest(t, true)

	// Do NOT set our router hash — it stays zero.

	records := make([]BuildRequestRecord, 3)
	for i := range records {
		records[i] = createTestBuildRequestRecord(t)
		records[i].NextTunnel = 0
	}

	err := processor.processAllBuildRecords(43, records, []int{0, 1, 2}, nil, 25)
	require.Error(t, err, "processing must fail when our router hash is unset")

	assert.Equal(t, 0, mockParticipant.getRegisteredCount(),
		"No records should be processed when our router hash is not set (zero)")

	routerCalls := mockForwarder.getRouterCalls()
	assert.Len(t, routerCalls, 0, "No replies should be forwarded when hash is zero")
}

// TestForwardBuildReply_RoutesByNextTunnel verifies that a reply with a zero
// NextTunnel goes to the router forwarder and a non-zero NextTunnel goes to
// the tunnel forwarder, with the input message type propagated for reply-type
// mapping.
func TestForwardBuildReply_RoutesByNextTunnel(t *testing.T) {
	tests := []struct {
		name        string
		nextTunnel  tunnel.TunnelID
		checkRouter bool
	}{
		{"Router_Direct", 0, true},
		{"Tunnel_ViaGateway", 12345, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processor, mockForwarder := setupProcessorWithForwarder(t)
			record := createTestBuildRequestRecord(t)
			record.NextTunnel = tt.nextTunnel

			err := processor.forwardBuildReply(1, record, []byte("encrypted"), 25)
			assert.NoError(t, err)

			if tt.checkRouter {
				routerCalls := mockForwarder.getRouterCalls()
				assert.Len(t, routerCalls, 1)
				assert.Equal(t, 25, routerCalls[0].inputMessageType,
					"input message type should reach ForwardBuildReplyToRouter")
			} else {
				tunnelCalls := mockForwarder.getTunnelCalls()
				assert.Len(t, tunnelCalls, 1)
				assert.Equal(t, 25, tunnelCalls[0].inputMessageType,
					"input message type should reach ForwardBuildReplyThroughTunnel")
			}
		})
	}
}
