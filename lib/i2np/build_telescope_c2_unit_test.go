// Tests for C2: STBM build-message telescoping and per-hop forwarding.
//
// Per tunnel-creation-ecies.rst ("Message Flow"), only the outbound endpoint
// (OBEP) hop emits a ShortTunnelBuildReply (type 26); every other hop relays
// the transformed build message (type 25) to the next hop. The outgoing I2NP
// message ID is the record's own "next message ID" field (bytes 52-55), not
// the ID the message arrived with.
package i2np

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newThreeSlotSTBMRaw builds a valid three-record STBM message body.
func newThreeSlotSTBMRaw() []byte {
	raw := make([]byte, 1+3*ShortBuildRecordSize)
	raw[0] = 3
	for i := 1; i < len(raw); i++ {
		raw[i] = byte(i % 197)
	}
	return raw
}

// TestGenerateAndSendBuildReply_TransitHopRelaysType25 verifies that a hop
// whose record has the OBEP flag cleared relays the transformed body as a
// type-25 build request to NextIdent instead of emitting a build reply.
func TestGenerateAndSendBuildReply_TransitHopRelaysType25(t *testing.T) {
	processor, mockForwarder, _ := setupBuildReplyTest(t, true)
	processor.stbmSlotCrypto = map[int]stbmSlotCrypto{1: newTestSTBMSlotCrypto()}

	record := createTestBuildRequestRecord(t)
	record.Flag = 0 // transit hop: OBEP bit clear
	record.SendMessageID = 9999

	err := processor.generateAndSendBuildReply(1000, 1, record, TunnelBuildReplySuccess, 0, newThreeSlotSTBMRaw(), 25)
	require.NoError(t, err)

	requestCalls := mockForwarder.getRequestCalls()
	require.Len(t, requestCalls, 1, "transit hop must relay a type-25 build request")
	assert.Equal(t, record.NextIdent, requestCalls[0].routerHash, "relay targets the record's NextIdent")
	assert.Equal(t, 9999, requestCalls[0].messageID,
		"relay message ID must be the record's own next-message-ID, not the incoming ID")
	assert.Len(t, requestCalls[0].body, 1+3*ShortBuildRecordSize,
		"relayed body is the full transformed build message")

	assert.Empty(t, mockForwarder.getRouterCalls(), "transit hop must not send a type-26 reply")
	assert.Empty(t, mockForwarder.getTunnelCalls(), "transit hop must not send a type-26 reply")
}

// TestGenerateAndSendBuildReply_OBEPHopSendsType26 verifies that the OBEP
// (outbound endpoint) hop emits the build reply and never relays the request.
func TestGenerateAndSendBuildReply_OBEPHopSendsType26(t *testing.T) {
	processor, mockForwarder, _ := setupBuildReplyTest(t, true)
	processor.stbmSlotCrypto = map[int]stbmSlotCrypto{2: newTestSTBMSlotCrypto()}

	record := createTestBuildRequestRecord(t)
	record.Flag = tunnel.FlagOBEP
	record.NextTunnel = 0 // reply goes directly to the reply-tunnel gateway router
	record.SendMessageID = 5555

	err := processor.generateAndSendBuildReply(1000, 2, record, TunnelBuildReplySuccess, 0, newThreeSlotSTBMRaw(), 25)
	require.NoError(t, err)

	routerCalls := mockForwarder.getRouterCalls()
	require.Len(t, routerCalls, 1, "OBEP hop must emit a build reply")
	assert.Equal(t, 5555, routerCalls[0].messageID, "reply ID must be the record's next-message-ID")
	assert.Equal(t, 25, routerCalls[0].inputMessageType, "reply derived from a type-25 request")

	assert.Empty(t, mockForwarder.getRequestCalls(), "OBEP hop must not relay the build request")
}

// TestProcessAllBuildRecords_TelescopesMixedFlags drives a three-record
// message where slots 0 and 1 are transit hops and slot 2 is the OBEP: the
// first two must relay type-25, the last must send the type-26 reply.
func TestProcessAllBuildRecords_TelescopesMixedFlags(t *testing.T) {
	processor, mockForwarder, mockParticipant := setupBuildReplyTest(t, true)
	var ourHash common.Hash
	for i := range ourHash {
		ourHash[i] = byte(0x10 + i)
	}
	processor.SetOurRouterHash(ourHash)
	processor.stbmSlotCrypto = map[int]stbmSlotCrypto{
		0: newTestSTBMSlotCrypto(),
		1: newTestSTBMSlotCrypto(),
		2: newTestSTBMSlotCrypto(),
	}

	records := make([]BuildRequestRecord, 3)
	for i := range records {
		records[i] = createTestBuildRequestRecord(t)
		records[i].OurIdent = ourHash
		records[i].Flag = 0 // transit by default
	}
	records[2].Flag = tunnel.FlagOBEP // outbound endpoint
	records[2].NextTunnel = 0         // reply routed directly to the reply gateway
	records[0].SendMessageID = 11
	records[1].SendMessageID = 22
	records[2].SendMessageID = 33

	require.NoError(t, processor.processAllBuildRecords(7000, records, []int{0, 1, 2}, newThreeSlotSTBMRaw(), 25))

	assert.Equal(t, 3, mockParticipant.getRegisteredCount(), "all three hops participate")

	requestCalls := mockForwarder.getRequestCalls()
	require.Len(t, requestCalls, 2, "two transit hops relay the build request")
	assert.Equal(t, 11, requestCalls[0].messageID)
	assert.Equal(t, 22, requestCalls[1].messageID)

	routerCalls := mockForwarder.getRouterCalls()
	require.Len(t, routerCalls, 1, "only the OBEP emits a build reply")
	assert.Equal(t, 33, routerCalls[0].messageID)
}

// TestGenerateAndSendBuildReply_RejectedTransitStillRelays verifies a rejected
// transit hop still relays the transformed message (with its failure slot) to
// the next hop rather than short-circuiting the chain.
func TestGenerateAndSendBuildReply_RejectedTransitStillRelays(t *testing.T) {
	processor, mockForwarder, _ := setupBuildReplyTest(t, true)
	processor.stbmSlotCrypto = map[int]stbmSlotCrypto{0: newTestSTBMSlotCrypto()}

	record := createTestBuildRequestRecord(t)
	record.Flag = 0
	record.SendMessageID = 777

	err := processor.generateAndSendBuildReply(1000, 0, record, TunnelBuildReplyCritical, 0, newThreeSlotSTBMRaw(), 25)
	require.NoError(t, err)

	requestCalls := mockForwarder.getRequestCalls()
	require.Len(t, requestCalls, 1, "rejected transit hop must still relay")
	assert.Equal(t, 777, requestCalls[0].messageID)
}

// inboundReplyProcessor implements TunnelBuildReplyProcessor plus the optional
// pendingInboundBuildMatcher so tests can drive inbound build completion.
type inboundReplyProcessor struct {
	pending  map[int]bool
	calls    []int
	handlers []TunnelReplyHandler
	err      error
}

func (m *inboundReplyProcessor) ProcessTunnelBuildReply(handler TunnelReplyHandler, messageID int) error {
	m.calls = append(m.calls, messageID)
	m.handlers = append(m.handlers, handler)
	return m.err
}

func (m *inboundReplyProcessor) HasPendingInboundBuild(messageID int) bool {
	return m.pending[messageID]
}

// newInboundReplySetBody builds the completed reply-set body an inbound build
// carries back to its creator: [count][N x 218].
func newInboundReplySetBody(count int) []byte {
	data := make([]byte, 1+count*ShortBuildRecordSize)
	data[0] = byte(count)
	for i := 1; i < len(data); i++ {
		data[i] = byte(i % 151)
	}
	return data
}

// TestTryCompleteInboundBuild_ConsumesOwnReplySet verifies that a type-25
// message whose ID matches our pending inbound build is handled as the
// completed reply set (mirrors i2pd GetPendingInboundTunnel).
func TestTryCompleteInboundBuild_ConsumesOwnReplySet(t *testing.T) {
	proc := &inboundReplyProcessor{pending: map[int]bool{4242: true}}
	processor := NewMessageProcessor()
	processor.SetBuildReplyProcessor(proc)

	handled, err := processor.tryCompleteInboundBuild(4242, newInboundReplySetBody(3))
	require.NoError(t, err)
	assert.True(t, handled, "message must be consumed as our inbound build reply")

	require.Len(t, proc.calls, 1)
	assert.Equal(t, 4242, proc.calls[0], "correlated by the relayed message ID")

	handler, ok := proc.handlers[0].(*ShortTunnelBuildReply)
	require.True(t, ok)
	assert.Equal(t, 3, handler.GetRecordCount())
	require.Len(t, handler.GetRawReplyRecords(), 3, "raw ciphertext preserved for deferred decryption")
	for i, raw := range handler.GetRawReplyRecords() {
		assert.Len(t, raw, ShortBuildRecordSize, "slot %d is a 218-byte short record", i)
	}
}

// TestTryCompleteInboundBuild_SkippedWhenNotPending verifies transit builds
// (no matching pending inbound build) fall through to normal processing.
func TestTryCompleteInboundBuild_SkippedWhenNotPending(t *testing.T) {
	proc := &inboundReplyProcessor{pending: map[int]bool{99: true}}
	processor := NewMessageProcessor()
	processor.SetBuildReplyProcessor(proc)

	handled, err := processor.tryCompleteInboundBuild(4242, newInboundReplySetBody(1))
	assert.NoError(t, err)
	assert.False(t, handled, "unrelated message must not be consumed")
	assert.Empty(t, proc.calls)
}

// TestTryCompleteInboundBuild_FallsBackOnUnparseableBody verifies a body that
// cannot be a reply set is left for build request processing instead of being
// misread as our inbound completion.
func TestTryCompleteInboundBuild_FallsBackOnUnparseableBody(t *testing.T) {
	proc := &inboundReplyProcessor{pending: map[int]bool{4242: true}}
	processor := NewMessageProcessor()
	processor.SetBuildReplyProcessor(proc)

	handled, err := processor.tryCompleteInboundBuild(4242, []byte{0}) // count 0 is invalid
	assert.NoError(t, err)
	assert.False(t, handled, "must fall back to build request processing")
	assert.Empty(t, proc.calls)
}

// TestBuildRequestProcessor_InboundCompletionShortCircuits drives the full
// process() path: the reply set must be dispatched to the reply processor and
// must never be parsed as build request records.
func TestBuildRequestProcessor_InboundCompletionShortCircuits(t *testing.T) {
	proc := &inboundReplyProcessor{pending: map[int]bool{5150: true}}
	processor, _, mockParticipant := setupBuildReplyTest(t, true)
	var ourHash common.Hash
	for i := range ourHash {
		ourHash[i] = byte(0x20 + i)
	}
	processor.SetOurRouterHash(ourHash)
	processor.SetBuildReplyProcessor(proc)

	msg := NewBaseI2NPMessage(I2NPMessageTypeShortTunnelBuild)
	msg.SetMessageID(5150)
	msg.SetData(newInboundReplySetBody(2))

	require.NoError(t, newBuildRequestProcessor(processor, msg).process())

	assert.Len(t, proc.calls, 1, "completed inbound build dispatched to reply processor")
	assert.Equal(t, 5150, proc.calls[0])
	assert.Equal(t, 0, mockParticipant.getRegisteredCount(),
		"a reply set must not be mistaken for a request to join a build")
}

// TestBuildRequestProcessor_TransitBuildStillProcessed verifies that when the
// reply processor does not match, process() continues with normal build
// request handling.
func TestBuildRequestProcessor_TransitBuildStillProcessed(t *testing.T) {
	proc := &inboundReplyProcessor{pending: map[int]bool{}}
	processor, mockForwarder, mockParticipant := setupBuildReplyTest(t, true)
	var ourHash common.Hash
	for i := range ourHash {
		ourHash[i] = byte(0x30 + i)
	}
	processor.SetOurRouterHash(ourHash)
	processor.SetBuildReplyProcessor(proc)
	processor.stbmSlotCrypto = map[int]stbmSlotCrypto{0: newTestSTBMSlotCrypto()}

	// A one-record body is not a parseable build request (undecryptable), so
	// it is dropped; the point is process() reached record parsing at all.
	msg := NewBaseI2NPMessage(I2NPMessageTypeShortTunnelBuild)
	msg.SetMessageID(6006)
	msg.SetData(newSingleSlotSTBMRaw())

	err := newBuildRequestProcessor(processor, msg).process()
	require.NoError(t, err)

	assert.Empty(t, proc.calls, "no pending inbound build -> reply processor untouched")
	assert.Empty(t, mockForwarder.getRequestCalls())
	assert.Equal(t, 0, mockParticipant.getRegisteredCount(),
		"an undecryptable record must not register participation")
}
