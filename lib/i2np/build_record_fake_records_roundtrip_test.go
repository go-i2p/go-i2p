// Round-trip proof that fake build records (C3) are consistent between the
// creator's wire assembly and the creator's reply peel.
//
// Spec: tunnel-creation-ecies.rst "Build Records" - inbound builds must carry a
// fake record for the originator, and the originator must verify it came back
// unmodified or discard the tunnel.
package i2np

import (
	"crypto/sha256"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/common/session_key"
	rand "github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/require"
)

// fakeRecordsRoundTrip drives one simulated padded build/reply cycle.
type fakeRecordsRoundTrip struct {
	recordSlots []int
	wireCount   int
	hopCount    int
	phonySlot   int
	phonySent   []byte
	retCodes    []byte
	rawWire     [][]byte // populated by run(): the padded reply as it hits the wire

	// crypto context captured by run() so a test can register the same pending
	// build through the public ReplyProcessor API.
	replyKeys     [][32]byte
	replyIVs      [][16]byte
	noiseHashes   [][32]byte
	phonyChecksum [sha256.Size]byte
}

// newRoundTrip picks a wire layout for a build with the given hop count that
// always carries a phony record, and finds a permutation whose phony slot is not
// the last slot - so the peel genuinely has to protect a slot in the middle of
// the reply set rather than getting the tail for free.
func newRoundTrip(t *testing.T, hopCount int) *fakeRecordsRoundTrip {
	t.Helper()

	pathEntries := hopCount + 1
	wireCount := shortBuildRecordCount(pathEntries)
	require.GreaterOrEqual(t, wireCount, pathEntries)

	f := &fakeRecordsRoundTrip{
		hopCount:  hopCount,
		wireCount: wireCount,
		retCodes:  make([]byte, hopCount),
	}
	for i := range f.retCodes {
		f.retCodes[i] = byte(0x20 + i) // distinct and non-zero, so misattribution shows up
	}

	for attempt := 0; attempt < 500; attempt++ {
		perm := shuffleRecordSlots(wireCount)
		if perm[hopCount] == wireCount-1 {
			continue // want the phony mid-set, not at the tail
		}
		f.recordSlots = perm
		return f
	}
	require.FailNow(t, "could not find a permutation placing the phony entry mid-set")
	return f
}

// run executes the full cycle: creator assembly with phony + padding, hop relay
// processing, and the creator's peel. When tamperPhony is set, one byte of our
// fake record is flipped in transit, which the spec says must fail the build.
func (f *fakeRecordsRoundTrip) run(t *testing.T, tamperPhony bool) ([]BuildResponseRecord, error) {
	t.Helper()

	replyKeys := make([][32]byte, f.hopCount)
	noiseHashes := make([][32]byte, f.hopCount)
	for i := 0; i < f.hopCount; i++ {
		_, err := rand.Read(replyKeys[i][:])
		require.NoError(t, err)
		_, err = rand.Read(noiseHashes[i][:])
		require.NoError(t, err)
	}

	// Path-ordered encrypted records for the real hops.
	pathRecords := make([][ShortBuildRecordSize]byte, f.hopCount)
	for i := range pathRecords {
		_, err := rand.Read(pathRecords[i][:])
		require.NoError(t, err)
	}

	f.replyKeys = replyKeys
	f.noiseHashes = noiseHashes
	f.replyIVs = make([][16]byte, f.hopCount)
	for i := range f.replyIVs {
		_, err := rand.Read(f.replyIVs[i][:])
		require.NoError(t, err)
	}

	pathEntries := f.hopCount + 1

	// The phony record: our hash prefix, a real X25519 key, random remainder.
	phony, err := makePhonyShortBuildRecord(testRouterHash())
	require.NoError(t, err)
	var phonyBuf [ShortBuildRecordSize]byte
	copy(phonyBuf[:], phony)
	pathRecords = append(pathRecords, phonyBuf)
	f.phonySent = append([]byte(nil), phony...)

	// Padding slots past the last path entry.
	for entry := pathEntries; entry < f.wireCount; entry++ {
		pad, padErr := makeRandomShortBuildRecord()
		require.NoError(t, padErr)
		var buf [ShortBuildRecordSize]byte
		copy(buf[:], pad)
		pathRecords = append(pathRecords, buf)
	}

	// Creator pre-applies ChaCha20 layers over the wire-slot layout, covering the
	// path entries (hops + phony) but never the padding - exactly what
	// createSerializedShortTunnelBuildMessage does.
	tm := &TunnelManager{}
	keyBytes := make([][32]byte, f.hopCount)
	copy(keyBytes, replyKeys)
	require.NoError(t, tm.applyChaCha20LayerObfuscation(pathRecords[:pathEntries], keyBytes, f.recordSlots))

	// Lay the records out on the wire in permuted order.
	wire := make([][ShortBuildRecordSize]byte, f.wireCount)
	for entry := 0; entry < f.wireCount; entry++ {
		wire[f.recordSlots[entry]] = pathRecords[entry]
	}
	f.phonySlot = f.recordSlots[f.hopCount]

	// Each hop relays the message: XOR every slot but its own, then replace its
	// own slot with its AEAD reply. Mirrors encryptSTBMSlots.
	for hopIndex := 0; hopIndex < f.hopCount; hopIndex++ {
		ourSlot := f.recordSlots[hopIndex]
		for j := 0; j < f.wireCount; j++ {
			if j == ourSlot {
				continue
			}
			require.NoError(t, chacha20XORRecord(&wire[j], replyKeys[hopIndex], j))
		}
		wire[ourSlot] = createAEADReplySlot(t, replyKeys[hopIndex], noiseHashes[hopIndex],
			ourSlot, f.retCodes[hopIndex])
	}

	if tamperPhony {
		wire[f.phonySlot][0] ^= 0x01
	}

	raw := make([][]byte, f.wireCount)
	for i := range wire {
		raw[i] = wire[i][:]
	}
	f.rawWire = raw

	// The reply parser fills every slot with the pending-decryption sentinel; the
	// peel overwrites only the real hops.
	records := make([]BuildResponseRecord, f.wireCount)
	for i := range records {
		records[i] = BuildResponseRecord{Reply: TunnelBuildReplyPendingDecryption}
	}

	f.phonyChecksum = sha256.Sum256(f.phonySent)

	pending := &PendingBuildRequest{
		ReplyKeys:      toSessionKeys(replyKeys),
		NoiseHashes:    noiseHashes,
		HopCount:       f.hopCount,
		HasPhonyRecord: true,
		PhonyChecksum:  sha256.Sum256(f.phonySent),
		RecordSlots:    f.recordSlots,
	}
	rp := NewReplyProcessor(DefaultReplyProcessorConfig(), nil)
	return records, rp.decryptSTBMReplyRecords(records, raw, pending)
}

// TestFakeRecordsRoundTrip asserts a padded inbound build round-trips: every
// hop's ret code is recovered in path order and the phony record comes back
// byte-identical so its checksum validates.
func TestFakeRecordsRoundTrip(t *testing.T) {
	for _, hopCount := range []int{1, 2, 3, 4, 5, 7} {
		t.Run(itoa(hopCount)+"-hops", func(t *testing.T) {
			f := newRoundTrip(t, hopCount)
			records, err := f.run(t, false)
			require.NoError(t, err, "padded inbound build must round-trip")

			for i := 0; i < hopCount; i++ {
				require.Equal(t, f.retCodes[i], records[i].Reply,
					"hop %d ret code mismatch (wire layout %v)", i, f.recordSlots)
			}
			// Fake/padding slots are never read: they must still hold the sentinel.
			for i := hopCount; i < len(records); i++ {
				require.Equal(t, byte(TunnelBuildReplyPendingDecryption), records[i].Reply,
					"slot %d should not have been evaluated as a hop reply", i)
			}
		})
	}
}

// TestFakeRecordsTamperDetected asserts the spec-mandated discard: if a previous
// hop modifies our fake record, the build must fail rather than be established.
func TestFakeRecordsTamperDetected(t *testing.T) {
	f := newRoundTrip(t, 3)
	_, err := f.run(t, true)
	require.Error(t, err, "modified phony record must discard the tunnel")
	require.Contains(t, err.Error(), "modified in transit")
}

// TestBuildRecordMinimumCount pins the recommended minimum of 4 build records
// and the 8-record ceiling for larger paths (this also closes W9's
// minimum-record finding for the default 3-hop tunnel).
func TestBuildRecordMinimumCount(t *testing.T) {
	require.Equal(t, 4, shortBuildRecordCount(1))
	require.Equal(t, 4, shortBuildRecordCount(3))
	require.Equal(t, 4, shortBuildRecordCount(4))
	require.Equal(t, 8, shortBuildRecordCount(5))
	require.Equal(t, 8, shortBuildRecordCount(8))
}

// TestPhonyRecordShape asserts the fake record carries the two fields the spec
// names, so the closest hop cannot tell the originator from a transit peer.
func TestPhonyRecordShape(t *testing.T) {
	hash := testRouterHash()
	rec, err := makePhonyShortBuildRecord(hash)
	require.NoError(t, err)
	require.Len(t, rec, ShortBuildRecordSize)

	require.Equal(t, hash[:16], rec[:phonyHashPrefixLen], "correct 16-byte hash prefix")

	key := rec[phonyHashPrefixLen:phonyBodyOffset]
	require.NotEqual(t, make([]byte, phonyEphemeralKeyID), key, "ephemeral key must not be zero")
	distinct := map[byte]bool{}
	for _, b := range key {
		distinct[b] = true
	}
	require.Greater(t, len(distinct), 1, "phony ephemeral key looks like filler bytes")

	_, err = makePhonyShortBuildRecord(common.Hash{})
	require.Error(t, err, "unset router hash must be refused, not sent anonymous")
}

// TestShouldInsertPhonyRecord pins the inbound-only rule and the no-room case.
func TestShouldInsertPhonyRecord(t *testing.T) {
	require.True(t, shouldInsertPhonyRecord(true, 3), "inbound builds must carry a phony record")
	require.False(t, shouldInsertPhonyRecord(false, 3), "outbound fake records are optional")
	require.False(t, shouldInsertPhonyRecord(true, maxBuildRecords),
		"a full 8-hop path has no room for an extra record")
}

// TestReplyHandlerScoresHopsNotWireRecords asserts a padded reply set is scored
// on hop count: the trailing fake/padding slots must not read as rejections.
func TestReplyHandlerScoresHopsNotWireRecords(t *testing.T) {
	replies := []BuildResponseRecord{
		{Reply: TunnelBuildReplySuccess},
		{Reply: TunnelBuildReplySuccess},
		{Reply: TunnelBuildReplySuccess},
		{Reply: TunnelBuildReplyPendingDecryption},
	}
	handler := &OutboundTunnelBuildReply{
		Count:                len(replies),
		BuildResponseRecords: replies,
	}

	// Without the hop count the padded slot is scored as a rejecting hop.
	require.Error(t, handler.ProcessReply(), "padding slot must not be scored as a hop")

	// With it, the build succeeds.
	handler.SetRepliedHopCount(3)
	require.NoError(t, handler.ProcessReply())
}

// TestSetRepliedHopCountIgnoresBogusValues guards the truncation helper against
// a count that would truncate or over-run a legitimate reply.
func TestSetRepliedHopCountIgnoresBogusValues(t *testing.T) {
	replies := make([]BuildResponseRecord, 4)
	for i := range replies {
		replies[i] = BuildResponseRecord{Reply: TunnelBuildReplySuccess}
	}
	h := &OutboundTunnelBuildReply{Count: 4, BuildResponseRecords: replies}

	h.SetRepliedHopCount(0)
	require.Equal(t, 4, h.hopRecordCount())
	h.SetRepliedHopCount(-1)
	require.Equal(t, 4, h.hopRecordCount())
	h.SetRepliedHopCount(maxBuildRecords + 1)
	require.Equal(t, 4, h.hopRecordCount())
}

// TestLockedReplySlotsCoversFakeRecords asserts the peel's protected set is
// exactly the slots belonging to path entries past the last hop - the phony
// record plus any padding - and that no hop's own slot is protected.
func TestLockedReplySlotsCoversFakeRecords(t *testing.T) {
	// 3 hops + 1 phony = 4 path entries on a 4-record wire: the phony entry (3)
	// maps to slot 1. Slots 2, 0 and 3 belong to hops 0, 1 and 2.
	pending := &PendingBuildRequest{
		ReplyKeys:      make([]session_key.SessionKey, 3),
		HopCount:       3,
		HasPhonyRecord: true,
		RecordSlots:    []int{2, 0, 3, 1},
	}
	locked := lockedReplySlots(pending, 4)
	require.Equal(t, map[int]bool{1: true}, locked, "only the phony slot is protected")
	require.False(t, locked[3], "hop 2's slot must be peeled")
	require.False(t, locked[2], "hop 0's slot must be peeled")

	// Same layout on an 8-record wire: entries 4..7 are padding, so slots 4..7
	// are protected alongside the phony.
	wide := &PendingBuildRequest{
		ReplyKeys:      make([]session_key.SessionKey, 3),
		HopCount:       3,
		HasPhonyRecord: true,
		RecordSlots:    []int{2, 0, 3, 1, 7, 6, 5, 4},
	}
	wideLocked := lockedReplySlots(wide, 8)
	require.Equal(t, map[int]bool{1: true, 7: true, 6: true, 5: true, 4: true}, wideLocked)
	require.False(t, wideLocked[2])
	require.False(t, wideLocked[0])
	require.False(t, wideLocked[3])
}

func testRouterHash() common.Hash {
	var h common.Hash
	_, _ = rand.Read(h[:])
	return h
}

// TestType26DispatchHandlesPaddedReply drives a padded reply through the real
// OutboundTunnelBuildReply (type 26) dispatch path rather than the simulated relay
// used above: processBuildReplyCommon parses the wire bytes into a handler whose
// Count is the WIRE record count, then TunnelManager correlates it to the pending
// build and the ReplyProcessor decrypts and scores it.
//
// This is the path that the round-trip harness alone does not cover, and it is
// where a padded reply could be mis-scored: the handler is built before anyone
// knows the hop count, so the reply must be truncated to the real hops before
// ProcessReply runs.
func TestType26DispatchHandlesPaddedReply(t *testing.T) {
	for _, hopCount := range []int{1, 3} {
		t.Run(itoa(hopCount)+"-hops", func(t *testing.T) {
			f := newRoundTrip(t, hopCount)
			// Hops must ACCEPT for the build to succeed; the peel test above uses
			// distinct non-zero codes to catch misattribution, but processAllHops
			// treats any non-zero byte as a rejection.
			for i := range f.retCodes {
				f.retCodes[i] = TunnelBuildReplySuccess
			}
			if _, err := f.run(t, false); err != nil {
				require.NoError(t, err, "padded inbound build must round-trip")
			}

			// Build the type-26 wire payload: 1 byte count + N 218-byte slots,
			// exactly as a transit hop would relay it back to us.
			data := make([]byte, 1+len(f.rawWire)*ShortBuildRecordSize)
			data[0] = byte(len(f.rawWire))
			off := 1
			for _, slot := range f.rawWire {
				copy(data[off:], slot)
				off += ShortBuildRecordSize
			}

			msg := NewBaseI2NPMessage(I2NPMessageTypeOutboundTunnelBuildReply)
			const messageID = 4242
			msg.SetMessageID(messageID)
			msg.SetData(data)

			tm := NewTunnelManager(&mockPeerSelector{})

			// Register the pending build through the same API the creator uses, so
			// the reply correlates by I2NP message ID instead of falling to the
			// uncorrelated late-reply path.
			result := &tunnel.TunnelBuildResult{
				TunnelID:       tunnel.TunnelID(12345),
				Hops:           make([]router_info.RouterInfo, hopCount),
				ReplyKeys:      toSessionKeys(f.replyKeys),
				ReplyIVs:       f.replyIVs,
				NoiseHashes:    f.noiseHashes,
				UseShortBuild:  true,
				IsInbound:      true,
				RecordSlots:    f.recordSlots,
				HasPhonyRecord: true,
				PhonyChecksum:  f.phonyChecksum,
			}
			tm.trackPendingBuild(result, messageID, tunnel.BuildTunnelRequest{
				HopCount: hopCount, IsInbound: true, UseShortBuild: true,
			})
			// finalizePendingBuild registers the same context on the ReplyProcessor
			// under the tunnel ID; mirror both registrations here.
			require.NoError(t, tm.replyProcessor.RegisterPendingBuild(
				result.TunnelID, result.ReplyKeys, result.ReplyIVs, true, hopCount))
			require.NoError(t, tm.replyProcessor.SetPendingBuildNoiseHashes(result.TunnelID, f.noiseHashes))
			require.NoError(t, tm.replyProcessor.SetPendingBuildRecordSlots(
				result.TunnelID, f.recordSlots, true, f.phonyChecksum))

			recorder := &recordingReplyProcessor{delegate: tm}
			processor := NewMessageProcessor()
			processor.SetBuildReplyProcessor(recorder)

			require.NoError(t, processor.processOutboundTunnelBuildReplyMessage(msg),
				"a padded type-26 reply must process cleanly through the real dispatch")

			// The hops must have been scored in PATH order with their real ret
			// codes, and the padded slots must not have been scored at all.
			stb, ok := recorder.handler.(*OutboundTunnelBuildReply)
			require.True(t, ok, "dispatch must build a OutboundTunnelBuildReply, got %T", recorder.handler)
			records := stb.GetReplyRecords()
			require.Len(t, records, f.wireCount,
				"dispatch must expose every wire slot, including the fake records")
			for i := 0; i < hopCount; i++ {
				require.Equal(t, byte(TunnelBuildReplySuccess), records[i].Reply,
					"dispatched reply lost hop %d's acceptance (wire layout %v)", i, f.recordSlots)
			}
			// Fake/padding slots stay unscored: the pending-decryption sentinel is
			// what an unpeeled slot holds, and scoring it as a hop would fail a
			// perfectly good build.
			for i := hopCount; i < len(records); i++ {
				require.Equal(t, byte(TunnelBuildReplyPendingDecryption), records[i].Reply,
					"slot %d must not be scored as a hop reply", i)
			}
		})
	}
}

// recordingReplyProcessor captures the handler the type-26 dispatch built while
// delegating the actual work to the TunnelManager, so a test can inspect the
// records after the real peel ran.
type recordingReplyProcessor struct {
	delegate TunnelBuildReplyProcessor
	handler  TunnelReplyHandler
}

func (r *recordingReplyProcessor) ProcessTunnelBuildReply(handler TunnelReplyHandler, messageID int) error {
	r.handler = handler
	return r.delegate.ProcessTunnelBuildReply(handler, messageID)
}
