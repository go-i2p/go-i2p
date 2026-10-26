package i2np

import (
	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/go-i2p/lib/util/logutil"
	"github.com/samber/oops"

	"github.com/go-i2p/logger"
)

/*
I2P I2NP OutboundTunnelBuildReply (this type is named OutboundTunnelBuildReply)
https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/i2np.rst
Added in version 0.9.51

NOTE ON THE NAME: the specification calls message type 26
OutboundTunnelBuildReply (i2np.rst:696, :1721), not OutboundTunnelBuildReply —
"OutboundTunnelBuildReply" does not appear in the spec. The distinction is
semantic, not cosmetic: tunnel-creation-ecies.rst:537 pairs the two new
messages as "Short Tunnel Build Message (type 25) and Outbound Tunnel Build
Reply Message (type 26)", and the reply travels back over the *outbound*
tunnel. [OutboundTunnelBuildReply] is the spec-named alias for this type;
the OutboundTunnelBuildReply name is kept as the primary identifier for API
stability.

Format:
+----+----+----+----+----+----+----+----+
| num| ShortBuildResponseRecords...
+----+----+----+----+----+----+----+----+

num ::
       1 byte Integer
       Valid values: 1-8

record size: 218 bytes
total size: 1+$num*218
*/

// OutboundTunnelBuildReply represents an I2NP OutboundTunnelBuildReply message
// OutboundTunnelBuildReply is the type 26 message (i2np.rst:696, :1721), the
// reply counterpart to ShortTunnelBuild. It carries one compact
// 218-byte build response record per hop (1-8 records), which the
// TunnelManager uses to determine whether the short tunnel build succeeded.
// See [I2P Spec: I2NP](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/i2np.rst) for the wire format.
// See also [ShortTunnelBuild].
type OutboundTunnelBuildReply struct {
	Count                int
	BuildResponseRecords []BuildResponseRecord
	RawRecordData        [][]byte // Original encrypted bytes before parsing

	// repliedHops is how many entries of BuildResponseRecords are actual hop
	// replies. Zero means "all of them". A short build reply relays every slot of
	// the build request it answered - including the fake records the creator added
	// for randomized/padded record order - so the reply set is longer than the
	// tunnel. Scoring those extra slots as hops would reject a healthy build.
	repliedHops int
}

// GetReplyRecords returns the parsed build response records. It satisfies
// the TunnelReplyHandler interface so the reply processor can handle
// short and standard build replies uniformly.
// See also [TunnelReplyHandler].
func (s *OutboundTunnelBuildReply) GetReplyRecords() []BuildResponseRecord {
	return s.BuildResponseRecords
}

// GetRawReplyRecords returns the original encrypted record bytes as they
// appeared on the wire, before parsing. Useful for debugging and for
// re-decryption attempts when parsing fails.
func (s *OutboundTunnelBuildReply) GetRawReplyRecords() [][]byte {
	return s.RawRecordData
}

// GetRecordCount returns the number of response records, as declared in
// the 1-byte count field of the message. ProcessReply validates that this
// matches the actual number of parsed records.
func (s *OutboundTunnelBuildReply) GetRecordCount() int {
	return s.Count
}

// ProcessReply processes the short tunnel build reply by analyzing each response record.
// The current tunnel build reply format (v0.9.51+).
// Validates response integrity and determines tunnel build success/failure.
//
// Only the hop replies are analyzed: the trailing fake records are padding whose
// contents carry no verdict, and they still hold the parser's
// "pending decryption" sentinel, so counting them as hops would fail every build
// that correctly pads its record order.
func (s *OutboundTunnelBuildReply) ProcessReply() error {
	return processReplySteps(s, s.BuildResponseRecords[:s.hopRecordCount()])
}

// SetRepliedHopCount records how many of the reply's slots are real hop replies.
// Called by the reply processor once the build's hop count is known; satisfies
// the repliedHopCounter interface. Values outside 1-8 are ignored so a bogus
// count cannot truncate a legitimate reply.
func (s *OutboundTunnelBuildReply) SetRepliedHopCount(count int) {
	if count < 1 || count > maxBuildRecords {
		return
	}
	s.repliedHops = count
}

// hopRecordCount returns the number of BuildResponseRecords that are hop replies.
// Never exceeds what the message actually carries.
func (s *OutboundTunnelBuildReply) hopRecordCount() int {
	total := len(s.BuildResponseRecords)
	if s.repliedHops <= 0 || s.repliedHops > total {
		return total
	}
	return s.repliedHops
}

// logReplyStart logs the initial processing information.
func (s *OutboundTunnelBuildReply) logReplyStart(recordCount int) {
	log.WithFields(logger.Fields{
		"at":               "OutboundTunnelBuildReply.ProcessReply",
		"hop_record_count": recordCount,
		"total_records":    len(s.BuildResponseRecords),
		"count_field":      s.Count,
	}).Debug("Processing OutboundTunnelBuildReply")
}

// validateRecordCount validates that Count field matches actual record count.
// Returns an error if count mismatch or no records present.
// Delegates to shared ValidateRecordCount helper.
//
// The Count field is the message's declared record count, which covers the fake
// records too, so it is checked against everything the message carries rather
// than against the hop replies alone.
func (s *OutboundTunnelBuildReply) validateRecordCount(_ int) error {
	return ValidateRecordCount(s.Count, len(s.BuildResponseRecords), "OutboundTunnelBuildReply")
}

// processAllHops processes each hop response and counts successes.
// Returns the success count and the first error encountered (if any).
func (s *OutboundTunnelBuildReply) processAllHops() (int, error) {
	records := s.BuildResponseRecords[:s.hopRecordCount()]
	return processAllRecordsAsHops(records, s.processHopResponse)
}

// processHopResponse processes a single hop's build response.
// Returns true if the hop accepted the tunnel request, false otherwise. A
// rejection is returned as an error carrying the hop index and reply code so
// the tunnel creator can tell *why* the build failed, per tunnel-creation.rst
// (reply byte 0 = accept, non-zero = one of the defined reject codes).
func (s *OutboundTunnelBuildReply) processHopResponse(hopIndex int, record BuildResponseRecord) (bool, error) {
	// Verify record integrity using SHA-256 hash
	if err := s.verifyRecordIntegrity(hopIndex, record); err != nil {
		return false, err
	}

	return processHopReplyCode(hopIndex, record.Reply, "Short tunnel ")
}

// verifyRecordIntegrity verifies the SHA-256 hash of a build response record.
// For live STBM replies: the ChaCha20-decrypted 218-byte slot has only a 1-byte
// reply code plus padding — no hash field, so record.Hash stays zero. This method
// early-returns for those records.
// For test/non-STBM cases with non-zero hashes, verifies integrity is maintained.
func (s *OutboundTunnelBuildReply) verifyRecordIntegrity(hopIndex int, record BuildResponseRecord) error {
	// STBM reply records have zero hash; skip verification for these.
	var zeroHash [32]byte
	if record.Hash == zeroHash {
		log.WithFields(logger.Fields{
			"at":        "OutboundTunnelBuildReply.verifyRecordIntegrity",
			"hop_index": hopIndex,
		}).Debug("STBM reply record: skipping hash check (not present in STBM cleartext)")
		return nil
	}

	// If record has a non-zero hash, verify it covers RandomData + Reply
	dataToHash := make([]byte, 496)
	copy(dataToHash[:495], record.RandomData[:])
	dataToHash[495] = record.Reply

	computedHash := types.SHA256(dataToHash)

	if record.Hash != computedHash {
		log.WithFields(logger.Fields{
			"at":            "OutboundTunnelBuildReply.verifyRecordIntegrity",
			"hop_index":     hopIndex,
			"provided_hash": logutil.HashPrefix(record.Hash),
			"computed_hash": logutil.HashPrefix(computedHash),
		}).Warn("Record hash mismatch - integrity check failed")
		return oops.Errorf("record %d hash mismatch: provided %x, computed %x", hopIndex, record.Hash[:8], computedHash[:8])
	}

	return nil
}

// logReplyCompletion logs the final processing results.
func (s *OutboundTunnelBuildReply) logReplyCompletion(successCount, recordCount int) {
	log.WithFields(logger.Fields{
		"at":            "OutboundTunnelBuildReply.ProcessReply",
		"success_count": successCount,
		"total_hops":    recordCount,
	}).Debug("Completed OutboundTunnelBuildReply processing")
}

// determineBuildResult determines if the tunnel build succeeded overall.
// A tunnel build succeeds only if ALL hops accepted the request.
func (s *OutboundTunnelBuildReply) determineBuildResult(successCount, recordCount int, firstError error) error {
	if successCount == recordCount {
		log.WithFields(logger.Fields{
			"at":         "OutboundTunnelBuildReply.determineBuildResult",
			"hop_count":  recordCount,
			"all_passed": true,
		}).Debug("Short tunnel build succeeded - all hops accepted")
		return nil
	}

	failedHops := recordCount - successCount
	log.WithFields(logger.Fields{
		"at":          "OutboundTunnelBuildReply.determineBuildResult",
		"failed_hops": failedHops,
		"total_hops":  recordCount,
	}).Warn("Short tunnel build failed - one or more hops rejected")

	if firstError != nil {
		return oops.Wrapf(firstError, "short tunnel build failed: %d of %d hops rejected, first error", failedHops, recordCount)
	}

	return oops.Errorf("short tunnel build failed: %d of %d hops rejected", failedHops, recordCount)
}

// NewOutboundTunnelBuildReply creates a new OutboundTunnelBuildReply from a set
// of already-parsed build response records, setting the record count
// automatically.
// See also [OutboundTunnelBuildReply].
func NewOutboundTunnelBuildReply(records []BuildResponseRecord) *OutboundTunnelBuildReply {
	log.WithFields(logger.Fields{
		"at":           "NewOutboundTunnelBuildReply",
		"record_count": len(records),
	}).Debug("Creating OutboundTunnelBuildReply")

	return &OutboundTunnelBuildReply{
		Count:                len(records),
		BuildResponseRecords: records,
	}
}

// Compile-time interface satisfaction check
var _ TunnelReplyHandler = (*OutboundTunnelBuildReply)(nil)
