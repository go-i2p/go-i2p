package i2np

import (
	"crypto/sha256"
	"fmt"

	"github.com/go-i2p/logger"
)

/*
I2P I2NP ShortTunnelBuildReply
https://geti2p.net/spec/i2np
Added in version 0.9.51

Format:
+----+----+----+----+----+----+----+----+
| num| ShortBuildResponseRecords...
+----+----+----+----+----+----+----+----+

num ::
       1 byte Integer
       Valid values: 1-8

record size: 218 bytes (ElGamal/AES) or variable (ECIES)
total size: 1+$num*218 (for ElGamal/AES records)
*/

type ShortTunnelBuildReply struct {
	Count                int
	BuildResponseRecords []BuildResponseRecord
	RawRecordData        [][]byte // Original encrypted bytes before parsing
}

// GetResponseRecords returns the build response records (legacy method name)
func (s *ShortTunnelBuildReply) GetResponseRecords() []BuildResponseRecord {
	return s.BuildResponseRecords
}

// GetReplyRecords returns the build response records (TunnelReplyHandler interface)
func (s *ShortTunnelBuildReply) GetReplyRecords() []BuildResponseRecord {
	return s.BuildResponseRecords
}

// GetRawReplyRecords returns the original encrypted record bytes.
func (s *ShortTunnelBuildReply) GetRawReplyRecords() [][]byte {
	return s.RawRecordData
}

// GetRecordCount returns the number of response records
func (s *ShortTunnelBuildReply) GetRecordCount() int {
	return s.Count
}

// ProcessReply processes the short tunnel build reply by analyzing each response record.
// Similar to VariableTunnelBuildReply but specifically for short tunnel builds (v0.9.51+).
// Validates response integrity and determines tunnel build success/failure.
func (s *ShortTunnelBuildReply) ProcessReply() error {
	recordCount := len(s.BuildResponseRecords)

	s.logReplyStart(recordCount)

	if err := s.validateRecordCount(recordCount); err != nil {
		return err
	}

	successCount, firstError := s.processAllHops()

	s.logReplyCompletion(successCount, recordCount)

	return s.determineBuildResult(successCount, recordCount, firstError)
}

// logReplyStart logs the initial processing information.
func (s *ShortTunnelBuildReply) logReplyStart(recordCount int) {
	log.WithFields(logger.Fields{
		"at":           "ShortTunnelBuildReply.ProcessReply",
		"record_count": recordCount,
		"count_field":  s.Count,
	}).Debug("Processing ShortTunnelBuildReply")
}

// validateRecordCount validates that Count field matches actual record count.
// Returns an error if count mismatch or no records present.
func (s *ShortTunnelBuildReply) validateRecordCount(recordCount int) error {
	if s.Count != recordCount {
		return fmt.Errorf("count mismatch: Count field is %d but have %d records", s.Count, recordCount)
	}

	if recordCount == 0 {
		log.Warn("ShortTunnelBuildReply has no response records")
		return fmt.Errorf("tunnel build failed: no response records")
	}

	return nil
}

// processAllHops processes each hop response and counts successes.
// Returns the success count and the first error encountered (if any).
func (s *ShortTunnelBuildReply) processAllHops() (int, error) {
	successCount := 0
	var firstError error

	for i, record := range s.BuildResponseRecords {
		success, err := s.processHopResponse(i, record)
		if err != nil {
			log.WithFields(logger.Fields{
				"at":        "ShortTunnelBuildReply.processAllHops",
				"hop_index": i,
				"error":     err,
			}).Warn("Failed to process hop response")

			if firstError == nil {
				firstError = err
			}
			continue
		}

		if success {
			successCount++
		}
	}

	return successCount, firstError
}

// processHopResponse processes a single hop's build response.
// Returns true if the hop accepted the tunnel request, false otherwise.
func (s *ShortTunnelBuildReply) processHopResponse(hopIndex int, record BuildResponseRecord) (bool, error) {
	// Verify record integrity using SHA-256 hash
	if err := s.verifyRecordIntegrity(hopIndex, record); err != nil {
		return false, err
	}

	// Check if this hop accepted the tunnel request
	// The Reply field contains the response code
	replyCode := record.Reply
	accepted := replyCode == TUNNEL_BUILD_REPLY_SUCCESS

	log.WithFields(logger.Fields{
		"at":         "ShortTunnelBuildReply.processHopResponse",
		"hop_index":  hopIndex,
		"reply_code": replyCode,
		"accepted":   accepted,
	}).Debug("Processed hop response")

	return accepted, nil
}

// verifyRecordIntegrity verifies the SHA-256 hash of a build response record.
func (s *ShortTunnelBuildReply) verifyRecordIntegrity(hopIndex int, record BuildResponseRecord) error {
	// BuildResponseRecord has: Hash (32 bytes), RandomData (495 bytes), Reply (1 byte)
	// Total: 528 bytes
	// The Hash field should match the SHA-256 of RandomData + Reply

	// Compute hash of RandomData + Reply
	dataToHash := make([]byte, 496)
	copy(dataToHash[:495], record.RandomData[:])
	dataToHash[495] = record.Reply

	computedHash := sha256.Sum256(dataToHash)

	if record.Hash != computedHash {
		log.WithFields(logger.Fields{
			"at":            "ShortTunnelBuildReply.verifyRecordIntegrity",
			"hop_index":     hopIndex,
			"provided_hash": fmt.Sprintf("%x", record.Hash[:8]),
			"computed_hash": fmt.Sprintf("%x", computedHash[:8]),
		}).Warn("Record hash mismatch - integrity check failed")
		return fmt.Errorf("record %d hash mismatch: provided %x, computed %x", hopIndex, record.Hash[:8], computedHash[:8])
	}

	return nil
}

// logReplyCompletion logs the final processing results.
func (s *ShortTunnelBuildReply) logReplyCompletion(successCount, recordCount int) {
	log.WithFields(logger.Fields{
		"at":            "ShortTunnelBuildReply.ProcessReply",
		"success_count": successCount,
		"total_hops":    recordCount,
	}).Debug("Completed ShortTunnelBuildReply processing")
}

// determineBuildResult determines if the tunnel build succeeded overall.
// A tunnel build succeeds only if ALL hops accepted the request.
func (s *ShortTunnelBuildReply) determineBuildResult(successCount, recordCount int, firstError error) error {
	if successCount == recordCount {
		log.WithFields(logger.Fields{
			"at":         "ShortTunnelBuildReply.determineBuildResult",
			"hop_count":  recordCount,
			"all_passed": true,
		}).Debug("Short tunnel build succeeded - all hops accepted")
		return nil
	}

	failedHops := recordCount - successCount
	log.WithFields(logger.Fields{
		"at":          "ShortTunnelBuildReply.determineBuildResult",
		"failed_hops": failedHops,
		"total_hops":  recordCount,
	}).Warn("Short tunnel build failed - one or more hops rejected")

	if firstError != nil {
		return fmt.Errorf("short tunnel build failed: %d of %d hops rejected, first error: %w", failedHops, recordCount, firstError)
	}

	return fmt.Errorf("short tunnel build failed: %d of %d hops rejected", failedHops, recordCount)
}

// NewShortTunnelBuildReply creates a new ShortTunnelBuildReply
func NewShortTunnelBuildReply(records []BuildResponseRecord) *ShortTunnelBuildReply {
	log.WithFields(logger.Fields{
		"at":           "NewShortTunnelBuildReply",
		"record_count": len(records),
	}).Debug("Creating ShortTunnelBuildReply")

	return &ShortTunnelBuildReply{
		Count:                len(records),
		BuildResponseRecords: records,
	}
}

// Compile-time interface satisfaction check
var _ TunnelReplyHandler = (*ShortTunnelBuildReply)(nil)
