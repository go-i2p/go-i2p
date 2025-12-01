package i2np

import (
	"crypto/sha256"
	"fmt"

	"github.com/go-i2p/logger"
)

/*
I2P I2NP VariableTunnelBuildReply
https://geti2p.net/spec/i2np
Accurate for version 0.9.28

+----+----+----+----+----+----+----+----+
| num| BuildResponseRecords...
+----+----+----+----+----+----+----+----+

Same format as VariableTunnelBuildMessage, with BuildResponseRecords.
*/

type VariableTunnelBuildReply struct {
	Count                int
	BuildResponseRecords []BuildResponseRecord
}

// GetReplyRecords returns the build response records
func (v *VariableTunnelBuildReply) GetReplyRecords() []BuildResponseRecord {
	return v.BuildResponseRecords
}

// ProcessReply processes the variable tunnel build reply by analyzing each response record.
// Similar to TunnelBuildReply but handles variable-length tunnels (1-8 hops).
// Validates response integrity and determines tunnel build success/failure.
func (v *VariableTunnelBuildReply) ProcessReply() error {
	recordCount := len(v.BuildResponseRecords)

	v.logReplyStart(recordCount)

	if err := v.validateRecordCount(recordCount); err != nil {
		return err
	}

	successCount, firstError := v.processAllHops()

	v.logReplyCompletion(successCount, recordCount)

	return v.determineBuildResult(successCount, recordCount, firstError)
}

// logReplyStart logs the initial processing information.
func (v *VariableTunnelBuildReply) logReplyStart(recordCount int) {
	log.WithFields(logger.Fields{
		"record_count": recordCount,
		"count_field":  v.Count,
	}).Debug("Processing VariableTunnelBuildReply")
}

// validateRecordCount validates that Count field matches actual record count.
// Returns an error if count mismatch or no records present.
func (v *VariableTunnelBuildReply) validateRecordCount(recordCount int) error {
	if v.Count != recordCount {
		return fmt.Errorf("count mismatch: Count field is %d but have %d records", v.Count, recordCount)
	}

	if recordCount == 0 {
		log.Warn("VariableTunnelBuildReply has no response records")
		return fmt.Errorf("tunnel build failed: no response records")
	}

	return nil
}

// processAllHops processes each hop response and counts successes.
// Returns the success count and the first error encountered (if any).
func (v *VariableTunnelBuildReply) processAllHops() (int, error) {
	successCount := 0
	var firstError error

	for i, record := range v.BuildResponseRecords {
		success, err := v.processHopResponse(i, record)
		if err != nil {
			log.WithFields(logger.Fields{
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

// logReplyCompletion logs the final processing results with success rate.
func (v *VariableTunnelBuildReply) logReplyCompletion(successCount, recordCount int) {
	log.WithFields(logger.Fields{
		"success_count": successCount,
		"total_hops":    recordCount,
		"success_rate":  float64(successCount) / float64(recordCount),
	}).Info("VariableTunnelBuildReply processing completed")
}

// determineBuildResult determines the final result based on success count.
// Returns nil if all hops accepted, otherwise returns an appropriate error.
func (v *VariableTunnelBuildReply) determineBuildResult(successCount, recordCount int, firstError error) error {
	if successCount == recordCount {
		log.Debug("Variable tunnel build successful - all hops accepted")
		return nil
	}

	if firstError != nil {
		return fmt.Errorf("variable tunnel build failed: %w", firstError)
	}

	return fmt.Errorf("variable tunnel build failed: only %d of %d hops accepted", successCount, recordCount)
}

// processHopResponse processes a single hop's response record for variable tunnels.
// Returns (success, error) where success indicates if the hop accepted the tunnel.
func (v *VariableTunnelBuildReply) processHopResponse(hopIndex int, record BuildResponseRecord) (bool, error) {
	log.WithFields(logger.Fields{
		"hop_index":  hopIndex,
		"reply_code": record.Reply,
	}).Debug("Processing variable tunnel hop response")

	// Validate response record (basic integrity check)
	if err := v.validateResponseRecord(record); err != nil {
		return false, fmt.Errorf("hop %d: invalid response record: %w", hopIndex, err)
	}

	// Process reply code (same logic as TunnelBuildReply)
	switch record.Reply {
	case TUNNEL_BUILD_REPLY_SUCCESS:
		log.WithField("hop_index", hopIndex).Debug("Variable tunnel hop accepted build request")
		return true, nil

	case TUNNEL_BUILD_REPLY_REJECT:
		log.WithField("hop_index", hopIndex).Warn("Variable tunnel hop rejected build request")
		return false, fmt.Errorf("hop %d: rejected request", hopIndex)

	case TUNNEL_BUILD_REPLY_OVERLOAD:
		log.WithField("hop_index", hopIndex).Warn("Variable tunnel hop is overloaded")
		return false, fmt.Errorf("hop %d: router overloaded", hopIndex)

	case TUNNEL_BUILD_REPLY_BANDWIDTH:
		log.WithField("hop_index", hopIndex).Warn("Variable tunnel hop has insufficient bandwidth")
		return false, fmt.Errorf("hop %d: insufficient bandwidth", hopIndex)

	case TUNNEL_BUILD_REPLY_INVALID:
		log.WithField("hop_index", hopIndex).Warn("Variable tunnel hop received invalid request data")
		return false, fmt.Errorf("hop %d: invalid request data", hopIndex)

	case TUNNEL_BUILD_REPLY_EXPIRED:
		log.WithField("hop_index", hopIndex).Warn("Variable tunnel hop request has expired")
		return false, fmt.Errorf("hop %d: request expired", hopIndex)

	default:
		log.WithFields(logger.Fields{
			"hop_index":  hopIndex,
			"reply_code": record.Reply,
		}).Warn("Variable tunnel hop returned unknown reply code")
		return false, fmt.Errorf("hop %d: unknown reply code %d", hopIndex, record.Reply)
	}
}

// validateResponseRecord performs basic validation of a variable tunnel build response record.
// This checks that the record structure is valid but does not verify cryptographic integrity.
func (v *VariableTunnelBuildReply) validateResponseRecord(record BuildResponseRecord) error {
	// Check if hash is all zeros (likely indicates an empty/invalid record)
	allZeros := true
	for _, b := range record.Hash {
		if b != 0 {
			allZeros = false
			break
		}
	}

	if allZeros {
		return fmt.Errorf("variable tunnel response record has empty hash")
	}

	// Verify SHA-256 hash: hash should be SHA256(random_data + reply_byte)
	data := make([]byte, 496)
	copy(data[0:495], record.RandomData[:])
	data[495] = record.Reply

	computedHash := sha256.Sum256(data)
	if computedHash != record.Hash {
		log.WithFields(logger.Fields{
			"expected": record.Hash,
			"computed": computedHash,
		}).Warn("Variable tunnel response record hash mismatch")
		return fmt.Errorf("variable tunnel response record hash verification failed")
	}

	log.Debug("Variable tunnel response record validation passed")
	return nil
}

// Compile-time interface satisfaction check
var _ TunnelReplyHandler = (*VariableTunnelBuildReply)(nil)
