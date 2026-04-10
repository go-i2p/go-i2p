package i2np

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
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

// VariableTunnelBuildReply represents an I2NP VariableTunnelBuildReply message containing a variable number of build response records.
type VariableTunnelBuildReply struct {
	Count                int
	BuildResponseRecords []BuildResponseRecord
	RawRecordData        [][]byte // Original encrypted bytes before parsing
}

// GetReplyRecords returns the build response records
func (v *VariableTunnelBuildReply) GetReplyRecords() []BuildResponseRecord {
	return v.BuildResponseRecords
}

// GetRawReplyRecords returns the original encrypted record bytes.
func (v *VariableTunnelBuildReply) GetRawReplyRecords() [][]byte {
	return v.RawRecordData
}

// ProcessReply processes the variable tunnel build reply by analyzing each response record.
// Similar to TunnelBuildReply but handles variable-length tunnels (1-8 hops).
// Validates response integrity and determines tunnel build success/failure.
func (v *VariableTunnelBuildReply) ProcessReply() error {
	return processReplySteps(v, v.BuildResponseRecords)
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
		return oops.Errorf("count mismatch: Count field is %d but have %d records", v.Count, recordCount)
	}

	if recordCount == 0 {
		log.WithFields(logger.Fields{"at": "validateRecordCount"}).Warn("VariableTunnelBuildReply has no response records")
		return oops.Errorf("tunnel build failed: no response records")
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
		log.WithFields(logger.Fields{"at": "determineBuildResult"}).Debug("Variable tunnel build successful - all hops accepted")
		return nil
	}

	if firstError != nil {
		return oops.Wrapf(firstError, "variable tunnel build failed")
	}

	return oops.Errorf("variable tunnel build failed: only %d of %d hops accepted", successCount, recordCount)
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
		return false, oops.Wrapf(err, "hop %d: invalid response record", hopIndex)
	}

	// Process reply code (same logic as TunnelBuildReply)
	switch record.Reply {
	case TunnelBuildReplySuccess:
		log.WithField("hop_index", hopIndex).Debug("Variable tunnel hop accepted build request")
		return true, nil

	case TunnelBuildReplyReject:
		log.WithField("hop_index", hopIndex).Warn("Variable tunnel hop rejected build request")
		return false, oops.Errorf("hop %d: rejected request", hopIndex)

	case TunnelBuildReplyOverload:
		log.WithField("hop_index", hopIndex).Warn("Variable tunnel hop is overloaded")
		return false, oops.Errorf("hop %d: router overloaded", hopIndex)

	case TunnelBuildReplyBandwidth:
		log.WithField("hop_index", hopIndex).Warn("Variable tunnel hop has insufficient bandwidth")
		return false, oops.Errorf("hop %d: insufficient bandwidth", hopIndex)

	case TunnelBuildReplyInvalid:
		log.WithField("hop_index", hopIndex).Warn("Variable tunnel hop received invalid request data")
		return false, oops.Errorf("hop %d: invalid request data", hopIndex)

	case TunnelBuildReplyExpired:
		log.WithField("hop_index", hopIndex).Warn("Variable tunnel hop request has expired")
		return false, oops.Errorf("hop %d: request expired", hopIndex)

	default:
		log.WithFields(logger.Fields{
			"hop_index":  hopIndex,
			"reply_code": record.Reply,
		}).Warn("Variable tunnel hop returned unknown reply code")
		return false, oops.Errorf("hop %d: unknown reply code %d", hopIndex, record.Reply)
	}
}

// validateResponseRecord delegates to the shared validateBuildResponseRecord helper.
func (v *VariableTunnelBuildReply) validateResponseRecord(record BuildResponseRecord) error {
	return validateBuildResponseRecord(record)
}

// Compile-time interface satisfaction check
var _ TunnelReplyHandler = (*VariableTunnelBuildReply)(nil)
