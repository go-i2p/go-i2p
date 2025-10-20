package i2np

import (
	"fmt"

	"github.com/sirupsen/logrus"
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

	log.WithFields(logrus.Fields{
		"record_count": recordCount,
		"count_field":  v.Count,
	}).Debug("Processing VariableTunnelBuildReply")

	// Validate that Count field matches actual record count
	if v.Count != recordCount {
		return fmt.Errorf("count mismatch: Count field is %d but have %d records", v.Count, recordCount)
	}

	// Handle empty tunnel (edge case)
	if recordCount == 0 {
		log.Warn("VariableTunnelBuildReply has no response records")
		return fmt.Errorf("tunnel build failed: no response records")
	}

	successCount := 0
	var firstError error

	for i, record := range v.BuildResponseRecords {
		success, err := v.processHopResponse(i, record)
		if err != nil {
			log.WithFields(logrus.Fields{
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

	log.WithFields(logrus.Fields{
		"success_count": successCount,
		"total_hops":    recordCount,
		"success_rate":  float64(successCount) / float64(recordCount),
	}).Info("VariableTunnelBuildReply processing completed")

	// Tunnel is considered successful if all hops accepted
	if successCount == recordCount {
		log.Debug("Variable tunnel build successful - all hops accepted")
		return nil
	}

	// Return first error encountered, or generic failure if no specific error
	if firstError != nil {
		return fmt.Errorf("variable tunnel build failed: %w", firstError)
	}

	return fmt.Errorf("variable tunnel build failed: only %d of %d hops accepted", successCount, recordCount)
}

// processHopResponse processes a single hop's response record for variable tunnels.
// Returns (success, error) where success indicates if the hop accepted the tunnel.
func (v *VariableTunnelBuildReply) processHopResponse(hopIndex int, record BuildResponseRecord) (bool, error) {
	log.WithFields(logrus.Fields{
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
		log.WithFields(logrus.Fields{
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

	// TODO: In a full implementation, we would verify the SHA-256 hash
	// hash should be SHA256(random_data + reply_byte)
	// This requires implementing the cryptographic verification

	log.Debug("Variable tunnel response record validation passed")
	return nil
}

// Compile-time interface satisfaction check
var _ TunnelReplyHandler = (*VariableTunnelBuildReply)(nil)
