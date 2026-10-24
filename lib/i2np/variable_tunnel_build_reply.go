package i2np

import (
	"github.com/go-i2p/logger"
)

/*
I2P I2NP VariableTunnelBuildReply
https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/i2np.rst
Accurate for version 0.9.28

+----+----+----+----+----+----+----+----+
| num| BuildResponseRecords...
+----+----+----+----+----+----+----+----+

Same format as VariableTunnelBuildMessage, with BuildResponseRecords.
*/

// VariableTunnelBuildReply represents an I2NP VariableTunnelBuildReply
// message containing a variable number (1-8) of build response records,
// the reply counterpart to VariableTunnelBuild. It is used to process
// replies for variable-length tunnels.
// See [I2P Spec: I2NP](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/i2np.rst) for the wire format.
// See also [VariableTunnelBuild].
type VariableTunnelBuildReply struct {
	Count                int
	BuildResponseRecords []BuildResponseRecord
	RawRecordData        [][]byte // Original encrypted bytes before parsing
}

// GetReplyRecords returns the parsed build response records. It satisfies
// the TunnelReplyHandler interface so the reply processor can handle
// variable-length and standard build replies uniformly.
// See also [TunnelReplyHandler].
func (v *VariableTunnelBuildReply) GetReplyRecords() []BuildResponseRecord {
	return v.BuildResponseRecords
}

// GetRawReplyRecords returns the original encrypted record bytes as they
// appeared on the wire, before parsing. Useful for debugging and for
// re-decryption attempts when parsing fails.
func (v *VariableTunnelBuildReply) GetRawReplyRecords() [][]byte {
	return v.RawRecordData
}

// ProcessReply processes the variable tunnel build reply by analyzing each response record.
// Handles variable-length tunnels (1-8 hops).
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
// Delegates to shared ValidateRecordCount helper.
func (v *VariableTunnelBuildReply) validateRecordCount(recordCount int) error {
	return ValidateRecordCount(v.Count, recordCount, "VariableTunnelBuildReply")
}

// processAllHops processes each hop response and counts successes.
// Returns the success count and the first error encountered (if any).
func (v *VariableTunnelBuildReply) processAllHops() (int, error) {
	return processAllRecordsAsHops(v.BuildResponseRecords, v.processHopResponse)
}

// logReplyCompletion logs the final processing results with success rate.
func (v *VariableTunnelBuildReply) logReplyCompletion(successCount, recordCount int) {
	fields := logger.Fields{
		"success_count": successCount,
		"total_hops":    recordCount,
	}
	if recordCount > 0 {
		fields["success_rate"] = float64(successCount) / float64(recordCount)
	}
	log.WithFields(fields).Debug("VariableTunnelBuildReply processing completed")
}

// determineBuildResult determines the final result based on success count.
// Returns nil if all hops accepted, otherwise returns an appropriate error.
// Delegates to shared DetermineBuildResult helper.
func (v *VariableTunnelBuildReply) determineBuildResult(successCount, recordCount int, firstError error) error {
	return DetermineBuildResult(successCount, recordCount, firstError, "variable tunnel")
}

// processHopResponse processes a single hop's response record for variable tunnels.
// Returns (success, error) where success indicates if the hop accepted the tunnel.
func (v *VariableTunnelBuildReply) processHopResponse(hopIndex int, record BuildResponseRecord) (bool, error) {
	return processValidatedHopResponseRecord(hopIndex, record, "Variable tunnel ")
}

// Compile-time interface satisfaction check
var _ TunnelReplyHandler = (*VariableTunnelBuildReply)(nil)
