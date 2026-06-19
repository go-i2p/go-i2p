package i2np

import (
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

// VariableTunnelBuildReply represents an I2NP VariableTunnelBuildReply message containing a variable number of build response records.
//
// NOTE (0.2.0 consolidation opportunity):
// This type shares GetReplyRecords() and GetRawReplyRecords() accessors with
// TunnelBuildReply, differing only in backing storage ([8]array vs []slice).
// See tunnel_build.go for the full context on consolidating fixed/variable accessors
// into a generic recordSet[T] type.
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
// L-4 Consolidation: Delegates to shared ValidateRecordCount helper.
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
	log.WithFields(fields).Info("VariableTunnelBuildReply processing completed")
}

// determineBuildResult determines the final result based on success count.
// Returns nil if all hops accepted, otherwise returns an appropriate error.
// L-1 Consolidation: Delegates to shared DetermineBuildResult helper.
func (v *VariableTunnelBuildReply) determineBuildResult(successCount, recordCount int, firstError error) error {
	return DetermineBuildResult(successCount, recordCount, firstError, "variable tunnel")
}

// processHopResponse processes a single hop's response record for variable tunnels.
// Returns (success, error) where success indicates if the hop accepted the tunnel.
func (v *VariableTunnelBuildReply) processHopResponse(hopIndex int, record BuildResponseRecord) (bool, error) {
	return processValidatedHopResponseRecord(hopIndex, record, "Variable tunnel ")
}

// validateResponseRecord delegates to the shared ValidateBuildResponseRecord helper.
func (v *VariableTunnelBuildReply) validateResponseRecord(record BuildResponseRecord) error {
	return ValidateBuildResponseRecord(record)
}

// Compile-time interface satisfaction check
var _ TunnelReplyHandler = (*VariableTunnelBuildReply)(nil)
