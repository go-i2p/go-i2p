package i2np

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

/*
I2P I2NP TunnelBuildReply
https://geti2p.net/spec/i2np
Accurate for version 0.9.28

Same format as TunnelBuildMessage, with BuildResponseRecords
*/

// TunnelBuildReply constants for processing responses
const (
	TunnelBuildReplySuccess   = 0x00 // Tunnel hop accepted the request
	TunnelBuildReplyReject    = 0x01 // General rejection
	TunnelBuildReplyOverload  = 0x02 // Router is overloaded
	TunnelBuildReplyBandwidth = 0x03 // Insufficient bandwidth
	TunnelBuildReplyInvalid   = 0x04 // Invalid request data
	TunnelBuildReplyExpired   = 0x05 // Request has expired
)

// TunnelBuildReply represents an I2NP TunnelBuildReply message containing exactly 8 build response records indicating the success or failure of a tunnel build request.
//
// NOTE (0.2.0 consolidation opportunity):
// This type shares GetReplyRecords() and GetRawReplyRecords() accessors with
// VariableTunnelBuildReply, differing only in backing storage ([8]array vs []slice).
// See tunnel_build.go for the full context on consolidating fixed/variable accessors
// into a generic recordSet[T] type.
type TunnelBuildReply struct {
	Records       [8]BuildResponseRecord
	RawRecordData [][]byte // Original encrypted bytes before parsing
}

// GetReplyRecords returns the build response records
func (t *TunnelBuildReply) GetReplyRecords() []BuildResponseRecord {
	return t.Records[:]
}

// GetRawReplyRecords returns the original encrypted record bytes.
func (t *TunnelBuildReply) GetRawReplyRecords() [][]byte {
	return t.RawRecordData
}

// ProcessReply processes the tunnel build reply by analyzing each response record.
// It validates response integrity, determines tunnel build success/failure,
// and returns detailed results for each hop.
// Implements replyStepProcessor interface for unified reply processing.
func (t *TunnelBuildReply) ProcessReply() error {
	return processReplySteps(t, t.GetReplyRecords())
}

// logReplyStart logs the start of tunnel build reply processing.
// Implements replyStepProcessor interface.
func (t *TunnelBuildReply) logReplyStart(recordCount int) {
	log.WithField("record_count", recordCount).Debug("Processing TunnelBuildReply")
}

// validateRecordCount validates that the record count is exactly 8 for fixed tunnels.
// Implements replyStepProcessor interface.
func (t *TunnelBuildReply) validateRecordCount(recordCount int) error {
	if recordCount != 8 {
		log.WithField("record_count", recordCount).Warn("TunnelBuildReply has unexpected record count (expected 8)")
		return oops.Errorf("tunnel build failed: expected 8 records but got %d", recordCount)
	}
	return nil
}

// processAllHops processes each hop's response record.
// Implements replyStepProcessor interface.
// Returns the success count and the first error encountered (if any).
func (t *TunnelBuildReply) processAllHops() (int, error) {
	successCount := 0
	var firstError error

	for i, record := range t.Records {
		success, err := t.processHopResponse(i, record)
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

// logReplyCompletion logs the completion of tunnel build reply processing.
// Implements replyStepProcessor interface.
func (t *TunnelBuildReply) logReplyCompletion(successCount, recordCount int) {
	log.WithFields(logger.Fields{
		"success_count": successCount,
		"total_hops":    recordCount,
		"success_rate":  float64(successCount) / float64(recordCount),
	}).Info("TunnelBuildReply processing completed")
}

// determineBuildResult determines the final result based on success count.
// Implements replyStepProcessor interface.
// Returns nil if all hops accepted, otherwise returns an appropriate error.
// L-1 Consolidation: Delegates to shared DetermineBuildResult helper.
func (t *TunnelBuildReply) determineBuildResult(successCount, recordCount int, firstError error) error {
	return DetermineBuildResult(successCount, recordCount, firstError, "tunnel")
}

// processHopResponse processes a single hop's response record.
// Returns (success, error) where success indicates if the hop accepted the tunnel.
func (t *TunnelBuildReply) processHopResponse(hopIndex int, record BuildResponseRecord) (bool, error) {
	// Validate response record (basic integrity check)
	if err := t.validateResponseRecord(record); err != nil {
		return false, oops.Wrapf(err, "hop %d: invalid response record", hopIndex)
	}

	// Process reply code using shared helper
	return processHopReplyCode(hopIndex, record.Reply, "")
}

// validateResponseRecord delegates to the shared ValidateBuildResponseRecord helper.
func (t *TunnelBuildReply) validateResponseRecord(record BuildResponseRecord) error {
	return ValidateBuildResponseRecord(record)
}

// Compile-time interface satisfaction check
var _ TunnelReplyHandler = (*TunnelBuildReply)(nil)
