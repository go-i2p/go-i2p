package i2np

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// processAllRecordsAsHops processes each response record and counts successful hops.
// It returns the total successes and the first error encountered, if any.
func processAllRecordsAsHops(records []BuildResponseRecord, processHop func(int, BuildResponseRecord) (bool, error)) (int, error) {
	successCount := 0
	var firstError error

	for i, record := range records {
		success, err := processHop(i, record)
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

// processValidatedHopResponseRecord validates a response record and processes its reply
// code.  It is the shared core of TunnelBuildReply.processHopResponse and
// VariableTunnelBuildReply.processHopResponse; only the log prefix differs.
func processValidatedHopResponseRecord(hopIndex int, record BuildResponseRecord, logPrefix string) (bool, error) {
	if err := ValidateBuildResponseRecord(record); err != nil {
		return false, oops.Wrapf(err, "hop %d: invalid response record", hopIndex)
	}
	return processHopReplyCode(hopIndex, record.Reply, logPrefix)
}
