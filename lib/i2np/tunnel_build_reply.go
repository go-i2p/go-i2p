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
func (t *TunnelBuildReply) ProcessReply() error {
	t.logProcessingStart()

	successCount, firstError := t.processAllHopResponses()

	t.logProcessingComplete(successCount)

	return t.determineTunnelBuildResult(successCount, firstError)
}

// logProcessingStart logs the start of tunnel build reply processing.
func (t *TunnelBuildReply) logProcessingStart() {
	log.WithField("record_count", len(t.Records)).Debug("Processing TunnelBuildReply")
}

// processAllHopResponses processes each hop's response record.
// Returns the success count and the first error encountered (if any).
func (t *TunnelBuildReply) processAllHopResponses() (int, error) {
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

// logProcessingComplete logs the completion of tunnel build reply processing.
func (t *TunnelBuildReply) logProcessingComplete(successCount int) {
	log.WithFields(logger.Fields{
		"success_count": successCount,
		"total_hops":    len(t.Records),
		"success_rate":  float64(successCount) / float64(len(t.Records)),
	}).Info("TunnelBuildReply processing completed")
}

// determineTunnelBuildResult determines the final result based on success count.
// Returns nil if all hops accepted, otherwise returns an appropriate error.
func (t *TunnelBuildReply) determineTunnelBuildResult(successCount int, firstError error) error {
	if successCount == len(t.Records) {
		log.WithFields(logger.Fields{"at": "determineTunnelBuildResult"}).Debug("Tunnel build successful - all hops accepted")
		return nil
	}

	if firstError != nil {
		return oops.Wrapf(firstError, "tunnel build failed")
	}

	return oops.Errorf("tunnel build failed: only %d of %d hops accepted", successCount, len(t.Records))
}

// processHopResponse processes a single hop's response record.
// Returns (success, error) where success indicates if the hop accepted the tunnel.
func (t *TunnelBuildReply) processHopResponse(hopIndex int, record BuildResponseRecord) (bool, error) {
	log.WithFields(logger.Fields{
		"hop_index":  hopIndex,
		"reply_code": record.Reply,
	}).Debug("Processing hop response")

	// Validate response record (basic integrity check)
	if err := t.validateResponseRecord(record); err != nil {
		return false, oops.Wrapf(err, "hop %d: invalid response record", hopIndex)
	}

	// Process reply code
	switch record.Reply {
	case TunnelBuildReplySuccess:
		log.WithField("hop_index", hopIndex).Debug("Hop accepted tunnel build request")
		return true, nil

	case TunnelBuildReplyReject:
		log.WithField("hop_index", hopIndex).Warn("Hop rejected tunnel build request")
		return false, oops.Errorf("hop %d: rejected request", hopIndex)

	case TunnelBuildReplyOverload:
		log.WithField("hop_index", hopIndex).Warn("Hop is overloaded")
		return false, oops.Errorf("hop %d: router overloaded", hopIndex)

	case TunnelBuildReplyBandwidth:
		log.WithField("hop_index", hopIndex).Warn("Hop has insufficient bandwidth")
		return false, oops.Errorf("hop %d: insufficient bandwidth", hopIndex)

	case TunnelBuildReplyInvalid:
		log.WithField("hop_index", hopIndex).Warn("Hop received invalid request data")
		return false, oops.Errorf("hop %d: invalid request data", hopIndex)

	case TunnelBuildReplyExpired:
		log.WithField("hop_index", hopIndex).Warn("Hop request has expired")
		return false, oops.Errorf("hop %d: request expired", hopIndex)

	default:
		log.WithFields(logger.Fields{
			"hop_index":  hopIndex,
			"reply_code": record.Reply,
		}).Warn("Hop returned unknown reply code")
		return false, oops.Errorf("hop %d: unknown reply code %d", hopIndex, record.Reply)
	}
}

// validateResponseRecord delegates to the shared validateBuildResponseRecord helper.
func (t *TunnelBuildReply) validateResponseRecord(record BuildResponseRecord) error {
	return validateBuildResponseRecord(record)
}

// Compile-time interface satisfaction check
var _ TunnelReplyHandler = (*TunnelBuildReply)(nil)
