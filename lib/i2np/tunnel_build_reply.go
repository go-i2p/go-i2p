package i2np

import (
	"crypto/sha256"
	"fmt"

	"github.com/go-i2p/logger"
)

/*
I2P I2NP TunnelBuildReply
https://geti2p.net/spec/i2np
Accurate for version 0.9.28

Same format as TunnelBuildMessage, with BuildResponseRecords
*/

// TunnelBuildReply constants for processing responses
const (
	TUNNEL_BUILD_REPLY_SUCCESS   = 0x00 // Tunnel hop accepted the request
	TUNNEL_BUILD_REPLY_REJECT    = 0x01 // General rejection
	TUNNEL_BUILD_REPLY_OVERLOAD  = 0x02 // Router is overloaded
	TUNNEL_BUILD_REPLY_BANDWIDTH = 0x03 // Insufficient bandwidth
	TUNNEL_BUILD_REPLY_INVALID   = 0x04 // Invalid request data
	TUNNEL_BUILD_REPLY_EXPIRED   = 0x05 // Request has expired
)

type TunnelBuildReply [8]BuildResponseRecord

// GetReplyRecords returns the build response records
func (t *TunnelBuildReply) GetReplyRecords() []BuildResponseRecord {
	return t[:]
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
	log.WithField("record_count", len(t)).Debug("Processing TunnelBuildReply")
}

// processAllHopResponses processes each hop's response record.
// Returns the success count and the first error encountered (if any).
func (t *TunnelBuildReply) processAllHopResponses() (int, error) {
	successCount := 0
	var firstError error

	for i, record := range t {
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
		"total_hops":    len(t),
		"success_rate":  float64(successCount) / float64(len(t)),
	}).Info("TunnelBuildReply processing completed")
}

// determineTunnelBuildResult determines the final result based on success count.
// Returns nil if all hops accepted, otherwise returns an appropriate error.
func (t *TunnelBuildReply) determineTunnelBuildResult(successCount int, firstError error) error {
	if successCount == len(t) {
		log.Debug("Tunnel build successful - all hops accepted")
		return nil
	}

	if firstError != nil {
		return fmt.Errorf("tunnel build failed: %w", firstError)
	}

	return fmt.Errorf("tunnel build failed: only %d of %d hops accepted", successCount, len(t))
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
		return false, fmt.Errorf("hop %d: invalid response record: %w", hopIndex, err)
	}

	// Process reply code
	switch record.Reply {
	case TUNNEL_BUILD_REPLY_SUCCESS:
		log.WithField("hop_index", hopIndex).Debug("Hop accepted tunnel build request")
		return true, nil

	case TUNNEL_BUILD_REPLY_REJECT:
		log.WithField("hop_index", hopIndex).Warn("Hop rejected tunnel build request")
		return false, fmt.Errorf("hop %d: rejected request", hopIndex)

	case TUNNEL_BUILD_REPLY_OVERLOAD:
		log.WithField("hop_index", hopIndex).Warn("Hop is overloaded")
		return false, fmt.Errorf("hop %d: router overloaded", hopIndex)

	case TUNNEL_BUILD_REPLY_BANDWIDTH:
		log.WithField("hop_index", hopIndex).Warn("Hop has insufficient bandwidth")
		return false, fmt.Errorf("hop %d: insufficient bandwidth", hopIndex)

	case TUNNEL_BUILD_REPLY_INVALID:
		log.WithField("hop_index", hopIndex).Warn("Hop received invalid request data")
		return false, fmt.Errorf("hop %d: invalid request data", hopIndex)

	case TUNNEL_BUILD_REPLY_EXPIRED:
		log.WithField("hop_index", hopIndex).Warn("Hop request has expired")
		return false, fmt.Errorf("hop %d: request expired", hopIndex)

	default:
		log.WithFields(logger.Fields{
			"hop_index":  hopIndex,
			"reply_code": record.Reply,
		}).Warn("Hop returned unknown reply code")
		return false, fmt.Errorf("hop %d: unknown reply code %d", hopIndex, record.Reply)
	}
}

// validateResponseRecord performs basic validation of a build response record.
// This checks that the record structure is valid but does not verify cryptographic integrity.
func (t *TunnelBuildReply) validateResponseRecord(record BuildResponseRecord) error {
	// Check if hash is all zeros (likely indicates an empty/invalid record)
	allZeros := true
	for _, b := range record.Hash {
		if b != 0 {
			allZeros = false
			break
		}
	}

	if allZeros {
		return fmt.Errorf("response record has empty hash")
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
		}).Warn("Response record hash mismatch")
		return fmt.Errorf("response record hash verification failed")
	}

	log.Debug("Response record validation passed")
	return nil
}

// Compile-time interface satisfaction check
var _ TunnelReplyHandler = (*TunnelBuildReply)(nil)
