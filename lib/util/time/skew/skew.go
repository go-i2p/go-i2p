package skew

import (
	"fmt"
	"time"
)

// MaxClockSkew is the maximum acceptable difference between a RouterInfo's
// published timestamp and the current time. Per the I2P specification
// (common-structures RouterInfo notes), routers MUST reject RouterInfo with
// a published timestamp more than 60 minutes in the future or past.
const MaxClockSkew = 60 * time.Minute

// nowFunc is overridable for testing. Defaults to time.Now.
var nowFunc = time.Now

// ValidateTimestamp checks whether the given timestamp is within the acceptable
// clock skew window (±MaxClockSkew from the current time). It returns nil if
// the timestamp is valid, or a descriptive error if it falls outside the window.
//
// A zero-value time.Time is always rejected as invalid.
//
// This implements the I2P spec requirement: "Router MUST reject RouterInfo with
// published timestamp >60 minutes in the future or past."
func ValidateTimestamp(published time.Time) error {
	if published.IsZero() {
		return fmt.Errorf("clock skew: published timestamp is zero")
	}

	now := nowFunc()
	skew := now.Sub(published)

	if skew > MaxClockSkew {
		log.WithFields(map[string]interface{}{
			"published": published.UTC().Format(time.RFC3339),
			"now":       now.UTC().Format(time.RFC3339),
			"skew":      skew.String(),
			"max":       MaxClockSkew.String(),
		}).Warn("Rejecting RouterInfo: published timestamp too far in the past")
		return fmt.Errorf("clock skew: timestamp is %s in the past (max %s)", skew, MaxClockSkew)
	}

	if skew < -MaxClockSkew {
		log.WithFields(map[string]interface{}{
			"published": published.UTC().Format(time.RFC3339),
			"now":       now.UTC().Format(time.RFC3339),
			"skew":      (-skew).String(),
			"max":       MaxClockSkew.String(),
		}).Warn("Rejecting RouterInfo: published timestamp too far in the future")
		return fmt.Errorf("clock skew: timestamp is %s in the future (max %s)", -skew, MaxClockSkew)
	}

	return nil
}

// IsTimestampValid is a convenience wrapper around ValidateTimestamp that returns
// a boolean instead of an error. It returns true if the timestamp is within
// the acceptable clock skew window.
func IsTimestampValid(published time.Time) bool {
	return ValidateTimestamp(published) == nil
}

// ValidateTimestampWithSkew checks whether the given timestamp is within a
// custom clock skew window. This is useful for subsystems that need different
// tolerances (e.g., NTCP2 handshake uses ±2 minutes).
//
// A zero-value time.Time is always rejected. A non-positive maxSkew is rejected
// with an error.
func ValidateTimestampWithSkew(published time.Time, maxSkew time.Duration) error {
	if maxSkew <= 0 {
		return fmt.Errorf("clock skew: maxSkew must be positive, got %s", maxSkew)
	}
	if published.IsZero() {
		return fmt.Errorf("clock skew: published timestamp is zero")
	}

	now := nowFunc()
	skew := now.Sub(published)

	if skew > maxSkew {
		return fmt.Errorf("clock skew: timestamp is %s in the past (max %s)", skew, maxSkew)
	}
	if skew < -maxSkew {
		return fmt.Errorf("clock skew: timestamp is %s in the future (max %s)", -skew, maxSkew)
	}

	return nil
}
