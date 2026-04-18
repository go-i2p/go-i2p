package ntcp2

import (
	"fmt"
	"math"
	"time"

	gonoise "github.com/go-i2p/go-noise/ntcp2"
)

// ClockSkewTolerance is the maximum allowed difference between local and
// peer timestamps. Per the NTCP2 spec, connections with a clock skew
// exceeding this value should be terminated with reason code 6.
//
// We intentionally use 30 s (half the go-noise default of 60 s) to narrow the
// post-restart replay window: a captured handshake msg1 is only replayable for
// up to 30 s rather than 60 s after a router restart that flushes the in-memory
// replay cache. This is a security trade-off; operators with loose NTP discipline
// should consider tightening NTP synchronisation rather than widening this value.
const ClockSkewTolerance = 30 * time.Second

// _ ensures the upstream constant is still importable to catch future changes.
var _ = gonoise.ClockSkewTolerance

// ClockSkewError is returned when a peer's timestamp exceeds the allowed skew.
type ClockSkewError struct {
	// PeerTime is the peer's reported Unix timestamp.
	PeerTime uint32
	// LocalTime is the local Unix timestamp at the time of validation.
	LocalTime uint32
	// Skew is the observed clock difference (peer - local).
	Skew time.Duration
}

// Error returns a human-readable description of the clock skew violation, including the peer and local timestamps, observed skew, and tolerance.
func (e *ClockSkewError) Error() string {
	return fmt.Sprintf("clock skew too large: peer=%d, local=%d, skew=%v (tolerance=%v)",
		e.PeerTime, e.LocalTime, e.Skew, ClockSkewTolerance)
}

// ValidateTimestamp checks whether a peer's timestamp is within the allowed
// clock skew tolerance relative to the current time.
//
// Returns nil if the timestamp is acceptable, or a *ClockSkewError if the
// skew exceeds ClockSkewTolerance.
//
// A peerTime of 0 is treated as "timestamp not provided" and is accepted
// without validation, since some peers may not include timestamps during
// early protocol negotiation.
func ValidateTimestamp(peerTime uint32) error {
	if peerTime == 0 {
		// Timestamp not provided — skip validation.
		return nil
	}

	localTime := uint32(time.Now().Unix())
	skewSeconds, skew := measureSkew(peerTime, localTime)
	if isClockSkewWithinTolerance(skewSeconds) {
		return nil
	}
	return &ClockSkewError{
		PeerTime:  peerTime,
		LocalTime: localTime,
		Skew:      skew,
	}
}

func measureSkew(peerTime, localTime uint32) (int64, time.Duration) {
	skewSeconds := int64(peerTime) - int64(localTime)
	return skewSeconds, time.Duration(skewSeconds) * time.Second
}

func isClockSkewWithinTolerance(skewSeconds int64) bool {
	return math.Abs(float64(skewSeconds)) <= ClockSkewTolerance.Seconds()
}

// MeasureClockSkew returns the observed clock skew between a peer's timestamp
// and the local time. Positive skew means the peer's clock is ahead of ours.
// This can be used for diagnostic logging without enforcing the tolerance.
func MeasureClockSkew(peerTime uint32) time.Duration {
	if peerTime == 0 {
		return 0
	}
	localTime := uint32(time.Now().Unix())
	return time.Duration(int64(peerTime)-int64(localTime)) * time.Second
}
