package transport

import (
	"math"
	"time"
)

// ClockSkewTolerance is the maximum allowed difference between local and
// peer timestamps for both NTCP2 and SSU2 protocols.
// Per the I2P specs, connections with clock skew exceeding this value
// should be terminated.
const ClockSkewTolerance = 60 * time.Second

// CalculateTimestampSkew returns the observed clock skew (in seconds) between
// a peer's timestamp and the local time. Positive skew means the peer's clock
// is ahead of ours. This can be used for diagnostic logging and validation.
func CalculateTimestampSkew(peerTime uint32, localTime uint32) int64 {
	return int64(peerTime) - int64(localTime)
}

// IsTimestampWithinTolerance returns true if the absolute skew between peerTime
// and the current local time is within the specified tolerance.
// A peerTime of 0 is treated as "timestamp not provided" and returns true
// (accepted without validation).
func IsTimestampWithinTolerance(peerTime uint32, tolerance time.Duration) bool {
	if peerTime == 0 {
		// Timestamp not provided — skip validation.
		return true
	}

	localTime := uint32(time.Now().Unix())
	skewSeconds := CalculateTimestampSkew(peerTime, localTime)
	return math.Abs(float64(skewSeconds)) <= tolerance.Seconds()
}

// MeasureTimestampSkewAgainstNow returns the observed clock skew (in seconds)
// between a peer's timestamp and the current local time. Positive skew means
// the peer's clock is ahead of ours.
func MeasureTimestampSkewAgainstNow(peerTime uint32) int64 {
	if peerTime == 0 {
		return 0
	}
	localTime := uint32(time.Now().Unix())
	return CalculateTimestampSkew(peerTime, localTime)
}
