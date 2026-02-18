package ntcp2

import (
	"fmt"
	"math"
	"time"
)

// Clock skew constants per the NTCP2 specification.
//
// Spec reference: https://geti2p.net/spec/ntcp2#timestamps
//
// Both peers exchange timestamps during the handshake (message 1 from Alice,
// message 2 from Bob). Each side must validate that the peer's clock is within
// an acceptable skew tolerance.
const (
	// ClockSkewTolerance is the maximum allowed difference between local and
	// peer timestamps. Per the NTCP2 spec, connections with a clock skew
	// exceeding this value should be terminated with reason code 6.
	ClockSkewTolerance = 60 * time.Second
)

// ClockSkewError is returned when a peer's timestamp exceeds the allowed skew.
type ClockSkewError struct {
	// PeerTime is the peer's reported Unix timestamp.
	PeerTime uint32
	// LocalTime is the local Unix timestamp at the time of validation.
	LocalTime uint32
	// Skew is the observed clock difference (peer - local).
	Skew time.Duration
}

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
	skewSeconds := int64(peerTime) - int64(localTime)
	skew := time.Duration(skewSeconds) * time.Second

	if math.Abs(float64(skewSeconds)) > ClockSkewTolerance.Seconds() {
		return &ClockSkewError{
			PeerTime:  peerTime,
			LocalTime: localTime,
			Skew:      skew,
		}
	}

	return nil
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
