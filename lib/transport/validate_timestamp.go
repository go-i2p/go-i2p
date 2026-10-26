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

// RoundUnixSeconds converts a time to a Unix timestamp in whole seconds,
// rounded to the nearest second rather than truncated.
//
// ntcp2.rst:1491 and ssu2.rst:2836 both state "Implementations must round to
// the nearest second to prevent clock bias in the network." Truncating with
// uint32(t.Unix()) always discards the sub-second remainder, so every
// timestamp we emit is biased up to one full second into the past. Peers
// measuring skew against those timestamps inherit that bias, which pushes
// legitimate connections toward the edge of the tolerance window.
func RoundUnixSeconds(t time.Time) uint32 {
	// time.Time.Round half-up to the nearest second, then take the epoch
	// seconds. Round() operates on absolute time, so the result is the
	// nearest whole second on both sides of the epoch.
	return uint32(t.Round(time.Second).Unix())
}

// CalculateTimestampSkew returns the observed clock skew (in seconds) between
// a peer's timestamp and the local time. Positive skew means the peer's clock
// is ahead of ours. This can be used for diagnostic logging and validation.
func CalculateTimestampSkew(peerTime, localTime uint32) int64 {
	return int64(peerTime) - int64(localTime)
}

// IsTimestampWithinTolerance returns true if the absolute skew between peerTime
// and the current local time is within the specified tolerance.
//
// A peerTime of 0 is rejected. Both transports require a timestamp on the
// messages they carry: ssu2.rst:4036-4039 says Token Request, Retry, Session
// Request, Session Created, Hole Punch and out-of-session Peer Test messages
// "must contain DateTime blocks", and ntcp2.rst:547-550 / :879-882 require each
// party to "reject connections where the timestamp value is too far off from the
// current time". A missing or zero timestamp is a violation of that MUST, not an
// absent optional field, and treating it as "not provided" would let an attacker
// zero the field on a captured handshake to skip skew and replay protection.
// This matches the explicit zero rejection in ntcp2.ValidateTimestamp and
// ssu2 DefaultHandler.ValidateTimestamp.
func IsTimestampWithinTolerance(peerTime uint32, tolerance time.Duration) bool {
	if peerTime == 0 {
		// Required timestamp missing — reject.
		return false
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

// ValidateTimestampAndLog runs a caller-provided timestamp validator and
// invokes logFailure when validation fails.
func ValidateTimestampAndLog(peerTime uint32, validate func(uint32) error, logFailure func(uint32, error)) error {
	err := validate(peerTime)
	if err == nil {
		return nil
	}
	if logFailure != nil {
		logFailure(peerTime, err)
	}
	return err
}
