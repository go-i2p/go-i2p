package ntcp2

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestValidateTimestamp_WithinTolerance(t *testing.T) {
	// Current time should always be within tolerance
	now := uint32(time.Now().Unix())
	assert.NoError(t, ValidateTimestamp(now))
}

func TestValidateTimestamp_SlightlySkewed(t *testing.T) {
	// 10 seconds off — well within tolerance
	peerTime := uint32(time.Now().Unix()) + 10
	assert.NoError(t, ValidateTimestamp(peerTime))

	peerTime = uint32(time.Now().Unix()) - 10
	assert.NoError(t, ValidateTimestamp(peerTime))
}

func TestValidateTimestamp_ExceedsTolerance(t *testing.T) {
	peerTime := uint32(time.Now().Unix()) + uint32(ClockSkewTolerance.Seconds()+1)
	err := ValidateTimestamp(peerTime)
	assert.Error(t, err)
	assert.IsType(t, &ClockSkewError{}, err)
}

func TestValidateTimestamp_FarBehind(t *testing.T) {
	peerTime := uint32(time.Now().Unix()) - uint32(ClockSkewTolerance.Seconds()+1)
	err := ValidateTimestamp(peerTime)
	assert.Error(t, err)
}

func TestValidateTimestamp_Zero(t *testing.T) {
	// H3 FIX: Zero is now treated as invalid (per I2P spec, timestamps are required)
	// Previously zero was accepted as "not provided", but this enables replay attacks.
	err := ValidateTimestamp(0)
	assert.Error(t, err)
	assert.IsType(t, &ClockSkewError{}, err)
}

func TestValidateTimestamp_BoundaryValues(t *testing.T) {
	now := uint32(time.Now().Unix())
	within := uint32(ClockSkewTolerance.Seconds()) - 1
	beyond := uint32(ClockSkewTolerance.Seconds()) + 1

	// Just within positive skew tolerance.
	assert.NoError(t, ValidateTimestamp(now+within))

	// Just within negative skew tolerance.
	assert.NoError(t, ValidateTimestamp(now-within))

	// Just beyond tolerance should fail.
	err := ValidateTimestamp(now + beyond)
	assert.Error(t, err)
}

func TestMeasureClockSkew(t *testing.T) {
	now := uint32(time.Now().Unix())

	// Peer is 30 seconds ahead
	skew := MeasureClockSkew(now + 30)
	assert.InDelta(t, 30.0, skew.Seconds(), 1.0)

	// Peer is 30 seconds behind
	skew = MeasureClockSkew(now - 30)
	assert.InDelta(t, -30.0, skew.Seconds(), 1.0)

	// Zero means "not provided"
	assert.Equal(t, time.Duration(0), MeasureClockSkew(0))
}

func TestClockSkewError_Message(t *testing.T) {
	err := &ClockSkewError{
		PeerTime:  1000,
		LocalTime: 900,
		Skew:      100 * time.Second,
	}
	msg := err.Error()
	assert.Contains(t, msg, "clock skew too large")
	assert.Contains(t, msg, "peer=1000")
	assert.Contains(t, msg, "local=900")
}
