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
	// 30 seconds off — well within the 60s tolerance
	peerTime := uint32(time.Now().Unix()) + 30
	assert.NoError(t, ValidateTimestamp(peerTime))

	peerTime = uint32(time.Now().Unix()) - 30
	assert.NoError(t, ValidateTimestamp(peerTime))
}

func TestValidateTimestamp_ExceedsTolerance(t *testing.T) {
	// 120 seconds ahead — exceeds 60s tolerance
	peerTime := uint32(time.Now().Unix()) + 120
	err := ValidateTimestamp(peerTime)
	assert.Error(t, err)
	assert.IsType(t, &ClockSkewError{}, err)
}

func TestValidateTimestamp_FarBehind(t *testing.T) {
	// 120 seconds behind — exceeds 60s tolerance
	peerTime := uint32(time.Now().Unix()) - 120
	err := ValidateTimestamp(peerTime)
	assert.Error(t, err)
}

func TestValidateTimestamp_Zero(t *testing.T) {
	// Zero means "not provided" — should be accepted
	assert.NoError(t, ValidateTimestamp(0))
}

func TestValidateTimestamp_BoundaryValues(t *testing.T) {
	now := uint32(time.Now().Unix())

	// Exactly at +60 seconds — should be within tolerance
	assert.NoError(t, ValidateTimestamp(now+60))

	// Exactly at -60 seconds — should be within tolerance
	assert.NoError(t, ValidateTimestamp(now-60))

	// 61 seconds off — just over the boundary
	err := ValidateTimestamp(now + 61)
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
