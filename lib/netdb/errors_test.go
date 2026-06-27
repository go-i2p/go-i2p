package netdb

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSentinelErrorsAreNonNull verifies that sentinel errors are properly
// defined and not empty strings.
func TestSentinelErrorsAreNonNull(t *testing.T) {
	assert.NotNil(t, ErrNoPeerData)
	assert.NotNil(t, ErrInvalidPeerHash)
	assert.NotNil(t, ErrCorruptedProfiles)
	assert.NotNil(t, ErrNetDBNotInitialized)

	assert.NotEmpty(t, ErrNoPeerData.Error())
	assert.NotEmpty(t, ErrInvalidPeerHash.Error())
	assert.NotEmpty(t, ErrCorruptedProfiles.Error())
	assert.NotEmpty(t, ErrNetDBNotInitialized.Error())
}

// TestThresholdConstantsArePositive verifies that threshold constants
// have sensible values.
func TestThresholdConstantsArePositive(t *testing.T) {
	assert.Greater(t, LowSuccessRateThreshold, 0.0)
	assert.Less(t, LowSuccessRateThreshold, 1.0)
	assert.Greater(t, HighSuccessRateThreshold, 0.0)
	assert.Less(t, HighSuccessRateThreshold, 1.0)
	assert.Greater(t, MinAttemptsForStats, 0)
	assert.Greater(t, ConsecutiveFailThreshold, 0)
	assert.Greater(t, EMAAlpha, 0.0)
	assert.Less(t, EMAAlpha, 1.0)
	assert.Positive(t, StalenessCheckWindow)
}
