package i2np

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReadI2NPSSUMessageExpiration_CorrectMillisecondConversion verifies that
// the SSU 4-byte seconds-since-epoch value is correctly converted to the
// Date type (which stores milliseconds since epoch).
func TestReadI2NPSSUMessageExpiration_CorrectMillisecondConversion(t *testing.T) {
	assert := assert.New(t)

	// Use a known epoch time: 2024-01-01 00:00:00 UTC = 1704067200 seconds
	var seconds uint32 = 1704067200
	data := make([]byte, 5)
	data[0] = 0x00 // type byte (ignored by the function but needed for offset)
	binary.BigEndian.PutUint32(data[1:5], seconds)

	date, err := ReadI2NPSSUMessageExpiration(data)
	assert.Nil(err)

	// The Date should represent 1704067200 * 1000 = 1704067200000 milliseconds
	resultTime := date.Time()
	expectedTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	// Allow 1 second of tolerance for rounding
	diff := resultTime.Sub(expectedTime)
	assert.True(diff >= 0 && diff < time.Second,
		"Expected time near %v, got %v (diff=%v)", expectedTime, resultTime, diff)
}

// TestReadI2NPSSUMessageExpiration_ZeroSeconds verifies that a zero timestamp
// produces a zero Date (Unix epoch).
func TestReadI2NPSSUMessageExpiration_ZeroSeconds(t *testing.T) {
	assert := assert.New(t)

	data := make([]byte, 5)
	// All zeros: type=0, seconds=0

	date, err := ReadI2NPSSUMessageExpiration(data)
	assert.Nil(err)

	resultTime := date.Time()
	// Zero milliseconds should yield Unix epoch
	assert.Equal(time.Unix(0, 0).UTC(), resultTime.UTC())
}

// TestReadI2NPSSUMessageExpiration_MaxUint32 verifies that the maximum
// 4-byte value (February 7, 2106) is handled without overflow.
func TestReadI2NPSSUMessageExpiration_MaxUint32(t *testing.T) {
	assert := assert.New(t)

	var seconds uint32 = 0xFFFFFFFF // 4294967295 seconds
	data := make([]byte, 5)
	data[0] = 0x00
	binary.BigEndian.PutUint32(data[1:5], seconds)

	date, err := ReadI2NPSSUMessageExpiration(data)
	assert.Nil(err)

	resultTime := date.Time()
	// 4294967295 seconds = February 7, 2106 06:28:15 UTC
	// The multiplication by 1000 should not overflow uint64
	expectedSeconds := int64(4294967295)
	expectedTime := time.Unix(expectedSeconds, 0)

	diff := resultTime.Sub(expectedTime)
	assert.True(diff >= 0 && diff < time.Second,
		"Expected time near %v, got %v (diff=%v)", expectedTime, resultTime, diff)
}

// TestReadI2NPSSUMessageExpiration_NotEnoughData verifies the error case.
func TestReadI2NPSSUMessageExpiration_NotEnoughData(t *testing.T) {
	assert := assert.New(t)

	// Only 4 bytes, need at least 5
	data := make([]byte, 4)
	_, err := ReadI2NPSSUMessageExpiration(data)
	assert.Equal(ERR_I2NP_NOT_ENOUGH_DATA, err)

	// Empty data
	_, err = ReadI2NPSSUMessageExpiration([]byte{})
	assert.Equal(ERR_I2NP_NOT_ENOUGH_DATA, err)
}

// TestReadI2NPSSUMessageExpiration_KnownTimestamp verifies conversion with
// a timestamp that's easy to verify manually.
func TestReadI2NPSSUMessageExpiration_KnownTimestamp(t *testing.T) {
	assert := assert.New(t)

	// 1000 seconds since epoch = Jan 1 1970 00:16:40 UTC
	var seconds uint32 = 1000
	data := make([]byte, 5)
	data[0] = 0x00
	binary.BigEndian.PutUint32(data[1:5], seconds)

	date, err := ReadI2NPSSUMessageExpiration(data)
	assert.Nil(err)

	resultTime := date.Time()
	expectedTime := time.Unix(1000, 0)

	diff := resultTime.Sub(expectedTime)
	assert.True(diff >= 0 && diff < time.Second,
		"Expected time near %v, got %v (diff=%v)", expectedTime, resultTime, diff)
}

// TestReadI2NPSSUMessageExpiration_SSUHeaderIntegration tests the full
// SSU header parsing path to ensure expiration flows correctly.
func TestReadI2NPSSUMessageExpiration_SSUHeaderIntegration(t *testing.T) {
	require := require.New(t)

	// Build a valid SSU header: 1 byte type + 4 bytes expiration
	var seconds uint32 = 1704067200 // 2024-01-01 00:00:00 UTC
	data := make([]byte, 5)
	data[0] = 0x01 // type = 1 (DatabaseStore)
	binary.BigEndian.PutUint32(data[1:5], seconds)

	header, err := ReadI2NPSSUHeader(data)
	require.Nil(err)

	expectedTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	diff := header.Expiration.Sub(expectedTime)
	require.True(diff >= 0 && diff < time.Second,
		"Expected time near %v, got %v (diff=%v)", expectedTime, header.Expiration, diff)
}
