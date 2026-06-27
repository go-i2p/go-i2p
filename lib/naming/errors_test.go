package naming

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSentinelErrorsAreNonNull verifies that sentinel errors are properly
// defined and not empty strings.
func TestSentinelErrorsAreNonNull(t *testing.T) {
	assert.NotNil(t, ErrHostnameNotFound)
	assert.NotNil(t, ErrEmptyHostname)
	assert.NotNil(t, ErrInvalidB32Length)
	assert.NotNil(t, ErrResolverNotInitialized)
	assert.NotNil(t, ErrInvalidBase64Destination)

	assert.NotEmpty(t, ErrHostnameNotFound.Error())
	assert.NotEmpty(t, ErrEmptyHostname.Error())
	assert.NotEmpty(t, ErrInvalidB32Length.Error())
	assert.NotEmpty(t, ErrResolverNotInitialized.Error())
	assert.NotEmpty(t, ErrInvalidBase64Destination.Error())
}

// TestAddressConstantsAreCorrect verifies that B32 address constants
// match the I2P specification.
func TestAddressConstantsAreCorrect(t *testing.T) {
	assert.Equal(t, 52, B32AddressLength, "256 bits in base32 = 52 chars")
	assert.Equal(t, 32, B32HashSize, "SHA-256 produces 32 bytes")
}

// TestDefaultFetchTimeoutIsPositive verifies the fetch timeout is reasonable.
func TestDefaultFetchTimeoutIsPositive(t *testing.T) {
	assert.Positive(t, DefaultFetchTimeout)
}
