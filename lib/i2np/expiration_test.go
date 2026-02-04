package i2np

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// ExpirationValidator Tests
// =============================================================================

func TestNewExpirationValidator(t *testing.T) {
	v := NewExpirationValidator()

	assert.NotNil(t, v)
	assert.Equal(t, int64(DefaultExpirationTolerance), v.toleranceSeconds)
	assert.True(t, v.IsEnabled())
	assert.Nil(t, v.timeSource)
}

func TestExpirationValidator_WithTolerance(t *testing.T) {
	v := NewExpirationValidator()

	// Test method chaining
	result := v.WithTolerance(120)
	assert.Same(t, v, result)
	assert.Equal(t, int64(120), v.toleranceSeconds)

	// Test negative tolerance (should clamp to 0)
	v.WithTolerance(-10)
	assert.Equal(t, int64(0), v.toleranceSeconds)

	// Test zero tolerance
	v.WithTolerance(0)
	assert.Equal(t, int64(0), v.toleranceSeconds)
}

func TestExpirationValidator_WithTimeSource(t *testing.T) {
	v := NewExpirationValidator()
	fixedTime := time.Date(2026, 2, 4, 12, 0, 0, 0, time.UTC)

	result := v.WithTimeSource(func() time.Time { return fixedTime })
	assert.Same(t, v, result)
	assert.NotNil(t, v.timeSource)
	assert.Equal(t, fixedTime, v.now())
}

func TestExpirationValidator_EnableDisable(t *testing.T) {
	v := NewExpirationValidator()

	// Verify enabled by default
	assert.True(t, v.IsEnabled())

	// Test disable
	result := v.Disable()
	assert.Same(t, v, result)
	assert.False(t, v.IsEnabled())

	// Test enable
	result = v.Enable()
	assert.Same(t, v, result)
	assert.True(t, v.IsEnabled())
}

func TestExpirationValidator_IsExpired(t *testing.T) {
	// Use a fixed time for consistent testing
	now := time.Date(2026, 2, 4, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name       string
		expiration time.Time
		tolerance  int64
		expected   bool
	}{
		{
			name:       "not expired - future",
			expiration: now.Add(10 * time.Minute),
			tolerance:  300,
			expected:   false,
		},
		{
			name:       "not expired - exactly now",
			expiration: now,
			tolerance:  300,
			expected:   false,
		},
		{
			name:       "not expired - within tolerance",
			expiration: now.Add(-4 * time.Minute),
			tolerance:  300,
			expected:   false,
		},
		{
			name:       "expired - beyond tolerance",
			expiration: now.Add(-10 * time.Minute),
			tolerance:  300,
			expected:   true,
		},
		{
			name:       "expired - exactly at tolerance boundary",
			expiration: now.Add(-300 * time.Second),
			tolerance:  300,
			expected:   false, // At exactly the boundary, not expired
		},
		{
			name:       "expired - just past tolerance boundary",
			expiration: now.Add(-301 * time.Second),
			tolerance:  300,
			expected:   true,
		},
		{
			name:       "expired - zero tolerance",
			expiration: now.Add(-1 * time.Second),
			tolerance:  0,
			expected:   true,
		},
		{
			name:       "not expired - zero tolerance with future time",
			expiration: now.Add(1 * time.Second),
			tolerance:  0,
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewExpirationValidator().
				WithTolerance(tt.tolerance).
				WithTimeSource(func() time.Time { return now })

			result := v.IsExpired(tt.expiration)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExpirationValidator_IsExpired_WhenDisabled(t *testing.T) {
	now := time.Date(2026, 2, 4, 12, 0, 0, 0, time.UTC)
	expiredTime := now.Add(-1 * time.Hour) // Clearly expired

	v := NewExpirationValidator().
		WithTolerance(0).
		WithTimeSource(func() time.Time { return now }).
		Disable()

	// Even clearly expired messages should return false when disabled
	assert.False(t, v.IsExpired(expiredTime))
}

func TestExpirationValidator_ValidateExpiration(t *testing.T) {
	now := time.Date(2026, 2, 4, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name        string
		expiration  time.Time
		tolerance   int64
		expectError bool
	}{
		{
			name:        "valid - future expiration",
			expiration:  now.Add(5 * time.Minute),
			tolerance:   300,
			expectError: false,
		},
		{
			name:        "valid - within tolerance",
			expiration:  now.Add(-2 * time.Minute),
			tolerance:   300,
			expectError: false,
		},
		{
			name:        "invalid - expired beyond tolerance",
			expiration:  now.Add(-10 * time.Minute),
			tolerance:   300,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewExpirationValidator().
				WithTolerance(tt.tolerance).
				WithTimeSource(func() time.Time { return now })

			err := v.ValidateExpiration(tt.expiration)
			if tt.expectError {
				require.Error(t, err)
				assert.True(t, errors.Is(err, ERR_I2NP_MESSAGE_EXPIRED))
				// Error message should contain useful context
				assert.Contains(t, err.Error(), "expired")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestExpirationValidator_ValidateExpiration_WhenDisabled(t *testing.T) {
	now := time.Date(2026, 2, 4, 12, 0, 0, 0, time.UTC)
	expiredTime := now.Add(-1 * time.Hour)

	v := NewExpirationValidator().
		WithTolerance(0).
		WithTimeSource(func() time.Time { return now }).
		Disable()

	err := v.ValidateExpiration(expiredTime)
	require.NoError(t, err)
}

func TestExpirationValidator_ValidateMessage(t *testing.T) {
	now := time.Date(2026, 2, 4, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name        string
		msgType     int
		expiration  time.Time
		expectError bool
	}{
		{
			name:        "valid data message",
			msgType:     I2NP_MESSAGE_TYPE_DATA,
			expiration:  now.Add(5 * time.Minute),
			expectError: false,
		},
		{
			name:        "expired data message",
			msgType:     I2NP_MESSAGE_TYPE_DATA,
			expiration:  now.Add(-10 * time.Minute),
			expectError: true,
		},
		{
			name:        "valid tunnel data message",
			msgType:     I2NP_MESSAGE_TYPE_TUNNEL_DATA,
			expiration:  now.Add(1 * time.Minute),
			expectError: false,
		},
		{
			name:        "expired tunnel data message",
			msgType:     I2NP_MESSAGE_TYPE_TUNNEL_DATA,
			expiration:  now.Add(-20 * time.Minute),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewExpirationValidator().
				WithTolerance(300).
				WithTimeSource(func() time.Time { return now })

			msg := NewBaseI2NPMessage(tt.msgType)
			msg.SetExpiration(tt.expiration)

			err := v.ValidateMessage(msg)
			if tt.expectError {
				require.Error(t, err)
				assert.True(t, errors.Is(err, ERR_I2NP_MESSAGE_EXPIRED))
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// =============================================================================
// Convenience Function Tests
// =============================================================================

func TestCheckMessageExpiration(t *testing.T) {
	// Reset default validator after test
	defer ResetDefaultExpirationValidator()

	now := time.Date(2026, 2, 4, 12, 0, 0, 0, time.UTC)

	// Set up a controlled default validator
	SetDefaultExpirationValidator(
		NewExpirationValidator().
			WithTolerance(300).
			WithTimeSource(func() time.Time { return now }),
	)

	// Test with valid message
	validMsg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATA)
	validMsg.SetExpiration(now.Add(5 * time.Minute))
	err := CheckMessageExpiration(validMsg)
	require.NoError(t, err)

	// Test with expired message
	expiredMsg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATA)
	expiredMsg.SetExpiration(now.Add(-10 * time.Minute))
	err = CheckMessageExpiration(expiredMsg)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ERR_I2NP_MESSAGE_EXPIRED))
}

func TestIsMessageExpired(t *testing.T) {
	// Reset default validator after test
	defer ResetDefaultExpirationValidator()

	now := time.Date(2026, 2, 4, 12, 0, 0, 0, time.UTC)

	SetDefaultExpirationValidator(
		NewExpirationValidator().
			WithTolerance(300).
			WithTimeSource(func() time.Time { return now }),
	)

	// Test with valid message
	validMsg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATA)
	validMsg.SetExpiration(now.Add(5 * time.Minute))
	assert.False(t, IsMessageExpired(validMsg))

	// Test with expired message
	expiredMsg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATA)
	expiredMsg.SetExpiration(now.Add(-10 * time.Minute))
	assert.True(t, IsMessageExpired(expiredMsg))
}

func TestSetDefaultExpirationValidator_NilHandling(t *testing.T) {
	// Reset default validator after test
	defer ResetDefaultExpirationValidator()

	originalValidator := defaultExpirationValidator
	SetDefaultExpirationValidator(nil)

	// Should not change the validator when nil is passed
	assert.Same(t, originalValidator, defaultExpirationValidator)
}

func TestResetDefaultExpirationValidator(t *testing.T) {
	// Modify the default validator
	customValidator := NewExpirationValidator().WithTolerance(999)
	SetDefaultExpirationValidator(customValidator)
	assert.Equal(t, int64(999), defaultExpirationValidator.toleranceSeconds)

	// Reset and verify
	ResetDefaultExpirationValidator()
	assert.Equal(t, int64(DefaultExpirationTolerance), defaultExpirationValidator.toleranceSeconds)
}

// =============================================================================
// MessageProcessor Integration Tests
// =============================================================================

func TestMessageProcessor_ExpirationValidation(t *testing.T) {
	now := time.Date(2026, 2, 4, 12, 0, 0, 0, time.UTC)

	processor := NewMessageProcessor()
	processor.SetExpirationValidator(
		NewExpirationValidator().
			WithTolerance(300).
			WithTimeSource(func() time.Time { return now }),
	)

	t.Run("valid message is processed", func(t *testing.T) {
		msg := NewDataMessage([]byte("test payload"))
		msg.SetExpiration(now.Add(5 * time.Minute))

		err := processor.ProcessMessage(msg)
		require.NoError(t, err)
	})

	t.Run("expired message is rejected", func(t *testing.T) {
		msg := NewDataMessage([]byte("test payload"))
		msg.SetExpiration(now.Add(-10 * time.Minute))

		err := processor.ProcessMessage(msg)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ERR_I2NP_MESSAGE_EXPIRED))
	})
}

func TestMessageProcessor_DisableExpirationCheck(t *testing.T) {
	now := time.Date(2026, 2, 4, 12, 0, 0, 0, time.UTC)

	processor := NewMessageProcessor()
	processor.SetExpirationValidator(
		NewExpirationValidator().
			WithTolerance(0).
			WithTimeSource(func() time.Time { return now }),
	)

	// Create an expired message
	msg := NewDataMessage([]byte("test payload"))
	msg.SetExpiration(now.Add(-1 * time.Hour))

	// Should fail with expiration check enabled
	err := processor.ProcessMessage(msg)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ERR_I2NP_MESSAGE_EXPIRED))

	// Disable expiration check
	processor.DisableExpirationCheck()

	// Should succeed now
	err = processor.ProcessMessage(msg)
	require.NoError(t, err)
}

func TestMessageProcessor_EnableExpirationCheck(t *testing.T) {
	now := time.Date(2026, 2, 4, 12, 0, 0, 0, time.UTC)

	processor := NewMessageProcessor()
	processor.SetExpirationValidator(
		NewExpirationValidator().
			WithTolerance(0).
			WithTimeSource(func() time.Time { return now }).
			Disable(), // Start disabled
	)

	// Create an expired message
	msg := NewDataMessage([]byte("test payload"))
	msg.SetExpiration(now.Add(-1 * time.Hour))

	// Should succeed with expiration check disabled
	err := processor.ProcessMessage(msg)
	require.NoError(t, err)

	// Enable expiration check
	processor.EnableExpirationCheck()

	// Should fail now
	err = processor.ProcessMessage(msg)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ERR_I2NP_MESSAGE_EXPIRED))
}

func TestMessageProcessor_NilExpirationValidator(t *testing.T) {
	processor := NewMessageProcessor()
	processor.expirationValidator = nil // Simulate uninitialized

	// Create a message (expiration doesn't matter since validator is nil)
	msg := NewDataMessage([]byte("test payload"))

	// Should not panic and should process normally
	err := processor.ProcessMessage(msg)
	require.NoError(t, err)
}

func TestMessageProcessor_SetExpirationValidator_NilHandling(t *testing.T) {
	processor := NewMessageProcessor()
	originalValidator := processor.expirationValidator

	processor.SetExpirationValidator(nil)

	// Should not change the validator when nil is passed
	assert.Same(t, originalValidator, processor.expirationValidator)
}

// =============================================================================
// Edge Case Tests
// =============================================================================

func TestExpirationValidator_VeryLargeTolerance(t *testing.T) {
	now := time.Date(2026, 2, 4, 12, 0, 0, 0, time.UTC)

	// Tolerance of 1 year (in seconds)
	v := NewExpirationValidator().
		WithTolerance(365 * 24 * 60 * 60).
		WithTimeSource(func() time.Time { return now })

	// Even a message that "expired" 6 months ago should be valid
	oldExpiration := now.Add(-6 * 30 * 24 * time.Hour)
	assert.False(t, v.IsExpired(oldExpiration))
}

func TestExpirationValidator_ZeroExpiration(t *testing.T) {
	now := time.Date(2026, 2, 4, 12, 0, 0, 0, time.UTC)

	v := NewExpirationValidator().
		WithTolerance(300).
		WithTimeSource(func() time.Time { return now })

	// Zero time is definitely expired
	assert.True(t, v.IsExpired(time.Time{}))
}

func TestExpirationValidator_FarFutureExpiration(t *testing.T) {
	now := time.Date(2026, 2, 4, 12, 0, 0, 0, time.UTC)

	v := NewExpirationValidator().
		WithTolerance(300).
		WithTimeSource(func() time.Time { return now })

	// Far future expiration should be valid
	futureTime := now.Add(100 * 365 * 24 * time.Hour) // 100 years
	assert.False(t, v.IsExpired(futureTime))
}

// =============================================================================
// Benchmark Tests
// =============================================================================

func BenchmarkExpirationValidator_IsExpired(b *testing.B) {
	now := time.Date(2026, 2, 4, 12, 0, 0, 0, time.UTC)
	v := NewExpirationValidator().
		WithTolerance(300).
		WithTimeSource(func() time.Time { return now })

	expiration := now.Add(5 * time.Minute)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v.IsExpired(expiration)
	}
}

func BenchmarkExpirationValidator_ValidateMessage(b *testing.B) {
	now := time.Date(2026, 2, 4, 12, 0, 0, 0, time.UTC)
	v := NewExpirationValidator().
		WithTolerance(300).
		WithTimeSource(func() time.Time { return now })

	msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATA)
	msg.SetExpiration(now.Add(5 * time.Minute))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v.ValidateMessage(msg)
	}
}

func BenchmarkCheckMessageExpiration(b *testing.B) {
	defer ResetDefaultExpirationValidator()

	now := time.Date(2026, 2, 4, 12, 0, 0, 0, time.UTC)
	SetDefaultExpirationValidator(
		NewExpirationValidator().
			WithTolerance(300).
			WithTimeSource(func() time.Time { return now }),
	)

	msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATA)
	msg.SetExpiration(now.Add(5 * time.Minute))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CheckMessageExpiration(msg)
	}
}
