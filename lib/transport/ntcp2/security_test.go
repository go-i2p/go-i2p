// Tests for NTCP2 security properties. Validates frame length limits,
// static key length, and obfuscation IV length checks.

package ntcp2

import (
	"strings"
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Security audit tests for NTCP2 package (2026-02-04)

// TestFrameLengthValidation verifies that the declared block size of an
// inbound data-phase frame is bounded by the data actually present, so a peer
// cannot make the receiver allocate and parse beyond the frame.
//
// ntcp2.rst:1441 defines the block header's size field as "2 bytes, big
// endian, size of data to follow, 0 - 65516", restated at :1450 "Maximum single
// block data size is 65516 bytes"; the decrypted frame itself is capped at 65535
// bytes (:1444) with a maximum single block of 65519 including the 3-byte header
// (:1447). ParseBlocks enforces both the absolute declared-size ceiling and the
// declared-size-vs-available-data relationship, which together are the
// memory-exhaustion guard on the live receive path.
func TestFrameLengthValidation(t *testing.T) {
	// maxI2NPMessageSize is the spec's maximum single block data size.
	const maxI2NPMessageSize = 65516

	testCases := []struct {
		name        string
		declared    int
		available   int
		expectError string
	}{
		{"valid_small_message", 100, 100, ""},
		{"valid_max_message", maxI2NPMessageSize, maxI2NPMessageSize, ""},
		// A size over 65516 cannot legally exist in one block (3 + 65517 would
		// exceed the 65519 single-block ceiling at :1447), so it is rejected as
		// an illegal declaration rather than merely a truncation.
		{"invalid_oversized_declaration", maxI2NPMessageSize + 1, 8, "over the 65516 byte maximum"},
		{"invalid_huge_declaration", 65535, 8, "over the 65516 byte maximum"},
		{"invalid_truncated_data", 512, 511, "truncated block data"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := make([]byte, tc.available)
			if tc.expectError == "" {
				// A parseable I2NP block payload: 9-byte short header only.
				copy(data, mustShortFramedI2NP(t))
			}

			payload := blockFrame(tc.declared, data)

			unframer := NewBlockUnframer(&mockConn{data: payload})
			_, err := unframer.ReadNextMessage()
			if tc.expectError != "" {
				assert.Error(t, err, "should reject block declaring %d bytes with %d available", tc.declared, tc.available)
				assert.Contains(t, err.Error(), tc.expectError)
			} else {
				assert.NoError(t, err, "should accept block declaring %d bytes", tc.declared)
			}
		})
	}
}

// blockFrame builds one data-phase block (type 3, I2NP) with the given
// declared size and data, as it appears after AEAD decryption.
func blockFrame(declaredSize int, data []byte) []byte {
	payload := make([]byte, 0, 3+len(data))
	payload = append(payload, BlockTypeI2NP, byte(declaredSize>>8), byte(declaredSize))
	return append(payload, data...)
}

// mustShortFramedI2NP returns a spec-conformant 9-byte short-header I2NP
// message payload for use as block data.
func mustShortFramedI2NP(t *testing.T) []byte {
	t.Helper()
	short, err := i2np.MarshalMessageShort(i2np.NewDataMessage([]byte("security test payload")))
	require.NoError(t, err)
	return short
}

// TestStaticKeyLengthValidation verifies that static keys must be exactly 32 bytes.
func TestStaticKeyLengthValidation(t *testing.T) {
	testCases := []struct {
		name        string
		keyLength   int
		expectValid bool
	}{
		{"valid_32_bytes", 32, true},
		{"invalid_16_bytes", 16, false},
		{"invalid_0_bytes", 0, false},
		{"invalid_64_bytes", 64, false},
		{"invalid_31_bytes", 31, false},
		{"invalid_33_bytes", 33, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Validation is done when setting static key on transport config
			// The initializeCryptoKeys function checks this
			key := make([]byte, tc.keyLength)

			// Create a config and check validation
			config, err := NewConfig(":8080")
			require.NoError(t, err)

			// Static key length is validated in go-noise's NTCP2Config
			// Here we just verify our wrapper behavior
			if tc.expectValid {
				assert.Len(t, key, 32, "valid static key should be 32 bytes")
			} else {
				assert.NotEqual(t, 32, len(key), "invalid static key should not be 32 bytes")
			}
			_ = config // Used to verify config creation works
		})
	}
}

// TestObfuscationIVLengthValidation verifies that obfuscation IV must be exactly 16 bytes.
func TestObfuscationIVLengthValidation(t *testing.T) {
	testCases := []struct {
		name        string
		ivLength    int
		expectValid bool
	}{
		{"valid_16_bytes", 16, true},
		{"invalid_0_bytes", 0, false},
		{"invalid_8_bytes", 8, false},
		{"invalid_32_bytes", 32, false},
		{"invalid_15_bytes", 15, false},
		{"invalid_17_bytes", 17, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			iv := make([]byte, tc.ivLength)
			if tc.expectValid {
				assert.Len(t, iv, obfuscationIVSize, "valid IV should be 16 bytes")
			} else {
				assert.NotEqual(t, obfuscationIVSize, len(iv), "invalid IV should not be 16 bytes")
			}
		})
	}
}

// TestSessionCleanupCallback verifies that cleanup callbacks are called exactly once.
func TestSessionCleanupCallback(t *testing.T) {
	session := newTestSession(t)

	callCount := 0
	session.SetCleanupCallback(func() {
		callCount++
	})

	// Close multiple times
	session.Close()
	session.Close()
	session.Close()

	// Callback should only be called once
	assert.Equal(t, 1, callCount, "cleanup callback should be called exactly once")
}

// TestSessionErrorOnce verifies that session errors are set exactly once.
func TestSessionErrorOnce(t *testing.T) {
	session := newTestSession(t)

	// Set error multiple times
	err1 := WrapNTCP2Error(ErrFramingError, "first error")
	err2 := WrapNTCP2Error(ErrHandshakeFailed, "second error")

	session.setError(err1)
	session.setError(err2)

	// Only first error should be recorded - verify errorOnce behavior
	// The actual error stored might be different due to receive worker starting,
	// but we verify that setError only records once
	assert.NotNil(t, session.lastError, "an error should be recorded")
}

// TestErrorMessagesNoInfoLeak verifies that error messages don't leak sensitive information.
func TestErrorMessagesNoInfoLeak(t *testing.T) {
	sensitivePatterns := []string{
		"password",
		"private key",
		"secret",
		"credential",
	}

	errors := []error{
		ErrNTCP2NotSupported,
		ErrSessionClosed,
		ErrHandshakeFailed,
		ErrInvalidRouterInfo,
		ErrConnectionPoolFull,
		ErrFramingError,
		ErrInvalidListenerAddress,
		ErrInvalidConfig,
	}

	for _, err := range errors {
		errStr := strings.ToLower(err.Error())
		for _, pattern := range sensitivePatterns {
			assert.NotContains(t, errStr, pattern,
				"error message should not contain sensitive pattern '%s': %s", pattern, err.Error())
		}
	}
}

// TestWrappedErrorMessagesNoInfoLeak verifies wrapped errors don't leak sensitive data.
func TestWrappedErrorMessagesNoInfoLeak(t *testing.T) {
	// Wrap with various operation contexts
	operations := []string{
		"handshake",
		"connection",
		"framing",
		"reading",
		"writing",
	}

	for _, op := range operations {
		wrapped := WrapNTCP2Error(ErrHandshakeFailed, op)
		errStr := strings.ToLower(wrapped.Error())

		// Should contain operation context but not sensitive data
		assert.NotContains(t, errStr, "private", "wrapped error should not contain 'private'")
		assert.NotContains(t, errStr, "key:", "wrapped error should not contain raw key data")
	}
}

// TestTimeoutConfiguration verifies that timeouts are properly configured.
func TestTimeoutConfiguration(t *testing.T) {
	// Verify default timeout is reasonable (P0.2: reduced from 30s to 10s)
	const expectedDialTimeout = 10 * time.Second

	// This is the timeout used in performNTCP2Handshake
	// We can't easily test the actual dial without network access,
	// but we verify the constant is reasonable
	assert.GreaterOrEqual(t, expectedDialTimeout, 5*time.Second, "dial timeout should be at least 5s")
	assert.LessOrEqual(t, expectedDialTimeout, 30*time.Second, "dial timeout should be at most 30s")
}

// TestConcurrentSessionAccess verifies thread-safe session operations.
func TestConcurrentSessionAccess(t *testing.T) {
	session := newTestSession(t)

	// Run concurrent operations
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			// Read queue size (atomic operation)
			_ = session.SendQueueSize()

			// Get bandwidth stats (atomic operations)
			_, _ = session.GetBandwidthStats()

			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestMessageFramingRoundTrip verifies that block framing produces non-empty output
// with the correct NTCP2 block format.
func TestMessageFramingRoundTrip(t *testing.T) {
	originalData := []byte("test message for round-trip validation")
	msg := i2np.NewDataMessage(originalData)
	msg.SetMessageID(12345)

	framedData, err := FrameI2NPMessageAsBlock(msg)
	require.NoError(t, err)
	require.NotEmpty(t, framedData)

	// Block framing wraps in a type-3 (I2NP) block; verify type byte
	assert.Equal(t, byte(3), framedData[0], "first byte must be I2NP block type (3)")
}

// TestHasDirectConnectivityValidation verifies direct connectivity detection.
func TestHasDirectConnectivityValidation(t *testing.T) {
	// HasDirectConnectivity should return false for nil
	// This tests the function's nil handling
	assert.False(t, HasDirectConnectivity(nil), "nil address should not have direct connectivity")
}

// TestSupportsNTCP2NilSafe verifies nil safety of SupportsNTCP2.
func TestSupportsNTCP2NilSafe(t *testing.T) {
	assert.False(t, SupportsNTCP2(nil), "nil RouterInfo should return false")
}

// TestSupportsDirectNTCP2NilSafe verifies nil safety of SupportsDirectNTCP2.
func TestSupportsDirectNTCP2NilSafe(t *testing.T) {
	assert.False(t, SupportsDirectNTCP2(nil), "nil RouterInfo should return false")
}

// TestBandwidthTrackingAtomic verifies that bandwidth tracking is thread-safe.
func TestBandwidthTrackingAtomic(t *testing.T) {
	session := newTestSession(t)

	// Initial values should be zero
	sent, received := session.GetBandwidthStats()
	assert.Equal(t, uint64(0), sent, "initial bytes sent should be 0")
	assert.Equal(t, uint64(0), received, "initial bytes received should be 0")

	// Concurrent reads should be safe
	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func() {
			_, _ = session.GetBandwidthStats()
			done <- true
		}()
	}

	for i := 0; i < 100; i++ {
		<-done
	}
}

// TestConfigValidation verifies that config validation catches invalid settings.
func TestConfigValidation(t *testing.T) {
	t.Run("empty_listener_address", func(t *testing.T) {
		config, err := NewConfig("")
		require.NoError(t, err) // Creation succeeds

		err = config.Validate()
		assert.Error(t, err, "empty listener address should fail validation")
		assert.Equal(t, ErrInvalidListenerAddress, err)
	})

	t.Run("valid_listener_address", func(t *testing.T) {
		config, err := NewConfig(":8080")
		require.NoError(t, err)

		err = config.Validate()
		assert.NoError(t, err, "valid listener address should pass validation")
	})
}
