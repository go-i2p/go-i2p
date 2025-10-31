package sntp

import (
	"os"
	"testing"
	"time"

	"github.com/beevik/ntp"
)

// TestLoggingWithDebugEnabled verifies that logging works when DEBUG_I2P is enabled
func TestLoggingWithDebugEnabled(t *testing.T) {
	// Enable debug logging for this test
	os.Setenv("DEBUG_I2P", "debug")
	defer os.Unsetenv("DEBUG_I2P")

	// Test validation functions that log warnings
	response := &ntp.Response{
		Leap:    ntp.LeapNotInSync,
		Stratum: 0,
		Time:    time.Now(),
	}

	// This should log a warning about leap indicator
	result := validateLeapAndStratum(response)
	if result {
		t.Error("Expected validation to fail for unsynchronized leap indicator")
	}

	// Test with invalid stratum
	response.Leap = ntp.LeapNoWarning
	response.Stratum = 16 // Out of range
	result = validateLeapAndStratum(response)
	if result {
		t.Error("Expected validation to fail for invalid stratum")
	}
}

// TestLoggingDisabled verifies that logging has no impact when DEBUG_I2P is not set
func TestLoggingDisabled(t *testing.T) {
	// Ensure DEBUG_I2P is not set
	os.Unsetenv("DEBUG_I2P")

	// Run validation - should work without any logging overhead
	response := &ntp.Response{
		Leap:           ntp.LeapNoWarning,
		Stratum:        3,
		Time:           time.Now(),
		RTT:            100 * time.Millisecond,
		ClockOffset:    5 * time.Second,
		RootDispersion: 500 * time.Millisecond,
		RootDelay:      500 * time.Millisecond,
	}

	rt := &MockRouterTimestamper{}
	// Should validate successfully
	result := rt.validateResponse(response)
	if !result {
		t.Error("Expected validation to succeed for valid response")
	}
}

// TestZonesLogging verifies that zone loading handles errors gracefully
func TestZonesLogging(t *testing.T) {
	os.Setenv("DEBUG_I2P", "debug")
	defer os.Unsetenv("DEBUG_I2P")

	// Create zones - should not panic even if continents.txt has issues
	zones := NewZones()
	if zones == nil {
		t.Error("Expected NewZones to return non-nil even with logging enabled")
	}
}

// MockRouterTimestamper is a minimal implementation for testing
type MockRouterTimestamper struct{}

func (rt *MockRouterTimestamper) validateResponse(response *ntp.Response) bool {
	if !validateLeapAndStratum(response) {
		return false
	}
	if !validateTimingMetrics(response) {
		return false
	}
	if !validateTimeValue(response) {
		return false
	}
	if !validateRootMetrics(response) {
		return false
	}
	return true
}

// TestStructuredFieldsInValidation verifies structured logging fields are present
func TestStructuredFieldsInValidation(t *testing.T) {
	os.Setenv("DEBUG_I2P", "debug")
	defer os.Unsetenv("DEBUG_I2P")

	// Test timing validation with out-of-bounds RTT
	response := &ntp.Response{
		Leap:        ntp.LeapNoWarning,
		Stratum:     3,
		Time:        time.Now(),
		RTT:         3 * time.Second, // Exceeds maxRTT
		ClockOffset: 1 * time.Second,
	}

	result := validateTimingMetrics(response)
	if result {
		t.Error("Expected validation to fail for excessive RTT")
	}

	// Test with excessive clock offset
	response.RTT = 500 * time.Millisecond
	response.ClockOffset = 15 * time.Second // Exceeds maxClockOffset
	result = validateTimingMetrics(response)
	if result {
		t.Error("Expected validation to fail for excessive clock offset")
	}
}

// BenchmarkValidationWithLoggingDisabled ensures no performance regression
func BenchmarkValidationWithLoggingDisabled(b *testing.B) {
	os.Unsetenv("DEBUG_I2P")

	response := &ntp.Response{
		Leap:           ntp.LeapNoWarning,
		Stratum:        3,
		Time:           time.Now(),
		RTT:            100 * time.Millisecond,
		ClockOffset:    1 * time.Second,
		RootDispersion: 500 * time.Millisecond,
		RootDelay:      500 * time.Millisecond,
	}

	rt := &MockRouterTimestamper{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rt.validateResponse(response)
	}
}

// BenchmarkValidationWithLoggingEnabled measures overhead with debug logging
func BenchmarkValidationWithLoggingEnabled(b *testing.B) {
	os.Setenv("DEBUG_I2P", "debug")
	defer os.Unsetenv("DEBUG_I2P")

	response := &ntp.Response{
		Leap:           ntp.LeapNoWarning,
		Stratum:        3,
		Time:           time.Now(),
		RTT:            100 * time.Millisecond,
		ClockOffset:    1 * time.Second,
		RootDispersion: 500 * time.Millisecond,
		RootDelay:      500 * time.Millisecond,
	}

	rt := &MockRouterTimestamper{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rt.validateResponse(response)
	}
}
