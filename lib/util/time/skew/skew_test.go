package skew

import (
	"strings"
	"testing"
	"time"
)

// =============================================================================
// ValidateTimestamp Tests
// =============================================================================

// TestValidateTimestamp_CurrentTime verifies that a timestamp equal to "now" is valid.
func TestValidateTimestamp_CurrentTime(t *testing.T) {
	now := time.Now()
	nowFunc = func() time.Time { return now }
	defer func() { nowFunc = time.Now }()

	if err := ValidateTimestamp(now); err != nil {
		t.Errorf("expected current time to be valid, got error: %v", err)
	}
}

// TestValidateTimestamp_WithinWindow verifies timestamps within ±60 minutes are accepted.
func TestValidateTimestamp_WithinWindow(t *testing.T) {
	now := time.Now()
	nowFunc = func() time.Time { return now }
	defer func() { nowFunc = time.Now }()

	tests := []struct {
		name      string
		published time.Time
	}{
		{"30 minutes ago", now.Add(-30 * time.Minute)},
		{"59 minutes ago", now.Add(-59 * time.Minute)},
		{"30 minutes in future", now.Add(30 * time.Minute)},
		{"59 minutes in future", now.Add(59 * time.Minute)},
		{"1 second ago", now.Add(-1 * time.Second)},
		{"1 second in future", now.Add(1 * time.Second)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateTimestamp(tc.published); err != nil {
				t.Errorf("expected timestamp %s to be valid, got error: %v", tc.name, err)
			}
		})
	}
}

// TestValidateTimestamp_TooOld verifies timestamps more than 60 minutes in the past are rejected.
func TestValidateTimestamp_TooOld(t *testing.T) {
	now := time.Now()
	nowFunc = func() time.Time { return now }
	defer func() { nowFunc = time.Now }()

	tests := []struct {
		name      string
		published time.Time
	}{
		{"61 minutes ago", now.Add(-61 * time.Minute)},
		{"2 hours ago", now.Add(-2 * time.Hour)},
		{"24 hours ago", now.Add(-24 * time.Hour)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateTimestamp(tc.published)
			if err == nil {
				t.Errorf("expected timestamp %s to be rejected, got nil error", tc.name)
			}
			if !strings.Contains(err.Error(), "in the past") {
				t.Errorf("expected 'in the past' in error, got: %v", err)
			}
		})
	}
}

// TestValidateTimestamp_TooFarInFuture verifies timestamps more than 60 minutes ahead are rejected.
func TestValidateTimestamp_TooFarInFuture(t *testing.T) {
	now := time.Now()
	nowFunc = func() time.Time { return now }
	defer func() { nowFunc = time.Now }()

	tests := []struct {
		name      string
		published time.Time
	}{
		{"61 minutes in future", now.Add(61 * time.Minute)},
		{"2 hours in future", now.Add(2 * time.Hour)},
		{"24 hours in future", now.Add(24 * time.Hour)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateTimestamp(tc.published)
			if err == nil {
				t.Errorf("expected timestamp %s to be rejected, got nil error", tc.name)
			}
			if !strings.Contains(err.Error(), "in the future") {
				t.Errorf("expected 'in the future' in error, got: %v", err)
			}
		})
	}
}

// TestValidateTimestamp_ZeroTime verifies that a zero-value time is rejected.
func TestValidateTimestamp_ZeroTime(t *testing.T) {
	err := ValidateTimestamp(time.Time{})
	if err == nil {
		t.Error("expected zero time to be rejected, got nil error")
	}
	if !strings.Contains(err.Error(), "zero") {
		t.Errorf("expected 'zero' in error, got: %v", err)
	}
}

// TestValidateTimestamp_ExactBoundary verifies behavior at exactly 60 minutes.
func TestValidateTimestamp_ExactBoundary(t *testing.T) {
	now := time.Now()
	nowFunc = func() time.Time { return now }
	defer func() { nowFunc = time.Now }()

	// Exactly 60 minutes ago should still be valid (skew == MaxClockSkew, not >)
	published := now.Add(-MaxClockSkew)
	if err := ValidateTimestamp(published); err != nil {
		t.Errorf("expected exactly 60 minutes ago to be valid, got: %v", err)
	}

	// Exactly 60 minutes in future should still be valid
	published = now.Add(MaxClockSkew)
	if err := ValidateTimestamp(published); err != nil {
		t.Errorf("expected exactly 60 minutes in future to be valid, got: %v", err)
	}
}

// =============================================================================
// IsTimestampValid Tests
// =============================================================================

// TestIsTimestampValid_ReturnsTrue verifies the boolean wrapper returns true for valid timestamps.
func TestIsTimestampValid_ReturnsTrue(t *testing.T) {
	now := time.Now()
	nowFunc = func() time.Time { return now }
	defer func() { nowFunc = time.Now }()

	if !IsTimestampValid(now) {
		t.Error("expected IsTimestampValid to return true for current time")
	}
}

// TestIsTimestampValid_ReturnsFalse verifies the boolean wrapper returns false for invalid timestamps.
func TestIsTimestampValid_ReturnsFalse(t *testing.T) {
	now := time.Now()
	nowFunc = func() time.Time { return now }
	defer func() { nowFunc = time.Now }()

	if IsTimestampValid(now.Add(-2 * time.Hour)) {
		t.Error("expected IsTimestampValid to return false for 2 hours ago")
	}

	if IsTimestampValid(time.Time{}) {
		t.Error("expected IsTimestampValid to return false for zero time")
	}
}

// =============================================================================
// ValidateTimestampWithSkew Tests
// =============================================================================

// TestValidateTimestampWithSkew_CustomWindow verifies custom skew windows work.
func TestValidateTimestampWithSkew_CustomWindow(t *testing.T) {
	now := time.Now()
	nowFunc = func() time.Time { return now }
	defer func() { nowFunc = time.Now }()

	// NTCP2 uses ±2 minutes
	ntcp2Skew := 2 * time.Minute

	// Within 2 minutes should pass
	if err := ValidateTimestampWithSkew(now.Add(-1*time.Minute), ntcp2Skew); err != nil {
		t.Errorf("expected 1 min ago with 2 min window to be valid, got: %v", err)
	}

	// Beyond 2 minutes should fail
	err := ValidateTimestampWithSkew(now.Add(-3*time.Minute), ntcp2Skew)
	if err == nil {
		t.Error("expected 3 min ago with 2 min window to be rejected")
	}
}

// TestValidateTimestampWithSkew_ZeroTime verifies zero time is rejected regardless of window.
func TestValidateTimestampWithSkew_ZeroTime(t *testing.T) {
	err := ValidateTimestampWithSkew(time.Time{}, 5*time.Minute)
	if err == nil {
		t.Error("expected zero time to be rejected")
	}
}

// TestValidateTimestampWithSkew_InvalidMaxSkew verifies non-positive maxSkew is rejected.
func TestValidateTimestampWithSkew_InvalidMaxSkew(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name    string
		maxSkew time.Duration
	}{
		{"zero duration", 0},
		{"negative duration", -5 * time.Minute},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateTimestampWithSkew(now, tc.maxSkew)
			if err == nil {
				t.Errorf("expected error for maxSkew=%s, got nil", tc.maxSkew)
			}
			if !strings.Contains(err.Error(), "must be positive") {
				t.Errorf("expected 'must be positive' in error, got: %v", err)
			}
		})
	}
}

// =============================================================================
// MaxClockSkew Constant Tests
// =============================================================================

// TestMaxClockSkewValue verifies the constant matches the spec requirement of 60 minutes.
func TestMaxClockSkewValue(t *testing.T) {
	if MaxClockSkew != 60*time.Minute {
		t.Errorf("MaxClockSkew should be 60 minutes, got %s", MaxClockSkew)
	}
}

// =============================================================================
// Error Message Tests
// =============================================================================

// TestValidateTimestamp_ErrorMessages verifies error messages contain useful diagnostics.
func TestValidateTimestamp_ErrorMessages(t *testing.T) {
	now := time.Now()
	nowFunc = func() time.Time { return now }
	defer func() { nowFunc = time.Now }()

	// Too old
	err := ValidateTimestamp(now.Add(-2 * time.Hour))
	if err == nil {
		t.Fatal("expected error for old timestamp")
	}
	if !strings.Contains(err.Error(), "clock skew") {
		t.Errorf("error should contain 'clock skew': %v", err)
	}

	// Too new
	err = ValidateTimestamp(now.Add(2 * time.Hour))
	if err == nil {
		t.Fatal("expected error for future timestamp")
	}
	if !strings.Contains(err.Error(), "clock skew") {
		t.Errorf("error should contain 'clock skew': %v", err)
	}
}
