package i2cp

import (
	"testing"
	"time"
)

// mockConnWithDeadlineTracking tracks SetWriteDeadline calls
type mockConnWithDeadlineTracking struct {
	mockConn
	lastWriteDeadline time.Time
	deadlineCalls     int
}

func (m *mockConnWithDeadlineTracking) SetWriteDeadline(t time.Time) error {
	m.lastWriteDeadline = t
	m.deadlineCalls++
	return nil
}

// TestM9_ApplyWriteDeadline_EnforcesMinimumOnZeroTimeout verifies that
// WriteTimeout=0 (no timeout) gets enforced with minimum deadline.
// M-9 FIX: Prevents indefinite blocking when WriteTimeout is 0.
func TestM9_ApplyWriteDeadline_EnforcesMinimumOnZeroTimeout(t *testing.T) {
	server := &Server{
		config: &ServerConfig{
			MaxSessions:    100,
			WriteTimeout:   0, // M-9 FIX: Zero timeout (disabled)
			SessionTimeout: 0,
		},
		manager: NewSessionManager(),
	}

	mockConn := &mockConnWithDeadlineTracking{}
	before := time.Now()
	server.applyWriteDeadline(mockConn)
	after := time.Now()

	// M-9 FIX: Verify deadline was set (not skipped)
	if mockConn.deadlineCalls == 0 {
		t.Fatal("expected SetWriteDeadline to be called when WriteTimeout=0")
	}

	// M-9 FIX: Verify deadline is in the future (within range)
	// Should be approximately now + minimumWriteTimeout
	expectedMin := before.Add(minimumWriteTimeout - 100*time.Millisecond)
	expectedMax := after.Add(minimumWriteTimeout + 100*time.Millisecond)

	if mockConn.lastWriteDeadline.Before(expectedMin) || mockConn.lastWriteDeadline.After(expectedMax) {
		t.Errorf("deadline not within expected range. Expected: %v±100ms, Got: %v", expectedMin, mockConn.lastWriteDeadline)
	}
}

// TestM9_ApplyWriteDeadline_RespectsShorterTimeout verifies that configured
// WriteTimeout shorter than minimum still gets enforced to minimum.
// M-9 FIX: Prevents undershooting write deadline.
func TestM9_ApplyWriteDeadline_RespectsShorterTimeout(t *testing.T) {
	server := &Server{
		config: &ServerConfig{
			MaxSessions:    100,
			WriteTimeout:   1 * time.Second, // M-9 FIX: Way shorter than minimum
			SessionTimeout: 0,
		},
		manager: NewSessionManager(),
	}

	mockConn := &mockConnWithDeadlineTracking{}
	before := time.Now()
	server.applyWriteDeadline(mockConn)
	after := time.Now()

	// M-9 FIX: Verify deadline was enforced to minimum
	expectedMin := before.Add(minimumWriteTimeout - 100*time.Millisecond)
	expectedMax := after.Add(minimumWriteTimeout + 100*time.Millisecond)

	if mockConn.lastWriteDeadline.Before(expectedMin) || mockConn.lastWriteDeadline.After(expectedMax) {
		t.Errorf("deadline not enforced to minimum. Expected: %v±100ms, Got: %v", expectedMin, mockConn.lastWriteDeadline)
	}
}

// TestM9_ApplyWriteDeadline_RespectsSensibleTimeout verifies that a reasonable
// WriteTimeout (between 0 and minimum) is enforced to minimum.
func TestM9_ApplyWriteDeadline_RespectsSensibleTimeout(t *testing.T) {
	server := &Server{
		config: &ServerConfig{
			MaxSessions:    100,
			WriteTimeout:   30 * time.Second, // M-9 FIX: Reasonable but less than minimum
			SessionTimeout: 0,
		},
		manager: NewSessionManager(),
	}

	mockConn := &mockConnWithDeadlineTracking{}
	before := time.Now()
	server.applyWriteDeadline(mockConn)
	after := time.Now()

	// M-9 FIX: Verify deadline was enforced to minimum
	expectedMin := before.Add(minimumWriteTimeout - 100*time.Millisecond)
	expectedMax := after.Add(minimumWriteTimeout + 100*time.Millisecond)

	if mockConn.lastWriteDeadline.Before(expectedMin) || mockConn.lastWriteDeadline.After(expectedMax) {
		t.Errorf("deadline not enforced to minimum for reasonable timeout. Expected: %v±100ms, Got: %v", expectedMin, mockConn.lastWriteDeadline)
	}
}

// TestM9_ApplyWriteDeadline_RespectLargerTimeout verifies that a WriteTimeout
// larger than minimum is respected as-is.
func TestM9_ApplyWriteDeadline_RespectLargerTimeout(t *testing.T) {
	largeTimeout := 30 * time.Minute // M-9 FIX: Larger than minimum
	server := &Server{
		config: &ServerConfig{
			MaxSessions:    100,
			WriteTimeout:   largeTimeout,
			SessionTimeout: 0,
		},
		manager: NewSessionManager(),
	}

	mockConn := &mockConnWithDeadlineTracking{}
	before := time.Now()
	server.applyWriteDeadline(mockConn)
	after := time.Now()

	// M-9 FIX: Verify deadline uses the configured larger timeout (not minimum)
	expectedMin := before.Add(largeTimeout - 100*time.Millisecond)
	expectedMax := after.Add(largeTimeout + 100*time.Millisecond)

	if mockConn.lastWriteDeadline.Before(expectedMin) || mockConn.lastWriteDeadline.After(expectedMax) {
		t.Errorf("deadline not using configured large timeout. Expected: %v±100ms, Got: %v", expectedMin, mockConn.lastWriteDeadline)
	}

	// M-9 FIX: Verify it's NOT the minimum timeout
	minimumMin := before.Add(minimumWriteTimeout - 100*time.Millisecond)
	if mockConn.lastWriteDeadline.Before(minimumMin) {
		t.Error("deadline was capped to minimum when it should use larger configured timeout")
	}
}

// TestM9_ApplyWriteDeadline_MultipleCalls verifies that each call to applyWriteDeadline
// correctly resets the deadline (not cumulative).
// M-9 FIX: Prevents deadline creep.
func TestM9_ApplyWriteDeadline_MultipleCalls(t *testing.T) {
	server := &Server{
		config: &ServerConfig{
			MaxSessions:    100,
			WriteTimeout:   0, // M-9 FIX: Enforce minimum
			SessionTimeout: 0,
		},
		manager: NewSessionManager(),
	}

	mockConn := &mockConnWithDeadlineTracking{}

	// M-9 FIX: Call applyWriteDeadline multiple times with delay
	server.applyWriteDeadline(mockConn)
	firstDeadline := mockConn.lastWriteDeadline

	time.Sleep(100 * time.Millisecond)

	secondBefore := time.Now()
	server.applyWriteDeadline(mockConn)
	secondDeadline := mockConn.lastWriteDeadline
	secondAfter := time.Now()

	// M-9 FIX: Second deadline should be roughly minimumWriteTimeout ahead of secondBefore
	// not ahead of firstBefore (no cumulative delay)
	expectedSecondMin := secondBefore.Add(minimumWriteTimeout - 100*time.Millisecond)
	expectedSecondMax := secondAfter.Add(minimumWriteTimeout + 100*time.Millisecond)

	if secondDeadline.Before(expectedSecondMin) || secondDeadline.After(expectedSecondMax) {
		t.Errorf("second deadline not reset properly. Expected: %v±100ms, Got: %v", expectedSecondMin, secondDeadline)
	}

	// M-9 FIX: Verify it's NOT just extending the first deadline
	if secondDeadline.Sub(firstDeadline) > 200*time.Millisecond {
		t.Errorf("second deadline appears to extend first deadline instead of resetting")
	}
}

// TestM9_MinimumWriteTimeoutConstant verifies that minimumWriteTimeout is set appropriately
// M-9 FIX: Sanity check on the safety constant.
func TestM9_MinimumWriteTimeoutConstant(t *testing.T) {
	// M-9 FIX: Verify minimum write timeout is reasonable (at least 30 seconds, typically 5 minutes)
	if minimumWriteTimeout < 30*time.Second {
		t.Errorf("minimumWriteTimeout too short: %v (should be at least 30s)", minimumWriteTimeout)
	}
	if minimumWriteTimeout > 1*time.Hour {
		t.Errorf("minimumWriteTimeout too long: %v (should be less than 1 hour)", minimumWriteTimeout)
	}
}

// TestM9_ApplyWriteDeadline_NegativeTimeout verifies that negative WriteTimeout
// is also enforced to minimum (defensive programming).
func TestM9_ApplyWriteDeadline_NegativeTimeout(t *testing.T) {
	server := &Server{
		config: &ServerConfig{
			MaxSessions:    100,
			WriteTimeout:   -10 * time.Second, // M-9 FIX: Invalid negative timeout
			SessionTimeout: 0,
		},
		manager: NewSessionManager(),
	}

	mockConn := &mockConnWithDeadlineTracking{}
	before := time.Now()
	server.applyWriteDeadline(mockConn)
	after := time.Now()

	// M-9 FIX: Negative should also be enforced to minimum
	expectedMin := before.Add(minimumWriteTimeout - 100*time.Millisecond)
	expectedMax := after.Add(minimumWriteTimeout + 100*time.Millisecond)

	if mockConn.lastWriteDeadline.Before(expectedMin) || mockConn.lastWriteDeadline.After(expectedMax) {
		t.Errorf("deadline not enforced to minimum for negative timeout. Expected: %v±100ms, Got: %v", expectedMin, mockConn.lastWriteDeadline)
	}
}
