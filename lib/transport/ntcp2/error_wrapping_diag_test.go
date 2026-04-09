package ntcp2

import (
	"errors"
	"net"
	"testing"

	"github.com/samber/oops"
)

// fakeTimeoutErr implements net.Error with Timeout() == true,
// simulating what the OS returns when a read deadline fires.
type fakeTimeoutErr struct{}

func (fakeTimeoutErr) Error() string   { return "i/o timeout" }
func (fakeTimeoutErr) Timeout() bool   { return true }
func (fakeTimeoutErr) Temporary() bool { return true }

// TestDiag_OopsWrappedTimeout_DirectTypeAssertion proves that a net.Error
// wrapped by oops.Wrapf is NOT detectable via direct type assertion
// (the pattern used in handleReadResult).
func TestDiag_OopsWrappedTimeout_DirectTypeAssertion(t *testing.T) {
	original := fakeTimeoutErr{}

	// Confirm the unwrapped error satisfies net.Error
	if _, ok := (error)(original).(net.Error); !ok {
		t.Fatal("unwrapped fakeTimeoutErr should satisfy net.Error")
	}

	// Wrap with oops, exactly as readObfuscatedFrameLength does:
	wrapped := oops.
		Code("READ_LENGTH_FAILED").
		In("ntcp2").
		Wrapf(original, "failed to read frame length (frame #%d)", 42)

	// ---- This is the pattern in handleReadResult (line 456) ----
	netErr, ok := wrapped.(net.Error)
	if ok {
		t.Logf("PASS: direct type assertion SUCCEEDED (netErr.Timeout()=%v)", netErr.Timeout())
	} else {
		t.Logf("CONFIRMED BUG: direct type assertion err.(net.Error) FAILS for oops-wrapped timeout")
		t.Logf("  concrete type of wrapped error: %T", wrapped)
	}

	// ---- This is the correct pattern (used in isTimeoutOrReset) ----
	var netErr2 net.Error
	if errors.As(wrapped, &netErr2) {
		t.Logf("PASS: errors.As(err, &net.Error) SUCCEEDS, Timeout()=%v", netErr2.Timeout())
	} else {
		t.Fatal("errors.As should find net.Error in oops error chain")
	}

	// Summary assertion: the direct assertion must fail for this to be a real bug
	if ok {
		t.Skip("Direct type assertion works — the bug hypothesis was wrong")
	}
}

// TestDiag_HandleReadResult_MissesOopsTimeout replicates the exact logic of
// handleReadResult and proves it misclassifies oops-wrapped timeouts as fatal.
func TestDiag_HandleReadResult_MissesOopsTimeout(t *testing.T) {
	original := fakeTimeoutErr{}
	wrapped := oops.Wrapf(original, "failed to read frame length")

	// Replicate handleReadResult logic
	shouldContinue := false
	if netErr, ok := wrapped.(net.Error); ok && netErr.Timeout() {
		shouldContinue = true
	}

	if shouldContinue {
		t.Skip("handleReadResult correctly detects timeout — no bug")
	}
	t.Log("CONFIRMED: handleReadResult returns false (fatal) for oops-wrapped timeout")
	t.Log("This kills sessions that should survive read-deadline rotation")

	// Prove the fix works
	var netErr net.Error
	shouldContinueFixed := errors.As(wrapped, &netErr) && netErr.Timeout()
	if !shouldContinueFixed {
		t.Fatal("Fixed logic with errors.As should detect timeout")
	}
	t.Log("FIX VERIFIED: errors.As correctly detects timeout through oops wrapping")
}
