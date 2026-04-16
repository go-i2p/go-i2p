package i2cp

import "testing"

// stubAuthenticator counts how many times Authenticate is called and always
// returns the configured result. It lets tests verify that the rate limiter
// short-circuits BEFORE reaching the delegate once the lockout is armed.
type stubAuthenticator struct {
	calls  int
	accept bool
}

func (s *stubAuthenticator) Authenticate(username, password string) bool {
	s.calls++
	return s.accept
}

func TestRateLimitedAuthenticator_LocksOutAfterThreshold(t *testing.T) {
	stub := &stubAuthenticator{accept: false}
	limiter := NewRateLimitedAuthenticator(stub)

	// The first maxI2CPFailedAttempts calls must reach the delegate.
	for i := 0; i < maxI2CPFailedAttempts; i++ {
		if limiter.Authenticate("user", "bad") {
			t.Fatalf("attempt %d unexpectedly succeeded", i+1)
		}
	}
	if stub.calls != maxI2CPFailedAttempts {
		t.Fatalf("expected %d delegate calls, got %d", maxI2CPFailedAttempts, stub.calls)
	}

	// The next attempt must be refused WITHOUT touching the delegate.
	callsBefore := stub.calls
	if limiter.Authenticate("user", "bad") {
		t.Fatalf("call after lockout unexpectedly succeeded")
	}
	if stub.calls != callsBefore {
		t.Fatalf("delegate called during lockout: before=%d after=%d", callsBefore, stub.calls)
	}

	// Even valid credentials are refused while locked out.
	stub.accept = true
	if limiter.Authenticate("user", "good") {
		t.Fatalf("valid credentials accepted during lockout")
	}
	if stub.calls != callsBefore {
		t.Fatalf("delegate called with valid credentials during lockout")
	}
}

func TestRateLimitedAuthenticator_SuccessResetsCounter(t *testing.T) {
	stub := &stubAuthenticator{accept: false}
	limiter := NewRateLimitedAuthenticator(stub)

	// Accumulate failures below the threshold.
	for i := 0; i < maxI2CPFailedAttempts-1; i++ {
		limiter.Authenticate("user", "bad")
	}

	// One success clears the counter.
	stub.accept = true
	if !limiter.Authenticate("user", "good") {
		t.Fatalf("valid credentials rejected before lockout")
	}

	// After the reset, another maxI2CPFailedAttempts-1 failures must NOT
	// trigger a lockout — confirming the counter was cleared.
	stub.accept = false
	for i := 0; i < maxI2CPFailedAttempts-1; i++ {
		if limiter.Authenticate("user", "bad") {
			t.Fatalf("attempt %d unexpectedly succeeded", i+1)
		}
	}
	limiter.mu.Lock()
	locked := !limiter.lockoutUntil.IsZero()
	limiter.mu.Unlock()
	if locked {
		t.Fatalf("lockout armed prematurely after counter reset")
	}
}

func TestSetAuthenticator_WrapsWithRateLimiter(t *testing.T) {
	s := &Server{}
	stub := &stubAuthenticator{accept: true}
	s.SetAuthenticator(stub)

	if _, ok := s.authenticator.(*RateLimitedAuthenticator); !ok {
		t.Fatalf("expected authenticator to be wrapped in RateLimitedAuthenticator, got %T", s.authenticator)
	}

	// Re-wrapping an already-rate-limited authenticator must be idempotent.
	already := NewRateLimitedAuthenticator(stub)
	s.SetAuthenticator(already)
	if s.authenticator != already {
		t.Fatalf("RateLimitedAuthenticator was re-wrapped; expected passthrough")
	}
}
