package i2cp

import (
	"net"
	"testing"
	"time"
)

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

type stubAddr string

func (a stubAddr) Network() string { return "tcp" }
func (a stubAddr) String() string  { return string(a) }

type stubConn struct {
	remote net.Addr
}

func (c *stubConn) Read(_ []byte) (int, error)         { return 0, nil }
func (c *stubConn) Write(b []byte) (int, error)        { return len(b), nil }
func (c *stubConn) Close() error                       { return nil }
func (c *stubConn) LocalAddr() net.Addr                { return stubAddr("127.0.0.1:7654") }
func (c *stubConn) RemoteAddr() net.Addr               { return c.remote }
func (c *stubConn) SetDeadline(_ time.Time) error      { return nil }
func (c *stubConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *stubConn) SetWriteDeadline(_ time.Time) error { return nil }

func TestRateLimitedAuthenticator_LocksOutAfterThreshold(t *testing.T) {
	stub := &stubAuthenticator{accept: false}
	limiter := NewRateLimitedAuthenticator(stub)
	// Use a real conn so per-IP rate limiting applies.
	conn := &stubConn{remote: stubAddr("127.0.0.1:9000")}

	// The first maxI2CPFailedAttempts calls must reach the delegate.
	for i := 0; i < maxI2CPFailedAttempts; i++ {
		if limiter.AuthenticateConnection(conn, "user", "bad") {
			t.Fatalf("attempt %d unexpectedly succeeded", i+1)
		}
	}
	if stub.calls != maxI2CPFailedAttempts {
		t.Fatalf("expected %d delegate calls, got %d", maxI2CPFailedAttempts, stub.calls)
	}

	// The next attempt must be refused WITHOUT touching the delegate.
	callsBefore := stub.calls
	if limiter.AuthenticateConnection(conn, "user", "bad") {
		t.Fatalf("call after lockout unexpectedly succeeded")
	}
	if stub.calls != callsBefore {
		t.Fatalf("delegate called during lockout: before=%d after=%d", callsBefore, stub.calls)
	}

	// Even valid credentials are refused while locked out.
	stub.accept = true
	if limiter.AuthenticateConnection(conn, "user", "good") {
		t.Fatalf("valid credentials accepted during lockout")
	}
	if stub.calls != callsBefore {
		t.Fatalf("delegate called with valid credentials during lockout")
	}
}

func TestRateLimitedAuthenticator_SuccessResetsCounter(t *testing.T) {
	stub := &stubAuthenticator{accept: false}
	limiter := NewRateLimitedAuthenticator(stub)
	// Use a real conn so per-IP rate limiting applies.
	conn := &stubConn{remote: stubAddr("127.0.0.1:9001")}

	// Accumulate failures below the threshold.
	for i := 0; i < maxI2CPFailedAttempts-1; i++ {
		limiter.AuthenticateConnection(conn, "user", "bad")
	}

	// One success clears the counter.
	stub.accept = true
	if !limiter.AuthenticateConnection(conn, "user", "good") {
		t.Fatalf("valid credentials rejected before lockout")
	}

	// After the reset, another maxI2CPFailedAttempts-1 failures must NOT
	// trigger a lockout — confirming the counter was cleared.
	stub.accept = false
	for i := 0; i < maxI2CPFailedAttempts-1; i++ {
		if limiter.AuthenticateConnection(conn, "user", "bad") {
			t.Fatalf("attempt %d unexpectedly succeeded", i+1)
		}
	}
	limiter.mu.Lock()
	locked := !limiter.entries["127.0.0.1"].lockoutUntil.IsZero()
	limiter.mu.Unlock()
	if locked {
		t.Fatalf("lockout armed prematurely after counter reset")
	}
}

func TestRateLimitedAuthenticator_IsolatesLockoutsPerRemote(t *testing.T) {
	stub := &stubAuthenticator{accept: false}
	limiter := NewRateLimitedAuthenticator(stub)

	// Two connections from different IPs should have isolated rate-limit counters.
	connA := &stubConn{remote: stubAddr("192.168.1.1:10001")}
	connB := &stubConn{remote: stubAddr("192.168.1.2:10002")}

	for i := 0; i < maxI2CPFailedAttempts; i++ {
		if limiter.AuthenticateConnection(connA, "user", "bad") {
			t.Fatalf("attempt %d unexpectedly succeeded", i+1)
		}
	}

	stub.accept = true
	if !limiter.AuthenticateConnection(connB, "user", "good") {
		t.Fatal("valid credentials from a different remote IP should not be locked out")
	}

	if limiter.AuthenticateConnection(connA, "user", "good") {
		t.Fatal("locked out remote unexpectedly authenticated")
	}
}

// TestRateLimitedAuthenticator_SharesRateLimitPerIP verifies the security fix:
// multiple connections from the same IP address (but different ephemeral ports)
// share a single rate-limit counter. This prevents an attacker from bypassing
// rate limits by opening N new connections, each with a fresh port and quota.
func TestRateLimitedAuthenticator_SharesRateLimitPerIP(t *testing.T) {
	stub := &stubAuthenticator{accept: false}
	limiter := NewRateLimitedAuthenticator(stub)

	// Two connections from the same IP but different ports should share rate limit.
	connA := &stubConn{remote: stubAddr("203.0.113.10:11001")}
	connB := &stubConn{remote: stubAddr("203.0.113.10:11002")}

	// Fail maxI2CPFailedAttempts-1 times on connA.
	for i := 0; i < maxI2CPFailedAttempts-1; i++ {
		limiter.AuthenticateConnection(connA, "user", "bad")
	}

	// One more failure on connB (same IP, different port) should trigger lockout.
	if limiter.AuthenticateConnection(connB, "user", "bad") {
		t.Fatal("unexpected success on final attempt")
	}

	// ConnA should now be locked out (lockout armed).
	stub.accept = true
	if limiter.AuthenticateConnection(connA, "user", "good") {
		t.Fatal("connA should be locked out due to shared IP-based rate limit")
	}

	// ConnB should also be locked out (same shared rate limit).
	if limiter.AuthenticateConnection(connB, "user", "good") {
		t.Fatal("connB should be locked out due to shared IP-based rate limit")
	}
}

// TestRateLimitedAuthenticator_NilConnBypassesRateLimit verifies that callers
// without a TCP connection (conn == nil) bypass per-IP rate limiting entirely.
// If nil-conn calls shared a single "unknown" bucket, a single local caller
// accumulating 10 failures would lock out every other in-process caller for
// five minutes — a shared-state DoS.
func TestRateLimitedAuthenticator_NilConnBypassesRateLimit(t *testing.T) {
	stub := &stubAuthenticator{accept: false}
	limiter := NewRateLimitedAuthenticator(stub)

	// Saturate the rate-limit on a real conn to ensure it is armed.
	conn := &stubConn{remote: stubAddr("127.0.0.1:9002")}
	for i := 0; i < maxI2CPFailedAttempts; i++ {
		limiter.AuthenticateConnection(conn, "user", "bad")
	}

	// nil-conn calls MUST reach the delegate regardless of any per-IP lockout.
	callsBefore := stub.calls
	limiter.Authenticate("user", "bad") // nil conn — should bypass rate limit
	if stub.calls == callsBefore {
		t.Fatal("nil-conn call should reach the delegate, not be blocked by per-IP lockout")
	}

	// nil-conn with valid credentials must succeed.
	stub.accept = true
	if !limiter.Authenticate("user", "good") {
		t.Fatal("nil-conn with valid credentials should succeed")
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
