package i2cp

import (
	"sync"
	"time"

	"github.com/go-i2p/logger"
)

// maxI2CPFailedAttempts is the number of consecutive failed authentication
// attempts allowed before the authenticator enters a lockout window. The
// threshold mirrors lib/i2pcontrol/auth.go (maxFailedAttempts) so both
// local control interfaces enforce identical brute-force resistance.
const maxI2CPFailedAttempts = 10

// i2cpFailedAttemptLockout is how long authentication stays refused after
// maxI2CPFailedAttempts consecutive failures. A successful authentication
// resets the counter. This mirrors lib/i2pcontrol/auth.go.
const i2cpFailedAttemptLockout = 5 * time.Minute

// RateLimitedAuthenticator wraps another Authenticator and refuses
// authentication attempts after too many consecutive failures. While locked
// out, Authenticate returns false without calling the delegate, which
// preserves constant-time behavior and prevents credential-stuffing /
// brute-force attacks from observing differential timing.
//
// The lockout clears either when the lockout window elapses or when a
// successful authentication occurs once the window has passed.
type RateLimitedAuthenticator struct {
	delegate Authenticator

	mu                sync.Mutex
	failedAttempts    int
	lockoutUntil      time.Time
	lastFailedAttempt time.Time
}

// NewRateLimitedAuthenticator wraps delegate with rate-limiting. If delegate
// is nil, the returned authenticator rejects every request.
func NewRateLimitedAuthenticator(delegate Authenticator) *RateLimitedAuthenticator {
	return &RateLimitedAuthenticator{delegate: delegate}
}

// Authenticate implements Authenticator. When the authenticator is in a
// lockout window, the delegate is NOT called and the method returns false.
// Otherwise the call is forwarded to the delegate; failures increment the
// counter and may arm a new lockout window.
func (r *RateLimitedAuthenticator) Authenticate(username, password string) bool {
	r.mu.Lock()
	if !r.lockoutUntil.IsZero() && time.Now().Before(r.lockoutUntil) {
		remaining := time.Until(r.lockoutUntil).Round(time.Second)
		r.mu.Unlock()
		log.WithFields(logger.Fields{
			"at":        "RateLimitedAuthenticator.Authenticate",
			"remaining": remaining.String(),
			"username":  username,
		}).Warn("i2cp_authentication_rate_limited")
		return false
	}
	delegate := r.delegate
	r.mu.Unlock()

	if delegate == nil {
		r.recordFailure()
		return false
	}

	if delegate.Authenticate(username, password) {
		r.reset()
		return true
	}
	r.recordFailure()
	return false
}

// recordFailure increments the failure counter and arms a lockout once the
// configured threshold is reached.
func (r *RateLimitedAuthenticator) recordFailure() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failedAttempts++
	r.lastFailedAttempt = time.Now()
	if r.failedAttempts >= maxI2CPFailedAttempts {
		r.lockoutUntil = time.Now().Add(i2cpFailedAttemptLockout)
		log.WithFields(logger.Fields{
			"at":       "RateLimitedAuthenticator.recordFailure",
			"attempts": r.failedAttempts,
			"lockout":  i2cpFailedAttemptLockout.String(),
		}).Warn("i2cp_authentication_lockout_triggered")
	}
}

// reset clears the failure counter and lockout window after a success.
func (r *RateLimitedAuthenticator) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failedAttempts = 0
	r.lockoutUntil = time.Time{}
}
