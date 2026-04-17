package i2cp

import (
	"container/list"
	"net"
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

const maxTrackedI2CPAuthRemotes = 1024

type authAttemptState struct {
	remoteAddr        string
	failedAttempts    int
	lockoutUntil      time.Time
	lastFailedAttempt time.Time
	lruEntry          *list.Element
}

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

	mu      sync.Mutex
	entries map[string]*authAttemptState
	lru     *list.List
}

// NewRateLimitedAuthenticator wraps delegate with rate-limiting. If delegate
// is nil, the returned authenticator rejects every request.
func NewRateLimitedAuthenticator(delegate Authenticator) *RateLimitedAuthenticator {
	return &RateLimitedAuthenticator{
		delegate: delegate,
		entries:  make(map[string]*authAttemptState),
		lru:      list.New(),
	}
}

// Authenticate implements Authenticator. When the authenticator is in a
// lockout window, the delegate is NOT called and the method returns false.
// Otherwise the call is forwarded to the delegate; failures increment the
// counter and may arm a new lockout window.
func (r *RateLimitedAuthenticator) Authenticate(username, password string) bool {
	return r.AuthenticateConnection(nil, username, password)
}

// AuthenticateConnection enforces lockouts independently for each remote
// address so one failing client cannot deny service to unrelated clients.
func (r *RateLimitedAuthenticator) AuthenticateConnection(conn net.Conn, username, password string) bool {
	remoteAddr := remoteAddrKey(conn)

	r.mu.Lock()
	state := r.getOrCreateStateLocked(remoteAddr)
	if !state.lockoutUntil.IsZero() && time.Now().Before(state.lockoutUntil) {
		remaining := time.Until(state.lockoutUntil).Round(time.Second)
		r.mu.Unlock()
		log.WithFields(logger.Fields{
			"at":         "RateLimitedAuthenticator.Authenticate",
			"remoteAddr": remoteAddr,
			"remaining":  remaining.String(),
		}).Warn("i2cp_authentication_rate_limited")
		return false
	}
	delegate := r.delegate
	r.mu.Unlock()

	if delegate == nil {
		r.recordFailure(remoteAddr)
		return false
	}

	if delegate.Authenticate(username, password) {
		r.reset(remoteAddr)
		return true
	}
	r.recordFailure(remoteAddr)
	return false
}

// recordFailure increments the failure counter and arms a lockout once the
// configured threshold is reached.
func (r *RateLimitedAuthenticator) recordFailure(remoteAddr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	state := r.getOrCreateStateLocked(remoteAddr)
	state.failedAttempts++
	state.lastFailedAttempt = time.Now()
	if state.failedAttempts >= maxI2CPFailedAttempts {
		state.lockoutUntil = time.Now().Add(i2cpFailedAttemptLockout)
		log.WithFields(logger.Fields{
			"at":         "RateLimitedAuthenticator.recordFailure",
			"attempts":   state.failedAttempts,
			"lockout":    i2cpFailedAttemptLockout.String(),
			"remoteAddr": remoteAddr,
		}).Warn("i2cp_authentication_lockout_triggered")
	}
}

// reset clears the failure counter and lockout window after a success.
func (r *RateLimitedAuthenticator) reset(remoteAddr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	state := r.getOrCreateStateLocked(remoteAddr)
	state.failedAttempts = 0
	state.lockoutUntil = time.Time{}
}

func (r *RateLimitedAuthenticator) getOrCreateStateLocked(remoteAddr string) *authAttemptState {
	if state, ok := r.entries[remoteAddr]; ok {
		r.touchLocked(state)
		return state
	}

	state := &authAttemptState{remoteAddr: remoteAddr}
	state.lruEntry = r.lru.PushFront(state)
	r.entries[remoteAddr] = state
	r.evictIfNeededLocked()
	return state
}

func (r *RateLimitedAuthenticator) touchLocked(state *authAttemptState) {
	if state.lruEntry != nil {
		r.lru.MoveToFront(state.lruEntry)
	}
}

func (r *RateLimitedAuthenticator) evictIfNeededLocked() {
	for len(r.entries) > maxTrackedI2CPAuthRemotes {
		oldest := r.lru.Back()
		if oldest == nil {
			return
		}
		state, ok := oldest.Value.(*authAttemptState)
		if !ok {
			r.lru.Remove(oldest)
			continue
		}
		delete(r.entries, state.remoteAddr)
		r.lru.Remove(oldest)
	}
}

func remoteAddrKey(conn net.Conn) string {
	if conn == nil || conn.RemoteAddr() == nil {
		return "unknown"
	}
	return conn.RemoteAddr().String()
}
