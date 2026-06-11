package transport

import (
	"sync"
	"sync/atomic"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/util/logutil"
	"github.com/go-i2p/logger"
)

// acceptedConn is a marker type wrapping a raw connection that has been
// delivered via Accept(). It prevents the connection from being promoted
// to a session (which would create dual ownership), since the Accept()
// consumer now owns the socket lifecycle.
type acceptedConn struct {
	Value interface{}
}

// SessionRegistry manages the ownership invariant for transport session maps,
// eliminating duplication between NTCP2Transport and SSU2Transport.
//
// Session Map Ownership Invariant (X-3 fix):
// Each peerHash in the sessions map has EXACTLY ONE owner at any given time:
//   - net.Conn (or transport-specific conn type): owned by trackInbound,
//     transferable to Accept or promotion
//   - acceptedConn: owned by the Accept() consumer; MUST NOT be promoted (dual-ownership)
//   - Session: owned by the session lifecycle; cleanup via Remove
//
// State transitions use CompareAndSwap to prevent race conditions:
//   - rawConn → acceptedConn: tracked but wrapped to prevent promotion
//   - rawConn → Session: CAS in Promote (after successful session creation)
//
// If inbound Accept CAS fails, a concurrent GetSession has already promoted the connection;
// do not deliver to Accept (ownership already transferred to the session).
// If promotion CAS fails, another goroutine won the race; close the duplicate session.
type SessionRegistry struct {
	// sessions map[RouterHash]<value> where value can be:
	//  - net.Conn (raw inbound connection after tracking, before Accept or promotion)
	//  - acceptedConn (wrapper marking ownership transferred to Accept() consumer - MUST NOT promote)
	//  - Session (fully established session)
	sessions sync.Map

	// sessionCount tracks active sessions (used for O(1) SessionCount queries)
	sessionCount int32

	// isShuttingDown is set during Close() for visibility
	isShuttingDown int32

	// logger is used for diagnostic output
	logger *logger.Entry
}

// NewSessionRegistry creates a new session registry with the given logger.
func NewSessionRegistry(logger *logger.Entry) *SessionRegistry {
	return &SessionRegistry{
		logger: logger,
	}
}

// TrackInboundConnection attempts to track a raw inbound connection.
// Returns true if this is a fresh connection (first time seeing this peer).
// Returns false if a duplicate was detected (another connection from same peer already exists).
//
// On duplicate, the connection is NOT added to the registry; the caller should
// handle closing it. The session slot is unreserved by the caller.
//
// Note: Session count should already be incremented by CheckLimitAndIncrement
// before this method is called.
func (sr *SessionRegistry) TrackInboundConnection(conn interface{}, peerHash data.Hash) bool {
	_, loaded := sr.sessions.LoadOrStore(peerHash, conn)
	return !loaded
}

// MarkAccepted marks a tracked connection as delivered to Accept().
// This prevents the connection from being promoted to a session (dual-ownership protection).
//
// Returns true if the mark succeeded, false if the connection was already promoted
// or removed (in which case no accept should be delivered).
func (sr *SessionRegistry) MarkAccepted(peerHash data.Hash, original interface{}) bool {
	marker := &acceptedConn{Value: original}
	return sr.sessions.CompareAndSwap(peerHash, original, marker)
}

// PromoteOptions configures promotion behavior.
type PromoteOptions struct {
	// PreflightCheck is called after CAS succeeds but before callback/workers start.
	// Used for logging/validation. Can be nil.
	PreflightCheck func() error

	// SetCallback is called to set the session's cleanup callback.
	SetCallback func(callback func())

	// StartWorkers starts the session's background workers.
	// Called only after CAS succeeds and callback is set.
	StartWorkers func()
}

// Promote attempts to promote a raw connection to a session via CompareAndSwap.
// The newSession must be the session object to store in the registry.
// Returns (session, true) if promotion succeeded, (nil, false) if it lost the race.
//
// On promotion success:
//  1. PreflightCheck is called (if provided) for validation
//  2. SetCallback is called to install the cleanup callback
//  3. StartWorkers is called to begin session's background work
//
// On promotion failure (race lost):
//   - The caller is responsible for closing the session and connection
func (sr *SessionRegistry) Promote(peerHash data.Hash, original interface{}, newSession interface{}, opts PromoteOptions) (interface{}, bool) {
	// Defense-in-depth: refuse to promote an acceptedConn (dual-ownership protection)
	if _, ok := original.(*acceptedConn); ok {
		sr.logger.WithField("peer_hash", logutil.HashPrefixPlain(peerHash)).
			Error("Refusing to promote acceptedConn (already delivered to Accept)")
		return nil, false
	}

	// Attempt CAS: replace the raw conn with the session
	if !sr.sessions.CompareAndSwap(peerHash, original, newSession) {
		// CAS failed: another goroutine won the promotion race
		return nil, false
	}

	// CAS succeeded! We own the session now. Run the setup callbacks.
	if opts.PreflightCheck != nil {
		if err := opts.PreflightCheck(); err != nil {
			sr.logger.WithField("peer_hash", logutil.HashPrefixPlain(peerHash)).
				WithError(err).Error("Preflight check failed after CAS")
		}
	}

	// Install cleanup callback BEFORE starting workers (HIGH-8.2 fix)
	if opts.SetCallback != nil {
		opts.SetCallback(func() {
			sr.Remove(peerHash)
		})
	}

	// Start workers NOW that we've won the promotion race
	if opts.StartWorkers != nil {
		opts.StartWorkers()
	}

	return newSession, true
}

// Remove removes a session from the registry and decrements the session count safely.
// Called when a session closes via its cleanup callback.
func (sr *SessionRegistry) Remove(peerHash data.Hash) {
	if _, loaded := sr.sessions.LoadAndDelete(peerHash); loaded {
		sr.DecrementCountSafe()
	}
}

// DecrementCountSafe performs a safe atomic decrement with runtime assertions.
// Catches double-decrements and other accounting errors at runtime.
// If the counter would go negative, logs error and force-resets to 0 (safety net).
func (sr *SessionRegistry) DecrementCountSafe() {
	for {
		current := atomic.LoadInt32(&sr.sessionCount)
		if current <= 0 {
			sr.logger.WithField("current_count", current).
				Error("CRITICAL: sessionCount would go negative on decrement (accounting bug detected)")
			// Force-reset as safety net to prevent persistent negative state
			atomic.StoreInt32(&sr.sessionCount, 0)
			return
		}
		if atomic.CompareAndSwapInt32(&sr.sessionCount, current, current-1) {
			return
		}
		// CAS failed, retry (another goroutine won the race)
	}
}

// Count returns the current session count.
func (sr *SessionRegistry) Count() int32 {
	return atomic.LoadInt32(&sr.sessionCount)
}

// IncrementCount safely increments the session count.
// Called when a new session is promoted to the map.
func (sr *SessionRegistry) IncrementCount() {
	atomic.AddInt32(&sr.sessionCount, 1)
}

// CheckLimitAndIncrement atomically checks if the count is below maxLimit and increments if so.
// Returns (nil, true) if increment succeeded, (ErrLimitReached, false) if limit reached.
func (sr *SessionRegistry) CheckLimitAndIncrement(maxLimit int) bool {
	for {
		current := atomic.LoadInt32(&sr.sessionCount)
		if int(current) >= maxLimit {
			return false
		}
		// Atomically increment
		if atomic.CompareAndSwapInt32(&sr.sessionCount, current, current+1) {
			return true
		}
		// CAS failed, retry
	}
}

// SetShutdown marks the registry as shutting down.
// Used for visibility during Close().
func (sr *SessionRegistry) SetShutdown() {
	atomic.StoreInt32(&sr.isShuttingDown, 1)
}

// IsShuttingDown returns true if the registry is shutting down.
func (sr *SessionRegistry) IsShuttingDown() bool {
	return atomic.LoadInt32(&sr.isShuttingDown) != 0
}

// GetSessions returns a snapshot of all active sessions in the registry.
// Used for iteration/cleanup on shutdown.
func (sr *SessionRegistry) GetSessions() []interface{} {
	var sessions []interface{}
	sr.sessions.Range(func(_, value interface{}) bool {
		// Skip acceptedConn markers (those are owned by Accept consumers)
		if _, ok := value.(*acceptedConn); !ok {
			sessions = append(sessions, value)
		}
		return true
	})
	return sessions
}

// Load retrieves a session from the registry by hash.
// Returns (value, exists).
func (sr *SessionRegistry) Load(peerHash data.Hash) (interface{}, bool) {
	return sr.sessions.Load(peerHash)
}

// LoadOrStore atomically loads or stores a value in the registry.
// Returns (value, loaded) where value is the stored or loaded value,
// and loaded is true if the value was already present.
func (sr *SessionRegistry) LoadOrStore(peerHash data.Hash, value interface{}) (interface{}, bool) {
	actual, loaded := sr.sessions.LoadOrStore(peerHash, value)
	if !loaded {
		// Fresh store - increment the count
		sr.IncrementCount()
	}
	return actual, loaded
}

// Delete removes an entry from the registry.
func (sr *SessionRegistry) Delete(peerHash data.Hash) {
	sr.sessions.Delete(peerHash)
}

// Range iterates over all entries in the registry, passing the raw sync.Map key/value pairs.
// The callback receives (key, value) as interface{} types for backwards compatibility with tests.
// Most code should prefer RangeWithHash which provides typed Hash parameters.
func (sr *SessionRegistry) Range(callback func(key, value interface{}) bool) {
	sr.sessions.Range(callback)
}

// RangeWithHash iterates over all entries in the registry with typed Hash parameters.
// The callback receives (hash, value) and should return true to continue iteration.
func (sr *SessionRegistry) RangeWithHash(callback func(hash data.Hash, value interface{}) bool) {
	sr.sessions.Range(func(k, v interface{}) bool {
		if hash, ok := k.(data.Hash); ok {
			return callback(hash, v)
		}
		return true
	})
}

// Store stores a value in the registry without atomically checking for existing entries.
// This is primarily for testing. Prefer LoadOrStore for production code.
func (sr *SessionRegistry) Store(peerHash data.Hash, value interface{}) {
	sr.sessions.Store(peerHash, value)
}

// StoreWithCount stores a value and increments the session count.
// This is a test-only helper that ensures session count stays in sync when directly storing test entries.
func (sr *SessionRegistry) StoreWithCount(peerHash data.Hash, value interface{}) {
	_, loaded := sr.sessions.LoadOrStore(peerHash, value)
	if !loaded {
		// Fresh entry: increment count
		atomic.AddInt32(&sr.sessionCount, 1)
	}
}

// CompareAndSwap atomically swaps the old value with the new value if the current value matches old.
// Returns true if the swap succeeded, false otherwise.
// This is primarily for testing. Prefer Promote for production code.
func (sr *SessionRegistry) CompareAndSwap(peerHash data.Hash, old, new interface{}) bool {
	return sr.sessions.CompareAndSwap(peerHash, old, new)
}
