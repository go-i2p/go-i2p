package router

import (
	"sync"
	"time"

	common "github.com/go-i2p/common/data"
)

// connectingPeerTTL bounds how long a peer may stay in the connecting set
// without its dial completing. A dial that hangs forever must not pin the
// entry indefinitely, so entries expire on read rather than relying on the
// dial path to always release them. The TTL sits comfortably above the ~30 s a
// RouterInfo lookup plus an NTCP2/SSU2 dial and handshake can take (see the
// note on TunnelManager.sendBuildMessage), so a slow-but-live dial is still
// treated as connecting rather than expiring mid-flight.
const connectingPeerTTL = 90 * time.Second

// maxConnectingPeers bounds the set so a pathological dial fan-out cannot grow
// it without limit. Past the cap the oldest entry is dropped, which keeps the
// set fresh rather than full of stale attempts.
const maxConnectingPeers = 512

// connectingTracker is the "session already connecting" tier of gateway
// selection (issue #55 requirement 1).
//
// activeSessions receives a peer only once its handshake has completed, so a
// peer we are dialing right now is invisible to selection. Without this
// tracker tier 2 is empty-by-construction: selection re-picks a peer another
// goroutine is already dialing, pays for a second dial, and often fails it.
//
// Entries expire on read (TTL) and the set is capped, so neither a hung dial
// nor a dial storm can grow it without bound.
type connectingTracker struct {
	mu      sync.Mutex
	attempt map[common.Hash]time.Time
}

func newConnectingTracker() *connectingTracker {
	return &connectingTracker{attempt: make(map[common.Hash]time.Time)}
}

// mark records that a dial to hash is in flight. Returns true if this call
// claimed the slot, false if a live attempt was already recorded.
func (t *connectingTracker) mark(hash common.Hash) bool {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.attempt == nil {
		t.attempt = make(map[common.Hash]time.Time)
	}
	if deadline, ok := t.attempt[hash]; ok && now.Before(deadline) {
		return false
	}
	t.evictStaleAndMakeRoom(now)
	t.attempt[hash] = now.Add(connectingPeerTTL)
	return true
}

// release clears a peer's in-flight marker once its dial has resolved, in
// either direction.
func (t *connectingTracker) release(hash common.Hash) {
	t.mu.Lock()
	delete(t.attempt, hash)
	t.mu.Unlock()
}

// snapshot returns the peers with a live in-flight dial, expiring stale
// entries as it goes so a tracker nobody reads cannot accumulate.
func (t *connectingTracker) snapshot() map[common.Hash]struct{} {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()

	if len(t.attempt) == 0 {
		return nil
	}
	out := make(map[common.Hash]struct{}, len(t.attempt))
	for hash, deadline := range t.attempt {
		if now.Before(deadline) {
			out[hash] = struct{}{}
			continue
		}
		delete(t.attempt, hash)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// evictStaleAndMakeRoom drops expired entries and, if still at capacity, the
// oldest live one. Caller holds t.mu.
func (t *connectingTracker) evictStaleAndMakeRoom(now time.Time) {
	for hash, deadline := range t.attempt {
		if !now.Before(deadline) {
			delete(t.attempt, hash)
		}
	}
	if len(t.attempt) < maxConnectingPeers {
		return
	}

	var oldest common.Hash
	var oldestDeadline time.Time
	first := true
	for hash, deadline := range t.attempt {
		if first || deadline.Before(oldestDeadline) {
			oldest, oldestDeadline, first = hash, deadline, false
		}
	}
	if !first {
		delete(t.attempt, oldest)
	}
}

// connectingPeerHashes returns peers whose transport dial is in flight right
// now. Wired into StdNetDB as the second selection tier: established session
// first, then a peer we are already dialing, then dial-on-demand.
func (r *Router) connectingPeerHashes() map[common.Hash]struct{} {
	if r.connecting == nil {
		return nil
	}
	return r.connecting.snapshot()
}
