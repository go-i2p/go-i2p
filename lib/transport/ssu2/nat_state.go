package ssu2

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	ssu2noise "github.com/go-i2p/go-noise/ssu2"
)

const (
	// natStateFilename is the file used to persist the last-known NAT type.
	natStateFilename = "ssu2_nat_state.json"

	// natResultTTL is the maximum age of a cached peer-test result before it
	// is considered stale and discarded.
	natResultTTL = 30 * time.Minute

	// natCleanupInterval is how often the cleanup goroutine runs.
	natCleanupInterval = 60 * time.Second

	// peerTestObservationWindow is the window within which 2+ observations
	// of the same external address are required to confirm it.
	peerTestObservationWindow = 10 * time.Minute

	// peerTestConfirmThreshold is the minimum number of matching observations
	// required to confirm an external address.
	peerTestConfirmThreshold = 2
)

// externalAddrObservation records a single PeerTest-observed external address.
type externalAddrObservation struct {
	addr string    // net.UDPAddr.String()
	at   time.Time // when the observation was received
}

// natState holds a cached NAT detection result with its timestamp.
type natState struct {
	mu       sync.RWMutex
	natType  ssu2noise.NATType
	updated  time.Time
	external string // cached external address string

	// observations accumulates external-address reports from PeerTest
	// replies to allow majority confirmation.
	observations []externalAddrObservation
}

// persistedNATState is the on-disk JSON representation of NAT state.
type persistedNATState struct {
	NATType  int    `json:"nat_type"`
	External string `json:"external_addr,omitempty"`
	Updated  int64  `json:"updated_unix"`
}

// set updates the cached NAT state.
func (ns *natState) set(natType ssu2noise.NATType, external string) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.natType = natType
	ns.external = external
	ns.updated = time.Now()
}

// get returns the cached NAT type and whether it is still valid (within TTL).
func (ns *natState) get() (ssu2noise.NATType, bool) {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	if ns.updated.IsZero() || time.Since(ns.updated) > natResultTTL {
		return ssu2noise.NATUnknown, false
	}
	return ns.natType, true
}

// getExternal returns the cached external address string from the last
// successful PeerTest. Returns an empty string if no result is cached or the
// cache has expired.
func (ns *natState) getExternal() string {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	if ns.updated.IsZero() || time.Since(ns.updated) > natResultTTL {
		return ""
	}
	return ns.external
}

// recordObservation appends a PeerTest-observed external address. Prunes
// observations older than peerTestObservationWindow before appending.
// Returns the confirmed address string if peerTestConfirmThreshold or more
// observations agree on the same address within the window; otherwise empty.
func (ns *natState) recordObservation(addr string) string {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-peerTestObservationWindow)

	// Prune stale observations.
	live := ns.observations[:0]
	for _, o := range ns.observations {
		if o.at.After(cutoff) {
			live = append(live, o)
		}
	}
	live = append(live, externalAddrObservation{addr: addr, at: now})
	ns.observations = live

	// Count occurrences per address.
	counts := make(map[string]int, len(live))
	for _, o := range live {
		counts[o.addr]++
	}
	for a, n := range counts {
		if n >= peerTestConfirmThreshold {
			return a
		}
	}
	return ""
}

// startNATCleanup spawns a goroutine that periodically calls CleanupExpired
// on the PeerTestManager and invalidates the cached NAT state when stale.
// The goroutine exits when the transport context is cancelled.
func (t *SSU2Transport) startNATCleanup() {
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		ticker := time.NewTicker(natCleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-t.ctx.Done():
				return
			case <-ticker.C:
				if t.peerTestManager != nil {
					t.peerTestManager.CleanupExpired()
				}
			}
		}
	}()
}

// saveNATState persists the current NAT state to disk. No-op if WorkingDir is
// empty (ephemeral mode).
func (t *SSU2Transport) saveNATState() {
	if t.config == nil || t.config.WorkingDir == "" || t.natStateCache == nil {
		return
	}
	t.natStateCache.mu.RLock()
	state := persistedNATState{
		NATType:  int(t.natStateCache.natType),
		External: t.natStateCache.external,
		Updated:  t.natStateCache.updated.Unix(),
	}
	t.natStateCache.mu.RUnlock()

	data, err := json.Marshal(state)
	if err != nil {
		t.logger.WithField("error", err).Warn("failed to marshal NAT state")
		return
	}
	path := filepath.Join(t.config.WorkingDir, natStateFilename)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.logger.WithField("error", err).Warn("failed to persist NAT state")
	}
}

// loadNATState reads the persisted NAT state from disk and populates the
// cache if the stored result is still within TTL. Returns true if a valid
// state was loaded.
func (t *SSU2Transport) loadNATState() bool {
	if t.config == nil || t.config.WorkingDir == "" || t.natStateCache == nil {
		return false
	}
	path := filepath.Join(t.config.WorkingDir, natStateFilename)
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var state persistedNATState
	if err := json.Unmarshal(raw, &state); err != nil {
		t.logger.WithField("error", err).Debug("invalid persisted NAT state, ignoring")
		return false
	}
	updated := time.Unix(state.Updated, 0)
	if time.Since(updated) > natResultTTL {
		return false
	}
	t.natStateCache.mu.Lock()
	t.natStateCache.natType = ssu2noise.NATType(state.NATType)
	t.natStateCache.external = state.External
	t.natStateCache.updated = updated
	t.natStateCache.mu.Unlock()
	t.logger.WithField("nat_type", ssu2noise.NATType(state.NATType).String()).
		Debug("loaded persisted NAT state")
	return true
}
