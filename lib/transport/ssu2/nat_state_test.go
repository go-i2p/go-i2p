package ssu2

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/go-i2p/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNatState_SetAndGet(t *testing.T) {
	ns := &natState{}
	ns.set(ssu2noise.NATCone, "1.2.3.4:5678")

	natType, valid := ns.get()
	assert.True(t, valid)
	assert.Equal(t, ssu2noise.NATCone, natType)
}

func TestNatState_GetExpired(t *testing.T) {
	ns := &natState{}
	ns.set(ssu2noise.NATSymmetric, "10.0.0.1:9000")

	// Manually force expiry by backdating the timestamp.
	ns.mu.Lock()
	ns.updated = time.Now().Add(-natResultTTL - time.Second)
	ns.mu.Unlock()

	natType, valid := ns.get()
	assert.False(t, valid)
	assert.Equal(t, ssu2noise.NATUnknown, natType)
}

func TestNatState_GetEmpty(t *testing.T) {
	ns := &natState{}
	natType, valid := ns.get()
	assert.False(t, valid)
	assert.Equal(t, ssu2noise.NATUnknown, natType)
}

func TestSaveAndLoadNATState(t *testing.T) {
	dir := t.TempDir()
	tr := &SSU2Transport{
		config:        &Config{WorkingDir: dir},
		natStateCache: &natState{},
		logger:        testLogger(),
	}

	// Set and save.
	tr.natStateCache.set(ssu2noise.NATRestricted, "5.6.7.8:1234")
	tr.saveNATState()

	// Verify file exists.
	path := filepath.Join(dir, natStateFilename)
	_, err := os.Stat(path)
	require.NoError(t, err)

	// Load into a fresh transport.
	tr2 := &SSU2Transport{
		config:        &Config{WorkingDir: dir},
		natStateCache: &natState{},
		logger:        testLogger(),
	}
	loaded := tr2.loadNATState()
	assert.True(t, loaded)

	natType, valid := tr2.natStateCache.get()
	assert.True(t, valid)
	assert.Equal(t, ssu2noise.NATRestricted, natType)
}

func TestLoadNATState_Expired(t *testing.T) {
	dir := t.TempDir()
	tr := &SSU2Transport{
		config:        &Config{WorkingDir: dir},
		natStateCache: &natState{},
		logger:        testLogger(),
	}

	// Set, backdate, and save.
	tr.natStateCache.set(ssu2noise.NATCone, "1.1.1.1:80")
	tr.natStateCache.mu.Lock()
	tr.natStateCache.updated = time.Now().Add(-natResultTTL - time.Minute)
	tr.natStateCache.mu.Unlock()
	tr.saveNATState()

	// Loading should reject the stale data.
	tr2 := &SSU2Transport{
		config:        &Config{WorkingDir: dir},
		natStateCache: &natState{},
		logger:        testLogger(),
	}
	assert.False(t, tr2.loadNATState())
}

func TestLoadNATState_NoWorkingDir(t *testing.T) {
	tr := &SSU2Transport{
		config:        &Config{WorkingDir: ""},
		natStateCache: &natState{},
		logger:        testLogger(),
	}
	assert.False(t, tr.loadNATState())
}

func TestLoadNATState_MissingFile(t *testing.T) {
	tr := &SSU2Transport{
		config:        &Config{WorkingDir: t.TempDir()},
		natStateCache: &natState{},
		logger:        testLogger(),
	}
	assert.False(t, tr.loadNATState())
}

func TestSaveNATState_NoWorkingDir(t *testing.T) {
	tr := &SSU2Transport{
		config:        &Config{WorkingDir: ""},
		natStateCache: &natState{},
		logger:        testLogger(),
	}
	// Should be a no-op, not panic.
	tr.saveNATState()
}

func TestLoadNATState_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, natStateFilename)
	require.NoError(t, os.WriteFile(path, []byte("{invalid json"), 0o600))

	tr := &SSU2Transport{
		config:        &Config{WorkingDir: dir},
		natStateCache: &natState{},
		logger:        testLogger(),
	}
	assert.False(t, tr.loadNATState())
}

func testLogger() *logger.Entry {
	return logger.WithField("test", "nat_state")
}

// TestNatState_GetExternal verifies that getExternal returns the cached
// external address string when the cache is fresh.
func TestNatState_GetExternal(t *testing.T) {
	ns := &natState{}
	ns.set(ssu2noise.NATCone, "203.0.113.10")

	ext := ns.getExternal()
	assert.Equal(t, "203.0.113.10", ext)
}

// TestNatState_GetExternal_Empty verifies that getExternal returns an empty
// string when no result has been cached.
func TestNatState_GetExternal_Empty(t *testing.T) {
	ns := &natState{}
	assert.Equal(t, "", ns.getExternal())
}

// TestNatState_GetExternal_Expired verifies that getExternal returns an empty
// string when the cached result has expired.
func TestNatState_GetExternal_Expired(t *testing.T) {
	ns := &natState{}
	ns.set(ssu2noise.NATCone, "203.0.113.10")

	// Force expiry by backdating the timestamp.
	ns.mu.Lock()
	ns.updated = time.Now().Add(-natResultTTL - time.Second)
	ns.mu.Unlock()

	assert.Equal(t, "", ns.getExternal())
}

// ---- D5 tests: PeerTest aggregator confirmation logic -------------------

// TestRecordObservation_ConfirmsAfterThreshold verifies that recordObservation
// returns a confirmed address only once the peerTestConfirmThreshold is met.
func TestRecordObservation_ConfirmsAfterThreshold(t *testing.T) {
	ns := &natState{}
	addr := "1.2.3.4:4567"

	// First observation — below threshold, no confirmation yet.
	confirmed := ns.recordObservation(addr)
	assert.Equal(t, "", confirmed, "should not confirm on first observation")

	// Second observation of the same address — meets threshold (2).
	confirmed = ns.recordObservation(addr)
	assert.Equal(t, addr, confirmed, "should confirm after peerTestConfirmThreshold observations")
}

// TestRecordObservation_DifferentAddressesNotConfirmed verifies that
// disagreeing observations (different peers report different addresses) do not
// produce a confirmation for either address independently.
func TestRecordObservation_DifferentAddressesNotConfirmed(t *testing.T) {
	ns := &natState{}

	confirmed := ns.recordObservation("1.2.3.4:4567")
	assert.Equal(t, "", confirmed)

	confirmed = ns.recordObservation("5.6.7.8:4567")
	assert.Equal(t, "", confirmed, "different addresses should not trigger confirmation")
}

// TestRecordObservation_StaleObservationsPruned verifies that observations
// older than peerTestObservationWindow are pruned and do not contribute to the
// confirmation count.
func TestRecordObservation_StaleObservationsPruned(t *testing.T) {
	ns := &natState{}
	addr := "1.2.3.4:4567"

	// Inject a stale observation directly.
	ns.mu.Lock()
	ns.observations = append(ns.observations, externalAddrObservation{
		addr: addr,
		at:   time.Now().Add(-peerTestObservationWindow - time.Second),
	})
	ns.mu.Unlock()

	// This fresh observation is the first non-stale one, so no confirmation.
	confirmed := ns.recordObservation(addr)
	assert.Equal(t, "", confirmed, "stale observation must not count towards threshold")
}

// TestRecordObservation_MixedAddressesConfirmsCorrect verifies that when one
// address reaches threshold among mixed observations, only that address is
// confirmed.
func TestRecordObservation_MixedAddressesConfirmsCorrect(t *testing.T) {
	ns := &natState{}
	target := "1.2.3.4:4567"
	noise := "9.9.9.9:9999"

	ns.recordObservation(noise)
	ns.recordObservation(target)

	confirmed := ns.recordObservation(target) // second occurrence of target
	assert.Equal(t, target, confirmed)
}
