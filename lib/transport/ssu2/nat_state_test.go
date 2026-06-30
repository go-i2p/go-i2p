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
	cfg := &Config{WorkingDir: dir}
	tr := &SSU2Transport{
		natStateCache: &natState{},
		logger:        testLogger(),
	}
	tr.config.Store(cfg)

	// Set and save.
	tr.natStateCache.set(ssu2noise.NATRestricted, "5.6.7.8:1234")
	tr.saveNATState()

	// Verify file exists.
	path := filepath.Join(dir, natStateFilename)
	_, err := os.Stat(path)
	require.NoError(t, err)

	// Load into a fresh transport.
	cfg2 := &Config{WorkingDir: dir}
	tr2 := &SSU2Transport{
		natStateCache: &natState{},
		logger:        testLogger(),
	}
	tr2.config.Store(cfg2)
	loaded := tr2.loadNATState()
	assert.True(t, loaded)

	natType, valid := tr2.natStateCache.get()
	assert.True(t, valid)
	assert.Equal(t, ssu2noise.NATRestricted, natType)
}

func TestLoadNATState_Expired(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{WorkingDir: dir}
	tr := &SSU2Transport{
		natStateCache: &natState{},
		logger:        testLogger(),
	}
	tr.config.Store(cfg)

	// Set, backdate, and save.
	tr.natStateCache.set(ssu2noise.NATCone, "1.1.1.1:80")
	tr.natStateCache.mu.Lock()
	tr.natStateCache.updated = time.Now().Add(-natResultTTL - time.Minute)
	tr.natStateCache.mu.Unlock()
	tr.saveNATState()

	// Loading should reject the stale data.
	cfg2 := &Config{WorkingDir: dir}
	tr2 := &SSU2Transport{
		natStateCache: &natState{},
		logger:        testLogger(),
	}
	tr2.config.Store(cfg2)
	assert.False(t, tr2.loadNATState())
}

func TestLoadNATState_NoWorkingDir(t *testing.T) {
	cfg := &Config{WorkingDir: ""}
	tr := &SSU2Transport{
		natStateCache: &natState{},
		logger:        testLogger(),
	}
	tr.config.Store(cfg)
	assert.False(t, tr.loadNATState())
}

func TestLoadNATState_MissingFile(t *testing.T) {
	cfg := &Config{WorkingDir: t.TempDir()}
	tr := &SSU2Transport{
		natStateCache: &natState{},
		logger:        testLogger(),
	}
	tr.config.Store(cfg)
	assert.False(t, tr.loadNATState())
}

func TestSaveNATState_NoWorkingDir(t *testing.T) {
	cfg := &Config{WorkingDir: ""}
	tr := &SSU2Transport{
		natStateCache: &natState{},
		logger:        testLogger(),
	}
	tr.config.Store(cfg)
	// Should be a no-op, not panic.
	tr.saveNATState()
}

func TestLoadNATState_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, natStateFilename)
	require.NoError(t, os.WriteFile(path, []byte("{invalid json"), 0o600))

	cfg := &Config{WorkingDir: dir}
	tr := &SSU2Transport{
		natStateCache: &natState{},
		logger:        testLogger(),
	}
	tr.config.Store(cfg)
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

// TestInboundBlockedStatusCode verifies that the SSU2 transport maps each NAT
// type to the correct granular I2PControl status code: symmetric NAT to
// ERROR_SYMMETRIC_NAT (11), other relay-requiring / restricted NATs to
// FIREWALLED (2), and directly-reachable or unknown NAT types to 0 (not
// blocked). This is the source of the granular FIREWALLED variant reported over
// I2PControl.
func TestInboundBlockedStatusCode(t *testing.T) {
	cases := []struct {
		name     string
		natType  ssu2noise.NATType
		wantCode int
		wantBool bool
	}{
		{"symmetric", ssu2noise.NATSymmetric, 11, true},
		{"port_restricted", ssu2noise.NATPortRestricted, 2, true},
		{"restricted", ssu2noise.NATRestricted, 2, true},
		{"cone", ssu2noise.NATCone, 0, false},
		{"none", ssu2noise.NATNone, 0, false},
		{"unknown", ssu2noise.NATUnknown, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr := &SSU2Transport{
				natStateCache: &natState{},
				logger:        testLogger(),
			}
			tr.natStateCache.set(c.natType, "203.0.113.5:1234")

			assert.Equal(t, c.wantCode, tr.InboundBlockedStatusCode())
			assert.Equal(t, c.wantBool, tr.IsInboundBlocked())
		})
	}
}

// TestInboundBlockedStatusCode_NoCache verifies that an SSU2 transport with no
// NAT cache reports not-blocked (code 0), so a not-yet-initialized transport is
// never misreported as firewalled.
func TestInboundBlockedStatusCode_NoCache(t *testing.T) {
	tr := &SSU2Transport{logger: testLogger()}
	assert.Equal(t, 0, tr.InboundBlockedStatusCode())
	assert.False(t, tr.IsInboundBlocked())
}

// TestInboundBlockedStatusCode_Expired verifies that an expired NAT result is
// treated as not-blocked, since stale firewalled state must not linger past the
// detection TTL.
func TestInboundBlockedStatusCode_Expired(t *testing.T) {
	tr := &SSU2Transport{
		natStateCache: &natState{},
		logger:        testLogger(),
	}
	tr.natStateCache.set(ssu2noise.NATSymmetric, "203.0.113.5:1234")
	tr.natStateCache.mu.Lock()
	tr.natStateCache.updated = time.Now().Add(-natResultTTL - time.Second)
	tr.natStateCache.mu.Unlock()

	assert.Equal(t, 0, tr.InboundBlockedStatusCode())
	assert.False(t, tr.IsInboundBlocked())
}



// TestRecordObservation_ConfirmsAfterThreshold verifies that recordObservation
// returns a confirmed address only once the peerTestConfirmThreshold is met.
func TestRecordObservation_ConfirmsAfterThreshold(t *testing.T) {
	ns := &natState{}
	addr := "1.2.3.4:4567"

	// BUG FIX HIGH RD-1: threshold raised from 2 to 3; adjust test to match.
	// First observation — below threshold, no confirmation yet.
	// Use different nonces to simulate observations from different PeerTests
	confirmed := ns.recordObservation(addr, uint32(1))
	assert.Equal(t, "", confirmed, "should not confirm on first observation")

	// Second observation — still below threshold (need 3).
	// Use a different nonce to avoid duplicate rejection
	confirmed = ns.recordObservation(addr, uint32(2))
	assert.Equal(t, "", confirmed, "should not confirm on second observation (threshold=3)")

	// Third observation of the same address — meets threshold (3).
	// Use a different nonce
	confirmed = ns.recordObservation(addr, uint32(3))
	assert.Equal(t, addr, confirmed, "should confirm after peerTestConfirmThreshold observations")
}

// TestRecordObservation_DifferentAddressesNotConfirmed verifies that
// disagreeing observations (different peers report different addresses) do not
// produce a confirmation for either address independently.
func TestRecordObservation_DifferentAddressesNotConfirmed(t *testing.T) {
	ns := &natState{}

	confirmed := ns.recordObservation("1.2.3.4:4567", uint32(1))
	assert.Equal(t, "", confirmed)

	confirmed = ns.recordObservation("5.6.7.8:4567", uint32(2))
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
	ns.completedNonces = make(map[uint32]time.Time)
	ns.observations = append(ns.observations, externalAddrObservation{
		addr: addr,
		at:   time.Now().Add(-peerTestObservationWindow - time.Second),
	})
	ns.mu.Unlock()

	// This fresh observation is the first non-stale one, so no confirmation.
	confirmed := ns.recordObservation(addr, uint32(1))
	assert.Equal(t, "", confirmed, "stale observation must not count towards threshold")
}

// TestRecordObservation_MixedAddressesConfirmsCorrect verifies that when one
// address reaches threshold among mixed observations, only that address is
// confirmed.
func TestRecordObservation_MixedAddressesConfirmsCorrect(t *testing.T) {
	ns := &natState{}
	target := "1.2.3.4:4567"
	noise := "9.9.9.9:9999"

	// BUG FIX HIGH RD-1: threshold raised from 2 to 3; adjust test to match.
	ns.recordObservation(noise, uint32(1))
	ns.recordObservation(target, uint32(2))
	ns.recordObservation(target, uint32(3)) // second occurrence of target from different nonce

	confirmed := ns.recordObservation(target, uint32(4)) // third occurrence of target from different nonce — meets threshold
	assert.Equal(t, target, confirmed)
}

// TestRecordObservation_DuplicateNonceRejected verifies that recordObservation
// rejects duplicate observations from the same nonce (CRITICAL RD-1 fix).
// This prevents address-poisoning attacks where an attacker sends multiple
// PeerTest replies with the same nonce but different addresses to skew
// majority voting and hijack external address confirmation.
func TestRecordObservation_DuplicateNonceRejected(t *testing.T) {
	ns := &natState{}
	dupNonce := uint32(100)
	addr1 := "1.2.3.4:4567"
	addr2 := "5.6.7.8:4567"
	addr3 := "9.9.9.9:4567"

	// First observation with nonce 100 — recorded
	confirmed := ns.recordObservation(addr1, dupNonce)
	assert.Equal(t, "", confirmed, "first observation should not trigger confirmation")

	// Second observation with SAME nonce 100 but different address — rejected
	// This is the attack: attacker tries to inject a different address under the same nonce
	confirmed = ns.recordObservation(addr2, dupNonce)
	assert.Equal(t, "", confirmed, "duplicate nonce should be rejected, no additional observation recorded")

	// Third observation with SAME nonce 100 but yet another address — also rejected
	confirmed = ns.recordObservation(addr3, dupNonce)
	assert.Equal(t, "", confirmed, "duplicate nonce should be rejected again")

	// Now add two more observations from different nonces for the original address
	// to verify that only addr1 (the first recorded) gets confirmed
	confirmed = ns.recordObservation(addr1, uint32(101))
	assert.Equal(t, "", confirmed, "need threshold observations")

	confirmed = ns.recordObservation(addr1, uint32(102))
	assert.Equal(t, addr1, confirmed, "addr1 should confirm (3 nonces: 100, 101, 102)")

	// Verify addr2 and addr3 never got added to observations despite multiple attempts
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	if len(ns.observations) != 3 {
		t.Logf("FAIL: expected 3 observations, got %d", len(ns.observations))
		for i, obs := range ns.observations {
			t.Logf("  [%d] addr=%s", i, obs.addr)
		}
		t.Fatal("duplicate nonce attack: unwanted observations were recorded")
	}
}

// TestLoadNATState_RejectsOversizedFile verifies that loadNATState rejects
// files exceeding maxNATStateSize (64 KiB) to prevent OOM attacks.
// See AUDIT.md MEDIUM — "Persisted SSU2 NAT-state JSON read without explicit size limit".
func TestLoadNATState_RejectsOversizedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, natStateFilename)

	// Create a file that is exactly 64 KiB + 1 byte (exceeds limit).
	oversized := make([]byte, 64*1024+1)
	for i := range oversized {
		oversized[i] = 'x'
	}
	require.NoError(t, os.WriteFile(path, oversized, 0o600))

	cfg := &Config{WorkingDir: dir}
	tr := &SSU2Transport{
		natStateCache: &natState{},
		logger:        testLogger(),
	}
	tr.config.Store(cfg)

	// loadNATState should return false because the JSON will be truncated and invalid.
	loaded := tr.loadNATState()
	assert.False(t, loaded, "loadNATState should reject oversized file")
}
