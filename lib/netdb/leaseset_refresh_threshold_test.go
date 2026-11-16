package netdb

import (
	"sync/atomic"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/lease_set"
	"github.com/stretchr/testify/assert"
)

// seedCachedLeaseSet inserts a LeaseSet into the in-memory cache with an
// explicit expiry, bypassing disk, so refresh-ahead can be exercised
// deterministically.
func seedCachedLeaseSet(db *StdNetDB, hash common.Hash, expiry time.Time) {
	ls := &lease_set.LeaseSet{}
	db.lsCache.put(hash, Entry{LeaseSet: ls})
	db.lsCache.setExpiry(hash, expiry)
}

// TestLeaseSetRefreshThreshold_StoresValue is the C1 guard that the operator's
// netdb.lease_set_refresh_threshold reaches the StdNetDB. Before this fix the
// value was validated but never reached behavior.
func TestLeaseSetRefreshThreshold_StoresValue(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	defer db.Stop()

	db.SetLeaseSetRefreshThreshold(90 * time.Second)
	assert.Equal(t, 90*time.Second, db.GetLeaseSetRefreshThreshold())

	db.SetLeaseSetRefreshThreshold(0)
	assert.Zero(t, db.GetLeaseSetRefreshThreshold(), "zero disables refresh-ahead")
}

// TestLeaseSetRefreshAhead_FiresNearExpiry verifies that a cache hit whose
// remaining lifetime is below the threshold schedules a background network
// refresh, while the still-valid entry is served immediately.
func TestLeaseSetRefreshAhead_FiresNearExpiry(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	defer db.Stop()

	var hash common.Hash
	hash[0] = 0x11

	// Cached LeaseSet expiring in 30s; threshold 2min → within threshold.
	seedCachedLeaseSet(db, hash, time.Now().Add(30*time.Second))

	var calls atomic.Int32
	refreshed := make(chan struct{}, 1)
	db.SetLeaseSetNetworkLookup(func(h common.Hash) bool {
		if calls.Add(1) == 1 {
			select {
			case refreshed <- struct{}{}:
			default:
			}
		}
		return true
	})
	db.SetLeaseSetRefreshThreshold(2 * time.Minute)

	ch := db.GetLeaseSet(hash)
	// The valid entry must be served immediately (not blocked on the refresh).
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("valid cached LeaseSet should be served immediately")
	}

	select {
	case <-refreshed:
	case <-time.After(2 * time.Second):
		t.Fatal("refresh-ahead should schedule a background network refresh near expiry")
	}
}

// TestLeaseSetRefreshAhead_SkipsWhenHealthy verifies no refresh is scheduled
// when the cached LeaseSet still has more lifetime than the threshold.
func TestLeaseSetRefreshAhead_SkipsWhenHealthy(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	defer db.Stop()

	var hash common.Hash
	hash[0] = 0x22

	// Expiring in 30min; threshold 2min → healthy, no refresh.
	seedCachedLeaseSet(db, hash, time.Now().Add(30*time.Minute))

	var calls atomic.Int32
	db.SetLeaseSetNetworkLookup(func(h common.Hash) bool {
		calls.Add(1)
		return true
	})
	db.SetLeaseSetRefreshThreshold(2 * time.Minute)

	ch := db.GetLeaseSet(hash)
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("healthy cached LeaseSet should be served")
	}

	// Give any (incorrect) background refresh a moment to fire.
	time.Sleep(200 * time.Millisecond)
	assert.Zero(t, calls.Load(), "no refresh expected while the LeaseSet is healthy")
}

// TestLeaseSetRefreshAhead_RateLimited verifies repeated lookups of the same
// near-expiry LeaseSet schedule at most one refresh per threshold window.
func TestLeaseSetRefreshAhead_RateLimited(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	defer db.Stop()

	var hash common.Hash
	hash[0] = 0x33

	seedCachedLeaseSet(db, hash, time.Now().Add(30*time.Second))

	var calls atomic.Int32
	db.SetLeaseSetNetworkLookup(func(h common.Hash) bool {
		calls.Add(1)
		return true
	})
	// Large threshold window so the rate limiter suppresses repeats.
	db.SetLeaseSetRefreshThreshold(10 * time.Minute)

	for i := 0; i < 5; i++ {
		ch := db.GetLeaseSet(hash)
		select {
		case <-ch:
		case <-time.After(2 * time.Second):
			t.Fatal("cached LeaseSet should be served")
		}
	}

	time.Sleep(300 * time.Millisecond)
	assert.Equal(t, int32(1), calls.Load(), "repeated near-expiry lookups should refresh at most once per window")
}
