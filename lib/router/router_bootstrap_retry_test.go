// Tests for the startup reseed retry loop (reseedUntilReadyWith). These guard
// the Gap A fix: a single transient reseed failure at startup must not stop the
// router; instead the router retries with backoff until the NetDB reaches the
// peer floor, the router is stopped, or the attempt budget is exhausted.
package router

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/netdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newReseedRetryTestRouter builds a minimal Router with a real (empty) StdNetDB
// and a bootstrap config, enough to drive reseedUntilReadyWith directly.
func newReseedRetryTestRouter(t *testing.T) *Router {
	t.Helper()
	cfg := &config.RouterConfig{
		Bootstrap: &config.BootstrapConfig{
			LowPeerThreshold: 10,
		},
	}
	return &Router{
		cfg:   cfg,
		netdb: netdb.NewStdNetDB(t.TempDir()),
	}
}

// fillNetDB inserts n dummy RouterInfo entries so Size() reaches n.
func fillNetDB(t *testing.T, db *netdb.StdNetDB, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		var hash data.Hash
		hash[0] = byte(i)
		db.TestInsertRouterInfo(hash, netdb.Entry{})
	}
}

// TestReseedUntilReady_SucceedsAfterTransientFailures verifies the core Gap A
// behavior: the loop keeps retrying while reseed fails and the NetDB is below
// the floor, and returns nil once a reseed populates the NetDB past the floor.
func TestReseedUntilReady_SucceedsAfterTransientFailures(t *testing.T) {
	r := newReseedRetryTestRouter(t)
	threshold := r.emergencyReseedThreshold()
	require.Greater(t, threshold, 0)

	var calls int
	reseed := func(ctx context.Context) error {
		calls++
		// Fail the first two attempts, then populate the NetDB on the third.
		if calls < 3 {
			return errors.New("transient reseed failure")
		}
		fillNetDB(t, r.netdb, threshold)
		return nil
	}

	err := r.reseedUntilReadyWith(context.Background(), reseed, startupReseedMaxAttempts, time.Millisecond)

	assert.NoError(t, err, "should succeed once a reseed populates the NetDB")
	assert.Equal(t, 3, calls, "should stop retrying immediately after success")
	assert.GreaterOrEqual(t, r.netdb.Size(), threshold)
}

// TestReseedUntilReady_ExhaustsAttempts verifies that when every reseed fails
// and the NetDB never reaches the floor, the loop gives up after maxAttempts
// and returns the last error.
func TestReseedUntilReady_ExhaustsAttempts(t *testing.T) {
	r := newReseedRetryTestRouter(t)
	sentinel := errors.New("persistent reseed failure")

	var calls int
	reseed := func(ctx context.Context) error {
		calls++
		return sentinel
	}

	err := r.reseedUntilReadyWith(context.Background(), reseed, 3, time.Millisecond)

	require.Error(t, err, "should return an error after exhausting attempts")
	assert.Equal(t, 3, calls, "should attempt exactly maxAttempts times")
	assert.ErrorIs(t, err, sentinel, "returned error should wrap the last reseed error")
	assert.Less(t, r.netdb.Size(), r.emergencyReseedThreshold())
}

// TestReseedUntilReady_RespectsContextCancellation verifies that stopping the
// router (cancelling ctx) interrupts the retry loop promptly instead of
// burning through the whole attempt budget.
func TestReseedUntilReady_RespectsContextCancellation(t *testing.T) {
	r := newReseedRetryTestRouter(t)

	ctx, cancel := context.WithCancel(context.Background())
	var calls int
	reseed := func(ctx context.Context) error {
		calls++
		// Cancel after the first attempt so the backoff select returns early.
		if calls == 1 {
			cancel()
		}
		return errors.New("reseed failure")
	}

	err := r.reseedUntilReadyWith(ctx, reseed, startupReseedMaxAttempts, time.Second)

	require.Error(t, err, "should return an error when the router is stopped")
	assert.ErrorIs(t, err, context.Canceled, "error should reflect context cancellation")
	assert.Less(t, calls, startupReseedMaxAttempts, "should not burn through the full budget after cancellation")
}

// TestReseedUntilReady_AlreadySufficient verifies that if the NetDB is already
// at or above the floor, the loop returns nil after a single reseed call (the
// success check runs after the first attempt). In production ensureNetDBReady
// only enters the loop when Size() < threshold, so this guards the loop's own
// success condition rather than the caller's guard.
func TestReseedUntilReady_AlreadySufficient(t *testing.T) {
	r := newReseedRetryTestRouter(t)
	fillNetDB(t, r.netdb, r.emergencyReseedThreshold())

	var calls int
	reseed := func(ctx context.Context) error {
		calls++
		return nil
	}

	err := r.reseedUntilReadyWith(context.Background(), reseed, startupReseedMaxAttempts, time.Millisecond)

	assert.NoError(t, err)
	assert.Equal(t, 1, calls, "should stop after the first attempt once the NetDB is sufficient")
}
