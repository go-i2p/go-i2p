// Issue #55: build-outcome classification, distinct terminal errors, and the
// counters that make a non-converging pool diagnosable without a debug log.
//
// Every test here fails against the pre-fix tree, and says so: before this
// change the pool classified failures by matching err.Error() against prose,
// an exhausted retry loop returned one undifferentiated
// "tunnel build failed after 3 retries" for both failure modes, and no counter
// existed at all.

package tunnel

import (
	"errors"
	"fmt"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBuildOutcome_SentinelClassificationIsNotProseBased proves classification
// travels by errors.Is, not by string matching. The error text here
// deliberately contains none of the prose markers the old classifier looked
// for, so a prose-only implementation cannot possibly recognise it.
//
// Pre-fix this fails: isGatewayOnlyFailure matched a fixed list of substrings
// and returns false for this error, penalising all three hops.
func TestBuildOutcome_SentinelClassificationIsNotProseBased(t *testing.T) {
	pool := NewTunnelPool(&MockPeerSelector{})
	defer pool.Stop()

	gateway := makePeerHash(0xD1)
	middle := makePeerHash(0xD2)
	end := makePeerHash(0xD3)

	// Text carries no "no transports available" / "failed to dial" marker.
	sentinelErr := fmt.Errorf("gateway %x refused the handshake: %w",
		gateway[:4], ErrGatewayUnreachable)

	require.True(t, IsGatewayUnreachable(sentinelErr),
		"a wrapped ErrGatewayUnreachable must classify via errors.Is")
	assert.False(t, containsAnySubstring(sentinelErr.Error(), gatewayUnreachableTerms...),
		"the error text must contain no prose marker, so this test proves sentinel classification")

	excluded := pool.extractAndMarkFailedPeersForError(&BuildTunnelResult{
		PeerHashes: []common.Hash{gateway, middle, end},
	}, sentinelErr)

	assert.Len(t, excluded, 3, "all hops still excluded for path diversity")
	assert.True(t, pool.IsPeerFailed(gateway), "the gateway is penalised")
	assert.False(t, pool.IsPeerFailed(middle), "uncontacted middle hop must not be penalised")
	assert.False(t, pool.IsPeerFailed(end), "uncontacted end hop must not be penalised")
}

// TestBuildOutcome_DialFailureAndRefusalDrawDifferentPenalties is requirement 2
// of #55: "we could not dial this peer" and "this peer refused the build" are
// different evidence and must not be punished the same way. A dial failure says
// something about our path to one address; a refusal says something about the
// peer.
//
// Pre-fix this fails: both reasons resolved to hardFailureCooldown (10 min)
// because both matched the same prose list, so a transient path problem burned
// a good peer for ten minutes.
func TestBuildOutcome_DialFailureAndRefusalDrawDifferentPenalties(t *testing.T) {
	dialReason := classifyTunnelBuildFailureReason(
		fmt.Errorf("could not reach gateway: %w", ErrGatewayUnreachable))
	refusedReason := classifyTunnelBuildFailureReason(
		fmt.Errorf("hop rejected the build: %w", ErrBuildRefused))

	require.NotEqual(t, dialReason, refusedReason,
		"a dial failure and a refusal must not classify to the same reason")

	dialCooldown := baseCooldownForFailureReason(dialReason)
	refusedCooldown := baseCooldownForFailureReason(refusedReason)

	assert.Less(t, dialCooldown, refusedCooldown,
		"an unreachable gateway must cool down for less time than a peer that refused us; "+
			"got dial=%v refused=%v", dialCooldown, refusedCooldown)

	// Both cooldowns stay bounded and positive: the penalty is a cooldown, not
	// a sticky failure.
	assert.Greater(t, dialCooldown, time.Duration(0))
	assert.Greater(t, refusedCooldown, time.Duration(0))
}

// TestBuildOutcome_TerminalErrorsDistinguishFailureModes is requirement 4 of
// #55: the retry loop must end with a *distinct* error for "no dialable
// candidates exist" versus "builds were attempted and refused", because both
// previously collapsed into `no transports available` and were undiagnosable.
//
// Pre-fix this fails: executeBuildWithRetry returned
// oops.Errorf("tunnel build failed after %d retries", maxRetries) with no
// sentinel, so neither errors.Is check could hold.
func TestBuildOutcome_TerminalErrorsDistinguishFailureModes(t *testing.T) {
	hops := []common.Hash{makePeerHash(0xE1), makePeerHash(0xE2), makePeerHash(0xE3)}

	t.Run("all attempts undialable", func(t *testing.T) {
		pool := newIssue55Pool()
		defer pool.Stop()
		pool.SetTunnelBuilder(&callbackBuilder{
			callback: func(BuildTunnelRequest) (*BuildTunnelResult, error) {
				return &BuildTunnelResult{PeerHashes: hops},
					fmt.Errorf("no session to gateway: %w", ErrGatewayUnreachable)
			},
		})

		req := newBuildTunnelRequest(3, false)
		_, err := pool.executeBuildWithRetry(&req)
		require.Error(t, err)

		assert.True(t, errors.Is(err, ErrNoDialableCandidates),
			"an all-undialable loop must report ErrNoDialableCandidates, got %v", err)
		assert.False(t, errors.Is(err, ErrBuildsRefused),
			"nothing was refused, so ErrBuildsRefused must not be reported")
	})

	t.Run("all attempts refused", func(t *testing.T) {
		pool := newIssue55Pool()
		defer pool.Stop()
		pool.SetTunnelBuilder(&callbackBuilder{
			callback: func(BuildTunnelRequest) (*BuildTunnelResult, error) {
				return &BuildTunnelResult{PeerHashes: hops},
					fmt.Errorf("hop 2 rejected the build: %w", ErrBuildRefused)
			},
		})

		req := newBuildTunnelRequest(3, false)
		_, err := pool.executeBuildWithRetry(&req)
		require.Error(t, err)

		assert.True(t, errors.Is(err, ErrBuildsRefused),
			"an all-refused loop must report ErrBuildsRefused, got %v", err)
		assert.False(t, errors.Is(err, ErrNoDialableCandidates),
			"we reached every gateway, so ErrNoDialableCandidates must not be reported")
	})
}

// TestBuildOutcome_CountersAttributeFailure is requirement 6 of #55: failures
// are debuggable only if attributable, so the pool must count builds attempted,
// builds with no dialable candidate, builds refused, and peers penalized by
// cause.
//
// Pre-fix this fails to compile: neither BuildStats nor GetBuildStats existed.
func TestBuildOutcome_CountersAttributeFailure(t *testing.T) {
	pool := NewTunnelPool(&MockPeerSelector{})
	defer pool.Stop()

	gateway := makePeerHash(0xF1)
	middle := makePeerHash(0xF2)
	end := makePeerHash(0xF3)

	before := pool.GetBuildStats()
	assert.Zero(t, before.BuildsAttempted, "a fresh pool has counted nothing")

	pool.SetTunnelBuilder(&callbackBuilder{
		callback: func(BuildTunnelRequest) (*BuildTunnelResult, error) {
			return &BuildTunnelResult{PeerHashes: []common.Hash{gateway, middle, end}},
				fmt.Errorf("no session to gateway: %w", ErrGatewayUnreachable)
		},
	})

	req := newBuildTunnelRequest(3, false)
	_, err := pool.executeBuildWithRetry(&req)
	require.Error(t, err)

	stats := pool.GetBuildStats()

	assert.Equal(t, uint64(3), stats.BuildsAttempted,
		"every retry attempt must be counted")
	assert.Equal(t, uint64(3), stats.BuildsNoDialableCandidate,
		"every attempt failed before reaching a gateway")
	assert.Zero(t, stats.BuildsRefused, "nothing was refused")

	assert.Equal(t, uint64(3), stats.PeersPenalizedGatewayUnreachable,
		"the gateway was penalized once per attempt, and must be counted by cause")
	assert.Zero(t, stats.PeersPenalizedRefused,
		"no peer was penalized for a refusal")

	// Only the gateway is implicated, so the by-cause total must not include
	// the uncontacted hops.
	totalPenalized := stats.PeersPenalizedGatewayUnreachable +
		stats.PeersPenalizedRefused + stats.PeersPenalizedUnknown
	assert.Equal(t, uint64(3), totalPenalized,
		"exactly one peer penalized per attempt; got %+v", stats)
}

// TestBuildOutcome_RefusedBuildCountedSeparately checks the refusal branch of
// the counters, which the unreachable branch above cannot distinguish.
func TestBuildOutcome_RefusedBuildCountedSeparately(t *testing.T) {
	pool := NewTunnelPool(&MockPeerSelector{})
	defer pool.Stop()

	hops := []common.Hash{makePeerHash(0xA9), makePeerHash(0xB9)}
	pool.SetTunnelBuilder(&callbackBuilder{
		callback: func(BuildTunnelRequest) (*BuildTunnelResult, error) {
			return &BuildTunnelResult{PeerHashes: hops},
				fmt.Errorf("gateway refused: %w", ErrBuildRefused)
		},
	})

	req := newBuildTunnelRequest(2, false)
	_, err := pool.executeBuildWithRetry(&req)
	require.Error(t, err)

	stats := pool.GetBuildStats()
	assert.Zero(t, stats.BuildsNoDialableCandidate, "we reached the gateway every time")
	assert.Equal(t, uint64(3), stats.BuildsRefused, "each attempt was refused")
	assert.Equal(t, uint64(6), stats.PeersPenalizedRefused,
		"a refusal implicates the whole hop set, so both hops are penalized per attempt")
}

// TestBuildOutcome_CountersAreRaceSafe keeps the counters lock-free: they are
// read from the I2CP monitor and the router status path while the maintenance
// goroutine writes them.
func TestBuildOutcome_CountersAreRaceSafe(t *testing.T) {
	pool := NewTunnelPool(&MockPeerSelector{})
	defer pool.Stop()

	hops := []common.Hash{makePeerHash(0xC9)}
	pool.SetTunnelBuilder(&callbackBuilder{
		callback: func(BuildTunnelRequest) (*BuildTunnelResult, error) {
			return &BuildTunnelResult{PeerHashes: hops},
				fmt.Errorf("no session: %w", ErrGatewayUnreachable)
		},
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 20; i++ {
			_ = pool.GetBuildStats()
		}
	}()

	req := newBuildTunnelRequest(1, false)
	_, _ = pool.executeBuildWithRetry(&req)
	<-done

	assert.Greater(t, pool.GetBuildStats().BuildsAttempted, uint64(0))
}

func newIssue55Pool() *Pool {
	return NewTunnelPoolWithConfig(&MockPeerSelector{}, PoolConfig{
		MinTunnels:      1,
		MaxTunnels:      2,
		HopCount:        3,
		BuildRetryDelay: time.Millisecond,
		MaxBuildRetries: 3,
	})
}
