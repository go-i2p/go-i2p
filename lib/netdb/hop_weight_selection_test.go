// Tests for weighted hop selection (I2P-017): the per-pool Kademlia
// XOR-distance ordering key and the exponential reliability weighting that
// replace the previous uniform CSPRNG shuffle in selectRandomPeers.

package netdb

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHopWeightFor_ScoreMonotonic verifies the exponential reliability term:
// a higher reliability score yields a strictly larger selection weight, so the
// peer is favored in the race. This is the second half of I2P-017.
func TestHopWeightFor_ScoreMonotonic(t *testing.T) {
	// No distance term (haveDistance=false) isolates the score contribution.
	wBad := hopWeightFor(0.0, 0, false)
	wMid := hopWeightFor(neutralPeerScore, 0, false)
	wGood := hopWeightFor(1.0, 0, false)

	assert.Greater(t, wMid, wBad, "neutral score should outweigh a proven-bad peer")
	assert.Greater(t, wGood, wMid, "perfect score should outweigh a neutral peer")

	// The weighting is exponential in the sense that the good:bad ratio is the
	// full (1+floor)/floor span, not a linear nudge.
	assert.Greater(t, wGood/wBad, 10.0, "reliable peers should be weighted an order of magnitude above proven-bad peers")
}

// TestHopWeightFor_DistanceMonotonic verifies the per-pool XOR-distance term:
// a candidate closer to us in the keyspace (smaller bucket) gets a larger
// weight at equal score. This is the first half of I2P-017.
func TestHopWeightFor_DistanceMonotonic(t *testing.T) {
	const score = 0.7
	wNear := hopWeightFor(score, 0, true)
	wFar := hopWeightFor(score, maxKademliaBucket, true)

	assert.Greater(t, wNear, wFar, "a closer peer should be weighted above a farther peer at equal score")
	// The distance factor is bounded by (1+gain), so it stays a soft preference.
	assert.InDelta(t, wNear/wFar, 1.0+hopWeightDistanceGain, 1e-9,
		"the near:far weight ratio should equal the configured distance gain")
}

// TestHopWeightFor_FloorPositive verifies a proven-bad peer keeps a strictly
// positive weight, so it is de-prioritized rather than excluded outright.
func TestHopWeightFor_FloorPositive(t *testing.T) {
	assert.Greater(t, hopWeightFor(0.0, maxKademliaBucket, true), 0.0,
		"even a proven-bad, far peer must keep a nonzero weight")
}

// TestHopWeightFor_NoDistanceIsScoreOnly verifies that when no distance is
// available the bucket is ignored entirely, leaving score-only weighting (the
// cold-start / no-our-hash degradation path).
func TestHopWeightFor_NoDistanceIsScoreOnly(t *testing.T) {
	const score = 0.6
	near := hopWeightFor(score, 0, false)
	far := hopWeightFor(score, maxKademliaBucket, false)
	assert.InDelta(t, near, far, 1e-12, "without a distance signal the bucket must not affect the weight")
}

// TestHopSelectionWeight_UniformWithoutSignals verifies the degradation to the
// pre-I2P-017 uniform behavior: with no PeerTracker and no our-hash provider,
// every candidate (here unhashable mock RouterInfos) receives identical weight.
func TestHopSelectionWeight_UniformWithoutSignals(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	db.PeerTracker = nil

	var zero common.Hash
	// Mock RouterInfos have a nil identity, so IdentHash errors and both terms
	// fall back to neutral/score-only with no distance.
	ri := mockRouterInfoSlice(1)[0]
	w := hopSelectionWeight(db, ri, zero, false)
	assert.InDelta(t, w, hopWeightFor(neutralPeerScore, 0, false), 1e-12,
		"with no signals the weight must equal the neutral score-only weight")
}

// TestWeightedPeerOrder_PrefersReliable is the end-to-end check that the
// exponential race actually favors reliable peers. Over many trials the
// high-score peer should rank first far more often than the 1/N uniform
// baseline.
func TestWeightedPeerOrder_PrefersReliable(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	require.NotNil(t, db.PeerTracker)

	// Two reachable, hashable peers with distinct identities.
	riGood := *createTestRouterInfoWithOptions(t, map[string]string{"caps": "R"})
	riBad := *createTestRouterInfoWithOptions(t, map[string]string{"caps": "R"})
	available := []router_info.RouterInfo{riGood, riBad}

	hGood, err := riGood.IdentHash()
	require.NoError(t, err)
	hBad, err := riBad.IdentHash()
	require.NoError(t, err)

	// Drive scores apart: many successes vs many failures. RecordAttempt is
	// required because ScorePeer only trusts a peer once TotalAttempts clears
	// minAttemptsForStats, and RecordSuccess/RecordFailure do not bump it.
	for i := 0; i < 20; i++ {
		db.PeerTracker.RecordAttempt(hGood)
		db.PeerTracker.RecordSuccess(hGood, 100)
		db.PeerTracker.RecordAttempt(hBad)
		db.PeerTracker.RecordFailure(hBad, "timeout")
	}
	require.Greater(t, db.PeerTracker.ScorePeer(hGood), db.PeerTracker.ScorePeer(hBad))

	const trials = 400
	goodFirst := 0
	for i := 0; i < trials; i++ {
		order := weightedPeerOrder(db, available)
		require.Len(t, order, 2)
		h, herr := available[order[0]].IdentHash()
		require.NoError(t, herr)
		if h == hGood {
			goodFirst++
		}
	}

	// Uniform would give ~50%; the ~21x weight ratio should push this well
	// above that. Use a conservative floor to avoid flakiness.
	assert.Greater(t, goodFirst, trials*3/4,
		"reliable peer should rank first in the weighted order far more often than chance")
}

// TestHopSelectionWeight_DistanceOrdering verifies the distance term end to
// end against real signed RouterInfo hashes: given a fixed our-hash, the peer
// whose actual Kademlia bucket is nearest must receive at least as much weight
// as the peer whose bucket is farthest.
func TestHopSelectionWeight_DistanceOrdering(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	db.PeerTracker = nil // isolate the distance term

	var ourHash common.Hash
	copy(ourHash[:], []byte("our-router-hash-32-bytes-aaaaa"))

	// Several signed peers with real (random) hashes.
	peers := make([]router_info.RouterInfo, 0, 6)
	for i := 0; i < 6; i++ {
		peers = append(peers, *createTestRouterInfoWithOptions(t, map[string]string{"caps": "R"}))
	}

	// Find the nearest and farthest by actual bucket distance.
	nearest, farthest := peers[0], peers[0]
	minBucket, maxBucket := 1<<30, -1
	for _, p := range peers {
		h, err := p.IdentHash()
		require.NoError(t, err)
		bucket := findMostSignificantDifferingBit(computeXORDistance(ourHash, h))
		if bucket < minBucket {
			minBucket, nearest = bucket, p
		}
		if bucket > maxBucket {
			maxBucket, farthest = bucket, p
		}
	}
	require.NotEqual(t, minBucket, maxBucket, "test needs peers at differing distances")

	wNear := hopSelectionWeight(db, nearest, ourHash, true)
	wFar := hopSelectionWeight(db, farthest, ourHash, true)
	assert.GreaterOrEqual(t, wNear, wFar,
		"the nearest peer must be weighted at least as high as the farthest")
}

// TestSelectRandomPeers_WeightedCountAndUnique verifies the weighted path still
// returns exactly the requested count with no duplicates.
func TestSelectRandomPeers_WeightedCountAndUnique(t *testing.T) {
	db := NewStdNetDB(t.TempDir())

	available := make([]router_info.RouterInfo, 0, 12)
	for i := 0; i < 12; i++ {
		available = append(available, *createTestRouterInfoWithOptions(t, map[string]string{"caps": "R"}))
	}

	for trial := 0; trial < 50; trial++ {
		selected := db.selectRandomPeers(available, 5)
		require.Len(t, selected, 5)

		seen := make(map[common.Hash]bool)
		for _, ri := range selected {
			h, err := ri.IdentHash()
			require.NoError(t, err)
			assert.False(t, seen[h], "selected peers must be unique")
			seen[h] = true
		}
	}
}
