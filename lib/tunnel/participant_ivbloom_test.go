package tunnel

import (
	"errors"
	"sync"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func hashWith(b byte) common.Hash {
	var h common.Hash
	h[0] = b
	h[31] = b
	return h
}

// makeTransitRecord builds a 1028-byte transit record whose decrypted form (via
// the passthrough encryptor) carries the given 16-byte IV at bytes 4..19. The
// passthrough encryptor returns the input unchanged, so the IV we place is the
// IV the IV-bloom inspects.
func makeTransitRecord(iv []byte) []byte {
	rec := make([]byte, TunnelMessageSize)
	copy(rec[TunnelIDSize:TunnelIDSize+TunnelIVSize], iv)
	return rec
}

// TestParticipant_Process_DropsDuplicateIV is the C4/I2P-B-1 guard: a transit
// relay must drop a record whose IV was already seen on the tunnel (the
// IV-bloom duplicate-delivery suppression the I2P Tunnel-Implementation spec
// mandates at Participant Processing). Before this fix the participant had no
// IV history, so a previous hop could replay one record indefinitely and every
// downstream hop re-processed it — the duplicate-delivery DoS primitive.
func TestParticipant_Process_DropsDuplicateIV(t *testing.T) {
	p, err := NewParticipant(TunnelID(4242), &passthroughEncryptor{})
	require.NoError(t, err)

	var iv [TunnelIVSize]byte
	iv[0] = 0x11
	iv[15] = 0xee

	// First delivery of this IV is accepted.
	_, _, err = p.Process(makeTransitRecord(iv[:]))
	require.NoError(t, err, "first record with a fresh IV must be accepted")

	// A replay of the same IV is rejected as a duplicate.
	_, _, err = p.Process(makeTransitRecord(iv[:]))
	require.Error(t, err, "replayed IV must be rejected")
	assert.True(t, errors.Is(err, ErrDuplicateTunnelRecord),
		"replay must be rejected specifically as a duplicate record, got %v", err)

	assert.Equal(t, uint64(1), p.DuplicateIVCount(), "duplicate counter must reflect the drop")
}

// TestParticipant_Process_DistinctIVsAccepted pins that distinct IVs are not
// falsely rejected, including two IVs that share the same first byte (same
// bloom bucket) but differ elsewhere.
func TestParticipant_Process_DistinctIVsAccepted(t *testing.T) {
	p, err := NewParticipant(TunnelID(4243), &passthroughEncryptor{})
	require.NoError(t, err)

	var ivA, ivB [TunnelIVSize]byte
	ivA[0] = 0x77 // same bucket
	ivB[0] = 0x77 // same bucket
	ivB[1] = 0x01 // different IV

	_, _, err = p.Process(makeTransitRecord(ivA[:]))
	require.NoError(t, err, "first distinct IV must be accepted")
	_, _, err = p.Process(makeTransitRecord(ivB[:]))
	require.NoError(t, err, "a different IV in the same bucket must be accepted")
	assert.Zero(t, p.DuplicateIVCount(), "no duplicates should have been dropped")
}

// TestParticipant_Process_ConcurrentDuplicateIV exercises the IV-bloom under
// concurrent Process calls with the same IV: exactly one record is accepted and
// the rest are dropped as duplicates (the mutex must serialize bucket access).
func TestParticipant_Process_ConcurrentDuplicateIV(t *testing.T) {
	p, err := NewParticipant(TunnelID(4244), &passthroughEncryptor{})
	require.NoError(t, err)

	var iv [TunnelIVSize]byte
	iv[0] = 0x55
	iv[1] = 0x99

	const n = 32
	var accepted, dup int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := p.Process(makeTransitRecord(iv[:]))
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				accepted++
			case errors.Is(err, ErrDuplicateTunnelRecord):
				dup++
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, 1, accepted, "exactly one record with a given IV must be accepted")
	assert.Equal(t, n-1, dup, "the remaining replays must be dropped as duplicates")
}

// TestParticipant_VerifySource_Pinning is the C4/I2P-B-1 guard for previous-hop
// pinning: once a participant is pinned to its previous hop (learned from the
// build record / delivering peer), a transit record arriving from any other peer
// must be rejected — only the previous hop holds the layer key. An unpinned
// participant and an unknown (zero) source are accepted, so pinning is a strict
// tightening only where a prev-hop identity is known.
func TestParticipant_VerifySource_Pinning(t *testing.T) {
	p, err := NewParticipant(TunnelID(5001), &passthroughEncryptor{})
	require.NoError(t, err)

	prev := hashWith(0xAA)
	other := hashWith(0xBB)

	// Unpinned: any source accepted.
	require.NoError(t, p.VerifySource(other), "unpinned participant must accept any source")

	// Pin to the previous hop.
	p.PinPrevHop(prev)

	require.NoError(t, p.VerifySource(prev), "record from the pinned previous hop must be accepted")
	require.NoError(t, p.VerifySource(common.Hash{}), "unknown (zero) source must be accepted")

	err = p.VerifySource(other)
	require.Error(t, err, "record from a non-pinned peer must be rejected")
	assert.True(t, errors.Is(err, ErrWrongPrevHop), "rejection must be ErrWrongPrevHop, got %v", err)
}

// TestParticipant_PinPrevHop_ZeroLeavesUnpinned pins that a zero prev-hop hash
// (no source attribution) leaves the participant unpinned, so a build path that
// cannot supply the delivering peer does not accidentally reject all sources.
func TestParticipant_PinPrevHop_ZeroLeavesUnpinned(t *testing.T) {
	p, err := NewParticipant(TunnelID(5002), &passthroughEncryptor{})
	require.NoError(t, err)

	p.PinPrevHop(common.Hash{}) // zero must not pin

	require.NoError(t, p.VerifySource(hashWith(0xCC)),
		"zero prev-hop must leave the participant unpinned (accept any source)")
}
