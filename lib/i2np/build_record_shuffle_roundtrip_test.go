// Round-trip proof that randomized build-record order (C2) is consistent
// between the creator's layer application and the creator's reply peel.
package i2np

import (
	"testing"

	"github.com/go-i2p/common/session_key"
	rand "github.com/go-i2p/crypto/rand"
	"github.com/stretchr/testify/require"
)

func toSessionKeys(in [][32]byte) []session_key.SessionKey {
	out := make([]session_key.SessionKey, len(in))
	for i, k := range in {
		out[i] = session_key.SessionKey(k)
	}
	return out
}

// TestBuildRecordShuffleReplyRoundTrip simulates the full STBM build/reply
// cycle with a shuffled wire layout and asserts the creator recovers every
// hop's reply code in PATH order.
//
// Spec: tunnel-creation-ecies.rst "Build Records" — "Build record order must be
// randomized, so middle hops do not know their location within the tunnel."
//
// The simulation mirrors the real wire algebra:
//  1. Creator encrypts each hop's record and pre-applies ChaCha20 layers for
//     hops j > i, using the WIRE SLOT as the nonce (applyChaCha20LayerObfuscation).
//  2. Records are placed on the wire in permuted order.
//  3. Each hop locates its own record by successful decryption, so it knows its
//     slot positionally; it replaces its slot with an AEAD reply (nonce = slot)
//     and ChaCha20-XORs every other slot (nonce = that slot).
//  4. Creator peels slots in reverse PATH order, addressing hop i's data at
//     RecordSlots[i] (decryptSTBMReplyRecords).
func TestBuildRecordShuffleReplyRoundTrip(t *testing.T) {
	for _, hopCount := range []int{1, 2, 3, 4, 5, 8} {
		t.Run(itoa(hopCount)+"-hops", func(t *testing.T) {
			replyKeys := make([][32]byte, hopCount)
			noiseHashes := make([][32]byte, hopCount)
			retCodes := make([]byte, hopCount)
			for i := 0; i < hopCount; i++ {
				_, err := rand.Read(replyKeys[i][:])
				require.NoError(t, err)
				_, err = rand.Read(noiseHashes[i][:])
				require.NoError(t, err)
				// Distinct codes so a mis-ordered peel is detectable.
				retCodes[i] = byte(0x10 + i)
			}

			// Creator side: path-ordered encrypted records + slot permutation.
			encrypted := make([][ShortBuildRecordSize]byte, hopCount)
			for i := range encrypted {
				_, err := rand.Read(encrypted[i][:])
				require.NoError(t, err)
			}
			recordSlots := shuffleRecordSlots(hopCount)
			require.Len(t, recordSlots, hopCount)
			require.ElementsMatch(t, orderedRange(hopCount), recordSlots,
				"shuffleRecordSlots must return a permutation")

			tm := &TunnelManager{}
			keyBytes := make([][32]byte, hopCount)
			copy(keyBytes, replyKeys)
			require.NoError(t, tm.applyChaCha20LayerObfuscation(encrypted, keyBytes, recordSlots))

			// Wire layout: slot[perm[i]] = record for hop i.
			wire := make([][ShortBuildRecordSize]byte, hopCount)
			for pathIndex, slot := range recordSlots {
				wire[slot] = encrypted[pathIndex]
			}

			// Hops process in path order (0..n-1), each addressing its own slot.
			for hopIndex := 0; hopIndex < hopCount; hopIndex++ {
				ourSlot := recordSlots[hopIndex]
				for j := 0; j < hopCount; j++ {
					if j == ourSlot {
						continue
					}
					require.NoError(t, chacha20XORRecord(&wire[j], replyKeys[hopIndex], j))
				}
				wire[ourSlot] = createAEADReplySlot(t, replyKeys[hopIndex], noiseHashes[hopIndex],
					ourSlot, retCodes[hopIndex])
			}

			// Creator peel: must recover retCodes in path order.
			raw := make([][]byte, hopCount)
			for i := range wire {
				raw[i] = wire[i][:]
			}
			records := make([]BuildResponseRecord, hopCount)
			pending := &PendingBuildRequest{
				ReplyKeys:   toSessionKeys(replyKeys),
				NoiseHashes: noiseHashes,
				RecordSlots: recordSlots,
				HopCount:    hopCount,
			}
			rp := NewReplyProcessor(DefaultReplyProcessorConfig(), nil)

			require.NoError(t, rp.decryptSTBMReplyRecords(records, raw, pending))
			for i := 0; i < hopCount; i++ {
				require.Equal(t, retCodes[i], records[i].Reply,
					"hop %d reply code mismatch (shuffle permutation %v)", i, recordSlots)
			}
		})
	}
}

// TestBuildRecordShuffleIdentityParity asserts the shuffled path agrees with the
// identity mapping: with perm = identity the new code must behave exactly like
// the pre-shuffle behaviour that the existing ChaCha20 property test validates.
func TestBuildRecordShuffleIdentityParity(t *testing.T) {
	hopCount := 3
	replyKeys := make([][32]byte, hopCount)
	noiseHashes := make([][32]byte, hopCount)
	retCodes := make([]byte, hopCount)
	for i := 0; i < hopCount; i++ {
		_, err := rand.Read(replyKeys[i][:])
		require.NoError(t, err)
		_, err = rand.Read(noiseHashes[i][:])
		require.NoError(t, err)
		retCodes[i] = byte(i)
	}

	identity := orderedRange(hopCount)
	encrypted := make([][ShortBuildRecordSize]byte, hopCount)
	for i := range encrypted {
		_, err := rand.Read(encrypted[i][:])
		require.NoError(t, err)
	}

	tm := &TunnelManager{}
	keyBytes := make([][32]byte, hopCount)
	copy(keyBytes, replyKeys)
	require.NoError(t, tm.applyChaCha20LayerObfuscation(encrypted, keyBytes, identity))

	wire := make([][ShortBuildRecordSize]byte, hopCount)
	copy(wire, encrypted)

	for hopIndex := 0; hopIndex < hopCount; hopIndex++ {
		for j := 0; j < hopCount; j++ {
			if j == hopIndex {
				continue
			}
			require.NoError(t, chacha20XORRecord(&wire[j], replyKeys[hopIndex], j))
		}
		wire[hopIndex] = createAEADReplySlot(t, replyKeys[hopIndex], noiseHashes[hopIndex],
			hopIndex, retCodes[hopIndex])
	}

	raw := make([][]byte, hopCount)
	for i := range wire {
		raw[i] = wire[i][:]
	}
	records := make([]BuildResponseRecord, hopCount)
	pending := &PendingBuildRequest{
		ReplyKeys:   toSessionKeys(replyKeys),
		NoiseHashes: noiseHashes,
		// RecordSlots deliberately nil: must fall back to identity.
	}
	rp := NewReplyProcessor(DefaultReplyProcessorConfig(), nil)
	require.NoError(t, rp.decryptSTBMReplyRecords(records, raw, pending))
	for i := 0; i < hopCount; i++ {
		require.Equal(t, retCodes[i], records[i].Reply)
	}
}

// TestBuildRecordShuffleActuallyRandomizes guards against a shuffle that is a
// no-op, which would silently leave the de-anonymization property unmet.
func TestBuildRecordShuffleActuallyRandomizes(t *testing.T) {
	const n = 8
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		perm := shuffleRecordSlots(n)
		require.Len(t, perm, n)
		require.ElementsMatch(t, orderedRange(n), perm)
		seen[permKey(perm)] = true
	}
	require.Greater(t, len(seen), 100, "shuffleRecordSlots produced too few distinct permutations")
}

// TestBuildRecordShuffleRejectsWrongNonce asserts the peel is genuinely
// slot-indexed: if the creator forgets the permutation while the hops used it,
// decryption must fail rather than silently mis-attribute replies.
func TestBuildRecordShuffleRejectsWrongNonce(t *testing.T) {
	hopCount := 4
	replyKeys := make([][32]byte, hopCount)
	noiseHashes := make([][32]byte, hopCount)
	for i := 0; i < hopCount; i++ {
		_, err := rand.Read(replyKeys[i][:])
		require.NoError(t, err)
		_, err = rand.Read(noiseHashes[i][:])
		require.NoError(t, err)
	}

	// Find a non-identity permutation to exercise the mismatch.
	var perm []int
	for i := 0; i < 50; i++ {
		candidate := shuffleRecordSlots(hopCount)
		if !isIdentity(candidate) {
			perm = candidate
			break
		}
	}
	require.NotNil(t, perm, "could not obtain a non-identity permutation")

	encrypted := make([][ShortBuildRecordSize]byte, hopCount)
	for i := range encrypted {
		_, err := rand.Read(encrypted[i][:])
		require.NoError(t, err)
	}
	tm := &TunnelManager{}
	keyBytes := make([][32]byte, hopCount)
	copy(keyBytes, replyKeys)
	require.NoError(t, tm.applyChaCha20LayerObfuscation(encrypted, keyBytes, perm))

	wire := make([][ShortBuildRecordSize]byte, hopCount)
	for pathIndex, slot := range perm {
		wire[slot] = encrypted[pathIndex]
	}
	for hopIndex := 0; hopIndex < hopCount; hopIndex++ {
		ourSlot := perm[hopIndex]
		for j := 0; j < hopCount; j++ {
			if j == ourSlot {
				continue
			}
			require.NoError(t, chacha20XORRecord(&wire[j], replyKeys[hopIndex], j))
		}
		wire[ourSlot] = createAEADReplySlot(t, replyKeys[hopIndex], noiseHashes[hopIndex], ourSlot, 0x00)
	}

	raw := make([][]byte, hopCount)
	for i := range wire {
		raw[i] = wire[i][:]
	}
	records := make([]BuildResponseRecord, hopCount)
	// Permutation deliberately omitted -> peel uses the wrong nonces.
	pending := &PendingBuildRequest{
		ReplyKeys:   toSessionKeys(replyKeys),
		NoiseHashes: noiseHashes,
	}
	rp := NewReplyProcessor(DefaultReplyProcessorConfig(), nil)
	require.Error(t, rp.decryptSTBMReplyRecords(records, raw, pending),
		"peel without the build permutation must fail, not mis-attribute replies")
}

func orderedRange(n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = i
	}
	return out
}

func isIdentity(perm []int) bool {
	for i, v := range perm {
		if v != i {
			return false
		}
	}
	return true
}

func permKey(perm []int) string {
	buf := make([]byte, len(perm))
	for i, v := range perm {
		buf[i] = byte('0' + v)
	}
	return string(buf)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}
