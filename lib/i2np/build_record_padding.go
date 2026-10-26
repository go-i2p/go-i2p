// Fake (phony and padding) STBM build records.
//
// tunnel-creation-ecies.rst §"Build Records" requires:
//
//   - "The recommended minimum number of build records is 4."
//   - "If there are more build records than hops, 'fake' records must be added,
//     containing random or implementation-specific data."
//   - "For inbound tunnel builds, there must always be one 'fake' record for the
//     originating router, with the correct 16-byte hash prefix and a real X25519
//     ephemeral key, otherwise the closest hop will know that the next hop is the
//     originator."
//   - "Originators of inbound tunnels must use some method to validate that their
//     'fake' record has not been modified by the previous hop ... If the 16-byte
//     hash prefix or other build record contents were modified, the router must
//     discard the tunnel."
//
// # Why the phony record returns byte-identical
//
// A transit hop answers a build by rewriting the slot addressed to it with its
// AEAD-encrypted reply and ChaCha20-XORing every OTHER slot, using each slot's
// own index as the nonce (spec §"Record Encryption", "n = record number 0-7").
// The creator pre-applies the same layers in path order so that they cancel one
// by one as the replies come back. If the phony record is placed at the END of
// the path and the creator applies a layer for every real hop *except* the
// phony entry itself, then on the reply path each hop i XORs the phony slot
// exactly once and the creator peels exactly the same set of XORs - so the
// phony slot arrives back byte-identical to what was sent. That is what makes
// the mandated tamper check possible with a plain checksum, and it is why the
// creator must NOT add a layer of its own for the phony entry.
//
// Padding records for the unfilled slots are pure random bytes and are never
// addressed to any hop. Every hop still XORs them along with everything else,
// so they too return unchanged, but the spec imposes no validation requirement
// on them.
package i2np

import (
	"crypto/sha256"
	"io"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/crypto/ecies"
	rand "github.com/go-i2p/crypto/rand"
	"github.com/samber/oops"
)

const (
	// standardBuildRecords is the record count of a standard tunnel build
	// message; the reference implementation uses it as the short-build minimum.
	standardBuildRecords = 4
	// maxBuildRecords is the maximum number of records a short tunnel build
	// message may carry (spec: num is a 1-byte integer, valid values 1-8).
	maxBuildRecords = 8
)

// shortBuildRecordCount returns how many build records to put on the wire for a
// build with the given number of path entries (real hops plus a phony record
// when one is included). Pad up to 4 records, or up to 8 once the entry count
// exceeds 4.
func shortBuildRecordCount(pathEntries int) int {
	if pathEntries <= standardBuildRecords {
		return standardBuildRecords
	}
	return maxBuildRecords
}

// shouldInsertPhonyRecord reports whether an inbound build needs the
// originator's fake record. An inbound build whose real hops already fill every
// slot has no room for it.
func shouldInsertPhonyRecord(isInbound bool, hopCount int) bool {
	return isInbound && hopCount < maxBuildRecords
}

// phonyRecordByteLayout is the offset table for the fake record described by
// spec §"Short Build Request Record Encrypted" / "Build Records": the 16-byte
// identity-hash prefix and the 32-byte ephemeral X25519 public key sit in the
// clear, the remainder is opaque.
const (
	phonyHashPrefixLen  = 16
	phonyEphemeralKeyID = 32
	phonyBodyOffset     = phonyHashPrefixLen + phonyEphemeralKeyID
)

// makePhonyShortBuildRecord builds the fake record standing in for the
// originating router on an inbound build. Its first 16 bytes are our own
// identity-hash prefix and the next 32 are a genuine X25519 public key, so the
// record has exactly the shape a real build record has; the remaining bytes are
// random, which the spec explicitly permits ("The remainder of the 'fake' record
// may be random data").
//
// The key material is delegated to the upstream ECIES helper
// (github.com/go-i2p/crypto/ecies.GenerateKeyPair) so the phony record's public
// key is a real, uniformly-sampled X25519 group element rather than random
// bytes that may not decode as one.
func makePhonyShortBuildRecord(ourHash common.Hash) ([]byte, error) {
	var zero common.Hash
	if ourHash == zero {
		return nil, oops.Errorf("cannot build phony record: our router hash is not set")
	}

	record := make([]byte, ShortBuildRecordSize)
	copy(record[:phonyHashPrefixLen], ourHash[:phonyHashPrefixLen])

	ephemeralPub, _, err := ecies.GenerateKeyPair()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to generate phony record X25519 key")
	}
	if len(ephemeralPub) != phonyEphemeralKeyID {
		return nil, oops.Errorf("unexpected X25519 public key size %d (want %d)",
			len(ephemeralPub), phonyEphemeralKeyID)
	}
	copy(record[phonyHashPrefixLen:phonyBodyOffset], ephemeralPub)

	if _, err := io.ReadFull(rand.Reader, record[phonyBodyOffset:]); err != nil {
		return nil, oops.Wrapf(err, "failed to randomize phony record body")
	}
	return record, nil
}

// makeRandomShortBuildRecord builds a padding record carrying no information.
// Such records are never addressed to any hop, so every hop only ever re-XORs
// them along with the rest of the message.
func makeRandomShortBuildRecord() ([]byte, error) {
	record := make([]byte, ShortBuildRecordSize)
	if _, err := io.ReadFull(rand.Reader, record); err != nil {
		return nil, oops.Wrapf(err, "failed to generate padding build record")
	}
	return record, nil
}

// checksumBuildRecord computes the validation tag the originator stores for its
// phony record. The creator compares it against the record as it comes back on
// the reply path, which is how the spec's "must validate that their fake record
// has not been modified" requirement is satisfied. SHA-256 is the digest the
// rest of the build protocol already uses for record integrity.
func checksumBuildRecord(record []byte) [sha256.Size]byte {
	return sha256.Sum256(record)
}
