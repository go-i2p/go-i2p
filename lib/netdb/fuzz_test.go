// Fuzz tests for NetDB entry parsers. Feeds arbitrary bytes to the parsers that
// turn remote-supplied records into NetDB entries, to catch panics on malformed
// input (C3: the parse/decrypt cluster was previously unfuzzed).
package netdb

import (
	"testing"

	"github.com/go-i2p/common/lease_set2"
)

// FuzzReadLeaseSet2 exercises the LeaseSet2 parser. LeaseSet2 records arrive
// from arbitrary peers over DatabaseStore and the DHT; a panic here (index-out-
// of-bounds, nil deref) would crash the router while processing untrusted input.
// This is the C3 latent-panic guard for the LeaseSet2 parse path.
func FuzzReadLeaseSet2(f *testing.F) {
	// Seed corpus: empty, a plausible header, and oversized buffers.
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})
	seed := make([]byte, 200)
	seed[0] = 0x05 // LeaseSet2 type byte
	f.Add(seed)
	f.Add(make([]byte, 512))
	f.Fuzz(func(t *testing.T, data []byte) {
		// ReadLeaseSet2 must return an error, not panic, on malformed input.
		_, _, _ = lease_set2.ReadLeaseSet2(data)
	})
}
