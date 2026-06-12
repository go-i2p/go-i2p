package reseed

// L-NEW-1 FIX: native Go fuzz targets for the reseed SU3 parser.
// Run with: go test -fuzz=FuzzParseSU3File ./lib/netdb/reseed/
// This is the most security-critical parser: skipping SU3 signature
// verification would allow injecting arbitrary router data.

import (
	"bytes"
	"testing"

	"github.com/go-i2p/su3"
)

// FuzzParseSU3File exercises the full SU3 parse path (including signature
// verification) via the unexported parseSU3File which delegates to su3.Read.
// Malformed or adversarially crafted SU3 data must not panic.
func FuzzParseSU3File(f *testing.F) {
	// Minimal header: magic bytes "I2Psu3" + zero fields
	su3Magic := append([]byte("I2Psu3"), make([]byte, 100)...)
	f.Add(su3Magic)
	f.Add([]byte{})
	f.Add(make([]byte, 50))
	f.Fuzz(func(t *testing.T, data []byte) {
		r := NewReseed()
		// parseSU3File is unexported so call it directly here (same package).
		_, _ = r.parseSU3File(data)
	})
}

// FuzzSU3Read exercises the su3 library's parser directly against
// arbitrary input, to catch panics in the underlying SU3 format decoder.
func FuzzSU3Read(f *testing.F) {
	su3Magic := append([]byte("I2Psu3"), make([]byte, 100)...)
	f.Add(su3Magic)
	f.Add([]byte{})
	f.Add(make([]byte, 200))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = su3.Read(bytes.NewReader(data))
	})
}
