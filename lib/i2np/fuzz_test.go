package i2np

// L-NEW-1 FIX: native Go fuzz targets for I2NP network-facing parsers.
// Run with: go test -fuzz=FuzzReadI2NPNTCPHeader ./lib/i2np/
// Each target feeds arbitrary bytes into a parser and checks for panics,
// index-out-of-bounds, and infinite loops. No crash == no finding.

import (
	"testing"
)

// FuzzReadI2NPNTCPHeader exercises the NTCP2 I2NP header parser.
// This is the first parser that touches inbound bytes from the network.
func FuzzReadI2NPNTCPHeader(f *testing.F) {
	// Seed corpus: valid minimal header, empty, and truncated forms
	f.Add([]byte{})
	f.Add([]byte{0x0e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{0x0e})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ReadI2NPNTCPHeader(data)
	})
}

// FuzzDatabaseSearchReplyUnmarshal exercises DatabaseSearchReply deserialization.
// This message arrives from arbitrary remote peers and feeds directly into the
// iterative Kademlia lookup; a panic here brings down the router.
func FuzzDatabaseSearchReplyUnmarshal(f *testing.F) {
	// Seed: minimal valid message (key 32B + count 1B + from 32B = 65B)
	seed := make([]byte, 65)
	seed[32] = 1 // Count = 1 → needs 32 more bytes, but 65-33=32 bytes available for from only; will fail gracefully
	f.Add(seed)
	f.Add([]byte{})
	f.Add(make([]byte, 200))
	f.Fuzz(func(t *testing.T, data []byte) {
		reply := &DatabaseSearchReply{}
		_ = reply.UnmarshalBinary(data)
	})
}

// FuzzDatabaseStoreUnmarshal exercises DatabaseStore deserialization.
// DatabaseStore messages carry RouterInfo and LeaseSet payloads from the
// network; malformed input must not panic or corrupt router state.
func FuzzDatabaseStoreUnmarshal(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 10))
	f.Add(make([]byte, 200))
	// RouterInfo type (0x00) with minimal fields
	seed := make([]byte, 100)
	seed[0] = 0x00 // type: RouterInfo
	f.Add(seed)
	f.Fuzz(func(t *testing.T, data []byte) {
		store := &DatabaseStore{}
		_ = store.UnmarshalBinary(data)
	})
}

// FuzzBuildRequestRecordUnmarshal exercises the variable-length tunnel build
// request record parser. Records arrive from untrusted peers on the tunnel-build
// path; a panic here is a remote crash.
func FuzzBuildRequestRecordUnmarshal(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 222)) // VariableTunnelBuild record size
	f.Add(make([]byte, 528)) // TunnelBuild record size
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ReadBuildRequestRecord(data)
	})
}

// FuzzShortBuildRequestRecordUnmarshal exercises the Short Tunnel Build
// message record parser used in STBM (Noise-ratchet-based tunnel building).
func FuzzShortBuildRequestRecordUnmarshal(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 218)) // STBM short record size
	f.Add(make([]byte, 528))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ReadShortBuildRequestRecord(data)
	})
}

// FuzzDatabaseLookupRead exercises the DatabaseLookup request parser.
// These arrive from floodfill peers and drive NetDB lookups; a panic makes
// the floodfill server unavailable.
func FuzzDatabaseLookupRead(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 65)) // minimal: key(32)+flags(1)+from(32)
	f.Add(make([]byte, 300))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ReadDatabaseLookup(data)
	})
}
