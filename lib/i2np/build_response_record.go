package i2np

import (
	"github.com/go-i2p/go-i2p/lib/tunnel/buildrecord"
)

// BuildResponseRecord is a type alias for buildrecord.BuildResponseRecord,
// the canonical definition shared by lib/tunnel and lib/i2np without an
// import cycle.
//
// The 528-byte long-format reply record parser and its SHA-256 hash validator
// were removed here: they belonged to the deprecated long-record path (see the
// "Tunnel build message coverage (known gap)" section of this package's
// doc.go), had no live callers, and the live short-record path authenticates
// replies with ChaCha20-Poly1305 instead. The Hash and RandomData fields
// remain on the struct because they describe the historical long-record layout
// and are still exercised by the format-documentation tests.
// See [I2P Spec: I2NP](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/i2np.rst) for the wire format.
// See also [BuildRequestRecord].
type BuildResponseRecord = buildrecord.BuildResponseRecord
